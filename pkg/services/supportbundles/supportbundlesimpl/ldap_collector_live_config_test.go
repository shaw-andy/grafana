package supportbundlesimpl

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/kvstore"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ldap"
	ldapapi "github.com/grafana/grafana/pkg/services/ldap/api"
	ldapservice "github.com/grafana/grafana/pkg/services/ldap/service"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/services/supportbundles"
	"github.com/grafana/grafana/pkg/services/supportbundles/bundleregistry"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const (
	// Obvious stand-ins for the LDAP bind secret. They are not credentials.
	bindPasswordA = "placeholder-bind-password-a"
	bindPasswordB = "placeholder-bind-password-b"
	bindDN        = "cn=placeholder-reader,dc=example,dc=org"
	loginName     = "placeholder-user"
	loginPassword = "placeholder-user-password"

	// The collector writes this token into the bundle. A fixed collector writes it
	// only onto a copy, so a later bind must not present it.
	censoredSecret = "********"
)

func TestAuthLDAPCollectorPreservesBindPasswordForLoginAndSync(t *testing.T) {
	rec := startLDAPRecorder(t, nil)
	svc, bundles := wireLDAPBundle(t, rec.Addr, []serverSpec{
		{bindPassword: bindPasswordA},
		{bindPassword: bindPasswordB},
	})

	// Login tries every server. User lookup and user sync stop at the first.
	want := []string{bindPasswordA, bindPasswordB, bindPasswordA, bindPasswordA}
	require.Equal(t, want, collectPasswords(t, svc, rec))

	markdown := collectAuthLDAP(t, bundles)
	require.NotContains(t, markdown, bindPasswordA)
	require.NotContains(t, markdown, bindPasswordB)
	require.Contains(t, markdown, censoredSecret)

	require.Equal(t, want, collectPasswords(t, svc, rec))
}

func TestAuthLDAPCollectorPreservesFileClientKeyAndBindPassword(t *testing.T) {
	client, serverLeaf := issueClientAndServer(t)
	dir := t.TempDir()
	certPath := dir + "/placeholder-client.crt"
	keyPath := dir + "/placeholder-client.key"
	require.NoError(t, os.WriteFile(certPath, client.certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, client.keyPEM, 0o600))

	rec := startLDAPRecorder(t, serverTLSConfig(serverLeaf, client.ca))
	svc, bundles := wireLDAPBundle(t, rec.Addr, []serverSpec{{
		bindPassword:  bindPasswordA,
		useSSL:        true,
		clientCert:    certPath,
		clientKey:     keyPath,
		skipVerifySSL: true,
	}})

	want := []string{bindPasswordA, bindPasswordA, bindPasswordA}
	assertPresentedMaterial(t, svc, rec, client.cert.Raw, want)

	markdown := collectAuthLDAP(t, bundles)
	require.NotContains(t, markdown, bindPasswordA)
	require.NotContains(t, markdown, keyPath)
	require.NotContains(t, markdown, string(client.keyPEM))
	require.Contains(t, markdown, censoredSecret)

	assertPresentedMaterial(t, svc, rec, client.cert.Raw, want)
}

func TestAuthLDAPCollectorPreservesInlineClientKeyAndBindPassword(t *testing.T) {
	client, serverLeaf := issueClientAndServer(t)
	rec := startLDAPRecorder(t, serverTLSConfig(serverLeaf, client.ca))
	svc, bundles := wireLDAPBundle(t, rec.Addr, []serverSpec{{
		bindPassword:    bindPasswordA,
		useSSL:          true,
		clientCertValue: client.certB64,
		clientKeyValue:  client.keyB64,
		skipVerifySSL:   true,
	}})

	want := []string{bindPasswordA, bindPasswordA, bindPasswordA}
	assertPresentedMaterial(t, svc, rec, client.cert.Raw, want)

	markdown := collectAuthLDAP(t, bundles)
	require.NotContains(t, markdown, bindPasswordA)
	require.NotContains(t, markdown, client.keyB64)
	require.Contains(t, markdown, censoredSecret)

	assertPresentedMaterial(t, svc, rec, client.cert.Raw, want)
}

// collectPasswords runs password login, user lookup, and user sync. Each one
// dials the stored server config and admin-binds with its bind password.
func collectPasswords(t *testing.T, svc *ldapservice.LDAPImpl, rec *ldapRecorder) []string {
	t.Helper()
	rec.Reset()
	bindAsLoginAndSync(t, svc)
	return rec.Passwords()
}

func bindAsLoginAndSync(t *testing.T, svc *ldapservice.LDAPImpl) {
	t.Helper()
	_, err := svc.Login(&login.LoginUserQuery{Username: loginName, Password: loginPassword})
	require.ErrorIs(t, err, ldap.ErrInvalidCredentials)

	_, err = svc.User(loginName)
	require.ErrorIs(t, err, ldap.ErrInvalidCredentials)

	_, err = svc.Client().Users([]string{loginName})
	require.ErrorIs(t, err, ldap.ErrInvalidCredentials)
}

func assertPresentedMaterial(t *testing.T, svc *ldapservice.LDAPImpl, rec *ldapRecorder, certDER []byte, wantPasswords []string) {
	t.Helper()
	rec.Reset()
	bindAsLoginAndSync(t, svc)

	statuses, err := svc.Client().Ping()
	require.NoError(t, err)
	require.NotEmpty(t, statuses)
	for _, status := range statuses {
		require.True(t, status.Available, "LDAP dial after the bundle: %v", status.Error)
	}

	require.Equal(t, wantPasswords, rec.Passwords())
	certs := rec.PeerCerts()
	require.NotEmpty(t, certs)
	for _, got := range certs {
		require.Equal(t, certDER, got)
	}
}

type serverSpec struct {
	bindPassword    string
	useSSL          bool
	skipVerifySSL   bool
	clientCert      string
	clientKey       string
	clientCertValue string
	clientKeyValue  string
}

func wireLDAPBundle(t *testing.T, addr string, specs []serverSpec) (*ldapservice.LDAPImpl, *Service) {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)

	servers := make([]any, 0, len(specs))
	for _, spec := range specs {
		servers = append(servers, map[string]any{
			"host":              host,
			"port":              port,
			"timeout":           3,
			"bind_dn":           bindDN,
			"bind_password":     spec.bindPassword,
			"use_ssl":           spec.useSSL,
			"ssl_skip_verify":   spec.skipVerifySSL,
			"client_cert":       spec.clientCert,
			"client_key":        spec.clientKey,
			"client_cert_value": spec.clientCertValue,
			"client_key_value":  spec.clientKeyValue,
			"search_filter":     "(uid=%s)",
			"search_base_dns":   []string{"dc=example,dc=org"},
			"attributes": map[string]any{
				"username": "uid",
			},
		})
	}

	sso := ssosettingstests.NewFakeService()
	sso.ExpectedSSOSetting = &models.SSOSettings{
		Provider: "ldap",
		Settings: map[string]any{
			"enabled":       true,
			"allow_sign_up": true,
			"config": map[string]any{
				"servers": servers,
			},
		},
	}

	ldapSvc := ldapservice.ProvideService(setting.NewCfg(), featuremgmt.WithFeatures(), sso)
	require.True(t, ldapSvc.Enabled())
	require.NotNil(t, ldapSvc.Client())
	require.Len(t, ldapSvc.Config().Servers, len(specs))

	cfg := setting.NewCfg()
	cfg.LDAPAuthEnabled = true
	registry := bundleregistry.ProvideService()
	ldapapi.ProvideService(
		cfg,
		routing.NewRouteRegister(),
		acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		usertest.NewUserServiceFake(),
		&authinfotest.FakeService{},
		ldap.ProvideGroupsService(),
		&authntest.FakeService{},
		&orgtest.FakeOrgService{},
		ldapSvc,
		authtest.NewFakeUserAuthTokenService(),
		registry,
	)
	_, registered := registry.Collectors()["auth-ldap"]
	require.True(t, registered, "auth-ldap collector was not registered")

	bundles := &Service{
		log:            log.New("test"),
		bundleRegistry: registry,
		store:          newStore(kvstore.NewFakeKVStore()),
		tracer:         tracing.InitializeTracerForTest(),
	}
	return ldapSvc, bundles
}

// collectAuthLDAP posts the collector list the support-bundle API accepts and
// waits until that collector has finished.
func collectAuthLDAP(t *testing.T, bundles *Service) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/support-bundles", strings.NewReader(`{"collectors":["auth-ldap"]}`))
	req.Header.Set("Content-Type", "application/json")
	resp := bundles.handleCreate(&contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{UserID: 1, Login: "placeholder-admin"},
	})
	require.Equal(t, http.StatusCreated, resp.Status())
	created, ok := resp.(*response.NormalResponse)
	require.True(t, ok)
	var accepted supportbundles.Bundle
	require.NoError(t, json.Unmarshal(created.Body(), &accepted))
	require.NotEmpty(t, accepted.UID)

	deadline := time.Now().Add(15 * time.Second)
	var stored *supportbundles.Bundle
	for time.Now().Before(deadline) {
		got, err := bundles.get(context.Background(), accepted.UID)
		require.NoError(t, err)
		if got.State != supportbundles.StatePending {
			require.Equal(t, supportbundles.StateComplete, got.State)
			stored = got
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotNil(t, stored, "auth-ldap bundle did not finish")
	return ldapMarkdown(t, stored.TarBytes)
}

func ldapMarkdown(t *testing.T, tarGz []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(tarGz))
	require.NoError(t, err)
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if strings.HasSuffix(hdr.Name, "ldap.md") {
			body, err := io.ReadAll(tr)
			require.NoError(t, err)
			return string(body)
		}
	}
	t.Fatal("auth-ldap collector did not write ldap.md")
	return ""
}

type ldapRecorder struct {
	Addr string

	ln        net.Listener
	tlsConfig *tls.Config

	mu        sync.Mutex
	passwords []string
	peerCerts [][]byte
}

func startLDAPRecorder(t *testing.T, tlsConfig *tls.Config) *ldapRecorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	rec := &ldapRecorder{Addr: ln.Addr().String(), ln: ln, tlsConfig: tlsConfig}
	go rec.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return rec
}

func (r *ldapRecorder) accept() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(conn)
	}
}

func (r *ldapRecorder) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	plain := conn
	if r.tlsConfig != nil {
		tlsConn := tls.Server(conn, r.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		state := tlsConn.ConnectionState()
		r.mu.Lock()
		for _, cert := range state.PeerCertificates {
			r.peerCerts = append(r.peerCerts, append([]byte(nil), cert.Raw...))
		}
		r.mu.Unlock()
		plain = tlsConn
	}

	packet, err := ber.ReadPacket(bufio.NewReader(plain))
	if err != nil {
		return
	}
	id, password, ok := simpleBind(packet)
	if !ok {
		return
	}
	r.mu.Lock()
	r.passwords = append(r.passwords, password)
	r.mu.Unlock()
	_ = writeBindResult(plain, id, ldapv3.LDAPResultInvalidCredentials)
}

func (r *ldapRecorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passwords = nil
	r.peerCerts = nil
}

func (r *ldapRecorder) Passwords() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.passwords))
	copy(out, r.passwords)
	return out
}

func (r *ldapRecorder) PeerCerts() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.peerCerts))
	copy(out, r.peerCerts)
	return out
}

// simpleBind reads the simple-bind request produced by go-ldap Conn.Bind:
// LDAPMessage { messageID, BindRequest { version, name, authentication } }.
func simpleBind(packet *ber.Packet) (int64, string, bool) {
	if packet == nil || len(packet.Children) < 2 {
		return 0, "", false
	}
	id, ok := packet.Children[0].Value.(int64)
	if !ok {
		return 0, "", false
	}
	req := packet.Children[1]
	if req.ClassType != ber.ClassApplication || req.Tag != ber.Tag(ldapv3.ApplicationBindRequest) || len(req.Children) < 3 {
		return 0, "", false
	}
	password := req.Children[2]
	if password.ClassType != ber.ClassContext || password.Tag != 0 || password.Data == nil {
		return 0, "", false
	}
	return id, password.Data.String(), true
}

func writeBindResult(conn net.Conn, messageID int64, resultCode int64) error {
	// NewInteger writes the integer payload. Encode alone stores the Go value
	// and leaves the BER contents empty, which the client reads back as zero.
	bindResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldapv3.ApplicationBindResponse), nil, "Bind Response")
	bindResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, resultCode, "resultCode"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	packet := ber.NewSequence("LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))
	packet.AppendChild(bindResponse)
	_, err := conn.Write(packet.Bytes())
	return err
}

type issuedCert struct {
	ca      *x509.Certificate
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
	certB64 string
	keyB64  string
}

func issueClientAndServer(t *testing.T) (client issuedCert, server issuedCert) {
	t.Helper()
	ca := issueCert(t, true, x509.ExtKeyUsageAny, nil, nil)
	client = issueCert(t, false, x509.ExtKeyUsageClientAuth, ca.cert, ca.key)
	client.ca = ca.cert
	server = issueCert(t, false, x509.ExtKeyUsageServerAuth, ca.cert, ca.key)
	return client, server
}

func issueCert(t *testing.T, isCA bool, usage x509.ExtKeyUsage, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) issuedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "placeholder-ldap"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	if isCA {
		tpl.IsCA = true
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
		tpl.Subject.CommonName = "placeholder-ldap-ca"
	}
	if usage == x509.ExtKeyUsageServerAuth {
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tpl.Subject.CommonName = "placeholder-ldap-server"
	}
	signerCert := tpl
	signerKey := key
	if parent != nil {
		signerCert = parent
		signerKey = parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, key.Public(), signerKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return issuedCert{
		cert:    parsed,
		key:     key,
		certPEM: certPEM,
		keyPEM:  keyPEM,
		certB64: base64.StdEncoding.EncodeToString(certPEM),
		keyB64:  base64.StdEncoding.EncodeToString(keyPEM),
	}
}

func serverTLSConfig(server issuedCert, ca *x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{server.cert.Raw},
			PrivateKey:  server.key,
			Leaf:        server.cert,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}
}
