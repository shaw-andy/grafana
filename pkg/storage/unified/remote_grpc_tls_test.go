package unified

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	authnlib "github.com/grafana/authlib/authn"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// Remote unified-grpc dials must protect dashboard and search payloads on any
// path that is not loopback. These tests are the spec for that behavior.
//
// [grafana-apiserver] keys the client has to honor:
//
//	grpc_client_tls_enabled      bool
//	grpc_client_tls_ca_file      PEM file of the CA that signed the store certificate
//	grpc_client_tls_server_name  name checked against the store certificate
//
// When grpc_client_tls_enabled is off or the CA does not verify the peer, a
// hostname other than localhost, or an IP that is not loopback, must be refused
// before a TCP connection is opened. The error text has to say "tls" or
// "transport security". Loopback (127.0.0.0/8, ::1, localhost) and unspecified
// hosts (empty, 0.0.0.0, ::) are outside these tests; in-process callers use them.
//
// The same rules apply to address and to search_server_address, and to every
// constructor that dials the resource store: ProvideUnifiedStorageClient,
// NewRemoteResourceClientFromConfig, NewRemoteResourceClientWithAuth,
// NewSearchClient, and GrpcConn. List, Delete, Watch, Bulk, and Stats travel on
// the connection Create and Read use; they are not called on their own here.

const (
	tlsEnabledKey    = "grpc_client_tls_enabled"
	tlsCAFileKey     = "grpc_client_tls_ca_file"
	tlsServerNameKey = "grpc_client_tls_server_name"

	createMarker = `{"kind":"Dashboard","title":"remote-plaintext-create-marker"}`
	updateMarker = `{"kind":"Dashboard","title":"remote-plaintext-update-marker"}`
	readMarker   = `{"kind":"Dashboard","title":"remote-plaintext-read-marker"}`
	searchMarker = "remote-plaintext-search-marker"
	storeName    = "resource-store.test"
)

func TestRemoteUnifiedStorageRefusesPlaintextBeforeDial(t *testing.T) {
	host := nonLoopbackHost(t)
	ln := listenCount(t, host)

	t.Run("startup client", func(t *testing.T) {
		ln.n.Store(0)
		_, err := ProvideUnifiedStorageClient(storageOpts(cfgWithRemote(ln.Addr().String(), "")), nil, nil, nil, nil)
		requireRefusedBeforeDial(t, err, &ln.n)
	})

	t.Run("unresolvable hostname", func(t *testing.T) {
		_, err := ProvideUnifiedStorageClient(storageOpts(cfgWithRemote("unified-storage.invalid:443", "")), nil, nil, nil, nil)
		requireTLSRefusal(t, err)
	})

	t.Run("remote config client", func(t *testing.T) {
		ln.n.Store(0)
		_, err := NewRemoteResourceClientFromConfig(cfgWithRemote(ln.Addr().String(), ""), featuremgmt.WithFeatures(), nil, prometheus.NewRegistry())
		requireRefusedBeforeDial(t, err, &ln.n)
	})

	t.Run("authenticated remote client", func(t *testing.T) {
		ln.n.Store(0)
		_, err := NewRemoteResourceClientWithAuth(cfgWithRemote(ln.Addr().String(), ""), otel.Tracer("unified-storage-tls-test"), prometheus.NewRegistry(), placeholderAuth())
		requireRefusedBeforeDial(t, err, &ln.n)
	})

	t.Run("search client", func(t *testing.T) {
		ln.n.Store(0)
		cfg := setting.NewCfg()
		cfg.Raw.Section("grafana-apiserver").Key("search_server_address").SetValue(ln.Addr().String())
		_, err := NewSearchClient(cfg, featuremgmt.WithFeatures())
		requireRefusedBeforeDial(t, err, &ln.n)
	})

	t.Run("loopback storage with remote search", func(t *testing.T) {
		ln.n.Store(0)
		_, err := ProvideUnifiedStorageClient(storageOpts(cfgWithRemote("127.0.0.1:1", ln.Addr().String())), nil, nil, nil, nil)
		requireRefusedBeforeDial(t, err, &ln.n)
	})

	t.Run("grpc conn helper", func(t *testing.T) {
		ln.n.Store(0)
		_, err := GrpcConn(ln.Addr().String(), prometheus.NewRegistry())
		requireRefusedBeforeDial(t, err, &ln.n)
	})
}

func TestProvideUnifiedStorageClientDoesNotExposeDashboardBody(t *testing.T) {
	host := nonLoopbackHost(t)
	backend, seen := startPlainResourceServer(t)
	proxy, tap := startCaptureProxy(t, host, backend)
	_, caPEM := newCA(t)

	client, err := ProvideUnifiedStorageClient(
		storageOpts(cfgWithRemoteTLS(proxy, "", writePEM(t, caPEM), storeName)),
		nil, nil, nil, nil,
	)
	require.NoError(t, err)

	ctx, cancel := serviceCtx()
	defer cancel()
	_, err = client.Create(ctx, &resourcepb.CreateRequest{Value: []byte(createMarker)})
	if tap.contains(createMarker) || bytes.Contains(tap.snapshot(), []byte("PRI * HTTP/2.0")) {
		t.Fatalf("dashboard create was readable on the TCP path (body=%v http2 preface=%v rpc err=%v)",
			tap.contains(createMarker), bytes.Contains(tap.snapshot(), []byte("PRI * HTTP/2.0")), err)
	}
	require.Error(t, err)
	require.False(t, seen.has(createMarker))
}

func TestProvideUnifiedStorageClientEncryptsRemoteResourceAndSearch(t *testing.T) {
	host := nonLoopbackHost(t)
	ca, caPEM := newCA(t)
	certPEM, keyPEM := serverCert(t, ca, storeName)

	storageSrv, storageSeen := startTLSResourceServer(t, certPEM, keyPEM)
	searchSrv, searchSeen := startTLSResourceServer(t, certPEM, keyPEM)
	storageProxy, storageTap := startCaptureProxy(t, host, storageSrv)
	searchProxy, searchTap := startCaptureProxy(t, host, searchSrv)
	caFile := writePEM(t, caPEM)

	client, err := ProvideUnifiedStorageClient(
		storageOpts(cfgWithRemoteTLS(storageProxy, searchProxy, caFile, storeName)),
		nil, nil, nil, nil,
	)
	require.NoError(t, err)

	ctx, cancel := serviceCtx()
	defer cancel()
	_, err = client.Create(ctx, &resourcepb.CreateRequest{Value: []byte(createMarker)})
	requireEncrypted(t, storageTap, createMarker, err)
	require.NoError(t, err)
	require.True(t, storageSeen.has(createMarker), "resource store did not receive the create body")

	_, err = client.Update(ctx, &resourcepb.UpdateRequest{Value: []byte(updateMarker)})
	requireEncrypted(t, storageTap, updateMarker, err)
	require.NoError(t, err)
	require.True(t, storageSeen.has(updateMarker), "resource store did not receive the update body")

	_, err = client.Read(ctx, &resourcepb.ReadRequest{})
	requireEncrypted(t, storageTap, readMarker, err)
	require.NoError(t, err)

	_, err = client.Search(ctx, &resourcepb.ResourceSearchRequest{Query: searchMarker})
	requireEncrypted(t, searchTap, searchMarker, err)
	require.NoError(t, err)
	require.True(t, searchSeen.has(searchMarker), "search server did not receive the query")
	require.False(t, storageTap.contains(searchMarker), "search query was sent to the resource store")
}

func TestNewRemoteResourceClientFromConfigEncryptsRemoteTraffic(t *testing.T) {
	assertResourceWriteHidden(t, func(cfg *setting.Cfg) (resource.ResourceClient, error) {
		return NewRemoteResourceClientFromConfig(cfg, featuremgmt.WithFeatures(), nil, prometheus.NewRegistry())
	})
}

func TestNewRemoteResourceClientWithAuthEncryptsRemoteTraffic(t *testing.T) {
	assertResourceWriteHidden(t, func(cfg *setting.Cfg) (resource.ResourceClient, error) {
		return NewRemoteResourceClientWithAuth(cfg, otel.Tracer("unified-storage-tls-test"), prometheus.NewRegistry(), placeholderAuth())
	})
}

func TestNewSearchClientEncryptsRemoteQuery(t *testing.T) {
	host := nonLoopbackHost(t)
	ca, caPEM := newCA(t)
	certPEM, keyPEM := serverCert(t, ca, storeName)
	searchSrv, searchSeen := startTLSResourceServer(t, certPEM, keyPEM)
	searchProxy, searchTap := startCaptureProxy(t, host, searchSrv)

	cfg := setting.NewCfg()
	sec := cfg.Raw.Section("grafana-apiserver")
	sec.Key("search_server_address").SetValue(searchProxy)
	sec.Key(tlsEnabledKey).SetValue("true")
	sec.Key(tlsCAFileKey).SetValue(writePEM(t, caPEM))
	sec.Key(tlsServerNameKey).SetValue(storeName)

	client, err := NewSearchClient(cfg, featuremgmt.WithFeatures())
	require.NoError(t, err)

	ctx, cancel := serviceCtx()
	defer cancel()
	_, err = client.Search(ctx, &resourcepb.ResourceSearchRequest{Query: searchMarker})
	requireEncrypted(t, searchTap, searchMarker, err)
	require.NoError(t, err)
	require.True(t, searchSeen.has(searchMarker))
}

func TestRemoteUnifiedStorageRejectsUntrustedCertificate(t *testing.T) {
	host := nonLoopbackHost(t)
	ca, _ := newCA(t)
	_, otherPEM := newCA(t)
	certPEM, keyPEM := serverCert(t, ca, storeName)
	storageSrv, storageSeen := startTLSResourceServer(t, certPEM, keyPEM)
	storageProxy, storageTap := startCaptureProxy(t, host, storageSrv)

	t.Run("ca does not sign the store", func(t *testing.T) {
		storageSeen.reset()
		storageTap.reset()
		client, err := ProvideUnifiedStorageClient(
			storageOpts(cfgWithRemoteTLS(storageProxy, "", writePEM(t, otherPEM), storeName)),
			nil, nil, nil, nil,
		)
		require.NoError(t, err)
		ctx, cancel := serviceCtx()
		defer cancel()
		_, err = client.Create(ctx, &resourcepb.CreateRequest{Value: []byte(createMarker)})
		requireEncrypted(t, storageTap, createMarker, err)
		require.Error(t, err)
		require.False(t, storageSeen.has(createMarker), "store accepted a create the CA did not verify")
	})

	t.Run("server name does not match", func(t *testing.T) {
		storageSeen.reset()
		storageTap.reset()
		// Use the CA that signed the store so only the name check can fail.
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
		client, err := ProvideUnifiedStorageClient(
			storageOpts(cfgWithRemoteTLS(storageProxy, "", writePEM(t, caPEM), "other.example")),
			nil, nil, nil, nil,
		)
		require.NoError(t, err)
		ctx, cancel := serviceCtx()
		defer cancel()
		_, err = client.Create(ctx, &resourcepb.CreateRequest{Value: []byte(createMarker)})
		requireEncrypted(t, storageTap, createMarker, err)
		require.Error(t, err)
		require.False(t, storageSeen.has(createMarker), "store accepted a create for the wrong server name")
	})
}

func assertResourceWriteHidden(t *testing.T, dial func(*setting.Cfg) (resource.ResourceClient, error)) {
	t.Helper()
	host := nonLoopbackHost(t)
	ca, caPEM := newCA(t)
	certPEM, keyPEM := serverCert(t, ca, storeName)
	storageSrv, storageSeen := startTLSResourceServer(t, certPEM, keyPEM)
	storageProxy, storageTap := startCaptureProxy(t, host, storageSrv)

	client, err := dial(cfgWithRemoteTLS(storageProxy, "", writePEM(t, caPEM), storeName))
	require.NoError(t, err)
	ctx, cancel := serviceCtx()
	defer cancel()
	_, err = client.Create(ctx, &resourcepb.CreateRequest{Value: []byte(createMarker)})
	requireEncrypted(t, storageTap, createMarker, err)
	require.NoError(t, err)
	require.True(t, storageSeen.has(createMarker))
}

func storageOpts(cfg *setting.Cfg) *Options {
	return &Options{Cfg: cfg, Features: featuremgmt.WithFeatures(), Reg: prometheus.NewRegistry()}
}

func cfgWithRemote(address, search string) *setting.Cfg {
	cfg := setting.NewCfg()
	sec := cfg.Raw.Section("grafana-apiserver")
	sec.Key("storage_type").SetValue("unified-grpc")
	sec.Key("address").SetValue(address)
	if search != "" {
		sec.Key("search_server_address").SetValue(search)
	}
	return cfg
}

func cfgWithRemoteTLS(address, search, caFile, serverName string) *setting.Cfg {
	cfg := cfgWithRemote(address, search)
	sec := cfg.Raw.Section("grafana-apiserver")
	sec.Key(tlsEnabledKey).SetValue("true")
	sec.Key(tlsCAFileKey).SetValue(caFile)
	sec.Key(tlsServerNameKey).SetValue(serverName)
	return cfg
}

func placeholderAuth() resource.RemoteResourceClientConfig {
	return resource.RemoteResourceClientConfig{
		TokenExchanger: authnlib.NewStaticTokenExchanger("placeholder-token"),
		Namespace:      "stack",
		Audiences:      []string{"resourceStore"},
	}
}

func serviceCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	return identity.WithServiceIdentityContext(ctx, 1), cancel
}

func requireTLSRefusal(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "tls") && !strings.Contains(msg, "transport security") {
		t.Fatalf("refusal error must name tls or transport security, got %v", err)
	}
}

func requireRefusedBeforeDial(t *testing.T, err error, accepts *atomic.Int32) {
	t.Helper()
	require.Zero(t, accepts.Load(), "plaintext dial opened a connection before it was refused")
	requireTLSRefusal(t, err)
}

func requireEncrypted(t *testing.T, tap *tape, marker string, err error) {
	t.Helper()
	raw := tap.snapshot()
	if bytes.Contains(raw, []byte("PRI * HTTP/2.0")) {
		t.Fatalf("gRPC connection preface on the path to the remote store was plaintext HTTP/2 (rpc err: %v)", err)
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatalf("payload %q was readable on the TCP path to the remote store (rpc err: %v)", marker, err)
	}
	if len(raw) > 0 && (raw[0] != 0x16 || len(raw) < 3 || raw[1] != 0x03) {
		t.Fatalf("bytes on the path were not a TLS handshake record (rpc err: %v)", err)
	}
}

type tape struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (t *tape) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.b.Write(p)
}

func (t *tape) contains(marker string) bool {
	return bytes.Contains(t.snapshot(), []byte(marker))
}

func (t *tape) snapshot() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.b.Bytes()...)
}

func (t *tape) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b.Reset()
}

type seenBytes struct {
	mu    sync.Mutex
	blobs [][]byte
}

func (s *seenBytes) add(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs = append(s.blobs, append([]byte(nil), b...))
}

func (s *seenBytes) has(marker string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := []byte(marker)
	for _, b := range s.blobs {
		if bytes.Contains(b, want) {
			return true
		}
	}
	return false
}

func (s *seenBytes) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs = nil
}

type countListener struct {
	net.Listener
	n atomic.Int32
}

func (c *countListener) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}

func listenCount(t *testing.T, host string) *countListener {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	cl := &countListener{Listener: ln}
	go func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return cl
}

func nonLoopbackHost(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		require.NoError(t, err)
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			probe, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
			if err != nil {
				continue
			}
			_ = probe.Close()
			return ip.String()
		}
	}
	t.Fatal("no non-loopback IPv4 address to bind a remote-store listener")
	return ""
}

func startCaptureProxy(t *testing.T, host, backend string) (string, *tape) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	tap := &tape{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go proxyConn(c, backend, tap)
		}
	}()
	return ln.Addr().String(), tap
}

func proxyConn(client net.Conn, backend string, tap *tape) {
	defer client.Close()
	server, err := net.Dial("tcp", backend)
	if err != nil {
		return
	}
	defer server.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(server, io.TeeReader(client, tap))
		_ = server.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, io.TeeReader(server, tap))
		_ = client.Close()
	}()
	wg.Wait()
}

type tlsMaterial struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) (tlsMaterial, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "resource-store-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tlsMaterial{cert: parsed, key: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func serverCert(t *testing.T, ca tlsMaterial, name string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func writePEM(t *testing.T, pemBytes []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func startPlainResourceServer(t *testing.T) (string, *seenBytes) {
	t.Helper()
	return startResourceServer(t, nil)
}

func startTLSResourceServer(t *testing.T, certPEM, keyPEM []byte) (string, *seenBytes) {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return startResourceServer(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
}

func startResourceServer(t *testing.T, tlsCfg *tls.Config) (string, *seenBytes) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	seen := &seenBytes{}
	var opts []grpc.ServerOption
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	opts = append(opts, grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(stream)
		switch method {
		case resourcepb.ResourceStore_Create_FullMethodName:
			var req resourcepb.CreateRequest
			if err := stream.RecvMsg(&req); err != nil {
				return err
			}
			seen.add(req.Value)
			return stream.SendMsg(&resourcepb.CreateResponse{})
		case resourcepb.ResourceStore_Update_FullMethodName:
			var req resourcepb.UpdateRequest
			if err := stream.RecvMsg(&req); err != nil {
				return err
			}
			seen.add(req.Value)
			return stream.SendMsg(&resourcepb.UpdateResponse{})
		case resourcepb.ResourceStore_Read_FullMethodName:
			if err := stream.RecvMsg(&resourcepb.ReadRequest{}); err != nil {
				return err
			}
			return stream.SendMsg(&resourcepb.ReadResponse{Value: []byte(readMarker)})
		case resourcepb.ResourceIndex_Search_FullMethodName:
			var req resourcepb.ResourceSearchRequest
			if err := stream.RecvMsg(&req); err != nil {
				return err
			}
			seen.add([]byte(req.Query))
			return stream.SendMsg(&resourcepb.ResourceSearchResponse{})
		default:
			return status.Errorf(codes.Unimplemented, "%s", method)
		}
	}))
	srv := grpc.NewServer(opts...)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = ln.Close()
	})
	return ln.Addr().String(), seen
}
