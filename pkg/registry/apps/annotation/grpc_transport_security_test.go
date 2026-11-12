package annotation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	annotationV0 "github.com/grafana/grafana/apps/annotation/pkg/apis/annotation/v0alpha1"
	storev1 "github.com/grafana/grafana/pkg/registry/apps/annotation/storepb/v1"
	"github.com/grafana/grafana/pkg/setting"
)

// Security contract for the annotation gRPC store client. A remote backend must
// not receive annotation bodies on an unauthenticated or unencrypted connection.
// The assertions fail while newGRPCStore still dials that way.

const (
	annotationPanelID = int64(867530901234)
	h2cPreface        = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

func TestAnnotationRemoteGRPCOmitsCleartextBodies(t *testing.T) {
	host := dialableRemoteName(t)
	modes := []tlsMode{tlsModeShippedDefault, tlsModeExplicitOff, tlsModeFlagDefault, tlsModeFlagExplicitOff}
	if host != "" {
		modes = append(modes, tlsMode{
			name:       "hostname-explicit-off",
			refuseDial: true,
			config: func(t *testing.T, addr string) Config {
				t.Helper()
				_, port, err := net.SplitHostPort(addr)
				require.NoError(t, err)
				return loadAnnotationGRPCConfig(t, net.JoinHostPort(host, port), map[string]string{
					"enabled":       "true",
					"store_backend": "grpc",
					"grpc_use_tls":  "false",
				})
			},
		})
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			for _, op := range annotationGRPCOps() {
				t.Run(op.name, func(t *testing.T) {
					peer, addr := startAnnotationPeer(t, nil)
					cfg := mode.config(t, addr)
					if mode.requiresTLSDefault {
						if !cfg.GRPCUseTLS {
							t.Errorf("grpc TLS must default on; got grpc_use_tls=false for %s", mode.name)
						}
					}
					assertRemoteAnnotationRPCRefusedInClear(t, cfg, peer, op, mode.refuseDial)
				})
			}
		})
	}
}

func TestAnnotationGRPCSkipVerifyDoesNotDeliverBodies(t *testing.T) {
	cert := testServerCertificate(t)
	for _, op := range annotationGRPCOps() {
		t.Run(op.name, func(t *testing.T) {
			peer, addr := startAnnotationPeer(t, &tls.Config{Certificates: []tls.Certificate{cert}})
			cfg := loadAnnotationGRPCConfig(t, addr, map[string]string{
				"enabled":              "true",
				"store_backend":        "grpc",
				"grpc_use_tls":         "true",
				"grpc_tls_skip_verify": "true",
			})
			assertPeerDidNotObserve(t, cfg, peer, op)
		})
	}
}

func TestAnnotationGRPCVerifiedTLSRejectsUntrustedServer(t *testing.T) {
	cert := testServerCertificate(t)
	for _, op := range annotationGRPCOps() {
		t.Run(op.name, func(t *testing.T) {
			peer, addr := startAnnotationPeer(t, &tls.Config{Certificates: []tls.Certificate{cert}})
			cfg := loadAnnotationGRPCConfig(t, addr, map[string]string{
				"enabled":       "true",
				"store_backend": "grpc",
				"grpc_use_tls":  "true",
			})
			assertPeerDidNotObserve(t, cfg, peer, op)
		})
	}
}

type tlsMode struct {
	name               string
	requiresTLSDefault bool
	refuseDial         bool
	config             func(t *testing.T, addr string) Config
}

var (
	tlsModeShippedDefault = tlsMode{
		name:               "ini-shipped-default",
		requiresTLSDefault: true,
		config: func(t *testing.T, addr string) Config {
			t.Helper()
			// grpc_use_tls is left unset so conf/defaults.ini and the loader default apply.
			return loadAnnotationGRPCConfig(t, addr, map[string]string{
				"enabled":       "true",
				"store_backend": "grpc",
			})
		},
	}
	tlsModeExplicitOff = tlsMode{
		name:       "ini-explicit-off",
		refuseDial: true,
		config: func(t *testing.T, addr string) Config {
			t.Helper()
			return loadAnnotationGRPCConfig(t, addr, map[string]string{
				"enabled":       "true",
				"store_backend": "grpc",
				"grpc_use_tls":  "false",
			})
		},
	}
	tlsModeFlagDefault = tlsMode{
		name:               "flag-default",
		requiresTLSDefault: true,
		config: func(t *testing.T, addr string) Config {
			t.Helper()
			return configFromAnnotationFlags(t, addr, nil)
		},
	}
	tlsModeFlagExplicitOff = tlsMode{
		name:       "flag-explicit-off",
		refuseDial: true,
		config: func(t *testing.T, addr string) Config {
			t.Helper()
			return configFromAnnotationFlags(t, addr, []string{"--annotation.grpc-use-tls=false"})
		},
	}
)

type annotationOp struct {
	name    string
	markers [][]byte
	run     func(ctx context.Context, store Store) error
}

func annotationGRPCOps() []annotationOp {
	text := "incident-note-body"
	tag := "incident-tag"
	dashboard := "dash-uid-remote"
	scope := "scope-remote"
	name := "anno-remote-name"
	panel := annotationPanelID
	panelKey := protoField(&storev1.AnnotationSpec{PanelId: &panel})
	listPanelKey := protoField(&storev1.ListOptions{PanelId: panel})

	anno := func(body string) *annotationV0.Annotation {
		return &annotationV0.Annotation{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "org-1"},
			Spec: annotationV0.AnnotationSpec{
				Text:         body,
				Time:         1_700_000_000_000,
				Tags:         []string{tag},
				Scopes:       []string{scope},
				DashboardUID: &dashboard,
				PanelID:      &panel,
			},
		}
	}

	bodyMarkers := func(body string) [][]byte {
		return [][]byte{[]byte(body), []byte(tag), []byte(dashboard), []byte(scope), []byte(name), panelKey}
	}

	return []annotationOp{
		{
			name:    "create",
			markers: bodyMarkers(text + "-create"),
			run: func(ctx context.Context, store Store) error {
				_, err := store.Create(ctx, anno(text+"-create"))
				return err
			},
		},
		{
			name:    "update",
			markers: bodyMarkers(text + "-update"),
			run: func(ctx context.Context, store Store) error {
				_, err := store.Update(ctx, anno(text+"-update"))
				return err
			},
		},
		{
			name:    "get",
			markers: bodyMarkers(text + "-get"),
			run: func(ctx context.Context, store Store) error {
				_, err := store.Get(ctx, "org-1", name)
				return err
			},
		},
		{
			name:    "list",
			markers: [][]byte{[]byte(tag), []byte(dashboard), []byte(scope), []byte(text + "-get"), listPanelKey},
			run: func(ctx context.Context, store Store) error {
				_, err := store.List(ctx, "org-1", ListOptions{
					DashboardUID: dashboard,
					PanelID:      panel,
					Tags:         []string{tag},
					Scopes:       []string{scope},
					Limit:        1,
				})
				return err
			},
		},
		{
			name:    "delete",
			markers: [][]byte{[]byte(name)},
			run: func(ctx context.Context, store Store) error {
				return store.Delete(ctx, "org-1", name)
			},
		},
		{
			name: "cleanup",
			run: func(ctx context.Context, store Store) error {
				life, ok := store.(LifecycleManager)
				if !ok {
					return errNotLifecycle
				}
				_, err := life.Cleanup(ctx, time.UnixMilli(1_700_000_000_000))
				return err
			},
		},
		{
			name:    "list-tags",
			markers: [][]byte{[]byte(tag)},
			run: func(ctx context.Context, store Store) error {
				tags, ok := store.(TagProvider)
				if !ok {
					return errNotTagProvider
				}
				_, err := tags.ListTags(ctx, "org-1", TagListOptions{Prefix: tag, Limit: 1})
				return err
			},
		},
	}
}

var (
	errNotLifecycle   = errOp("store does not implement LifecycleManager")
	errNotTagProvider = errOp("store does not implement TagProvider")
)

type errOp string

func (e errOp) Error() string { return string(e) }

func assertRemoteAnnotationRPCRefusedInClear(t *testing.T, cfg Config, peer *annotationPeer, op annotationOp, refuseDial bool) {
	t.Helper()
	store, openErr := createStore(context.Background(), cfg, nil, nil, nil)
	var opErr error
	if openErr == nil {
		if _, ok := store.(*storeGRPC); !ok {
			t.Fatalf("store_backend grpc returned %T", store)
		}
		t.Cleanup(func() { _ = store.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		opErr = op.run(ctx, store)
	}

	captured := peer.bytes()
	if bytes.Contains(captured, []byte(h2cPreface)) {
		t.Errorf("%s spoke plaintext HTTP/2 to non-loopback %s", op.name, peer.addr)
	}
	for _, marker := range op.markers {
		if bytes.Contains(captured, marker) {
			t.Errorf("%s exposed %q in cleartext on %s", op.name, marker, peer.addr)
		}
	}
	if openErr == nil && opErr == nil {
		t.Errorf("%s completed against a peer that does not offer the client's authenticated TLS", op.name)
	}
	if len(peer.observed()) > 0 {
		t.Errorf("%s delivered annotation fields to the remote peer: %q", op.name, peer.observed())
	}
	if refuseDial && peer.accepts() != 0 {
		t.Errorf("%s accepted %d connection(s) to non-loopback %s before refusing plaintext", op.name, peer.accepts(), peer.addr)
	}
	if refuseDial && openErr == nil && opErr == nil {
		t.Errorf("%s was not refused when grpc TLS was off", op.name)
	}
}

func assertPeerDidNotObserve(t *testing.T, cfg Config, peer *annotationPeer, op annotationOp) {
	t.Helper()
	store, openErr := createStore(context.Background(), cfg, nil, nil, nil)
	var opErr error
	if openErr == nil {
		if _, ok := store.(*storeGRPC); !ok {
			t.Fatalf("store_backend grpc returned %T", store)
		}
		t.Cleanup(func() { _ = store.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		opErr = op.run(ctx, store)
	}
	if openErr == nil && opErr == nil {
		t.Errorf("%s completed without a trusted server certificate", op.name)
	}
	if observed := peer.observed(); len(observed) > 0 {
		t.Errorf("%s delivered annotation fields to an untrusted server: %q", op.name, observed)
	}
	for _, marker := range op.markers {
		if bytes.Contains(peer.bytes(), marker) {
			t.Errorf("%s exposed %q on the connection to an untrusted server", op.name, marker)
		}
	}
}

func loadAnnotationGRPCConfig(t *testing.T, addr string, keys map[string]string) Config {
	t.Helper()
	clearAnnotationEnv(t)

	dir := t.TempDir()
	overlay := filepath.Join(dir, "custom.ini")
	var buf bytes.Buffer
	buf.WriteString("[paths]\n")
	buf.WriteString("data = " + filepath.Join(dir, "data") + "\n")
	buf.WriteString("logs = " + filepath.Join(dir, "logs") + "\n")
	buf.WriteString("plugins = " + filepath.Join(dir, "plugins") + "\n")
	buf.WriteString("provisioning = " + filepath.Join(dir, "provisioning") + "\n")
	buf.WriteString("\n[annotations.app_platform]\n")
	buf.WriteString("grpc_address = " + addr + "\n")
	for k, v := range keys {
		buf.WriteString(k + " = " + v + "\n")
	}
	require.NoError(t, os.WriteFile(overlay, buf.Bytes(), 0o600))

	cfg, err := setting.NewCfgFromArgs(setting.CommandLineArgs{
		HomePath: grafanaRoot(t),
		Config:   overlay,
	})
	require.NoError(t, err)
	loaded := newConfigFromSettings(cfg)
	if loaded.StoreBackend != "grpc" {
		t.Fatalf("store backend = %q", loaded.StoreBackend)
	}
	if loaded.GRPCAddress != addr {
		t.Fatalf("grpc address = %q, want %s", loaded.GRPCAddress, addr)
	}
	return loaded
}

func configFromAnnotationFlags(t *testing.T, addr string, extra []string) Config {
	t.Helper()
	var cfg Config
	fs := pflag.NewFlagSet("annotation", pflag.ContinueOnError)
	cfg.AddFlags(fs)
	args := append([]string{
		"--annotation.store-backend=grpc",
		"--annotation.grpc-address=" + addr,
	}, extra...)
	require.NoError(t, fs.Parse(args))
	if cfg.GRPCAddress != addr {
		t.Fatalf("grpc address = %q, want %s", cfg.GRPCAddress, addr)
	}
	return cfg
}

func clearAnnotationEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"GF_ANNOTATIONS_APP_PLATFORM_ENABLED",
		"GF_ANNOTATIONS_APP_PLATFORM_STORE_BACKEND",
		"GF_ANNOTATIONS_APP_PLATFORM_GRPC_ADDRESS",
		"GF_ANNOTATIONS_APP_PLATFORM_GRPC_USE_TLS",
		"GF_ANNOTATIONS_APP_PLATFORM_GRPC_TLS_CA_FILE",
		"GF_ANNOTATIONS_APP_PLATFORM_GRPC_TLS_SKIP_VERIFY",
		"GF_PATHS_DATA",
		"GF_PATHS_LOGS",
		"GF_PATHS_PLUGINS",
		"GF_PATHS_PROVISIONING",
	} {
		t.Setenv(key, "")
	}
}

func grafanaRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../../..")
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "conf", "defaults.ini"))
	require.NoError(t, err)
	return root
}

type annotationPeer struct {
	addr string
	ln   *recordingListener
	srv  *grpc.Server

	mu    sync.Mutex
	seen  []string
	reply *storev1.Annotation
}

func startAnnotationPeer(t *testing.T, serverTLS *tls.Config) (*annotationPeer, string) {
	t.Helper()
	ip := nonLoopbackIPv4(t)
	ln, err := net.Listen("tcp", ip.String()+":0")
	require.NoError(t, err)
	rec := &recordingListener{Listener: ln}
	addr := ln.Addr().String()
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	parsed := net.ParseIP(host)
	require.NotNil(t, parsed)
	require.False(t, parsed.IsLoopback(), "test address %s is loopback", addr)

	panel := annotationPanelID
	dashboard := "dash-uid-remote"
	peer := &annotationPeer{
		addr: addr,
		ln:   rec,
		reply: &storev1.Annotation{
			Name:      "anno-remote-name",
			Namespace: "org-1",
			Spec: &storev1.AnnotationSpec{
				Text:         "incident-note-body-get",
				Tags:         []string{"incident-tag"},
				Scopes:       []string{"scope-remote"},
				DashboardUid: &dashboard,
				PanelId:      &panel,
			},
		},
	}
	var opts []grpc.ServerOption
	if serverTLS != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(serverTLS)))
	}
	peer.srv = grpc.NewServer(opts...)
	storev1.RegisterAnnotationStoreServer(peer.srv, peer)
	go func() {
		_ = peer.srv.Serve(rec)
	}()
	t.Cleanup(func() {
		peer.srv.Stop()
		_ = ln.Close()
	})
	return peer, addr
}

func (p *annotationPeer) accepts() int {
	p.ln.mu.Lock()
	defer p.ln.mu.Unlock()
	return p.ln.accepts
}

func (p *annotationPeer) bytes() []byte {
	p.ln.mu.Lock()
	defer p.ln.mu.Unlock()
	return append([]byte(nil), p.ln.buf.Bytes()...)
}

func (p *annotationPeer) observed() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.seen))
	copy(out, p.seen)
	return out
}

func (p *annotationPeer) note(vals ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range vals {
		if v != "" {
			p.seen = append(p.seen, v)
		}
	}
}

func (p *annotationPeer) noteAnnotation(anno *storev1.Annotation) {
	if anno == nil {
		return
	}
	p.note(anno.GetName(), anno.GetNamespace())
	if spec := anno.GetSpec(); spec != nil {
		p.note(spec.GetText(), spec.GetDashboardUid())
		p.note(spec.GetTags()...)
		p.note(spec.GetScopes()...)
	}
}

func (p *annotationPeer) Get(context.Context, *storev1.GetRequest) (*storev1.GetResponse, error) {
	p.noteAnnotation(p.reply)
	return &storev1.GetResponse{Annotation: p.reply}, nil
}

func (p *annotationPeer) List(_ context.Context, req *storev1.ListRequest) (*storev1.ListResponse, error) {
	opts := req.GetOptions()
	if opts != nil {
		p.note(opts.GetDashboardUid())
		p.note(opts.GetTags()...)
		p.note(opts.GetScopes()...)
	}
	p.noteAnnotation(p.reply)
	return &storev1.ListResponse{Items: []*storev1.Annotation{p.reply}}, nil
}

func (p *annotationPeer) Create(_ context.Context, req *storev1.CreateRequest) (*storev1.CreateResponse, error) {
	p.noteAnnotation(req.GetAnnotation())
	return &storev1.CreateResponse{Annotation: req.GetAnnotation()}, nil
}

func (p *annotationPeer) Update(_ context.Context, req *storev1.UpdateRequest) (*storev1.UpdateResponse, error) {
	p.noteAnnotation(req.GetAnnotation())
	return &storev1.UpdateResponse{Annotation: req.GetAnnotation()}, nil
}

func (p *annotationPeer) Delete(_ context.Context, req *storev1.DeleteRequest) (*storev1.DeleteResponse, error) {
	p.note(req.GetNamespace(), req.GetName())
	return &storev1.DeleteResponse{}, nil
}

func (p *annotationPeer) Cleanup(context.Context, *storev1.CleanupRequest) (*storev1.CleanupResponse, error) {
	p.note("cleanup")
	return &storev1.CleanupResponse{}, nil
}

func (p *annotationPeer) ListTags(_ context.Context, req *storev1.ListTagsRequest) (*storev1.ListTagsResponse, error) {
	if opts := req.GetOptions(); opts != nil {
		p.note(opts.GetPrefix(), opts.GetContains())
	}
	return &storev1.ListTagsResponse{Tags: []*storev1.Tag{{Name: "incident-tag", Count: 1}}}, nil
}

type recordingListener struct {
	net.Listener
	mu      sync.Mutex
	buf     bytes.Buffer
	accepts int
}

func (l *recordingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.accepts++
	l.mu.Unlock()
	return &recordingConn{Conn: conn, rec: l}, nil
}

type recordingConn struct {
	net.Conn
	rec *recordingListener
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rec.record(p[:n])
	}
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.rec.record(p[:n])
	}
	return n, err
}

func (l *recordingListener) record(p []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.buf.Write(p)
}

func dialableRemoteName(t *testing.T) string {
	t.Helper()
	ip := nonLoopbackIPv4(t)
	path := filepath.Join(t.TempDir(), "hostaliases")
	const name = "annoremote"
	require.NoError(t, os.WriteFile(path, []byte(name+" "+ip.String()+"\n"), 0o600))
	t.Setenv("HOSTALIASES", path)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil {
		t.Logf("hostname dial not covered; HOSTALIASES lookup failed: %v", err)
		return ""
	}
	for _, got := range ips {
		if got.IP.Equal(ip) {
			return name
		}
	}
	t.Logf("hostname dial not covered; %s resolved to %v, want %s", name, ips, ip)
	return ""
}

func nonLoopbackIPv4(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, addr := range addrs {
		ipn, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		return ip
	}
	t.Fatal("no non-loopback IPv4 address available")
	return nil
}

func testServerCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "annotation.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"annotation.invalid"},
		IPAddresses:  []net.IP{net.ParseIP("192.0.2.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func protoField(msg proto.Message) []byte {
	b, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	return b
}
