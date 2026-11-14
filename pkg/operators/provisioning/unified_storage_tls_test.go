package provisioning

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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// The provisioning operator dials unified storage through setupUnifiedStorageClient.
// [unified_storage] grpc_address and grpc_index_address follow the same rule as
// the grafana-apiserver client: a non-loopback address is refused before dial
// unless TLS is configured.
//
//	grpc_use_tls         bool
//	grpc_tls_ca_file     PEM CA that signed the store certificate
//	grpc_tls_server_name name checked against that certificate
//
// The refusal error has to say "tls" or "transport security".

const (
	provisioningTLSEnabledKey = "grpc_use_tls"
	provisioningTLSCAKey      = "grpc_tls_ca_file"
	provisioningTLSNameKey    = "grpc_tls_server_name"
	provisioningSearchMarker  = "provisioning-plaintext-search-marker"
	provisioningStoreName     = "resource-store.test"
)

func TestSetupUnifiedStorageClientRefusesRemotePlaintext(t *testing.T) {
	host := provisioningNonLoopbackHost(t)
	ln := provisioningListenCount(t, host)
	cfg := setting.NewCfg()
	sec := cfg.Raw.Section("unified_storage")
	sec.Key("grpc_address").SetValue(ln.Addr().String())
	sec.Key("grpc_index_address").SetValue(ln.Addr().String())
	sec.Key("audiences").SetValue("resourceStore")

	_, err := setupUnifiedStorageClient(cfg, tracing.InitializeTracerForTest(), prometheus.NewRegistry(), provisioningAuth(tokenExchangeURL(t)))
	require.Zero(t, ln.n.Load(), "plaintext dial opened a connection before it was refused")
	require.Error(t, err)
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "tls") && !strings.Contains(msg, "transport security") {
		t.Fatalf("refusal error must name tls or transport security, got %v", err)
	}
}

func TestSetupUnifiedStorageClientEncryptsRemoteSearch(t *testing.T) {
	host := provisioningNonLoopbackHost(t)
	ca, caPEM := provisioningCA(t)
	certPEM, keyPEM := provisioningServerCert(t, ca, provisioningStoreName)
	backend, seen := provisioningTLSServer(t, certPEM, keyPEM)
	proxy, tap := provisioningProxy(t, host, backend)

	cfg := setting.NewCfg()
	sec := cfg.Raw.Section("unified_storage")
	sec.Key("grpc_address").SetValue(proxy)
	sec.Key("grpc_index_address").SetValue(proxy)
	sec.Key("audiences").SetValue("resourceStore")
	sec.Key(provisioningTLSEnabledKey).SetValue("true")
	sec.Key(provisioningTLSCAKey).SetValue(provisioningWritePEM(t, caPEM))
	sec.Key(provisioningTLSNameKey).SetValue(provisioningStoreName)

	client, err := setupUnifiedStorageClient(cfg, tracing.InitializeTracerForTest(), prometheus.NewRegistry(), provisioningAuth(tokenExchangeURL(t)))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = identity.WithServiceIdentityContext(ctx, 1)
	_, err = client.Search(ctx, &resourcepb.ResourceSearchRequest{Query: provisioningSearchMarker})
	raw := tap.snapshot()
	if bytes.Contains(raw, []byte("PRI * HTTP/2.0")) {
		t.Fatalf("gRPC connection preface on the path to unified storage was plaintext HTTP/2 (rpc err: %v)", err)
	}
	if bytes.Contains(raw, []byte(provisioningSearchMarker)) {
		t.Fatalf("search query was readable on the TCP path (rpc err: %v)", err)
	}
	require.NoError(t, err)
	require.True(t, seen.has(provisioningSearchMarker))
}

func provisioningAuth(exchangeURL string) resource.RemoteResourceClientConfig {
	return resource.RemoteResourceClientConfig{
		Token:            "placeholder-token",
		TokenExchangeURL: exchangeURL,
		Namespace:        "stack",
		Audiences:        []string{"resourceStore"},
	}
}

func tokenExchangeURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"token":"placeholder-token"}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

type provisioningTape struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (t *provisioningTape) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.b.Write(p)
}

func (t *provisioningTape) snapshot() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.b.Bytes()...)
}

type provisioningSeen struct {
	mu    sync.Mutex
	blobs [][]byte
}

func (s *provisioningSeen) add(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs = append(s.blobs, append([]byte(nil), b...))
}

func (s *provisioningSeen) has(marker string) bool {
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

type provisioningCountLn struct {
	net.Listener
	n atomic.Int32
}

func (c *provisioningCountLn) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}

func provisioningListenCount(t *testing.T, host string) *provisioningCountLn {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	cl := &provisioningCountLn{Listener: ln}
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

func provisioningNonLoopbackHost(t *testing.T) string {
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
	t.Fatal("no non-loopback IPv4 address")
	return ""
}

func provisioningProxy(t *testing.T, host, backend string) (string, *provisioningTape) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	tap := &provisioningTape{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				server, err := net.Dial("tcp", backend)
				if err != nil {
					return
				}
				defer server.Close()
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = io.Copy(server, io.TeeReader(c, tap))
					_ = server.Close()
				}()
				go func() {
					defer wg.Done()
					_, _ = io.Copy(c, io.TeeReader(server, tap))
					_ = c.Close()
				}()
				wg.Wait()
			}(c)
		}
	}()
	return ln.Addr().String(), tap
}

type provisioningCAMaterial struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func provisioningCA(t *testing.T) (provisioningCAMaterial, []byte) {
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
	return provisioningCAMaterial{cert: parsed, key: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func provisioningServerCert(t *testing.T, ca provisioningCAMaterial, name string) (certPEM, keyPEM []byte) {
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

func provisioningWritePEM(t *testing.T, pemBytes []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func provisioningTLSServer(t *testing.T, certPEM, keyPEM []byte) (string, *provisioningSeen) {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	seen := &provisioningSeen{}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})),
		grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
			method, _ := grpc.MethodFromServerStream(stream)
			if method != resourcepb.ResourceIndex_Search_FullMethodName {
				return status.Errorf(codes.Unimplemented, "%s", method)
			}
			var req resourcepb.ResourceSearchRequest
			if err := stream.RecvMsg(&req); err != nil {
				return err
			}
			seen.add([]byte(req.Query))
			return stream.SendMsg(&resourcepb.ResourceSearchResponse{})
		}),
	)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = ln.Close()
	})
	return ln.Addr().String(), seen
}
