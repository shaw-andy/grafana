package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// Trailer declarations are one HTTP/2 header field on the wire. net/http then
// inserts every comma-separated name into Request.Trailer. Go 1.26.9 charges
// each of those names against the header budget and returns 431 before the
// handler. Go 1.26.6, which this module builds with, only charges the single
// field, so a declaration that fits in MaxHeaderBytes still builds the map.
func TestHTTPServerHTTP2TrailerDeclarationStaysWithinHeaderBudget(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scheme  setting.Scheme
		network string
	}{
		{name: "h2", scheme: setting.HTTP2Scheme, network: "tcp"},
		{name: "socket_h2", scheme: setting.SocketHTTP2Scheme, network: "unix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertTrailerDeclarationRejected(t, tc.scheme, tc.network)
		})
	}
}

func assertTrailerDeclarationRejected(t *testing.T, scheme setting.Scheme, network string) {
	t.Helper()

	certFile, keyFile := writeServerCert(t)
	var called atomic.Bool
	var trailerLen atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		trailerLen.Store(int64(len(r.Trailer)))
		w.WriteHeader(http.StatusOK)
	})

	cfg := setting.NewCfg()
	cfg.Protocol = scheme
	cfg.MinTLSVersion = "TLS1.2"
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.HTTPAddr = "127.0.0.1"
	cfg.HTTPPort = "0"

	hs := &HTTPServer{
		Cfg: cfg,
		log: log.NewNopLogger(),
		httpSrv: &http.Server{
			Handler:     handler,
			ReadTimeout: cfg.ReadTimeout,
		},
	}
	require.NoError(t, hs.configureTLS())
	require.Contains(t, hs.httpSrv.TLSConfig.NextProtos, "h2")
	require.Nil(t, hs.httpSrv.TLSNextProto)
	require.Zero(t, hs.httpSrv.MaxHeaderBytes)

	ln := listenForScheme(t, network)
	errCh := make(chan error, 1)
	go func() {
		err := hs.httpSrv.ServeTLS(ln, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	t.Cleanup(func() {
		_ = hs.httpSrv.Close()
	})

	client, url := httpClientFor(t, ln)
	limit := headerListLimit(hs.httpSrv.MaxHeaderBytes)

	t.Run("within budget", func(t *testing.T) {
		called.Store(false)
		trailerLen.Store(0)
		keys := trailerKeys(3)
		resp := doTrailerRequest(t, client, url, keys)
		defer resp.Body.Close()
		require.Equal(t, "HTTP/2.0", resp.Proto)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, called.Load())
		require.Equal(t, len(keys), int(trailerLen.Load()))
	})

	t.Run("over per-field budget", func(t *testing.T) {
		called.Store(false)
		trailerLen.Store(0)
		keys := trailerKeys(overBudgetTrailerCount(limit))
		raw, accounted := trailerSizes(keys)
		require.LessOrEqual(t, raw, limit)
		require.Greater(t, accounted, limit)

		resp := doTrailerRequest(t, client, url, keys)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "HTTP/2.0", resp.Proto)
		require.Falsef(t, called.Load(),
			"handler ran with %d trailer fields (raw header %d bytes, per-field cost %d, limit %d)",
			trailerLen.Load(), raw, accounted, limit)
		require.Equalf(t, http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode,
			"body %q", body)

		select {
		case err := <-errCh:
			t.Fatalf("server: %v", err)
		default:
		}
	})
}

func listenForScheme(t *testing.T, network string) net.Listener {
	t.Helper()
	if network == "unix" {
		f, err := os.CreateTemp("/tmp", "gfh2-*.sock")
		require.NoError(t, err)
		path := f.Name()
		require.NoError(t, f.Close())
		require.NoError(t, os.Remove(path))
		t.Cleanup(func() { _ = os.Remove(path) })
		ln, err := net.Listen("unix", path)
		require.NoError(t, err)
		return ln
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return ln
}

func httpClientFor(t *testing.T, ln net.Listener) (*http.Client, string) {
	t.Helper()
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         "localhost",
	}
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: tlsCfg}
	url := "https://" + ln.Addr().String() + "/"
	if ln.Addr().Network() == "unix" {
		url = "https://localhost/"
		socketPath := ln.Addr().String()
		tr.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(c, tlsCfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, err
			}
			return tc, nil
		}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, url
}

func doTrailerRequest(t *testing.T, client *http.Client, url string, keys []string) *http.Response {
	t.Helper()
	var last error
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		req.Trailer = make(http.Header, len(keys))
		for _, k := range keys {
			req.Trailer[k] = nil
		}
		resp, err := client.Do(req)
		if err == nil {
			return resp
		}
		last = err
		if time.Now().After(deadline) {
			t.Fatalf("request: %v", last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func headerListLimit(maxHeaderBytes int) uint32 {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 1 << 20
	}
	// http2adjustHTTP1MaxHeaderSize pads by 32 bytes for 10 typical fields.
	return uint32(maxHeaderBytes + 10*32)
}

func trailerSizes(keys []string) (raw, accounted uint32) {
	value := strings.Join(keys, ",")
	fieldCount := len(keys)
	raw = uint32(len("trailer") + len(value) + 32)
	accounted = uint32(len(value)-fieldCount+1) + uint32(fieldCount)*32
	return raw, accounted
}

func overBudgetTrailerCount(limit uint32) int {
	// trailerKeys emits 4-character names, so the joined value is 5*n-1 bytes,
	// the raw header field is 5*n+38 bytes, and the per-field cost is 36*n.
	for n := 1; ; n++ {
		raw := uint32(5*n + 38)
		accounted := uint32(36 * n)
		if accounted > limit && raw <= limit {
			return n
		}
		if raw > limit {
			panic("raw trailer header exceeded the limit before the per-field cost did")
		}
	}
}

func trailerKeys(n int) []string {
	keys := make([]string, n)
	for i := 0; i < n; i++ {
		keys[i] = string([]byte{
			'A' + byte(i/26/26/26%26),
			'a' + byte(i/26/26%26),
			'a' + byte(i/26%26),
			'a' + byte(i%26),
		})
	}
	return keys
}

func writeServerCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}
