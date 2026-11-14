package server

import (
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grafana/dskit/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// The instrumentation server turns on HTTP/2 by ListenAndServeTLS when
// [server] protocol is https. The same Trailer-header budget as the main
// HTTP/2 server applies: a declaration that fits in one header field must
// not expand into a Request.Trailer map past that budget.
func TestInstrumentationHTTPSTrailerDeclarationStaysWithinHeaderBudget(t *testing.T) {
	certFile, keyFile := writeServerCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	cfg := setting.NewCfg()
	cfg.Protocol = setting.HTTPSScheme
	cfg.MinTLSVersion = "TLS1.2"
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.HTTPAddr = "127.0.0.1"
	cfg.HTTPPort = strconv.Itoa(port)

	ms := &ModuleServer{
		log:          log.NewNopLogger(),
		cfg:          cfg,
		promGatherer: prometheus.NewRegistry(),
	}
	s, err := ms.initInstrumentationServer()
	require.NoError(t, err)
	require.Zero(t, s.httpServ.MaxHeaderBytes)
	require.Nil(t, s.httpServ.TLSNextProto)

	var called atomic.Bool
	var trailerLen atomic.Int64
	orig := s.httpServ.Handler
	s.httpServ.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		trailerLen.Store(int64(len(r.Trailer)))
		orig.ServeHTTP(w, r)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, services.StartAndAwaitRunning(ctx, s))
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = services.StopAndAwaitTerminated(stopCtx, s)
	})

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2"},
				ServerName:         "localhost",
			},
		},
	}
	t.Cleanup(client.CloseIdleConnections)
	url := "https://127.0.0.1:" + cfg.HTTPPort + "/livez"
	limit := headerListLimit(s.httpServ.MaxHeaderBytes)

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
		require.Equalf(t, http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode, "body %q", body)
	})
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
