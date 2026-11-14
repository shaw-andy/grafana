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
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// trailerNameLen is the length of names produced by trailerNames.
// A fixed HTTP/2 server charges len(name)+32 per field declared by a Trailer
// header, against MAX_HEADER_LIST_SIZE.
const trailerNameLen = 8

func headerListBudget(maxHeaderBytes int) int {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 1 << 20
	}
	return maxHeaderBytes + 10*32
}

func overBudgetTrailerCount(maxHeaderBytes int) int {
	return headerListBudget(maxHeaderBytes)/(trailerNameLen+32) + 8
}

func trailerNames(n int) []string {
	names := make([]string, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, trailerNameLen)
		buf[0] = 'T'
		v := i
		for j := trailerNameLen - 1; j >= 1; j-- {
			buf[j] = byte('0' + v%10)
			v /= 10
		}
		names[i] = string(buf)
	}
	return names
}

func rawTrailerFieldSize(n int) int {
	valueLen := n*trailerNameLen + (n - 1)
	return len("trailer") + valueLen + 32
}

type trailerProbe struct {
	mu     sync.Mutex
	called bool
	keys   int
	proto  string
}

func (p *trailerProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.called = true
	p.keys = len(r.Trailer)
	p.proto = r.Proto
	p.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (p *trailerProbe) reset() {
	p.mu.Lock()
	p.called = false
	p.keys = 0
	p.proto = ""
	p.mu.Unlock()
}

func (p *trailerProbe) snapshot() (bool, int, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.called, p.keys, p.proto
}

func writeInstrumentationCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
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

// TestInstrumentationHTTPSTrailerDeclarationStaysWithinHeaderBudget covers the
// metrics/health server. With protocol=https it calls ListenAndServeTLS and
// does not clear HTTP/2, so clients speak h2 to that port.
func TestInstrumentationHTTPSTrailerDeclarationStaysWithinHeaderBudget(t *testing.T) {
	t.Run("default limit", func(t *testing.T) {
		testInstrumentationTrailerBudget(t, 0)
	})
	t.Run("explicit limit", func(t *testing.T) {
		testInstrumentationTrailerBudget(t, 4096)
	})
}

func testInstrumentationTrailerBudget(t *testing.T, maxHeaderBytes int) {
	t.Helper()

	budget := headerListBudget(maxHeaderBytes)
	attackCount := overBudgetTrailerCount(maxHeaderBytes)
	rawSize := rawTrailerFieldSize(attackCount)
	require.Less(t, rawSize+512, budget)
	require.Greater(t, attackCount*(trailerNameLen+32), budget)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	certFile, keyFile := writeInstrumentationCert(t)
	cfg := setting.NewCfg()
	cfg.Protocol = setting.HTTPSScheme
	cfg.MinTLSVersion = "TLS1.2"
	cfg.HTTPAddr = "127.0.0.1"
	cfg.HTTPPort = strconv.Itoa(port)
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile

	probe := &trailerProbe{}
	ms := &ModuleServer{
		log:            log.New("instrumentation-trailer-budget-test"),
		cfg:            cfg,
		promGatherer:   prometheus.NewRegistry(),
		healthNotifier: NewHealthNotifier(),
	}
	svc, err := ms.initInstrumentationServer()
	require.NoError(t, err)
	ms.httpServerRouter.HandleFunc("/probe", probe.ServeHTTP).Methods(http.MethodGet)
	svc.httpServ.MaxHeaderBytes = maxHeaderBytes

	require.NoError(t, svc.start(context.Background()))
	t.Cleanup(func() {
		_ = svc.stop(nil)
	})

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2"},
			},
		},
	}
	url := "https://127.0.0.1:" + cfg.HTTPPort + "/probe"

	send := func(names []string) (*http.Response, error) {
		req, reqErr := http.NewRequest(http.MethodGet, url, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		if len(names) > 0 {
			req.Trailer = make(http.Header, len(names))
			for _, name := range names {
				req.Trailer[name] = nil
			}
		}
		return client.Do(req)
	}

	var controlResp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe.reset()
		controlResp, err = send(trailerNames(4))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("instrumentation HTTP/2 control request was not served: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Equal(t, http.StatusNoContent, controlResp.StatusCode)
	controlResp.Body.Close()
	called, keys, proto := probe.snapshot()
	require.True(t, called)
	require.Equal(t, "HTTP/2.0", proto)
	require.Equal(t, 4, keys)

	probe.reset()
	attackResp, attackErr := send(trailerNames(attackCount))
	called, keys, proto = probe.snapshot()
	if called {
		t.Fatalf("instrumentation HTTP/2 handler saw %d trailer fields (proto %s) from a Trailer header of %d raw bytes; per-field size %d exceeds header list budget %d and must be rejected before the handler",
			keys, proto, rawSize, attackCount*(trailerNameLen+32), budget)
	}
	if attackErr != nil {
		require.NotContains(t, attackErr.Error(), "advertised limit")
		return
	}
	require.NotNil(t, attackResp)
	defer attackResp.Body.Close()
	_, _ = io.Copy(io.Discard, attackResp.Body)
	require.Equalf(t, http.StatusRequestHeaderFieldsTooLarge, attackResp.StatusCode, "over-budget Trailer header must be rejected")
}
