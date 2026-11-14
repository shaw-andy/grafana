package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grafana/dskit/services"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// TestInstrumentationHTTPSTrailerHeaderBudget covers the module instrumentation
// listener. With protocol=https it calls ListenAndServeTLS and does not clear
// TLSNextProto, so the stdlib HTTP/2 server is enabled. The same Trailer-header
// budget bypass as the main h2 listener applies. The test fails on Go 1.26.6
// and passes once the stdlib server rejects the over-budget declaration with 431.
func TestInstrumentationHTTPSTrailerHeaderBudget(t *testing.T) {
	srv := startInstrumentationHTTPS(t)
	budget := instrumentationHeaderListBudget(0)

	t.Run("names that fit are accepted", func(t *testing.T) {
		const n = 8
		value := instrumentationTrailerDeclaration(n)
		status, saw := srv.roundTrip(t, value)
		if status != "200" || saw != n {
			t.Fatalf("control Trailer declaration: status %s, handler saw %d names; want 200 and %d", status, saw, n)
		}
	})

	t.Run("names past the header budget are rejected", func(t *testing.T) {
		n := budget/instrumentationTrailerPerField() + 1
		value := instrumentationTrailerDeclaration(n)
		expanded := instrumentationTrailerExpandedSize(value)
		raw := (len(":method") + len("GET") + 32) +
			(len(":path") + len("/") + 32) +
			(len(":scheme") + len("https") + 32) +
			(len(":authority") + len(srv.authority) + 32) +
			(len("trailer") + len(value) + 32)
		if expanded <= budget || raw > budget {
			t.Fatalf("payload expanded %d raw %d budget %d is not a bypass case", expanded, raw, budget)
		}
		status, saw := srv.roundTrip(t, value)
		if status != "431" || saw != 0 {
			t.Fatalf("Trailer header declared %d names (raw field %d bytes, expanded %d bytes) against header budget %d: status %s, handler Trailer map length %d; want 431 and no map",
				n, len("trailer")+len(value)+int(hpack.HeaderField{}.Size()), expanded, budget, status, saw)
		}
	})
}

func instrumentationHeaderListBudget(maxHeaderBytes int) int {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = http.DefaultMaxHeaderBytes
	}
	return maxHeaderBytes + 10*32
}

func instrumentationTrailerPerField() int {
	return 4 + int(hpack.HeaderField{}.Size())
}

func instrumentationTrailerExpandedSize(value string) int {
	fieldCount := strings.Count(value, ",") + 1
	overhead := int(hpack.HeaderField{}.Size())
	return (len(value) - fieldCount + 1) + fieldCount*overhead
}

func instrumentationTrailerDeclaration(n int) string {
	var b strings.Builder
	b.Grow(n * 5)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%04x", i)
	}
	return b.String()
}

type instrumentationTrailerObs struct {
	mu  sync.Mutex
	saw int
	hit bool
}

func (o *instrumentationTrailerObs) reset() {
	o.mu.Lock()
	o.saw = 0
	o.hit = false
	o.mu.Unlock()
}

func (o *instrumentationTrailerObs) record(n int) {
	o.mu.Lock()
	o.saw = n
	o.hit = true
	o.mu.Unlock()
}

func (o *instrumentationTrailerObs) get() (int, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.saw, o.hit
}

type instrumentationH2 struct {
	addr      string
	authority string
	obs       *instrumentationTrailerObs
}

func (s *instrumentationH2) roundTrip(t *testing.T, trailerValue string) (string, int) {
	t.Helper()
	s.obs.reset()

	raw, err := net.DialTimeout("tcp", s.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", s.addr, err)
	}
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	})
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated %q, want h2", got)
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: s.authority},
		{Name: "trailer", Value: trailerValue},
	} {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	block := buf.Bytes()
	const maxFrame = 16384
	first, rest := block, []byte(nil)
	if len(block) > maxFrame {
		first, rest = block[:maxFrame], block[maxFrame:]
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: first, EndStream: true, EndHeaders: len(rest) == 0,
	}); err != nil {
		t.Fatal(err)
	}
	for len(rest) > 0 {
		n := maxFrame
		if n > len(rest) {
			n = len(rest)
		}
		chunk := rest[:n]
		rest = rest[n:]
		if err := fr.WriteContinuation(1, len(rest) == 0, chunk); err != nil {
			t.Fatal(err)
		}
	}
	var status string
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.MetaHeadersFrame:
			status = ff.PseudoValue("status")
			n, hit := s.obs.get()
			if !hit {
				return status, 0
			}
			return status, n
		case *http2.RSTStreamFrame:
			t.Fatalf("rst stream %d code %v", ff.StreamID, ff.ErrCode)
		case *http2.GoAwayFrame:
			t.Fatalf("goaway last %d code %v", ff.LastStreamID, ff.ErrCode)
		}
	}
}

func startInstrumentationHTTPS(t *testing.T) *instrumentationH2 {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile := writeInstrumentationCert(t, dir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := setting.NewCfg()
	cfg.Protocol = setting.HTTPSScheme
	cfg.HTTPAddr = "127.0.0.1"
	cfg.HTTPPort = strconv.Itoa(port)
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.MinTLSVersion = "TLS1.2"

	obs := &instrumentationTrailerObs{}
	ms := ModuleServer{
		log:            log.New("instrumentation-h2-test"),
		cfg:            cfg,
		promGatherer:   prometheus.NewRegistry(),
		healthNotifier: NewHealthNotifier(),
	}
	s, err := ms.initInstrumentationServer()
	if err != nil {
		t.Fatal(err)
	}
	// Observation point only. ListenAndServeTLS still serves this handler over HTTP/2.
	s.httpServ.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs.record(len(r.Trailer))
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := services.StartAndAwaitRunning(ctx, s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = services.StopAndAwaitTerminated(stopCtx, s)
	})

	return &instrumentationH2{
		addr:      net.JoinHostPort(cfg.HTTPAddr, cfg.HTTPPort),
		authority: net.JoinHostPort(cfg.HTTPAddr, cfg.HTTPPort),
		obs:       obs,
	}
}

func writeInstrumentationCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
