package api

import (
	"bytes"
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
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/setting"
)

// TestHTTPServerTrailerHeaderBudget is the spec for CVE-2026-78659 on Grafana's
// HTTP/2 listener. It fails on the Go version this module declares (1.26.6) and
// passes once that stdlib HTTP/2 server charges every name declared in a
// Trailer header against the header-list budget (Go 1.26.9).
//
// Grafana leaves Server.MaxHeaderBytes unset, so net/http uses DefaultMaxHeaderBytes.
// configureTLS turns HTTP/2 on for protocol h2 and socket_h2, and ServeTLS uses the
// stdlib HTTP/2 server. A client sends one Trailer header whose raw size fits in
// that budget while the comma-separated names, counted as separate header fields,
// do not. The fixed server answers 431 and does not hand the handler a Trailer map
// built from that header. The unfixed server accepts the request.
func TestHTTPServerTrailerHeaderBudget(t *testing.T) {
	for _, scheme := range []setting.Scheme{setting.HTTP2Scheme, setting.SocketHTTP2Scheme} {
		t.Run(string(scheme), func(t *testing.T) {
			srv := startProductHTTP2Server(t, scheme)
			budget := headerListBudget(srv.maxHeaderBytes)

			t.Run("names that fit are accepted", func(t *testing.T) {
				const n = 8
				value := trailerDeclaration(n)
				if got := trailerExpandedSize(value); got > budget {
					t.Fatalf("control declaration expanded size %d exceeds budget %d", got, budget)
				}
				status, saw := srv.roundTrip(t, value)
				if status != "200" || saw != n {
					t.Fatalf("control Trailer declaration: status %s, handler saw %d names; want 200 and %d", status, saw, n)
				}
			})

			t.Run("names past the header budget are rejected", func(t *testing.T) {
				n := overBudgetTrailerCount(budget)
				value := trailerDeclaration(n)
				assertTrailerExceedsBudgetButRawHeaderFits(t, value, srv.authority, budget)

				status, saw := srv.roundTrip(t, value)
				expanded := trailerExpandedSize(value)
				if status != "431" || saw != 0 {
					t.Fatalf("Trailer header declared %d names (raw field %d bytes, expanded %d bytes) against header budget %d: status %s, handler Trailer map length %d; want 431 and no map",
						n, len("trailer")+len(value)+int(hpack.HeaderField{}.Size()), expanded, budget, status, saw)
				}
			})
		})
	}
}

// headerListBudget is net/http's HTTP/2 MAX_HEADER_LIST_SIZE for a Server.MaxHeaderBytes
// value. A non-positive MaxHeaderBytes means DefaultMaxHeaderBytes, then 32 bytes per
// field are added for ten typical headers. See http2adjustHTTP1MaxHeaderSize.
func headerListBudget(maxHeaderBytes int) int {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = http.DefaultMaxHeaderBytes
	}
	const perFieldOverhead = 32
	const typicalHeaders = 10
	return maxHeaderBytes + typicalHeaders*perFieldOverhead
}

// trailerExpandedSize is the size the fixed HTTP/2 server charges for one Trailer
// header value: each comma-separated name is a header field of hpack.HeaderField{}.Size()
// plus the name bytes. Spaces are not inserted by trailerDeclaration.
func trailerExpandedSize(value string) int {
	fieldCount := strings.Count(value, ",") + 1
	overhead := int(hpack.HeaderField{}.Size())
	return (len(value) - fieldCount + 1) + fieldCount*overhead
}

// overBudgetTrailerCount is the smallest number of 4-character names whose expanded
// Trailer size is strictly larger than budget. Names are "%04x", so this holds for
// counts below 65536.
func overBudgetTrailerCount(budget int) int {
	per := 4 + int(hpack.HeaderField{}.Size())
	return budget/per + 1
}

func assertTrailerExceedsBudgetButRawHeaderFits(t *testing.T, value, authority string, budget int) {
	t.Helper()
	expanded := trailerExpandedSize(value)
	if expanded <= budget {
		t.Fatalf("declaration expanded size %d does not exceed budget %d", expanded, budget)
	}
	// One HPACK field per header, the unit the unfixed server uses.
	raw := (len(":method") + len("GET") + 32) +
		(len(":path") + len("/") + 32) +
		(len(":scheme") + len("https") + 32) +
		(len(":authority") + len(authority) + 32) +
		(len("trailer") + len(value) + 32)
	if raw > budget {
		t.Fatalf("raw header list %d exceeds budget %d; the unfixed server would reject it for size alone", raw, budget)
	}
}

func trailerDeclaration(n int) string {
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

type trailerObserver struct {
	mu     sync.Mutex
	saw    int
	called bool
}

func (o *trailerObserver) reset() {
	o.mu.Lock()
	o.saw = 0
	o.called = false
	o.mu.Unlock()
}

func (o *trailerObserver) record(n int) {
	o.mu.Lock()
	o.saw = n
	o.called = true
	o.mu.Unlock()
}

func (o *trailerObserver) get() (int, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.saw, o.called
}

type productH2Server struct {
	network        string
	addr           string
	authority      string
	maxHeaderBytes int
	obs            *trailerObserver
}

func (s *productH2Server) roundTrip(t *testing.T, trailerValue string) (status string, saw int) {
	t.Helper()
	s.obs.reset()

	raw, err := net.DialTimeout(s.network, s.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s %s: %v", s.network, s.addr, err)
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
	block := encodeRequestHeaders(t, s.authority, trailerValue)
	if err := writeHeaderBlock(fr, block); err != nil {
		t.Fatal(err)
	}

	status, err = readResponseStatus(fr)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	n, called := s.obs.get()
	if !called {
		return status, 0
	}
	return status, n
}

func encodeRequestHeaders(t *testing.T, authority, trailerValue string) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: "trailer", Value: trailerValue},
	}
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// initialMaxFrameSize is the HTTP/2 default the server enforces before SETTINGS.
const initialMaxFrameSize = 16384

func writeHeaderBlock(fr *http2.Framer, block []byte) error {
	first := block
	rest := []byte(nil)
	if len(block) > initialMaxFrameSize {
		first = block[:initialMaxFrameSize]
		rest = block[initialMaxFrameSize:]
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: first,
		EndStream:     true,
		EndHeaders:    len(rest) == 0,
	}); err != nil {
		return err
	}
	for len(rest) > 0 {
		n := initialMaxFrameSize
		if n > len(rest) {
			n = len(rest)
		}
		chunk := rest[:n]
		rest = rest[n:]
		if err := fr.WriteContinuation(1, len(rest) == 0, chunk); err != nil {
			return err
		}
	}
	return nil
}

func readResponseStatus(fr *http2.Framer) (string, error) {
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return "", err
		}
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return "", err
				}
			}
		case *http2.MetaHeadersFrame:
			return ff.PseudoValue("status"), nil
		case *http2.RSTStreamFrame:
			return "", fmt.Errorf("rst stream %d code %v", ff.StreamID, ff.ErrCode)
		case *http2.GoAwayFrame:
			return "", fmt.Errorf("goaway last %d code %v", ff.LastStreamID, ff.ErrCode)
		}
	}
}

func startProductHTTP2Server(t *testing.T, scheme setting.Scheme) *productH2Server {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile := writeServerCert(t, dir)

	cfg := setting.NewCfg()
	cfg.Protocol = scheme
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	cfg.MinTLSVersion = "TLS1.2"
	cfg.Domain = "localhost"

	obs := &trailerObserver{}
	hs := &HTTPServer{
		Cfg: cfg,
		log: log.New("h2-trailer-test"),
	}
	// Same Server construction as HTTPServer.Run: Addr, Handler, ReadTimeout.
	// MaxHeaderBytes stays at zero, which is what Run leaves in place.
	hs.httpSrv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			obs.record(len(r.Trailer))
			w.WriteHeader(http.StatusOK)
		}),
		ReadTimeout: hs.Cfg.ReadTimeout,
	}
	if err := hs.configureTLS(); err != nil {
		t.Fatalf("configureTLS: %v", err)
	}

	out := &productH2Server{obs: obs, maxHeaderBytes: hs.httpSrv.MaxHeaderBytes}
	var ln net.Listener
	switch scheme {
	case setting.HTTP2Scheme:
		var err error
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		out.network = "tcp"
		out.addr = ln.Addr().String()
		host, port, err := net.SplitHostPort(out.addr)
		if err != nil {
			t.Fatal(err)
		}
		out.authority = net.JoinHostPort(host, port)
	case setting.SocketHTTP2Scheme:
		sock := filepath.Join(dir, "grafana.sock")
		var err error
		ln, err = net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		out.network = "unix"
		out.addr = sock
		// :authority has no socket path. Use the name configureTLS's cert presents.
		out.authority = "localhost"
	default:
		t.Fatalf("unsupported scheme %s", scheme)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		_ = hs.httpSrv.ServeTLS(ln, "", "")
	}()
	t.Cleanup(func() { hs.httpSrv.Close() })
	return out
}

func writeServerCert(t *testing.T, dir string) (certFile, keyFile string) {
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
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
