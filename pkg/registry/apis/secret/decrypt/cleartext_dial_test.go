package decrypt_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gopkg.in/ini.v1"

	authnlib "github.com/grafana/authlib/authn"
	decryptv1beta1 "github.com/grafana/grafana/apps/secret/decrypt/v1beta1"
	"github.com/grafana/grafana/pkg/registry/apis/secret/decrypt"
	"github.com/grafana/grafana/pkg/setting"
)

// Placeholders stand in for the service credential, the exchanged access
// token, and a decrypted secure value. They are not real secrets.
const (
	placeholderServiceToken   = "PLACEHOLDER_SERVICE_TOKEN"
	placeholderExchangedToken = "PLACEHOLDER_EXCHANGED_ACCESS_TOKEN"
	placeholderDecryptedValue = "PLACEHOLDER_DECRYPTED_SECURE_VALUE"
)

// The secrets-manager decrypt client must not carry decrypted secure values,
// or the access token exchanged for the call, on a cleartext HTTP/2 connection.
// Cleartext is permitted only when grpc_server_use_tls is explicitly false and
// secrets_manager.grpc_server_allow_insecure is explicitly true. Leaving
// grpc_server_use_tls unset must not open that connection, including when the
// insecure override is set, because the shipped default has to require TLS
// once the gRPC client is enabled.
func TestSecretsManagerCleartextDial_Decrypt(t *testing.T) {
	cases := []struct {
		name          string
		useTLS        *bool
		allowInsecure bool
		wantCleartext bool
	}{
		{name: "tls flag omitted", wantCleartext: false},
		{name: "tls flag omitted with insecure override", allowInsecure: true, wantCleartext: false},
		{name: "tls explicitly off", useTLS: boolPtr(false), wantCleartext: false},
		{name: "tls explicitly off with insecure override", useTLS: boolPtr(false), allowInsecure: true, wantCleartext: true},
		{name: "tls explicitly on", useTLS: boolPtr(true), wantCleartext: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exchange := newExchangeServer(t)
			peer := newCleartextDecryptPeer(t, placeholderDecryptedValue)
			cfg := loadCfg(t, secretsINI(peer.addr, exchange.URL, tc.useTLS, tc.allowInsecure, true))

			tracer := noop.NewTracerProvider().Tracer("test")
			svc, provideErr := decrypt.ProvideDecryptService(cfg, tracer, nil)

			var callErr error
			if provideErr != nil {
				callErr = provideErr
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				result, err := svc.Decrypt(ctx, "svc-identity", "stacks-1234", "secure-value-1")
				callErr = err
				if err == nil {
					got := result["secure-value-1"].Value()
					require.NotNil(t, got)
					require.Equal(t, placeholderDecryptedValue, got.DangerouslyExposeAndConsumeValue())
				}
			}

			captured := peer.snapshot()
			preface := bytes.Contains(captured, []byte(http2.ClientPreface))
			valueOnWire := bytes.Contains(captured, []byte(placeholderDecryptedValue))
			tokenOnWire := bytes.Contains(captured, []byte(placeholderExchangedToken))
			t.Logf("parsedUseTLS=%v provideErr=%v callErr=%v capture=%d preface=%v valueOnWire=%v tokenBytes=%v serverSawToken=%v",
				cfg.SecretsManagement.GrpcServerUseTLS, provideErr, callErr, len(captured), preface, valueOnWire, tokenOnWire, peer.sawToken())

			if tc.wantCleartext {
				require.NoError(t, callErr)
				require.True(t, preface, "explicit insecure override must dial cleartext HTTP/2")
				require.True(t, valueOnWire, "decrypted value must be readable on that connection")
				require.True(t, peer.sawToken(), "exchanged access token must be delivered on that connection")
				return
			}

			require.False(t, preface, "client opened a cleartext HTTP/2 connection")
			require.False(t, valueOnWire, "decrypted value was readable on the connection")
			require.False(t, peer.sawToken(), "insecure peer received the exchanged access token")
			require.False(t, tokenOnWire, "exchanged access token was readable on the connection")
			require.Error(t, callErr)
			require.False(t, errors.Is(callErr, authnlib.ErrInvalidExchangeResponse), "token exchange failed before the dial: %v", callErr)
			require.False(t, errors.Is(callErr, authnlib.ErrMissingNamespace), "token exchange failed before the dial: %v", callErr)
			require.False(t, errors.Is(callErr, authnlib.ErrMissingAudiences), "token exchange failed before the dial: %v", callErr)
		})
	}
}

func boolPtr(v bool) *bool { return &v }

func secretsINI(addr, exchangeURL string, useTLS *bool, allowInsecure, enableClient bool) string {
	var b bytes.Buffer
	b.WriteString("[secrets_manager]\n")
	if enableClient {
		b.WriteString("grpc_client_enable = true\n")
	}
	fmt.Fprintf(&b, "grpc_server_address = %s\n", addr)
	if useTLS != nil {
		fmt.Fprintf(&b, "grpc_server_use_tls = %t\n", *useTLS)
	}
	if allowInsecure {
		b.WriteString("grpc_server_allow_insecure = true\n")
	}
	b.WriteString("\n[grpc_client_authentication]\n")
	fmt.Fprintf(&b, "token = %s\n", placeholderServiceToken)
	fmt.Fprintf(&b, "token_exchange_url = %s\n", exchangeURL)
	return b.String()
}

func loadCfg(t *testing.T, overlay string) *setting.Cfg {
	t.Helper()
	defaults := filepath.Join(repoRoot(t), "conf", "defaults.ini")
	parsed, err := ini.Load(defaults, []byte(overlay))
	require.NoError(t, err)
	// The shipped defaults file does not turn TLS on. The code default has to.
	_, err = parsed.Section("secrets_manager").GetKey("grpc_server_use_tls")
	if overlayKeyOmitted(overlay, "grpc_server_use_tls") {
		require.Error(t, err, "conf/defaults.ini sets grpc_server_use_tls; the omitted-flag case is no longer the shipped default")
	}
	cfg, err := setting.NewCfgFromINIFile(parsed)
	require.NoError(t, err)
	return cfg
}

func overlayKeyOmitted(overlay, key string) bool {
	return !bytes.Contains([]byte(overlay), []byte(key+" =")) && !bytes.Contains([]byte(overlay), []byte(key+"="))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(file)
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "conf", "defaults.ini")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("conf/defaults.ini not found")
	return ""
}

func newExchangeServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"token":"%s"}}`, placeholderExchangedToken)
	}))
	t.Cleanup(server.Close)
	return server
}

type cleartextDecryptPeer struct {
	addr string
	buf  bytes.Buffer
	mu   sync.Mutex
	got  bool
}

func newCleartextDecryptPeer(t *testing.T, value string) *cleartextDecryptPeer {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	peer := &cleartextDecryptPeer{addr: lis.Addr().String()}
	recording := &recordingListener{Listener: lis, peer: peer}
	sink := &decryptSink{value: value, peer: peer}
	server := grpc.NewServer()
	decryptv1beta1.RegisterSecureValueDecrypterServer(server, sink)

	go func() { _ = server.Serve(recording) }()
	t.Cleanup(func() {
		server.Stop()
		_ = lis.Close()
	})
	return peer
}

func (p *cleartextDecryptPeer) snapshot() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.buf.Bytes()...)
}

func (p *cleartextDecryptPeer) sawToken() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.got
}

func (p *cleartextDecryptPeer) record(b []byte) {
	p.mu.Lock()
	p.buf.Write(b)
	p.mu.Unlock()
}

func (p *cleartextDecryptPeer) markToken() {
	p.mu.Lock()
	p.got = true
	p.mu.Unlock()
}

type recordingListener struct {
	net.Listener
	peer *cleartextDecryptPeer
}

func (l *recordingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: conn, peer: l.peer}, nil
}

type recordingConn struct {
	net.Conn
	peer *cleartextDecryptPeer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.peer.record(p[:n])
	}
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	// Record before the write so a short write cannot hide bytes the server already framed.
	c.peer.record(p)
	return c.Conn.Write(p)
}

type decryptSink struct {
	decryptv1beta1.UnimplementedSecureValueDecrypterServer
	value string
	peer  *cleartextDecryptPeer
}

func (s *decryptSink) DecryptSecureValues(ctx context.Context, _ *decryptv1beta1.SecureValueDecryptRequest) (*decryptv1beta1.SecureValueDecryptResponseCollection, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if vals := md.Get("x-access-token"); len(vals) == 1 && vals[0] == placeholderExchangedToken {
		s.peer.markToken()
	}
	return &decryptv1beta1.SecureValueDecryptResponseCollection{
		DecryptedValues: map[string]*decryptv1beta1.Result{
			"secure-value-1": {Result: &decryptv1beta1.Result_Value{Value: s.value}},
		},
	}, nil
}
