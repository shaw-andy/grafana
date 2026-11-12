package provisioning

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

	"github.com/grafana/authlib/authn"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gopkg.in/ini.v1"

	decryptv1beta1 "github.com/grafana/grafana/apps/secret/decrypt/v1beta1"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/setting"
)

// Placeholders stand in for the service credential, the exchanged access
// token, and a decrypted secure value. They are not real secrets.
const (
	placeholderServiceToken   = "PLACEHOLDER_SERVICE_TOKEN"
	placeholderExchangedToken = "PLACEHOLDER_EXCHANGED_ACCESS_TOKEN"
	placeholderDecryptedValue = "PLACEHOLDER_DECRYPTED_SECURE_VALUE"
)

// setupDecryptService reads grpc_server_use_tls from the same parsed config
// as the API decrypt client. An omitted flag must not dial cleartext, and
// explicitly setting the flag to false must not either, unless
// secrets_manager.grpc_server_allow_insecure is true. The insecure override
// does not apply when the flag is omitted: that case has to require TLS.
func TestSecretsManagerCleartextDial_OperatorDecrypt(t *testing.T) {
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
			cfg := loadCfg(t, operatorSecretsINI(peer.addr, tc.useTLS, tc.allowInsecure))

			tokenClient, err := authn.NewTokenExchangeClient(authn.TokenExchangeConfig{
				Token:            placeholderServiceToken,
				TokenExchangeURL: exchange.URL,
			})
			require.NoError(t, err)

			svc, provideErr := setupDecryptService(cfg, stubTracer{Tracer: noop.NewTracerProvider().Tracer("test")}, tokenClient)

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
			t.Logf("provideErr=%v callErr=%v capture=%d preface=%v valueOnWire=%v tokenBytes=%v serverSawToken=%v",
				provideErr, callErr, len(captured), preface, valueOnWire, tokenOnWire, peer.sawToken())

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
			require.False(t, errors.Is(callErr, authn.ErrInvalidExchangeResponse), "token exchange failed before the dial: %v", callErr)
			require.False(t, errors.Is(callErr, authn.ErrMissingNamespace), "token exchange failed before the dial: %v", callErr)
			require.False(t, errors.Is(callErr, authn.ErrMissingAudiences), "token exchange failed before the dial: %v", callErr)
		})
	}
}

// stubTracer satisfies tracing.Tracer without replacing the process-wide tracer.
type stubTracer struct{ trace.Tracer }

func (stubTracer) Inject(context.Context, http.Header, trace.Span) {}

var _ tracing.Tracer = stubTracer{}

func boolPtr(v bool) *bool { return &v }

func operatorSecretsINI(addr string, useTLS *bool, allowInsecure bool) string {
	var b bytes.Buffer
	b.WriteString("[secrets_manager]\n")
	fmt.Fprintf(&b, "grpc_server_address = %s\n", addr)
	if useTLS != nil {
		fmt.Fprintf(&b, "grpc_server_use_tls = %t\n", *useTLS)
	}
	if allowInsecure {
		b.WriteString("grpc_server_allow_insecure = true\n")
	}
	return b.String()
}

func loadCfg(t *testing.T, overlay string) *setting.Cfg {
	t.Helper()
	defaults := filepath.Join(repoRoot(t), "conf", "defaults.ini")
	parsed, err := ini.Load(defaults, []byte(overlay))
	require.NoError(t, err)
	cfg, err := setting.NewCfgFromINIFile(parsed)
	require.NoError(t, err)
	return cfg
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
	server := grpc.NewServer()
	decryptv1beta1.RegisterSecureValueDecrypterServer(server, &decryptSink{value: value, peer: peer})
	go func() { _ = server.Serve(&recordingListener{Listener: lis, peer: peer}) }()
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
