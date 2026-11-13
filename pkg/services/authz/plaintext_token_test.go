package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	authnlib "github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grafana/grafana/pkg/services/authz/proto/v1"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

// Placeholders stand in for the bootstrap credential and the credential the
// token exchange returns. They are not real credentials.
const (
	plaintextBootstrapPlaceholder = "placeholder-bootstrap-token"
	plaintextExchangedPlaceholder = "placeholder-exchanged-access-token"
)

// TestRemoteZanzanaClientDoesNotSendExchangedTokenInPlaintext follows the
// operator path: zanzana client mode, an address, token exchange settings, and
// an empty tls_cert. The exchanged access token must not be recoverable from
// the plaintext connection those settings dial.
func TestRemoteZanzanaClientDoesNotSendExchangedTokenInPlaintext(t *testing.T) {
	observer := newPlaintextObserver(t)

	cfg := zanzanaClientConfig(t, observer)
	require.Equal(t, setting.ZanzanaModeClient, cfg.ZanzanaClient.Mode)
	require.Empty(t, cfg.ZanzanaClient.ServerCertFile)
	require.Equal(t, plaintextBootstrapPlaceholder, cfg.ZanzanaClient.Token)
	require.NotEmpty(t, cfg.ZanzanaClient.TokenExchangeURL)

	features := featuremgmt.WithFeatures(featuremgmt.FlagZanzana)

	embedded, err := ProvideZanzanaClient(cfg, nil, nil, features, prometheus.NewRegistry())
	observer.invokeZanzana(t, embedded, err)

	standalone, err := ProvideStandaloneZanzanaClient(cfg, features, prometheus.NewRegistry())
	observer.invokeZanzana(t, standalone, err)

	observer.assertExchangedTokenNotOnPlaintext(t)
}

// TestRemoteRBACClientDoesNotSendExchangedTokenInPlaintext covers the cloud
// authorization client, which attaches the same per-call credential to an
// insecure dial when cert_file is empty.
func TestRemoteRBACClientDoesNotSendExchangedTokenInPlaintext(t *testing.T) {
	observer := newPlaintextObserver(t)

	cfg := rbacClientConfig(t, observer)
	authCfg, err := readAuthzClientSettings(cfg)
	require.NoError(t, err)
	require.Equal(t, clientModeCloud, authCfg.mode)
	require.Empty(t, authCfg.certFile)
	require.Equal(t, plaintextBootstrapPlaceholder, authCfg.token)

	client, err := ProvideStandaloneAuthZClient(
		cfg,
		featuremgmt.WithFeatures(featuremgmt.FlagAuthZGRPCServer),
		noop.NewTracerProvider().Tracer("plaintext-token-test"),
		prometheus.NewRegistry(),
	)
	if err == nil && client != nil {
		observer.noteClientCreated()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		observer.noteRPCAttempted()
		_, _ = client.Check(ctx, plaintextUserAuthInfo(), types.CheckRequest{
			Namespace: "stacks-1",
			Group:     "dashboards.grafana.app",
			Resource:  "dashboards",
			Verb:      "get",
			Name:      "uid",
		}, "")
	}

	observer.assertExchangedTokenNotOnPlaintext(t)
}

func zanzanaClientConfig(t *testing.T, observer *plaintextObserver) *setting.Cfg {
	t.Helper()
	cfg, err := setting.NewCfgFromBytes([]byte(`
[zanzana.client]
mode = client
address = ` + observer.dialTarget + `
tls_cert =

[grpc_client_authentication]
token = ` + plaintextBootstrapPlaceholder + `
token_exchange_url = ` + observer.exchangeURL + `
token_namespace = stacks-1
`))
	require.NoError(t, err)
	return cfg
}

func rbacClientConfig(t *testing.T, observer *plaintextObserver) *setting.Cfg {
	t.Helper()
	cfg, err := setting.NewCfgFromBytes([]byte(`
[authorization]
mode = cloud
remote_address = ` + observer.dialTarget + `
cert_file =

[grpc_client_authentication]
token = ` + plaintextBootstrapPlaceholder + `
token_exchange_url = ` + observer.exchangeURL + `
token_namespace = stacks-1
`))
	require.NoError(t, err)
	return cfg
}

func plaintextUserAuthInfo() types.AuthInfo {
	return authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
		Claims: jwt.Claims{Subject: "access-policy:placeholder"},
		Rest: authnlib.AccessTokenClaims{
			Namespace:            "stacks-1",
			DelegatedPermissions: []string{"dashboards.grafana.app/dashboards:get"},
			Actor: &authnlib.ActorClaims{
				Subject: "user:1",
				IDTokenClaims: authnlib.IDTokenClaims{
					Identifier: "1",
					Type:       types.TypeUser,
				},
			},
		},
	})
}

type plaintextObserver struct {
	dialTarget  string
	exchangeURL string

	mu            sync.Mutex
	conns         []*captureConn
	serverTokens  []string
	exchangeCalls int
	clientCreated bool
	rpcAttempted  bool
}

func newPlaintextObserver(t *testing.T) *plaintextObserver {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	obs := &plaintextObserver{
		dialTarget: "passthrough:///" + lis.Addr().String(),
	}
	capture := &captureListener{Listener: lis, obs: obs}

	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		obs.recordServerTokens(md.Get("x-access-token"))
		return status.Error(codes.Unimplemented, "plaintext observer")
	}))
	go func() {
		_ = srv.Serve(capture)
	}()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})

	exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs.noteExchange()
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]string{"token": plaintextExchangedPlaceholder},
		})
	}))
	t.Cleanup(exchange.Close)
	obs.exchangeURL = exchange.URL

	return obs
}

func (o *plaintextObserver) invokeZanzana(t *testing.T, client interface {
	Check(context.Context, types.AuthInfo, types.CheckRequest, string) (types.CheckResponse, error)
	List(context.Context, *authzv1.ListRequest) (*authzv1.ListResponse, error)
	Read(context.Context, *v1.ReadRequest) (*v1.ReadResponse, error)
	Write(context.Context, *v1.WriteRequest) error
	Mutate(context.Context, *v1.MutateRequest) error
	Query(context.Context, *v1.QueryRequest) (*v1.QueryResponse, error)
}, err error) {
	t.Helper()
	if err != nil || client == nil {
		return
	}
	o.noteClientCreated()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// BatchCheck and Compile use this same connection and per-call credential.
	calls := []func() error{
		func() error {
			_, err := client.Check(ctx, plaintextUserAuthInfo(), types.CheckRequest{
				Namespace: "stacks-1",
				Group:     "dashboards.grafana.app",
				Resource:  "dashboards",
				Verb:      "get",
				Name:      "uid",
			}, "")
			return err
		},
		func() error { _, err := client.List(ctx, &authzv1.ListRequest{}); return err },
		func() error { _, err := client.Read(ctx, &v1.ReadRequest{}); return err },
		func() error { return client.Write(ctx, &v1.WriteRequest{}) },
		func() error { return client.Mutate(ctx, &v1.MutateRequest{}) },
		func() error { _, err := client.Query(ctx, &v1.QueryRequest{}); return err },
	}
	for _, call := range calls {
		o.noteRPCAttempted()
		_ = call()
	}
}

func (o *plaintextObserver) noteClientCreated() {
	o.mu.Lock()
	o.clientCreated = true
	o.mu.Unlock()
}

func (o *plaintextObserver) noteRPCAttempted() {
	o.mu.Lock()
	o.rpcAttempted = true
	o.mu.Unlock()
}

func (o *plaintextObserver) assertExchangedTokenNotOnPlaintext(t *testing.T) {
	t.Helper()

	o.mu.Lock()
	defer o.mu.Unlock()

	var decodeErr error
	decodedHeader := false
	for _, conn := range o.conns {
		raw := conn.bytes()
		if len(raw) == 0 {
			continue
		}
		if !bytes.HasPrefix(raw, []byte(http2.ClientPreface)) {
			t.Fatal("accepted connection did not start with the HTTP/2 client preface")
		}
		tokens, decoded, err := accessTokensAfterPreface(raw)
		if err != nil && decodeErr == nil {
			decodeErr = err
		}
		decodedHeader = decodedHeader || decoded
		if tokenListContains(tokens, plaintextExchangedPlaceholder) || tokenListContains(o.serverTokens, plaintextExchangedPlaceholder) {
			t.Fatal("exchanged access token was recoverable from the plaintext gRPC connection")
		}
	}
	if tokenListContains(o.serverTokens, plaintextExchangedPlaceholder) {
		t.Fatal("exchanged access token was delivered to the plaintext gRPC server")
	}

	if !o.clientCreated {
		return
	}
	if !o.rpcAttempted {
		t.Fatal("remote client was created but no RPC was attempted")
	}
	if len(o.conns) == 0 || (!decodedHeader && decodeErr != nil) {
		t.Fatalf("plaintext RPC bytes could not be decoded: %v", decodeErr)
	}
	if o.exchangeCalls == 0 && !decodedHeader {
		t.Fatal("remote client was created but token exchange and the plaintext RPC did not run")
	}
}

func (o *plaintextObserver) recordServerTokens(tokens []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.serverTokens = append(o.serverTokens, tokens...)
}

func (o *plaintextObserver) noteExchange() {
	o.mu.Lock()
	o.exchangeCalls++
	o.mu.Unlock()
}

func tokenListContains(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

// accessTokensAfterPreface decodes HTTP/2 header blocks with the HPACK decoder
// from the net/http2 module gRPC uses, and returns every x-access-token value.
func accessTokensAfterPreface(raw []byte) ([]string, bool, error) {
	payload := raw[len(http2.ClientPreface):]
	framer := http2.NewFramer(io.Discard, bytes.NewReader(payload))
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	var tokens []string
	decoded := false
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return tokens, decoded, nil
			}
			return tokens, decoded, err
		}
		headers, ok := frame.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		decoded = true
		for _, field := range headers.Fields {
			if field.Name == "x-access-token" {
				tokens = append(tokens, field.Value)
			}
		}
	}
}

type captureListener struct {
	net.Listener
	obs *plaintextObserver
}

func (l *captureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	captured := &captureConn{Conn: conn}
	l.obs.mu.Lock()
	l.obs.conns = append(l.obs.conns, captured)
	l.obs.mu.Unlock()
	return captured, nil
}

type captureConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.buf.Write(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *captureConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}
