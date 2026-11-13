package authz

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	authnlib "github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	authlib "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/infra/tracing"
	authzextv1 "github.com/grafana/grafana/pkg/services/authz/proto/v1"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

// Placeholders only. They stand in for the bootstrap token and the token the
// exchange endpoint returns, so the test can recognise that value on the wire
// without using a real credential.
const (
	plaintextTestBootstrapToken = "placeholder-bootstrap-token"
	plaintextTestExchangedToken = "placeholder-exchanged-access-token"
)

// plaintextAuthzServer is a gRPC server with no TLS credentials. It records
// whether an incoming RPC carried access-token metadata. The peer auth type
// comes from the transport the client actually negotiated.
type plaintextAuthzServer struct {
	lis net.Listener

	mu   sync.Mutex
	hits []plaintextHit
}

type plaintextHit struct {
	method   string
	authType string
}

func (s *plaintextAuthzServer) addr() string {
	return s.lis.Addr().String()
}

func (s *plaintextAuthzServer) observe(ctx context.Context, method string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return
	}
	matched := false
	for _, value := range md.Get("x-access-token") {
		if value == plaintextTestExchangedToken {
			matched = true
			break
		}
	}
	if !matched {
		return
	}
	// A server started without transport credentials leaves AuthInfo nil and
	// reads the RPC from the raw connection. That is the plaintext peer.
	authType := "none"
	if p, ok := peer.FromContext(ctx); ok && p.AuthInfo != nil {
		authType = p.AuthInfo.AuthType()
	}
	s.mu.Lock()
	s.hits = append(s.hits, plaintextHit{method: method, authType: authType})
	s.mu.Unlock()
}

func (s *plaintextAuthzServer) requireNoAccessToken(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hits) == 0 {
		return
	}
	methods := make([]string, len(s.hits))
	for i, hit := range s.hits {
		methods[i] = hit.method + " (peer auth type " + hit.authType + ")"
	}
	t.Fatalf("access token metadata arrived on the plaintext authorization server: %v", methods)
}

func startPlaintextAuthzServer(t *testing.T) *plaintextAuthzServer {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	capture := &plaintextAuthzServer{lis: lis}
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			capture.observe(ctx, info.FullMethod)
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			capture.observe(ss.Context(), info.FullMethod)
			return handler(srv, ss)
		}),
	)
	authzv1.RegisterAuthzServiceServer(srv, authzv1.UnimplementedAuthzServiceServer{})
	authzextv1.RegisterAuthzExtentionServiceServer(srv, authzextv1.UnimplementedAuthzExtentionServiceServer{})

	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.Stop()
	})
	return capture
}

func startTokenExchange(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "unreadable exchange request", http.StatusBadRequest)
			return
		}
		var exchanged authnlib.TokenExchangeRequest
		if err := json.Unmarshal(body, &exchanged); err != nil {
			http.Error(w, "unreadable exchange request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+plaintextTestBootstrapToken {
			http.Error(w, "unexpected bootstrap credential", http.StatusUnauthorized)
			return
		}
		if len(exchanged.Audiences) != 1 || exchanged.Audiences[0] != AuthzServiceAudience {
			http.Error(w, "unexpected audience", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]string{"token": plaintextTestExchangedToken},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cloudCfg(t *testing.T, remoteAddress, exchangeURL string) *setting.Cfg {
	t.Helper()
	cfg, err := setting.NewCfgFromBytes([]byte(
		"[authorization]\n" +
			"mode = cloud\n" +
			"remote_address = " + remoteAddress + "\n" +
			"\n" +
			"[grpc_client_authentication]\n" +
			"token = " + plaintextTestBootstrapToken + "\n" +
			"token_exchange_url = " + exchangeURL + "\n" +
			"token_namespace = stacks-1\n",
	))
	require.NoError(t, err)
	return cfg
}

func delegatedAuthInfo() authlib.AuthInfo {
	return authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
		Claims: jwt.Claims{Subject: "access-policy:placeholder"},
		Rest: authnlib.AccessTokenClaims{
			Namespace: "*",
			DelegatedPermissions: []string{
				"dashboards.grafana.app/dashboards:get",
				"authz.grafana.app/userpermissions:get",
			},
			Actor: &authnlib.ActorClaims{
				Subject: "user:1",
				IDTokenClaims: authnlib.IDTokenClaims{
					Identifier: "1",
					Type:       authlib.TypeUser,
					Namespace:  "stacks-1",
				},
			},
		},
	})
}

func callCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestCloudRBACDoesNotSendAccessTokenOnPlaintext drives authorization mode
// cloud with cert_file left unset. Every remote authorization RPC on that
// client must keep the exchanged access token off the plaintext connection.
func TestCloudRBACDoesNotSendAccessTokenOnPlaintext(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")

	authzSrv := startPlaintextAuthzServer(t)
	exchange := startTokenExchange(t)
	cfg := cloudCfg(t, authzSrv.addr(), exchange.URL)

	// Cloud mode does not construct the remote client unless this flag is on.
	// The flag does not select TLS; cert_file still defaults to empty.
	clients, err := ProvideAuthZClients(
		cfg,
		featuremgmt.WithFeatures(featuremgmt.FlagAuthZGRPCServer),
		nil,
		tracing.InitializeTracerForTest(),
		prometheus.NewRegistry(),
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	if err != nil {
		authzSrv.requireNoAccessToken(t)
		return
	}

	info := delegatedAuthInfo()
	ctx := callCtx(t)
	_, _ = clients.accessClient.Check(ctx, info, authlib.CheckRequest{
		Verb:      "get",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Namespace: "stacks-1",
		Name:      "dash",
		SkipCache: true,
	}, "")
	_, _, _ = clients.accessClient.Compile(ctx, info, authlib.ListRequest{
		Verb:      "get",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Namespace: "stacks-1",
		SkipCache: true,
	})
	_, _ = clients.accessClient.BatchCheck(ctx, info, authlib.BatchCheckRequest{
		Namespace: "stacks-1",
		SkipCache: true,
		Checks: []authlib.BatchCheckItem{{
			CorrelationID: "dash",
			Verb:          "get",
			Group:         "dashboards.grafana.app",
			Resource:      "dashboards",
			Name:          "dash",
		}},
	})
	_, _ = clients.userPermissionsClient.GetUserPermissions(ctx, info, authlib.GetUserPermissionsRequest{
		Namespace: "stacks-1",
		SkipCache: true,
	})

	authzSrv.requireNoAccessToken(t)
}

// TestRemoteZanzanaDoesNotSendAccessTokenOnPlaintext covers the other remote
// authorization client. It uses the same credential helper and dials without
// TLS when zanzana.client tls_cert is left unset.
func TestRemoteZanzanaDoesNotSendAccessTokenOnPlaintext(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")

	authzSrv := startPlaintextAuthzServer(t)
	exchange := startTokenExchange(t)
	cfg, err := setting.NewCfgFromBytes([]byte(
		"[zanzana.client]\n" +
			"mode = client\n" +
			"address = " + authzSrv.addr() + "\n" +
			"\n" +
			"[grpc_client_authentication]\n" +
			"token = " + plaintextTestBootstrapToken + "\n" +
			"token_exchange_url = " + exchange.URL + "\n" +
			"token_namespace = stacks-1\n",
	))
	require.NoError(t, err)

	client, err := ProvideZanzanaClient(
		cfg,
		nil,
		nil,
		featuremgmt.WithFeatures(featuremgmt.FlagZanzana),
		prometheus.NewRegistry(),
	)
	if err != nil {
		authzSrv.requireNoAccessToken(t)
		return
	}

	info := delegatedAuthInfo()
	ctx := callCtx(t)
	_, _ = client.Check(ctx, info, authlib.CheckRequest{
		Verb:      "get",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Namespace: "stacks-1",
		Name:      "dash",
		SkipCache: true,
	}, "")
	_, _, _ = client.Compile(ctx, info, authlib.ListRequest{
		Verb:      "get",
		Group:     "dashboards.grafana.app",
		Resource:  "dashboards",
		Namespace: "stacks-1",
		SkipCache: true,
	})
	_, _ = client.BatchCheck(ctx, info, authlib.BatchCheckRequest{
		Namespace: "stacks-1",
		SkipCache: true,
		Checks: []authlib.BatchCheckItem{{
			CorrelationID: "dash",
			Verb:          "get",
			Group:         "dashboards.grafana.app",
			Resource:      "dashboards",
			Name:          "dash",
		}},
	})
	_, _ = client.List(ctx, &authzv1.ListRequest{Namespace: "stacks-1"})
	_, _ = client.Read(ctx, &authzextv1.ReadRequest{})
	_ = client.Write(ctx, &authzextv1.WriteRequest{})
	_ = client.Mutate(ctx, &authzextv1.MutateRequest{})
	_, _ = client.Query(ctx, &authzextv1.QueryRequest{})

	authzSrv.requireNoAccessToken(t)
}
