package clientmiddleware

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/handlertest"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/auth/idimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/signingkeys"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/proxyutil"
)

type staticSigningKeys struct {
	id  string
	key *ecdsa.PrivateKey
}

func (s staticSigningKeys) GetJWKS(context.Context) (jose.JSONWebKeySet, error) {
	return jose.JSONWebKeySet{}, nil
}

func (s staticSigningKeys) GetOrCreatePrivateKey(context.Context, string, jose.SignatureAlgorithm) (string, crypto.Signer, error) {
	return s.id, s.key, nil
}

func signViewerIdentity(t *testing.T) (string, *user.SignedInUser) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var keys signingkeys.Service = staticSigningKeys{id: "test-signing-key", key: key}
	signer, err := idimpl.ProvideLocalSigner(keys)
	require.NoError(t, err)
	svc := idimpl.ProvideService(
		setting.NewCfg(),
		signer,
		remotecache.NewFakeCacheStorage(),
		&authntest.FakeService{},
		nil,
		tracing.InitializeTracerForTest(),
	)
	ident := &authn.Identity{
		ID:            "42",
		UID:           "vieweruid",
		Type:          claims.TypeUser,
		Login:         "viewer.login",
		Name:          "Viewer Name",
		Email:         "viewer@example.com",
		EmailVerified: true,
		OrgID:         1,
		OrgRoles:      map[int64]org.RoleType{1: org.RoleViewer},
		Groups:        []string{"team-a", "team-b"},
	}
	require.NoError(t, svc.SyncIDToken(context.Background(), ident, nil))
	signedIn := ident.SignedInUser()
	require.NotEmpty(t, signedIn.GetIDToken())
	return signedIn.GetIDToken(), signedIn
}

func assertNoIdentityToken(t *testing.T, header http.Header, token string) {
	t.Helper()
	require.NotEmpty(t, token)
	if header.Get(proxyutil.IDHeaderName) != "" {
		t.Fatalf("datasource HTTP request included %s", proxyutil.IDHeaderName)
	}
	for name, values := range header {
		for _, value := range values {
			if strings.Contains(value, token) {
				t.Fatalf("datasource HTTP header %s included the signed identity token", name)
			}
		}
	}
}

// datasourceRoundTripper records the request a plugin HTTP client would send to a datasource host.
func datasourceRoundTripper(dst *http.Request) httpclient.RoundTripperFunc {
	return func(req *http.Request) (*http.Response, error) {
		*dst = *req.Clone(req.Context())
		dst.Header = req.Header.Clone()
		return &http.Response{
			StatusCode: http.StatusOK,
			Request:    req,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		}, nil
	}
}

func TestPluginHTTPClientDoesNotForwardSignedIdentityToken(t *testing.T) {
	token, viewer := signViewerIdentity(t)
	req, err := http.NewRequest(http.MethodGet, "http://grafana.example/api/ds/query", nil)
	require.NoError(t, err)

	cdt := handlertest.NewHandlerMiddlewareTest(t,
		WithReqContext(req, viewer),
		handlertest.WithMiddlewares(
			NewForwardIDMiddleware(),
			NewHTTPClientMiddleware(),
		),
	)
	pluginCtx := backend.PluginContext{
		DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{},
	}

	t.Run("query data", func(t *testing.T) {
		_, err := cdt.MiddlewareHandler.QueryData(req.Context(), &backend.QueryDataRequest{
			PluginContext: pluginCtx,
		})
		require.NoError(t, err)
		forwarded := http.Request{}
		middlewares := httpclient.ContextualMiddlewareFromContext(cdt.QueryDataCtx)
		require.NotEmpty(t, middlewares)
		outbound, err := http.NewRequest(http.MethodPost, "http://datasource.example/api/v1/query", nil)
		require.NoError(t, err)
		res, err := middlewares[0].CreateMiddleware(httpclient.Options{}, datasourceRoundTripper(&forwarded)).RoundTrip(outbound)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		assertNoIdentityToken(t, forwarded.Header, token)
	})

	t.Run("call resource", func(t *testing.T) {
		err := cdt.MiddlewareHandler.CallResource(req.Context(), &backend.CallResourceRequest{
			PluginContext: pluginCtx,
		}, nopCallResourceSender)
		require.NoError(t, err)
		forwarded := http.Request{}
		middlewares := httpclient.ContextualMiddlewareFromContext(cdt.CallResourceCtx)
		require.NotEmpty(t, middlewares)
		outbound, err := http.NewRequest(http.MethodGet, "http://datasource.example/resources", nil)
		require.NoError(t, err)
		res, err := middlewares[0].CreateMiddleware(httpclient.Options{}, datasourceRoundTripper(&forwarded)).RoundTrip(outbound)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		assertNoIdentityToken(t, forwarded.Header, token)
	})

	t.Run("check health", func(t *testing.T) {
		_, err := cdt.MiddlewareHandler.CheckHealth(req.Context(), &backend.CheckHealthRequest{
			PluginContext: pluginCtx,
		})
		require.NoError(t, err)
		forwarded := http.Request{}
		middlewares := httpclient.ContextualMiddlewareFromContext(cdt.CheckHealthCtx)
		require.NotEmpty(t, middlewares)
		outbound, err := http.NewRequest(http.MethodGet, "http://datasource.example/health", nil)
		require.NoError(t, err)
		res, err := middlewares[0].CreateMiddleware(httpclient.Options{}, datasourceRoundTripper(&forwarded)).RoundTrip(outbound)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		assertNoIdentityToken(t, forwarded.Header, token)
	})

	t.Run("query chunked data", func(t *testing.T) {
		err := cdt.MiddlewareHandler.QueryChunkedData(req.Context(), &backend.QueryChunkedDataRequest{
			PluginContext: pluginCtx,
		}, nopChunkedWriter{})
		require.NoError(t, err)
		forwarded := http.Request{}
		middlewares := httpclient.ContextualMiddlewareFromContext(cdt.QueryChunkedDataCtx)
		require.NotEmpty(t, middlewares)
		outbound, err := http.NewRequest(http.MethodPost, "http://datasource.example/api/v1/query", nil)
		require.NoError(t, err)
		res, err := middlewares[0].CreateMiddleware(httpclient.Options{}, datasourceRoundTripper(&forwarded)).RoundTrip(outbound)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		assertNoIdentityToken(t, forwarded.Header, token)
	})
}
