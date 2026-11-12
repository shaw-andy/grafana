package pluginproxy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/db/dbtest"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/idimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/oauthtoken/oauthtokentest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/signingkeys"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/proxyutil"
	"github.com/grafana/grafana/pkg/web"
)

// staticSigningKeys returns one ephemeral signing key. It does not change the claims
// that idimpl.LocalSigner serializes into the identity token.
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

// signViewerIdentity runs the post-auth identity hook for a Viewer and returns the
// signed token plus the requester the proxy will see.
func signViewerIdentity(t *testing.T) (string, *user.SignedInUser, *ecdsa.PrivateKey) {
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
	require.NotEmpty(t, ident.GetIDToken())

	signedIn := ident.SignedInUser()
	require.Equal(t, org.RoleViewer, signedIn.GetOrgRole())
	require.Equal(t, ident.GetIDToken(), signedIn.GetIDToken())
	return ident.GetIDToken(), signedIn, key
}

func decodeSignedIdentity(t *testing.T, token string, key *ecdsa.PrivateKey) *auth.IDClaims {
	t.Helper()
	if strings.Count(token, ".") != 2 {
		t.Fatal("identity token is not a compact signed JWT")
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	verified := &auth.IDClaims{}
	require.NoError(t, parsed.Claims(&key.PublicKey, &verified.Claims, &verified.Rest))

	unverified := &auth.IDClaims{}
	require.NoError(t, parsed.UnsafeClaimsWithoutVerification(&unverified.Claims, &unverified.Rest))
	require.Equal(t, verified.Rest, unverified.Rest)

	require.Equal(t, "viewer@example.com", unverified.Rest.Email)
	require.Equal(t, "viewer.login", unverified.Rest.Username)
	require.Equal(t, "Viewer Name", unverified.Rest.DisplayName)
	require.Equal(t, string(org.RoleViewer), unverified.Rest.Role)
	require.Equal(t, []string{"team-a", "team-b"}, unverified.Rest.Groups)
	return unverified
}

// assertUpstreamHasNoIdentityToken fails when the signed token, or the header that carries it, reached the upstream host.
func assertUpstreamHasNoIdentityToken(t *testing.T, header http.Header, rawURL string, body []byte, token string) {
	t.Helper()
	require.NotEmpty(t, token)
	if header.Get(proxyutil.IDHeaderName) != "" {
		t.Fatalf("upstream request included %s", proxyutil.IDHeaderName)
	}
	for name, values := range header {
		for _, value := range values {
			if strings.Contains(value, token) {
				t.Fatalf("upstream header %s included the signed identity token", name)
			}
		}
	}
	if strings.Contains(rawURL, token) {
		t.Fatal("upstream URL included the signed identity token")
	}
	if strings.Contains(string(body), token) {
		t.Fatal("upstream body included the signed identity token")
	}
}

type capturedUpstream struct {
	once   sync.Once
	called chan struct{}
	header http.Header
	body   []byte
	rawURL string
}

func newCapturedUpstream(t *testing.T) (*httptest.Server, *capturedUpstream) {
	t.Helper()
	cap := &capturedUpstream{called: make(chan struct{})}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		cap.once.Do(func() {
			cap.header = r.Header.Clone()
			cap.body = body
			cap.rawURL = r.URL.String()
			close(cap.called)
		})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	return server, cap
}

func (c *capturedUpstream) wait(t *testing.T) {
	t.Helper()
	select {
	case <-c.called:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream host did not receive the proxied request")
	}
}

func newProxyService(t *testing.T) *datasourceservice.Service {
	t.Helper()
	cfg := setting.NewCfg()
	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	secretsStore := secretskvs.NewSQLSecretsKVStore(dbtest.NewFakeDB(), secretsService, log.NewNopLogger())
	features := featuremgmt.WithFeatures()
	var sqlStore db.DB
	dsRetriever := datasourceservice.ProvideDataSourceRetriever(sqlStore, features)
	dsService, err := datasourceservice.ProvideService(
		sqlStore, secretsService, secretsStore, cfg, features,
		acimpl.ProvideAccessControl(features),
		&actest.FakePermissionsService{},
		quotatest.New(false, nil),
		&pluginstore.FakePluginStore{},
		&pluginfakes.FakePluginClient{},
		plugincontext.ProvideBaseService(cfg, pluginconfig.NewFakePluginRequestConfigProvider()),
		dsRetriever,
	)
	require.NoError(t, err)
	return dsService
}

func proxyViewerRequest(t *testing.T, ds *datasources.DataSource, user *user.SignedInUser, settings *DataSourceProxySettings, proxyPath string) (*capturedUpstream, int) {
	t.Helper()
	upstream, cap := newCapturedUpstream(t)
	ds.URL = upstream.URL
	if ds.JsonData == nil {
		ds.JsonData = simplejson.New()
	}
	if ds.Access == "" {
		ds.Access = datasources.DS_ACCESS_PROXY
	}

	req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/datasources/proxy/uid/ds/"+proxyPath, nil)
	// Match the context handler, which removes these headers before the proxy runs.
	req.Header.Del(clients.ExtJWTAuthorizationHeaderName)
	req.Header.Del(clients.ExtJWTAuthenticationHeaderName)
	resp := web.NewResponseWriter(http.MethodGet, httptest.NewRecorder())
	reqCtx := &contextmodel.ReqContext{
		Context:      &web.Context{Req: req, Resp: resp},
		SignedInUser: user,
	}

	loader, err := NewDataSourceLoader(ds, newProxyService(t))
	require.NoError(t, err)
	proxy, err := NewDataSourceProxy(
		loader,
		nil,
		toHTTPContext(t, reqCtx),
		proxyPath,
		settings,
		httpclient.NewProvider(),
		&oauthtokentest.MockOauthTokenService{
			GetCurrentOauthTokenFunc: func(context.Context, identity.Requester, *auth.UserToken) *oauth2.Token {
				return (&oauth2.Token{
					AccessToken: "oauth-access-placeholder",
					TokenType:   "Bearer",
					Expiry:      time.Now().Add(time.Hour),
				}).WithExtra(map[string]any{"id_token": "oauth-id-token-placeholder"})
			},
		},
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	proxy.HandleRequest()
	return cap, resp.Status()
}

func TestSignedIdentityTokenIsNotForwardedToUpstreamHosts(t *testing.T) {
	token, viewer, key := signViewerIdentity(t)
	decodeSignedIdentity(t, token, key)

	t.Run("identity token alone is not a grafana api credential", func(t *testing.T) {
		tracer := tracing.InitializeTracerForTest()
		disabled := setting.NewCfg()
		extDisabled := clients.ProvideExtendedJWT(disabled, tracer)
		jwtClient := clients.ProvideJWT(nil, nil, disabled, tracer)

		req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/datasources", nil)
		req.Header.Set(clients.ExtJWTAuthorizationHeaderName, token)
		authReq := &authn.Request{HTTPRequest: req}

		require.False(t, extDisabled.Test(context.Background(), authReq))
		require.False(t, extDisabled.IsEnabled(context.Background()))
		_, err := extDisabled.Authenticate(context.Background(), authReq)
		require.Error(t, err)
		require.False(t, jwtClient.Test(context.Background(), authReq))

		enabled := setting.NewCfg()
		enabled.ExtJWTAuth.Enabled = true
		extEnabled := clients.ProvideExtendedJWT(enabled, tracer)
		require.True(t, extEnabled.IsEnabled(context.Background()))
		require.False(t, extEnabled.Test(context.Background(), authReq))
		_, err = extEnabled.Authenticate(context.Background(), authReq)
		require.Error(t, err)
	})

	cases := []struct {
		name           string
		dsType         string
		sendUserHeader bool
		oauthPassThru  bool
		user           string
	}{
		{name: "prometheus default", dsType: datasources.DS_PROMETHEUS},
		{name: "prometheus with login header enabled", dsType: datasources.DS_PROMETHEUS, sendUserHeader: true},
		{name: "loki", dsType: datasources.DS_LOKI},
		{name: "elasticsearch", dsType: datasources.DS_ES},
		{name: "influxdb", dsType: datasources.DS_INFLUXDB, user: "influx"},
		{name: "influxdb 0.8", dsType: datasources.DS_INFLUXDB_08, user: "influx"},
		{name: "custom datasource", dsType: "custom-datasource"},
		{name: "prometheus oauth pass-through", dsType: datasources.DS_PROMETHEUS, oauthPassThru: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jsonData := map[string]any{}
			if tc.oauthPassThru {
				jsonData["oauthPassThru"] = true
			}
			ds := &datasources.DataSource{
				Name:     "ds",
				Type:     tc.dsType,
				Access:   datasources.DS_ACCESS_PROXY,
				User:     tc.user,
				JsonData: simplejson.NewFromAny(jsonData),
			}
			settings := &DataSourceProxySettings{SendUserHeader: tc.sendUserHeader}
			cap, status := proxyViewerRequest(t, ds, viewer, settings, "api/v1/query")
			cap.wait(t)
			if status != 0 && status != http.StatusOK {
				t.Fatalf("proxy status %d", status)
			}
			assertUpstreamHasNoIdentityToken(t, cap.header, cap.rawURL, cap.body, token)
			if tc.sendUserHeader {
				require.Equal(t, viewer.GetLogin(), cap.header.Get(proxyutil.UserHeaderName))
			} else {
				require.Empty(t, cap.header.Get(proxyutil.UserHeaderName))
			}
		})
	}

	t.Run("app plugin route", func(t *testing.T) {
		for _, sendUserHeader := range []bool{false, true} {
			upstream, cap := newCapturedUpstream(t)
			routes := []*plugins.Route{{
				Path:   "/",
				Method: http.MethodGet,
				URL:    upstream.URL,
			}}
			req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/plugin-proxy/my-app/", nil)
			req.Header.Del(clients.ExtJWTAuthorizationHeaderName)
			resp := web.NewResponseWriter(http.MethodGet, httptest.NewRecorder())
			proxy, err := NewPluginProxy(
				&pluginsettings.DTO{PluginID: "my-app", JSONData: map[string]any{}},
				routes,
				req,
				resp,
				viewer,
				"",
				false,
				sendUserHeader,
				nil,
				tracing.InitializeTracerForTest(),
				&http.Transport{},
				acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
				featuremgmt.WithFeatures(),
			)
			require.NoError(t, err)
			proxy.HandleRequest()
			cap.wait(t)
			assertUpstreamHasNoIdentityToken(t, cap.header, cap.rawURL, cap.body, token)
			if sendUserHeader {
				require.Equal(t, viewer.GetLogin(), cap.header.Get(proxyutil.UserHeaderName))
			} else {
				require.Empty(t, cap.header.Get(proxyutil.UserHeaderName))
			}
		}
	})

	t.Run("plugin route denied for a viewer is not forwarded", func(t *testing.T) {
		upstream, cap := newCapturedUpstream(t)
		routes := []*plugins.Route{{
			Path:    "admin",
			Method:  http.MethodGet,
			URL:     upstream.URL,
			ReqRole: org.RoleAdmin,
		}}
		req := httptest.NewRequest(http.MethodGet, "http://grafana.example/api/plugin-proxy/my-app/admin", nil)
		resp := web.NewResponseWriter(http.MethodGet, httptest.NewRecorder())
		proxy, err := NewPluginProxy(
			&pluginsettings.DTO{PluginID: "my-app"},
			routes,
			req,
			resp,
			viewer,
			"admin",
			false,
			false,
			nil,
			tracing.InitializeTracerForTest(),
			&http.Transport{},
			acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
			featuremgmt.WithFeatures(),
		)
		require.NoError(t, err)
		proxy.HandleRequest()
		select {
		case <-cap.called:
			t.Fatal("denied plugin route reached the upstream host")
		default:
		}
		require.Equal(t, http.StatusForbidden, resp.Status())
	})
}
