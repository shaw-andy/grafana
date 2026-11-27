package sso

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/oauth2"
	"gopkg.in/ini.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	iamv0 "github.com/grafana/grafana/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/login/social/socialimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	secretsFakes "github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/ssosettings"
	"github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingsimpl"
	"github.com/grafana/grafana/pkg/services/ssosettings/strategies"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/testsuite"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

const (
	storedClientSecret = "placeholder-stored-client-secret"
	placeholderClient  = "placeholder-client-id"
)

func TestLegacyStoreUpdateReusesStoredClientSecretAtReplacementTokenURL(t *testing.T) {
	sqlStore := db.InitTestDB(t) //nolint:staticcheck // the settings store is the migrated legacy table
	env := newSSOService(t, sqlStore)
	require.NoError(t, env.svc.Upsert(context.Background(), &models.SSOSettings{
		Provider: social.GenericOAuthProviderName,
		Settings: map[string]any{
			"enabled":       true,
			"client_id":     placeholderClient,
			"client_secret": storedClientSecret,
			"auth_url":      env.legitimate.URL + "/auth",
			"token_url":     env.legitimate.URL + "/token",
		},
	}, &user.SignedInUser{IsGrafanaAdmin: true}))

	store := NewLegacyStore(env.svc, noop.NewTracerProvider().Tracer("secret-reuse"))
	ctx := identity.WithRequester(context.Background(), &identity.StaticRequester{})
	current, err := store.Get(ctx, social.GenericOAuthProviderName, &metav1.GetOptions{})
	require.NoError(t, err)
	updated := current.(*iamv0.SSOSetting).DeepCopy()
	require.Equal(t, setting.RedactedPassword, updated.Spec.Settings.Object["client_secret"])
	updated.Spec.Settings.Object["token_url"] = env.attacker.URL + "/token"
	updated.Spec.Settings.Object["auth_url"] = env.attacker.URL + "/auth"

	_, _, err = store.Update(ctx, social.GenericOAuthProviderName, rest.DefaultUpdatedObjectInfo(updated), nil, nil, false, &metav1.UpdateOptions{})
	env.finishLogin(t)
	require.Falsef(t, env.attackHits.sawSecret(storedClientSecret), "stored client secret was presented after a Kubernetes SSO settings update: %v", err)
}

func TestLegacyStoreCreateReusesStoredClientSecretAtReplacementTokenURL(t *testing.T) {
	sqlStore := db.InitTestDB(t) //nolint:staticcheck // the settings store is the migrated legacy table
	env := newSSOService(t, sqlStore)
	require.NoError(t, env.svc.Upsert(context.Background(), &models.SSOSettings{
		Provider: social.GenericOAuthProviderName,
		Settings: map[string]any{
			"enabled":       true,
			"client_id":     placeholderClient,
			"client_secret": storedClientSecret,
			"auth_url":      env.legitimate.URL + "/auth",
			"token_url":     env.legitimate.URL + "/token",
		},
	}, &user.SignedInUser{IsGrafanaAdmin: true}))

	store := NewLegacyStore(env.svc, noop.NewTracerProvider().Tracer("secret-reuse"))
	ctx := identity.WithRequester(context.Background(), &identity.StaticRequester{})
	current, err := store.Get(ctx, social.GenericOAuthProviderName, &metav1.GetOptions{})
	require.NoError(t, err)
	created := current.(*iamv0.SSOSetting).DeepCopy()
	created.Spec.Settings.Object["token_url"] = env.attacker.URL + "/token"
	_, err = store.Create(ctx, created, nil, &metav1.CreateOptions{})
	env.finishLogin(t)
	require.Falsef(t, env.attackHits.sawSecret(storedClientSecret), "stored client secret was presented after a Kubernetes SSO settings create: %v", err)
}

func TestMTSettingsUpdateReusesStoredClientSecretAtReplacementTokenURL(t *testing.T) {
	legitimate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(legitimate.Close)
	hits := &requestCapture{}
	attacker := httptest.NewServer(hits)
	t.Cleanup(attacker.Close)

	rows := newFakeSettings(
		usRow("auth.generic_oauth", "enabled", "true"),
		usRow("auth.generic_oauth", "client_id", placeholderClient),
		usRow("auth.generic_oauth", "client_secret", storedClientSecret),
		usRow("auth.generic_oauth", "auth_url", legitimate.URL+"/auth"),
		usRow("auth.generic_oauth", "token_url", legitimate.URL+"/token"),
	)
	store := NewMTSettingsStore(rows, rows, nil)
	ctx := nsCtx()
	current, err := store.Get(ctx, social.GenericOAuthProviderName, &metav1.GetOptions{})
	require.NoError(t, err)
	updated := current.(*iamv0.SSOSetting).DeepCopy()
	require.Equal(t, setting.RedactedPassword, updated.Spec.Settings.Object["client_secret"])
	updated.Spec.Settings.Object["token_url"] = attacker.URL + "/token"

	_, _, err = store.Update(ctx, social.GenericOAuthProviderName, rest.DefaultUpdatedObjectInfo(updated), nil, nil, false, &metav1.UpdateOptions{})
	loaded, loadErr := strategies.NewMTSettingsOAuthStrategy(rows, true).GetProviderConfig(context.Background(), social.GenericOAuthProviderName)
	require.NoError(t, loadErr)
	presentStoredSecret(t, loaded, attacker.Client())
	require.Falsef(t, hits.sawSecret(storedClientSecret), "stored client secret was presented after an MT-Settings SSO update: %v", err)
}

type ssoEnv struct {
	svc        *ssosettingsimpl.Service
	social     *socialimpl.SocialService
	cfg        *setting.Cfg
	legitimate *httptest.Server
	attacker   *httptest.Server
	attackHits *requestCapture
}

func newSSOService(t *testing.T, sqlStore db.DB) *ssoEnv {
	t.Helper()
	hits := &requestCapture{}
	legitimate := httptest.NewServer(hits)
	attackerHits := &requestCapture{}
	attacker := httptest.NewServer(attackerHits)
	t.Cleanup(legitimate.Close)
	t.Cleanup(attacker.Close)

	raw, err := ini.Load([]byte(""))
	require.NoError(t, err)
	configurable := map[string]bool{}
	for _, provider := range ssosettings.AllOAuthProviders {
		configurable[provider] = true
	}
	cfg := &setting.Cfg{
		Raw:                              raw,
		AppURL:                           "http://localhost:3000/",
		SecretKey:                        "placeholder-oauth-state-key",
		SSOSettingsConfigurableProviders: configurable,
	}
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	licensing := licensingtest.NewFakeLicensing()
	licensing.On("FeatureEnabled", mock.Anything).Return(false)
	svc := ssosettingsimpl.ProvideService(
		cfg,
		cfgProvider,
		legacysql.NewDatabaseProvider(sqlStore),
		acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		routing.NewRouteRegister(),
		featuremgmt.WithFeatures(),
		secretsFakes.NewFakeSecretsService(),
		&usagestats.UsageStatsMock{},
		prometheus.NewRegistry(),
		&setting.OSSImpl{Cfg: cfg},
		licensing,
	)
	socialSvc := socialimpl.ProvideService(
		context.Background(), cfgProvider, featuremgmt.WithFeatures(), &usagestats.UsageStatsMock{},
		supportbundlestest.NewFakeBundleService(), nil, nil, svc,
	)
	return &ssoEnv{svc: svc, social: socialSvc, cfg: cfg, legitimate: legitimate, attacker: attacker, attackHits: attackerHits}
}

func (e *ssoEnv) finishLogin(t *testing.T) {
	t.Helper()
	cfgProvider, err := configprovider.ProvideService(e.cfg)
	require.NoError(t, err)
	client := clients.ProvideOAuth(
		authn.ClientWithPrefix(social.GenericOAuthProviderName), cfgProvider, nil, e.social,
		&setting.OSSImpl{Cfg: e.cfg}, featuremgmt.WithFeatures(), noop.NewTracerProvider().Tracer("secret-reuse"),
	)
	redirect, err := client.RedirectURL(context.Background(), &authn.Request{HTTPRequest: httptest.NewRequest(http.MethodGet, "/login/generic_oauth", nil)})
	require.NoError(t, err)
	redirectURL, err := url.Parse(redirect.URL)
	require.NoError(t, err)
	callback := "/login/generic_oauth?code=placeholder-code&state=" + url.QueryEscape(redirectURL.Query().Get("state"))
	req := httptest.NewRequest(http.MethodGet, callback, nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: redirect.Extra[authn.KeyOAuthState]})
	_, _ = client.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
}

func presentStoredSecret(t *testing.T, settings map[string]any, client *http.Client) {
	t.Helper()
	raw, err := ini.Load([]byte(""))
	require.NoError(t, err)
	cfg := &setting.Cfg{Raw: raw, AppURL: "http://localhost:3000/"}
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	info, err := connectors.CreateOAuthInfoFromKeyValues(settings)
	require.NoError(t, err)
	provider, err := connectors.NewGenericOAuthProvider(context.Background(), info, cfgProvider, connectors.ProvideOrgRoleMapper(cfgProvider, nil), nil, featuremgmt.WithFeatures(), nil)
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	_, _ = provider.Exchange(ctx, "placeholder-code")
}

type requestCapture struct {
	mu   sync.Mutex
	reqs [][]byte
	hdrs []http.Header
}

func (c *requestCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.reqs = append(c.reqs, body)
	c.hdrs = append(c.hdrs, r.Header.Clone())
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"placeholder-access-token","token_type":"bearer"}`))
}

func (c *requestCapture) sawSecret(secret string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, body := range c.reqs {
		probe, err := http.NewRequest(http.MethodPost, "http://token.invalid", nil)
		if err == nil {
			probe.Header.Set("Authorization", c.hdrs[i].Get("Authorization"))
			_, pass, ok := probe.BasicAuth()
			if ok {
				pass, _ = url.QueryUnescape(pass)
				if pass == secret {
					return true
				}
			}
		}
		values, err := url.ParseQuery(string(body))
		if err == nil && values.Get("client_secret") == secret {
			return true
		}
	}
	return false
}
