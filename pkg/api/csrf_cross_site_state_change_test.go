package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

// Cross-site top-level GET navigations send a SameSite=Lax session cookie and omit
// Origin. These tests require that such a request does not change session state.
// They fail while the CSRF middleware treats a missing Origin as success.
//
// Not covered here, because each one is authorized by a secret in the URL rather
// than by the session cookie alone:
//   - GET /user/email/update (verification code)
//   - GET /api/snapshots-delete/:deleteKey (snapshot delete key; public_mode is false)
//
// GET /login/:name starts an OAuth redirect even when the session cookie is absent,
// so the empty-Origin branch is not what permits it.

func TestIntegrationCrossSiteStateChangeWithoutOrigin(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	cfg := cfgFromShippedDefaults(t)
	ctx := context.Background()
	store := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	sql := legacysql.NewDatabaseProvider(store)
	tracer := tracing.InitializeTracerForTest()
	features := featuremgmt.WithFeatures()

	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	quotaService := quotaimpl.ProvideService(ctx, sql, cfgProvider)
	orgService, err := orgimpl.ProvideService(sql, cfg, quotaService)
	require.NoError(t, err)
	userService, err := userimpl.ProvideService(
		sql, orgService, cfg, teamtest.NewFakeService(), nil, tracer,
		quotaService, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	tokenService, err := authimpl.ProvideUserAuthTokenService(
		ctx, sql, nil, quotaService, fakes.NewFakeSecretsService(), cfgProvider, tracer, features,
	)
	require.NoError(t, err)

	authInfo := &authinfotest.FakeService{ExpectedError: user.ErrUserNotFound}
	authenticator := authnimpl.ProvideService(
		cfg, tracer, tokenService, &usagestats.NoopUsageStats{}, prometheus.NewRegistry(), authInfo,
	)
	authenticator.RegisterClient(clients.ProvideSession(cfgProvider, tokenService, authInfo, tracer))
	authenticator.RegisterPostAuthHook(sync.ProvideUserSync(
		userService, nil, authInfo, quotaService, tracer, features, cfg, nil,
	).FetchSyncedUserHook, 100)

	hs := &HTTPServer{
		Cfg:              cfg,
		log:              log.New("csrf-cross-site-test"),
		orgService:       orgService,
		userService:      userService,
		authnService:     authenticator,
		AuthTokenService: tokenService,
		Features:         features,
	}

	mux := web.New()
	mux.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	mux.UseMiddleware(contexthandler.ProvideService(cfg, authenticator, features).Middleware)
	mux.Use(middleware.OrgRedirect(cfg, userService))
	// Same paths as registerRoutes in api.go.
	mux.Get("/profile/switch-org/:id", middleware.ReqSignedInNoAnonymous, hs.ChangeActiveOrgAndRedirectToHome)
	mux.Get("/logout", hs.Logout)
	mux.Get("/user/auth-tokens/rotate", routing.Wrap(hs.RotateUserAuthTokenRedirect))
	mux.Post("/api/user/using/:id", middleware.ReqSignedInNoAnonymous, routing.Wrap(hs.UserSetUsingOrg))
	mux.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	t.Run("session cookie uses the shipped SameSite Lax policy", func(t *testing.T) {
		rec := httptest.NewRecorder()
		authn.WriteSessionCookie(rec, cfg, &auth.UserToken{UnhashedToken: "placeholder-token"})
		var session *http.Cookie
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == cfg.LoginCookieName {
				session = cookie
			}
		}
		require.NotNil(t, session)
		require.Equal(t, http.SameSiteLaxMode, session.SameSite)
	})

	t.Run("get switch-org with no origin leaves the active organization", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		resp := sendStateChange(t, client, server.URL, http.MethodGet, "/profile/switch-org/"+strconv.FormatInt(env.targetOrg, 10), env.rawToken, "")
		require.NoError(t, resp.Body.Close())
		requireActiveOrgsUnchanged(t, ctx, userService, env)
	})

	t.Run("get switch-org with a foreign origin leaves the active organization", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		resp := sendStateChange(t, client, server.URL, http.MethodGet, "/profile/switch-org/"+strconv.FormatInt(env.targetOrg, 10), env.rawToken, "https://attacker.example")
		require.NoError(t, resp.Body.Close())
		requireActiveOrgsUnchanged(t, ctx, userService, env)
	})

	t.Run("head switch-org with a foreign origin leaves the active organization", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		resp := sendStateChange(t, client, server.URL, http.MethodHead, "/profile/switch-org/"+strconv.FormatInt(env.targetOrg, 10), env.rawToken, "https://attacker.example")
		require.NoError(t, resp.Body.Close())
		requireActiveOrgsUnchanged(t, ctx, userService, env)
	})

	t.Run("post using-org with no origin leaves the active organization", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		resp := sendStateChange(t, client, server.URL, http.MethodPost, "/api/user/using/"+strconv.FormatInt(env.targetOrg, 10), env.rawToken, "")
		require.NoError(t, resp.Body.Close())
		requireActiveOrgsUnchanged(t, ctx, userService, env)
	})

	t.Run("get with orgId query and no origin does not persist the active organization", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		resp := sendStateChange(t, client, server.URL, http.MethodGet, "/?orgId="+strconv.FormatInt(env.targetOrg, 10), env.rawToken, "")
		require.NoError(t, resp.Body.Close())
		requireActiveOrgsUnchanged(t, ctx, userService, env)
	})

	t.Run("get logout with no origin leaves the session", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		before := lookupSession(t, ctx, tokenService, env.rawToken)
		resp := sendStateChange(t, client, server.URL, http.MethodGet, "/logout", env.rawToken, "")
		requireSessionKept(t, resp, cfg.LoginCookieName)
		require.NoError(t, resp.Body.Close())
		after := lookupSession(t, ctx, tokenService, env.rawToken)
		require.Equal(t, before.AuthToken, after.AuthToken)
		require.Zero(t, after.RevokedAt)
	})

	t.Run("head logout with a foreign origin leaves the session", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		before := lookupSession(t, ctx, tokenService, env.rawToken)
		resp := sendStateChange(t, client, server.URL, http.MethodHead, "/logout", env.rawToken, "https://attacker.example")
		requireSessionKept(t, resp, cfg.LoginCookieName)
		require.NoError(t, resp.Body.Close())
		after := lookupSession(t, ctx, tokenService, env.rawToken)
		require.Equal(t, before.AuthToken, after.AuthToken)
		require.Zero(t, after.RevokedAt)
	})

	t.Run("get token rotation with no origin keeps the session token", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		ageSession(t, store, env.tokenID)
		before := lookupSession(t, ctx, tokenService, env.rawToken)
		resp := sendStateChange(t, client, server.URL, http.MethodGet, "/user/auth-tokens/rotate", env.rawToken, "")
		requireSessionKept(t, resp, cfg.LoginCookieName)
		require.NoError(t, resp.Body.Close())
		after := lookupSession(t, ctx, tokenService, env.rawToken)
		require.Equal(t, before.AuthToken, after.AuthToken)
		require.Equal(t, before.UnhashedToken, after.UnhashedToken)
	})

	t.Run("head token rotation with a foreign origin keeps the session token", func(t *testing.T) {
		env := newSignedInVictim(t, ctx, userService, orgService, tokenService)
		ageSession(t, store, env.tokenID)
		before := lookupSession(t, ctx, tokenService, env.rawToken)
		resp := sendStateChange(t, client, server.URL, http.MethodHead, "/user/auth-tokens/rotate", env.rawToken, "https://attacker.example")
		requireSessionKept(t, resp, cfg.LoginCookieName)
		require.NoError(t, resp.Body.Close())
		after := lookupSession(t, ctx, tokenService, env.rawToken)
		require.Equal(t, before.AuthToken, after.AuthToken)
		require.Equal(t, before.UnhashedToken, after.UnhashedToken)
	})
}

func cfgFromShippedDefaults(t *testing.T) *setting.Cfg {
	t.Helper()
	defaults, err := ini.Load(filepath.Join("..", "..", "conf", "defaults.ini"))
	require.NoError(t, err)
	security := defaults.Section("security")
	authSection := defaults.Section("auth")

	require.Equal(t, "lax", security.Key("cookie_samesite").String())
	require.Equal(t, "false", security.Key("csrf_always_check").String())
	require.Equal(t, "grafana_session", authSection.Key("login_cookie_name").String())

	raw := ini.Empty()
	sec, err := raw.NewSection("security")
	require.NoError(t, err)
	_, err = sec.NewKey("cookie_samesite", security.Key("cookie_samesite").String())
	require.NoError(t, err)
	_, err = sec.NewKey("cookie_secure", security.Key("cookie_secure").String())
	require.NoError(t, err)
	_, err = sec.NewKey("csrf_always_check", security.Key("csrf_always_check").String())
	require.NoError(t, err)
	_, err = sec.NewKey("secret_key", "test-secret-placeholder")
	require.NoError(t, err)

	authIni, err := raw.NewSection("auth")
	require.NoError(t, err)
	_, err = authIni.NewKey("login_cookie_name", authSection.Key("login_cookie_name").String())
	require.NoError(t, err)
	_, err = authIni.NewKey("token_rotation_interval_minutes", authSection.Key("token_rotation_interval_minutes").String())
	require.NoError(t, err)

	cfg := setting.NewCfg()
	require.NoError(t, cfg.ApplyAuthnSettings(raw))
	require.Equal(t, http.SameSiteLaxMode, cfg.CookieSameSiteMode)
	require.False(t, cfg.CookieSameSiteDisabled)
	require.Equal(t, "grafana_session", cfg.LoginCookieName)

	// WriteSessionCookie stores the session cookie through cookies.NewCookieOptions,
	// which reads the package globals assigned from this config at startup.
	prevSecure := setting.CookieSecure
	prevSameSite := setting.CookieSameSiteMode
	prevDisabled := setting.CookieSameSiteDisabled
	t.Cleanup(func() {
		setting.CookieSecure = prevSecure
		setting.CookieSameSiteMode = prevSameSite
		setting.CookieSameSiteDisabled = prevDisabled
	})
	setting.CookieSecure = cfg.CookieSecure
	if cfg.CookieSameSiteDisabled {
		setting.CookieSameSiteDisabled = true
	} else {
		setting.CookieSameSiteMode = cfg.CookieSameSiteMode
	}
	return cfg
}

type signedInVictim struct {
	userID       int64
	homeOrg      int64
	targetOrg    int64
	bystander    int64
	bystanderOrg int64
	rawToken     string
	tokenID      int64
}

func newSignedInVictim(t *testing.T, ctx context.Context, userService user.Service, orgService org.Service, tokenService auth.UserTokenService) signedInVictim {
	t.Helper()
	suffix := time.Now().UnixNano()
	victim, err := userService.Create(ctx, &user.CreateUserCommand{
		Email: fmt.Sprintf("victim-%d@example.com", suffix),
		Login: fmt.Sprintf("victim-%d", suffix),
		Name:  "Victim",
	})
	require.NoError(t, err)
	target, err := orgService.CreateWithMember(ctx, &org.CreateOrgCommand{Name: fmt.Sprintf("target-org-%d", suffix), UserID: victim.ID})
	require.NoError(t, err)
	require.NotEqual(t, victim.OrgID, target.ID)

	bystander, err := userService.Create(ctx, &user.CreateUserCommand{
		Email: fmt.Sprintf("bystander-%d@example.com", suffix),
		Login: fmt.Sprintf("bystander-%d", suffix),
		Name:  "Bystander",
	})
	require.NoError(t, err)

	token, err := tokenService.CreateToken(ctx, &auth.CreateTokenCommand{User: victim})
	require.NoError(t, err)
	require.NotEmpty(t, token.UnhashedToken)

	return signedInVictim{
		userID:       victim.ID,
		homeOrg:      victim.OrgID,
		targetOrg:    target.ID,
		bystander:    bystander.ID,
		bystanderOrg: bystander.OrgID,
		rawToken:     token.UnhashedToken,
		tokenID:      token.Id,
	}
}

func sendStateChange(t *testing.T, client *http.Client, baseURL, method, path, rawToken, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, baseURL+path, nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "grafana_session", Value: rawToken})
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func requireActiveOrgsUnchanged(t *testing.T, ctx context.Context, userService user.Service, env signedInVictim) {
	t.Helper()
	victim, err := userService.GetByID(ctx, &user.GetUserByIDQuery{ID: env.userID})
	require.NoError(t, err)
	require.Equal(t, env.homeOrg, victim.OrgID, "active organization of the signed-in user changed")

	bystander, err := userService.GetByID(ctx, &user.GetUserByIDQuery{ID: env.bystander})
	require.NoError(t, err)
	require.Equal(t, env.bystanderOrg, bystander.OrgID, "organization update landed on a different user")
}

func lookupSession(t *testing.T, ctx context.Context, tokenService auth.UserTokenService, rawToken string) *auth.UserToken {
	t.Helper()
	token, err := tokenService.LookupToken(ctx, rawToken)
	require.NoError(t, err)
	return token
}

func requireSessionKept(t *testing.T, resp *http.Response, cookieName string) {
	t.Helper()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieName {
			require.GreaterOrEqual(t, cookie.MaxAge, 0, "session cookie was cleared")
		}
	}
}

func ageSession(t *testing.T, store *sqlstore.SQLStore, tokenID int64) {
	t.Helper()
	err := store.WithDbSession(context.Background(), func(sess *sqlstore.DBSession) error {
		_, err := sess.Table("user_auth_token").Where("id = ?", tokenID).Cols("rotated_at").
			Update(map[string]any{"rotated_at": time.Now().Add(-30 * time.Second).Unix()})
		return err
	})
	require.NoError(t, err)
}
