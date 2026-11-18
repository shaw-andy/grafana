package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/auth/authimpl"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	tempuserimpl "github.com/grafana/grafana/pkg/services/temp_user/tempuserimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

// errNoSession is the authenticator result for a request that presents no
// session. Anonymous access is disabled in the shipped configuration, so
// authentication fails and the request continues with no signed-in user.
var errNoSession = errors.New("no session")

const (
	registeredEmail = "registered.user@example.com"
	mixedCaseEmail  = "Registered.User@example.com"
	unknownEmail    = "unknown.user@example.com"
	// placeholderPassword is not a credential. Signup completion requires a
	// password that passes the length check, and this value is only used as
	// that input.
	placeholderPassword = "placeholder-password"
)

// TestIntegrationSignupDoesNotDiscloseExistingAccount checks that an
// unauthenticated client cannot tell whether an email already has a local
// account from POST /api/user/signup or POST /api/user/signup/step2.
//
// The two responses must match while users.allow_sign_up is enabled. The
// shipped default leaves signup disabled, and that configuration is covered
// separately because every address then receives the same unauthorized
// response.
func TestIntegrationSignupDoesNotDiscloseExistingAccount(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	env := newSignupEnumerationEnv(t)
	env.createLocalUser(t, registeredEmail, "registered-login")

	t.Run("signup start", func(t *testing.T) {
		env.cfg.AllowUserSignUp = true
		env.cfg.VerifyEmailEnabled = false

		unknown := env.postJSON(t, "/api/user/signup", map[string]any{"email": unknownEmail})
		registered := env.postJSON(t, "/api/user/signup", map[string]any{"email": registeredEmail})
		mixedCase := env.postJSON(t, "/api/user/signup", map[string]any{"email": mixedCaseEmail})
		t.Logf("unknown=%d %s", unknown.status, unknown.raw)
		t.Logf("registered=%d %s", registered.status, registered.raw)
		t.Logf("mixedCase=%d %s", mixedCase.status, mixedCase.raw)

		requireSameSignupResponse(t, unknown, registered)
		requireSameSignupResponse(t, unknown, mixedCase)
	})

	t.Run("signup completion", func(t *testing.T) {
		env.cfg.AllowUserSignUp = true
		env.cfg.VerifyEmailEnabled = false

		unknown := env.postJSON(t, "/api/user/signup/step2", signupStep2Body(unknownEmail, "probe-unknown"))
		registered := env.postJSON(t, "/api/user/signup/step2", signupStep2Body(registeredEmail, "probe-registered"))
		mixedCase := env.postJSON(t, "/api/user/signup/step2", signupStep2Body(mixedCaseEmail, "probe-mixed-case"))
		t.Logf("unknown=%d %s", unknown.status, unknown.raw)
		t.Logf("registered=%d %s", registered.status, registered.raw)
		t.Logf("mixedCase=%d %s", mixedCase.status, mixedCase.raw)

		requireSameSignupResponse(t, unknown, registered)
		requireSameSignupResponse(t, unknown, mixedCase)
	})
}

// TestIntegrationSignupDisabledHidesAccountExistence checks the shipped
// default. With signup disabled, a registered address and an unknown address
// produce the same unauthorized response on both signup routes.
func TestIntegrationSignupDisabledHidesAccountExistence(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	env := newSignupEnumerationEnv(t)
	env.cfg.AllowUserSignUp = false
	env.cfg.VerifyEmailEnabled = false
	env.createLocalUser(t, registeredEmail, "registered-login")

	for _, path := range []string{"/api/user/signup", "/api/user/signup/step2"} {
		t.Run(path, func(t *testing.T) {
			var body any
			if path == "/api/user/signup" {
				body = map[string]any{"email": unknownEmail}
			} else {
				body = signupStep2Body(unknownEmail, "probe-unknown")
			}
			unknown := env.postJSON(t, path, body)

			if path == "/api/user/signup" {
				body = map[string]any{"email": registeredEmail}
			} else {
				body = signupStep2Body(registeredEmail, "probe-registered")
			}
			registered := env.postJSON(t, path, body)

			requireSameSignupResponse(t, unknown, registered)
			require.Equal(t, http.StatusUnauthorized, unknown.status)
			require.Equal(t, "User signup is disabled", unknown.body["message"])
		})
	}
}

func signupStep2Body(email, username string) map[string]any {
	return map[string]any{
		"email":    email,
		"name":     "Signup Probe",
		"username": username,
		"password": placeholderPassword,
	}
}

type signupHTTPResult struct {
	status int
	body   map[string]any
	raw    []byte
}

func requireSameSignupResponse(t *testing.T, want, got signupHTTPResult) {
	t.Helper()
	require.Equal(t, want.status, got.status, "bodies %s vs %s", string(want.raw), string(got.raw))
	require.Equal(t, want.body, got.body, "bodies %s vs %s", string(want.raw), string(got.raw))
}

type signupEnumerationEnv struct {
	cfg *setting.Cfg
	mux *web.Mux
	hs  *HTTPServer
}

func newSignupEnumerationEnv(t *testing.T) *signupEnumerationEnv {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.AllowUserSignUp = true
	cfg.VerifyEmailEnabled = false
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = string(org.RoleViewer)
	// Shipped cookie name. A request with no session does not send this cookie,
	// which is what lets the CSRF filter skip the check.
	cfg.LoginCookieName = "grafana_session"

	sqlStore := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	dbProvider := legacysql.NewDatabaseProvider(sqlStore)
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	quotaSvc := quotaimpl.ProvideService(t.Context(), dbProvider, cfgProvider)
	orgSvc, err := orgimpl.ProvideService(dbProvider, cfg, quotaSvc)
	require.NoError(t, err)
	_, err = orgSvc.GetOrCreate(t.Context(), orgimpl.MainOrgName)
	require.NoError(t, err)

	tracer := tracing.InitializeTracerForTest()
	userSvc, err := userimpl.ProvideService(
		dbProvider, orgSvc, cfg, nil, nil, tracer,
		quotaSvc, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)
	authTokens, err := authimpl.ProvideUserAuthTokenService(
		t.Context(), dbProvider, nil, quotaSvc, fakes.NewFakeSecretsService(),
		cfgProvider, tracer, featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)

	hs := &HTTPServer{
		log:              log.New("signup-enumeration-test"),
		Cfg:              cfg,
		userService:      userSvc,
		tempUserService:  tempuserimpl.ProvideService(sqlStore, cfg),
		bus:              bus.ProvideBus(tracer),
		AuthTokenService: authTokens,
		QuotaService:     quotaSvc,
	}

	// Authentication fails, as it does when anonymous access is disabled and
	// the request has no session. The signup routes are not wrapped in
	// ReqSignedIn, so the handler still runs.
	ctxHdlr := contexthandler.ProvideService(cfg, &authntest.FakeService{ExpectedErr: errNoSession}, featuremgmt.WithFeatures())
	quota := middleware.Quota(quotaSvc)

	mux := web.New()
	mux.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	mux.Use(ctxHdlr.Middleware)
	mux.Post("/api/user/signup", quota(user.QuotaTargetSrv), quota(org.QuotaTargetSrv), routing.Wrap(hs.SignUp))
	mux.Post("/api/user/signup/step2", routing.Wrap(hs.SignUpStep2))

	return &signupEnumerationEnv{cfg: cfg, mux: mux, hs: hs}
}

func (e *signupEnumerationEnv) createLocalUser(t *testing.T, email, login string) {
	t.Helper()
	_, err := e.hs.userService.Create(t.Context(), &user.CreateUserCommand{
		Email: email,
		Login: login,
		Name:  "Registered User",
	})
	require.NoError(t, err)
}

func (e *signupEnumerationEnv) postJSON(t *testing.T, path string, payload any) signupHTTPResult {
	t.Helper()

	rawBody, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Del("Cookie")
	req.Header.Del("Authorization")
	recorder := httptest.NewRecorder()
	e.mux.ServeHTTP(recorder, req)

	resp := recorder.Result()
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	decoded := map[string]any{}
	if len(body) > 0 {
		require.NoError(t, json.Unmarshal(body, &decoded), "response is not JSON: %s", string(body))
	}
	return signupHTTPResult{status: resp.StatusCode, body: decoded, raw: body}
}
