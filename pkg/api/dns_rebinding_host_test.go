package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db/dbtest"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/middleware/loggermw"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Markers the shipped handlers emit. A foreign Host must not receive them,
// and the password-reset mailer must not be invoked for that Host.
const (
	dnsRebindVersion = "9.9.9-rebind-canary"
	dnsRebindCommit  = "rebindcommitcanary"
	dnsRebindMetric  = "grafana_dns_rebinding_canary"
	dnsRebindPlugin  = "plugin_dns_rebinding_canary"
	dnsRebindUser    = "rebind-user@example.com"
)

// TestForeignHostRejectedOnShippedDefaults loads conf/defaults.ini and sends
// the Host a browser would send after rebinding the page's name onto this
// Grafana. The handlers under test are the ones that run without a session
// cookie: Prometheus metrics, plugin metrics, both health handlers, the
// frontend log sink, and the password-reset mailer.
func TestForeignHostRejectedOnShippedDefaults(t *testing.T) {
	srv := newShippedHostServer(t, false)

	for _, host := range []string{"http://rebind.example:3000", "http://rebind.example"} {
		srv.assertForeignHostRefused(t, host)
	}
}

// TestForeignHostRejectedWhenEnforceDomainEnabled covers the same monitoring
// handlers with the host check switched on. Those handlers are installed
// ahead of ValidateHostHeader, so enabling the flag alone still serves them.
func TestForeignHostRejectedWhenEnforceDomainEnabled(t *testing.T) {
	srv := newShippedHostServer(t, true)
	require.True(t, srv.hs.Cfg.EnforceDomain)

	srv.assertForeignHostRefused(t, "http://rebind.example:3000")
}

// TestConfiguredHostStillServesMonitoringData is the matching-host control.
// The configured domain must keep receiving the same responses.
func TestConfiguredHostStillServesMonitoringData(t *testing.T) {
	srv := newShippedHostServer(t, false)
	host := "http://localhost:3000"

	metrics := srv.request(t, http.MethodGet, host+"/metrics", nil, "")
	require.Equal(t, http.StatusOK, metrics.Code)
	require.Contains(t, metrics.Body.String(), dnsRebindMetric)

	health := srv.request(t, http.MethodGet, host+"/api/health", nil, "")
	require.Equal(t, http.StatusOK, health.Code)
	require.Contains(t, health.Body.String(), dnsRebindVersion)
	require.Contains(t, health.Body.String(), dnsRebindCommit)
	require.Contains(t, health.Body.String(), `"database": "ok"`)

	healthz := srv.request(t, http.MethodGet, host+"/healthz", nil, "")
	require.Equal(t, http.StatusOK, healthz.Code)
	require.Equal(t, "Ok", healthz.Body.String())

	plugin := srv.request(t, http.MethodGet, host+"/metrics/plugins/canary", nil, "")
	require.Equal(t, http.StatusOK, plugin.Code)
	require.Contains(t, plugin.Body.String(), dnsRebindPlugin)

	reset := srv.request(t, http.MethodPost, host+"/api/user/password/send-reset-email", strings.NewReader(`{"userOrEmail":"`+dnsRebindUser+`"}`), "application/json")
	require.Equal(t, http.StatusOK, reset.Code)
	require.Contains(t, reset.Body.String(), "Email sent")
	require.Len(t, srv.mailer.resets, 1)
	require.Equal(t, dnsRebindUser, srv.mailer.resets[0].User.Email)
}

func requireRefused(t *testing.T, rec *httptest.ResponseRecorder, leaked ...string) {
	t.Helper()
	body := rec.Body.String()
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("foreign Host was served HTTP %d: %s", rec.Code, body)
	}
	for _, snippet := range leaked {
		if strings.Contains(body, snippet) {
			t.Fatalf("foreign Host response contains %q (HTTP %d): %s", snippet, rec.Code, body)
		}
	}
}

type shippedHostServer struct {
	hs     *HTTPServer
	mailer *resetMailer
}

func (s shippedHostServer) assertForeignHostRefused(t *testing.T, host string) {
	t.Helper()
	t.Run(host+"/metrics", func(t *testing.T) {
		requireRefused(t, s.request(t, http.MethodGet, host+"/metrics", nil, ""), dnsRebindMetric)
	})
	t.Run(host+"/api/health", func(t *testing.T) {
		requireRefused(t, s.request(t, http.MethodGet, host+"/api/health", nil, ""), dnsRebindVersion, dnsRebindCommit, `"database"`)
	})
	t.Run(host+"/healthz", func(t *testing.T) {
		requireRefused(t, s.request(t, http.MethodGet, host+"/healthz", nil, ""))
	})
	t.Run(host+"/metrics/plugins/canary", func(t *testing.T) {
		requireRefused(t, s.request(t, http.MethodGet, host+"/metrics/plugins/canary", nil, ""), dnsRebindPlugin)
	})
	t.Run(host+"/log-grafana-javascript-agent", func(t *testing.T) {
		rec := s.request(t, http.MethodPost, host+"/log-grafana-javascript-agent", strings.NewReader(`{}`), "application/json")
		requireRefused(t, rec)
	})
	t.Run(host+"/api/user/password/send-reset-email", func(t *testing.T) {
		before := len(s.mailer.resets)
		rec := s.request(t, http.MethodPost, host+"/api/user/password/send-reset-email", strings.NewReader(`{"userOrEmail":"`+dnsRebindUser+`"}`), "application/json")
		if got := len(s.mailer.resets) - before; got != 0 {
			t.Errorf("password reset mail was handed to the mailer for a foreign Host (%d call(s))", got)
		}
		requireRefused(t, rec, "Email sent")
	})
}

func (s shippedHostServer) request(t *testing.T, method, target string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	s.hs.web.ServeHTTP(rec, req)
	return rec
}

func newShippedHostServer(t *testing.T, enforceDomain bool) shippedHostServer {
	t.Helper()

	cfg, err := setting.NewCfgFromArgs(setting.CommandLineArgs{
		HomePath: "../..",
		Config:   "../../conf/defaults.ini",
	})
	require.NoError(t, err)

	// Identity strings the health handler copies into the response. They are
	// not read from the ini file; the binary stamps them at build time.
	cfg.BuildVersion = dnsRebindVersion
	cfg.BuildCommit = dnsRebindCommit
	// Leave the loaded enforce_domain value in place for the shipped-defaults
	// case. The caller sets it only when it wants the flag on top of that file.
	if enforceDomain {
		cfg.EnforceDomain = true
	}
	// Avoid parsing the repo's frontend templates. The host check does not
	// depend on those files; an empty root still runs the static middleware.
	cfg.StaticRootPath = t.TempDir()

	require.Equal(t, setting.DefaultHTTPAddr, cfg.HTTPAddr)
	require.Equal(t, "3000", cfg.HTTPPort)
	require.Equal(t, "localhost", cfg.Domain)
	require.True(t, cfg.MetricsEndpointEnabled)
	require.Empty(t, cfg.MetricsEndpointBasicAuthUsername)
	require.Empty(t, cfg.MetricsEndpointBasicAuthPassword)
	require.False(t, cfg.Anonymous.HideVersion)
	require.False(t, cfg.DisableLoginForm)
	require.False(t, cfg.DisableLogin)
	require.False(t, cfg.GrafanaJavascriptAgent.Enabled)

	web.Env = cfg.Env

	reg := prometheus.NewRegistry()
	canary := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: dnsRebindMetric,
		Help: "Canary series used to recognise a metrics response.",
	})
	canary.Set(1)
	reg.MustRegister(canary)

	features := featuremgmt.WithFeatures()
	mailer := &resetMailer{}
	hs := &HTTPServer{
		Cfg:              cfg,
		web:              web.New(),
		log:              log.New("http.server"),
		promRegister:     reg,
		promGatherer:     reg,
		tracer:           tracing.InitializeTracerForTest(),
		Features:         features,
		LoggerMiddleware: loggermw.Provide(cfg, features),
		Csrf:             csrf.ProvideCSRFFilter(cfg),
		License:          &licensing.OSSLicensingService{Cfg: cfg},
		ContextHandler:   contexthandler.ProvideService(cfg, rejectAuthenticator{}, features),
		CacheService:     localcache.New(5*time.Minute, 10*time.Minute),
		SQLStore:         dbtest.NewFakeDB(),
		pluginClient: &pluginfakes.FakePluginClient{
			CollectMetricsHandlerFunc: func(_ context.Context, _ *backend.CollectMetricsRequest) (*backend.CollectMetricsResult, error) {
				return &backend.CollectMetricsResult{PrometheusMetrics: []byte(dnsRebindPlugin + " 1\n")}, nil
			},
		},
		userService: &usertest.FakeUserService{
			ExpectedUser: &user.User{
				ID:    7,
				Email: dnsRebindUser,
				Login: "rebind-user",
				Name:  "Rebind User",
			},
		},
		authInfoService:     missingAuthInfo{},
		NotificationService: mailer,
	}

	// Same order as HTTPServer.applyRoutes: middleware (including the
	// monitoring handlers) first, then routes that do not require a session.
	hs.addMiddlewaresAndStaticRoutes()
	hs.web.Post("/api/user/password/send-reset-email", routing.Wrap(hs.SendResetPasswordEmail))
	hs.web.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return shippedHostServer{hs: hs, mailer: mailer}
}

type rejectAuthenticator struct{}

func (rejectAuthenticator) Authenticate(context.Context, *authn.Request) (*authn.Identity, error) {
	return nil, errors.New("no credentials")
}

// missingAuthInfo reports that the user has no external auth module, which is
// the path that proceeds to the mailer.
type missingAuthInfo struct{}

func (missingAuthInfo) GetAuthInfo(context.Context, *login.GetAuthInfoQuery) (*login.UserAuth, error) {
	return nil, errors.New("auth info not found")
}

func (missingAuthInfo) GetUsersRecentlyUsedLabel(context.Context, login.GetUserLabelsQuery) (map[int64]string, error) {
	return nil, errors.New("auth info not found")
}

func (missingAuthInfo) GetUserAuthModuleLabels(context.Context, int64) ([]string, error) {
	return nil, errors.New("auth info not found")
}

func (missingAuthInfo) SetAuthInfo(context.Context, *login.SetAuthInfoCommand) error {
	return errors.New("auth info not found")
}

func (missingAuthInfo) UpdateAuthInfo(context.Context, *login.UpdateAuthInfoCommand) error {
	return errors.New("auth info not found")
}

func (missingAuthInfo) DeleteUserAuthInfo(context.Context, int64) error {
	return errors.New("auth info not found")
}

// resetMailer records password-reset handoff. The production mailer queues a
// message from this call; the test fails if that handoff happens for a
// foreign Host.
type resetMailer struct {
	resets []*notifications.SendResetPasswordEmailCommand
}

func (m *resetMailer) SendResetPasswordEmail(_ context.Context, cmd *notifications.SendResetPasswordEmailCommand) error {
	m.resets = append(m.resets, cmd)
	return nil
}

func (m *resetMailer) ValidateResetPasswordCode(context.Context, *notifications.ValidateResetPasswordCodeQuery, notifications.GetUserByLoginFunc) (*user.User, error) {
	return nil, errors.New("not used")
}

func (m *resetMailer) SendWebhookSync(context.Context, *notifications.SendWebhookSync) error {
	return nil
}

func (m *resetMailer) SendEmailCommandHandlerSync(context.Context, *notifications.SendEmailCommandSync) error {
	return nil
}

func (m *resetMailer) SendEmailCommandHandler(context.Context, *notifications.SendEmailCommand) error {
	return nil
}

func (m *resetMailer) SendVerificationEmail(context.Context, *notifications.SendVerifyEmailCommand) error {
	return nil
}
