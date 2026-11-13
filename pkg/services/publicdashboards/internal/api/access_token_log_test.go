package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gokitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/middleware/loggermw"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	pdinternal "github.com/grafana/grafana/pkg/services/publicdashboards/internal"
	pdmodels "github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
	publicdashboardsservice "github.com/grafana/grafana/pkg/services/publicdashboards/internal/service"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const (
	defaultsPath         = "../../../../../conf/defaults.ini"
	invalidAccessToken   = "not-a-valid-access-token"
	sharedDashboardTitle = "shared-dashboard"
)

// TestPublicDashboardRequestLogOmitsAccessToken is the spec for request-log
// redaction on public dashboards. It fails while a failed request records the
// access token that a later request can use to view the same dashboard.
func TestPublicDashboardRequestLogOmitsAccessToken(t *testing.T) {
	defaults := loadDefaults(t)
	require.Equal(t, "false", defaults.Section("server").Key("router_logging").String())
	require.Equal(t, "info", defaults.Section("log").Key("level").String())
	require.Equal(t, "true", defaults.Section("public_dashboards").Key("enabled").String())

	logs := captureContextLogs(t)
	accessToken := newAccessToken(t)

	t.Run("bad panel query is logged without the token and the same token can view", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		service.On("FindByAccessToken", mock.Anything, accessToken).
			Return(&pdmodels.PublicDashboard{AccessToken: accessToken, IsEnabled: true}, nil).Once()
		service.On("GetPublicDashboardForView", mock.Anything, accessToken).
			Return(sharedDashboard(), nil).Once()

		srv := newPublicDashboardServer(t, service, false)
		status, _ := request(t, srv, http.MethodPost, "/api/public/dashboards/"+accessToken+"/panels/not-a-panel/query", pageReferer(accessToken), strings.NewReader("{}"))
		require.Equal(t, http.StatusBadRequest, status)
		failedLog := logs.String()

		logs.Reset()
		status, body := request(t, srv, http.MethodGet, "/api/public/dashboards/"+accessToken, "", nil)
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, sharedDashboardTitle)
		assertLogOmitsToken(t, logs.String(), accessToken)
		assertCompletionOmitsToken(t, failedLog, accessToken)
	})

	t.Run("query server error is logged without the token", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		service.On("FindByAccessToken", mock.Anything, accessToken).
			Return(&pdmodels.PublicDashboard{AccessToken: accessToken, IsEnabled: true}, nil).Once()
		service.On("GetQueryDataResponse", mock.Anything, false, mock.Anything, int64(2), accessToken).
			Return(nil, pdmodels.ErrInternalServerError.Errorf("query failed")).Once()

		srv := newPublicDashboardServer(t, service, false)
		status, _ := request(t, srv, http.MethodPost, "/api/public/dashboards/"+accessToken+"/panels/2/query", apiReferer(accessToken), strings.NewReader("{}"))
		require.Equal(t, http.StatusInternalServerError, status)
		line := completionLine(t, logs.String())
		require.Contains(t, line, "level=error")
		assertLogOmitsToken(t, line, accessToken)
	})

	t.Run("annotations failure keeps the token out of the log", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		// Same log message the service builds when the published dashboard is paused.
		service.On("FindAnnotations", mock.Anything, mock.Anything, accessToken).
			Return(nil, pdmodels.ErrPublicDashboardNotEnabled.Errorf("FindEnabledPublicDashboardAndDashboardByAccessToken: Public dashboard is not enabled accessToken: %s", accessToken)).Once()

		srv := newPublicDashboardServer(t, service, false)
		status, body := request(t, srv, http.MethodGet, "/api/public/dashboards/"+accessToken+"/annotations", pageReferer(accessToken), nil)
		require.Equal(t, http.StatusForbidden, status)
		require.NotContains(t, body, accessToken)
		assertCompletionOmitsToken(t, logs.String(), accessToken)
	})

	t.Run("head annotations failure keeps the token out of the log", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		service.On("FindAnnotations", mock.Anything, mock.Anything, accessToken).
			Return(nil, pdmodels.ErrPublicDashboardNotFound.Errorf("FindByAccessToken: Public dashboard not found accessToken: %s", accessToken)).Once()

		srv := newPublicDashboardServer(t, service, false)
		status, _ := request(t, srv, http.MethodHead, "/api/public/dashboards/"+accessToken+"/annotations", "", nil)
		require.Equal(t, http.StatusNotFound, status)
		assertCompletionOmitsToken(t, logs.String(), accessToken)
	})

	t.Run("missing dashboard view is logged without the token", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		service.On("GetPublicDashboardForView", mock.Anything, accessToken).
			Return(nil, pdmodels.ErrPublicDashboardNotFound.Errorf("FindByAccessToken: Public dashboard not found accessToken: %s", accessToken)).Once()

		srv := newPublicDashboardServer(t, service, false)
		status, body := request(t, srv, http.MethodGet, "/api/public/dashboards/"+accessToken, apiReferer(accessToken), nil)
		require.Equal(t, http.StatusNotFound, status)
		require.NotContains(t, body, accessToken)
		assertCompletionOmitsToken(t, logs.String(), accessToken)
	})

	t.Run("head view failure keeps the token out of the log", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		service.On("GetPublicDashboardForView", mock.Anything, accessToken).
			Return(nil, pdmodels.ErrPublicDashboardNotEnabled.Errorf("FindEnabledPublicDashboardAndDashboardByAccessToken: Public dashboard is not enabled accessToken: %s", accessToken)).Once()

		srv := newPublicDashboardServer(t, service, false)
		status, _ := request(t, srv, http.MethodHead, "/api/public/dashboards/"+accessToken, pageReferer(accessToken), nil)
		require.Equal(t, http.StatusForbidden, status)
		assertCompletionOmitsToken(t, logs.String(), accessToken)
	})

	t.Run("invalid path still logs a reusable token from the referer", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		service.On("GetPublicDashboardForView", mock.Anything, accessToken).
			Return(sharedDashboard(), nil).Once()

		srv := newPublicDashboardServer(t, service, false)
		status, _ := request(t, srv, http.MethodGet, "/api/public/dashboards/"+invalidAccessToken, pageReferer(accessToken), nil)
		require.Equal(t, http.StatusBadRequest, status)
		failedLog := logs.String()

		logs.Reset()
		status, body := request(t, srv, http.MethodGet, "/api/public/dashboards/"+accessToken, "", nil)
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, sharedDashboardTitle)
		assertLogOmitsToken(t, logs.String(), accessToken)
		assertCompletionOmitsToken(t, failedLog, accessToken)
		assertLogOmitsToken(t, failedLog, invalidAccessToken)
	})

	t.Run("successful view is omitted when router logging is off", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		service.On("GetPublicDashboardForView", mock.Anything, accessToken).
			Return(sharedDashboard(), nil).Once()

		srv := newPublicDashboardServer(t, service, false)
		status, _ := request(t, srv, http.MethodGet, "/api/public/dashboards/"+accessToken, pageReferer(accessToken), nil)
		require.Equal(t, http.StatusOK, status)
		require.NotContains(t, logs.String(), "Request Completed")
		assertLogOmitsToken(t, logs.String(), accessToken)
	})

	t.Run("successful view log omits the token when router logging is on", func(t *testing.T) {
		logs.Reset()
		service := pdinternal.NewFakePublicDashboardService(t)
		service.On("GetPublicDashboardForView", mock.Anything, accessToken).
			Return(sharedDashboard(), nil).Once()

		srv := newPublicDashboardServer(t, service, true)
		status, _ := request(t, srv, http.MethodGet, "/api/public/dashboards/"+accessToken, pageReferer(accessToken), nil)
		require.Equal(t, http.StatusOK, status)
		assertCompletionOmitsToken(t, logs.String(), accessToken)
	})
}

func loadDefaults(t *testing.T) *ini.File {
	t.Helper()
	file, err := ini.Load(defaultsPath)
	require.NoError(t, err)
	return file
}

func newAccessToken(t *testing.T) string {
	t.Helper()
	token, err := publicdashboardsservice.GenerateAccessToken()
	require.NoError(t, err)
	require.NotEmpty(t, token)
	return token
}

func sharedDashboard() *dtos.DashboardFullWithMeta {
	return &dtos.DashboardFullWithMeta{
		Dashboard: simplejson.NewFromAny(map[string]any{"title": sharedDashboardTitle}),
	}
}

func pageReferer(token string) string {
	return "http://localhost:3000/public-dashboards/" + token
}

func apiReferer(token string) string {
	return "http://localhost:3000/api/public/dashboards/" + token + "/panels/2/query"
}

func captureContextLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	// defaults.ini sets [log] level = info. pkg/infra/log maps that name to
	// level.AllowInfo, which passes info, warn, and error.
	filtered := level.NewFilter(gokitlog.NewLogfmtLogger(gokitlog.NewSyncWriter(buf)), level.AllowInfo())
	logger := log.New("context")
	logger.Swap(filtered)
	t.Cleanup(func() {
		logger.Swap(gokitlog.NewLogfmtLogger(gokitlog.NewSyncWriter(io.Discard)))
	})
	return buf
}

func newPublicDashboardServer(t *testing.T, service pdinternal.Service, routerLogging bool) *httptest.Server {
	t.Helper()

	cfg := setting.NewCfg()
	// Zero-value RouterLogging matches conf/defaults.ini. The flag is set from
	// the argument so one case can cover router_logging = true.
	cfg.RouterLogging = routerLogging
	cfg.PublicDashboardsEnabled = true
	cfg.LoginCookieName = "grafana_session"

	features := featuremgmt.WithFeatures()
	ctxHandler := contexthandler.ProvideService(cfg, &authntest.FakeService{
		ExpectedIdentity: &authn.Identity{ID: "0", Type: claims.TypeAnonymous},
	}, features)

	m := web.New()
	// Logger, then a macaron middleware, then context. That is the order in
	// pkg/api/http_server.go: the macaron middleware publishes the logger's
	// request on the web context before the context handler stores ReqContext
	// back onto that same request.
	m.UseMiddleware(loggermw.Provide(cfg, features).Middleware())
	m.Use(middleware.AddDefaultResponseHeaders(cfg))
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	m.UseMiddleware(ctxHandler.Middleware)

	rr := routing.NewRouteRegister()
	ProvideApi(
		service,
		rr,
		acimpl.ProvideAccessControl(features),
		features,
		&Middleware{},
		cfg,
		&licensing.OSSLicensingService{},
	)
	rr.Register(m)

	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv
}

func request(t *testing.T, srv *httptest.Server, method, path, referer string, body io.Reader) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(payload)
}

func assertCompletionOmitsToken(t *testing.T, logText, token string) {
	t.Helper()
	line := completionLine(t, logText)
	require.Contains(t, line, "Request Completed")
	assertLogOmitsToken(t, line, token)
}

func completionLine(t *testing.T, logText string) string {
	t.Helper()
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, "Request Completed") {
			return line
		}
	}
	t.Fatalf("expected a request completion log, got %q", logText)
	return ""
}

func assertLogOmitsToken(t *testing.T, logText, token string) {
	t.Helper()
	if token != "" && strings.Contains(logText, token) {
		t.Fatalf("request log contains the public dashboard access token: %s", strings.ReplaceAll(logText, token, "ACCESS_TOKEN"))
	}
}
