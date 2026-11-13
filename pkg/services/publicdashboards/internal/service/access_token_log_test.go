package service

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/loggermw"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	"github.com/grafana/grafana/pkg/services/org"
	publicdashboards "github.com/grafana/grafana/pkg/services/publicdashboards/internal"
	pdapi "github.com/grafana/grafana/pkg/services/publicdashboards/internal/api"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/service/intervalv2"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const dashboardUID = "abcdef"

// These tests are the spec for the public-dashboard access-token leak.
// They fail while a failed lookup still writes the access token into an
// info log, and they pass once that value is no longer written there.
// The response body is checked as well: callers must keep seeing only the
// generic public text.

func TestPublicDashboardLookupErrorsOmitAccessToken(t *testing.T) {
	token := mustAccessToken(t)

	t.Run("missing share", func(t *testing.T) {
		svc := newLookupService(pubdashStore(func(store *publicdashboards.FakePublicDashboardStore) {
			store.On("FindByAccessToken", mock.Anything, token).Return(nil, nil)
		}), &dashboards.FakeDashboardService{})

		_, err := svc.FindByAccessToken(t.Context(), token)
		requireLookupErrorOmitsToken(t, err, token, "Dashboard not found")
	})

	t.Run("disabled share", func(t *testing.T) {
		svc := newLookupService(enabledStore(token, false, models.PublicShareType), dashboardReturning(t, &dashboards.Dashboard{
			UID: dashboardUID, OrgID: 1, Data: simplejson.New(),
		}))

		_, _, err := svc.FindEnabledPublicDashboardAndDashboardByAccessToken(t.Context(), token)
		requireLookupErrorOmitsToken(t, err, token, "Dashboard paused")
	})

	t.Run("email share without license", func(t *testing.T) {
		svc := newLookupService(enabledStore(token, true, models.EmailShareType), dashboardReturning(t, &dashboards.Dashboard{
			UID: dashboardUID, OrgID: 1, Data: simplejson.New(),
		}))

		_, _, err := svc.FindEnabledPublicDashboardAndDashboardByAccessToken(t.Context(), token)
		requireLookupErrorOmitsToken(t, err, token, "Dashboard not found")
	})

	t.Run("deleted dashboard", func(t *testing.T) {
		svc := newLookupService(enabledStore(token, true, models.PublicShareType), dashboardReturning(t, nil))

		_, _, err := svc.FindPublicDashboardAndDashboardByAccessToken(t.Context(), token)
		requireLookupErrorOmitsToken(t, err, token, "Dashboard not found")
	})

	t.Run("duplicate access token on create", func(t *testing.T) {
		store := publicdashboards.FakePublicDashboardStore{}
		store.On("FindByDashboardUid", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
		store.On("Find", mock.Anything, mock.Anything).Return(nil, nil)
		store.On("FindByAccessToken", mock.Anything, token).Return(&models.PublicDashboard{AccessToken: token}, nil)
		svc := newLookupService(&store, dashboardReturning(t, &dashboards.Dashboard{
			UID: dashboardUID, OrgID: 1, Data: simplejson.New(),
		}))

		_, err := svc.Create(t.Context(), userForCreate(), &models.SavePublicDashboardDTO{
			OrgID:        1,
			UserId:       2,
			DashboardUid: dashboardUID,
			PublicDashboard: &models.PublicDashboardDTO{
				AccessToken: token,
				Share:       models.PublicShareType,
			},
		})
		requireLookupErrorOmitsToken(t, err, token, "Dashboard Access Token already exists")
	})
}

func TestFailedPublicDashboardRequestsDoNotWriteAccessTokenToInfoLogs(t *testing.T) {
	logPath := redirectInfoLogs(t)
	cfg := setting.NewCfg()
	cfg.PublicDashboardsEnabled = true
	// defaults.ini leaves router logging off and the log level at info.
	cfg.RouterLogging = false

	token := mustAccessToken(t)
	queryBody := []byte(`{"intervalMs":1000,"maxDataPoints":100}`)

	tests := []struct {
		name          string
		method        string
		path          string
		body          []byte
		status        int
		publicMessage string
		authenticated bool
		secret        string
		configure     func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService)
	}{
		{
			name:          "view missing share",
			method:        http.MethodGet,
			path:          "/api/public/dashboards/" + token,
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, _ *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(nil, nil)
			},
		},
		{
			name:          "view disabled share",
			method:        http.MethodGet,
			path:          "/api/public/dashboards/" + token,
			status:        http.StatusForbidden,
			publicMessage: "Dashboard paused",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, false, models.PublicShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{UID: dashboardUID, OrgID: 1, Data: simplejson.New()}, nil)
			},
		},
		{
			name:          "view email share without license",
			method:        http.MethodGet,
			path:          "/api/public/dashboards/" + token,
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, true, models.EmailShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{UID: dashboardUID, OrgID: 1, Data: simplejson.New()}, nil)
			},
		},
		{
			name:          "view deleted dashboard",
			method:        http.MethodGet,
			path:          "/api/public/dashboards/" + token,
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, true, models.PublicShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(nil, nil)
			},
		},
		{
			name:          "annotations missing share",
			method:        http.MethodGet,
			path:          "/api/public/dashboards/" + token + "/annotations",
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, _ *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(nil, nil)
			},
		},
		{
			name:          "annotations disabled share",
			method:        http.MethodGet,
			path:          "/api/public/dashboards/" + token + "/annotations",
			status:        http.StatusForbidden,
			publicMessage: "Dashboard paused",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, false, models.PublicShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{UID: dashboardUID, OrgID: 1, Data: simplejson.New()}, nil)
			},
		},
		{
			name:          "annotations email share without license",
			method:        http.MethodGet,
			path:          "/api/public/dashboards/" + token + "/annotations",
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, true, models.EmailShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{UID: dashboardUID, OrgID: 1, Data: simplejson.New()}, nil)
			},
		},
		{
			name:          "annotations deleted dashboard",
			method:        http.MethodGet,
			path:          "/api/public/dashboards/" + token + "/annotations",
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, true, models.PublicShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(nil, nil)
			},
		},
		{
			name:          "query missing share",
			method:        http.MethodPost,
			path:          "/api/public/dashboards/" + token + "/panels/2/query",
			body:          queryBody,
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, _ *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(nil, nil)
			},
		},
		{
			name:          "query disabled share",
			method:        http.MethodPost,
			path:          "/api/public/dashboards/" + token + "/panels/2/query",
			body:          queryBody,
			status:        http.StatusForbidden,
			publicMessage: "Dashboard paused",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, false, models.PublicShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{UID: dashboardUID, OrgID: 1, Data: simplejson.New()}, nil)
			},
		},
		{
			name:          "query email share without license",
			method:        http.MethodPost,
			path:          "/api/public/dashboards/" + token + "/panels/2/query",
			body:          queryBody,
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, true, models.EmailShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{UID: dashboardUID, OrgID: 1, Data: simplejson.New()}, nil)
			},
		},
		{
			name:          "query deleted dashboard",
			method:        http.MethodPost,
			path:          "/api/public/dashboards/" + token + "/panels/2/query",
			body:          queryBody,
			status:        http.StatusNotFound,
			publicMessage: "Dashboard not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, true, models.PublicShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(nil, nil)
			},
		},
		{
			name:          "query missing panel on enabled share",
			method:        http.MethodPost,
			path:          "/api/public/dashboards/" + token + "/panels/2/query",
			body:          queryBody,
			status:        http.StatusNotFound,
			publicMessage: "Dashboard panel not found",
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, true, models.PublicShareType), nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{UID: dashboardUID, OrgID: 1, Data: simplejson.New()}, nil)
			},
		},
		{
			name:          "create duplicate access token",
			method:        http.MethodPost,
			path:          "/api/dashboards/uid/" + dashboardUID + "/public-dashboards",
			body:          []byte(`{"accessToken":"` + token + `","share":"public"}`),
			status:        http.StatusBadRequest,
			publicMessage: "Dashboard Access Token already exists",
			authenticated: true,
			secret:        token,
			configure: func(store *publicdashboards.FakePublicDashboardStore, dash *dashboards.FakeDashboardService) {
				store.On("FindByDashboardUid", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
				store.On("Find", mock.Anything, mock.Anything).Return(nil, nil)
				store.On("FindByAccessToken", mock.Anything, token).Return(&models.PublicDashboard{AccessToken: token}, nil)
				dash.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{UID: dashboardUID, OrgID: 1, Data: simplejson.New()}, nil)
			},
		},
		{
			name:          "create invalid access token",
			method:        http.MethodPost,
			path:          "/api/dashboards/uid/" + dashboardUID + "/public-dashboards",
			body:          []byte(`{"accessToken":"not-a-valid-token","share":"public"}`),
			status:        http.StatusBadRequest,
			publicMessage: "Invalid access token",
			authenticated: true,
			secret:        "not-a-valid-token",
			configure:     func(*publicdashboards.FakePublicDashboardStore, *dashboards.FakeDashboardService) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &publicdashboards.FakePublicDashboardStore{}
			dash := &dashboards.FakeDashboardService{}
			tt.configure(store, dash)
			svc := newLookupService(store, dash)

			server := newPublicDashboardServer(t, cfg, svc, tt.authenticated)
			before := fileLen(t, logPath)

			var body io.Reader
			if tt.body != nil {
				body = bytes.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			if tt.body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, tt.status, redact(rec.Body.String(), tt.secret))
			}
			responseBody := rec.Body.String()
			if strings.Contains(responseBody, tt.secret) {
				t.Errorf("response body contains the access token: %s", redact(responseBody, tt.secret))
			}
			if !strings.Contains(responseBody, tt.publicMessage) {
				t.Fatalf("response body = %s, want public message %q", redact(responseBody, tt.secret), tt.publicMessage)
			}

			written := readFrom(t, logPath, before)
			if strings.TrimSpace(written) == "" {
				t.Fatal("failed request produced no info log")
			}
			if !strings.Contains(written, "level=info") {
				t.Fatalf("failed request was not logged at info: %s", redact(written, tt.secret))
			}
			if strings.Contains(written, tt.secret) {
				t.Errorf("info log contains the access token: %s", redact(written, tt.secret))
			}
		})
	}
}

func newLookupService(store publicdashboards.Store, dash dashboards.DashboardService) *PublicDashboardServiceImpl {
	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", models.FeaturePublicDashboardsEmailSharing).Return(false)
	return &PublicDashboardServiceImpl{
		log:                log.New("publicdashboards.service.test"),
		intervalCalculator: intervalv2.NewCalculator(),
		dashboardService:   dash,
		store:              store,
		serviceWrapper:     ProvideServiceWrapper(store),
		license:            license,
		features:           featuremgmt.WithFeatures(),
	}
}

func newPublicDashboardServer(t *testing.T, cfg *setting.Cfg, svc *PublicDashboardServiceImpl, authenticated bool) *web.Mux {
	t.Helper()

	authnService := &authntest.FakeService{ExpectedErr: errors.New("no session")}
	if authenticated {
		authnService.ExpectedErr = nil
		authnService.ExpectedIdentity = &authn.Identity{
			ID:       "2",
			Type:     claims.TypeUser,
			OrgID:    1,
			OrgRoles: map[int64]org.RoleType{1: org.RoleAdmin},
			Login:    "tester",
			Permissions: map[int64]map[string][]string{
				1: {publicdashboards.ActionDashboardsPublicWrite: {dashboards.ScopeDashboardsAll}},
			},
		}
	}

	features := featuremgmt.WithFeatures()
	m := web.New()
	// Same order as HTTPServer.addMiddlewaresAndStaticRoutes: the request
	// logger runs, then a macaron handler, then the context handler.
	m.UseMiddleware(loggermw.Provide(cfg, features).Middleware())
	m.Use(middleware.AddDefaultResponseHeaders(cfg))
	m.UseMiddleware(contexthandler.ProvideService(cfg, authnService, features).Middleware)

	rr := routing.NewRouteRegister()
	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", mock.Anything).Return(false)
	pdapi.ProvideApi(svc, rr, acimpl.ProvideAccessControl(features), features, &pdapi.Middleware{}, cfg, license)
	rr.Register(m.Router)
	return m
}

func redirectInfoLogs(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "grafana.log")
	require.NoError(t, configureFileLog(path, "info"))
	t.Cleanup(func() {
		_ = configureFileLog(os.DevNull, "error")
	})

	log.New("context").Info("public-dashboard-log-probe")
	probe, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(probe), "public-dashboard-log-probe")
	return path
}

func configureFileLog(path, levelName string) error {
	iniFile := ini.Empty()
	logSec, err := iniFile.NewSection("log")
	if err != nil {
		return err
	}
	if _, err = logSec.NewKey("level", levelName); err != nil {
		return err
	}
	fileSec, err := iniFile.NewSection("log.file")
	if err != nil {
		return err
	}
	for _, kv := range [][2]string{
		{"level", levelName},
		{"format", "text"},
		{"file_name", path},
		{"log_rotate", "false"},
		{"daily_rotate", "false"},
	} {
		if _, err = fileSec.NewKey(kv[0], kv[1]); err != nil {
			return err
		}
	}
	return log.ReadLoggingConfig([]string{"file"}, filepath.Dir(path), iniFile)
}

func requireLookupErrorOmitsToken(t *testing.T, err error, token, publicMessage string) {
	t.Helper()
	var gfErr errutil.Error
	require.ErrorAs(t, err, &gfErr)
	if gfErr.LogMessage == "" {
		t.Fatal("lookup error has an empty log message")
	}
	if strings.Contains(gfErr.LogMessage, token) || strings.Contains(gfErr.Error(), token) {
		t.Errorf("log message contains the access token: %s", redact(gfErr.Error(), token))
	}
	if gfErr.Public().Message != publicMessage {
		t.Fatalf("public message = %q, want %q", gfErr.Public().Message, publicMessage)
	}
	if strings.Contains(gfErr.Public().Message, token) || strings.Contains(gfErr.Public().Error(), token) {
		t.Errorf("public error contains the access token: %s", redact(gfErr.Public().Error(), token))
	}
}

func enabledStore(token string, enabled bool, share models.ShareType) *publicdashboards.FakePublicDashboardStore {
	store := &publicdashboards.FakePublicDashboardStore{}
	store.On("FindByAccessToken", mock.Anything, token).Return(enabledPubdash(token, enabled, share), nil)
	return store
}

func enabledPubdash(token string, enabled bool, share models.ShareType) *models.PublicDashboard {
	return &models.PublicDashboard{
		Uid:          "pubdash1",
		DashboardUid: dashboardUID,
		OrgId:        1,
		AccessToken:  token,
		IsEnabled:    enabled,
		Share:        share,
	}
}

func pubdashStore(configure func(*publicdashboards.FakePublicDashboardStore)) *publicdashboards.FakePublicDashboardStore {
	store := &publicdashboards.FakePublicDashboardStore{}
	configure(store)
	return store
}

func dashboardReturning(t *testing.T, dash *dashboards.Dashboard) *dashboards.FakeDashboardService {
	t.Helper()
	svc := &dashboards.FakeDashboardService{}
	svc.On("GetDashboard", mock.Anything, mock.Anything).Return(dash, nil)
	return svc
}

func userForCreate() *user.SignedInUser {
	return &user.SignedInUser{UserID: 2, OrgID: 1, Login: "tester"}
}

func mustAccessToken(t *testing.T) string {
	t.Helper()
	token, err := GenerateAccessToken()
	require.NoError(t, err)
	require.NotEmpty(t, token)
	return token
}

func fileLen(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Size()
}

func readFrom(t *testing.T, path string, offset int64) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	_, err = f.Seek(offset, io.SeekStart)
	require.NoError(t, err)
	buf, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(buf)
}

func redact(value, secret string) string {
	if secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, "<redacted>")
}
