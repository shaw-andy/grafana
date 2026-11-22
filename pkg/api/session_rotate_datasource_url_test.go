package api

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/plugins/pluginassets/modulehash"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	datasourcesfakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginassets"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	sessionCookieName     = "grafana_session"
	sessionCookieValue    = "session-placeholder"
	rotatedCookieValue    = "rotated-placeholder"
	logoutRedirect        = "/logout"
	encodedLogoutRedirect = "/%6cogout"
	orgSwitchRedirect     = "/profile/switch-org/2"
	safeRedirect          = "/alerting"
	viewerUserID          = int64(7)
	viewerOrgID           = int64(1)
	otherOrgID            = int64(2)
)

func TestUseSessionStorageForRedirectionEnabledByDefault(t *testing.T) {
	t.Parallel()

	cfg := setting.NewCfg()
	fm, err := featuremgmt.ProvideManagerService(cfg)
	require.NoError(t, err)

	assert.True(t, fm.IsEnabledGlobally(featuremgmt.FlagUseSessionStorageForRedirection))
}

func TestDirectAccessPathURLIsNotPublishedInFrontendSettings(t *testing.T) {
	t.Parallel()

	pathURL := "/user/auth-tokens/rotate?redirectTo=/logout#"
	externalURL := "http://prom.example:9090"

	hs := &HTTPServer{
		Cfg:         setting.NewCfg(),
		tracer:      tracing.InitializeTracerForTest(),
		dsGuardian:  guardian.ProvideGuardian(),
		pluginStore: pluginstore.NewFakePluginStore(),
		pluginAssets: pluginassets.ProvideService(modulehash.NewCalculator(
			nil,
			registry.NewInMemory(),
			nil,
			nil,
		)),
		DataSourcesService: &datasourcesfakes.FakeDataSourceService{
			DataSources: []*datasources.DataSource{
				frontendDataSource(1, "path-prom", "prom-path", datasources.DS_PROMETHEUS, datasources.DS_ACCESS_DIRECT, pathURL),
				frontendDataSource(1, "external-prom", "prom-external", datasources.DS_PROMETHEUS, datasources.DS_ACCESS_DIRECT, externalURL),
				frontendDataSource(1, "proxy-prom", "prom-proxy", datasources.DS_PROMETHEUS, datasources.DS_ACCESS_PROXY, externalURL),
				frontendDataSource(1, "path-loki", "loki-path", datasources.DS_LOKI, datasources.DS_ACCESS_DIRECT, pathURL),
				frontendDataSource(1, "path-am", "am-path", datasources.DS_ALERTMANAGER, datasources.DS_ACCESS_DIRECT, pathURL),
				frontendDataSource(1, "path-amazon", "amazon-path", datasources.DS_AMAZON_PROMETHEUS, datasources.DS_ACCESS_DIRECT, pathURL),
				frontendDataSource(1, "path-azure", "azure-path", datasources.DS_AZURE_PROMETHEUS, datasources.DS_ACCESS_DIRECT, pathURL),
			},
		},
	}

	req := httptestNewRequest()
	ctx := &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{UserID: viewerUserID, OrgID: viewerOrgID},
		IsSignedIn:   true,
		Logger:       log.New("test"),
	}

	available := AvailablePlugins{
		plugins.TypeDataSource: map[string]*availablePluginDTO{},
	}
	for _, dsType := range []string{
		datasources.DS_PROMETHEUS,
		datasources.DS_LOKI,
		datasources.DS_ALERTMANAGER,
		datasources.DS_AMAZON_PROMETHEUS,
		datasources.DS_AZURE_PROMETHEUS,
	} {
		available[plugins.TypeDataSource][dsType] = &availablePluginDTO{
			Plugin: pluginstore.Plugin{
				JSONData: plugins.JSONData{ID: dsType, Type: plugins.TypeDataSource, Name: dsType},
			},
		}
	}

	got, err := hs.getFSDataSources(ctx, available)
	require.NoError(t, err)

	for _, name := range []string{"path-prom", "path-loki", "path-am", "path-amazon", "path-azure"} {
		dto, ok := got[name]
		require.Truef(t, ok, "missing frontend datasource %s", name)
		assert.NotContains(t, dto.URL, "/user/auth-tokens/rotate")
		assert.Truef(t,
			dto.URL == "" || hasProxyPrefix(dto.URL, dto.UID),
			"%s URL %q is still the stored browser path", name, dto.URL,
		)
		if direct, ok := dto.JSONData["directUrl"].(string); ok {
			assert.NotContains(t, direct, "/user/auth-tokens/rotate")
		}
	}

	external := got["external-prom"]
	assert.Equal(t, externalURL, external.URL)
	assert.Equal(t, externalURL, external.JSONData["directUrl"])

	proxy := got["proxy-prom"]
	assert.Equal(t, "/api/datasources/proxy/uid/prom-proxy", proxy.URL)
}

func TestSessionRotationDoesNotFollowLogoutOrOrgSwitch(t *testing.T) {
	tests := []struct {
		name       string
		redirectTo string
		dangerous  bool
	}{
		{name: "logout", redirectTo: logoutRedirect, dangerous: true},
		{name: "encoded logout", redirectTo: encodedLogoutRedirect, dangerous: true},
		{name: "org switch", redirectTo: orgSwitchRedirect, dangerous: true},
		{name: "alerting page", redirectTo: safeRedirect, dangerous: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rotatedTokens []string
			var switchedOrg int64
			logoutCalls := 0

			userSvc := &usertest.FakeUserService{
				UpdateFn: func(_ context.Context, cmd *user.UpdateUserCommand) error {
					if cmd != nil && cmd.OrgID != nil {
						switchedOrg = *cmd.OrgID
					}
					return nil
				},
			}
			logoutSvc := &logoutCounter{FakeService: &authntest.FakeService{}, calls: &logoutCalls}

			server := SetupAPITestServer(t, func(hs *HTTPServer) {
				cfg := setting.NewCfg()
				cfg.LoginCookieName = sessionCookieName
				cfg.LoginMaxLifetime = 10 * time.Hour
				hs.Cfg = cfg
				hs.log = log.New("test")
				hs.userService = userSvc
				hs.orgService = &orgtest.FakeOrgService{
					ExpectedUserOrgDTO: []*org.UserOrgDTO{{OrgID: viewerOrgID}, {OrgID: otherOrgID}},
				}
				hs.authnService = logoutSvc
				hs.AuthTokenService = &authtest.FakeUserAuthTokenService{
					RotateTokenProvider: func(_ context.Context, cmd auth.RotateCommand) (*auth.UserToken, error) {
						rotatedTokens = append(rotatedTokens, cmd.UnHashedToken)
						return &auth.UserToken{UnhashedToken: rotatedCookieValue}, nil
					},
				}
			})

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			server.HttpClient.Jar = jar
			server.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				if !tt.dangerous || (req.URL.Path != "/logout" && req.URL.Path != "/profile/switch-org/2") {
					return http.ErrUseLastResponse
				}
				req.Header.Set("X-GRAFANA-WEB-TEST-ID", via[0].Header.Get("X-GRAFANA-WEB-TEST-ID"))
				return nil
			}

			target := "/user/auth-tokens/rotate?redirectTo=" + tt.redirectTo
			req := server.NewGetRequest(target)
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookieValue, Path: "/"})
			req = webtest.RequestWithWebContext(req, &contextmodel.ReqContext{
				UseSessionStorageRedirect: true,
				IsSignedIn:                true,
				SignedInUser:              &user.SignedInUser{UserID: viewerUserID, OrgID: viewerOrgID},
			})

			res, err := server.Send(req)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())

			if tt.dangerous {
				assert.Empty(t, rotatedTokens)
				assert.Zero(t, logoutCalls)
				assert.Zero(t, switchedOrg)
				location := res.Header.Get("Location")
				assert.NotContains(t, location, "/logout")
				assert.NotContains(t, location, "/profile/switch-org/")
				return
			}

			assert.Equal(t, []string{sessionCookieValue}, rotatedTokens)
			assert.Equal(t, http.StatusFound, res.StatusCode)
			assert.Equal(t, safeRedirect, res.Header.Get("Location"))
			assert.Zero(t, logoutCalls)
			assert.Zero(t, switchedOrg)
		})
	}
}

type logoutCounter struct {
	*authntest.FakeService
	calls *int
}

func (l *logoutCounter) Logout(context.Context, identity.Requester, *auth.UserToken) (*authn.Redirect, error) {
	*l.calls++
	return &authn.Redirect{URL: "/login"}, nil
}

func frontendDataSource(orgID int64, name, uid, dsType string, access datasources.DsAccess, rawURL string) *datasources.DataSource {
	return &datasources.DataSource{
		ID:       orgID,
		OrgID:    orgID,
		Name:     name,
		UID:      uid,
		Type:     dsType,
		Access:   access,
		URL:      rawURL,
		JsonData: simplejson.New(),
	}
}

func hasProxyPrefix(rawURL, uid string) bool {
	prefix := "/api/datasources/proxy/uid/" + uid
	return rawURL == prefix || strings.HasPrefix(rawURL, prefix+"/")
}

func httptestNewRequest() *http.Request {
	req, err := http.NewRequest(http.MethodGet, "http://grafana.example/", nil)
	if err != nil {
		panic(err)
	}
	return req
}
