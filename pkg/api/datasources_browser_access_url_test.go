package api

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

// browserAccessURLIsSafeToHandToTheBrowser reports whether a datasource URL string
// can be published to the browser without the case-sensitive local-URL check
// treating an external host as a Grafana-local request.
//
// net/url.Parse lowercases the scheme on the parsed value and leaves the caller's
// string unchanged, so a check against parsed.Scheme hides an uppercase scheme
// that boot data and the browser still receive.
func browserAccessURLIsSafeToHandToTheBrowser(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() != "collector.example" {
		return false
	}
	return strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
}

func TestAddAndUpdateDataSource_DirectAccessUppercaseSchemeIsRejectedOrNormalized(t *testing.T) {
	const rawURL = "HTTPS://collector.example/graphite"

	newServer := func(ds datasources.DataSourceService) *HTTPServer {
		hs := &HTTPServer{
			DataSourcesService:   ds,
			Cfg:                  setting.NewCfg(),
			AccessControl:        acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
			accesscontrolService: actest.FakeService{},
			Live:                 newTestLive(t),
		}
		hs.promRegister, hs.dsConfigHandlerRequestsDuration, hs.dsEndpointRedirects = setupDsConfigHandlerMetrics()
		return hs
	}

	t.Run("add", func(t *testing.T) {
		var storedURL string
		hs := newServer(&dataSourcesServiceMock{
			mockAddDataSource: func(_ context.Context, cmd *datasources.AddDataSourceCommand) (*datasources.DataSource, error) {
				storedURL = cmd.URL
				return &datasources.DataSource{
					ID:     1,
					UID:    "graphite-uid",
					Name:   cmd.Name,
					Type:   cmd.Type,
					Access: cmd.Access,
					URL:    cmd.URL,
				}, nil
			},
		})

		sc := setupScenarioContext(t, "/api/datasources")
		sc.m.Post(sc.url, routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
			c.Req.Body = mockRequestBody(datasources.AddDataSourceCommand{
				Name:   "graphite",
				Type:   datasources.DS_GRAPHITE,
				Access: datasources.DS_ACCESS_DIRECT,
				URL:    rawURL,
			})
			c.SignedInUser = authedUserWithPermissions(testOrgID, testUserID, nil)
			return hs.AddDataSource(c)
		}))
		sc.fakeReqWithParams("POST", sc.url, map[string]string{}).exec()

		if sc.resp.Code >= 400 {
			require.Less(t, sc.resp.Code, 500, sc.resp.Body.String())
			require.Contains(t, strings.ToLower(sc.resp.Body.String()), "url")
			return
		}
		require.Equal(t, 200, sc.resp.Code)
		require.Truef(t, browserAccessURLIsSafeToHandToTheBrowser(storedURL), "add stored %q", storedURL)
	})

	t.Run("update by uid", func(t *testing.T) {
		var storedURL string
		existing := &datasources.DataSource{
			ID:     1,
			UID:    "graphite-uid",
			OrgID:  testOrgID,
			Name:   "graphite",
			Type:   datasources.DS_GRAPHITE,
			Access: datasources.DS_ACCESS_DIRECT,
			URL:    "https://old.example",
		}
		hs := newServer(&dataSourcesServiceMock{
			expectedDatasource: existing,
			mockUpdateDataSource: func(_ context.Context, cmd *datasources.UpdateDataSourceCommand) (*datasources.DataSource, error) {
				storedURL = cmd.URL
				updated := *existing
				updated.URL = cmd.URL
				updated.Name = cmd.Name
				updated.Access = cmd.Access
				return &updated, nil
			},
		})

		sc := setupScenarioContext(t, "/api/datasources/uid/graphite-uid")
		sc.m.Put("/api/datasources/uid/:uid", routing.Wrap(func(c *contextmodel.ReqContext) response.Response {
			c.Req.Body = mockRequestBody(datasources.UpdateDataSourceCommand{
				Name:   "graphite",
				Type:   datasources.DS_GRAPHITE,
				Access: datasources.DS_ACCESS_DIRECT,
				URL:    rawURL,
				UID:    "graphite-uid",
			})
			c.SignedInUser = authedUserWithPermissions(testOrgID, testUserID, nil)
			return hs.UpdateDataSourceByUID(c)
		}))
		sc.fakeReqWithParams("PUT", "/api/datasources/uid/graphite-uid", map[string]string{}).exec()

		if sc.resp.Code >= 400 {
			require.Less(t, sc.resp.Code, 500, sc.resp.Body.String())
			require.Contains(t, strings.ToLower(sc.resp.Body.String()), "url")
			return
		}
		require.Equal(t, 200, sc.resp.Code)
		require.Truef(t, browserAccessURLIsSafeToHandToTheBrowser(storedURL), "update stored %q", storedURL)
	})
}
