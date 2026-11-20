package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

func TestGetDashboardTagsAuthorization(t *testing.T) {
	t.Run("signed-in user without dashboards read does not reach the search", func(t *testing.T) {
		server, svc := newDashboardTagsServer(t)
		allowTagsSearch(svc)
		res, err := server.Send(webtest.RequestWithSignedInUser(
			server.NewGetRequest("/api/dashboards/tags"),
			userWithPermissions(1, []accesscontrol.Permission{{Action: "annotations:read"}}),
		))
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, res.StatusCode)
		require.NoError(t, res.Body.Close())
		svc.AssertNotCalled(t, "GetDashboardTags", mock.Anything, mock.Anything)
	})

	t.Run("dashboards read in another org does not search the current org", func(t *testing.T) {
		server, svc := newDashboardTagsServer(t)
		allowTagsSearch(svc)
		user := userWithPermissions(2, []accesscontrol.Permission{{
			Action: dashboards.ActionDashboardsRead,
			Scope:  dashboards.ScopeDashboardsAll,
		}})
		user.OrgID = 1
		res, err := server.Send(webtest.RequestWithSignedInUser(server.NewGetRequest("/api/dashboards/tags"), user))
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, res.StatusCode)
		require.NoError(t, res.Body.Close())
		svc.AssertNotCalled(t, "GetDashboardTags", mock.Anything, mock.Anything)
	})

	t.Run("dashboards read in the current org searches only that org", func(t *testing.T) {
		server, svc := newDashboardTagsServer(t)
		svc.On("GetDashboardTags", mock.Anything, mock.MatchedBy(func(q *dashboards.GetDashboardTagsQuery) bool {
			return q != nil && q.OrgID == 1
		})).Return([]*dashboards.DashboardTagCloudItem{{Term: "shared", Count: 2}}, nil).Once()

		res, err := server.Send(webtest.RequestWithSignedInUser(
			server.NewGetRequest("/api/dashboards/tags"),
			userWithPermissions(1, []accesscontrol.Permission{{
				Action: dashboards.ActionDashboardsRead,
				Scope:  dashboards.ScopeDashboardsAll,
			}}),
		))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.NoError(t, res.Body.Close())
	})

	t.Run("no session does not reach the search", func(t *testing.T) {
		server, svc := newDashboardTagsServer(t)
		allowTagsSearch(svc)
		res, err := server.Send(server.NewGetRequest("/api/dashboards/tags"))
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
		require.NoError(t, res.Body.Close())
		svc.AssertNotCalled(t, "GetDashboardTags", mock.Anything, mock.Anything)
	})
}

func allowTagsSearch(svc *dashboards.FakeDashboardService) {
	svc.On("GetDashboardTags", mock.Anything, mock.Anything).
		Return([]*dashboards.DashboardTagCloudItem{}, nil).Maybe()
}

func newDashboardTagsServer(t *testing.T) (*webtest.Server, *dashboards.FakeDashboardService) {
	t.Helper()
	svc := dashboards.NewFakeDashboardService(t)
	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = setting.NewCfg()
		hs.DashboardService = svc
	})
	return server, svc
}
