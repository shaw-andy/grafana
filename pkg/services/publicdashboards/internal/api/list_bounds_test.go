package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	"github.com/grafana/grafana/pkg/services/org"
	publicdashboards "github.com/grafana/grafana/pkg/services/publicdashboards/internal"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// maxPublicDashboardListPageSize is the largest perpage ListPublicDashboards
// may forward. A missing or non-positive perpage already becomes 1000; a
// larger value must be clamped to at most this.
const maxPublicDashboardListPageSize = 1000

// TestListPublicDashboardsPageSizeIsCapped fails while the list handler
// forwards an attacker-chosen perpage straight through. It passes once a
// signed-in viewer, and an anonymous session when anonymous access is on,
// can still list, but only with a page size inside the cap. perpage=1 stays 1.
func TestListPublicDashboardsPageSizeIsCapped(t *testing.T) {
	viewer := &user.SignedInUser{
		UserID:      4,
		OrgID:       1,
		OrgRole:     org.RoleViewer,
		Login:       "viewer",
		Permissions: map[int64]map[string][]string{},
	}
	anonymous := &user.SignedInUser{
		IsAnonymous: true,
		OrgID:       1,
		OrgRole:     org.RoleViewer,
	}

	t.Run("signed-in viewer with no public-dashboard write permission", func(t *testing.T) {
		assertListPageLimit(t, viewer, false, "/api/dashboards/public-dashboards?page=1&perpage=1", 1)
		assertListPageLimit(t, viewer, false, "/api/dashboards/public-dashboards?page=1&perpage=1000000", maxPublicDashboardListPageSize)
	})

	t.Run("anonymous session when anonymous access is enabled", func(t *testing.T) {
		assertListPageLimit(t, anonymous, true, "/api/dashboards/public-dashboards?page=1&perpage=1", 1)
		assertListPageLimit(t, anonymous, true, "/api/dashboards/public-dashboards?page=1&perpage=1000000", maxPublicDashboardListPageSize)
	})

	t.Run("signed-out request does not reach the list", func(t *testing.T) {
		service := publicdashboards.NewFakePublicDashboardService(t)
		server := setupListBoundsServer(t, service, nil, false)
		response := callAPI(server, http.MethodGet, "/api/dashboards/public-dashboards?page=1&perpage=1", nil, t)
		require.Equal(t, http.StatusUnauthorized, response.Code)
		service.AssertNotCalled(t, "FindAllWithPagination", mock.Anything, mock.Anything)
	})
}

func assertListPageLimit(t *testing.T, u *user.SignedInUser, anonymousAccess bool, path string, maxLimit int) {
	t.Helper()
	service := publicdashboards.NewFakePublicDashboardService(t)
	var gotLimit int
	var called bool
	service.On("FindAllWithPagination", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		called = true
		query := args.Get(1).(*models.PublicDashboardListQuery)
		gotLimit = query.Limit
	}).Return(&models.PublicDashboardListResponseWithPagination{
		PublicDashboards: []*models.PublicDashboardListResponse{},
	}, nil)

	server := setupListBoundsServer(t, service, u, anonymousAccess)
	response := callAPI(server, http.MethodGet, path, nil, t)
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, called)
	require.Greater(t, gotLimit, 0)
	require.LessOrEqual(t, gotLimit, maxLimit)
}

// setupListBoundsServer registers the real list route. anonymousAccess mirrors
// ContextHandler: an anonymous identity is not signed in and is allowed
// through ReqSignedIn only when anonymous access produced that identity.
func setupListBoundsServer(t *testing.T, service publicdashboards.Service, u *user.SignedInUser, anonymousAccess bool) *web.Mux {
	t.Helper()

	rr := routing.NewRouteRegister()
	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	m := web.New()
	m.Use(func(c *web.Context) {
		signedIn := u != nil && !u.IsAnonymous
		allowAnonymous := false
		if anonymousAccess && u != nil && u.IsAnonymous {
			signedIn = false
			allowAnonymous = true
		}
		reqCtx := &contextmodel.ReqContext{
			Context:        c,
			SignedInUser:   u,
			IsSignedIn:     signedIn,
			AllowAnonymous: allowAnonymous,
			Logger:         log.New("publicdashboards-list-bounds-test"),
		}
		c.Req = c.Req.WithContext(ctxkey.Set(c.Req.Context(), reqCtx))
	})

	cfg := setting.NewCfg()
	cfg.PublicDashboardsEnabled = true
	features := featuremgmt.WithFeatures()
	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", models.FeaturePublicDashboardsEmailSharing).Return(false)
	ProvideApi(service, rr, ac, features, &Middleware{}, cfg, license)
	rr.Register(m.Router)
	return m
}
