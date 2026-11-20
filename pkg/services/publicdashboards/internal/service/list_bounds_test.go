package service

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/database"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

// maxPublicDashboardListPageSize matches the cap enforced on the list query.
// Dashboard search must be given at most this many identifiers, and at most
// the requested page size when that size is smaller.
const maxPublicDashboardListPageSize = 1000

// searchCall is the dashboard search request FindAllWithPagination builds.
// buildDashboardSearchRequest copies DashboardUIDs into the search field
// values and, when Limit is below 1, replaces it with 1000 before
// k8sHandler.Search forwards the request unchanged.
type searchCall struct {
	dashboardUIDs []string
	limit         int64
}

// TestFindAllWithPaginationDoesNotSearchEveryDashboard fails while one list
// page asks dashboard search for every public dashboard in the org. It passes
// once each call passes only that page's identifiers, still returns that page
// for a viewer who can see the dashboards, and still withholds rows from a
// viewer who cannot.
func TestFindAllWithPaginationDoesNotSearchEveryDashboard(t *testing.T) {
	const (
		orgID    = int64(7)
		otherOrg = int64(8)
		pageSize = 1
		rowCount = 4
	)

	sqlStore := db.NewTestStore(t)
	cfg := setting.NewCfg()
	pdStore := database.ProvideStore(sqlStore, cfg, featuremgmt.WithFeatures())
	orgDashboards := make([]string, 0, rowCount)
	for i := 0; i < rowCount; i++ {
		orgDashboards = append(orgDashboards, insertListSharingRow(t, pdStore, orgID, i))
	}
	otherDashboard := insertListSharingRow(t, pdStore, otherOrg, 100)

	viewer := &user.SignedInUser{
		UserID:      4,
		OrgID:       orgID,
		OrgRole:     org.RoleViewer,
		Login:       "viewer",
		Permissions: map[int64]map[string][]string{},
	}

	t.Run("viewer who can see the dashboards searches one page at a time", func(t *testing.T) {
		fakeDash := &dashboards.FakeDashboardService{}
		var calls []searchCall
		fakeDash.On("FindDashboards", mock.Anything, mock.Anything).Return(
			func(ctx context.Context, query *dashboards.FindPersistedDashboardsQuery) ([]dashboards.DashboardSearchProjection, error) {
				calls = append(calls, recordSearchCall(query))
				found := make([]dashboards.DashboardSearchProjection, len(query.DashboardUIDs))
				for i, uid := range query.DashboardUIDs {
					found[i] = dashboards.DashboardSearchProjection{UID: uid, Title: uid, OrgID: query.OrgId}
				}
				return found, nil
			},
			nil,
		)
		svc, _, _ := newPublicDashboardServiceImpl(t, sqlStore, cfg, pdStore, fakeDash, nil)

		var seen []string
		for page := 1; page <= 2; page++ {
			before := len(calls)
			resp, err := svc.FindAllWithPagination(context.Background(), &models.PublicDashboardListQuery{
				OrgID: orgID,
				Page:  page,
				Limit: pageSize,
				User:  viewer,
			})
			require.NoError(t, err)
			require.Len(t, resp.PublicDashboards, pageSize)
			require.Greater(t, len(calls), before)
			call := calls[len(calls)-1]
			assertSearchCallBounded(t, call, pageSize)
			require.NotContains(t, call.dashboardUIDs, otherDashboard)
			for _, uid := range call.dashboardUIDs {
				require.Contains(t, orgDashboards, uid)
			}
			require.Contains(t, call.dashboardUIDs, resp.PublicDashboards[0].DashboardUid)
			seen = append(seen, resp.PublicDashboards[0].DashboardUid)
		}
		require.NotEqual(t, seen[0], seen[1])
		require.Len(t, calls, 2)
	})

	t.Run("repeating the first page searches the page again, not the whole org", func(t *testing.T) {
		fakeDash := &dashboards.FakeDashboardService{}
		var calls []searchCall
		fakeDash.On("FindDashboards", mock.Anything, mock.Anything).Return(
			func(ctx context.Context, query *dashboards.FindPersistedDashboardsQuery) ([]dashboards.DashboardSearchProjection, error) {
				calls = append(calls, recordSearchCall(query))
				found := make([]dashboards.DashboardSearchProjection, len(query.DashboardUIDs))
				for i, uid := range query.DashboardUIDs {
					found[i] = dashboards.DashboardSearchProjection{UID: uid, Title: uid, OrgID: query.OrgId}
				}
				return found, nil
			},
			nil,
		)
		svc, _, _ := newPublicDashboardServiceImpl(t, sqlStore, cfg, pdStore, fakeDash, nil)
		for range 2 {
			_, err := svc.FindAllWithPagination(context.Background(), &models.PublicDashboardListQuery{
				OrgID: orgID,
				Page:  1,
				Limit: pageSize,
				User:  viewer,
			})
			require.NoError(t, err)
		}
		require.Len(t, calls, 2)
		for _, call := range calls {
			assertSearchCallBounded(t, call, pageSize)
		}
	})

	t.Run("viewer with no dashboard access still searches only the page", func(t *testing.T) {
		fakeDash := &dashboards.FakeDashboardService{}
		var calls []searchCall
		fakeDash.On("FindDashboards", mock.Anything, mock.Anything).Return(
			func(ctx context.Context, query *dashboards.FindPersistedDashboardsQuery) ([]dashboards.DashboardSearchProjection, error) {
				calls = append(calls, recordSearchCall(query))
				return []dashboards.DashboardSearchProjection{}, nil
			},
			nil,
		)
		svc, _, _ := newPublicDashboardServiceImpl(t, sqlStore, cfg, pdStore, fakeDash, nil)
		resp, err := svc.FindAllWithPagination(context.Background(), &models.PublicDashboardListQuery{
			OrgID: orgID,
			Page:  1,
			Limit: pageSize,
			User:  viewer,
		})
		require.NoError(t, err)
		require.Empty(t, resp.PublicDashboards)
		require.NotEmpty(t, calls)
		for _, call := range calls {
			assertSearchCallBounded(t, call, pageSize)
			require.NotContains(t, call.dashboardUIDs, otherDashboard)
		}
	})

	t.Run("limit above the cap searches at most the cap", func(t *testing.T) {
		cappedStore := db.NewTestStore(t)
		cappedPublic := database.ProvideStore(cappedStore, cfg, featuremgmt.WithFeatures())
		const aboveCap = maxPublicDashboardListPageSize + 1
		for i := 0; i < aboveCap; i++ {
			insertListSharingRow(t, cappedPublic, orgID, i)
		}
		fakeDash := &dashboards.FakeDashboardService{}
		var calls []searchCall
		fakeDash.On("FindDashboards", mock.Anything, mock.Anything).Return(
			func(ctx context.Context, query *dashboards.FindPersistedDashboardsQuery) ([]dashboards.DashboardSearchProjection, error) {
				calls = append(calls, recordSearchCall(query))
				return []dashboards.DashboardSearchProjection{}, nil
			},
			nil,
		)
		svc, _, _ := newPublicDashboardServiceImpl(t, cappedStore, cfg, cappedPublic, fakeDash, nil)
		_, err := svc.FindAllWithPagination(context.Background(), &models.PublicDashboardListQuery{
			OrgID: orgID,
			Page:  1,
			Limit: 500000,
			User:  viewer,
		})
		require.NoError(t, err)
		require.NotEmpty(t, calls)
		for _, call := range calls {
			assertSearchCallBounded(t, call, maxPublicDashboardListPageSize)
		}
	})
}

func recordSearchCall(query *dashboards.FindPersistedDashboardsQuery) searchCall {
	uids := append([]string(nil), query.DashboardUIDs...)
	limit := query.Limit
	// Same substitution as DashboardServiceImpl.buildDashboardSearchRequest.
	if limit < 1 {
		limit = 1000
	}
	return searchCall{dashboardUIDs: uids, limit: limit}
}

func assertSearchCallBounded(t *testing.T, call searchCall, maxRows int) {
	t.Helper()
	require.NotEmpty(t, call.dashboardUIDs)
	require.LessOrEqual(t, len(call.dashboardUIDs), maxRows)
	require.Greater(t, call.limit, int64(0))
	require.LessOrEqual(t, call.limit, int64(maxRows))
}

func insertListSharingRow(t *testing.T, store *database.PublicDashboardStoreImpl, orgID int64, n int) string {
	t.Helper()
	dashboardUID := "dash-uid-" + strconv.Itoa(int(orgID)) + "-" + strconv.Itoa(n)
	_, err := store.Create(context.Background(), models.SavePublicDashboardCommand{
		PublicDashboard: models.PublicDashboard{
			Uid:          "pub-uid-" + strconv.Itoa(int(orgID)) + "-" + strconv.Itoa(n),
			DashboardUid: dashboardUID,
			OrgId:        orgID,
			AccessToken:  "placeholder-token-" + strconv.Itoa(int(orgID)) + "-" + strconv.Itoa(n),
			CreatedBy:    1,
			CreatedAt:    time.Unix(1_700_000_000, 0).UTC().Add(time.Duration(n) * time.Second),
			IsEnabled:    true,
			TimeSettings: &models.TimeSettings{},
			Share:        models.PublicShareType,
		},
	})
	require.NoError(t, err)
	return dashboardUID
}
