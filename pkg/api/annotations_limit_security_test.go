package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// maxAnnotationLimit matches the cap dashboard search already enforces in Search.
// Callers who can read annotations must not be able to choose a larger value.
const maxAnnotationLimit int64 = 5000

// viewerAnnotationRead is the permission seeded for the Viewer role
// (fixed:annotations:reader). EvalPermission(annotations:read) has no scope, so
// this grant is enough to reach both list handlers.
func viewerAnnotationRead() []accesscontrol.Permission {
	return []accesscontrol.Permission{{
		Action: accesscontrol.ActionAnnotationsRead,
		Scope:  accesscontrol.ScopeAnnotationsTypeOrganization,
	}}
}

func TestGetAnnotationsBoundsCallerLimit(t *testing.T) {
	tests := []struct {
		name  string
		query string
		limit int64
	}{
		{
			name:  "attack path limit is not forwarded",
			query: "/api/annotations?dashboardUID=any&limit=2000000000",
			limit: 2_000_000_000,
		},
		{
			name:  "limit just above the dashboard search cap is not forwarded",
			query: "/api/annotations?dashboardUID=any&limit=5001",
			limit: 5001,
		},
		{
			name:  "negative limit is not forwarded",
			query: "/api/annotations?dashboardUID=any&limit=-1",
			limit: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &annotations.FakeAnnotationsRepo{}
			var got *annotations.ItemQuery
			repo.On("Find", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				got = args.Get(1).(*annotations.ItemQuery)
			}).Return([]*annotations.ItemDTO{}, nil)

			status := sendAnnotationRequest(t, repo, http.MethodGet, tt.query)
			require.NotEqualf(t, http.StatusForbidden, status, "annotations:read must reach the handler; the limit check is separate from authorization")
			require.NotEqual(t, http.StatusUnauthorized, status)
			assertCallerLimitBounded(t, status, got != nil, limitOfItemQuery(got), tt.limit)
		})
	}
}

func TestGetAnnotationsAllowsLimitAtSearchCap(t *testing.T) {
	repo := &annotations.FakeAnnotationsRepo{}
	var got *annotations.ItemQuery
	repo.On("Find", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		got = args.Get(1).(*annotations.ItemQuery)
	}).Return([]*annotations.ItemDTO{}, nil)

	status := sendAnnotationRequest(t, repo, http.MethodGet, "/api/annotations?dashboardUID=any&limit=5000")
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, got)
	require.Equal(t, int64(5000), got.Limit)
	require.Equal(t, "any", got.DashboardUID)
}

func TestGetAnnotationTagsBoundsCallerLimit(t *testing.T) {
	tests := []struct {
		name  string
		query string
		limit int64
	}{
		{
			name:  "attack path limit is not interpolated via the repository query",
			query: "/api/annotations/tags?limit=2000000000",
			limit: 2_000_000_000,
		},
		{
			name:  "limit just above the dashboard search cap is not forwarded",
			query: "/api/annotations/tags?limit=5001",
			limit: 5001,
		},
		{
			name:  "negative limit is not forwarded",
			query: "/api/annotations/tags?limit=-1",
			limit: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &annotations.FakeAnnotationsRepo{}
			var got *annotations.TagsQuery
			repo.On("FindTags", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				got = args.Get(1).(*annotations.TagsQuery)
			}).Return(annotations.FindTagsResult{}, nil)

			status := sendAnnotationRequest(t, repo, http.MethodGet, tt.query)
			require.NotEqual(t, http.StatusForbidden, status)
			require.NotEqual(t, http.StatusUnauthorized, status)
			called := got != nil
			gotLimit := int64(0)
			if called {
				gotLimit = got.Limit
			}
			assertCallerLimitBounded(t, status, called, gotLimit, tt.limit)
		})
	}
}

func sendAnnotationRequest(t *testing.T, repo annotations.Repository, method, path string) int {
	t.Helper()

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = setting.NewCfg()
		hs.annotationsRepo = repo
		hs.Features = featuremgmt.WithFeatures()
		hs.AccessControl = acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	})

	req := webtest.RequestWithSignedInUser(
		server.NewRequest(method, path, nil),
		authedUserWithPermissions(1, 1, viewerAnnotationRead()),
	)
	res, err := server.SendJSON(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, res.Body.Close())
	}()
	return res.StatusCode
}

func limitOfItemQuery(q *annotations.ItemQuery) int64 {
	if q == nil {
		return 0
	}
	return q.Limit
}

// assertCallerLimitBounded fails while the handler copies the raw query parameter
// into the repository call. A fix may reject the request or clamp the value.
// Rejection must happen before Find or FindTags is invoked with the raw value.
func assertCallerLimitBounded(t *testing.T, status int, called bool, gotLimit, rawLimit int64) {
	t.Helper()

	if called {
		require.LessOrEqualf(t, gotLimit, maxAnnotationLimit, "repository was called with caller limit %d", rawLimit)
		require.GreaterOrEqualf(t, gotLimit, int64(0), "repository was called with caller limit %d", rawLimit)
	}

	if status >= 200 && status < 300 {
		require.Truef(t, called, "successful response for limit %d did not query annotations", rawLimit)
		return
	}

	require.GreaterOrEqualf(t, status, 400, "limit %d must be rejected or clamped, got status %d", rawLimit, status)
	require.Lessf(t, status, 500, "limit %d must be a client error, got status %d", rawLimit, status)
}
