package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/authz"
	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/kinds/dashboard"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/annotations/annotationsimpl"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	publicdashboards "github.com/grafana/grafana/pkg/services/publicdashboards/internal"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/api"
	"github.com/grafana/grafana/pkg/services/publicdashboards/internal/models"
	"github.com/grafana/grafana/pkg/services/search/model"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/tag/tagimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// placeholderAccessToken is an obvious placeholder for the public dashboard
	// access token. It is not a credential from any deployment.
	placeholderAccessToken = "00000000-0000-4000-8000-000000000001"

	publishedDashboardUID = "pubdash1"
	privateDashboardUID   = "privdash"
	otherOrgDashboardUID  = "otherorg"

	publishedNote   = "published-dashboard-note"
	privateNote     = "private-dashboard-note"
	unrelatedNote   = "unrelated-tag-note"
	untaggedPublic  = "untagged-published-note"
	untaggedPrivate = "untagged-private-note"
	orgNote         = "organization-annotation-note"
	otherOrgNote    = "other-organization-note"

	annotationEpoch int64 = 1_700_000_000_000
	queryFrom       int64 = 1_600_000_000_000
	queryTo         int64 = 1_800_000_000_000
)

// dashboardReadActions are the actions checkPermissionWithMapping accepts for a
// dashboard get. The direct action is dashboards:read; the rest are the action
// sets registered for that verb.
var dashboardReadActions = []string{
	dashboards.ActionDashboardsRead,
	"dashboards:view",
	"folders:view",
	"dashboards:edit",
	"folders:edit",
	"dashboards:admin",
	"folders:admin",
}

// TestIntegrationPublicAnnotationQueriesDoNotCrossDashboards is the spec for
// public annotation reads. Tag queries must not return annotation text, tags,
// or dashboard UIDs from any dashboard other than the one published with the
// access token, and they must not return organization annotations.
func TestIntegrationPublicAnnotationQueriesDoNotCrossDashboards(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	sqlStore, cfg := db.InitTestDBWithCfg(t)
	cfg.AnnotationMaximumTagsLength = 60
	catalog := &annotationDashboardCatalog{}
	published := newAnnotationDashboard(t, "Published", publishedDashboardUID, 11, 1, nil)
	privateDash := newAnnotationDashboard(t, "Private", privateDashboardUID, 22, 1, nil)
	otherOrg := newAnnotationDashboard(t, "Other org", otherOrgDashboardUID, 33, 2, nil)
	catalog.dashboards = []*dashboards.Dashboard{published, privateDash, otherOrg}

	dashSvc := dashboards.NewFakeDashboardService(t)
	dashSvc.On("GetDashboard", mock.Anything, mock.Anything).Return(catalog.get)
	dashSvc.On("SearchDashboards", mock.Anything, mock.Anything).Return(catalog.search)

	repo := annotationsimpl.ProvideService(
		sqlStore,
		cfg,
		featuremgmt.WithFeatures(),
		tagimpl.ProvideService(sqlStore),
		tracing.InitializeTracerForTest(),
		nil,
		dashSvc,
		prometheus.NewRegistry(),
	)
	seedAnnotation(t, repo, &annotations.Item{
		OrgID: 1, DashboardID: published.ID, DashboardUID: published.UID,
		Text: publishedNote, Epoch: annotationEpoch, Tags: []string{"incident"},
	})
	seedAnnotation(t, repo, &annotations.Item{
		OrgID: 1, DashboardID: privateDash.ID, DashboardUID: privateDash.UID,
		Text: privateNote, Epoch: annotationEpoch, Tags: []string{"incident"},
	})
	seedAnnotation(t, repo, &annotations.Item{
		OrgID: 1, DashboardID: privateDash.ID, DashboardUID: privateDash.UID,
		Text: unrelatedNote, Epoch: annotationEpoch, Tags: []string{"unrelated"},
	})
	seedAnnotation(t, repo, &annotations.Item{
		OrgID: 1, DashboardID: published.ID, DashboardUID: published.UID,
		Text: untaggedPublic, Epoch: annotationEpoch,
	})
	seedAnnotation(t, repo, &annotations.Item{
		OrgID: 1, DashboardID: privateDash.ID, DashboardUID: privateDash.UID,
		Text: untaggedPrivate, Epoch: annotationEpoch,
	})
	seedAnnotation(t, repo, &annotations.Item{
		OrgID: 1, Text: orgNote, Epoch: annotationEpoch, Tags: []string{"incident"},
	})
	seedAnnotation(t, repo, &annotations.Item{
		OrgID: 2, DashboardID: otherOrg.ID, DashboardUID: otherOrg.UID,
		Text: otherOrgNote, Epoch: annotationEpoch, Tags: []string{"incident"},
	})

	pub := &models.PublicDashboard{
		Uid:                  "pub0000001",
		IsEnabled:            true,
		OrgId:                published.OrgID,
		DashboardUid:         published.UID,
		AnnotationsEnabled:   true,
		TimeSelectionEnabled: true,
		Share:                models.PublicShareType,
	}

	cases := []struct {
		name          string
		targetType    string
		tags          []string
		matchAny      bool
		wantTexts     []string
		forbiddenText []string
	}{
		{
			name:          "tag query",
			targetType:    "tags",
			tags:          []string{"incident"},
			wantTexts:     []string{publishedNote},
			forbiddenText: []string{privateNote, unrelatedNote, orgNote, otherOrgNote, untaggedPrivate},
		},
		{
			name:          "match any tag query",
			targetType:    "tags",
			tags:          []string{"incident", "maintenance"},
			matchAny:      true,
			wantTexts:     []string{publishedNote},
			forbiddenText: []string{privateNote, unrelatedNote, orgNote, otherOrgNote, untaggedPrivate},
		},
		{
			name:          "tag query without tags",
			targetType:    "tags",
			wantTexts:     []string{publishedNote, untaggedPublic},
			forbiddenText: []string{privateNote, unrelatedNote, untaggedPrivate, orgNote, otherOrgNote},
		},
		{
			name:          "dashboard query",
			targetType:    "dashboard",
			wantTexts:     []string{publishedNote, untaggedPublic},
			forbiddenText: []string{privateNote, unrelatedNote, untaggedPrivate, orgNote, otherOrgNote},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind := tc.targetType
			AddAnnotationsToDashboard(t, published, []models.DashAnnotation{{
				Datasource: CreateDatasource("grafana", "grafana"),
				Enable:     true,
				Name:       "Annotations",
				IconColor:  "red",
				Type:       &kind,
				Target: &dashboard.AnnotationTarget{
					Limit:    100,
					MatchAny: tc.matchAny,
					Tags:     tc.tags,
					Type:     tc.targetType,
				},
			}})

			events := findPublicAnnotations(t, sqlStore, cfg, dashSvc, repo, pub)
			assertAnnotationScope(t, events, published.UID, tc.wantTexts, tc.forbiddenText)
		})
	}

	t.Run("http get annotations", func(t *testing.T) {
		kind := "tags"
		AddAnnotationsToDashboard(t, published, []models.DashAnnotation{{
			Datasource: CreateDatasource("grafana", "grafana"),
			Enable:     true,
			Name:       "Annotations",
			IconColor:  "red",
			Type:       &kind,
			Target: &dashboard.AnnotationTarget{
				Limit: 100,
				Tags:  []string{"incident"},
				Type:  "tags",
			},
		}})
		pd := newPublicDashboardServiceImplWithRepo(t, sqlStore, cfg, pub, dashSvc, repo)
		body := getPublicAnnotationsHTTP(t, pd, placeholderAccessToken, queryFrom, queryTo)
		var events []models.AnnotationEvent
		require.NoError(t, json.Unmarshal(body, &events))
		assertAnnotationScope(t, events, published.UID, []string{publishedNote}, []string{
			privateNote, unrelatedNote, orgNote, otherOrgNote, untaggedPrivate,
		})
	})
}

func findPublicAnnotations(t *testing.T, sqlStore *sqlstore.SQLStore, cfg *setting.Cfg, dashSvc dashboards.DashboardService, repo annotations.Repository, pub *models.PublicDashboard) []models.AnnotationEvent {
	t.Helper()
	pd := newPublicDashboardServiceImplWithRepo(t, sqlStore, cfg, pub, dashSvc, repo)
	events, err := pd.FindAnnotations(context.Background(), models.AnnotationsQueryDTO{From: queryFrom, To: queryTo}, placeholderAccessToken)
	require.NoError(t, err)
	return events
}

func newPublicDashboardServiceImplWithRepo(t *testing.T, sqlStore *sqlstore.SQLStore, cfg *setting.Cfg, pub *models.PublicDashboard, dashSvc dashboards.DashboardService, repo annotations.Repository) *PublicDashboardServiceImpl {
	t.Helper()
	store := &publicdashboards.FakePublicDashboardStore{}
	store.On("FindByAccessToken", mock.Anything, mock.AnythingOfType("string")).Return(pub, nil)
	service, _, _ := newPublicDashboardServiceImpl(t, sqlStore, cfg, store, dashSvc, repo)
	return service
}

func assertAnnotationScope(t *testing.T, events []models.AnnotationEvent, publishedUID string, wantTexts, forbidden []string) {
	t.Helper()
	byText := make(map[string]models.AnnotationEvent, len(events))
	for _, event := range events {
		byText[event.Text] = event
	}
	for _, text := range wantTexts {
		event, ok := byText[text]
		require.Truef(t, ok, "missing annotation %q in %#v", text, events)
		require.Equal(t, publishedUID, event.DashboardUID)
	}
	for _, text := range forbidden {
		_, ok := byText[text]
		require.Falsef(t, ok, "annotation %q crossed the published dashboard: %#v", text, events)
	}
}

func seedAnnotation(t *testing.T, repo annotations.Repository, item *annotations.Item) {
	t.Helper()
	require.NoError(t, repo.Save(context.Background(), item))
}

func newAnnotationDashboard(t *testing.T, title, uid string, id, orgID int64, queries []models.DashAnnotation) *dashboards.Dashboard {
	t.Helper()
	dash := dashboards.NewDashboard(title)
	dash.UID = uid
	dash.ID = id
	dash.OrgID = orgID
	dash.Data.SetPath([]string{"time", "from"}, "2020-01-01T00:00:00.000Z")
	dash.Data.SetPath([]string{"time", "to"}, "2030-01-01T00:00:00.000Z")
	dash.Data.Set("timezone", "UTC")
	if queries != nil {
		return AddAnnotationsToDashboard(t, dash, queries)
	}
	return dash
}

// annotationDashboardCatalog is the dashboard list SearchDashboards walks.
// Visibility follows the search authorizer: a service identity is allowed or
// denied only by its token permission for dashboard.grafana.app/dashboards:get,
// and any other identity is allowed only for dashboards its dashboards:read
// scopes name.
type annotationDashboardCatalog struct {
	dashboards []*dashboards.Dashboard
}

func (c *annotationDashboardCatalog) get(ctx context.Context, query *dashboards.GetDashboardQuery) (*dashboards.Dashboard, error) {
	allowed, dash, err := c.visible(ctx, query.OrgID, []string{query.UID})
	if err != nil {
		return nil, err
	}
	if len(allowed) == 0 || dash[0] == nil {
		return nil, dashboards.ErrDashboardNotFound
	}
	return dash[0], nil
}

func (c *annotationDashboardCatalog) search(ctx context.Context, query *dashboards.FindPersistedDashboardsQuery) (model.HitList, error) {
	limit := query.Limit
	if limit < 1 {
		limit = 1000
	}
	page := query.Page
	if page < 1 {
		page = 1
	}

	visible, _, err := c.visible(ctx, query.OrgId, query.DashboardUIDs)
	if err != nil {
		return nil, err
	}
	start := (page - 1) * limit
	if start >= int64(len(visible)) {
		return model.HitList{}, nil
	}
	end := start + limit
	if end > int64(len(visible)) {
		end = int64(len(visible))
	}
	return visible[start:end], nil
}

func (c *annotationDashboardCatalog) visible(ctx context.Context, orgID int64, dashboardUIDs []string) (model.HitList, []*dashboards.Dashboard, error) {
	authInfo, ok := claims.AuthInfoFrom(ctx)
	if !ok || authInfo == nil || authInfo.GetSubject() == "" {
		return nil, nil, errors.New("no user found in context")
	}
	namespace := claims.OrgNamespaceFormatter(orgID)
	if !claims.NamespaceMatches(authInfo.GetNamespace(), namespace) {
		return nil, nil, claims.ErrNamespaceMismatch
	}

	wanted := map[string]struct{}{}
	for _, uid := range dashboardUIDs {
		wanted[uid] = struct{}{}
	}

	hits := make(model.HitList, 0, len(c.dashboards))
	matched := make([]*dashboards.Dashboard, 0, len(c.dashboards))
	for _, dash := range c.dashboards {
		if dash.OrgID != orgID {
			continue
		}
		if len(wanted) > 0 {
			if _, ok := wanted[dash.UID]; !ok {
				continue
			}
		}
		allowed, err := identityCanReadDashboard(authInfo, dash.UID)
		if err != nil {
			return nil, nil, err
		}
		if !allowed {
			continue
		}
		hits = append(hits, &model.Hit{ID: dash.ID, UID: dash.UID, OrgID: dash.OrgID, Title: dash.Title})
		matched = append(matched, dash)
	}
	return hits, matched, nil
}

func identityCanReadDashboard(id claims.AuthInfo, uid string) (bool, error) {
	// authzLimitedClient.BatchCheck forwards dashboard checks, and
	// ClientImpl.BatchCheck answers a service identity from its token alone.
	res := authz.CheckServicePermissions(id, "dashboard.grafana.app", "dashboards", utils.VerbGet)
	if res.ServiceCall {
		return res.Allowed, nil
	}
	if !res.Allowed {
		return false, nil
	}

	requester, ok := id.(identity.Requester)
	if !ok {
		return false, nil
	}
	scope := dashboards.ScopeDashboardsProvider.GetResourceScopeUID(uid)
	for _, action := range dashboardReadActions {
		if accesscontrol.Checker(requester, action)(scope) {
			return true, nil
		}
	}
	return false, nil
}

func getPublicAnnotationsHTTP(t *testing.T, pd *PublicDashboardServiceImpl, accessToken string, from, to int64) []byte {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.PublicDashboardsEnabled = true
	rr := routing.NewRouteRegister()
	license := licensingtest.NewFakeLicensing()
	license.On("FeatureEnabled", models.FeaturePublicDashboardsEmailSharing).Return(false)
	api.ProvideApi(pd, rr, acimpl.ProvideAccessControl(featuremgmt.WithFeatures()), featuremgmt.WithFeatures(), &api.Middleware{}, cfg, license)

	mux := web.New()
	mux.Use(func(c *web.Context) {
		reqCtx := &contextmodel.ReqContext{
			Context:      c,
			SignedInUser: &user.SignedInUser{IsAnonymous: true},
			Logger:       log.New("publicdashboards-test"),
		}
		c.Req = c.Req.WithContext(ctxkey.Set(c.Req.Context(), reqCtx))
	})
	rr.Register(mux.Router)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/api/public/dashboards/%s/annotations?from=%d&to=%d", accessToken, from, to), nil)
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code)
	body, err := io.ReadAll(recorder.Body)
	require.NoError(t, err)
	return body
}
