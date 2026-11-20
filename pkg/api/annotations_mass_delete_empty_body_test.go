package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/annotations/annotationsapi"
	"github.com/grafana/grafana/pkg/services/annotations/annotationsimpl"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/tag/tagimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	tutil "github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	massDeletePath = "/api/annotations/mass-delete"

	keptDashboardID  int64 = 42
	keptDashboardUID       = "dash-kept"
	keptPanelID      int64 = 3
	otherPanelID     int64 = 9

	callerOrg int64 = 1
	otherOrg  int64 = 2
)

// TestIntegrationAnnotationMassDeleteEmptyBody rejects a mass-delete whose
// JSON leaves the annotation, dashboard, and panel unset. That request must
// not delete organization annotations (dashboard_id = 0 and panel_id = 0) or
// their tag rows. A named dashboard and panel still deletes only that pair.
func TestIntegrationAnnotationMassDeleteEmptyBody(t *testing.T) {
	tutil.SkipIntegrationTestInShortMode(t)

	editor := signedInWithRolePermissions(org.RoleEditor, callerOrg, nil)
	viewer := signedInWithRolePermissions(org.RoleViewer, callerOrg, nil)
	dashboardDeleter := signedInWithRolePermissions(org.RoleViewer, callerOrg, []accesscontrol.Permission{{
		Action: accesscontrol.ActionAnnotationsDelete,
		Scope:  dashboards.ScopeDashboardsProvider.GetResourceScopeUID(keptDashboardUID),
	}})

	omittedTargets := []struct {
		name string
		body string
	}{
		{name: "empty object", body: "{}"},
		{name: "explicit zero fields", body: `{"annotationId":0,"dashboardId":0,"panelId":0,"dashboardUID":""}`},
		{name: "empty json body", body: ""},
	}

	for _, tt := range omittedTargets {
		t.Run(tt.name, func(t *testing.T) {
			srv, sql, seeded := setupMassDeleteServer(t)
			res := postMassDelete(t, srv, editor, tt.body)
			assertAnnotationsUntouched(t, sql, seeded, res)
		})
	}

	t.Run("viewer cannot mass delete", func(t *testing.T) {
		srv, sql, seeded := setupMassDeleteServer(t)
		res := postMassDelete(t, srv, viewer, "{}")
		assertDeniedWithoutDeleting(t, sql, seeded, res)
	})

	t.Run("dashboard delete permission does not delete organization annotations", func(t *testing.T) {
		srv, sql, seeded := setupMassDeleteServer(t)
		res := postMassDelete(t, srv, dashboardDeleter, "{}")
		assertDeniedWithoutDeleting(t, sql, seeded, res)
	})

	t.Run("named dashboard and panel deletes only that pair", func(t *testing.T) {
		editorOnDashboard := signedInWithRolePermissions(org.RoleEditor, callerOrg, []accesscontrol.Permission{{
			Action: accesscontrol.ActionAnnotationsDelete,
			Scope:  dashboards.ScopeDashboardsProvider.GetResourceScopeUID(keptDashboardUID),
		}})
		srv, sql, seeded := setupMassDeleteServer(t)
		res := postMassDelete(t, srv, editorOnDashboard, `{"dashboardUID":"dash-kept","panelId":3}`)
		require.Equal(t, http.StatusOK, res.statusCode, "body: %s", res.body)

		remaining := annotationTexts(t, sql)
		assert.NotContains(t, remaining, seeded.panelText)
		assert.Contains(t, remaining, seeded.orgText)
		assert.Contains(t, remaining, seeded.otherPanelText)
		assert.Contains(t, remaining, seeded.otherOrgText)
		assert.Equal(t, int64(1), annotationTagCount(t, sql, seeded.orgID))
		assert.Equal(t, int64(0), annotationTagCount(t, sql, seeded.panelID))
	})
}

type seededAnnotations struct {
	orgID          int64
	orgText        string
	panelID        int64
	panelText      string
	otherPanelText string
	otherOrgText   string
}

type massDeleteResult struct {
	statusCode int
	body       string
}

func setupMassDeleteServer(t *testing.T) (*webtest.Server, db.DB, seededAnnotations) {
	t.Helper()

	sqlStore := db.NewTestStore(t)
	cfg := setting.NewCfg()
	// defaults.ini: tags_length = 500, api_migration_phase = off.
	// NewCfg does not load that file, so set the same defaults the product ships.
	cfg.AnnotationMaximumTagsLength = 500
	cfg.AnnotationAppPlatform.APIMigrationPhase = setting.AnnotationAPIMigrationPhaseOff

	dash := &dashboards.FakeDashboardService{}
	dash.On("GetDashboard", mock.Anything, mock.MatchedBy(func(q *dashboards.GetDashboardQuery) bool {
		return q != nil && q.UID == keptDashboardUID && q.OrgID == callerOrg
	})).Return(&dashboards.Dashboard{ID: keptDashboardID, UID: keptDashboardUID, OrgID: callerOrg}, nil)

	repo := annotationsimpl.ProvideService(
		sqlStore,
		cfg,
		featuremgmt.WithFeatures(),
		tagimpl.ProvideService(sqlStore),
		tracing.InitializeTracerForTest(),
		nil,
		dash,
		prometheus.NewRegistry(),
	)
	// Same wiring as HTTPServer: the migration wrapper is a no-op while the phase is off.
	annotationsRepo := annotationsapi.NewMigrationRepository(repo, nil, cfg, nil)

	seeded := seedAnnotations(t, annotationsRepo)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.annotationsRepo = annotationsRepo
		hs.DashboardService = dash
		hs.AccessControl = acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	})
	return server, sqlStore, seeded
}

func seedAnnotations(t *testing.T, repo annotations.Repository) seededAnnotations {
	t.Helper()
	ctx := context.Background()

	orgNote := &annotations.Item{
		OrgID: callerOrg,
		Text:  "org-shared-note",
		Epoch: 1_700_000_000_000,
		Tags:  []string{"shared"},
	}
	require.NoError(t, repo.Save(ctx, orgNote))

	panelNote := &annotations.Item{
		OrgID:        callerOrg,
		DashboardID:  keptDashboardID,
		DashboardUID: keptDashboardUID,
		PanelID:      keptPanelID,
		Text:         "dashboard-panel-note",
		Epoch:        1_700_000_000_001,
		Tags:         []string{"panel"},
	}
	require.NoError(t, repo.Save(ctx, panelNote))

	otherPanel := &annotations.Item{
		OrgID:        callerOrg,
		DashboardID:  keptDashboardID,
		DashboardUID: keptDashboardUID,
		PanelID:      otherPanelID,
		Text:         "dashboard-other-panel-note",
		Epoch:        1_700_000_000_002,
	}
	require.NoError(t, repo.Save(ctx, otherPanel))

	otherOrgNote := &annotations.Item{
		OrgID: otherOrg,
		Text:  "other-org-note",
		Epoch: 1_700_000_000_003,
		Tags:  []string{"elsewhere"},
	}
	require.NoError(t, repo.Save(ctx, otherOrgNote))

	return seededAnnotations{
		orgID:          orgNote.ID,
		orgText:        orgNote.Text,
		panelID:        panelNote.ID,
		panelText:      panelNote.Text,
		otherPanelText: otherPanel.Text,
		otherOrgText:   otherOrgNote.Text,
	}
}

func postMassDelete(t *testing.T, server *webtest.Server, usr *user.SignedInUser, body string) massDeleteResult {
	t.Helper()
	req := webtest.RequestWithSignedInUser(server.NewRequest(http.MethodPost, massDeletePath, strings.NewReader(body)), usr)
	res, err := server.SendJSON(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = res.Body.Close()
	})
	payload, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return massDeleteResult{statusCode: res.StatusCode, body: string(payload)}
}

func assertAnnotationsUntouched(t *testing.T, sql db.DB, seeded seededAnnotations, res massDeleteResult) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, res.statusCode, "body: %s", res.body)
	assertStoredAnnotations(t, sql, seeded)
}

func assertDeniedWithoutDeleting(t *testing.T, sql db.DB, seeded seededAnnotations, res massDeleteResult) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, res.statusCode, "body: %s", res.body)
	assertStoredAnnotations(t, sql, seeded)
}

func assertStoredAnnotations(t *testing.T, sql db.DB, seeded seededAnnotations) {
	t.Helper()
	assert.ElementsMatch(t, []string{
		seeded.orgText,
		seeded.panelText,
		seeded.otherPanelText,
		seeded.otherOrgText,
	}, annotationTexts(t, sql))
	assert.Equal(t, int64(1), annotationTagCount(t, sql, seeded.orgID), "organization annotation tag rows must survive")
	assert.Equal(t, int64(1), annotationTagCount(t, sql, seeded.panelID), "dashboard annotation tag rows must survive")
}

func annotationTexts(t *testing.T, sql db.DB) []string {
	t.Helper()
	type row struct {
		Text string
	}
	var rows []row
	err := sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		return sess.SQL("SELECT text FROM annotation").Find(&rows)
	})
	require.NoError(t, err)
	texts := make([]string, 0, len(rows))
	for _, row := range rows {
		texts = append(texts, row.Text)
	}
	return texts
}

func annotationTagCount(t *testing.T, sql db.DB, annotationID int64) int64 {
	t.Helper()
	var count int64
	err := sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL("SELECT COUNT(*) FROM annotation_tag WHERE annotation_id = ?", annotationID).Get(&count)
		return err
	})
	require.NoError(t, err)
	return count
}

// signedInWithRolePermissions builds the caller's permission set from the fixed
// roles actually granted to that built-in org role, including grants inherited
// through parent roles.
func signedInWithRolePermissions(role org.RoleType, orgID int64, extra []accesscontrol.Permission) *user.SignedInUser {
	perms := permissionsGrantedTo(role)
	perms = append(perms, extra...)
	return &user.SignedInUser{
		UserID:  1,
		OrgID:   orgID,
		OrgRole: role,
		Permissions: map[int64]map[string][]string{
			orgID: accesscontrol.GroupScopesByActionContext(context.Background(), perms),
		},
	}
}

func permissionsGrantedTo(role org.RoleType) []accesscontrol.Permission {
	wanted := string(role)
	var perms []accesscontrol.Permission
	for _, reg := range FixedRoleRegistrations(false, false) {
		if _, ok := accesscontrol.BuiltInRolesWithParents(reg.Grants)[wanted]; !ok {
			continue
		}
		perms = append(perms, reg.Role.Permissions...)
	}
	return perms
}
