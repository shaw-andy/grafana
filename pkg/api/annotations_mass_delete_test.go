package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/seeding"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/annotations/annotationsapi"
	"github.com/grafana/grafana/pkg/services/annotations/annotationsimpl"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/tag/tagimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	massDeleteOrgID          int64 = 1
	massDeleteOtherOrgID     int64 = 2
	massDeleteDashboardID    int64 = 7
	massDeletePanelID        int64 = 3
	massDeleteOtherPanelID   int64 = 9
	massDeleteDashboardUID         = "dash-uid"
	massDeleteOrgNote              = "organization annotation shared across dashboards"
	massDeleteSecondOrgNote        = "second organization annotation"
	massDeletePanelNote            = "dashboard panel annotation"
	massDeleteOtherPanelNote       = "same dashboard other panel"
	massDeleteZeroPanelNote        = "dashboard id zero with a panel"
	massDeleteOtherOrgNote         = "other organization annotation"
)

// TestMassDeleteAnnotationsEmptyTarget is the spec for POST /api/annotations/mass-delete
// when the body does not name an annotation, a dashboard, or a panel.
//
// An Editor is granted annotations:delete on annotations:type:organization. That permission
// authorizes deleting organization annotations. It does not authorize treating a missing
// target as "every annotation stored with dashboard id 0 and panel id 0". The handler must
// reject that request before anything is deleted. A named dashboard and panel still deletes
// only that panel.
//
// These tests fail while the empty target is executed as that delete.
func TestMassDeleteAnnotationsEmptyTarget(t *testing.T) {
	sqlStore := sqlstore.NewTestStore(t)
	cfg := setting.NewCfg()
	cfg.AnnotationMaximumTagsLength = 500
	// Default [annotations.app_platform] api_migration_phase is "off", which keeps the
	// legacy SQL repository. An enabled migration phase refuses a mass delete that has
	// no dashboard UID inside the wrapper; that is not the path under test.
	cfg.AnnotationAppPlatform.APIMigrationPhase = setting.AnnotationAPIMigrationPhaseOff

	repo := legacyAnnotationRepository(t, sqlStore, cfg)
	dashService := &dashboards.FakeDashboardService{}
	dashService.On("GetDashboard", mock.Anything, mock.AnythingOfType("*dashboards.GetDashboardQuery")).
		Return(&dashboards.Dashboard{ID: massDeleteDashboardID, UID: massDeleteDashboardUID, OrgID: massDeleteOrgID}, nil)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.annotationsRepo = annotationsapi.NewMigrationRepository(repo, nil, cfg, nil)
		hs.DashboardService = dashService
		hs.Features = featuremgmt.WithFeatures()
		hs.AccessControl = acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	})

	editorPerms := builtinRolePermissions(t, org.RoleEditor)
	require.Contains(t, editorPerms, accesscontrol.Permission{
		Action: accesscontrol.ActionAnnotationsDelete,
		Scope:  accesscontrol.ScopeAnnotationsTypeOrganization,
	}, "built-in Editor must be granted organization annotation delete; the attack uses that grant")

	viewerPerms := builtinRolePermissions(t, org.RoleViewer)
	require.NotContains(t, viewerPerms, accesscontrol.Permission{
		Action: accesscontrol.ActionAnnotationsDelete,
		Scope:  accesscontrol.ScopeAnnotationsTypeOrganization,
	})

	reseed := func(t *testing.T) {
		t.Helper()
		clearAnnotations(t, sqlStore)
		items := []*annotations.Item{
			{OrgID: massDeleteOrgID, Text: massDeleteOrgNote, Tags: []string{"shared-note"}, Epoch: 10},
			{OrgID: massDeleteOrgID, Text: massDeleteSecondOrgNote, Tags: []string{"shared-note-2"}, Epoch: 11},
			{
				OrgID: massDeleteOrgID, DashboardID: massDeleteDashboardID, DashboardUID: massDeleteDashboardUID,
				PanelID: massDeletePanelID, Text: massDeletePanelNote, Tags: []string{"panel-note"}, Epoch: 12,
			},
			{
				OrgID: massDeleteOrgID, DashboardID: massDeleteDashboardID, DashboardUID: massDeleteDashboardUID,
				PanelID: massDeleteOtherPanelID, Text: massDeleteOtherPanelNote, Epoch: 13,
			},
			{OrgID: massDeleteOrgID, PanelID: 4, Text: massDeleteZeroPanelNote, Epoch: 14},
			{OrgID: massDeleteOtherOrgID, Text: massDeleteOtherOrgNote, Tags: []string{"other-org"}, Epoch: 15},
		}
		for _, item := range items {
			require.NoError(t, repo.Save(context.Background(), item))
		}
	}

	assertUntouched := func(t *testing.T, beforeAnnotations []storedAnnotation, beforeTags []storedAnnotationTag, body string) {
		t.Helper()
		require.Equal(t, beforeAnnotations, listAnnotations(t, sqlStore), "stored annotations changed: %s", body)
		require.Equal(t, beforeTags, listAnnotationTags(t, sqlStore), "annotation tag rows changed: %s", body)
	}

	post := func(t *testing.T, role org.RoleType, perms []accesscontrol.Permission, body string) (int, string) {
		t.Helper()
		req := webtest.RequestWithSignedInUser(
			server.NewRequest(http.MethodPost, "/api/annotations/mass-delete", strings.NewReader(body)),
			signedInWithRole(massDeleteOrgID, role, perms),
		)
		res, err := server.SendJSON(req)
		require.NoError(t, err)
		defer func() { require.NoError(t, res.Body.Close()) }()
		payload, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		return res.StatusCode, string(payload)
	}

	t.Run("editor json object with no fields is rejected and deletes nothing", func(t *testing.T) {
		reseed(t)
		beforeAnnotations := listAnnotations(t, sqlStore)
		beforeTags := listAnnotationTags(t, sqlStore)
		require.NotEmpty(t, beforeAnnotations)
		require.NotEmpty(t, beforeTags)

		status, body := post(t, org.RoleEditor, editorPerms, `{}`)
		assertUntouched(t, beforeAnnotations, beforeTags, body)
		require.Equal(t, http.StatusBadRequest, status, body)
	})

	t.Run("editor empty json body is rejected and deletes nothing", func(t *testing.T) {
		reseed(t)
		beforeAnnotations := listAnnotations(t, sqlStore)
		beforeTags := listAnnotationTags(t, sqlStore)

		status, body := post(t, org.RoleEditor, editorPerms, ``)
		assertUntouched(t, beforeAnnotations, beforeTags, body)
		require.Equal(t, http.StatusBadRequest, status, body)
	})

	t.Run("editor explicit zero ids are rejected and delete nothing", func(t *testing.T) {
		reseed(t)
		beforeAnnotations := listAnnotations(t, sqlStore)
		beforeTags := listAnnotationTags(t, sqlStore)

		status, body := post(t, org.RoleEditor, editorPerms, `{"annotationId":0,"dashboardId":0,"panelId":0,"dashboardUID":""}`)
		assertUntouched(t, beforeAnnotations, beforeTags, body)
		require.Equal(t, http.StatusBadRequest, status, body)
	})

	t.Run("viewer is forbidden and deletes nothing", func(t *testing.T) {
		reseed(t)
		beforeAnnotations := listAnnotations(t, sqlStore)
		beforeTags := listAnnotationTags(t, sqlStore)

		status, body := post(t, org.RoleViewer, viewerPerms, `{}`)
		assertUntouched(t, beforeAnnotations, beforeTags, body)
		require.Equal(t, http.StatusForbidden, status, body)
	})

	t.Run("dashboard annotation delete does not authorize an untargeted organization delete", func(t *testing.T) {
		reseed(t)
		beforeAnnotations := listAnnotations(t, sqlStore)
		beforeTags := listAnnotationTags(t, sqlStore)
		perms := []accesscontrol.Permission{{
			Action: accesscontrol.ActionAnnotationsDelete,
			Scope:  dashboards.ScopeDashboardsProvider.GetResourceScopeUID(massDeleteDashboardUID),
		}}

		status, body := post(t, org.RoleEditor, perms, `{}`)
		assertUntouched(t, beforeAnnotations, beforeTags, body)
		require.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, status, body)
	})

	t.Run("named dashboard and panel deletes only that panel", func(t *testing.T) {
		reseed(t)
		perms := append([]accesscontrol.Permission{{
			Action: accesscontrol.ActionAnnotationsDelete,
			Scope:  dashboards.ScopeDashboardsProvider.GetResourceScopeUID(massDeleteDashboardUID),
		}}, editorPerms...)

		status, body := post(t, org.RoleEditor, perms, `{"dashboardId":7,"panelId":3}`)
		require.Equal(t, http.StatusOK, status, body)

		remaining := listAnnotations(t, sqlStore)
		require.NotContains(t, annotationTexts(remaining), massDeletePanelNote)
		for _, text := range []string{
			massDeleteOrgNote,
			massDeleteSecondOrgNote,
			massDeleteOtherPanelNote,
			massDeleteZeroPanelNote,
			massDeleteOtherOrgNote,
		} {
			require.Contains(t, annotationTexts(remaining), text)
		}

		tags := listAnnotationTags(t, sqlStore)
		require.NotContains(t, tagTexts(tags), massDeletePanelNote)
		require.Contains(t, tagTexts(tags), massDeleteOrgNote)
		require.Contains(t, tagTexts(tags), massDeleteSecondOrgNote)
		require.Contains(t, tagTexts(tags), massDeleteOtherOrgNote)
	})
}

func legacyAnnotationRepository(t *testing.T, sqlStore db.DB, cfg *setting.Cfg) annotations.Repository {
	t.Helper()
	store := annotationsimpl.NewXormStore(cfg, log.New("annotation.test"), sqlStore, tagimpl.ProvideService(sqlStore), prometheus.NewRegistry())
	return annotationsimpl.NewRepositoryImpl(nil, featuremgmt.WithFeatures(), store, store)
}

func builtinRolePermissions(t *testing.T, role org.RoleType) []accesscontrol.Permission {
	t.Helper()
	desired := map[accesscontrol.SeedPermission]struct{}{}
	for _, registration := range FixedRoleRegistrations(false, false) {
		seeding.AppendDesiredPermissions(desired, log.New("annotation.test"), &registration.Role, registration.Grants, registration.Exclude)
	}

	permissions := make([]accesscontrol.Permission, 0)
	for permission := range desired {
		if permission.BuiltInRole != string(role) {
			continue
		}
		permissions = append(permissions, accesscontrol.Permission{Action: permission.Action, Scope: permission.Scope})
	}
	return permissions
}

func signedInWithRole(orgID int64, role org.RoleType, permissions []accesscontrol.Permission) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  1,
		OrgID:   orgID,
		OrgRole: role,
		Permissions: map[int64]map[string][]string{
			orgID: accesscontrol.GroupScopesByActionContext(context.Background(), permissions),
		},
	}
}

type storedAnnotation struct {
	OrgID        int64  `xorm:"org_id"`
	DashboardID  int64  `xorm:"dashboard_id"`
	DashboardUID string `xorm:"dashboard_uid"`
	PanelID      int64  `xorm:"panel_id"`
	Text         string `xorm:"text"`
}

type storedAnnotationTag struct {
	OrgID int64  `xorm:"org_id"`
	Text  string `xorm:"text"`
	Key   string `xorm:"tag_key"`
}

func clearAnnotations(t *testing.T, sqlStore db.DB) {
	t.Helper()
	err := sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		if _, err := sess.Exec("DELETE FROM annotation_tag"); err != nil {
			return err
		}
		if _, err := sess.Exec("DELETE FROM annotation"); err != nil {
			return err
		}
		_, err := sess.Exec("DELETE FROM tag")
		return err
	})
	require.NoError(t, err)
}

func listAnnotations(t *testing.T, sqlStore db.DB) []storedAnnotation {
	t.Helper()
	var rows []storedAnnotation
	err := sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		return sess.SQL(`
			SELECT org_id, dashboard_id, dashboard_uid, panel_id, text
			FROM annotation
			ORDER BY org_id, dashboard_id, panel_id, text
		`).Find(&rows)
	})
	require.NoError(t, err)
	return rows
}

func listAnnotationTags(t *testing.T, sqlStore db.DB) []storedAnnotationTag {
	t.Helper()
	var rows []storedAnnotationTag
	key := sqlStore.GetDialect().Quote("key")
	err := sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		return sess.SQL(`
			SELECT annotation.org_id AS org_id, annotation.text AS text, tag.` + key + ` AS tag_key
			FROM annotation_tag
			INNER JOIN annotation ON annotation.id = annotation_tag.annotation_id
			INNER JOIN tag ON tag.id = annotation_tag.tag_id
			ORDER BY annotation.org_id, annotation.text, tag.` + key + `
		`).Find(&rows)
	})
	require.NoError(t, err)
	return rows
}

func annotationTexts(rows []storedAnnotation) []string {
	texts := make([]string, 0, len(rows))
	for _, row := range rows {
		texts = append(texts, row.Text)
	}
	return texts
}

func tagTexts(rows []storedAnnotationTag) []string {
	texts := make([]string, 0, len(rows))
	for _, row := range rows {
		texts = append(texts, row.Text)
	}
	return texts
}
