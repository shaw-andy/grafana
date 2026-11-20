package annotations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// These tests pin the annotation list authorization contract.
// A caller who can open a dashboard, and who holds annotations:read on some
// other scope, must not receive that dashboard's annotation text, tags, alert
// state, login, or email. GET /api/annotations/{id} already applies the
// dashboard and folder scopes stored on annotations:read; the list, the
// dashboard-scoped list filters, and the tag list must use those same scopes.

const scopeTestPassword = "password"

const (
	allowedNoteText = "note-inside-annotation-scope"
	allowedNoteTag  = "tag-inside-annotation-scope"

	outsideNoteText = "incident-note-outside-scope"
	outsideNoteTag  = "incident-tag-outside-scope"
	outsidePrev     = "incident-prev-state"
	outsideNew      = "incident-new-state"
	outsideLogin    = "incidentauthor"
	outsideEmail    = "incident-author@example.com"
	outsideAlertID  = int64(424242)

	childNoteText = "note-inside-parent-folder-scope"
	rootNoteText  = "note-inside-general-folder-scope"
	orgNoteText   = "org-annotation-inside-org-scope"
	orgNoteTag    = "org-tag-inside-org-scope"
)

func TestIntegrationAnnotationListHonorsAnnotationReadScopes(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	dir, path := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableAuthZClientCache: true,
		DisableAnonymous:        true,
	})
	grafanaListedAddr, env := testinfra.StartGrafanaEnv(t, dir, path)

	authorID := tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleEditor),
		Login:          outsideLogin,
		Email:          outsideEmail,
		Password:       scopeTestPassword,
		OrgID:          1,
	})

	folderA := createFolder(t, grafanaListedAddr, "Annotation Scope Folder A")
	folderB := createFolder(t, grafanaListedAddr, "Annotation Scope Folder B")
	parent := createFolder(t, grafanaListedAddr, "Annotation Scope Parent")
	child := createFolderWithParent(t, grafanaListedAddr, "Annotation Scope Child", parent.UID)

	dashAllowed := createDashboard(t, grafanaListedAddr, "Allowed Dashboard", folderA.ID, folderA.UID) // nolint:staticcheck
	dashOutside := createDashboard(t, grafanaListedAddr, "Outside Dashboard", folderB.ID, folderB.UID) // nolint:staticcheck
	dashChild := createDashboard(t, grafanaListedAddr, "Child Dashboard", child.ID, child.UID)         // nolint:staticcheck
	dashRoot := createDashboard(t, grafanaListedAddr, "Root Dashboard", 0, "")

	allowedID := createAnnotationReturningID(t, grafanaListedAddr, map[string]any{
		"dashboardUID": dashAllowed.UID,
		"panelId":      1,
		"text":         allowedNoteText,
		"tags":         []string{allowedNoteTag},
		"time":         int64(1234567890000),
	})
	outsideID := createAnnotationReturningID(t, grafanaListedAddr, map[string]any{
		"dashboardUID": dashOutside.UID,
		"panelId":      1,
		"text":         outsideNoteText,
		"tags":         []string{outsideNoteTag},
		"time":         int64(1234567890000),
	})
	createAnnotationReturningID(t, grafanaListedAddr, map[string]any{
		"dashboardUID": dashChild.UID,
		"panelId":      1,
		"text":         childNoteText,
		"tags":         []string{"child-folder-tag"},
		"time":         int64(1234567890000),
	})
	createAnnotationReturningID(t, grafanaListedAddr, map[string]any{
		"dashboardUID": dashRoot.UID,
		"panelId":      1,
		"text":         rootNoteText,
		"tags":         []string{"general-folder-tag"},
		"time":         int64(1234567890000),
	})
	createAnnotationReturningID(t, grafanaListedAddr, map[string]any{
		"text": orgNoteText,
		"tags": []string{orgNoteTag},
		"time": int64(1234567890000),
	})

	stampOutsideAnnotation(t, env.SQLStore, outsideID, authorID)

	readable := []string{dashAllowed.UID, dashOutside.UID, dashChild.UID, dashRoot.UID}
	dashReader := tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleNone),
		Login:          "annodashreader",
		Email:          "annodashreader@example.com",
		Password:       scopeTestPassword,
		OrgID:          1,
	})
	folderReader := tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleNone),
		Login:          "annofolderreader",
		Email:          "annofolderreader@example.com",
		Password:       scopeTestPassword,
		OrgID:          1,
	})
	orgReader := tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleNone),
		Login:          "annoorgreader",
		Email:          "annoorgreader@example.com",
		Password:       scopeTestPassword,
		OrgID:          1,
	})
	parentReader := tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleNone),
		Login:          "annoparentreader",
		Email:          "annoparentreader@example.com",
		Password:       scopeTestPassword,
		OrgID:          1,
	})
	generalReader := tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleNone),
		Login:          "annogeneralreader",
		Email:          "annogeneralreader@example.com",
		Password:       scopeTestPassword,
		OrgID:          1,
	})
	legacyReader := tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleNone),
		Login:          "annolegacyreader",
		Email:          "annolegacyreader@example.com",
		Password:       scopeTestPassword,
		OrgID:          1,
	})

	grantManagedPermissions(t, env.SQLStore, dashReader, append(
		dashboardReadPermissions(readable),
		accesscontrol.Permission{Action: accesscontrol.ActionAnnotationsRead, Scope: dashboards.ScopeDashboardsProvider.GetResourceScopeUID(dashAllowed.UID)},
	))
	grantManagedPermissions(t, env.SQLStore, folderReader, append(
		dashboardReadPermissions(readable),
		accesscontrol.Permission{Action: accesscontrol.ActionAnnotationsRead, Scope: folder.ScopeFoldersProvider.GetResourceScopeUID(folderA.UID)},
	))
	grantManagedPermissions(t, env.SQLStore, orgReader, append(
		dashboardReadPermissions(readable),
		accesscontrol.Permission{Action: accesscontrol.ActionAnnotationsRead, Scope: accesscontrol.ScopeAnnotationsTypeOrganization},
	))
	grantManagedPermissions(t, env.SQLStore, parentReader, append(
		dashboardReadPermissions(readable),
		accesscontrol.Permission{Action: accesscontrol.ActionAnnotationsRead, Scope: folder.ScopeFoldersProvider.GetResourceScopeUID(parent.UID)},
	))
	grantManagedPermissions(t, env.SQLStore, generalReader, append(
		dashboardReadPermissions(readable),
		accesscontrol.Permission{Action: accesscontrol.ActionAnnotationsRead, Scope: folder.ScopeFoldersProvider.GetResourceScopeUID(folder.GeneralFolderUID)},
	))
	grantManagedPermissions(t, env.SQLStore, legacyReader, append(
		dashboardReadPermissions(readable),
		accesscontrol.Permission{Action: accesscontrol.ActionAnnotationsRead, Scope: accesscontrol.ScopeAnnotationsTypeDashboard},
	))

	admin := apiClient{addr: grafanaListedAddr, login: "admin", password: "admin"}
	dashClient := apiClient{addr: grafanaListedAddr, login: "annodashreader", password: scopeTestPassword}
	folderClient := apiClient{addr: grafanaListedAddr, login: "annofolderreader", password: scopeTestPassword}
	orgClient := apiClient{addr: grafanaListedAddr, login: "annoorgreader", password: scopeTestPassword}
	parentClient := apiClient{addr: grafanaListedAddr, login: "annoparentreader", password: scopeTestPassword}
	generalClient := apiClient{addr: grafanaListedAddr, login: "annogeneralreader", password: scopeTestPassword}
	legacyClient := apiClient{addr: grafanaListedAddr, login: "annolegacyreader", password: scopeTestPassword}

	t.Run("preconditions", func(t *testing.T) {
		// The caller can open the dashboard the annotation scope does not cover.
		status, body := dashClient.get(t, "/api/dashboards/uid/"+dashOutside.UID)
		require.Equal(t, http.StatusOK, status, string(body))

		// The stored row really carries the fields the list would disclose.
		status, body = admin.get(t, "/api/annotations")
		require.Equal(t, http.StatusOK, status, string(body))
		items := decodeAnnotations(t, body)
		outside := annotationByText(t, items, outsideNoteText)
		require.Equal(t, []string{outsideNoteTag}, outside.Tags)
		require.Equal(t, outsidePrev, outside.PrevState)
		require.Equal(t, outsideNew, outside.NewState)
		require.Equal(t, outsideAlertID, outside.AlertID)
		require.Equal(t, outsideLogin, outside.Login)
		require.Equal(t, outsideEmail, outside.Email)
		require.NotNil(t, outside.DashboardUID)
		require.Equal(t, dashOutside.UID, *outside.DashboardUID)

		// Reading that same row by id applies the annotation scope and denies the caller.
		status, body = dashClient.get(t, fmt.Sprintf("/api/annotations/%d", outsideID))
		require.Equal(t, http.StatusForbidden, status, string(body))
		requireNoSensitiveOutsideFields(t, body)

		// The scope that was granted still allows that one annotation by id.
		status, body = dashClient.get(t, fmt.Sprintf("/api/annotations/%d", allowedID))
		require.Equal(t, http.StatusOK, status, string(body))
		require.Contains(t, string(body), allowedNoteText)
	})

	outsideMarkers := []string{outsideNoteText, outsideNoteTag, outsidePrev, outsideNew, outsideLogin, outsideEmail}

	t.Run("dashboard scope list omits other readable dashboards", func(t *testing.T) {
		status, body := dashClient.get(t, "/api/annotations")
		require.Equal(t, http.StatusOK, status, string(body))
		requireNoSensitiveOutsideFields(t, body)
		items := decodeAnnotations(t, body)
		require.Equal(t, []string{allowedNoteText}, texts(items))
		allowed := annotationByText(t, items, allowedNoteText)
		require.NotNil(t, allowed.DashboardUID)
		require.Equal(t, dashAllowed.UID, *allowed.DashboardUID)
		for _, item := range items {
			if item.DashboardUID != nil {
				require.NotEqual(t, dashOutside.UID, *item.DashboardUID)
				require.NotEqual(t, dashChild.UID, *item.DashboardUID)
				require.NotEqual(t, dashRoot.UID, *item.DashboardUID)
			}
		}
	})

	t.Run("dashboardUID outside the annotation scope is denied", func(t *testing.T) {
		status, body := dashClient.get(t, "/api/annotations?dashboardUID="+dashOutside.UID)
		requireNoLeak(t, status, body, outsideMarkers...)
		require.NotContains(t, string(body), dashOutside.UID)
	})

	t.Run("dashboardId outside the annotation scope is denied", func(t *testing.T) {
		status, body := dashClient.get(t, fmt.Sprintf("/api/annotations?dashboardId=%d", dashOutside.ID)) // nolint:staticcheck
		requireNoLeak(t, status, body, outsideMarkers...)
	})

	t.Run("dashboardUID inside the annotation scope returns only that dashboard", func(t *testing.T) {
		status, body := dashClient.get(t, "/api/annotations?dashboardUID="+dashAllowed.UID)
		require.Equal(t, http.StatusOK, status, string(body))
		items := decodeAnnotations(t, body)
		require.Equal(t, []string{allowedNoteText}, texts(items))
		requireNoSensitiveOutsideFields(t, body)
	})

	t.Run("alert annotation query uses the same scopes", func(t *testing.T) {
		status, body := dashClient.get(t, "/api/annotations?type=alert")
		require.Equal(t, http.StatusOK, status, string(body))
		requireNoSensitiveOutsideFields(t, body)
		require.NotContains(t, texts(decodeAnnotations(t, body)), outsideNoteText)

		status, body = dashClient.get(t, fmt.Sprintf("/api/annotations?alertId=%d", outsideAlertID))
		requireNoLeak(t, status, body, outsideMarkers...)
	})

	t.Run("tag list uses the same scopes", func(t *testing.T) {
		status, body := dashClient.get(t, "/api/annotations/tags")
		require.Equal(t, http.StatusOK, status, string(body))
		require.Contains(t, string(body), allowedNoteTag)
		require.NotContains(t, string(body), outsideNoteTag)
		require.NotContains(t, string(body), orgNoteTag)
	})

	t.Run("folder scope does not cover a dashboard in another folder", func(t *testing.T) {
		status, body := folderClient.get(t, "/api/annotations")
		require.Equal(t, http.StatusOK, status, string(body))
		requireNoSensitiveOutsideFields(t, body)
		items := decodeAnnotations(t, body)
		require.Equal(t, []string{allowedNoteText}, texts(items))
	})

	t.Run("organization scope does not cover dashboard annotations", func(t *testing.T) {
		status, body := orgClient.get(t, "/api/annotations")
		require.Equal(t, http.StatusOK, status, string(body))
		requireNoSensitiveOutsideFields(t, body)
		items := decodeAnnotations(t, body)
		require.Equal(t, []string{orgNoteText}, texts(items))
		for _, item := range items {
			require.True(t, item.DashboardUID == nil || *item.DashboardUID == "")
		}
	})

	t.Run("parent folder scope covers a nested dashboard and nothing else", func(t *testing.T) {
		status, body := parentClient.get(t, "/api/annotations")
		require.Equal(t, http.StatusOK, status, string(body))
		requireNoSensitiveOutsideFields(t, body)
		items := decodeAnnotations(t, body)
		require.Equal(t, []string{childNoteText}, texts(items))
		got := annotationByText(t, items, childNoteText)
		require.NotNil(t, got.DashboardUID)
		require.Equal(t, dashChild.UID, *got.DashboardUID)
	})

	t.Run("general folder scope covers only root dashboards", func(t *testing.T) {
		status, body := generalClient.get(t, "/api/annotations")
		require.Equal(t, http.StatusOK, status, string(body))
		requireNoSensitiveOutsideFields(t, body)
		items := decodeAnnotations(t, body)
		require.Equal(t, []string{rootNoteText}, texts(items))
		got := annotationByText(t, items, rootNoteText)
		require.NotNil(t, got.DashboardUID)
		require.Equal(t, dashRoot.UID, *got.DashboardUID)
	})

	t.Run("legacy annotation type dashboard scope grants no dashboard rows", func(t *testing.T) {
		status, body := legacyClient.get(t, "/api/annotations")
		require.Equal(t, http.StatusOK, status, string(body))
		require.Empty(t, decodeAnnotations(t, body))
		requireNoSensitiveOutsideFields(t, body)
	})

	t.Run("explicit dashboardUID outside a folder scope is denied", func(t *testing.T) {
		status, body := folderClient.get(t, "/api/annotations?dashboardUID="+dashOutside.UID)
		requireNoLeak(t, status, body, outsideMarkers...)
		status, body = parentClient.get(t, "/api/annotations?dashboardUID="+dashOutside.UID)
		requireNoLeak(t, status, body, outsideMarkers...)
		status, body = generalClient.get(t, "/api/annotations?dashboardUID="+dashAllowed.UID)
		requireNoLeak(t, status, body, allowedNoteText, allowedNoteTag)
		status, body = orgClient.get(t, "/api/annotations?dashboardUID="+dashOutside.UID)
		requireNoLeak(t, status, body, outsideMarkers...)
	})
}

type listedAnnotation struct {
	Text         string   `json:"text"`
	Tags         []string `json:"tags"`
	PrevState    string   `json:"prevState"`
	NewState     string   `json:"newState"`
	AlertID      int64    `json:"alertId"`
	Login        string   `json:"login"`
	Email        string   `json:"email"`
	DashboardUID *string  `json:"dashboardUID"`
}

type apiClient struct {
	addr     string
	login    string
	password string
}

func (c apiClient) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s", c.addr, path), nil)
	require.NoError(t, err)
	req.SetBasicAuth(c.login, c.password)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func requireNoLeak(t *testing.T, status int, body []byte, markers ...string) {
	t.Helper()
	require.NotEqual(t, http.StatusInternalServerError, status, string(body))
	switch status {
	case http.StatusOK:
		items := decodeAnnotations(t, body)
		require.Empty(t, items, string(body))
	case http.StatusForbidden:
	default:
		t.Fatalf("status %d, body %s", status, body)
	}
	requireNoMarkers(t, body, markers...)
}

func requireNoSensitiveOutsideFields(t *testing.T, body []byte) {
	t.Helper()
	requireNoMarkers(t, body, outsideNoteText, outsideNoteTag, outsidePrev, outsideNew, outsideLogin, outsideEmail)
}

func requireNoMarkers(t *testing.T, body []byte, markers ...string) {
	t.Helper()
	text := string(body)
	for _, marker := range markers {
		require.NotContains(t, text, marker)
	}
}

func decodeAnnotations(t *testing.T, body []byte) []listedAnnotation {
	t.Helper()
	var items []listedAnnotation
	require.NoError(t, json.Unmarshal(body, &items), string(body))
	return items
}

func texts(items []listedAnnotation) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Text)
	}
	return out
}

func annotationByText(t *testing.T, items []listedAnnotation, text string) listedAnnotation {
	t.Helper()
	for _, item := range items {
		if item.Text == text {
			return item
		}
	}
	require.Failf(t, "missing annotation", "text %q not in %#v", text, texts(items))
	return listedAnnotation{}
}

func dashboardReadPermissions(uids []string) []accesscontrol.Permission {
	perms := make([]accesscontrol.Permission, 0, len(uids))
	for _, uid := range uids {
		perms = append(perms, accesscontrol.Permission{
			Action: dashboards.ActionDashboardsRead,
			Scope:  dashboards.ScopeDashboardsProvider.GetResourceScopeUID(uid),
		})
	}
	return perms
}

func grantManagedPermissions(t *testing.T, store db.DB, userID int64, perms []accesscontrol.Permission) {
	t.Helper()
	err := store.WithDbSession(context.Background(), func(sess *sqlstore.DBSession) error {
		now := time.Now()
		role := &accesscontrol.Role{
			OrgID:   1,
			UID:     fmt.Sprintf("managed_user_%d_permissions", userID),
			Name:    accesscontrol.ManagedUserRoleName(userID),
			Updated: now,
			Created: now,
		}
		if _, err := sess.Insert(role); err != nil {
			return err
		}
		if _, err := sess.Insert(&accesscontrol.UserRole{
			OrgID:   1,
			RoleID:  role.ID,
			UserID:  userID,
			Created: now,
		}); err != nil {
			return err
		}
		for _, perm := range perms {
			perm.RoleID = role.ID
			perm.Created = now
			perm.Updated = now
			perm.Kind, perm.Attribute, perm.Identifier = accesscontrol.SplitScope(perm.Scope)
			if _, err := sess.Insert(&perm); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
}

func stampOutsideAnnotation(t *testing.T, store db.DB, annotationID, userID int64) {
	t.Helper()
	err := store.WithDbSession(context.Background(), func(sess *sqlstore.DBSession) error {
		_, err := sess.Exec(
			"UPDATE annotation SET user_id = ?, prev_state = ?, new_state = ?, alert_id = ? WHERE id = ?",
			userID, outsidePrev, outsideNew, outsideAlertID, annotationID,
		)
		return err
	})
	require.NoError(t, err)
}

func createAnnotationReturningID(t *testing.T, grafanaListedAddr string, payload map[string]any) int64 {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/api/annotations", grafanaListedAddr), bytes.NewReader(payloadBytes))
	require.NoError(t, err)
	req.SetBasicAuth("admin", "admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var created struct {
		ID int64 `json:"id"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	require.NotZero(t, created.ID)
	return created.ID
}

func createFolderWithParent(t *testing.T, grafanaListedAddr, title, parentUID string) *dtos.Folder {
	t.Helper()
	buf := &bytes.Buffer{}
	require.NoError(t, json.NewEncoder(buf).Encode(folder.CreateFolderCommand{
		Title:     title,
		ParentUID: parentUID,
	}))
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/api/folders", grafanaListedAddr), buf)
	require.NoError(t, err)
	req.SetBasicAuth("admin", "admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var created dtos.Folder
	require.NoError(t, json.Unmarshal(body, &created))
	require.NotEmpty(t, created.UID)
	require.NotEqual(t, parentUID, created.UID)
	return &created
}
