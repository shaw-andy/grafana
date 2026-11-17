package libraryelements_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/services/dashboards/dashboardaccess"
	"github.com/grafana/grafana/pkg/services/libraryelements/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// placeholderPassword is a fake credential used only by this test process.
const placeholderPassword = "placeholder"

// TestIntegrationLibraryElementFolderIDPatchSkipsDestinationCheck is the HTTP
// form of a library-panel move that sends the deprecated folderId and omits
// folderUid. The caller can edit the panel's current folder and can only view
// the destination. The panel must stay where it is.
func TestIntegrationLibraryElementFolderIDPatchSkipsDestinationCheck(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	dir, path := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{})
	grafanaListedAddr, env := testinfra.StartGrafanaEnv(t, dir, path)
	cfgProvider, err := configprovider.ProvideService(env.Cfg)
	require.NoError(t, err)
	quotaService := quotaimpl.ProvideService(context.Background(), legacysql.NewDatabaseProvider(env.SQLStore), cfgProvider)
	orgService, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(env.SQLStore), env.Cfg, quotaService)
	require.NoError(t, err)

	sharedOrg, err := orgService.CreateWithMember(context.Background(), &org.CreateOrgCommand{Name: "folder id patch org"})
	require.NoError(t, err)

	editorID := createUserInOrg(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleViewer),
		Password:       placeholderPassword,
		Login:          "folder-editor",
		OrgID:          sharedOrg.ID,
	})
	createUserInOrg(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleAdmin),
		Password:       placeholderPassword,
		Login:          "folder-admin",
		OrgID:          sharedOrg.ID,
	})

	folderA := createNamedFolder(t, grafanaListedAddr, "Folder A")
	folderB := createNamedFolder(t, grafanaListedAddr, "Folder B")
	require.NotZero(t, folderB.ID, "folder B must have a numeric id so folderId can name it")
	require.NotEqual(t, folderA.UID, folderB.UID)

	grantFolderPermissionAs(t, grafanaListedAddr, "folder-admin", placeholderPassword, folderA.UID, editorID, dashboardaccess.PERMISSION_EDIT)
	grantFolderPermissionAs(t, grafanaListedAddr, "folder-admin", placeholderPassword, folderB.UID, editorID, dashboardaccess.PERMISSION_VIEW)

	t.Run("folderUid into a view-only folder is forbidden", func(t *testing.T) {
		panelUID := createNamedLibraryElement(t, grafanaListedAddr, "folder-editor", placeholderPassword, folderA.UID, "Panel Folder UID")
		status, _ := patchLibraryElementRaw(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID, map[string]any{
			"folderUid": folderB.UID,
			"version":   libraryElementVersion(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID),
			"kind":      1,
		})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, folderA.UID, libraryElementFolderUID(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID))
	})

	t.Run("folderId into a view-only folder is forbidden and the panel stays", func(t *testing.T) {
		panelUID := createNamedLibraryElement(t, grafanaListedAddr, "folder-editor", placeholderPassword, folderA.UID, "Panel Folder ID")
		version := libraryElementVersion(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID)
		status, body := patchLibraryElementRaw(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID, map[string]any{
			"folderId": folderB.ID,
			"version":  version,
			"kind":     1,
		})
		got := libraryElementFolderUID(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID)
		require.Equalf(t, http.StatusForbidden, status, "PATCH response %s left the panel in folder %q", body, got)
		require.Equal(t, folderA.UID, got)
		require.NotContains(t, libraryElementUIDsInFolder(t, grafanaListedAddr, "folder-editor", placeholderPassword, folderB.UID), panelUID)
	})

	t.Run("folderId 0 does not move the panel into the general folder", func(t *testing.T) {
		panelUID := createNamedLibraryElement(t, grafanaListedAddr, "folder-editor", placeholderPassword, folderA.UID, "Panel General")
		version := libraryElementVersion(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID)
		status, body := patchLibraryElementRaw(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID, map[string]any{
			"folderId": int64(0),
			"version":  version,
			"kind":     1,
		})
		got := libraryElementFolderUID(t, grafanaListedAddr, "folder-editor", placeholderPassword, panelUID)
		require.Equalf(t, http.StatusForbidden, status, "PATCH response %s left the panel in folder %q", body, got)
		require.Equal(t, folderA.UID, got)
	})
}

type folderIDResponse struct {
	ID  int64  `json:"id"`
	UID string `json:"uid"`
}

func createNamedFolder(t *testing.T, grafanaListedAddr, title string) folderIDResponse {
	t.Helper()
	resp := makeHTTPRequest(t, http.MethodPost, fmt.Sprintf("http://folder-admin:%s@%s/api/folders", placeholderPassword, grafanaListedAddr), map[string]any{
		"title": title,
	}, http.StatusOK)
	var folder folderIDResponse
	require.NoError(t, json.Unmarshal(resp, &folder))
	require.NotEmpty(t, folder.UID)
	return folder
}

func createNamedLibraryElement(t *testing.T, grafanaListedAddr, userName, password, folderUID, name string) string {
	t.Helper()
	resp := makeHTTPRequest(t, http.MethodPost, fmt.Sprintf("http://%s:%s@%s/api/library-elements", userName, password, grafanaListedAddr), map[string]any{
		"name": name,
		"model": map[string]any{
			"datasource":  "${DS_GDEV-TESTDATA}",
			"id":          1,
			"title":       name,
			"type":        "text",
			"description": "A description",
		},
		"folderUid": folderUID,
		"kind":      int64(1),
	}, http.StatusOK)
	var result model.LibraryElementResponse
	require.NoError(t, json.Unmarshal(resp, &result))
	require.NotEmpty(t, result.Result.UID)
	return result.Result.UID
}

func libraryElementVersion(t *testing.T, grafanaListedAddr, userName, password, uid string) int64 {
	t.Helper()
	return libraryElementResult(t, grafanaListedAddr, userName, password, uid).Version
}

func libraryElementFolderUID(t *testing.T, grafanaListedAddr, userName, password, uid string) string {
	t.Helper()
	return libraryElementResult(t, grafanaListedAddr, userName, password, uid).FolderUID
}

func libraryElementResult(t *testing.T, grafanaListedAddr, userName, password, uid string) model.LibraryElementDTO {
	t.Helper()
	resp := makeHTTPRequest(t, http.MethodGet, fmt.Sprintf("http://%s:%s@%s/api/library-elements/%s", userName, password, grafanaListedAddr, uid), nil, http.StatusOK)
	var result model.LibraryElementResponse
	require.NoError(t, json.Unmarshal(resp, &result))
	return result.Result
}

func libraryElementUIDsInFolder(t *testing.T, grafanaListedAddr, userName, password, folderUID string) []string {
	t.Helper()
	resp := makeHTTPRequest(t, http.MethodGet, fmt.Sprintf("http://%s:%s@%s/api/library-elements?folderFilterUIDs=%s", userName, password, grafanaListedAddr, folderUID), nil, http.StatusOK)
	var result model.LibraryElementSearchResponse
	require.NoError(t, json.Unmarshal(resp, &result))
	uids := make([]string, 0, len(result.Result.Elements))
	for _, element := range result.Result.Elements {
		uids = append(uids, element.UID)
	}
	return uids
}

func patchLibraryElementRaw(t *testing.T, grafanaListedAddr, userName, password, uid string, body map[string]any) (int, string) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("http://%s:%s@%s/api/library-elements/%s", userName, password, grafanaListedAddr, uid), bytes.NewReader(buf))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(payload)
}

func grantFolderPermissionAs(t *testing.T, grafanaListedAddr, userName, password, folderUID string, userID int64, permission dashboardaccess.PermissionType) {
	t.Helper()
	makeHTTPRequest(t, http.MethodPost, fmt.Sprintf("http://%s:%s@%s/api/folders/%s/permissions", userName, password, grafanaListedAddr, folderUID), map[string]any{
		"items": []map[string]any{
			{
				"userId":     userID,
				"permission": int(permission),
			},
		},
	}, http.StatusOK)
}
