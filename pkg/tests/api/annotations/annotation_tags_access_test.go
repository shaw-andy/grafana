package annotations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/dashboards/dashboardaccess"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

const (
	// Local accounts created by this test. Logins and passwords are identical
	// placeholders, matching the other tests in this package.
	viewerLogin = "viewer"
	editorLogin = "editor"
	noneLogin   = "noneuser"

	hiddenTag       = "restricted-only-label"
	hiddenKeyValue  = "incident:hidden-customer"
	sharedTag       = "shared-label"
	visibleDashTag  = "visible-dash-label"
	orgTag          = "org-visible-label"
	hiddenEventText = "hidden-dashboard-event"
	visibleText     = "visible-dashboard-event"
	orgText         = "organization-event"
)

// TestIntegrationAnnotationTagSearchHidesInaccessibleDashboards is the spec for
// GET /api/annotations/tags. It fails while tag search counts annotations on
// dashboards the caller cannot read.
func TestIntegrationAnnotationTagSearchHidesInaccessibleDashboards(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	addr, editorID, noneUserID := startAnnotationFixture(t, testinfra.GrafanaOpts{
		DisableAnonymous: true,
	})
	sc := seedAnnotationTagScenario(t, addr, editorID)

	assertHiddenDashboardIsUnreadable(t, addr, sc)
	assertAnnotationListHidesRestrictedEvents(t, addr, sc)

	// No annotations:read grant at all. The route must still reject this caller.
	denied := getTagsDecoded(t, addr, noneLogin, noneLogin, "/api/annotations/tags", "tag", "", legacyTagResponse)
	require.Equalf(t, http.StatusForbidden, denied.status, "body: %s", denied.body)

	// Keep the Viewer and Editor grants that already exist on the general-folder
	// dashboard, and add a user whose only annotations:read is that dashboard.
	setDashboardPermissions(t, addr, sc.visibleDash.uid, []map[string]interface{}{
		{"role": string(org.RoleViewer), "permission": int(dashboardaccess.PERMISSION_VIEW)},
		{"role": string(org.RoleEditor), "permission": int(dashboardaccess.PERMISSION_EDIT)},
		{"userId": noneUserID, "permission": int(dashboardaccess.PERMISSION_VIEW)},
	})

	t.Run("viewer with organization annotations:read", func(t *testing.T) {
		assertTagSearchHidesRestrictedEvents(t, addr, "/api/annotations/tags", "tag", legacyTagResponse)
	})
	t.Run("caller limited to one dashboard", func(t *testing.T) {
		body := apiBody(t, addr, noneLogin, noneLogin, http.MethodGet, "/api/annotations?limit=100", http.StatusOK)
		require.NotContains(t, string(body), hiddenTag)
		require.NotContains(t, string(body), orgTag)
		require.Contains(t, string(body), visibleDashTag)

		noneTags := getTagsDecoded(t, addr, noneLogin, noneLogin, "/api/annotations/tags", "tag", "", legacyTagResponse)
		require.Equal(t, http.StatusOK, noneTags.status, "dashboard view grants annotations:read, which is enough to call tag search: %s", noneTags.body)
		assertCallerCannotSeeRestrictedTags(t, noneTags.counts, false)
	})
}

// TestIntegrationAnnotationAppTagSearchHidesInaccessibleDashboards covers the
// annotation app tags route. The app is off unless annotations.app_platform is
// enabled; with the default legacy-sql backend that route counts the same rows
// as GET /api/annotations/tags.
func TestIntegrationAnnotationAppTagSearchHidesInaccessibleDashboards(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	addr, editorID, _ := startAnnotationFixture(t, testinfra.GrafanaOpts{
		DisableAnonymous:            true,
		EnableAnnotationAppPlatform: false,
	}, enableLegacySQLAnnotationApp)
	seedAnnotationTagScenario(t, addr, editorID)

	// The app route filters with contains/prefix. contains is passed through to the
	// same tag column match the legacy route exposes as tag.
	assertTagSearchHidesRestrictedEvents(t, addr, "/apis/annotation.grafana.app/v0alpha1/namespaces/default/tags", "contains", appTagResponse)
}

type dashRef struct {
	uid string
}

type tagScenario struct {
	hiddenDash  dashRef
	visibleDash dashRef
}

type tagPayload struct {
	counts map[string]int64
	status int
	body   string
}

func startAnnotationFixture(t *testing.T, opts testinfra.GrafanaOpts, mutateCfg ...func(t *testing.T, cfgPath string)) (addr string, editorID, noneUserID int64) {
	t.Helper()

	dir, cfgPath := testinfra.CreateGrafDir(t, opts)
	for _, mutate := range mutateCfg {
		mutate(t, cfgPath)
	}
	addr, env := testinfra.StartGrafanaEnv(t, dir, cfgPath)

	noneUserID = tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleNone),
		Login:          noneLogin,
		Password:       noneLogin,
		OrgID:          1,
	})
	editorID = tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleEditor),
		Login:          editorLogin,
		Password:       editorLogin,
		OrgID:          1,
	})
	tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleViewer),
		Login:          viewerLogin,
		Password:       viewerLogin,
		OrgID:          1,
	})
	return addr, editorID, noneUserID
}

func enableLegacySQLAnnotationApp(t *testing.T, cfgPath string) {
	t.Helper()
	// The product default store is legacy-sql. testinfra's helper switches the
	// app to the memory store, which would skip the SQL tag query.
	extra := "\n[annotations.app_platform]\nenabled = true\nstore_backend = legacy-sql\n"
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString(extra)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

func seedAnnotationTagScenario(t *testing.T, addr string, editorID int64) tagScenario {
	t.Helper()

	restricted := createFolder(t, addr, "Restricted Folder")
	setFolderPermissions(t, addr, restricted.UID, []map[string]interface{}{
		{"userId": editorID, "permission": int(dashboardaccess.PERMISSION_EDIT)},
	})
	hidden := createDashboard(t, addr, "Restricted Dashboard", restricted.ID, restricted.UID)
	visible := createDashboard(t, addr, "Visible Dashboard", 0, "")

	// Two events on the restricted dashboard so a leaked count cannot be explained
	// by a single row the caller can already see.
	createAnnotation(t, addr, "admin", "admin", map[string]interface{}{
		"dashboardUID": hidden.UID,
		"panelId":      1,
		"text":         hiddenEventText,
		"time":         1_700_000_000_000,
		"tags":         []string{hiddenTag, hiddenKeyValue, sharedTag},
	})
	createAnnotation(t, addr, "admin", "admin", map[string]interface{}{
		"dashboardUID": hidden.UID,
		"panelId":      1,
		"text":         hiddenEventText + "-second",
		"time":         1_700_000_000_001,
		"tags":         []string{hiddenTag},
	})
	createAnnotation(t, addr, "admin", "admin", map[string]interface{}{
		"dashboardUID": visible.UID,
		"panelId":      1,
		"text":         visibleText,
		"time":         1_700_000_000_002,
		"tags":         []string{visibleDashTag, sharedTag},
	})
	createAnnotation(t, addr, editorLogin, editorLogin, map[string]interface{}{
		"text": orgText,
		"time": 1_700_000_000_003,
		"tags": []string{orgTag},
	})

	return tagScenario{
		hiddenDash:  dashRef{uid: hidden.UID},
		visibleDash: dashRef{uid: visible.UID},
	}
}

func assertHiddenDashboardIsUnreadable(t *testing.T, addr string, sc tagScenario) {
	t.Helper()

	hidden := apiStatus(t, addr, viewerLogin, viewerLogin, http.MethodGet, "/api/dashboards/uid/"+sc.hiddenDash.uid)
	require.Equalf(t, http.StatusForbidden, hidden, "viewer must not be able to open the restricted dashboard")

	visible := apiStatus(t, addr, viewerLogin, viewerLogin, http.MethodGet, "/api/dashboards/uid/"+sc.visibleDash.uid)
	require.Equalf(t, http.StatusOK, visible, "viewer must still be able to open the general-folder dashboard")

	// The editor who was granted the folder can open the restricted dashboard.
	editor := apiStatus(t, addr, editorLogin, editorLogin, http.MethodGet, "/api/dashboards/uid/"+sc.hiddenDash.uid)
	require.Equalf(t, http.StatusOK, editor, "folder edit grant must allow the editor to open the dashboard")
}

func assertAnnotationListHidesRestrictedEvents(t *testing.T, addr string, sc tagScenario) {
	t.Helper()

	body := apiBody(t, addr, viewerLogin, viewerLogin, http.MethodGet, "/api/annotations?limit=100", http.StatusOK)
	var items []struct {
		Text         string   `json:"text"`
		Tags         []string `json:"tags"`
		DashboardUID string   `json:"dashboardUID"`
	}
	require.NoError(t, json.Unmarshal(body, &items))

	var texts []string
	var tags []string
	var dashboards []string
	for _, item := range items {
		texts = append(texts, item.Text)
		tags = append(tags, item.Tags...)
		if item.DashboardUID != "" {
			dashboards = append(dashboards, item.DashboardUID)
		}
	}
	require.NotContains(t, texts, hiddenEventText)
	require.NotContains(t, texts, hiddenEventText+"-second")
	require.NotContains(t, tags, hiddenTag)
	require.NotContains(t, tags, hiddenKeyValue)
	require.NotContains(t, dashboards, sc.hiddenDash.uid)
	require.Contains(t, texts, visibleText)
	require.Contains(t, texts, orgText)
	require.Contains(t, tags, visibleDashTag)
	require.Contains(t, tags, orgTag)

	filtered := apiBody(t, addr, viewerLogin, viewerLogin, http.MethodGet, "/api/annotations?limit=100&tags="+url.QueryEscape(hiddenTag), http.StatusOK)
	var filteredItems []struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(filtered, &filteredItems))
	require.Empty(t, filteredItems, "annotation list tag filter must not return events on dashboards the caller cannot read")
}

func assertTagSearchHidesRestrictedEvents(t *testing.T, addr, path, queryParam string, decode func(*testing.T, []byte) map[string]int64) {
	t.Helper()

	admin := getTagsDecoded(t, addr, "admin", "admin", path, queryParam, "", decode)
	require.Equal(t, http.StatusOK, admin.status, "admin tag search: %s", admin.body)
	require.Equal(t, int64(2), admin.counts[hiddenTag], "admin must see both restricted annotations, got %#v from %s", admin.counts, admin.body)
	require.Equal(t, int64(1), admin.counts[hiddenKeyValue])
	require.Equal(t, int64(2), admin.counts[sharedTag])
	require.Equal(t, int64(1), admin.counts[visibleDashTag])
	require.Equal(t, int64(1), admin.counts[orgTag])

	viewer := getTagsDecoded(t, addr, viewerLogin, viewerLogin, path, queryParam, "", decode)
	require.Equal(t, http.StatusOK, viewer.status, "viewer has organization annotations:read, so tag search must succeed: %s", viewer.body)
	assertCallerCannotSeeRestrictedTags(t, viewer.counts, true)

	byHiddenKey := getTagsDecoded(t, addr, viewerLogin, viewerLogin, path, queryParam, hiddenTag, decode)
	require.Equal(t, http.StatusOK, byHiddenKey.status, "%s", byHiddenKey.body)
	require.NotContains(t, byHiddenKey.counts, hiddenTag, "tag query must not return a label that exists only on a dashboard the caller cannot read: %s", byHiddenKey.body)

	byHiddenValue := getTagsDecoded(t, addr, viewerLogin, viewerLogin, path, queryParam, "hidden-customer", decode)
	require.Equal(t, http.StatusOK, byHiddenValue.status, "%s", byHiddenValue.body)
	require.NotContains(t, byHiddenValue.counts, hiddenKeyValue, "tag query must not match the value of a label on a dashboard the caller cannot read: %s", byHiddenValue.body)

	byShared := getTagsDecoded(t, addr, viewerLogin, viewerLogin, path, queryParam, sharedTag, decode)
	require.Equal(t, http.StatusOK, byShared.status, "%s", byShared.body)
	require.Equal(t, int64(1), byShared.counts[sharedTag], "shared tag count must exclude the restricted dashboard, got %#v from %s", byShared.counts, byShared.body)
}

func assertCallerCannotSeeRestrictedTags(t *testing.T, counts map[string]int64, canReadOrgAnnotations bool) {
	t.Helper()

	require.NotContains(t, counts, hiddenTag)
	require.NotContains(t, counts, hiddenKeyValue)
	require.Equal(t, int64(1), counts[sharedTag], "count must include only the annotation on the dashboard this caller can read, got %#v", counts)
	require.Equal(t, int64(1), counts[visibleDashTag])
	if canReadOrgAnnotations {
		require.Equal(t, int64(1), counts[orgTag])
		return
	}
	require.NotContains(t, counts, orgTag, "organization annotation tags require the organization annotations:read scope, got %#v", counts)
}

func legacyTagResponse(t *testing.T, body []byte) map[string]int64 {
	t.Helper()
	var payload struct {
		Result struct {
			Tags []struct {
				Tag   string `json:"tag"`
				Count int64  `json:"count"`
			} `json:"tags"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &payload), "body: %s", body)
	counts := make(map[string]int64, len(payload.Result.Tags))
	for _, tag := range payload.Result.Tags {
		counts[tag.Tag] = tag.Count
	}
	return counts
}

func appTagResponse(t *testing.T, body []byte) map[string]int64 {
	t.Helper()
	var payload struct {
		Tags []struct {
			Tag   string `json:"tag"`
			Count int64  `json:"count"`
		} `json:"tags"`
	}
	require.NoError(t, json.Unmarshal(body, &payload), "body: %s", body)
	counts := make(map[string]int64, len(payload.Tags))
	for _, tag := range payload.Tags {
		counts[tag.Tag] = tag.Count
	}
	return counts
}

func getTagsDecoded(t *testing.T, addr, login, password, path, queryParam, tag string, decode func(*testing.T, []byte) map[string]int64) tagPayload {
	t.Helper()
	if tag != "" {
		path += "?" + queryParam + "=" + url.QueryEscape(tag) + "&limit=100"
	}
	status, body := apiDo(t, addr, login, password, http.MethodGet, path, nil)
	payload := tagPayload{status: status, body: string(body)}
	if status == http.StatusOK {
		payload.counts = decode(t, body)
	}
	return payload
}

func apiStatus(t *testing.T, addr, login, password, method, path string) int {
	t.Helper()
	status, body := apiDo(t, addr, login, password, method, path, nil)
	if status >= 500 {
		t.Fatalf("%s %s: status %d body %s", method, path, status, body)
	}
	return status
}

func apiBody(t *testing.T, addr, login, password, method, path string, want int) []byte {
	t.Helper()
	status, body := apiDo(t, addr, login, password, method, path, nil)
	require.Equalf(t, want, status, "%s %s body: %s", method, path, body)
	return body
}

func apiDo(t *testing.T, addr, login, password, method, path string, payload []byte) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://%s%s", addr, path), body)
	require.NoError(t, err)
	req.SetBasicAuth(login, password)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}
