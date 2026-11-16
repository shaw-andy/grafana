package annotations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// placeholderPassword is a local test credential, not a real secret.
const placeholderPassword = "placeholder"

// TestIntegrationHiddenUsersAnnotationIdentity checks that annotation reads do not
// disclose login, email, avatar URL, user id, or user UID for accounts listed in
// hidden_users, except to a Grafana server admin and to that same user.
//
// The assertions are the intended behavior. They fail while those fields are copied
// from the user join into the annotation JSON with no hidden_users check.
func TestIntegrationHiddenUsersAnnotationIdentity(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	const (
		hiddenLogin   = "breakglass"
		hiddenEmail   = "breakglass@example.com"
		visibleLogin  = "visible-editor"
		visibleEmail  = "visible-editor@example.com"
		viewerLogin   = "viewer-caller"
		orgAdminLogin = "org-admin"

		hiddenDashText     = "hidden dashboard annotation"
		hiddenOrgText      = "hidden organization annotation"
		hiddenGraphiteText = "hidden graphite annotation"
		visibleDashText    = "visible dashboard annotation"
	)

	dir, path := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableAnonymous: true,
	})
	grafanaListedAddr, env := testinfra.StartGrafanaEnv(t, dir, path)

	hiddenUserID := tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleEditor),
		Login:          hiddenLogin,
		Email:          hiddenEmail,
		Password:       placeholderPassword,
		IsAdmin:        false,
		OrgID:          1,
	})
	require.NotZero(t, hiddenUserID)

	tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleEditor),
		Login:          visibleLogin,
		Email:          visibleEmail,
		Password:       placeholderPassword,
		IsAdmin:        false,
		OrgID:          1,
	})
	tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleViewer),
		Login:          viewerLogin,
		Email:          "viewer-caller@example.com",
		Password:       placeholderPassword,
		IsAdmin:        false,
		OrgID:          1,
	})
	tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleAdmin),
		Login:          orgAdminLogin,
		Email:          "org-admin@example.com",
		Password:       placeholderPassword,
		IsAdmin:        false,
		OrgID:          1,
	})

	// Same map the running server reads. IsHiddenUser looks it up per request.
	require.NotNil(t, env.Cfg.HiddenUsers)
	env.Cfg.HiddenUsers[hiddenLogin] = struct{}{}
	t.Cleanup(func() {
		delete(env.Cfg.HiddenUsers, hiddenLogin)
	})

	dash := createDashboard(t, grafanaListedAddr, "Hidden user annotation dashboard", 0, "")

	hiddenDashID := createAnnotationReturningID(t, grafanaListedAddr, hiddenLogin, placeholderPassword, map[string]any{
		"dashboardUID": dash.UID,
		"panelId":      1,
		"text":         hiddenDashText,
		"time":         int64(1700000000000),
	})
	hiddenOrgID := createAnnotationReturningID(t, grafanaListedAddr, hiddenLogin, placeholderPassword, map[string]any{
		"text": hiddenOrgText,
		"time": int64(1700000001000),
	})
	hiddenGraphiteID := createGraphiteAnnotationReturningID(t, grafanaListedAddr, hiddenLogin, placeholderPassword, map[string]any{
		"what": hiddenGraphiteText,
		"when": int64(1700000002),
		"tags": "deploy",
	})
	visibleDashID := createAnnotationReturningID(t, grafanaListedAddr, visibleLogin, placeholderPassword, map[string]any{
		"dashboardUID": dash.UID,
		"panelId":      1,
		"text":         visibleDashText,
		"time":         int64(1700000003000),
	})

	t.Run("org user search hides the account from an org admin", func(t *testing.T) {
		logins := orgUserLogins(t, grafanaListedAddr, orgAdminLogin, placeholderPassword)
		require.NotContains(t, logins, hiddenLogin)
		require.Contains(t, logins, visibleLogin)
	})

	t.Run("org user search still shows the account to a grafana server admin", func(t *testing.T) {
		logins := orgUserLogins(t, grafanaListedAddr, env.Cfg.AdminUser, env.Cfg.AdminPassword)
		require.Contains(t, logins, hiddenLogin)
		require.Contains(t, logins, visibleLogin)
	})

	callersWhoMustNotSeeHiddenIdentity := []struct {
		name  string
		login string
	}{
		{name: "viewer", login: viewerLogin},
		{name: "org admin who is not a grafana server admin", login: orgAdminLogin},
	}

	for _, caller := range callersWhoMustNotSeeHiddenIdentity {
		t.Run(caller.name+" listing annotations by dashboard uid", func(t *testing.T) {
			items := listAnnotations(t, grafanaListedAddr, caller.login, placeholderPassword, "dashboardUID="+dash.UID)
			hidden := annotationByText(t, items, hiddenDashText)
			visible := annotationByText(t, items, visibleDashText)
			require.Equal(t, hiddenDashID, hidden.ID)
			require.Equal(t, visibleDashID, visible.ID)
			assertHiddenAuthorCleared(t, hidden)
			assertAuthorVisible(t, visible, visibleLogin, visibleEmail)
		})

		t.Run(caller.name+" listing annotations without a dashboard filter", func(t *testing.T) {
			items := listAnnotations(t, grafanaListedAddr, caller.login, placeholderPassword, "")
			assertHiddenAuthorCleared(t, annotationByText(t, items, hiddenDashText))
			assertHiddenAuthorCleared(t, annotationByText(t, items, hiddenOrgText))
			assertHiddenAuthorCleared(t, annotationByText(t, items, hiddenGraphiteText))
			assertAuthorVisible(t, annotationByText(t, items, visibleDashText), visibleLogin, visibleEmail)
		})

		for _, idCase := range []struct {
			name string
			id   int64
			text string
		}{
			{name: "dashboard annotation", id: hiddenDashID, text: hiddenDashText},
			{name: "organization annotation", id: hiddenOrgID, text: hiddenOrgText},
			{name: "graphite annotation", id: hiddenGraphiteID, text: hiddenGraphiteText},
		} {
			t.Run(caller.name+" reading "+idCase.name+" by id", func(t *testing.T) {
				item := getAnnotationByID(t, grafanaListedAddr, caller.login, placeholderPassword, idCase.id)
				require.Equal(t, idCase.text, item.Text)
				require.Equal(t, idCase.id, item.ID)
				assertHiddenAuthorCleared(t, item)
			})
		}

		t.Run(caller.name+" reading a non-hidden author's annotation by id", func(t *testing.T) {
			item := getAnnotationByID(t, grafanaListedAddr, caller.login, placeholderPassword, visibleDashID)
			require.Equal(t, visibleDashText, item.Text)
			assertAuthorVisible(t, item, visibleLogin, visibleEmail)
		})
	}

	t.Run("grafana server admin still sees the hidden account", func(t *testing.T) {
		items := listAnnotations(t, grafanaListedAddr, env.Cfg.AdminUser, env.Cfg.AdminPassword, "dashboardUID="+dash.UID)
		assertAuthorVisible(t, annotationByText(t, items, hiddenDashText), hiddenLogin, hiddenEmail)

		item := getAnnotationByID(t, grafanaListedAddr, env.Cfg.AdminUser, env.Cfg.AdminPassword, hiddenOrgID)
		require.Equal(t, hiddenOrgText, item.Text)
		assertAuthorVisible(t, item, hiddenLogin, hiddenEmail)
	})

	t.Run("the hidden user still sees their own identity", func(t *testing.T) {
		items := listAnnotations(t, grafanaListedAddr, hiddenLogin, placeholderPassword, "dashboardUID="+dash.UID)
		assertAuthorVisible(t, annotationByText(t, items, hiddenDashText), hiddenLogin, hiddenEmail)

		item := getAnnotationByID(t, grafanaListedAddr, hiddenLogin, placeholderPassword, hiddenGraphiteID)
		require.Equal(t, hiddenGraphiteText, item.Text)
		assertAuthorVisible(t, item, hiddenLogin, hiddenEmail)
	})
}

type annotationAuthorBody struct {
	ID        int64  `json:"id"`
	Text      string `json:"text"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatarUrl"`
	UserID    int64  `json:"userId"`
	UserUID   string `json:"userUID"`
}

func assertHiddenAuthorCleared(t *testing.T, item annotationAuthorBody) {
	t.Helper()
	require.Empty(t, item.Login)
	require.Empty(t, item.Email)
	require.Empty(t, item.AvatarURL)
	require.Empty(t, item.UserUID)
	require.Zero(t, item.UserID)
	require.NotEmpty(t, item.Text)
}

func assertAuthorVisible(t *testing.T, item annotationAuthorBody, login, email string) {
	t.Helper()
	require.Equal(t, login, item.Login)
	require.Equal(t, email, item.Email)
	require.NotEmpty(t, item.AvatarURL)
	require.NotEmpty(t, item.UserUID)
}

func annotationByText(t *testing.T, items []annotationAuthorBody, text string) annotationAuthorBody {
	t.Helper()
	for _, item := range items {
		if item.Text == text {
			return item
		}
	}
	require.Failf(t, "annotation not found", "text %q not in %d annotations", text, len(items))
	return annotationAuthorBody{}
}

func listAnnotations(t *testing.T, addr, login, password, query string) []annotationAuthorBody {
	t.Helper()
	url := fmt.Sprintf("http://%s/api/annotations", addr)
	if query != "" {
		url += "?" + query
	}
	status, body := doAnnotationRequest(t, http.MethodGet, url, login, password, nil)
	require.Equalf(t, http.StatusOK, status, "body: %s", body)
	var items []annotationAuthorBody
	require.NoError(t, json.Unmarshal(body, &items))
	return items
}

func getAnnotationByID(t *testing.T, addr, login, password string, id int64) annotationAuthorBody {
	t.Helper()
	url := fmt.Sprintf("http://%s/api/annotations/%d", addr, id)
	status, body := doAnnotationRequest(t, http.MethodGet, url, login, password, nil)
	require.Equalf(t, http.StatusOK, status, "body: %s", body)
	var item annotationAuthorBody
	require.NoError(t, json.Unmarshal(body, &item))
	return item
}

func orgUserLogins(t *testing.T, addr, login, password string) []string {
	t.Helper()
	url := fmt.Sprintf("http://%s/api/org/users/search?perpage=100&page=1", addr)
	status, body := doAnnotationRequest(t, http.MethodGet, url, login, password, nil)
	require.Equalf(t, http.StatusOK, status, "body: %s", body)
	var result struct {
		OrgUsers []struct {
			Login string `json:"login"`
		} `json:"orgUsers"`
	}
	require.NoError(t, json.Unmarshal(body, &result))
	logins := make([]string, 0, len(result.OrgUsers))
	for _, u := range result.OrgUsers {
		logins = append(logins, u.Login)
	}
	return logins
}

func createAnnotationReturningID(t *testing.T, addr, login, password string, payload map[string]any) int64 {
	t.Helper()
	url := fmt.Sprintf("http://%s/api/annotations", addr)
	status, body := doAnnotationRequest(t, http.MethodPost, url, login, password, payload)
	require.Equalf(t, http.StatusOK, status, "body: %s", body)
	var created struct {
		ID int64 `json:"id"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	require.NotZero(t, created.ID)
	return created.ID
}

func createGraphiteAnnotationReturningID(t *testing.T, addr, login, password string, payload map[string]any) int64 {
	t.Helper()
	url := fmt.Sprintf("http://%s/api/annotations/graphite", addr)
	status, body := doAnnotationRequest(t, http.MethodPost, url, login, password, payload)
	require.Equalf(t, http.StatusOK, status, "body: %s", body)
	var created struct {
		ID int64 `json:"id"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	require.NotZero(t, created.ID)
	return created.ID
}

func doAnnotationRequest(t *testing.T, method, url, login, password string, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		require.NoError(t, err)
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, url, body)
	require.NoError(t, err)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(login, password)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, respBody
}
