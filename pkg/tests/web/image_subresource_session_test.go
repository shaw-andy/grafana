package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/server"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// TestIntegrationImageSubresourceSession covers the server half of a table image cell
// whose address is a same-origin path. A browser image load is a GET with the session
// cookie, no Origin header, and Sec-Fetch-Dest: image. That request must not sign the
// viewer out or move them to another organization. A top-level navigation to the same
// URLs still may.
func TestIntegrationImageSubresourceSession(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	grafDir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{})
	addr, env := testinfra.StartGrafanaEnv(t, grafDir, cfgPath)

	created := testinfra.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		Login:    "viewer",
		Password: "placeholder",
		Email:    "viewer@example.com",
	})
	require.NotZero(t, created.ID)
	require.NotZero(t, created.OrgID)

	second := createOrgWithMember(t, env, created.ID)
	require.NotEqual(t, created.OrgID, second.ID)

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	cookieName := env.Cfg.LoginCookieName

	t.Run("image GET /logout does not revoke the session", func(t *testing.T) {
		session := loginUser(t, addr, "viewer", "placeholder")
		status, _ := fetchProfile(t, client, addr, session)
		require.Equal(t, http.StatusOK, status)

		resp := fetchWithMetadata(t, client, addr, "/logout", session, imageFetch)
		cleared := sessionCookieCleared(resp, cookieName)
		resp.Body.Close()

		status, _ = fetchProfile(t, client, addr, session)
		assert.False(t, cleared, "image load cleared the session cookie")
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("document navigation GET /logout still revokes the session", func(t *testing.T) {
		session := loginUser(t, addr, "viewer", "placeholder")
		resp := fetchWithMetadata(t, client, addr, "/logout", session, navigateFetch)
		resp.Body.Close()

		status, _ := fetchProfile(t, client, addr, session)
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("image GET /profile/switch-org does not change the active organization", func(t *testing.T) {
		session := loginUser(t, addr, "viewer", "placeholder")
		status, orgID := fetchProfile(t, client, addr, session)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, created.OrgID, orgID)

		path := "/profile/switch-org/" + strconv.FormatInt(second.ID, 10)
		resp := fetchWithMetadata(t, client, addr, path, session, imageFetch)
		require.False(t, sessionCookieCleared(resp, cookieName), "image load cleared the session cookie")
		resp.Body.Close()

		status, orgID = fetchProfile(t, client, addr, session)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, created.OrgID, orgID)
	})

	t.Run("document navigation GET /profile/switch-org still changes the active organization", func(t *testing.T) {
		session := loginUser(t, addr, "viewer", "placeholder")
		path := "/profile/switch-org/" + strconv.FormatInt(second.ID, 10)
		resp := fetchWithMetadata(t, client, addr, path, session, navigateFetch)
		resp.Body.Close()

		status, orgID := fetchProfile(t, client, addr, session)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, second.ID, orgID)
	})
}

type fetchMetadata func(req *http.Request)

func imageFetch(req *http.Request) {
	req.Header.Set("Sec-Fetch-Dest", "image")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
}

func navigateFetch(req *http.Request) {
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
}

func fetchWithMetadata(t *testing.T, client *http.Client, addr, path string, session *http.Cookie, meta fetchMetadata) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s", addr, path), nil)
	require.NoError(t, err)
	req.AddCookie(session)
	meta(req)
	// Image and same-origin GET navigations do not send Origin. Leaving it unset
	// is the request the browser makes.

	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func sessionCookieCleared(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name && (c.MaxAge < 0 || c.Value == "") {
			return true
		}
	}
	return false
}

func fetchProfile(t *testing.T, client *http.Client, addr string, session *http.Cookie) (int, int64) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/api/user", addr), nil)
	require.NoError(t, err)
	req.AddCookie(session)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, 0
	}

	var profile struct {
		OrgID int64 `json:"orgId"`
	}
	require.NoError(t, json.Unmarshal(body, &profile))
	return resp.StatusCode, profile.OrgID
}

func createOrgWithMember(t *testing.T, env *server.TestEnv, userID int64) *org.Org {
	t.Helper()

	cfgProvider, err := configprovider.ProvideService(env.Cfg)
	require.NoError(t, err)
	quotaService := quotaimpl.ProvideService(context.Background(), legacysql.NewDatabaseProvider(env.SQLStore), cfgProvider)
	orgService, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(env.SQLStore), env.Cfg, quotaService)
	require.NoError(t, err)

	created, err := orgService.CreateWithMember(context.Background(), &org.CreateOrgCommand{
		Name:   fmt.Sprintf("other-org-%d", time.Now().UnixNano()),
		UserID: userID,
	})
	require.NoError(t, err)
	return created
}
