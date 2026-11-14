package shorturl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/testinfra"
)

// TestIntegrationShortURLCannotMutateAnotherUsersSession is the spec for short
// URL paths. It fails while a signed-in viewer can publish a relative path that
// Grafana will redirect a colleague's browser to, when that path is a GET route
// which changes the colleague's session or deletes a snapshot.
//
// Read-only paths such as explore must keep working.
func TestIntegrationShortURLCannotMutateAnotherUsersSession(t *testing.T) {
	dir, path := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		AppModeProduction: true,
		DisableAnonymous:  true,
	})
	addr, env := testinfra.StartGrafanaEnv(t, dir, path)

	const (
		viewerLogin = "viewer-shorturl"
		viewerPass  = "viewer"
		victimLogin = "victim-shorturl"
		victimPass  = "victim"
	)

	createUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleViewer),
		Password:       user.Password(viewerPass),
		Login:          viewerLogin,
	})
	victimID := createUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(org.RoleAdmin),
		Password:       user.Password(victimPass),
		Login:          victimLogin,
	})

	orgService, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(env.SQLStore), env.Cfg, quotatest.New(false, nil))
	require.NoError(t, err)
	otherOrg, err := orgService.CreateWithMember(context.Background(), &org.CreateOrgCommand{
		Name:   fmt.Sprintf("shorturl-other-%d", time.Now().UnixNano()),
		UserID: victimID,
	})
	require.NoError(t, err)

	publisher := client(addr, viewerLogin, viewerPass)
	victim := newSessionClient(t, addr, victimLogin, victimPass)
	homeOrg, homeStatus := victim.currentOrg(t)
	require.Equal(t, http.StatusOK, homeStatus)
	require.NotEqual(t, otherOrg.ID, homeOrg, "victim must start in a different org than the switch target")

	t.Run("read-only explore path still redirects", func(t *testing.T) {
		uid := mustCreateShortURL(t, publisher, "explore")
		location := victim.gotoLocation(t, uid)
		require.Equal(t, "/explore", locationPath(t, location))
		require.Equal(t, homeOrg, mustCurrentOrg(t, victim))
	})

	t.Run("logout path does not end the victim session", func(t *testing.T) {
		fresh := newSessionClient(t, addr, victimLogin, victimPass)
		require.Equal(t, http.StatusOK, mustStatus(t, fresh.get("/api/user")))
		assertStateChangingPathRejected(t, publisher, fresh, "logout", func(t *testing.T, followed *http.Response) {
			t.Helper()
			require.Equal(t, http.StatusOK, mustStatus(t, fresh.get("/api/user")), "original session must still be accepted after the short link was opened")
			_ = followed
		})
	})

	t.Run("token rotation path is not published", func(t *testing.T) {
		fresh := newSessionClient(t, addr, victimLogin, victimPass)
		assertStateChangingPathRejected(t, publisher, fresh, "user/auth-tokens/rotate", func(t *testing.T, followed *http.Response) {
			t.Helper()
			_ = followed
			require.Equal(t, http.StatusOK, mustStatus(t, fresh.get("/api/user")), "original session must still be accepted")
		})
	})

	t.Run("snapshot delete path does not delete the snapshot", func(t *testing.T) {
		creator := newSessionClient(t, addr, victimLogin, victimPass)
		dashUID := createDashboard(t, creator)
		key, deleteKey := createSnapshot(t, creator, dashUID)
		fresh := newSessionClient(t, addr, victimLogin, victimPass)
		path := "api/snapshots-delete/" + deleteKey
		assertStateChangingPathRejected(t, publisher, fresh, path, func(t *testing.T, followed *http.Response) {
			t.Helper()
			_ = followed
			res := fresh.get("/api/snapshots/" + key)
			defer func() { _ = res.Body.Close() }()
			require.Equal(t, http.StatusOK, res.StatusCode, "snapshot must still exist after the short link was opened")
		})
	})

	t.Run("email update and invite completion paths are not published", func(t *testing.T) {
		for _, path := range []string{
			"user/email/update?code=example",
			"api/user/invite/complete",
		} {
			t.Run(path, func(t *testing.T) {
				fresh := newSessionClient(t, addr, victimLogin, victimPass)
				assertStateChangingPathRejected(t, publisher, fresh, path, func(t *testing.T, followed *http.Response) {
					t.Helper()
					_ = followed
				})
			})
		}
	})

	t.Run("org switch path does not change the victim active org", func(t *testing.T) {
		t.Cleanup(func() {
			// Opening the link updates the stored active org. Put it back so this
			// failure does not leave the victim in the other organization.
			restored := newSessionClient(t, addr, victimLogin, victimPass)
			res := restored.do(http.MethodPost, fmt.Sprintf("/api/user/using/%d", homeOrg), nil, "")
			_ = mustStatus(t, res)
		})
		fresh := newSessionClient(t, addr, victimLogin, victimPass)
		before, status := fresh.currentOrg(t)
		require.Equal(t, http.StatusOK, status)
		require.NotEqual(t, otherOrg.ID, before)
		path := fmt.Sprintf("profile/switch-org/%d", otherOrg.ID)
		assertStateChangingPathRejected(t, publisher, fresh, path, func(t *testing.T, followed *http.Response) {
			t.Helper()
			_ = followed
			after, status := fresh.currentOrg(t)
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, before, after, "active org must be unchanged after the short link was opened")
		})
	})
}

// assertStateChangingPathRejected fails when a viewer can publish path and the
// victim's browser, following /goto, is sent to that path. Once publishing is
// refused, the follow callback is not run.
func assertStateChangingPathRejected(t *testing.T, publisher apiClient, victim *sessionClient, path string, afterFollow func(t *testing.T, followed *http.Response)) {
	t.Helper()
	status, uid, body := createShortURL(t, publisher, path)
	if status < 200 || status >= 300 {
		require.GreaterOrEqual(t, status, 400, "body: %s", body)
		require.Less(t, status, 500, "body: %s", body)
		return
	}

	location := victim.gotoLocation(t, uid)
	gotPath := locationPath(t, location)
	followed := victim.followLocation(t, location)
	defer func() { _ = followed.Body.Close() }()
	afterFollow(t, followed)
	require.Falsef(t, isStateChangingPath(gotPath), "viewer published short url %s for %q and /goto redirected to %s", uid, path, location)
	t.Fatalf("viewer published a short url for state-changing path %q", path)
}

func isStateChangingPath(p string) bool {
	switch {
	case p == "/logout":
		return true
	case strings.HasPrefix(p, "/profile/switch-org/"):
		return true
	case p == "/user/auth-tokens/rotate":
		return true
	case strings.HasPrefix(p, "/api/snapshots-delete/"):
		return true
	case p == "/user/email/update":
		return true
	case p == "/api/user/invite/complete":
		return true
	default:
		return false
	}
}

func mustCreateShortURL(t *testing.T, publisher apiClient, path string) string {
	t.Helper()
	status, uid, body := createShortURL(t, publisher, path)
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	require.NotEmpty(t, uid)
	return uid
}

func createShortURL(t *testing.T, publisher apiClient, path string) (int, string, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"path": path})
	require.NoError(t, err)
	res, err := publisher.post("/api/short-urls", bytes.NewReader(payload))
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	parsed := struct {
		UID string `json:"uid"`
	}{}
	_ = json.Unmarshal(raw, &parsed)
	return res.StatusCode, parsed.UID, string(raw)
}

func createDashboard(t *testing.T, victim *sessionClient) string {
	t.Helper()
	const uid = "shorturlsnap1"
	body := []byte(`{"dashboard":{"uid":"` + uid + `","title":"shorturl session snapshot","schemaVersion":39,"panels":[]}}`)
	res := victim.do(http.MethodPost, "/api/dashboards/db", bytes.NewReader(body), "application/json")
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, "create dashboard: %s", raw)
	return uid
}

func createSnapshot(t *testing.T, victim *sessionClient, dashboardUID string) (key, deleteKey string) {
	t.Helper()
	body := []byte(`{"name":"shorturl-session-test","expires":3600,"dashboard":{"uid":"` + dashboardUID + `","title":"shorturl session snapshot","panels":[]}}`)
	res := victim.do(http.MethodPost, "/api/snapshots/", bytes.NewReader(body), "application/json")
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, "create snapshot: %s", raw)
	parsed := struct {
		Key       string `json:"key"`
		DeleteKey string `json:"deleteKey"`
	}{}
	require.NoError(t, json.Unmarshal(raw, &parsed))
	require.NotEmpty(t, parsed.Key)
	require.NotEmpty(t, parsed.DeleteKey)
	return parsed.Key, parsed.DeleteKey
}

func locationPath(t *testing.T, location string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	return parsed.Path
}

func mustCurrentOrg(t *testing.T, c *sessionClient) int64 {
	t.Helper()
	orgID, status := c.currentOrg(t)
	require.Equal(t, http.StatusOK, status)
	return orgID
}

func mustStatus(t *testing.T, res *http.Response) int {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

type sessionClient struct {
	t       *testing.T
	addr    string
	session *http.Cookie
	http    *http.Client
}

func newSessionClient(t *testing.T, addr, login, password string) *sessionClient {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"user": login, "password": password})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/login", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{CheckRedirect: refuseRedirect}
	res, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	require.Equal(t, http.StatusOK, res.StatusCode, "login: %s", raw)

	var session *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "grafana_session" {
			copied := *c
			session = &copied
		}
	}
	require.NotNil(t, session)
	return &sessionClient{t: t, addr: addr, session: session, http: httpClient}
}

func (c *sessionClient) get(path string) *http.Response {
	return c.do(http.MethodGet, path, nil, "")
}

func (c *sessionClient) do(method, path string, body io.Reader, contentType string) *http.Response {
	c.t.Helper()
	req, err := http.NewRequest(method, "http://"+c.addr+path, body)
	require.NoError(c.t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// Send the cookie captured at login. A later Set-Cookie that clears it must
	// not hide whether the server still accepts this session.
	if c.session != nil {
		req.AddCookie(c.session)
	}
	res, err := c.http.Do(req)
	require.NoError(c.t, err)
	return res
}

func (c *sessionClient) currentOrg(t *testing.T) (int64, int) {
	t.Helper()
	res := c.get("/api/user")
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	if res.StatusCode != http.StatusOK {
		return 0, res.StatusCode
	}
	parsed := struct {
		OrgID int64 `json:"orgId"`
	}{}
	require.NoError(t, json.Unmarshal(raw, &parsed), "body: %s", raw)
	return parsed.OrgID, res.StatusCode
}

func (c *sessionClient) gotoLocation(t *testing.T, uid string) string {
	t.Helper()
	res := c.get("/goto/" + uid)
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	require.Equalf(t, http.StatusFound, res.StatusCode, "GET /goto/%s location=%q body=%s", uid, res.Header.Get("Location"), raw)
	location := res.Header.Get("Location")
	require.NotEmpty(t, location)
	return location
}

func (c *sessionClient) followLocation(t *testing.T, location string) *http.Response {
	t.Helper()
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	// root_url in the test process is the default host, which is not the
	// ephemeral listener. Request the path the redirect named, on this server.
	target := parsed.RequestURI()
	if target == "" {
		target = parsed.Path
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return c.get(target)
}

func refuseRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}
