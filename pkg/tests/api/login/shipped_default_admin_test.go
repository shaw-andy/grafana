package login

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

// placeholderControlPassword is not a shipped secret. It is only used to show
// that an account with some other password can still sign in.
const placeholderControlPassword = "placeholder-control-password"

// placeholderUnusedPassword is sent in request bodies that must be refused
// before any user or datasource row is written.
const placeholderUnusedPassword = "placeholder-must-not-be-created"

type shippedAdminSettings struct {
	user     string
	password string
	email    string
	disabled bool
}

// TestIntegrationShippedDefaultAdminCannotAct is the spec for first boot with
// the security.admin_user, security.admin_password, security.admin_email, and
// security.disable_initial_admin_creation values in conf/defaults.ini.
//
// Those credentials must not obtain a usable session, and HTTP basic auth with
// the same credentials must not be able to call any other API. A fix may still
// allow a password change; this test does not call that endpoint.
//
// Auth proxy, API keys, grafana-cli, and an enabled external LDAP directory are
// not part of this scenario. The form and basic clients both go through the
// in-process password chain, which is what these requests hit.
func TestIntegrationShippedDefaultAdminCannotAct(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	clearShippedAdminEnv(t)

	grafDir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableAnonymous: true,
	})
	addr, env := testinfra.StartGrafanaEnv(t, grafDir, cfgPath)
	shipped := readShippedAdminSettings(t, grafDir)
	if shipped.user == "" || shipped.password == "" || shipped.email == "" || shipped.disabled {
		t.Fatal("conf/defaults.ini security admin settings are not the first-boot configuration this test targets")
	}
	if env.Cfg.AdminUser != shipped.user || env.Cfg.AdminPassword != shipped.password || env.Cfg.AdminEmail != shipped.email || env.Cfg.DisableInitAdminCreation {
		t.Fatal("running security admin settings do not match conf/defaults.ini")
	}
	if placeholderControlPassword == shipped.password || placeholderUnusedPassword == shipped.password {
		t.Fatal("placeholder password collides with security.admin_password in conf/defaults.ini")
	}

	present, isAdmin := lookupLogin(t, env.SQLStore, shipped.user)
	t.Logf("first boot account present=%v is_admin=%v", present, isAdmin)

	const dataSourceUID = "shipped-default-admin-testdata"
	_, err := env.Server.HTTPServer.DataSourcesService.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		OrgID:  1,
		Access: datasources.DS_ACCESS_PROXY,
		Name:   dataSourceUID,
		Type:   datasources.DS_TESTDATA,
		UID:    dataSourceUID,
	})
	require.NoError(t, err)

	httpClient := &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	api := &grafanaAPI{addr: addr, client: httpClient, cookieName: env.Cfg.LoginCookieName, store: env.SQLStore}

	tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		Login:          "control-user",
		Email:          "control-user@example.com",
		Password:       placeholderControlPassword,
		DefaultOrgRole: string(org.RoleAdmin),
	})
	observer := api.withT(t)
	controlStatus, controlCookie := observer.login("control-user", placeholderControlPassword)
	require.GreaterOrEqual(t, controlStatus, 200)
	require.Less(t, controlStatus, 300)
	require.NotNil(t, controlCookie)
	api.observer = controlCookie

	t.Run("other password still signs in and can query", func(t *testing.T) {
		sub := api.withT(t)
		status, cookie := sub.login("control-user", placeholderControlPassword)
		require.GreaterOrEqual(t, status, 200)
		require.Less(t, status, 300)
		require.NotNil(t, cookie)

		status = sub.call(actor{name: "control", cookie: cookie}, http.MethodGet, "/api/user", nil)
		require.GreaterOrEqual(t, status, 200)
		require.Less(t, status, 300)

		status = sub.call(actor{name: "control", cookie: cookie}, http.MethodPost, "/api/ds/query", queryBody(t, dataSourceUID))
		require.GreaterOrEqual(t, status, 200, "testdata query used as the control did not succeed")
		require.Less(t, status, 300)
	})

	t.Run("form login as security.admin_user", func(t *testing.T) {
		sub := api.withT(t)
		sub.assertFormLoginCannotAct("form-user", shipped.user, shipped.password, dataSourceUID)
	})
	t.Run("form login as security.admin_email", func(t *testing.T) {
		sub := api.withT(t)
		sub.assertFormLoginCannotAct("form-email", shipped.email, shipped.password, dataSourceUID)
	})
	t.Run("basic auth as security.admin_user", func(t *testing.T) {
		sub := api.withT(t)
		sub.assertBasicAuthCannotAct("basic-user", shipped.user, shipped.password, dataSourceUID)
	})
	t.Run("basic auth as security.admin_email", func(t *testing.T) {
		sub := api.withT(t)
		sub.assertBasicAuthCannotAct("basic-email", shipped.email, shipped.password, dataSourceUID)
	})
}

func (g grafanaAPI) withT(t *testing.T) grafanaAPI {
	g.t = t
	return g
}

func clearShippedAdminEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"GF_SECURITY_ADMIN_USER",
		"GF_SECURITY_ADMIN_PASSWORD",
		"GF_SECURITY_ADMIN_EMAIL",
		"GF_SECURITY_DISABLE_INITIAL_ADMIN_CREATION",
	} {
		t.Setenv(key, "")
	}
}

func readShippedAdminSettings(t *testing.T, grafDir string) shippedAdminSettings {
	t.Helper()
	file, err := ini.Load(filepath.Join(grafDir, "conf", "defaults.ini"))
	require.NoError(t, err)
	section := file.Section("security")
	return shippedAdminSettings{
		user:     section.Key("admin_user").String(),
		password: section.Key("admin_password").String(),
		email:    section.Key("admin_email").String(),
		disabled: section.Key("disable_initial_admin_creation").MustBool(false),
	}
}

func lookupLogin(t *testing.T, store db.DB, loginName string) (bool, bool) {
	t.Helper()
	var row struct {
		IsAdmin bool `xorm:"is_admin"`
	}
	var found bool
	err := store.WithDbSession(context.Background(), func(sess *db.Session) error {
		var err error
		found, err = sess.SQL(
			"SELECT is_admin FROM "+store.GetDialect().Quote("user")+" WHERE login = ?",
			strings.ToLower(loginName),
		).Get(&row)
		return err
	})
	require.NoError(t, err)
	return found, row.IsAdmin
}

func countRows(t *testing.T, store db.DB, table string) int64 {
	t.Helper()
	var n int64
	err := store.WithDbSession(context.Background(), func(sess *db.Session) error {
		var err error
		n, err = sess.Table(table).Count()
		return err
	})
	require.NoError(t, err)
	return n
}

type actor struct {
	name   string
	cookie *http.Cookie
	user   string
	pass   string
	basic  bool
}

type grafanaAPI struct {
	t          *testing.T
	addr       string
	client     *http.Client
	cookieName string
	store      db.DB
	// observer is a session that does not use the shipped admin settings.
	// It counts dashboard search hits so a write that lands before a refusal
	// is still a failure. Dashboards are stored through the resource API, not
	// only the legacy dashboard table.
	observer *http.Cookie
}

func (g *grafanaAPI) assertFormLoginCannotAct(name, username, password, dataSourceUID string) {
	g.t.Helper()
	tokensBefore := countRows(g.t, g.store, "user_auth_token")
	status, cookie := g.login(username, password)
	if status < 200 || status >= 300 {
		if cookie != nil {
			g.t.Errorf("%s: refused login still set %s, status %d", name, g.cookieName, status)
		}
		tokensAfter := countRows(g.t, g.store, "user_auth_token")
		if tokensAfter != tokensBefore {
			g.t.Errorf("%s: refused login wrote user_auth_token rows (%d -> %d), status %d", name, tokensBefore, tokensAfter, status)
		}
		return
	}
	if cookie == nil {
		g.t.Errorf("%s: login returned status %d without %s", name, status, g.cookieName)
	}
	g.assertActorCannotAct(actor{name: name, cookie: cookie}, dataSourceUID)
}

func (g *grafanaAPI) assertBasicAuthCannotAct(name, username, password, dataSourceUID string) {
	g.t.Helper()
	g.assertActorCannotAct(actor{name: name, user: username, pass: password, basic: true}, dataSourceUID)
}

func (g *grafanaAPI) assertActorCannotAct(who actor, dataSourceUID string) {
	g.t.Helper()
	reads := []string{
		"/api/user",
		"/api/login/ping",
		"/api/datasources",
		"/api/datasources/uid/" + dataSourceUID,
		"/api/search/?limit=1",
		"/api/org",
		"/api/org/users",
		"/api/users",
		"/api/admin/stats",
		"/api/admin/settings",
	}
	for _, path := range reads {
		status := g.call(who, http.MethodGet, path, nil)
		if path == "/api/user" && status >= 200 && status < 300 {
			g.t.Errorf("%s: GET /api/user succeeded with status %d isGrafanaAdmin=%v", who.name, status, g.isGrafanaAdmin(who))
			continue
		}
		if status >= 200 && status < 300 {
			g.t.Errorf("%s: GET %s succeeded with status %d", who.name, path, status)
		}
	}

	g.assertWriteRefused(who, http.MethodPost, "/api/dashboards/db", dashboardBody(who.name), "dashboard", "resource", "resource_history")
	g.assertWriteRefused(who, http.MethodPost, "/api/datasources", datasourceBody(who.name), "data_source")
	g.assertWriteRefused(who, http.MethodPost, "/api/admin/users", userBody(tName(who.name)), "user")

	status := g.call(who, http.MethodPost, "/api/ds/query", queryBody(g.t, dataSourceUID))
	if status >= 200 && status < 300 {
		g.t.Errorf("%s: POST /api/ds/query succeeded with status %d", who.name, status)
	}
}

func (g *grafanaAPI) assertWriteRefused(who actor, method, path string, body []byte, tables ...string) {
	g.t.Helper()
	before := make(map[string]int64, len(tables))
	for _, table := range tables {
		before[table] = countRows(g.t, g.store, table)
	}
	hitsBefore := g.searchHits()
	status := g.call(who, method, path, body)
	if status >= 200 && status < 300 {
		g.t.Errorf("%s: %s %s succeeded with status %d", who.name, method, path, status)
	}
	for _, table := range tables {
		after := countRows(g.t, g.store, table)
		if after != before[table] {
			g.t.Errorf("%s: %s %s changed %s rows from %d to %d with status %d", who.name, method, path, table, before[table], after, status)
		}
	}
	hitsAfter := g.searchHits()
	if path == "/api/dashboards/db" && hitsAfter != hitsBefore {
		g.t.Errorf("%s: %s %s changed dashboard search hits from %d to %d with status %d", who.name, method, path, hitsBefore, hitsAfter, status)
	}
}

func (g *grafanaAPI) searchHits() int {
	g.t.Helper()
	if g.observer == nil {
		g.t.Fatal("dashboard search observer was not signed in")
	}
	status, body := g.callBody(actor{name: "observer", cookie: g.observer}, http.MethodGet, "/api/search/?limit=5000&type=dash-db", nil)
	if status < 200 || status >= 300 {
		g.t.Fatalf("observer search failed with status %d", status)
	}
	var hits []json.RawMessage
	require.NoError(g.t, json.Unmarshal(body, &hits))
	return len(hits)
}

func (g *grafanaAPI) isGrafanaAdmin(who actor) bool {
	g.t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+g.addr+"/api/user", nil)
	require.NoError(g.t, err)
	g.authorize(req, who)
	resp, err := g.client.Do(req)
	require.NoError(g.t, err)
	defer func() {
		require.NoError(g.t, resp.Body.Close())
	}()
	var profile struct {
		IsGrafanaAdmin bool `json:"isGrafanaAdmin"`
	}
	require.NoError(g.t, json.NewDecoder(resp.Body).Decode(&profile))
	return profile.IsGrafanaAdmin
}

func (g *grafanaAPI) login(username, password string) (int, *http.Cookie) {
	g.t.Helper()
	payload, err := json.Marshal(struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}{User: username, Password: password}) // #nosec G117 -- test login request marshal
	require.NoError(g.t, err)

	req, err := http.NewRequest(http.MethodPost, "http://"+g.addr+"/login", bytes.NewReader(payload))
	require.NoError(g.t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	require.NoError(g.t, err)
	defer func() {
		require.NoError(g.t, resp.Body.Close())
	}()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(g.t, err)

	var session *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == g.cookieName {
			session = cookie
		}
	}
	return resp.StatusCode, session
}

func (g *grafanaAPI) call(who actor, method, path string, body []byte) int {
	g.t.Helper()
	status, _ := g.callBody(who, method, path, body)
	return status
}

func (g *grafanaAPI) callBody(who actor, method, path string, body []byte) (int, []byte) {
	g.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://"+g.addr+path, reader)
	require.NoError(g.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	g.authorize(req, who)

	resp, err := g.client.Do(req)
	require.NoError(g.t, err)
	defer func() {
		require.NoError(g.t, resp.Body.Close())
	}()
	payload, err := io.ReadAll(resp.Body)
	require.NoError(g.t, err)
	return resp.StatusCode, payload
}

func (g *grafanaAPI) authorize(req *http.Request, who actor) {
	if who.cookie != nil {
		req.AddCookie(who.cookie)
	}
	if who.basic {
		req.SetBasicAuth(who.user, who.pass)
	}
}

func dashboardBody(name string) []byte {
	body, err := json.Marshal(map[string]any{
		"overwrite": false,
		"dashboard": map[string]any{
			"title": "must-not-be-saved-" + name,
		},
	})
	if err != nil {
		panic(err)
	}
	return body
}

func datasourceBody(name string) []byte {
	body, err := json.Marshal(map[string]any{
		"name":   "must-not-be-created-" + name,
		"type":   datasources.DS_TESTDATA,
		"access": string(datasources.DS_ACCESS_PROXY),
	})
	if err != nil {
		panic(err)
	}
	return body
}

func userBody(name string) []byte {
	body, err := json.Marshal(map[string]any{
		"login":    "must-not-be-created-" + name,
		"email":    "must-not-be-created-" + name + "@example.com",
		"password": placeholderUnusedPassword,
	})
	if err != nil {
		panic(err)
	}
	return body
}

func tName(name string) string {
	return strings.ReplaceAll(name, " ", "-")
}

func queryBody(t *testing.T, dataSourceUID string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"from": "now-1h",
		"to":   "now",
		"queries": []map[string]any{{
			"refId":      "A",
			"scenarioId": "random_walk",
			"datasource": map[string]any{
				"type": datasources.DS_TESTDATA,
				"uid":  dataSourceUID,
			},
		}},
	})
	require.NoError(t, err)
	return body
}
