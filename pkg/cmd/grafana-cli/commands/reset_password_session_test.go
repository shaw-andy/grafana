package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/server"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

// Placeholders stand in for password values. They are not credentials.
const (
	placeholderCLICurrent = "placeholder-current"
	placeholderCLIUpdated = "placeholder-cli"
)

// TestIntegrationResetPasswordRevokesExistingSessions runs grafana-cli's admin
// password reset and then repeats a signed-in request with a session cookie
// issued before the reset. That cookie must be rejected once the new password
// is stored.
func TestIntegrationResetPasswordRevokesExistingSessions(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	grafDir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableAnonymous: true,
	})
	addr, env := testinfra.StartGrafanaEnv(t, grafDir, cfgPath)
	cookieName := env.Cfg.LoginCookieName
	require.NotEmpty(t, cookieName)

	admin := testinfra.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		Login:    "cli-session-admin",
		Email:    "cli-session-admin@example.com",
		Password: placeholderCLICurrent,
		IsAdmin:  true,
	})
	other := testinfra.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		Login:    "cli-session-other",
		Email:    "cli-session-other@example.com",
		Password: placeholderCLICurrent,
	})

	adminSession := cliLoginSession(t, addr, cookieName, admin.Login, placeholderCLICurrent)
	stolenAdminSession := cliLoginSession(t, addr, cookieName, admin.Login, placeholderCLICurrent)
	otherSession := cliLoginSession(t, addr, cookieName, other.Login, placeholderCLICurrent)
	cliRequireSignedInAs(t, addr, adminSession, admin.Login)
	cliRequireSignedInAs(t, addr, stolenAdminSession, admin.Login)
	cliRequireSignedInAs(t, addr, otherSession, other.Login)

	svc := cliUserService(t, env)
	err := resetPassword(admin.ID, placeholderCLIUpdated, svc)
	require.NoError(t, err)

	updatedSession := cliLoginSession(t, addr, cookieName, admin.Login, placeholderCLIUpdated)
	cliRequireSignedInAs(t, addr, updatedSession, admin.Login)
	refusedStatus, refusedBody, _ := cliPostLogin(t, addr, cookieName, admin.Login, placeholderCLICurrent)
	require.NotEqual(t, http.StatusOK, refusedStatus, refusedBody)

	cliRequireSessionRejected(t, addr, adminSession)
	cliRequireSessionRejected(t, addr, stolenAdminSession)
	cliRequireSignedInAs(t, addr, otherSession, other.Login)
}

func cliUserService(t *testing.T, env *server.TestEnv) user.Service {
	t.Helper()

	store := env.SQLStore
	cfg := env.Cfg
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	quotaService := quotaimpl.ProvideService(context.Background(), legacysql.NewDatabaseProvider(store), cfgProvider)
	orgService, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(store), cfg, quotaService)
	require.NoError(t, err)
	svc, err := userimpl.ProvideService(
		legacysql.NewDatabaseProvider(store),
		orgService,
		cfg,
		nil,
		nil,
		tracing.InitializeTracerForTest(),
		quotaService,
		supportbundlestest.NewFakeBundleService(),
		nil,
	)
	require.NoError(t, err)
	return svc
}

func cliLoginSession(t *testing.T, addr, cookieName, login, password string) *http.Cookie {
	t.Helper()

	status, body, cookie := cliPostLogin(t, addr, cookieName, login, password)
	require.Equal(t, http.StatusOK, status, body)
	require.NotNil(t, cookie, "login response did not set %s", cookieName)
	return cookie
}

func cliPostLogin(t *testing.T, addr, cookieName, login, password string) (int, string, *http.Cookie) {
	t.Helper()

	payload, err := json.Marshal(map[string]string{
		"user":     login,
		"password": password,
	})
	require.NoError(t, err)

	status, body, resp := cliDoRequest(t, http.MethodPost, "http://"+addr+"/login", payload, nil)
	return status, body, cliCookieNamed(resp, cookieName)
}

func cliCookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func cliRequireSignedInAs(t *testing.T, addr string, session *http.Cookie, login string) {
	t.Helper()

	status, body, _ := cliDoRequest(t, http.MethodGet, "http://"+addr+"/api/user", nil, session)
	require.Equal(t, http.StatusOK, status, body)

	var profile struct {
		Login string `json:"login"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &profile), body)
	require.Equal(t, login, profile.Login, body)
}

func cliRequireSessionRejected(t *testing.T, addr string, session *http.Cookie) {
	t.Helper()

	status, body, _ := cliDoRequest(t, http.MethodGet, "http://"+addr+"/api/user", nil, session)
	require.Equalf(t, http.StatusUnauthorized, status,
		"session issued before the password reset is still accepted: %s", body)
}

func cliDoRequest(t *testing.T, method, url string, payload []byte, session *http.Cookie) (int, string, *http.Response) {
	t.Helper()

	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if session != nil {
		req.AddCookie(session)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(responseBody), resp
}
