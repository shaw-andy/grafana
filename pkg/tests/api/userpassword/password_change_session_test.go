package userpassword

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

// Placeholders stand in for password values. They are not credentials.
const (
	placeholderCurrent  = "placeholder-current"
	placeholderUpdated  = "placeholder-updated"
	placeholderRejected = "placeholder-rejected"
)

// TestIntegrationPasswordChangeRevokesExistingSessions follows a signed-in
// password change and then repeats a request with a session cookie that was
// issued before the change. The stolen cookie must be rejected once the
// password has been stored. A refused change must leave that cookie valid.
func TestIntegrationPasswordChangeRevokesExistingSessions(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	grafDir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableAnonymous: true,
	})
	addr, env := testinfra.StartGrafanaEnv(t, grafDir, cfgPath)
	cookieName := env.Cfg.LoginCookieName
	require.NotEmpty(t, cookieName)

	owner := testinfra.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		Login:    "session-owner",
		Email:    "session-owner@example.com",
		Password: placeholderCurrent,
	})
	other := testinfra.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		Login:    "session-other",
		Email:    "session-other@example.com",
		Password: placeholderCurrent,
	})

	ownerSession := loginSession(t, addr, cookieName, owner.Login, placeholderCurrent)
	stolenSession := loginSession(t, addr, cookieName, owner.Login, placeholderCurrent)
	secondStolenSession := loginSession(t, addr, cookieName, owner.Login, placeholderCurrent)
	otherSession := loginSession(t, addr, cookieName, other.Login, placeholderCurrent)

	requireSignedInAs(t, addr, ownerSession, owner.Login)
	requireSignedInAs(t, addr, stolenSession, owner.Login)
	requireSignedInAs(t, addr, secondStolenSession, owner.Login)
	requireSignedInAs(t, addr, otherSession, other.Login)

	t.Run("rejected change leaves sessions signed in", func(t *testing.T) {
		status, body := changePassword(t, addr, ownerSession, placeholderRejected, placeholderUpdated)
		require.Equal(t, http.StatusBadRequest, status, body)

		requireSignedInAs(t, addr, ownerSession, owner.Login)
		requireSignedInAs(t, addr, stolenSession, owner.Login)
		requireSignedInAs(t, addr, secondStolenSession, owner.Login)
		requireSignedInAs(t, addr, otherSession, other.Login)
	})

	t.Run("stored password revokes the user's other sessions", func(t *testing.T) {
		status, body := changePassword(t, addr, ownerSession, placeholderCurrent, placeholderUpdated)
		require.Equal(t, http.StatusOK, status, body)

		// Logging in with the updated password shows the hash was stored before
		// the session check. A cookie that still works is a session that survived
		// the write.
		updatedSession := loginSession(t, addr, cookieName, owner.Login, placeholderUpdated)
		requireSignedInAs(t, addr, updatedSession, owner.Login)
		refusedStatus, refusedBody, _ := postLogin(t, addr, cookieName, owner.Login, placeholderCurrent)
		require.NotEqual(t, http.StatusOK, refusedStatus, refusedBody)

		requireSessionRejected(t, addr, stolenSession)
		requireSessionRejected(t, addr, secondStolenSession)
		requireSignedInAs(t, addr, otherSession, other.Login)
	})
}

func loginSession(t *testing.T, addr, cookieName, login, password string) *http.Cookie {
	t.Helper()

	status, body, cookie := postLogin(t, addr, cookieName, login, password)
	require.Equal(t, http.StatusOK, status, body)
	require.NotNil(t, cookie, "login response did not set %s", cookieName)
	return cookie
}

func postLogin(t *testing.T, addr, cookieName, login, password string) (int, string, *http.Cookie) {
	t.Helper()

	payload, err := json.Marshal(map[string]string{
		"user":     login,
		"password": password,
	})
	require.NoError(t, err)

	status, body, resp := doRequest(t, http.MethodPost, "http://"+addr+"/login", payload, nil)
	return status, body, cookieNamed(resp, cookieName)
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func changePassword(t *testing.T, addr string, session *http.Cookie, oldPassword, newPassword string) (int, string) {
	t.Helper()

	payload, err := json.Marshal(map[string]string{
		"oldPassword": oldPassword,
		"newPassword": newPassword,
	})
	require.NoError(t, err)

	status, body, _ := doRequest(t, http.MethodPut, "http://"+addr+"/api/user/password", payload, session)
	return status, body
}

func requireSignedInAs(t *testing.T, addr string, session *http.Cookie, login string) {
	t.Helper()

	status, body, _ := doRequest(t, http.MethodGet, "http://"+addr+"/api/user", nil, session)
	require.Equal(t, http.StatusOK, status, body)

	var profile struct {
		Login string `json:"login"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &profile), body)
	require.Equal(t, login, profile.Login, body)
}

func requireSessionRejected(t *testing.T, addr string, session *http.Cookie) {
	t.Helper()

	status, body, _ := doRequest(t, http.MethodGet, "http://"+addr+"/api/user", nil, session)
	require.Equalf(t, http.StatusUnauthorized, status,
		"session issued before the password change is still accepted: %s", body)
}

func doRequest(t *testing.T, method, url string, payload []byte, session *http.Cookie) (int, string, *http.Response) {
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
