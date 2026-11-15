package oauthredirect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/server"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

const (
	oauthClientID                = "test-oauth-client"
	oauthClientSecretPlaceholder = "oauth-client-secret-placeholder"
	oauthAuthCode                = "test-auth-code"
	victimEmail                  = "victim@example.com"
)

// TestIntegrationOAuthPostLoginRedirectDoesNotAct drives the OAuth login the
// product serves: a redirectTo on the login start URL is stored and, after the
// identity provider accepts the user, the callback sends the browser to that
// path with the new session cookie. Logout and organization switching are GET
// routes, so that redirect must not sign the user out or change the active
// organization.
func TestIntegrationOAuthPostLoginRedirectDoesNotAct(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	var grafanaBase string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			if grafanaBase == "" {
				http.Error(w, "grafana address is not ready", http.StatusInternalServerError)
				return
			}
			state := r.URL.Query().Get("state")
			if state == "" {
				http.Error(w, "authorize request missing state", http.StatusBadRequest)
				return
			}
			callback := grafanaBase + "/login/generic_oauth?code=" + url.QueryEscape(oauthAuthCode) + "&state=" + url.QueryEscape(state)
			http.Redirect(w, r, callback, http.StatusFound)
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != oauthAuthCode {
				http.Error(w, "unexpected token request", http.StatusBadRequest)
				return
			}
			if r.Form.Get("client_id") != oauthClientID || r.Form.Get("client_secret") != oauthClientSecretPlaceholder {
				http.Error(w, "unexpected client authentication", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"idp-access-token","token_type":"Bearer"}`)
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer idp-access-token" {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"sub":"victim-subject","email":"`+victimEmail+`","login":"victim","name":"Victim"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	dir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{DisableAnonymous: true})
	configureGenericOAuth(t, cfgPath, idp.URL)

	grafanaAddr, env := testinfra.StartGrafanaEnv(t, dir, cfgPath)
	grafanaBase = "http://" + grafanaAddr
	require.True(t, env.FeatureToggles.IsEnabledGlobally(featuremgmt.FlagUseSessionStorageForRedirection),
		"session-storage redirect is the default path this test exercises")

	setupClient, setupHops := finishOAuthLogin(t, grafanaBase, "/")
	requireCallback(t, setupHops)
	setupProfile := signedInProfile(t, setupClient, grafanaBase)
	require.Equal(t, victimEmail, setupProfile.Email)
	originalOrgID := activeOrgID(t, env.SQLStore, setupProfile.ID)
	require.NotZero(t, originalOrgID)

	otherOrgID := createOrgForUser(t, env, setupProfile.ID)
	require.NotEqual(t, originalOrgID, otherOrgID)

	t.Run("logout redirect keeps the new session", func(t *testing.T) {
		sessionsBefore := sessionCount(t, env.SQLStore, setupProfile.ID)
		client, hops := finishOAuthLogin(t, grafanaBase, "/logout")
		requireCallback(t, hops)

		status, body := getPath(t, client, grafanaBase+"/api/user")
		sessionsAfter := sessionCount(t, env.SQLStore, setupProfile.ID)
		require.Equalf(t, http.StatusOK, status,
			"session created by this login must still authenticate after redirectTo=/logout; body: %s; hops: %s",
			strings.TrimSpace(string(body)), strings.Join(hops, " -> "))
		require.Equal(t, sessionsBefore+1, sessionsAfter,
			"the session row created by this login must still exist; hops: %s", strings.Join(hops, " -> "))

		var profile user.UserProfileDTO
		require.NoError(t, json.Unmarshal(body, &profile))
		require.Equal(t, setupProfile.ID, profile.ID)
	})

	t.Run("organization switch redirect keeps the active organization", func(t *testing.T) {
		redirectTo := "/profile/switch-org/" + fmt.Sprint(otherOrgID)
		client, hops := finishOAuthLogin(t, grafanaBase, redirectTo)
		requireCallback(t, hops)

		require.Equal(t, originalOrgID, activeOrgID(t, env.SQLStore, setupProfile.ID),
			"active organization must stay %d after redirectTo=%s; hops: %s",
			originalOrgID, redirectTo, strings.Join(hops, " -> "))

		status, body := getPath(t, client, grafanaBase+"/api/user")
		require.Equalf(t, http.StatusOK, status, "body: %s; hops: %s", strings.TrimSpace(string(body)), strings.Join(hops, " -> "))
		var profile user.UserProfileDTO
		require.NoError(t, json.Unmarshal(body, &profile))
		require.Equal(t, originalOrgID, profile.OrgID,
			"signed-in profile must still report the organization from before this login")
	})
}

func configureGenericOAuth(t *testing.T, cfgPath, idpURL string) {
	t.Helper()
	cfg, err := ini.Load(cfgPath)
	require.NoError(t, err)
	section, err := cfg.NewSection("auth.generic_oauth")
	require.NoError(t, err)
	values := map[string]string{
		"enabled":       "true",
		"allow_sign_up": "true",
		"client_id":     oauthClientID,
		"client_secret": oauthClientSecretPlaceholder,
		"scopes":        "openid email profile",
		"auth_url":      idpURL + "/authorize",
		"token_url":     idpURL + "/token",
		"api_url":       idpURL + "/userinfo",
		"auth_style":    "inparams",
		"use_pkce":      "false",
	}
	for key, value := range values {
		_, err := section.NewKey(key, value)
		require.NoError(t, err)
	}
	require.NoError(t, cfg.SaveTo(cfgPath))
}

func finishOAuthLogin(t *testing.T, grafanaBase, redirectTo string) (*http.Client, []string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	var hops []string
	client := &http.Client{Jar: jar}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		hops = append(hops, req.URL.String())
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	start := grafanaBase + "/login/generic_oauth?redirectTo=" + url.QueryEscape(redirectTo)
	resp, err := client.Get(start) // nolint:gosec // test server started by this test
	require.NoError(t, err)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Less(t, resp.StatusCode, 400, "oauth login finished with %d at %s: %s; hops: %s",
		resp.StatusCode, resp.Request.URL.String(), strings.TrimSpace(string(body)), strings.Join(hops, " -> "))
	return client, hops
}

func requireCallback(t *testing.T, hops []string) {
	t.Helper()
	for _, hop := range hops {
		parsed, err := url.Parse(hop)
		require.NoError(t, err)
		if strings.HasSuffix(parsed.Path, "/login/generic_oauth") && parsed.Query().Get("code") == oauthAuthCode {
			return
		}
	}
	t.Fatalf("identity provider callback was not requested; hops: %s", strings.Join(hops, " -> "))
}

func signedInProfile(t *testing.T, client *http.Client, grafanaBase string) user.UserProfileDTO {
	t.Helper()
	status, body := getPath(t, client, grafanaBase+"/api/user")
	require.Equal(t, http.StatusOK, status, "signed-in user profile: %s", strings.TrimSpace(string(body)))
	var profile user.UserProfileDTO
	require.NoError(t, json.Unmarshal(body, &profile))
	return profile
}

func getPath(t *testing.T, client *http.Client, target string) (int, []byte) {
	t.Helper()
	resp, err := client.Get(target) // nolint:gosec // test server started by this test
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func activeOrgID(t *testing.T, store db.DB, userID int64) int64 {
	t.Helper()
	var got user.User
	err := store.WithDbSession(context.Background(), func(sess *db.Session) error {
		has, err := sess.ID(userID).Get(&got)
		if err != nil {
			return err
		}
		if !has {
			return fmt.Errorf("user %d not found", userID)
		}
		return nil
	})
	require.NoError(t, err)
	return got.OrgID
}

func sessionCount(t *testing.T, store db.DB, userID int64) int64 {
	t.Helper()
	var count int64
	err := store.WithDbSession(context.Background(), func(sess *db.Session) error {
		var err error
		count, err = sess.Table("user_auth_token").Where("user_id = ?", userID).Count()
		return err
	})
	require.NoError(t, err)
	return count
}

func createOrgForUser(t *testing.T, env *server.TestEnv, userID int64) int64 {
	t.Helper()
	cfgProvider, err := configprovider.ProvideService(env.Cfg)
	require.NoError(t, err)
	quotaService := quotaimpl.ProvideService(context.Background(), legacysql.NewDatabaseProvider(env.SQLStore), cfgProvider)
	orgService, err := orgimpl.ProvideService(legacysql.NewDatabaseProvider(env.SQLStore), env.Cfg, quotaService)
	require.NoError(t, err)
	created, err := orgService.CreateWithMember(context.Background(), &org.CreateOrgCommand{
		Name:   "other-org",
		UserID: userID,
	})
	require.NoError(t, err)
	return created.ID
}
