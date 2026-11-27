package ssosettingsimpl

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/db/dbtest"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/socialimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	ldapsvc "github.com/grafana/grafana/pkg/services/ldap/service"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	"github.com/grafana/grafana/pkg/services/login"
	secretsFakes "github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/ssosettings"
	"github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// These tests are the spec for stored-secret reuse when an SSO endpoint changes.
// They fail while a settings write can keep the stored secret and a later login
// presents it to the replacement endpoint. They pass when that write is refused
// or the stored secret is no longer the one presented.

const (
	storedOAuthSecret   = "placeholder-stored-client-secret"
	rotatedOAuthSecret  = "placeholder-rotated-client-secret"
	storedBindPasswordA = "placeholder-bind-password-a"
	storedBindPasswordB = "placeholder-bind-password-b"
	placeholderClientID = "placeholder-client-id"
	placeholderBindDN   = "cn=placeholder-bind,dc=example,dc=org"
)

func TestOAuthPatchReusesStoredClientSecretAtReplacementTokenURL(t *testing.T) {
	env := newSecretReuseEnv(t)
	env.seedOAuth(t, social.GenericOAuthProviderName, map[string]any{
		"enabled":       true,
		"client_id":     placeholderClientID,
		"client_secret": storedOAuthSecret,
		"auth_url":      env.legitimate.URL + "/auth",
		"token_url":     env.legitimate.URL + "/token",
	})

	status := env.patchSettings(t, social.GenericOAuthProviderName, map[string]any{
		"auth_url":  env.attacker.URL + "/auth",
		"token_url": env.attacker.URL + "/token",
	})
	env.finishOAuthLogin(t, social.GenericOAuthProviderName)
	env.requireStoredSecretNotPresented(t, status, storedOAuthSecret)
}

func TestOAuthPutRedactedSecretReusesStoredClientSecretAtReplacementTokenURL(t *testing.T) {
	env := newSecretReuseEnv(t)
	env.seedOAuth(t, social.GenericOAuthProviderName, map[string]any{
		"enabled":       true,
		"client_id":     placeholderClientID,
		"client_secret": storedOAuthSecret,
		"auth_url":      env.legitimate.URL + "/auth",
		"token_url":     env.legitimate.URL + "/token",
	})

	body := env.getProviderJSON(t, social.GenericOAuthProviderName)
	require.NotContains(t, string(body), storedOAuthSecret)
	settings := settingsObject(t, body)
	settings["tokenUrl"] = env.attacker.URL + "/token"
	settings["authUrl"] = env.attacker.URL + "/auth"
	status := env.putProvider(t, social.GenericOAuthProviderName, settings)
	env.finishOAuthLogin(t, social.GenericOAuthProviderName)
	env.requireStoredSecretNotPresented(t, status, storedOAuthSecret)
}

func TestOAuthPutClientSecretPostReusesStoredSecretInFormBody(t *testing.T) {
	env := newSecretReuseEnv(t)
	env.seedOAuth(t, social.GenericOAuthProviderName, map[string]any{
		"enabled":               true,
		"client_id":             placeholderClientID,
		"client_secret":         storedOAuthSecret,
		"client_authentication": social.ClientSecretPost,
		"auth_style":            "inparams",
		"auth_url":              env.legitimate.URL + "/auth",
		"token_url":             env.legitimate.URL + "/token",
	})

	body := env.getProviderJSON(t, social.GenericOAuthProviderName)
	require.NotContains(t, string(body), storedOAuthSecret)
	settings := settingsObject(t, body)
	settings["tokenUrl"] = env.attacker.URL + "/token"
	status := env.putProvider(t, social.GenericOAuthProviderName, settings)
	env.finishOAuthLogin(t, social.GenericOAuthProviderName)
	env.requireStoredSecretNotPresented(t, status, storedOAuthSecret)
}

func TestOktaPatchReusesStoredClientSecretAtReplacementTokenURL(t *testing.T) {
	env := newSecretReuseEnv(t)
	env.seedOAuth(t, social.OktaProviderName, map[string]any{
		"enabled":       true,
		"client_id":     placeholderClientID,
		"client_secret": storedOAuthSecret,
		"auth_url":      env.legitimate.URL + "/auth",
		"token_url":     env.legitimate.URL + "/token",
		"api_url":       env.legitimate.URL + "/userinfo",
	})

	status := env.patchSettings(t, social.OktaProviderName, map[string]any{
		"token_url": env.attacker.URL + "/token",
	})
	env.finishOAuthLogin(t, social.OktaProviderName)
	env.requireStoredSecretNotPresented(t, status, storedOAuthSecret)
}

func TestAzureADPatchReusesStoredClientSecretAtReplacementTokenURL(t *testing.T) {
	env := newSecretReuseEnv(t)
	env.seedOAuth(t, social.AzureADProviderName, map[string]any{
		"enabled":       true,
		"client_id":     placeholderClientID,
		"client_secret": storedOAuthSecret,
		"auth_url":      env.legitimate.URL + "/auth",
		"token_url":     env.legitimate.URL + "/token",
	})

	status := env.patchSettings(t, social.AzureADProviderName, map[string]any{
		"auth_url":  env.attacker.URL + "/auth",
		"token_url": env.attacker.URL + "/token",
	})
	env.finishOAuthLogin(t, social.AzureADProviderName)
	env.requireStoredSecretNotPresented(t, status, storedOAuthSecret)
}

func TestOAuthPutWithRotatedSecretDoesNotPresentStoredSecret(t *testing.T) {
	env := newSecretReuseEnv(t)
	env.seedOAuth(t, social.GenericOAuthProviderName, map[string]any{
		"enabled":       true,
		"client_id":     placeholderClientID,
		"client_secret": storedOAuthSecret,
		"auth_url":      env.legitimate.URL + "/auth",
		"token_url":     env.legitimate.URL + "/token",
	})

	body := env.getProviderJSON(t, social.GenericOAuthProviderName)
	settings := settingsObject(t, body)
	settings["tokenUrl"] = env.attacker.URL + "/token"
	settings["authUrl"] = env.attacker.URL + "/auth"
	settings["clientSecret"] = rotatedOAuthSecret
	status := env.putProvider(t, social.GenericOAuthProviderName, settings)
	require.Less(t, status, 300)
	env.finishOAuthLogin(t, social.GenericOAuthProviderName)
	require.False(t, env.attackerSaw(storedOAuthSecret), "rotated secret must replace the stored secret at the new token endpoint")
	require.True(t, env.attackerSaw(rotatedOAuthSecret), "the secret supplied with the endpoint change must be the one presented")
}

func TestOAuthPutUnchangedEndpointStillPresentsStoredSecretToOriginalTokenURL(t *testing.T) {
	env := newSecretReuseEnv(t)
	env.seedOAuth(t, social.GenericOAuthProviderName, map[string]any{
		"enabled":       true,
		"client_id":     placeholderClientID,
		"client_secret": storedOAuthSecret,
		"auth_url":      env.legitimate.URL + "/auth",
		"token_url":     env.legitimate.URL + "/token",
	})

	body := env.getProviderJSON(t, social.GenericOAuthProviderName)
	settings := settingsObject(t, body)
	settings["name"] = "placeholder-name"
	status := env.putProvider(t, social.GenericOAuthProviderName, settings)
	require.Less(t, status, 300)
	env.finishOAuthLogin(t, social.GenericOAuthProviderName)
	require.False(t, env.attackerSaw(storedOAuthSecret))
	require.True(t, env.legitimateSaw(storedOAuthSecret), "an update that keeps the token endpoint must still present the stored secret there")
}

func TestSSOSettingsWritePermissionIsRequiredBeforeEndpointChange(t *testing.T) {
	env := newSecretReuseEnv(t)
	env.seedOAuth(t, social.GenericOAuthProviderName, map[string]any{
		"enabled":       true,
		"client_id":     placeholderClientID,
		"client_secret": storedOAuthSecret,
		"auth_url":      env.legitimate.URL + "/auth",
		"token_url":     env.legitimate.URL + "/token",
	})

	status := env.patchSettingsAs(t, social.GenericOAuthProviderName, map[string]any{
		"token_url": env.attacker.URL + "/token",
	}, env.reader(social.GenericOAuthProviderName))
	require.Equal(t, http.StatusForbidden, status)
	env.finishOAuthLogin(t, social.GenericOAuthProviderName)
	require.False(t, env.attackerSaw(storedOAuthSecret))
	require.True(t, env.legitimateSaw(storedOAuthSecret))
}

func TestLDAPPatchReusesBindPasswordAtReplacementHost(t *testing.T) {
	env := newSecretReuseEnv(t)
	ldapClient := env.seedLDAP(t, []map[string]any{
		ldapServer("127.0.0.1", 1, storedBindPasswordA),
	})
	attacker := startLDAPListener(t)

	status := env.patchSettings(t, social.LDAPProviderName, map[string]any{
		"config": map[string]any{
			"servers": []any{ldapServer(attacker.host, attacker.port, settingRedacted())},
		},
	})
	if status < 300 {
		waitForLDAPServer(t, ldapClient, attacker.host, attacker.port)
	}
	_, _ = ldapClient.Login(&login.LoginUserQuery{Username: "placeholder-user", Password: "placeholder-user-password"})
	require.Falsef(t, attacker.sawPassword(storedBindPasswordA),
		"stored bind password was presented to the replacement LDAP host (settings write status %d)", status)
}

func TestLDAPPatchReusesBindPasswordAtReplacementPort(t *testing.T) {
	env := newSecretReuseEnv(t)
	ldapClient := env.seedLDAP(t, []map[string]any{
		ldapServer("127.0.0.1", 1, storedBindPasswordA),
	})
	attacker := startLDAPListener(t)

	status := env.patchSettings(t, social.LDAPProviderName, map[string]any{
		"config": map[string]any{
			"servers": []any{ldapServer("127.0.0.1", attacker.port, settingRedacted())},
		},
	})
	if status < 300 {
		waitForLDAPServer(t, ldapClient, "127.0.0.1", attacker.port)
	}
	_, _ = ldapClient.Login(&login.LoginUserQuery{Username: "placeholder-user", Password: "placeholder-user-password"})
	require.Falsef(t, attacker.sawPassword(storedBindPasswordA),
		"stored bind password was presented to the replacement LDAP port (settings write status %d)", status)
}

func TestLDAPReorderDoesNotPresentBindPasswordToTheOtherHost(t *testing.T) {
	env := newSecretReuseEnv(t)
	first := startLDAPListener(t)
	second := startLDAPListener(t)
	ldapClient := env.seedLDAP(t, []map[string]any{
		ldapServer(first.host, first.port, storedBindPasswordA),
		ldapServer(second.host, second.port, storedBindPasswordB),
	})

	status := env.patchSettings(t, social.LDAPProviderName, map[string]any{
		"config": map[string]any{
			"servers": []any{
				ldapServer(second.host, second.port, settingRedacted()),
				ldapServer(first.host, first.port, settingRedacted()),
			},
		},
	})
	if status < 300 {
		waitForLDAPServer(t, ldapClient, second.host, second.port)
	}
	_, _ = ldapClient.Login(&login.LoginUserQuery{Username: "placeholder-user", Password: "placeholder-user-password"})
	require.False(t, second.sawPassword(storedBindPasswordA), "bind password of the first server was presented to the second host")
	require.False(t, first.sawPassword(storedBindPasswordB), "bind password of the second server was presented to the first host")
}

type secretReuseEnv struct {
	t          *testing.T
	svc        *Service
	social     *socialimpl.SocialService
	cfg        *setting.Cfg
	routes     routing.RouteRegister
	legitimate *httptest.Server
	attacker   *httptest.Server
	legitHits  *requestCapture
	attackHits *requestCapture
}

func newSecretReuseEnv(t *testing.T) *secretReuseEnv {
	t.Helper()
	legitHits := &requestCapture{}
	attackHits := &requestCapture{}
	legitimate := httptest.NewServer(legitHits)
	attacker := httptest.NewServer(attackHits)
	t.Cleanup(legitimate.Close)
	t.Cleanup(attacker.Close)

	raw, err := ini.Load([]byte(""))
	require.NoError(t, err)
	configurable := map[string]bool{}
	for _, provider := range ssosettings.AllOAuthProviders {
		configurable[provider] = true
	}
	cfg := &setting.Cfg{
		Raw:                              raw,
		AppURL:                           "http://localhost:3000/",
		SecretKey:                        "placeholder-oauth-state-key",
		SSOSettingsConfigurableProviders: configurable,
	}
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	licensing := licensingtest.NewFakeLicensing()
	licensing.On("FeatureEnabled", mock.Anything).Return(false)
	routes := routing.NewRouteRegister()
	svc := ProvideService(
		cfg,
		cfgProvider,
		legacysql.NewDatabaseProvider(&dbtest.FakeDB{}),
		acimpl.ProvideAccessControl(featuremgmt.WithFeatures()),
		routes,
		featuremgmt.WithFeatures(),
		secretsFakes.NewFakeSecretsService(),
		&usagestats.UsageStatsMock{},
		prometheus.NewRegistry(),
		&setting.OSSImpl{Cfg: cfg},
		licensing,
	)
	svc.store = newMemStore()

	socialSvc := socialimpl.ProvideService(
		context.Background(),
		cfgProvider,
		featuremgmt.WithFeatures(),
		&usagestats.UsageStatsMock{},
		supportbundlestest.NewFakeBundleService(),
		nil,
		nil,
		svc,
	)

	return &secretReuseEnv{
		t:          t,
		svc:        svc,
		social:     socialSvc,
		cfg:        cfg,
		routes:     routes,
		legitimate: legitimate,
		attacker:   attacker,
		legitHits:  legitHits,
		attackHits: attackHits,
	}
}

func (e *secretReuseEnv) seedOAuth(t *testing.T, provider string, settings map[string]any) {
	t.Helper()
	err := e.svc.Upsert(context.Background(), &models.SSOSettings{
		Provider: provider,
		Settings: settings,
	}, &user.SignedInUser{IsGrafanaAdmin: true})
	require.NoError(t, err)
}

func (e *secretReuseEnv) seedLDAP(t *testing.T, servers []map[string]any) *ldapsvc.LDAPImpl {
	t.Helper()
	client := ldapsvc.ProvideService(e.cfg, featuremgmt.WithFeatures(), e.svc)
	serverList := make([]any, 0, len(servers))
	for _, server := range servers {
		serverList = append(serverList, server)
	}
	err := e.svc.Upsert(context.Background(), &models.SSOSettings{
		Provider: social.LDAPProviderName,
		Settings: map[string]any{
			"enabled": true,
			"config": map[string]any{
				"servers": serverList,
			},
		},
	}, &user.SignedInUser{IsGrafanaAdmin: true})
	require.NoError(t, err)
	waitForLDAPServer(t, client, servers[0]["host"].(string), servers[0]["port"].(int))
	return client
}

func (e *secretReuseEnv) patchSettings(t *testing.T, provider string, settings map[string]any) int {
	t.Helper()
	return e.patchSettingsAs(t, provider, settings, e.writer(provider))
}

func (e *secretReuseEnv) patchSettingsAs(t *testing.T, provider string, settings map[string]any, usr *user.SignedInUser) int {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"settings": settings})
	require.NoError(t, err)
	return e.send(t, http.MethodPatch, "/api/v1/sso-settings/"+provider, payload, usr)
}

func (e *secretReuseEnv) putProvider(t *testing.T, provider string, settings map[string]any) int {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"provider": provider,
		"settings": settings,
	})
	require.NoError(t, err)
	return e.send(t, http.MethodPut, "/api/v1/sso-settings/"+provider, payload, e.writer(provider))
}

func (e *secretReuseEnv) getProviderJSON(t *testing.T, provider string) []byte {
	t.Helper()
	server := webtest.NewServer(t, e.routes)
	req := server.NewRequest(http.MethodGet, "/api/v1/sso-settings/"+provider, nil)
	webtest.RequestWithSignedInUser(req, e.writer(provider))
	res, err := server.SendJSON(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, string(body))
	return body
}

func (e *secretReuseEnv) send(t *testing.T, method, path string, payload []byte, usr *user.SignedInUser) int {
	t.Helper()
	server := webtest.NewServer(t, e.routes)
	req := server.NewRequest(method, path, bytes.NewReader(payload))
	webtest.RequestWithSignedInUser(req, usr)
	res, err := server.SendJSON(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	if res.StatusCode >= 500 {
		t.Logf("settings write returned %d: %s", res.StatusCode, body)
	}
	return res.StatusCode
}

func (e *secretReuseEnv) finishOAuthLogin(t *testing.T, provider string) {
	t.Helper()
	cfgProvider, err := configprovider.ProvideService(e.cfg)
	require.NoError(t, err)
	client := clients.ProvideOAuth(
		authn.ClientWithPrefix(provider),
		cfgProvider,
		nil,
		e.social,
		&setting.OSSImpl{Cfg: e.cfg},
		featuremgmt.WithFeatures(),
		noop.NewTracerProvider().Tracer("secret-reuse"),
	)
	redirect, err := client.RedirectURL(context.Background(), &authn.Request{
		HTTPRequest: httptest.NewRequest(http.MethodGet, "/login/"+provider, nil),
	})
	require.NoError(t, err)
	redirectURL, err := url.Parse(redirect.URL)
	require.NoError(t, err)
	callback, err := url.Parse("/login/" + provider)
	require.NoError(t, err)
	query := callback.Query()
	query.Set("code", "placeholder-code")
	query.Set("state", redirectURL.Query().Get("state"))
	callback.RawQuery = query.Encode()
	req := httptest.NewRequest(http.MethodGet, callback.String(), nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: redirect.Extra[authn.KeyOAuthState]})
	_, _ = client.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
}

func (e *secretReuseEnv) requireStoredSecretNotPresented(t *testing.T, status int, secret string) {
	t.Helper()
	require.Falsef(t, e.attackerSaw(secret),
		"stored client secret was presented to the replacement token endpoint (settings write status %d)", status)
}

func (e *secretReuseEnv) attackerSaw(secret string) bool {
	return e.attackHits.sawSecret(secret)
}

func (e *secretReuseEnv) legitimateSaw(secret string) bool {
	return e.legitHits.sawSecret(secret)
}

func (e *secretReuseEnv) writer(provider string) *user.SignedInUser {
	return e.userWithPermissions(
		accesscontrol.ActionSettingsRead, accesscontrol.ScopeSettingsOAuth(provider),
		accesscontrol.ActionSettingsWrite, accesscontrol.ScopeSettingsOAuth(provider),
	)
}

func (e *secretReuseEnv) reader(provider string) *user.SignedInUser {
	return e.userWithPermissions(accesscontrol.ActionSettingsRead, accesscontrol.ScopeSettingsOAuth(provider))
}

func (e *secretReuseEnv) userWithPermissions(actionScope ...string) *user.SignedInUser {
	perms := make([]accesscontrol.Permission, 0, len(actionScope)/2)
	for i := 0; i < len(actionScope); i += 2 {
		perms = append(perms, accesscontrol.Permission{Action: actionScope[i], Scope: actionScope[i+1]})
	}
	return &user.SignedInUser{
		OrgID:   1,
		OrgRole: "Editor",
		Permissions: map[int64]map[string][]string{
			1: accesscontrol.GroupScopesByActionContext(context.Background(), perms),
		},
	}
}

func settingsObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var decoded struct {
		Settings map[string]any `json:"settings"`
	}
	require.NoError(t, json.Unmarshal(body, &decoded))
	require.NotNil(t, decoded.Settings)
	return decoded.Settings
}

func ldapServer(host string, port int, bindPassword string) map[string]any {
	return map[string]any{
		"host":            host,
		"port":            port,
		"bind_dn":         placeholderBindDN,
		"bind_password":   bindPassword,
		"search_filter":   "(uid=%s)",
		"search_base_dns": []any{"dc=example,dc=org"},
		"timeout":         1,
	}
}

func settingRedacted() string {
	return setting.RedactedPassword
}

func waitForLDAPServer(t *testing.T, client *ldapsvc.LDAPImpl, host string, port int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cfg := client.Config()
		if cfg != nil && len(cfg.Servers) > 0 && cfg.Servers[0].Host == host && cfg.Servers[0].Port == port {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("running LDAP client did not adopt the saved server endpoint")
}

type requestCapture struct {
	mu   sync.Mutex
	reqs []capturedRequest
}

type capturedRequest struct {
	header http.Header
	body   []byte
}

func (c *requestCapture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.reqs = append(c.reqs, capturedRequest{header: r.Header.Clone(), body: body})
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"placeholder-access-token","token_type":"bearer"}`))
}

func (c *requestCapture) sawSecret(secret string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, req := range c.reqs {
		if secretPresented(req, secret) {
			return true
		}
	}
	return false
}

func secretPresented(req capturedRequest, secret string) bool {
	header := req.header.Get("Authorization")
	if header != "" {
		probe, err := http.NewRequest(http.MethodPost, "http://token.invalid", nil)
		if err == nil {
			probe.Header.Set("Authorization", header)
			user, pass, ok := probe.BasicAuth()
			if ok {
				user, _ = url.QueryUnescape(user)
				pass, _ = url.QueryUnescape(pass)
				if pass == secret || user == secret {
					return true
				}
			}
		}
	}
	values, err := url.ParseQuery(string(req.body))
	if err == nil && (values.Get("client_secret") == secret || values.Get("client_id") == secret) {
		return true
	}
	return false
}

type ldapListener struct {
	host string
	port int
	mu   sync.Mutex
	raw  bytes.Buffer
}

func startLDAPListener(t *testing.T) *ldapListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcp, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)
	listener := &ldapListener{host: tcp.IP.String(), port: tcp.Port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go listener.serve(&recordingConn{Conn: conn, listener: listener})
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return listener
}

func (l *ldapListener) serve(conn net.Conn) {
	defer conn.Close()
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		messageID, ok := integerValue(packet.Children[0])
		if !ok {
			return
		}
		switch packet.Children[1].Tag {
		case ldapv3.ApplicationBindRequest:
			if writeLDAPResult(conn, messageID, ldapv3.ApplicationBindResponse) != nil {
				return
			}
		case ldapv3.ApplicationSearchRequest:
			if writeLDAPResult(conn, messageID, ldapv3.ApplicationSearchResultDone) != nil {
				return
			}
		case ldapv3.ApplicationUnbindRequest:
			return
		default:
			return
		}
	}
}

// recordingConn keeps the bytes Grafana wrote. go-asn1-ber drops primitive
// context-specific values, which is where a simple bind carries the password.
type recordingConn struct {
	net.Conn
	listener *ldapListener
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.listener.mu.Lock()
		_, _ = c.listener.raw.Write(p[:n])
		c.listener.mu.Unlock()
	}
	return n, err
}

func (l *ldapListener) sawPassword(password string) bool {
	l.mu.Lock()
	raw := append([]byte(nil), l.raw.Bytes()...)
	l.mu.Unlock()
	for _, candidate := range simpleBindPasswords(raw) {
		if candidate == password {
			return true
		}
	}
	return false
}

// simpleBindPasswords returns the simple-authentication octets from LDAP bind
// requests. Those octets are a context-specific primitive [0], per the encoding
// go-ldap writes in SimpleBindRequest.appendTo.
func simpleBindPasswords(raw []byte) []string {
	var passwords []string
	collectBindPasswords(raw, &passwords)
	return passwords
}

func collectBindPasswords(raw []byte, passwords *[]string) {
	for len(raw) > 0 {
		class, constructed, tag, content, rest, ok := takeTLV(raw)
		if !ok {
			return
		}
		raw = rest
		if class == ber.ClassContext && !constructed && tag == 0 {
			*passwords = append(*passwords, string(content))
			continue
		}
		if constructed {
			collectBindPasswords(content, passwords)
		}
	}
}

func takeTLV(raw []byte) (class ber.Class, constructed bool, tag ber.Tag, content, rest []byte, ok bool) {
	if len(raw) < 2 {
		return 0, false, 0, nil, raw, false
	}
	ident := raw[0]
	class = ber.Class(ident & 0xC0)
	constructed = ident&0x20 != 0
	tag = ber.Tag(ident & 0x1F)
	offset := 1
	if tag == 0x1F {
		tag = 0
		for {
			if offset >= len(raw) {
				return 0, false, 0, nil, raw, false
			}
			next := raw[offset]
			offset++
			tag = tag<<7 | ber.Tag(next&0x7F)
			if next&0x80 == 0 {
				break
			}
		}
	}
	if offset >= len(raw) {
		return 0, false, 0, nil, raw, false
	}
	lengthByte := raw[offset]
	offset++
	var length int
	if lengthByte&0x80 == 0 {
		length = int(lengthByte)
	} else {
		count := int(lengthByte & 0x7F)
		if count == 0 || offset+count > len(raw) {
			return 0, false, 0, nil, raw, false
		}
		for i := 0; i < count; i++ {
			length = length<<8 | int(raw[offset+i])
		}
		offset += count
	}
	if length < 0 || offset+length > len(raw) {
		return 0, false, 0, nil, raw, false
	}
	return class, constructed, tag, raw[offset : offset+length], raw[offset+length:], true
}

func writeLDAPResult(conn net.Conn, messageID int64, tag ber.Tag) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "LDAP Result")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(ldapv3.LDAPResultSuccess), "resultCode"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	packet.AppendChild(response)
	_, err := conn.Write(packet.Bytes())
	return err
}

func integerValue(packet *ber.Packet) (int64, bool) {
	if packet == nil || packet.Value == nil {
		return 0, false
	}
	switch value := packet.Value.(type) {
	case int64:
		return value, true
	case int:
		return int64(value), true
	case uint64:
		return int64(value), true
	default:
		return 0, false
	}
}

type memStore struct {
	mu       sync.Mutex
	settings map[string]*models.SSOSettings
}

func newMemStore() *memStore {
	return &memStore{settings: map[string]*models.SSOSettings{}}
}

func (m *memStore) Get(_ context.Context, provider string) (*models.SSOSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.settings[provider]
	if !ok {
		return nil, ssosettings.ErrNotFound
	}
	return cloneSSOSettings(stored), nil
}

func (m *memStore) List(_ context.Context) ([]*models.SSOSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*models.SSOSettings, 0, len(m.settings))
	for _, stored := range m.settings {
		out = append(out, cloneSSOSettings(stored))
	}
	return out, nil
}

func (m *memStore) Upsert(_ context.Context, settings *models.SSOSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings[settings.Provider] = cloneSSOSettings(settings)
	return nil
}

func (m *memStore) Patch(context.Context, string, map[string]any) error {
	return nil
}

func (m *memStore) Delete(_ context.Context, provider string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.settings, provider)
	return nil
}

func cloneSSOSettings(in *models.SSOSettings) *models.SSOSettings {
	if in == nil {
		return nil
	}
	raw, err := json.Marshal(in.Settings)
	if err != nil {
		copied := *in
		return &copied
	}
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		copied := *in
		return &copied
	}
	copied := *in
	copied.Settings = settings
	return &copied
}
