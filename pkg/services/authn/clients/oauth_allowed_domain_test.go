package clients_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/login/social/socialtest"
	"github.com/grafana/grafana/pkg/services/authn"
	authsync "github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfoimpl"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
)

const (
	allowedTestDomain = "company.com"
	// A single mailbox in the configured domain. Login with this address is the
	// behavior allowed_domains is supposed to permit.
	allowedMailbox = "allowed.person@company.com"
)

// notAMailbox is an address that is not one mailbox. The whole string ends in
// @company.com, which is the comparison the allowed-domain check performs.
func notAMailbox(local string) string {
	return local + "@outside.example@" + allowedTestDomain
}

// TestOAuthAllowedDomainRequiresOneMailbox is the specification for the OAuth
// allowed-domain check. Addresses that are not one mailbox in an allowed
// domain must be refused before a user, organization membership, or external
// auth link is created. A mailbox whose domain is exactly one of the
// configured domains must still be able to sign up.
func TestOAuthAllowedDomainRequiresOneMailbox(t *testing.T) {
	env := newAllowedDomainEnv(t)

	t.Run("foreign domain is refused and creates nobody", func(t *testing.T) {
		env.reject(t, "foreign-domain", env.genericUserInfo("person@outside.example", "foreign-subject"))
	})

	t.Run("domain label suffix is refused and creates nobody", func(t *testing.T) {
		env.reject(t, "label-suffix", env.genericUserInfo("person@notcompany.com", "label-suffix-subject"))
	})

	t.Run("subdomain is refused and creates nobody", func(t *testing.T) {
		env.reject(t, "subdomain", env.genericUserInfo("person@sub.company.com", "subdomain-subject"))
	})

	t.Run("generic oauth userinfo email that only ends with the domain", func(t *testing.T) {
		env.reject(t, "generic-userinfo", env.genericUserInfo(notAMailbox("userinfo"), "generic-userinfo-subject"))
	})

	t.Run("generic oauth email attribute path that only ends with the domain", func(t *testing.T) {
		info := env.baseInfo(env.server.URL + "/userinfo")
		info.EmailAttributePath = "profile.email"
		env.reject(t, "generic-attribute-path", idpExchange{
			info:     info,
			provider: social.GenericOAuthProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/userinfo": map[string]any{
					"sub": "attribute-path-subject",
					"profile": map[string]any{
						"email": notAMailbox("attribute-path"),
					},
				},
			},
		})
	})

	t.Run("generic oauth email attribute that only ends with the domain", func(t *testing.T) {
		info := env.baseInfo(env.server.URL + "/userinfo")
		info.EmailAttributeName = "email:primary"
		env.reject(t, "generic-attribute", idpExchange{
			info:     info,
			provider: social.GenericOAuthProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/userinfo": map[string]any{
					"sub": "attribute-subject",
					"attributes": map[string][]string{
						"email:primary": {notAMailbox("attribute")},
					},
				},
			},
		})
	})

	t.Run("generic oauth id token email that only ends with the domain", func(t *testing.T) {
		info := env.baseInfo("")
		env.reject(t, "generic-id-token", idpExchange{
			info:     info,
			provider: social.GenericOAuthProviderName,
			token: bearerToken("opaque-token", unsignedJWT(t, map[string]any{
				"sub":   "id-token-subject",
				"email": notAMailbox("id-token"),
			})),
			routes: map[string]any{},
		})
	})

	t.Run("generic oauth access token email that only ends with the domain", func(t *testing.T) {
		info := env.baseInfo("")
		env.reject(t, "generic-access-token", idpExchange{
			info:     info,
			provider: social.GenericOAuthProviderName,
			token: bearerToken(unsignedJWT(t, map[string]any{
				"sub":   "access-token-subject",
				"email": notAMailbox("access-token"),
			}), ""),
			routes: map[string]any{},
		})
	})

	t.Run("comma separated value that only ends with the domain", func(t *testing.T) {
		env.reject(t, "comma-list", env.genericUserInfo("attacker@outside.example,person@"+allowedTestDomain, "comma-subject"))
	})

	t.Run("allowed domain compared case insensitively still rejects a non mailbox", func(t *testing.T) {
		info := env.baseInfo(env.server.URL + "/userinfo")
		info.AllowedDomains = []string{"Company.COM"}
		env.reject(t, "generic-case", idpExchange{
			info:     info,
			provider: social.GenericOAuthProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/userinfo": map[string]any{
					"sub":   "case-subject",
					"email": "attacker@outside.example@Company.COM",
				},
			},
		})
	})

	t.Run("role attribute does not admit a non mailbox", func(t *testing.T) {
		info := env.baseInfo(env.server.URL + "/userinfo")
		info.RoleAttributePath = "role"
		env.reject(t, "generic-admin-role", idpExchange{
			info:     info,
			provider: social.GenericOAuthProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/userinfo": map[string]any{
					"sub":   "admin-role-subject",
					"email": notAMailbox("admin-role"),
					"role":  "Admin",
				},
			},
		})
	})

	t.Run("github profile email that only ends with the domain", func(t *testing.T) {
		api := env.server.URL + "/github/user"
		info := env.baseInfo(api)
		env.reject(t, "github-profile", idpExchange{
			info:     info,
			provider: social.GitHubProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/github/user": map[string]any{
					"id":    7,
					"login": "github-profile",
					"email": notAMailbox("github-profile"),
					"name":  "GitHub Profile",
				},
				"/github/user/teams": []any{},
			},
		})
	})

	t.Run("github private email that only ends with the domain", func(t *testing.T) {
		api := env.server.URL + "/github/user"
		info := env.baseInfo(api)
		env.reject(t, "github-private-email", idpExchange{
			info:     info,
			provider: social.GitHubProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/github/user": map[string]any{
					"id":    8,
					"login": "github-private",
					"name":  "GitHub Private",
				},
				"/github/user/emails": []any{
					map[string]any{"email": notAMailbox("github-private"), "primary": true, "verified": true},
				},
				"/github/user/teams": []any{},
			},
		})
	})

	t.Run("gitlab api email that only ends with the domain", func(t *testing.T) {
		api := env.server.URL + "/gitlab"
		info := env.baseInfo(api)
		confirmed := "2020-01-01T00:00:00Z"
		env.reject(t, "gitlab-api", idpExchange{
			info:     info,
			provider: social.GitlabProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/gitlab/user": map[string]any{
					"id":           9,
					"username":     "gitlab-user",
					"name":         "GitLab User",
					"email":        notAMailbox("gitlab"),
					"state":        "active",
					"confirmed_at": confirmed,
				},
				"/gitlab/groups": []any{},
			},
		})
	})

	t.Run("google userinfo email that only ends with the domain", func(t *testing.T) {
		info := env.baseInfo(env.server.URL + "/google/userinfo")
		env.reject(t, "google-userinfo", idpExchange{
			info:     info,
			provider: social.GoogleProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/google/userinfo": map[string]any{
					"sub":            "google-subject",
					"email":          notAMailbox("google"),
					"email_verified": true,
					"name":           "Attacker",
					"hd":             allowedTestDomain,
				},
			},
		})
	})

	t.Run("okta id token email that only ends with the domain", func(t *testing.T) {
		info := env.baseInfo(env.server.URL + "/okta/userinfo")
		env.reject(t, "okta-id-token", idpExchange{
			info:     info,
			provider: social.OktaProviderName,
			token: bearerToken("opaque-token", env.sign(t, map[string]any{
				"sub":   "okta-subject",
				"email": notAMailbox("okta"),
				"name":  "Attacker",
			})),
			routes: map[string]any{
				"/okta/userinfo": map[string]any{},
			},
		})
	})

	t.Run("azure ad id token email that only ends with the domain", func(t *testing.T) {
		info := env.baseInfo("")
		info.ClientId = "azure-client"
		info.AuthUrl = env.server.URL + "/oauth2/v2.0/authorize"
		env.reject(t, "azuread-id-token", idpExchange{
			info:     info,
			provider: social.AzureADProviderName,
			token: bearerToken("opaque-token", env.sign(t, map[string]any{
				"aud":   "azure-client",
				"email": notAMailbox("azure"),
				"oid":   "azure-subject",
				"name":  "Attacker",
				"ver":   "2.0",
				"tid":   "tenant",
			})),
			routes: map[string]any{
				"/discovery/v2.0/keys": env.jwks(),
			},
		})
	})

	t.Run("one mailbox in the allowed domain signs up as viewer in org 1", func(t *testing.T) {
		env.allow(t, "allowed-mailbox", env.genericUserInfo(allowedMailbox, "allowed-subject"), org.RoleViewer)
	})

	t.Run("one mailbox keeps an idp admin role", func(t *testing.T) {
		info := env.baseInfo(env.server.URL + "/userinfo")
		info.RoleAttributePath = "role"
		env.allow(t, "allowed-admin", idpExchange{
			info:     info,
			provider: social.GenericOAuthProviderName,
			token:    bearerToken("opaque-token", ""),
			routes: map[string]any{
				"/userinfo": map[string]any{
					"sub":   "allowed-admin-subject",
					"email": "admin.person@" + allowedTestDomain,
					"role":  "Admin",
				},
			},
		}, org.RoleAdmin)
	})
}

type idpExchange struct {
	info     *social.OAuthInfo
	provider string
	token    map[string]any
	routes   map[string]any
}

type recordingAuthInfo struct {
	authinfotest.FakeService
	links []login.SetAuthInfoCommand
}

func (a *recordingAuthInfo) GetAuthInfo(context.Context, *login.GetAuthInfoQuery) (*login.UserAuth, error) {
	return nil, user.ErrUserNotFound
}

func (a *recordingAuthInfo) SetAuthInfo(_ context.Context, cmd *login.SetAuthInfoCommand) error {
	a.links = append(a.links, *cmd)
	return nil
}

type allowedDomainEnv struct {
	t        *testing.T
	cfg      *setting.Cfg
	store    *sqlstore.SQLStore
	users    user.Service
	orgs     org.Service
	userSync *authsync.UserSync
	orgSync  *authsync.OrgSync
	auth     *recordingAuthInfo
	server   *httptest.Server
	idp      *scriptedIDP
	key      *rsa.PrivateKey
	keyID    string
}

func newAllowedDomainEnv(t *testing.T) *allowedDomainEnv {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = string(org.RoleViewer)
	cfg.SecretKey = "state-hash-key"

	store := sqlstore.NewTestStore(t, sqlstore.WithCfg(cfg))
	sqlstore.SeedDefaultOrgAndUser(t, store)

	sql := legacysql.NewDatabaseProvider(store)
	quota := quotatest.New(false, nil)
	orgService, err := orgimpl.ProvideService(sql, cfg, quota)
	require.NoError(t, err)
	userService, err := userimpl.NewLegacyService(
		sql, orgService, cfg, teamtest.NewFakeService(), localcache.ProvideService(),
		tracing.InitializeTracerForTest(), quota, &supportbundlestest.FakeBundleService{},
	)
	require.NoError(t, err)

	authInfo := &recordingAuthInfo{}
	tracer := tracing.InitializeTracerForTest()
	features := featuremgmt.WithFeatures()
	env := &allowedDomainEnv{
		t:        t,
		cfg:      cfg,
		store:    store,
		users:    userService,
		orgs:     orgService,
		userSync: authsync.ProvideUserSync(userService, authinfoimpl.ProvideOSSUserProtectionService(), authInfo, quota, tracer, features, cfg, nil),
		orgSync:  authsync.ProvideOrgSync(userService, orgService, nil, cfg, tracer),
		auth:     authInfo,
		idp:      &scriptedIDP{},
		keyID:    "test-key",
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	env.key = key
	env.server = httptest.NewServer(env.idp)
	t.Cleanup(env.server.Close)
	return env
}

func (e *allowedDomainEnv) baseInfo(apiURL string) *social.OAuthInfo {
	return &social.OAuthInfo{
		Enabled:        true,
		AllowSignup:    true,
		AllowedDomains: []string{allowedTestDomain},
		ClientId:       "client",
		AuthUrl:        e.server.URL + "/authorize",
		TokenUrl:       e.server.URL + "/token",
		ApiUrl:         apiURL,
		Scopes:         []string{"openid", "email"},
	}
}

func (e *allowedDomainEnv) genericUserInfo(email, subject string) idpExchange {
	return idpExchange{
		info:     e.baseInfo(e.server.URL + "/userinfo"),
		provider: social.GenericOAuthProviderName,
		token:    bearerToken("opaque-token", ""),
		routes: map[string]any{
			"/userinfo": map[string]any{
				"sub":   subject,
				"email": email,
				"name":  "Person",
			},
		},
	}
}

func (e *allowedDomainEnv) reject(t *testing.T, name string, exchange idpExchange) {
	t.Helper()
	before := e.emails(t)
	links := len(e.auth.links)

	identity, err := e.login(t, exchange)
	if err == nil && identity != nil {
		req := &authn.Request{}
		require.NoError(t, e.userSync.SyncUserHook(context.Background(), identity, req))
		require.NoError(t, e.orgSync.SyncOrgRolesHook(context.Background(), identity, req))
	}

	require.Error(t, err, "%s accepted %q and created a user", name, exchange.email())
	require.Contains(t, err.Error(), "auth.oauth.email.not-allowed", "%s: %v", name, err)
	require.Equal(t, before, e.emails(t), "%s persisted a user before refusing the login", name)
	require.Len(t, e.auth.links, links, "%s linked an external subject before refusing the login", name)
}

func (e *allowedDomainEnv) allow(t *testing.T, name string, exchange idpExchange, role org.RoleType) {
	t.Helper()
	before := e.emails(t)
	identity, err := e.login(t, exchange)
	require.NoError(t, err, name)
	require.NotNil(t, identity)

	req := &authn.Request{}
	require.NoError(t, e.userSync.SyncUserHook(context.Background(), identity, req))
	require.NoError(t, e.orgSync.SyncOrgRolesHook(context.Background(), identity, req))

	wantEmail := strings.ToLower(exchange.email())
	got := e.emails(t)
	require.ElementsMatch(t, append(append([]string{}, before...), wantEmail), got)

	created, err := e.users.GetByEmail(context.Background(), &user.GetUserByEmailQuery{Email: wantEmail})
	require.NoError(t, err)
	require.Equal(t, wantEmail, created.Email)
	require.Equal(t, wantEmail, created.Login)

	memberships, err := e.orgs.GetUserOrgList(context.Background(), &org.GetUserOrgListQuery{UserID: created.ID})
	require.NoError(t, err)
	require.Len(t, memberships, 1)
	require.Equal(t, int64(1), memberships[0].OrgID)
	require.Equal(t, role, memberships[0].Role)

	require.NotEmpty(t, e.auth.links)
	link := e.auth.links[len(e.auth.links)-1]
	require.Equal(t, created.ID, link.UserId)
	require.Equal(t, "oauth_"+exchange.provider, link.AuthModule)
	require.NotEmpty(t, link.AuthId)
	require.Equal(t, identity.AuthID, link.AuthId)
}

func (e *allowedDomainEnv) login(t *testing.T, exchange idpExchange) (*authn.Identity, error) {
	t.Helper()
	e.idp.set(exchange.token, exchange.routes)

	connector := e.connector(t, exchange)
	cfgProvider := testConfigProvider(t, e.cfg)
	client := clients.ProvideOAuth(
		authn.ClientWithPrefix(exchange.provider),
		cfgProvider,
		nil,
		&socialtest.FakeSocialService{
			ExpectedAuthInfoProvider: exchange.info,
			ExpectedConnector:        connector,
			ExpectedHttpClient:       e.server.Client(),
		},
		setting.ProvideProvider(e.cfg),
		featuremgmt.WithFeatures(),
		tracing.InitializeTracerForTest(),
	)

	const state = "returned-state"
	request := &authn.Request{HTTPRequest: &http.Request{
		Header: http.Header{},
		URL:    mustParseURL(t, "https://grafana.example/login?state="+state+"&code=auth-code"),
	}}
	request.HTTPRequest.AddCookie(&http.Cookie{
		Name:  "oauth_state",
		Value: hashOAuthState(state, e.cfg.SecretKey, exchange.info.ClientSecret),
	})

	return client.Authenticate(context.Background(), request)
}

func (e *allowedDomainEnv) connector(t *testing.T, exchange idpExchange) social.SocialConnector {
	t.Helper()
	ctx := context.Background()
	cfgProvider := testConfigProvider(t, e.cfg)
	mapper := connectors.ProvideOrgRoleMapper(cfgProvider, e.orgs)
	features := featuremgmt.WithFeatures()
	var (
		connector social.SocialConnector
		err       error
	)
	switch exchange.provider {
	case social.GenericOAuthProviderName:
		connector, err = connectors.NewGenericOAuthProvider(ctx, exchange.info, cfgProvider, mapper, nil, features, nil)
	case social.GitHubProviderName:
		connector, err = connectors.NewGitHubProvider(ctx, exchange.info, cfgProvider, mapper, nil, features)
	case social.GitlabProviderName:
		connector, err = connectors.NewGitLabProvider(ctx, exchange.info, cfgProvider, mapper, nil, features, nil)
	case social.GoogleProviderName:
		connector, err = connectors.NewGoogleProvider(ctx, exchange.info, cfgProvider, mapper, nil, features, nil)
	case social.OktaProviderName:
		connector, err = connectors.NewOktaProvider(ctx, exchange.info, cfgProvider, mapper, nil, features, nil)
	case social.AzureADProviderName:
		connector, err = connectors.NewAzureADProvider(ctx, exchange.info, cfgProvider, mapper, nil, features, nil)
	default:
		t.Fatalf("unknown provider %s", exchange.provider)
	}
	require.NoError(t, err)
	return connector
}

func (e *allowedDomainEnv) emails(t *testing.T) []string {
	t.Helper()
	var rows []struct {
		Email string `xorm:"email"`
	}
	require.NoError(t, e.store.GetEngine().Table("user").Cols("email").OrderBy("email").Find(&rows))
	emails := make([]string, 0, len(rows))
	for _, row := range rows {
		emails = append(emails, row.Email)
	}
	return emails
}

func (e *allowedDomainEnv) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: e.key},
		(&jose.SignerOptions{}).WithHeader("kid", e.keyID).WithType("JWT"),
	)
	require.NoError(t, err)
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func (e *allowedDomainEnv) jwks() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       e.key.Public(),
		KeyID:     e.keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
}

func (exchange idpExchange) email() string {
	if body, ok := exchange.routes["/userinfo"].(map[string]any); ok {
		if email, ok := body["email"].(string); ok {
			return email
		}
		if profile, ok := body["profile"].(map[string]any); ok {
			if email, ok := profile["email"].(string); ok {
				return email
			}
		}
		if attributes, ok := body["attributes"].(map[string][]string); ok {
			for _, values := range attributes {
				if len(values) > 0 {
					return values[0]
				}
			}
		}
	}
	for _, route := range []string{"/github/user", "/google/userinfo", "/gitlab/user"} {
		if body, ok := exchange.routes[route].(map[string]any); ok {
			if email, ok := body["email"].(string); ok && email != "" {
				return email
			}
		}
	}
	if emails, ok := exchange.routes["/github/user/emails"].([]any); ok && len(emails) > 0 {
		if row, ok := emails[0].(map[string]any); ok {
			if email, ok := row["email"].(string); ok {
				return email
			}
		}
	}
	if idToken, ok := exchange.token["id_token"].(string); ok && idToken != "" {
		if email := emailFromJWT(idToken); email != "" {
			return email
		}
	}
	if accessToken, ok := exchange.token["access_token"].(string); ok {
		if email := emailFromJWT(accessToken); email != "" {
			return email
		}
	}
	return ""
}

func emailFromJWT(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	email, _ := claims["email"].(string)
	return email
}

func bearerToken(accessToken, idToken string) map[string]any {
	token := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
	}
	if idToken != "" {
		token["id_token"] = idToken
	}
	return token
}

func testConfigProvider(t *testing.T, cfg *setting.Cfg) configprovider.ConfigProvider {
	t.Helper()
	provider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	return provider
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}

func hashOAuthState(state, secret, seed string) string {
	hashBytes := sha256.Sum256([]byte(state + secret + seed))
	return hex.EncodeToString(hashBytes[:])
}

func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

type scriptedIDP struct {
	mu     sync.Mutex
	token  map[string]any
	routes map[string]any
}

func (s *scriptedIDP) set(token map[string]any, routes map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	s.routes = routes
}

func (s *scriptedIDP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var body any
	if r.URL.Path == "/token" {
		body = s.token
	} else {
		var ok bool
		body, ok = s.routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded)
}
