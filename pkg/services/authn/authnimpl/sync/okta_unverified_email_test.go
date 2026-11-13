package sync

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/login/social/socialtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfotest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
)

// Cookie names and the state hash are the OAuth client's values. The client
// package cannot be the test package here: importing this sync package from
// it cycles through the auth registration imports.
const (
	oktaOAuthStateCookie = "oauth_state"
	oktaOAuthPKCECookie  = "oauth_code_verifier"
)

const (
	oktaCompanyDomain = "company.test"
	oktaVictimEmail   = "victim@company.test"
	oktaAliasEmail    = "alias@company.test"
	oktaProfileEmail  = "profile@company.test"
	oktaOutsideEmail  = "outsider@evil.test"
)

// TestOktaShippedConfigAllowsSignupWithoutEmailLinking reads the shipped
// defaults. The login tests below enable the provider and set allowed domains
// on top of these values.
func TestOktaShippedConfigAllowsSignupWithoutEmailLinking(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	defaults := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "..", "conf", "defaults.ini")
	file, err := ini.Load(defaults)
	require.NoError(t, err)

	okta := file.Section("auth.okta")
	require.False(t, okta.Key("enabled").MustBool(true))
	require.True(t, okta.Key("allow_sign_up").MustBool(false))
	require.Empty(t, okta.Key("allowed_domains").String())
	require.False(t, file.Section("auth").Key("oauth_allow_insecure_email_lookup").MustBool(true))
}

func TestOktaLoginRejectsUnverifiedEmail(t *testing.T) {
	t.Run("email claim with email_verified false does not satisfy allowed domains", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			allowedDomains:    []string{oktaCompanyDomain},
			email:             oktaVictimEmail,
			preferredUsername: oktaAliasEmail,
			userInfoEmail:     oktaProfileEmail,
			emailVerified:     boolPtr(false),
		})
		outcome.requireRejected(t)
	})

	t.Run("missing email_verified is rejected when allowed domains are configured", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			allowedDomains:    []string{oktaCompanyDomain},
			email:             oktaVictimEmail,
			preferredUsername: oktaAliasEmail,
			userInfoEmail:     oktaProfileEmail,
		})
		outcome.requireRejected(t)
	})

	t.Run("missing email_verified is rejected when no allowed domains are configured", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			email:             oktaVictimEmail,
			preferredUsername: oktaAliasEmail,
			userInfoEmail:     oktaProfileEmail,
		})
		outcome.requireRejected(t)
	})

	t.Run("preferred_username is not accepted when email_verified is false", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			allowedDomains:    []string{oktaCompanyDomain},
			preferredUsername: oktaVictimEmail,
			userInfoEmail:     oktaProfileEmail,
			emailVerified:     boolPtr(false),
		})
		outcome.requireRejected(t)
	})

	t.Run("preferred_username is not accepted when email_verified is missing and domains are configured", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			allowedDomains:    []string{oktaCompanyDomain},
			preferredUsername: oktaVictimEmail,
			userInfoEmail:     oktaProfileEmail,
		})
		outcome.requireRejected(t)
	})

	t.Run("signature validation still rejects an unverified email", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			allowedDomains:    []string{oktaCompanyDomain},
			email:             oktaVictimEmail,
			preferredUsername: oktaAliasEmail,
			userInfoEmail:     oktaProfileEmail,
			emailVerified:     boolPtr(false),
			validateIDToken:   true,
		})
		outcome.requireRejected(t)
	})

	t.Run("verified email is stored and the domain check does not use the other addresses", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			allowedDomains:    []string{oktaCompanyDomain},
			email:             oktaVictimEmail,
			preferredUsername: oktaAliasEmail,
			userInfoEmail:     oktaProfileEmail,
			emailVerified:     boolPtr(true),
		})
		outcome.requireAcceptedAs(t, oktaVictimEmail)
	})

	t.Run("verified email outside the allowed domain is rejected even when preferred_username matches", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			allowedDomains:    []string{oktaCompanyDomain},
			email:             oktaOutsideEmail,
			preferredUsername: oktaVictimEmail,
			userInfoEmail:     oktaProfileEmail,
			emailVerified:     boolPtr(true),
		})
		outcome.requireRejected(t)
	})

	t.Run("preferred_username is the account email only when the email claim is empty and email_verified is true", func(t *testing.T) {
		outcome := loginWithOktaIDToken(t, oktaLoginInput{
			allowedDomains:    []string{oktaCompanyDomain},
			preferredUsername: oktaVictimEmail,
			userInfoEmail:     oktaProfileEmail,
			emailVerified:     boolPtr(true),
		})
		outcome.requireAcceptedAs(t, oktaVictimEmail)
	})
}

type oktaLoginInput struct {
	allowedDomains    []string
	email             string
	preferredUsername string
	userInfoEmail     string
	emailVerified     *bool
	validateIDToken   bool
}

type oktaLoginOutcome struct {
	err      error
	identity *authn.Identity
	created  []user.CreateUserCommand
	updated  []user.UpdateUserCommand
	orgUsers []org.AddOrgUserCommand
	tokenHit bool
}

func (o oktaLoginOutcome) requireRejected(t *testing.T) {
	t.Helper()
	require.True(t, o.tokenHit, "token endpoint was not called")
	if o.err == nil {
		email, login := "", ""
		if o.identity != nil {
			email = o.identity.Email
			login = o.identity.Login
		}
		t.Fatalf("okta login was accepted, email=%q login=%q users_created=%d org_memberships=%d", email, login, len(o.created), len(o.orgUsers))
	}
	require.NotContains(t, o.err.Error(), "failed to exchange code to token")
	require.NotContains(t, o.err.Error(), "error getting user info response")
	require.NotContains(t, o.err.Error(), "no id_token found")
	require.Empty(t, o.created, "a user was created before the login was refused")
	require.Empty(t, o.orgUsers, "org membership was created before the login was refused")
	require.Empty(t, o.updated, "an existing account was changed before the login was refused")
}

func (o oktaLoginOutcome) requireAcceptedAs(t *testing.T, email string) {
	t.Helper()
	require.NoError(t, o.err)
	require.NotNil(t, o.identity)
	require.Equal(t, email, o.identity.Email)
	require.Equal(t, email, o.identity.Login)
	require.Nil(t, o.identity.ClientParams.LookUpParams.Email)
	require.Nil(t, o.identity.ClientParams.LookUpParams.Login)
	require.True(t, o.identity.ClientParams.AllowSignUp)
	require.Len(t, o.created, 1)
	require.Equal(t, email, o.created[0].Email)
	require.Equal(t, email, o.created[0].Login)
	require.NotEqual(t, oktaAliasEmail, o.created[0].Email)
	require.NotEqual(t, oktaProfileEmail, o.created[0].Email)
	require.NotEqual(t, oktaOutsideEmail, o.created[0].Email)
	require.Len(t, o.orgUsers, 1)
	require.Equal(t, int64(1), o.orgUsers[0].OrgID)
	require.Equal(t, org.RoleViewer, o.orgUsers[0].Role)
}

func loginWithOktaIDToken(t *testing.T, in oktaLoginInput) oktaLoginOutcome {
	t.Helper()
	provider.UsingFlags(t, defaultFeatureFlags)

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const keyID = "test-key-id"

	claims := map[string]any{
		"sub":  "okta-user",
		"name": "Okta User",
	}
	if in.email != "" {
		claims["email"] = in.email
	}
	if in.preferredUsername != "" {
		claims["preferred_username"] = in.preferredUsername
	}
	if in.emailVerified != nil {
		claims["email_verified"] = *in.emailVerified
	}
	idToken := signOktaIDToken(t, signingKey, keyID, claims)

	var tokenHit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHit = true
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"access_token": "placeholder-access-token",
				"token_type":   "Bearer",
				"id_token":     idToken,
			}))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"sub":   "okta-user",
				"email": in.userInfoEmail,
				"name":  "Directory Profile",
			}))
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			jwk := jose.JSONWebKey{Key: signingKey.Public(), KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"}
			require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cfg := setting.NewCfg()
	cfg.SecretKey = "placeholder-secret-key"
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = string(org.RoleViewer)
	_, err = cfg.Raw.Section("auth").NewKey("oauth_allow_insecure_email_lookup", "false")
	require.NoError(t, err)

	info := &social.OAuthInfo{
		Enabled:        true,
		AllowSignup:    true,
		AllowedDomains: in.allowedDomains,
		ClientId:       "placeholder-client-id",
		ClientSecret:   "placeholder-client-secret",
		AuthUrl:        server.URL + "/authorize",
		TokenUrl:       server.URL + "/token",
		ApiUrl:         server.URL + "/userinfo",
		Scopes:         []string{"openid", "profile", "email", "groups"},
		UsePKCE:        true,
	}
	if in.validateIDToken {
		info.ValidateIDToken = true
		info.JwkSetURL = server.URL + "/keys"
	}

	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	connector, err := connectors.NewOktaProvider(
		context.Background(),
		info,
		cfgProvider,
		connectors.ProvideOrgRoleMapper(cfgProvider, &orgtest.FakeOrgService{}),
		ssosettingstests.NewFakeService(),
		featuremgmt.WithFeatures(),
		nil,
	)
	require.NoError(t, err)

	client := clients.ProvideOAuth(
		authn.ClientWithPrefix(social.OktaProviderName),
		cfgProvider,
		nil,
		&socialtest.FakeSocialService{
			ExpectedAuthInfoProvider: info,
			ExpectedConnector:        connector,
			ExpectedHttpClient:       server.Client(),
		},
		setting.ProvideProvider(cfg),
		featuremgmt.WithFeatures(),
		tracing.InitializeTracerForTest(),
	)

	const state = "placeholder-oauth-state"
	callbackURL, err := url.Parse("http://grafana.example/login/okta?state=" + state + "&code=placeholder-auth-code")
	require.NoError(t, err)
	req := &authn.Request{HTTPRequest: &http.Request{
		Header: http.Header{},
		URL:    callbackURL,
	}}
	req.HTTPRequest.AddCookie(&http.Cookie{
		Name:  oktaOAuthStateCookie,
		Value: hashOktaOAuthState(state, cfg.SecretKey, info.ClientSecret),
	})
	req.HTTPRequest.AddCookie(&http.Cookie{Name: oktaOAuthPKCECookie, Value: "placeholder-pkce-verifier"})

	identity, authErr := client.Authenticate(context.Background(), req)
	outcome := oktaLoginOutcome{err: authErr, identity: identity, tokenHit: tokenHit}
	if authErr != nil || identity == nil {
		return outcome
	}

	users := &usertest.FakeUserService{ExpectedError: user.ErrUserNotFound}
	users.CreateFn = func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
		copied := *cmd
		outcome.created = append(outcome.created, copied)
		loginName := copied.Login
		if loginName == "" {
			loginName = copied.Email
		}
		return &user.User{
			ID:    7,
			Email: strings.ToLower(copied.Email),
			Login: strings.ToLower(loginName),
			Name:  copied.Name,
		}, nil
	}
	users.UpdateFn = func(_ context.Context, cmd *user.UpdateUserCommand) error {
		outcome.updated = append(outcome.updated, *cmd)
		return nil
	}

	orgService := &recordingOrgService{}
	userSync := ProvideUserSync(
		users,
		nil,
		&authinfotest.FakeService{
			ExpectedError: user.ErrUserNotFound,
			SetAuthInfoFn: func(context.Context, *login.SetAuthInfoCommand) error { return nil },
		},
		quotatest.New(false, nil),
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
		cfg,
		nil,
	)
	if err := userSync.SyncUserHook(context.Background(), identity, req); err != nil {
		outcome.err = err
		return outcome
	}
	orgSync := ProvideOrgSync(users, orgService, nil, cfg, tracing.InitializeTracerForTest())
	if err := orgSync.SyncOrgRolesHook(context.Background(), identity, req); err != nil {
		outcome.err = err
		return outcome
	}
	outcome.orgUsers = orgService.added
	return outcome
}

type recordingOrgService struct {
	orgtest.FakeOrgService
	added []org.AddOrgUserCommand
}

func (s *recordingOrgService) AddOrgUser(_ context.Context, cmd *org.AddOrgUserCommand) error {
	s.added = append(s.added, *cmd)
	return nil
}

func signOktaIDToken(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", keyID).WithType("JWT"),
	)
	require.NoError(t, err)
	token, err := jwt.Signed(sig).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func boolPtr(v bool) *bool {
	return &v
}

func hashOktaOAuthState(state, secret, seed string) string {
	sum := sha256.Sum256([]byte(state + secret + seed))
	return hex.EncodeToString(sum[:])
}
