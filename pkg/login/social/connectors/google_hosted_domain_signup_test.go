package connectors_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/login/social/socialtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfoimpl"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/strategies"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	hostedDomain       = "mycompany.com"
	workspaceEmail     = "person@mycompany.com"
	workspaceSubject   = "workspace-subject"
	consumerSubject    = "consumer-subject"
	decoyEmail         = "other@mycompany.com"
	decoySubject       = "decoy-subject"
	outsideEmail       = "person@elsewhere.example"
	oauthCallbackState = "callback-state"
	oauthPKCEVerifier  = "pkce-verifier"
)

// TestGoogleValidateHDDefaultAllowsNonWorkspaceSignup checks the Google login
// path described by defaults.ini and the Google auth docs: with validate_hd
// left at its default, an ID token or userinfo payload whose hosted-domain
// claim is missing or different must not become a Grafana user, even when the
// verified email ends with an allowed domain. allow_sign_up stays at the
// provider default. A second, conflicting userinfo response is served if the
// connector reads the hosted domain again after the ID token.
func TestGoogleValidateHDDefaultAllowsNonWorkspaceSignup(t *testing.T) {
	reloadTrue := true
	reloadFalse := false

	testCases := []struct {
		name            string
		googleIni       string
		reloadValidate  *bool
		validateHD      bool
		allowedDomains  []string
		useIDToken      bool
		legacyAPI       bool
		subject         string
		email           string
		hostedDomain    string
		omitHostedClaim bool
		wantUser        bool
		wantErrText     string
	}{
		{
			name:            "default validate_hd rejects an id token with no hd claim",
			googleIni:       "allowed_domains = " + hostedDomain + "\n",
			validateHD:      true,
			allowedDomains:  []string{hostedDomain},
			useIDToken:      true,
			subject:         consumerSubject,
			email:           workspaceEmail,
			omitHostedClaim: true,
			wantErrText:     "hd claim",
		},
		{
			name:           "default validate_hd rejects an id token with a different hd claim",
			googleIni:      "allowed_domains = " + hostedDomain + "\n",
			validateHD:     true,
			allowedDomains: []string{hostedDomain},
			useIDToken:     true,
			subject:        consumerSubject,
			email:          workspaceEmail,
			hostedDomain:   "other.example",
			wantErrText:    "hd claim",
		},
		{
			name:            "explicit validate_hd true rejects an id token with no hd claim",
			googleIni:       "allowed_domains = " + hostedDomain + "\nvalidate_hd = true\n",
			validateHD:      true,
			allowedDomains:  []string{hostedDomain},
			useIDToken:      true,
			subject:         consumerSubject,
			email:           workspaceEmail,
			omitHostedClaim: true,
			wantErrText:     "hd claim",
		},
		{
			name:            "userinfo without an id token and no hd claim is rejected at the default",
			googleIni:       "allowed_domains = " + hostedDomain + "\n",
			validateHD:      true,
			allowedDomains:  []string{hostedDomain},
			subject:         consumerSubject,
			email:           workspaceEmail,
			omitHostedClaim: true,
			wantErrText:     "hd claim",
		},
		{
			name:            "legacy userinfo without an hd claim is rejected at the default",
			googleIni:       "allowed_domains = " + hostedDomain + "\napi_url = https://www.googleapis.com/oauth2/v1/userinfo\n",
			validateHD:      true,
			allowedDomains:  []string{hostedDomain},
			legacyAPI:       true,
			subject:         consumerSubject,
			email:           workspaceEmail,
			omitHostedClaim: true,
			wantErrText:     "hd claim",
		},
		{
			name:            "reload to validate_hd true rejects an id token with no hd claim",
			googleIni:       "allowed_domains = " + hostedDomain + "\nvalidate_hd = false\n",
			reloadValidate:  &reloadTrue,
			validateHD:      true,
			allowedDomains:  []string{hostedDomain},
			useIDToken:      true,
			subject:         consumerSubject,
			email:           workspaceEmail,
			omitHostedClaim: true,
			wantErrText:     "hd claim",
		},
		{
			name:           "matching hd with default validate_hd creates that token's user",
			googleIni:      "allowed_domains = " + hostedDomain + "\n",
			validateHD:     true,
			allowedDomains: []string{hostedDomain},
			useIDToken:     true,
			subject:        workspaceSubject,
			email:          workspaceEmail,
			hostedDomain:   hostedDomain,
			wantUser:       true,
		},
		{
			name:            "validate_hd false allows an allowed-domain email with no hd claim",
			googleIni:       "allowed_domains = " + hostedDomain + "\nvalidate_hd = false\n",
			validateHD:      false,
			allowedDomains:  []string{hostedDomain},
			useIDToken:      true,
			subject:         consumerSubject,
			email:           workspaceEmail,
			omitHostedClaim: true,
			wantUser:        true,
		},
		{
			name:            "reload to validate_hd false allows an id token with no hd claim",
			googleIni:       "allowed_domains = " + hostedDomain + "\n",
			reloadValidate:  &reloadFalse,
			validateHD:      false,
			allowedDomains:  []string{hostedDomain},
			useIDToken:      true,
			subject:         consumerSubject,
			email:           workspaceEmail,
			omitHostedClaim: true,
			wantUser:        true,
		},
		{
			name:            "no allowed domains does not require an hd claim",
			validateHD:      true,
			allowedDomains:  []string{},
			useIDToken:      true,
			subject:         consumerSubject,
			email:           workspaceEmail,
			omitHostedClaim: true,
			wantUser:        true,
		},
		{
			name:           "email outside allowed domains is not created when hd matches",
			googleIni:      "allowed_domains = " + hostedDomain + "\n",
			validateHD:     true,
			allowedDomains: []string{hostedDomain},
			useIDToken:     true,
			subject:        workspaceSubject,
			email:          outsideEmail,
			hostedDomain:   hostedDomain,
			wantErrText:    "not allowed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := loadGrafanaConfig(t, tc.googleIni)
			cfgProvider, err := configprovider.ProvideService(cfg)
			require.NoError(t, err)

			settings, err := strategies.NewOAuthStrategy(cfgProvider).GetProviderConfig(ctx, social.GoogleProviderName)
			require.NoError(t, err)
			info, err := connectors.CreateOAuthInfoFromKeyValuesWithLogging(log.New("test"), social.GoogleProviderName, settings)
			require.NoError(t, err)

			connector, err := connectors.NewGoogleProvider(
				ctx,
				info,
				cfgProvider,
				connectors.ProvideOrgRoleMapper(cfgProvider, orgtest.NewOrgServiceFake()),
				nil,
				featuremgmt.WithFeatures(),
				nil,
			)
			require.NoError(t, err)

			if tc.reloadValidate != nil {
				reloaded := cloneSettings(settings)
				reloaded["validate_hd"] = *tc.reloadValidate
				require.NoError(t, connector.Reload(ctx, models.SSOSettings{Provider: social.GoogleProviderName, Settings: reloaded}))
			}

			effective := connector.GetOAuthInfo()
			require.True(t, effective.Enabled, "Google auth must be enabled for this signup path")
			require.True(t, effective.AllowSignup, "allow_sign_up must stay at the Google provider default")
			require.Empty(t, effective.HostedDomain)
			require.Equal(t, tc.allowedDomains, effective.AllowedDomains)
			require.Equal(t, tc.validateHD, connectors.MustBool(effective.Extra["validate_hd"], true))

			account := googleAccount{
				subject:         tc.subject,
				email:           tc.email,
				name:            "Workspace Person",
				hostedDomain:    tc.hostedDomain,
				omitHostedClaim: tc.omitHostedClaim,
				legacy:          tc.legacyAPI,
			}
			// A later read must not be able to substitute a different account or a hosted domain the first payload did not carry.
			decoy := googleAccount{
				subject:         decoySubject,
				email:           decoyEmail,
				name:            "Decoy User",
				hostedDomain:    hostedDomain,
				omitHostedClaim: !tc.omitHostedClaim,
				legacy:          tc.legacyAPI,
			}
			if tc.wantUser && tc.omitHostedClaim {
				decoy.omitHostedClaim = false
				decoy.hostedDomain = hostedDomain
			}
			if !tc.wantUser && tc.omitHostedClaim {
				decoy.omitHostedClaim = false
				decoy.hostedDomain = hostedDomain
				decoy.subject = tc.subject
				decoy.email = tc.email
			}
			if !tc.wantUser && !tc.omitHostedClaim && tc.hostedDomain != hostedDomain {
				decoy.subject = tc.subject
				decoy.email = tc.email
				decoy.hostedDomain = hostedDomain
				decoy.omitHostedClaim = false
			}

			var idToken string
			userinfoBodies := [][]byte{
				googleUserInfoResponse(t, account),
				googleUserInfoResponse(t, decoy),
			}
			if tc.useIDToken {
				idToken = unsignedIDToken(t, account)
				// Any userinfo read must disagree with the ID token so a second lookup cannot satisfy the check.
				userinfoBodies = [][]byte{
					googleUserInfoResponse(t, decoy),
					googleUserInfoResponse(t, decoy),
				}
			}
			transport := &scriptedGoogleTransport{
				tokenBody:      googleTokenResponse(t, idToken),
				userinfoBodies: userinfoBodies,
			}

			created, authConnections, identity, authErr := signupGoogleUser(t, ctx, cfg, cfgProvider, connector, info, transport)

			if tc.wantUser {
				require.NoError(t, authErr)
				require.NotNil(t, identity)
				require.Equal(t, tc.email, identity.Email)
				require.Equal(t, tc.email, identity.Login)
				require.Equal(t, tc.subject, identity.AuthID)
				require.Equal(t, login.GoogleAuthModule, identity.AuthenticatedBy)
				require.True(t, identity.ClientParams.AllowSignUp)
				require.True(t, identity.ClientParams.SyncUser)
				require.Len(t, created, 1)
				require.Equal(t, tc.email, created[0].Email)
				require.Equal(t, tc.email, created[0].Login)
				require.Equal(t, "Workspace Person", created[0].Name)
				require.Len(t, authConnections, 1)
				require.Equal(t, tc.subject, authConnections[0].AuthId)
				require.Equal(t, login.GoogleAuthModule, authConnections[0].AuthModule)
				require.Equal(t, created[0].Login, identity.Login)
				return
			}

			require.Error(t, authErr)
			require.Contains(t, authErr.Error(), tc.wantErrText)
			require.Empty(t, created)
			require.Empty(t, authConnections)
		})
	}
}

type googleAccount struct {
	subject         string
	email           string
	name            string
	hostedDomain    string
	omitHostedClaim bool
	legacy          bool
}

func loadGrafanaConfig(t *testing.T, googleIni string) *setting.Cfg {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))

	custom := filepath.Join(t.TempDir(), "custom.ini")
	body := "[security]\nsecret_key = placeholder-secret\n\n[auth.google]\nenabled = true\n" + googleIni
	require.NoError(t, os.WriteFile(custom, []byte(body), 0o600))

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: root,
		Config:   custom,
	}))
	return cfg
}

func cloneSettings(settings map[string]any) map[string]any {
	cloned := make(map[string]any, len(settings))
	for key, value := range settings {
		cloned[key] = value
	}
	return cloned
}

func unsignedIDToken(t *testing.T, account googleAccount) string {
	t.Helper()
	payload := map[string]any{
		"sub":            account.subject,
		"email":          account.email,
		"name":           account.name,
		"email_verified": true,
	}
	if !account.omitHostedClaim {
		payload["hd"] = account.hostedDomain
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func googleTokenResponse(t *testing.T, idToken string) []byte {
	t.Helper()
	payload := map[string]any{
		"access_token":  "placeholder-access-token",
		"token_type":    "Bearer",
		"refresh_token": "placeholder-refresh-token",
		"expires_in":    3600,
	}
	if idToken != "" {
		payload["id_token"] = idToken
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return raw
}

func googleUserInfoResponse(t *testing.T, account googleAccount) []byte {
	t.Helper()
	payload := map[string]any{
		"name": account.name,
	}
	if account.legacy {
		payload["id"] = account.subject
		payload["email"] = account.email
		payload["verified_email"] = true
	} else {
		payload["sub"] = account.subject
		payload["email"] = account.email
		payload["email_verified"] = true
	}
	if !account.omitHostedClaim {
		payload["hd"] = account.hostedDomain
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	return raw
}

type scriptedGoogleTransport struct {
	tokenBody      []byte
	userinfoBodies [][]byte
	userinfoCalls  int
}

func (s *scriptedGoogleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	switch {
	case req.URL.Host == "oauth2.googleapis.com" && req.URL.Path == "/token":
		body = s.tokenBody
	case strings.Contains(req.URL.Path, "userinfo"):
		body = s.userinfoBodies[len(s.userinfoBodies)-1]
		if s.userinfoCalls < len(s.userinfoBodies) {
			body = s.userinfoBodies[s.userinfoCalls]
		}
		s.userinfoCalls++
	default:
		return nil, errUnexpectedGoogleRequest(req)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Request:    req,
	}, nil
}

type unexpectedGoogleRequest struct {
	method string
	url    string
}

func errUnexpectedGoogleRequest(req *http.Request) error {
	return &unexpectedGoogleRequest{method: req.Method, url: req.URL.String()}
}

func (e *unexpectedGoogleRequest) Error() string {
	return "unexpected Google request " + e.method + " " + e.url
}

func signupGoogleUser(
	t *testing.T,
	ctx context.Context,
	cfg *setting.Cfg,
	cfgProvider configprovider.ConfigProvider,
	connector *connectors.SocialGoogle,
	info *social.OAuthInfo,
	transport http.RoundTripper,
) ([]*user.CreateUserCommand, []*login.SetAuthInfoCommand, *authn.Identity, error) {
	t.Helper()

	var created []*user.CreateUserCommand
	users := usertest.NewUserServiceFake()
	users.ExpectedError = user.ErrUserNotFound
	users.GetByEmailFn = func(context.Context, *user.GetUserByEmailQuery) (*user.User, error) {
		return nil, user.ErrUserNotFound
	}
	users.GetByLoginFn = func(context.Context, *user.GetUserByLoginQuery) (*user.User, error) {
		return nil, user.ErrUserNotFound
	}
	users.CreateFn = func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
		copied := *cmd
		created = append(created, &copied)
		return &user.User{ID: 7, UID: "uid-7", Login: cmd.Login, Email: cmd.Email, Name: cmd.Name}, nil
	}

	authInfo := &recordingAuthInfo{}
	tracer := tracing.InitializeTracerForTest()
	userSync := sync.ProvideUserSync(
		users,
		authinfoimpl.ProvideOSSUserProtectionService(),
		authInfo,
		&quotatest.FakeQuotaService{},
		tracer,
		featuremgmt.WithFeatures(),
		cfg,
		nil,
	)

	oauthClient := clients.ProvideOAuth(
		authn.ClientWithPrefix(social.GoogleProviderName),
		cfgProvider,
		nil,
		&socialtest.FakeSocialService{
			ExpectedAuthInfoProvider: info,
			ExpectedConnector:        connector,
			ExpectedHttpClient:       &http.Client{Transport: transport},
		},
		setting.ProvideProvider(cfg),
		featuremgmt.WithFeatures(),
		tracer,
	)

	request := httptest.NewRequest(http.MethodGet, "https://grafana.example/login/google?code=auth-code&state="+oauthCallbackState, nil)
	request.AddCookie(&http.Cookie{
		Name:  "oauth_state",
		Value: oauthStateCookie(oauthCallbackState, cfg.SecretKey, info.ClientSecret),
	})
	if info.UsePKCE {
		request.AddCookie(&http.Cookie{Name: "oauth_code_verifier", Value: oauthPKCEVerifier})
	}

	identity, authErr := oauthClient.Authenticate(ctx, &authn.Request{HTTPRequest: request})
	if identity != nil {
		syncErr := userSync.SyncUserHook(ctx, identity, &authn.Request{HTTPRequest: request})
		if authErr == nil {
			authErr = syncErr
		}
	}
	return created, authInfo.set, identity, authErr
}

// oauthStateCookie is the value Authenticate recomputes from the callback state.
func oauthStateCookie(state, secretKey, clientSecret string) string {
	sum := sha256.Sum256([]byte(state + secretKey + clientSecret))
	return hex.EncodeToString(sum[:])
}

type recordingAuthInfo struct {
	set []*login.SetAuthInfoCommand
}

func (a *recordingAuthInfo) GetAuthInfo(context.Context, *login.GetAuthInfoQuery) (*login.UserAuth, error) {
	return nil, user.ErrUserNotFound
}

func (a *recordingAuthInfo) GetUsersRecentlyUsedLabel(context.Context, login.GetUserLabelsQuery) (map[int64]string, error) {
	return nil, nil
}

func (a *recordingAuthInfo) GetUserAuthModuleLabels(context.Context, int64) ([]string, error) {
	return nil, nil
}

func (a *recordingAuthInfo) SetAuthInfo(_ context.Context, cmd *login.SetAuthInfoCommand) error {
	copied := *cmd
	a.set = append(a.set, &copied)
	return nil
}

func (a *recordingAuthInfo) UpdateAuthInfo(context.Context, *login.UpdateAuthInfoCommand) error {
	return nil
}

func (a *recordingAuthInfo) DeleteUserAuthInfo(context.Context, int64) error {
	return nil
}
