package authnimpl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	authjwt "github.com/grafana/grafana/pkg/services/auth/jwt"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl/sync"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/login/authinfoimpl"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	secretstest "github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

const (
	jwtHeaderName       = "X-JWT-Assertion"
	attackerSubject     = "subject-not-yet-linked"
	linkedSubject       = "subject-already-linked"
	victimLogin         = "org-admin"
	victimEmail         = "org-admin@example.test"
	victimName          = "Org Admin"
	bystanderLogin      = "bystander"
	bystanderEmail      = "bystander@example.test"
	attackerLogin       = "new-subject"
	attackerEmail       = "new-subject@example.test"
	attackerDisplayName = "New Subject"
)

// TestIntegrationJWTUnlinkedSubjectDoesNotTakeOverExistingUser exercises the
// product login path: a token signed by the configured JWT key is verified,
// then user sync resolves the identity. A subject that has no auth row must
// not be signed in as another user, and must not gain an auth connection to
// that user, when an email claim, username claim, or attribute path equals
// that user's email or login.
func TestIntegrationJWTUnlinkedSubjectDoesNotTakeOverExistingUser(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	signingKey := generateSigningKey(t)
	publicKeyFile := writePublicKeyPEM(t, signingKey)

	cases := []struct {
		name            string
		emailClaim      string
		usernameClaim   string
		emailPath       string
		usernamePath    string
		autoSignUp      bool
		urlLogin        bool
		bearerPrefix    bool
		linkSubject     bool
		claims          func() map[string]any
		wantExistingUsr bool
	}{
		{
			name:       "email claim matches org admin and email_verified is absent",
			emailClaim: "email",
			claims: func() map[string]any {
				return map[string]any{
					"sub":   attackerSubject,
					"email": victimEmail,
					"name":  attackerDisplayName,
				}
			},
		},
		{
			name:       "email claim matches org admin and email_verified is false",
			emailClaim: "email",
			claims: func() map[string]any {
				return map[string]any{
					"sub":            attackerSubject,
					"email":          victimEmail,
					"email_verified": false,
					"name":           attackerDisplayName,
				}
			},
		},
		{
			name:       "email claim matches org admin and email_verified is true",
			emailClaim: "email",
			claims: func() map[string]any {
				return map[string]any{
					"sub":            attackerSubject,
					"email":          victimEmail,
					"email_verified": true,
					"name":           attackerDisplayName,
				}
			},
		},
		{
			name:          "username claim matches org admin login after email misses",
			emailClaim:    "email",
			usernameClaim: "preferred_username",
			claims: func() map[string]any {
				return map[string]any{
					"sub":                attackerSubject,
					"email":              attackerEmail,
					"preferred_username": victimLogin,
					"name":               attackerDisplayName,
				}
			},
		},
		{
			name:          "username claim matches org admin email",
			usernameClaim: "preferred_username",
			claims: func() map[string]any {
				return map[string]any{
					"sub":                attackerSubject,
					"preferred_username": victimEmail,
					"name":               attackerDisplayName,
				}
			},
		},
		{
			name:      "email attribute path matches org admin",
			emailPath: "profile.email",
			claims: func() map[string]any {
				return map[string]any{
					"sub":     attackerSubject,
					"profile": map[string]any{"email": victimEmail},
					"name":    attackerDisplayName,
				}
			},
		},
		{
			name:         "username attribute path matches org admin login",
			usernamePath: "profile.login",
			claims: func() map[string]any {
				return map[string]any{
					"sub":     attackerSubject,
					"profile": map[string]any{"login": victimLogin},
					"name":    attackerDisplayName,
				}
			},
		},
		{
			name:       "auto sign up still does not attach a new subject to the org admin",
			emailClaim: "email",
			autoSignUp: true,
			claims: func() map[string]any {
				return map[string]any{
					"sub":                attackerSubject,
					"email":              victimEmail,
					"preferred_username": attackerLogin,
					"email_verified":     false,
					"name":               attackerDisplayName,
				}
			},
		},
		{
			name:         "url login token with an email claim matches org admin",
			emailClaim:   "email",
			urlLogin:     true,
			bearerPrefix: false,
			claims: func() map[string]any {
				return map[string]any{
					"sub":            attackerSubject,
					"email":          victimEmail,
					"email_verified": false,
					"name":           attackerDisplayName,
				}
			},
		},
		{
			name:         "bearer prefix on the header does not change email matching",
			emailClaim:   "email",
			bearerPrefix: true,
			claims: func() map[string]any {
				return map[string]any{
					"sub":            attackerSubject,
					"email":          victimEmail,
					"email_verified": false,
					"name":           attackerDisplayName,
				}
			},
		},
		{
			name:            "subject that is already linked still signs in as that user",
			emailClaim:      "email",
			usernameClaim:   "preferred_username",
			linkSubject:     true,
			wantExistingUsr: true,
			claims: func() map[string]any {
				return map[string]any{
					"sub":                linkedSubject,
					"email":              victimEmail,
					"preferred_username": victimLogin,
					"name":               victimName,
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			env := newJWTLoginEnv(t, publicKeyFile, tc.emailClaim, tc.usernameClaim, tc.emailPath, tc.usernamePath, tc.autoSignUp, tc.urlLogin)

			victim := createUser(t, ctx, env.userService, user.CreateUserCommand{
				Login:   victimLogin,
				Email:   victimEmail,
				Name:    victimName,
				IsAdmin: true,
			})
			require.Equal(t, org.RoleAdmin, orgRole(t, ctx, env.userService, victim))

			bystander := createUser(t, ctx, env.userService, user.CreateUserCommand{
				Login: bystanderLogin,
				Email: bystanderEmail,
				Name:  "Bystander",
			})

			subject := attackerSubject
			if tc.linkSubject {
				subject = linkedSubject
				require.NoError(t, env.authInfo.SetAuthInfo(ctx, &login.SetAuthInfoCommand{
					UserId:     victim.ID,
					UserUID:    victim.UID,
					AuthModule: login.JWTModule,
					AuthId:     subject,
				}))
			}

			token := signToken(t, signingKey, tc.claims())
			req := jwtRequest(t, token, tc.urlLogin, tc.bearerPrefix)
			identity, err := env.authn.Authenticate(ctx, &authn.Request{HTTPRequest: req})

			if tc.linkSubject {
				requireSubjectLinksUser(t, ctx, env.authInfo, victim.ID, subject)
			} else {
				requireSubjectUnlinked(t, ctx, env.authInfo, subject)
				requireUserHasNoJWTAuth(t, ctx, env.authInfo, victim.ID)
			}
			requireUserHasNoJWTAuth(t, ctx, env.authInfo, bystander.ID)
			requireUserUnchanged(t, ctx, env.userService, victim)
			requireUserUnchanged(t, ctx, env.userService, bystander)

			if tc.wantExistingUsr {
				require.NoError(t, err)
				require.NotNil(t, identity)
				gotID, idErr := identity.GetInternalID()
				require.NoError(t, idErr)
				require.Equal(t, victim.ID, gotID)
				require.Equal(t, org.RoleAdmin, identity.GetOrgRole())
				require.NotNil(t, identity.IsGrafanaAdmin)
				require.True(t, *identity.IsGrafanaAdmin)
				return
			}

			if err == nil && identity != nil {
				gotID, _ := identity.GetInternalID()
				t.Fatalf("unlinked subject %q was signed in as user %d (%s) with org role %s; login must be refused and no auth connection stored",
					subject, gotID, identity.Login, identity.GetOrgRole())
			}
			require.Error(t, err)
			require.Nil(t, identity)
			_, lookupErr := env.userService.GetByLogin(ctx, &user.GetUserByLoginQuery{LoginOrEmail: attackerLogin})
			require.ErrorIs(t, lookupErr, user.ErrUserNotFound)
			if tc.emailClaim == "" && tc.emailPath == "" {
				_, emailErr := env.userService.GetByEmail(ctx, &user.GetUserByEmailQuery{Email: attackerEmail})
				require.ErrorIs(t, emailErr, user.ErrUserNotFound)
			}
		})
	}
}

type jwtLoginEnv struct {
	authn       *authnimpl.Service
	userService user.Service
	authInfo    login.AuthInfoService
}

func newJWTLoginEnv(t *testing.T, publicKeyFile, emailClaim, usernameClaim, emailPath, usernamePath string, autoSignUp, urlLogin bool) jwtLoginEnv {
	t.Helper()

	sqlStore, cfg := db.InitTestDBWithCfg(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	cfg.JWTAuth.Enabled = true
	cfg.JWTAuth.HeaderName = jwtHeaderName
	cfg.JWTAuth.EmailClaim = emailClaim
	cfg.JWTAuth.UsernameClaim = usernameClaim
	cfg.JWTAuth.EmailAttributePath = emailPath
	cfg.JWTAuth.UsernameAttributePath = usernamePath
	cfg.JWTAuth.AutoSignUp = autoSignUp
	cfg.JWTAuth.URLLogin = urlLogin
	cfg.JWTAuth.ExpectClaims = "{}"
	cfg.JWTAuth.KeyFile = publicKeyFile
	cfg.JWTAuth.SkipOrgRoleSync = true

	sql := legacysql.NewDatabaseProvider(sqlStore)
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)
	quotaService := quotaimpl.ProvideService(context.Background(), sql, cfgProvider)
	orgService, err := orgimpl.ProvideService(sql, cfg, quotaService)
	require.NoError(t, err)
	userService, err := userimpl.ProvideService(
		sql, orgService, cfg, teamtest.NewFakeService(), localcache.ProvideService(),
		tracing.InitializeTracerForTest(), quotaService, supportbundlestest.NewFakeBundleService(), nil,
	)
	require.NoError(t, err)

	authStore, err := authinfoimpl.ProvideStore(context.Background(), sql, secretstest.NewFakeSecretsService())
	require.NoError(t, err)
	authInfo := authinfoimpl.ProvideService(authStore, remotecache.NewFakeStore(t), secretstest.NewFakeSecretsService())

	jwtService, err := authjwt.ProvideService(cfg, remotecache.NewFakeStore(t))
	require.NoError(t, err)

	tracer := tracing.InitializeTracerForTest()
	authnService := authnimpl.ProvideService(cfg, tracer, nil, &usagestats.NoopUsageStats{}, nil, authInfo)
	authnService.RegisterClient(clients.ProvideJWT(
		jwtService,
		connectors.ProvideOrgRoleMapper(cfgProvider, orgService),
		cfg,
		tracer,
	))
	userSync := sync.ProvideUserSync(
		userService,
		authinfoimpl.ProvideOSSUserProtectionService(),
		authInfo,
		quotaService,
		tracer,
		featuremgmt.WithFeatures(),
		cfg,
		nil,
	)
	authnService.RegisterPostAuthHook(userSync.SyncUserHook, 10)
	authnService.RegisterPostAuthHook(userSync.FetchSyncedUserHook, 100)

	return jwtLoginEnv{authn: authnService, userService: userService, authInfo: authInfo}
}

func createUser(t *testing.T, ctx context.Context, userService user.Service, cmd user.CreateUserCommand) *user.User {
	t.Helper()
	created, err := userService.Create(ctx, &cmd)
	require.NoError(t, err)
	return created
}

func orgRole(t *testing.T, ctx context.Context, userService user.Service, usr *user.User) org.RoleType {
	t.Helper()
	signedIn, err := userService.GetSignedInUser(ctx, &user.GetSignedInUserQuery{UserID: usr.ID, OrgID: usr.OrgID})
	require.NoError(t, err)
	return signedIn.OrgRole
}

func requireSubjectUnlinked(t *testing.T, ctx context.Context, authInfo login.AuthInfoService, subject string) {
	t.Helper()
	info, err := authInfo.GetAuthInfo(ctx, &login.GetAuthInfoQuery{AuthModule: login.JWTModule, AuthId: subject})
	if err == nil {
		t.Fatalf("stored a jwt auth connection for subject %s on user %d; an unlinked subject must not be stored", subject, info.UserId)
	}
	require.ErrorIs(t, err, user.ErrUserNotFound)
	require.Nil(t, info)
}

func requireSubjectLinksUser(t *testing.T, ctx context.Context, authInfo login.AuthInfoService, userID int64, subject string) {
	t.Helper()
	info, err := authInfo.GetAuthInfo(ctx, &login.GetAuthInfoQuery{AuthModule: login.JWTModule, AuthId: subject})
	require.NoError(t, err)
	require.Equal(t, userID, info.UserId)
	require.Equal(t, subject, info.AuthId)
}

func requireUserHasNoJWTAuth(t *testing.T, ctx context.Context, authInfo login.AuthInfoService, userID int64) {
	t.Helper()
	info, err := authInfo.GetAuthInfo(ctx, &login.GetAuthInfoQuery{AuthModule: login.JWTModule, UserId: userID})
	require.ErrorIs(t, err, user.ErrUserNotFound)
	require.Nil(t, info)
}

func requireUserUnchanged(t *testing.T, ctx context.Context, userService user.Service, before *user.User) {
	t.Helper()
	after, err := userService.GetByID(ctx, &user.GetUserByIDQuery{ID: before.ID})
	require.NoError(t, err)
	require.Equal(t, before.Login, after.Login)
	require.Equal(t, before.Email, after.Email)
	require.Equal(t, before.Name, after.Name)
	require.Equal(t, before.IsAdmin, after.IsAdmin)
	require.Equal(t, before.OrgID, after.OrgID)
}

func jwtRequest(t *testing.T, token string, urlLogin, bearerPrefix bool) *http.Request {
	t.Helper()
	if urlLogin {
		req := httptest.NewRequest(http.MethodGet, "/login?auth_token="+url.QueryEscape(token), nil)
		return req
	}
	value := token
	if bearerPrefix {
		value = "Bearer " + token
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(jwtHeaderName, value)
	return req
}

func signToken(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func generateSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func writePublicKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "jwt-public-*.pem")
	require.NoError(t, err)
	require.NoError(t, pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	require.NoError(t, file.Close())
	return file.Name()
}
