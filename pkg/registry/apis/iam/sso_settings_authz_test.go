package iam

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8suser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"

	"github.com/grafana/authlib/types"
	iamv0 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	commonv1 "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	legacyiamv0 "github.com/grafana/grafana/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/registry/apis/iam/legacy"
	"github.com/grafana/grafana/pkg/registry/apis/iam/resourcepermission"
	"github.com/grafana/grafana/pkg/registry/apis/iam/sso"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	gfauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/apiserver/builder"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	secretsfakes "github.com/grafana/grafana/pkg/services/secrets/fakes"
	ssomodels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingsimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/storage/unified/apistore"
	"github.com/prometheus/client_golang/prometheus"
)

// Obvious placeholders. These are not credentials.
const (
	storedClientSecret = "placeholder-client-secret"
	systemClientSecret = "placeholder-system-client-secret"
	storedClientID     = "placeholder-client-id"
)

const ssoSettingsINI = `
app_mode = development

[server]
root_url = http://localhost:3000/

[sso_settings]
configurable_providers = github,generic_oauth,okta

[auth.generic_oauth]
enabled = true
client_id = placeholder-client-id
client_secret = placeholder-system-client-secret
auth_url = https://idp.example/auth
token_url = https://idp.example/token
api_url = https://idp.example/userinfo

[auth.github]
enabled = true
client_id = placeholder-client-id
client_secret = placeholder-system-client-secret
allowed_domains = kept.example

[auth.okta]
enabled = true
client_id = placeholder-client-id
client_secret = placeholder-system-client-secret
auth_url = https://idp.example/oauth/authorize
token_url = https://idp.example/oauth/token
api_url = https://idp.example/oauth/userinfo
`

// errSSOSettingsDenied is returned when the authorizer does not allow the request.
// The apiserver filter returns before the storage handler runs.
var errSSOSettingsDenied = errors.New("sso settings request denied")

func TestSSOSettingAuthorization(t *testing.T) {
	ac := acimpl.ProvideAccessControlTest()
	inProcess := ssoSettingsChainAuthorizer(t, ac)
	standalone := standaloneSSOAuthorizer(t, ac)

	viewer := ssoUser(identity.RoleViewer, false, map[string][]string{
		"dashboards:read": {"dashboards:*"},
	})
	orgAdmin := ssoUser(identity.RoleAdmin, false, map[string][]string{
		"dashboards:read": {"dashboards:*"},
	})
	serverAdmin := ssoUser(identity.RoleAdmin, true, nil)
	genericReader := ssoUser(identity.RoleViewer, false, map[string][]string{
		accesscontrol.ActionSettingsRead: {accesscontrol.ScopeSettingsOAuth(social.GenericOAuthProviderName)},
	})
	genericWriter := ssoUser(identity.RoleEditor, false, map[string][]string{
		accesscontrol.ActionSettingsRead:  {accesscontrol.ScopeSettingsOAuth(social.GenericOAuthProviderName)},
		accesscontrol.ActionSettingsWrite: {accesscontrol.ScopeSettingsOAuth(social.GenericOAuthProviderName)},
	})
	githubWriter := ssoUser(identity.RoleEditor, false, map[string][]string{
		accesscontrol.ActionSettingsRead:  {accesscontrol.ScopeSettingsOAuth(social.GitHubProviderName)},
		accesscontrol.ActionSettingsWrite: {accesscontrol.ScopeSettingsOAuth(social.GitHubProviderName)},
	})
	anonymous := &identity.StaticRequester{Type: types.TypeAnonymous, OrgID: 1, Namespace: "default", OrgRole: identity.RoleNone}

	reads := []string{utils.VerbGet, utils.VerbList, utils.VerbWatch}
	writes := []string{utils.VerbCreate, utils.VerbUpdate, utils.VerbPatch, utils.VerbDelete, utils.VerbDeleteCollection}

	authorizers := []struct {
		name string
		auth authorizer.Authorizer
	}{
		{name: "in-process", auth: inProcess},
		{name: "standalone", auth: standalone},
	}

	for _, az := range authorizers {
		t.Run(az.name, func(t *testing.T) {
			t.Run("anonymous is denied", func(t *testing.T) {
				decision, _, err := az.auth.Authorize(withSSOUser(anonymous), ssoAttrs(utils.VerbGet, social.GenericOAuthProviderName, anonymous))
				require.NoError(t, err)
				require.Equal(t, authorizer.DecisionDeny, decision)
			})

			t.Run("missing identity is denied", func(t *testing.T) {
				decision, _, err := az.auth.Authorize(context.Background(), ssoAttrs(utils.VerbGet, social.GenericOAuthProviderName, viewer))
				require.Error(t, err)
				require.Equal(t, authorizer.DecisionDeny, decision)
			})

			for _, verb := range append(append([]string{}, reads...), writes...) {
				verb := verb
				t.Run("viewer "+verb, func(t *testing.T) {
					requireDecision(t, az.auth, viewer, verb, social.GenericOAuthProviderName, authorizer.DecisionDeny)
				})
				t.Run("org admin without settings permission "+verb, func(t *testing.T) {
					requireDecision(t, az.auth, orgAdmin, verb, social.GenericOAuthProviderName, authorizer.DecisionDeny)
				})
				t.Run("server admin without settings permission "+verb, func(t *testing.T) {
					requireDecision(t, az.auth, serverAdmin, verb, social.GenericOAuthProviderName, authorizer.DecisionDeny)
				})
			}

			for _, verb := range reads {
				verb := verb
				t.Run("generic reader "+verb+" generic_oauth", func(t *testing.T) {
					name := social.GenericOAuthProviderName
					if verb == utils.VerbList {
						name = ""
					}
					requireDecision(t, az.auth, genericReader, verb, name, authorizer.DecisionAllow)
				})
				t.Run("generic reader "+verb+" github", func(t *testing.T) {
					if verb == utils.VerbList {
						t.Skip()
					}
					requireDecision(t, az.auth, genericReader, verb, social.GitHubProviderName, authorizer.DecisionDeny)
				})
			}

			for _, verb := range writes {
				verb := verb
				t.Run("generic reader "+verb, func(t *testing.T) {
					name := social.GenericOAuthProviderName
					if verb == utils.VerbCreate || verb == utils.VerbDeleteCollection {
						name = ""
					}
					requireDecision(t, az.auth, genericReader, verb, name, authorizer.DecisionDeny)
				})
				if verb == utils.VerbCreate || verb == utils.VerbDeleteCollection {
					// The collection request has no provider name. Whether that
					// verb is allowed is covered by the storage tests, which
					// refuse a write to a provider the caller cannot write.
					continue
				}
				t.Run("generic writer "+verb+" generic_oauth", func(t *testing.T) {
					requireDecision(t, az.auth, genericWriter, verb, social.GenericOAuthProviderName, authorizer.DecisionAllow)
				})
				t.Run("generic writer "+verb+" github", func(t *testing.T) {
					requireDecision(t, az.auth, genericWriter, verb, social.GitHubProviderName, authorizer.DecisionDeny)
				})
				t.Run("github writer "+verb+" generic_oauth", func(t *testing.T) {
					requireDecision(t, az.auth, githubWriter, verb, social.GenericOAuthProviderName, authorizer.DecisionDeny)
				})
			}
		})
	}
}

func TestSSOSettingFeatureToggleGatesStorage(t *testing.T) {
	store := sso.NewLegacyStore(nil, noop.NewTracerProvider().Tracer("test"))
	opts := builder.APIGroupOptions{StorageOptsRegister: func(schema.GroupResource, apistore.StorageOptions) {}}

	t.Run("disabled", func(t *testing.T) {
		info := &genericapiserver.APIGroupInfo{VersionedResourcesStorageMap: map[string]map[string]rest.Storage{}}
		builder := &IdentityAccessManagementAPIBuilder{
			features:       &Features{},
			ssoLegacyStore: store,
		}
		require.NoError(t, builder.UpdateAPIGroupInfo(info, opts))
		_, ok := info.VersionedResourcesStorageMap[legacyiamv0.VERSION][legacyiamv0.SSOSettingResourceInfo.StoragePath()]
		require.False(t, ok)
	})

	t.Run("enabled", func(t *testing.T) {
		info := &genericapiserver.APIGroupInfo{VersionedResourcesStorageMap: map[string]map[string]rest.Storage{}}
		builder := &IdentityAccessManagementAPIBuilder{
			features:       &Features{SSOSettingsAPI: true},
			ssoLegacyStore: store,
		}
		require.NoError(t, builder.UpdateAPIGroupInfo(info, opts))
		require.NotNil(t, info.VersionedResourcesStorageMap[legacyiamv0.VERSION][legacyiamv0.SSOSettingResourceInfo.StoragePath()])
	})
}

func TestViewerCannotRedirectGenericOAuthTokenURL(t *testing.T) {
	env := newSSOEnv(t)
	attacker := newTokenServer(t)
	defer attacker.Close()

	seed := env.redactedSettings(t, social.GenericOAuthProviderName)
	seed["client_secret"] = storedClientSecret
	env.mustUpsert(t, social.GenericOAuthProviderName, seed, env.writer(social.GenericOAuthProviderName))
	env.waitForTokenURL(t, env.generic, "https://idp.example/token")

	rewritten := cloneSettings(seed)
	rewritten["client_secret"] = setting.RedactedPassword
	rewritten["token_url"] = attacker.URL
	rewritten["auth_url"] = attacker.URL + "/auth"

	writer := env.writer(social.GenericOAuthProviderName)
	require.NoError(t, env.update(t, writer, social.GenericOAuthProviderName, rewritten))
	env.waitForTokenURL(t, env.generic, attacker.URL)
	_, _ = env.generic.Exchange(context.Background(), "placeholder-code")
	require.True(t, attacker.sawSecret.Load(), "authorized writer update did not post the stored client secret")
	attacker.sawSecret.Store(false)

	// Put the saved provider back, then repeat the same write as a viewer.
	restored := cloneSettings(seed)
	require.NoError(t, env.update(t, writer, social.GenericOAuthProviderName, restored))
	env.waitForTokenURL(t, env.generic, "https://idp.example/token")

	viewer := env.viewer()
	err := env.update(t, viewer, social.GenericOAuthProviderName, rewritten)
	require.ErrorIs(t, err, errSSOSettingsDenied)
	require.Equal(t, "https://idp.example/token", env.settingString(t, social.GenericOAuthProviderName, "token_url"))
	require.Equal(t, storedClientSecret, env.settingString(t, social.GenericOAuthProviderName, "client_secret"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = env.generic.Exchange(ctx, "placeholder-code")
	require.False(t, attacker.sawSecret.Load(), "viewer update posted the stored client secret")
}

func TestViewerCannotRewriteGitHubSettings(t *testing.T) {
	env := newSSOEnv(t)
	seed := env.redactedSettings(t, social.GitHubProviderName)
	seed["client_secret"] = storedClientSecret
	seed["allowed_domains"] = "kept.example"
	writer := env.writer(social.GitHubProviderName)
	env.mustUpsert(t, social.GitHubProviderName, seed, writer)

	rewritten := cloneSettings(env.redactedSettings(t, social.GitHubProviderName))
	rewritten["allowed_domains"] = "attacker.example"
	require.NoError(t, env.update(t, writer, social.GitHubProviderName, rewritten))
	require.Equal(t, "attacker.example", env.settingString(t, social.GitHubProviderName, "allowed_domains"))

	require.NoError(t, env.update(t, writer, social.GitHubProviderName, seed))
	err := env.update(t, env.viewer(), social.GitHubProviderName, rewritten)
	require.ErrorIs(t, err, errSSOSettingsDenied)
	require.Equal(t, "kept.example", env.settingString(t, social.GitHubProviderName, "allowed_domains"))
	require.Equal(t, storedClientSecret, env.settingString(t, social.GitHubProviderName, "client_secret"))
}

func TestViewerCannotDeleteOrCreateSSOSettings(t *testing.T) {
	env := newSSOEnv(t)
	seed := env.redactedSettings(t, social.GenericOAuthProviderName)
	seed["client_secret"] = storedClientSecret
	seed["allowed_domains"] = "kept.example"
	writer := env.writer(social.GenericOAuthProviderName)
	env.mustUpsert(t, social.GenericOAuthProviderName, seed, writer)

	err := env.delete(t, env.viewer(), social.GenericOAuthProviderName)
	require.ErrorIs(t, err, errSSOSettingsDenied)
	require.Equal(t, "kept.example", env.settingString(t, social.GenericOAuthProviderName, "allowed_domains"))

	okta := env.redactedSettings(t, social.OktaProviderName)
	okta["client_secret"] = setting.RedactedPassword
	okta["token_url"] = "https://attacker.example/token"
	err = env.create(t, env.viewer(), social.OktaProviderName, okta)
	require.ErrorIs(t, err, errSSOSettingsDenied)
	require.Equal(t, "https://idp.example/oauth/token", env.settingString(t, social.OktaProviderName, "token_url"))
}

func TestWriterCannotUpdateADifferentProvider(t *testing.T) {
	env := newSSOEnv(t)
	githubWriter := env.writer(social.GitHubProviderName)
	rewritten := cloneSettings(env.redactedSettings(t, social.GenericOAuthProviderName))
	rewritten["client_secret"] = setting.RedactedPassword
	rewritten["token_url"] = "https://attacker.example/token"

	err := env.update(t, githubWriter, social.GenericOAuthProviderName, rewritten)
	require.ErrorIs(t, err, errSSOSettingsDenied)
	require.Equal(t, "https://idp.example/token", env.settingString(t, social.GenericOAuthProviderName, "token_url"))
	require.Equal(t, systemClientSecret, env.settingString(t, social.GenericOAuthProviderName, "client_secret"))
}

func TestCreateDoesNotWriteAProviderTheCallerCannotWrite(t *testing.T) {
	env := newSSOEnv(t)
	githubWriter := env.writer(social.GitHubProviderName)
	rewritten := cloneSettings(env.redactedSettings(t, social.GenericOAuthProviderName))
	rewritten["client_secret"] = setting.RedactedPassword
	rewritten["token_url"] = "https://attacker.example/token"

	// Collection create has an empty name in the authorizer attributes. The
	// object name is the provider that would be stored.
	err := env.create(t, githubWriter, social.GenericOAuthProviderName, rewritten)
	require.Error(t, err)
	require.Equal(t, "https://idp.example/token", env.settingString(t, social.GenericOAuthProviderName, "token_url"))
	require.NotEqual(t, "https://attacker.example/token", env.settingString(t, social.GenericOAuthProviderName, "token_url"))
}

func TestUpdateDoesNotPersistADifferentProviderThanAuthorized(t *testing.T) {
	env := newSSOEnv(t)
	writer := env.writer(social.GenericOAuthProviderName)
	okta := cloneSettings(env.redactedSettings(t, social.OktaProviderName))
	okta["client_secret"] = setting.RedactedPassword
	okta["token_url"] = "https://attacker.example/token"

	// The request name is the provider the caller can write. The object names
	// a provider the caller cannot write.
	err := env.updateObject(t, writer, social.GenericOAuthProviderName, social.OktaProviderName, okta)
	require.Error(t, err)
	require.Equal(t, "https://idp.example/oauth/token", env.settingString(t, social.OktaProviderName, "token_url"))
	require.Equal(t, "https://idp.example/token", env.settingString(t, social.GenericOAuthProviderName, "token_url"))
}

func TestSettingsWriterCannotAssignGrafanaAdmin(t *testing.T) {
	env := newSSOEnv(t)
	writer := env.writer(social.GenericOAuthProviderName)
	seed := env.redactedSettings(t, social.GenericOAuthProviderName)
	seed["client_secret"] = storedClientSecret
	env.mustUpsert(t, social.GenericOAuthProviderName, seed, writer)

	rewritten := cloneSettings(env.redactedSettings(t, social.GenericOAuthProviderName))
	rewritten["allow_assign_grafana_admin"] = true
	err := env.update(t, writer, social.GenericOAuthProviderName, rewritten)
	require.Error(t, err)
	require.Equal(t, false, env.settingValue(t, social.GenericOAuthProviderName, "allow_assign_grafana_admin"))

	admin := env.writer(social.GenericOAuthProviderName)
	admin.IsGrafanaAdmin = true
	require.NoError(t, env.update(t, admin, social.GenericOAuthProviderName, rewritten))
	require.Equal(t, true, env.settingValue(t, social.GenericOAuthProviderName, "allow_assign_grafana_admin"))
}

func TestListDoesNotReturnProvidersTheCallerCannotRead(t *testing.T) {
	env := newSSOEnv(t)
	reader := env.reader(social.GenericOAuthProviderName)
	names, err := env.list(t, reader)
	require.NoError(t, err)
	for _, name := range names {
		require.Equal(t, social.GenericOAuthProviderName, name)
	}
}

type tokenServer struct {
	*httptest.Server
	sawSecret atomic.Bool
}

func newTokenServer(t *testing.T) *tokenServer {
	t.Helper()
	ts := &tokenServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCarriesSecret(r, storedClientSecret) {
			ts.sawSecret.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"placeholder-token","token_type":"bearer","expires_in":3600}`)
	}))
	return ts
}

func requestCarriesSecret(r *http.Request, secret string) bool {
	if _, password, ok := r.BasicAuth(); ok && password == secret {
		return true
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	return r.PostForm.Get("client_secret") == secret
}

type ssoEnv struct {
	t         *testing.T
	svc       *ssosettingsimpl.Service
	storage   ssoREST
	authz     authorizer.Authorizer
	generic   *connectors.SocialGenericOAuth
	namespace string
}

type ssoREST interface {
	rest.Getter
	rest.Lister
	rest.Creater
	rest.Updater
	rest.GracefulDeleter
}

func newSSOEnv(t *testing.T) *ssoEnv {
	t.Helper()
	cfg, err := setting.NewCfgFromBytesWithoutJSValidation([]byte(ssoSettingsINI))
	require.NoError(t, err)
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	sqlStore := db.NewTestStore(t)
	svc := ssosettingsimpl.ProvideReadOnlyService(cfgProvider, legacysql.NewDatabaseProvider(sqlStore), secretsfakes.NewFakeSecretsService())
	mapper := connectors.ProvideOrgRoleMapper(cfgProvider, nil)
	features := featuremgmt.WithFeatures()
	generic, err := connectors.NewGenericOAuthProvider(context.Background(), &social.OAuthInfo{
		ClientId:     storedClientID,
		ClientSecret: systemClientSecret,
		AuthUrl:      "https://idp.example/auth",
		TokenUrl:     "https://idp.example/token",
		ApiUrl:       "https://idp.example/userinfo",
		Enabled:      true,
	}, cfgProvider, mapper, svc, features, nil)
	require.NoError(t, err)
	_, err = connectors.NewGitHubProvider(context.Background(), &social.OAuthInfo{
		ClientId: storedClientID, ClientSecret: systemClientSecret, Enabled: true,
	}, cfgProvider, mapper, svc, features)
	require.NoError(t, err)
	_, err = connectors.NewOktaProvider(context.Background(), &social.OAuthInfo{
		ClientId: storedClientID, ClientSecret: systemClientSecret, Enabled: true,
		AuthUrl: "https://idp.example/oauth/authorize", TokenUrl: "https://idp.example/oauth/token", ApiUrl: "https://idp.example/oauth/userinfo",
	}, cfgProvider, mapper, svc, features, nil)
	require.NoError(t, err)

	ac := acimpl.ProvideAccessControlTest()
	legacyStore := sso.NewLegacyStore(svc, noop.NewTracerProvider().Tracer("sso-settings-authz"))
	info := &genericapiserver.APIGroupInfo{VersionedResourcesStorageMap: map[string]map[string]rest.Storage{}}
	groupBuilder := &IdentityAccessManagementAPIBuilder{
		features:       &Features{SSOSettingsAPI: true},
		ssoLegacyStore: legacyStore,
		ac:             ac,
		authorizer:     ssoSettingsChainAuthorizer(t, ac),
	}
	require.NoError(t, groupBuilder.UpdateAPIGroupInfo(info, builder.APIGroupOptions{
		StorageOptsRegister: func(schema.GroupResource, apistore.StorageOptions) {},
	}))
	storage, ok := info.VersionedResourcesStorageMap[legacyiamv0.VERSION][legacyiamv0.SSOSettingResourceInfo.StoragePath()].(ssoREST)
	require.True(t, ok)

	return &ssoEnv{
		t:         t,
		svc:       svc,
		storage:   storage,
		authz:     groupBuilder.GetAuthorizer(),
		generic:   generic,
		namespace: "default",
	}
}

func (e *ssoEnv) viewer() *identity.StaticRequester {
	return ssoUser(identity.RoleViewer, false, map[string][]string{
		"dashboards:read": {"dashboards:*"},
	})
}

func (e *ssoEnv) reader(provider string) *identity.StaticRequester {
	return ssoUser(identity.RoleViewer, false, map[string][]string{
		accesscontrol.ActionSettingsRead: {accesscontrol.ScopeSettingsOAuth(provider)},
	})
}

func (e *ssoEnv) writer(provider string) *identity.StaticRequester {
	return ssoUser(identity.RoleEditor, false, map[string][]string{
		accesscontrol.ActionSettingsRead:  {accesscontrol.ScopeSettingsOAuth(provider)},
		accesscontrol.ActionSettingsWrite: {accesscontrol.ScopeSettingsOAuth(provider)},
	})
}

func (e *ssoEnv) mustUpsert(t *testing.T, provider string, settings map[string]any, user *identity.StaticRequester) {
	t.Helper()
	require.NoError(t, e.svc.Upsert(withSSOUser(user), &ssomodels.SSOSettings{
		Provider: provider,
		Settings: cloneSettings(settings),
	}, user))
}

func (e *ssoEnv) redactedSettings(t *testing.T, provider string) map[string]any {
	t.Helper()
	got, err := e.svc.GetForProviderWithRedactedSecrets(context.Background(), provider)
	require.NoError(t, err)
	return cloneSettings(got.Settings)
}

func (e *ssoEnv) settingString(t *testing.T, provider, key string) string {
	t.Helper()
	value := e.settingValue(t, provider, key)
	text, ok := value.(string)
	require.Truef(t, ok, "setting %s is %T", key, value)
	return text
}

func (e *ssoEnv) settingValue(t *testing.T, provider, key string) any {
	t.Helper()
	got, err := e.svc.GetForProvider(context.Background(), provider)
	require.NoError(t, err)
	return got.Settings[key]
}

func (e *ssoEnv) update(t *testing.T, user *identity.StaticRequester, provider string, settings map[string]any) error {
	t.Helper()
	return e.updateObject(t, user, provider, provider, settings)
}

func (e *ssoEnv) updateObject(t *testing.T, user *identity.StaticRequester, requestName, objectName string, settings map[string]any) error {
	t.Helper()
	ctx := withSSOUser(user)
	if err := e.authorize(ctx, user, utils.VerbUpdate, requestName); err != nil {
		return err
	}
	obj := ssoObject(e.namespace, objectName, settings)
	_, _, err := e.storage.Update(ctx, requestName, rest.DefaultUpdatedObjectInfo(obj), rest.ValidateAllObjectFunc, nil, false, &metav1.UpdateOptions{})
	return err
}

func (e *ssoEnv) create(t *testing.T, user *identity.StaticRequester, provider string, settings map[string]any) error {
	t.Helper()
	ctx := withSSOUser(user)
	// A collection POST has no object name in the authorizer attributes.
	if err := e.authorize(ctx, user, utils.VerbCreate, ""); err != nil {
		return err
	}
	_, err := e.storage.Create(ctx, ssoObject(e.namespace, provider, settings), rest.ValidateAllObjectFunc, &metav1.CreateOptions{})
	return err
}

func (e *ssoEnv) delete(t *testing.T, user *identity.StaticRequester, provider string) error {
	t.Helper()
	ctx := withSSOUser(user)
	if err := e.authorize(ctx, user, utils.VerbDelete, provider); err != nil {
		return err
	}
	_, _, err := e.storage.Delete(ctx, provider, rest.ValidateAllObjectFunc, &metav1.DeleteOptions{})
	return err
}

func (e *ssoEnv) list(t *testing.T, user *identity.StaticRequester) ([]string, error) {
	t.Helper()
	ctx := withSSOUser(user)
	if err := e.authorize(ctx, user, utils.VerbList, ""); err != nil {
		if errors.Is(err, errSSOSettingsDenied) {
			return nil, nil
		}
		return nil, err
	}
	obj, err := e.storage.List(ctx, nil)
	if err != nil {
		return nil, err
	}
	list, ok := obj.(*legacyiamv0.SSOSettingList)
	require.True(t, ok)
	names := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		names = append(names, item.Name)
	}
	return names, nil
}

func (e *ssoEnv) authorize(ctx context.Context, user *identity.StaticRequester, verb, name string) error {
	decision, _, err := e.authz.Authorize(ctx, ssoAttrs(verb, name, user))
	if err != nil {
		return err
	}
	if decision != authorizer.DecisionAllow {
		return errSSOSettingsDenied
	}
	return nil
}

func (e *ssoEnv) waitForTokenURL(t *testing.T, connector *connectors.SocialGenericOAuth, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		info := connector.GetOAuthInfo()
		return info != nil && info.TokenUrl == want
	}, 2*time.Second, 20*time.Millisecond)
}

func ssoSettingsChainAuthorizer(t *testing.T, ac accesscontrol.AccessControl) authorizer.Authorizer {
	t.Helper()
	client := newLegacyAccessClient(ac, legacy.NewLegacySQLStores(legacysql.NewDatabaseProvider(nil)))
	iamAuth := newIAMAuthorizer(
		client,
		client,
		&NoopApiInstaller[*iamv0.Role]{ResourceInfo: iamv0.RoleInfo},
		&NoopApiInstaller[*iamv0.GlobalRole]{ResourceInfo: iamv0.GlobalRoleInfo},
		&NoopApiInstaller[*iamv0.TeamLBACRule]{ResourceInfo: iamv0.TeamLBACRuleInfo},
		&NoopApiInstaller[*iamv0.RoleBinding]{ResourceInfo: iamv0.RoleBindingInfo},
	)
	chain := gfauthorizer.NewGrafanaBuiltInSTAuthorizer()
	chain.Register(legacyiamv0.SchemeGroupVersion, iamAuth)
	return chain
}

func standaloneSSOAuthorizer(t *testing.T, ac accesscontrol.AccessControl) authorizer.Authorizer {
	t.Helper()
	client := newLegacyAccessClient(ac, legacy.NewLegacySQLStores(legacysql.NewDatabaseProvider(nil)))
	groupBuilder := NewAPIService(
		client,
		nil,
		legacysql.NewDatabaseProvider(nil),
		&NoopApiInstaller[*iamv0.RoleBinding]{ResourceInfo: iamv0.RoleBindingInfo},
		&NoopApiInstaller[*iamv0.Role]{ResourceInfo: iamv0.RoleInfo},
		&NoopApiInstaller[*iamv0.GlobalRole]{ResourceInfo: iamv0.GlobalRoleInfo},
		&NoopApiInstaller[*iamv0.TeamLBACRule]{ResourceInfo: iamv0.TeamLBACRuleInfo},
		nil,
		prometheus.NewRegistry(),
		nil,
		nil,
		tracing.InitializeTracerForTest(),
		resourcepermission.NewMappersRegistry(),
		nil,
	)
	return groupBuilder.GetAuthorizer()
}

func requireDecision(t *testing.T, authz authorizer.Authorizer, user *identity.StaticRequester, verb, name string, want authorizer.Decision) {
	t.Helper()
	decision, reason, err := authz.Authorize(withSSOUser(user), ssoAttrs(verb, name, user))
	require.NoError(t, err)
	require.Equalf(t, want, decision, "verb %s name %q reason %s", verb, name, reason)
}

func ssoAttrs(verb, name string, user identity.Requester) authorizer.AttributesRecord {
	return authorizer.AttributesRecord{
		User:            &k8suser.DefaultInfo{Name: user.GetLogin(), Groups: user.GetGroups()},
		Verb:            verb,
		APIGroup:        legacyiamv0.SchemeGroupVersion.Group,
		APIVersion:      legacyiamv0.SchemeGroupVersion.Version,
		Resource:        legacyiamv0.SSOSettingResourceInfo.GetName(),
		Name:            name,
		Namespace:       "default",
		ResourceRequest: true,
	}
}

func ssoUser(role identity.RoleType, serverAdmin bool, permissions map[string][]string) *identity.StaticRequester {
	return &identity.StaticRequester{
		Type:           types.TypeUser,
		UserID:         7,
		UserUID:        "user-7",
		OrgID:          1,
		OrgRole:        role,
		Login:          "user-7",
		Namespace:      "default",
		IsGrafanaAdmin: serverAdmin,
		Permissions:    map[int64]map[string][]string{1: permissions},
	}
}

func withSSOUser(user *identity.StaticRequester) context.Context {
	ctx := identity.WithRequester(context.Background(), user)
	return k8srequest.WithNamespace(ctx, user.GetNamespace())
}

func ssoObject(namespace, name string, settings map[string]any) *legacyiamv0.SSOSetting {
	return &legacyiamv0.SSOSetting{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: legacyiamv0.SSOSettingSpec{
			Settings: commonv1.Unstructured{Object: cloneSettings(settings)},
		},
	}
}

func cloneSettings(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
