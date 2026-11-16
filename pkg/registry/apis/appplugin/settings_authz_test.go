package appplugin

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	common "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	apppluginV0 "github.com/grafana/grafana/pkg/apis/appplugin/v0alpha1"
	grafanarest "github.com/grafana/grafana/pkg/apiserver/rest"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/plugins"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	authorizerpkg "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/org"
	pluginaccesscontrol "github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	pluginsettingssvc "github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings/service"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretsManager "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql/dualwrite"
	"github.com/grafana/grafana/pkg/storage/unified/migrations"
)

const (
	pluginA = "plugin-a"
	pluginB = "plugin-b"
	pluginC = "plugin-c"

	orgNamespace = "default"
	otherOrg     = "org-2"
	upstreamURL  = "https://upstream.example"
	collectorURL = "https://collector.example"
	secureField  = "token"
	placeholder  = "placeholder-value"
)

// fixedRolePermissions is the permission set a basic org role receives from
// DeclareRBACRoles, including grants expanded onto parent roles.
func fixedRolePermissions(role org.RoleType, extra ...ac.Permission) map[string][]string {
	granted := map[string][]string{}
	for _, registration := range pluginaccesscontrol.FixedRoleRegistrations(false) {
		if _, ok := ac.BuiltInRolesWithParents(registration.Grants)[string(role)]; !ok {
			continue
		}
		for _, permission := range registration.Role.Permissions {
			granted[permission.Action] = append(granted[permission.Action], permission.Scope)
		}
	}
	for _, permission := range extra {
		granted[permission.Action] = append(granted[permission.Action], permission.Scope)
	}
	return granted
}

func requester(id int64, role org.RoleType, permissions map[string][]string) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:      id,
		OrgID:       1,
		OrgRole:     role,
		Namespace:   orgNamespace,
		Login:       string(role),
		Name:        string(role),
		Permissions: map[int64]map[string][]string{1: permissions},
	}
}

func requestContext(user identity.Requester) context.Context {
	ctx := identity.WithRequester(context.Background(), user)
	return k8srequest.WithNamespace(ctx, orgNamespace)
}

func settingsAttributes(pluginID, verb string) authorizer.AttributesRecord {
	return authorizer.AttributesRecord{
		Verb:            verb,
		Namespace:       orgNamespace,
		APIGroup:        pluginID,
		APIVersion:      apppluginV0.VERSION,
		Resource:        apppluginV0.APP_RESOURCE_NAME,
		Name:            apppluginV0.INSTANCE_NAME,
		ResourceRequest: true,
	}
}

func newBuilder(pluginID string, access ac.AccessControl) *AppPluginAPIBuilder {
	return &AppPluginAPIBuilder{
		group:         pluginID,
		pluginJSON:    plugins.JSONData{ID: pluginID, Type: plugins.TypeApp},
		accessChecker: NewPluginAccessChecker(access),
	}
}

// embeddedAuthorizer is the chain the in-process API server installs: the
// per-group authorizer runs before the org-role fallback.
func embeddedAuthorizer(t *testing.T, builders map[string]*AppPluginAPIBuilder) authorizer.Authorizer {
	t.Helper()
	chain := authorizerpkg.NewGrafanaBuiltInSTAuthorizer()
	for pluginID, builder := range builders {
		chain.Register(schema.GroupVersion{Group: pluginID, Version: apppluginV0.VERSION}, builder.GetAuthorizer())
	}
	return chain
}

// routerAuthorizer is the chain pluginroute.NewHandler installs for one plugin
// when grafana.useRouterMiddleware is on. It has no org-role fallback.
func routerAuthorizer(t *testing.T, builder *AppPluginAPIBuilder) authorizer.Authorizer {
	t.Helper()
	chain, err := union.New(
		union.NamedAuthorizer{AuthorizerName: "impersonation", Authorizer: authorizerpkg.NewImpersonationAuthorizer()},
		union.NamedAuthorizer{AuthorizerName: "namespace", Authorizer: authorizerpkg.NewNamespaceAuthorizer()},
		union.NamedAuthorizer{AuthorizerName: "plugin", Authorizer: builder.GetAuthorizer()},
	)
	require.NoError(t, err)
	return chain
}

func TestViewerCannotRewriteAppPluginSettings(t *testing.T) {
	access := acimpl.ProvideAccessControlTest()
	builders := map[string]*AppPluginAPIBuilder{
		pluginA: newBuilder(pluginA, access),
		pluginB: newBuilder(pluginB, access),
	}
	embedded := embeddedAuthorizer(t, builders)
	routers := map[string]authorizer.Authorizer{
		pluginA: routerAuthorizer(t, builders[pluginA]),
		pluginB: routerAuthorizer(t, builders[pluginB]),
	}

	viewer := requester(2, org.RoleViewer, fixedRolePermissions(org.RoleViewer))
	editor := requester(3, org.RoleEditor, fixedRolePermissions(org.RoleEditor))
	// Same app-access grant as a viewer, plus plugins:write for one plugin only.
	scoped := requester(4, org.RoleViewer, fixedRolePermissions(org.RoleViewer, ac.Permission{
		Action: pluginaccesscontrol.ActionWrite,
		Scope:  pluginaccesscontrol.ScopeProvider.GetResourceScope(pluginA),
	}))
	admin := requester(5, org.RoleAdmin, fixedRolePermissions(org.RoleAdmin))

	writeVerbs := []string{"create", "update", "patch", "delete"}
	readVerbs := []string{"get", "list", "watch"}

	chains := []struct {
		name    string
		forPlug func(pluginID string) authorizer.Authorizer
	}{
		{name: "embedded", forPlug: func(string) authorizer.Authorizer { return embedded }},
		{name: "router", forPlug: func(pluginID string) authorizer.Authorizer { return routers[pluginID] }},
	}

	for _, chain := range chains {
		t.Run(chain.name, func(t *testing.T) {
			for _, pluginID := range []string{pluginA, pluginB} {
				authz := chain.forPlug(pluginID)
				for _, caller := range []*user.SignedInUser{viewer, editor} {
					t.Run(string(caller.OrgRole)+"/"+pluginID, func(t *testing.T) {
						ctx := requestContext(caller)
						for _, verb := range readVerbs {
							decision, _, err := authz.Authorize(ctx, settingsAttributes(pluginID, verb))
							require.NoError(t, err)
							require.Equal(t, authorizer.DecisionAllow, decision, "verb %s", verb)
						}
						for _, verb := range writeVerbs {
							decision, reason, err := authz.Authorize(ctx, settingsAttributes(pluginID, verb))
							require.NoError(t, err)
							require.Equal(t, authorizer.DecisionDeny, decision, "verb %s reason %s", verb, reason)
						}
					})
				}

				t.Run("scoped-writer/"+pluginID, func(t *testing.T) {
					ctx := requestContext(scoped)
					want := authorizer.DecisionDeny
					if pluginID == pluginA {
						want = authorizer.DecisionAllow
					}
					for _, verb := range writeVerbs {
						decision, reason, err := authz.Authorize(ctx, settingsAttributes(pluginID, verb))
						require.NoError(t, err)
						require.Equal(t, want, decision, "verb %s reason %s", verb, reason)
					}
				})

				t.Run("admin/"+pluginID, func(t *testing.T) {
					ctx := requestContext(admin)
					for _, verb := range writeVerbs {
						decision, reason, err := authz.Authorize(ctx, settingsAttributes(pluginID, verb))
						require.NoError(t, err)
						require.Equal(t, authorizer.DecisionAllow, decision, "verb %s reason %s", verb, reason)
					}
				})
			}

			t.Run("other org namespace is denied", func(t *testing.T) {
				ctx := requestContext(admin)
				attr := settingsAttributes(pluginA, "update")
				attr.Namespace = otherOrg
				decision, _, err := chain.forPlug(pluginA).Authorize(ctx, attr)
				require.NoError(t, err)
				require.Equal(t, authorizer.DecisionDeny, decision)
			})
		})
	}

	t.Run("legacy storage", func(t *testing.T) {
		store := db.NewTestStore(t)
		secretsSvc := secretsManager.SetupTestService(t, fakes.NewFakeSecretsStore())
		settingsSvc := pluginsettingssvc.ProvideService(store, secretsSvc)
		cfg := setting.NewCfg()
		status, err := migrations.ProvideMigrationStatusReader(store, cfg, migrations.NewMigrationRegistry(), prometheus.NewRegistry())
		require.NoError(t, err)
		dual, err := dualwrite.ProvideService(cfg, dualwrite.NewFakeMigrator(), status, prometheus.NewRegistry())
		require.NoError(t, err)

		seed := func(t *testing.T) {
			t.Helper()
			for _, args := range []*pluginsettings.UpdateArgs{
				{PluginID: pluginA, OrgID: 1, Enabled: true, Pinned: true, JSONData: map[string]any{"url": upstreamURL}, SecureJSONData: map[string]string{secureField: placeholder}},
				{PluginID: pluginB, OrgID: 1, Enabled: true, Pinned: true, JSONData: map[string]any{"url": upstreamURL}, SecureJSONData: map[string]string{secureField: placeholder}},
				{PluginID: pluginA, OrgID: 2, Enabled: true, Pinned: true, JSONData: map[string]any{"url": upstreamURL}, SecureJSONData: map[string]string{secureField: placeholder}},
			} {
				require.NoError(t, settingsSvc.UpdatePluginSetting(context.Background(), args))
			}
		}

		storageFor := func(t *testing.T, pluginID string) grafanarest.Storage {
			t.Helper()
			legacy := NewLegacySettingsStore(pluginID, pluginID, settingsSvc)
			got, err := dual.NewStorage(schema.GroupResource{Group: pluginID, Resource: apppluginV0.APP_RESOURCE_NAME}, legacy, nil)
			require.NoError(t, err)
			require.Same(t, legacy, got)
			return got
		}

		attack := &apppluginV0.Settings{
			ObjectMeta: metav1.ObjectMeta{
				Name: apppluginV0.INSTANCE_NAME,
				// The body names a different org than the authorized request namespace.
				Namespace: otherOrg,
			},
			Spec: apppluginV0.SettingsSpec{
				Enabled:  false,
				Pinned:   false,
				JsonData: common.Unstructured{Object: map[string]any{"url": collectorURL}},
			},
		}

		requireUnchanged := func(t *testing.T) {
			t.Helper()
			for _, want := range []struct {
				pluginID string
				orgID    int64
			}{{pluginA, 1}, {pluginB, 1}, {pluginA, 2}} {
				got, err := settingsSvc.GetPluginSettingByPluginID(context.Background(), &pluginsettings.GetByPluginIDArgs{
					PluginID: want.pluginID, OrgID: want.orgID,
				})
				require.NoError(t, err)
				require.Equal(t, want.pluginID, got.PluginID)
				require.Equal(t, want.orgID, got.OrgID)
				require.True(t, got.Enabled)
				require.Equal(t, map[string]any{"url": upstreamURL}, got.JSONData)
				require.Equal(t, placeholder, settingsSvc.DecryptedValues(got)[secureField])
			}
			_, err := settingsSvc.GetPluginSettingByPluginID(context.Background(), &pluginsettings.GetByPluginIDArgs{
				PluginID: pluginC, OrgID: 1,
			})
			require.ErrorIs(t, err, pluginsettings.ErrPluginSettingNotFound)
		}

		storages := map[string]grafanarest.Storage{
			pluginA: storageFor(t, pluginA),
			pluginB: storageFor(t, pluginB),
			pluginC: storageFor(t, pluginC),
		}

		for _, caller := range []*user.SignedInUser{viewer, editor} {
			t.Run(string(caller.OrgRole), func(t *testing.T) {
				seed(t)
				ctx := requestContext(caller)
				for _, pluginID := range []string{pluginA, pluginB} {
					_, err := storages[pluginID].Create(ctx, attack.DeepCopyObject(), nil, nil)
					require.Error(t, err)
					require.Truef(t, apierrors.IsForbidden(err), "create: %v", err)

					_, _, err = storages[pluginID].Update(ctx, apppluginV0.INSTANCE_NAME,
						rest.DefaultUpdatedObjectInfo(attack.DeepCopyObject()), nil, nil, false, nil)
					require.Error(t, err)
					require.Truef(t, apierrors.IsForbidden(err), "update: %v", err)
				}
				_, err := storages[pluginC].Create(ctx, attack.DeepCopyObject(), nil, nil)
				require.Error(t, err)
				require.Truef(t, apierrors.IsForbidden(err), "create missing: %v", err)
				requireUnchanged(t)
			})
		}

		t.Run("scoped writer updates only the authorized plugin", func(t *testing.T) {
			seed(t)
			ctx := requestContext(scoped)

			_, _, err := storages[pluginB].Update(ctx, apppluginV0.INSTANCE_NAME,
				rest.DefaultUpdatedObjectInfo(attack.DeepCopyObject()), nil, nil, false, nil)
			require.Error(t, err)
			require.Truef(t, apierrors.IsForbidden(err), "plugin-b: %v", err)

			obj, _, err := storages[pluginA].Update(ctx, apppluginV0.INSTANCE_NAME,
				rest.DefaultUpdatedObjectInfo(attack.DeepCopyObject()), nil, nil, false, nil)
			require.NoError(t, err)
			saved := obj.(*apppluginV0.Settings)
			require.Equal(t, collectorURL, saved.Spec.JsonData.Object["url"])
			require.False(t, saved.Spec.Enabled)

			got, err := settingsSvc.GetPluginSettingByPluginID(context.Background(), &pluginsettings.GetByPluginIDArgs{
				PluginID: pluginA, OrgID: 1,
			})
			require.NoError(t, err)
			require.Equal(t, pluginA, got.PluginID)
			require.Equal(t, int64(1), got.OrgID)
			require.False(t, got.Enabled)
			require.Equal(t, map[string]any{"url": collectorURL}, got.JSONData)
			require.Equal(t, placeholder, settingsSvc.DecryptedValues(got)[secureField])

			for _, want := range []struct {
				pluginID string
				orgID    int64
			}{{pluginB, 1}, {pluginA, 2}} {
				other, err := settingsSvc.GetPluginSettingByPluginID(context.Background(), &pluginsettings.GetByPluginIDArgs{
					PluginID: want.pluginID, OrgID: want.orgID,
				})
				require.NoError(t, err)
				require.Equal(t, want.pluginID, other.PluginID)
				require.Equal(t, want.orgID, other.OrgID)
				require.True(t, other.Enabled)
				require.Equal(t, map[string]any{"url": upstreamURL}, other.JSONData)
				require.Equal(t, placeholder, settingsSvc.DecryptedValues(other)[secureField])
			}
		})
	})
}
