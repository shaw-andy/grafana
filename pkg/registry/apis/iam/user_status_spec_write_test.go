package iam

import (
	"context"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/admission"
	k8suser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	k8srest "k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/storagebackend"

	authnlib "github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/authz"
	authlib "github.com/grafana/authlib/types"
	iamv0 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	grafanarest "github.com/grafana/grafana/pkg/apiserver/rest"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	iamuser "github.com/grafana/grafana/pkg/registry/apis/iam/user"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/apiserver/builder"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql/dualwrite"
	"github.com/grafana/grafana/pkg/storage/unified/apistore"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
)

// basicRoleAccessClient follows authz.ClientImpl.Check at authlib v0.0.0-20260814184937-0d62418c2815:
// a service call is allowed from the token alone, and a user call continues only when the
// token's delegated permissions cover the verb. The user half uses the built-in role grants
// the RBAC service expands: mapper verb to action, then wildcard scope collapse.
type basicRoleAccessClient struct{}

func (basicRoleAccessClient) Check(_ context.Context, id authlib.AuthInfo, req authlib.CheckRequest, _ string) (authlib.CheckResponse, error) {
	if !authlib.NamespaceMatches(id.GetNamespace(), req.Namespace) {
		return authlib.CheckResponse{Allowed: false}, authlib.ErrNamespaceMismatch
	}
	service := authz.CheckServicePermissions(id, req.Group, req.Resource, req.Verb)
	if service.ServiceCall {
		return authlib.CheckResponse{Allowed: service.Allowed}, nil
	}
	if !service.Allowed {
		return authlib.CheckResponse{Allowed: false}, nil
	}
	return authlib.CheckResponse{Allowed: basicRoleAllows(id, req)}, nil
}

// sessionAccessClaims is what AccessClaimsHook attaches when a session has no access token.
func sessionAccessClaims() *authnlib.Claims[authnlib.AccessTokenClaims] {
	return &authnlib.Claims[authnlib.AccessTokenClaims]{
		Rest: authnlib.AccessTokenClaims{
			DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
		},
	}
}

func (basicRoleAccessClient) Compile(context.Context, authlib.AuthInfo, authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return nil, authlib.NoopZookie{}, nil
}

func (basicRoleAccessClient) BatchCheck(context.Context, authlib.AuthInfo, authlib.BatchCheckRequest) (authlib.BatchCheckResponse, error) {
	return authlib.BatchCheckResponse{}, nil
}

func basicRoleAllows(id authlib.AuthInfo, req authlib.CheckRequest) bool {
	requester, ok := id.(identity.Requester)
	if !ok {
		return false
	}
	mapping, ok := rbac.NewMapperRegistry().Get(req.Group, req.Resource, req.Subresource)
	if !ok {
		return false
	}
	action, ok := mapping.Action(req.Verb)
	if !ok {
		return false
	}
	scopeMap := scopeMapForAction(permissionsForBasicRole(requester.GetOrgRole(), requester.GetIsGrafanaAdmin()), action)
	if req.Name == "" && req.Verb != utils.VerbCreate && !mapping.HasFolderSupport() {
		if mapping.Scope("") == "*" {
			return scopeMap["*"]
		}
		return len(scopeMap) > 0
	}
	if mapping.SkipScope(req.Verb) {
		return scopeMap[""]
	}
	if !mapping.SkipWildcard() && scopeMap["*"] {
		return true
	}
	return req.Name != "" && scopeMap[mapping.Scope(req.Name)]
}

func permissionsForBasicRole(orgRole identity.RoleType, grafanaAdmin bool) []accesscontrol.Permission {
	var perms []accesscontrol.Permission
	for _, reg := range accesscontrol.FixedRoleRegistrations() {
		expanded := accesscontrol.BuiltInRolesWithParents(reg.Grants)
		if _, ok := expanded[string(orgRole)]; ok {
			perms = append(perms, reg.Role.Permissions...)
		}
		if grafanaAdmin {
			if _, ok := expanded[accesscontrol.RoleGrafanaAdmin]; ok {
				perms = append(perms, reg.Role.Permissions...)
			}
		}
	}
	return perms
}

func scopeMapForAction(perms []accesscontrol.Permission, action string) map[string]bool {
	permMap := map[string]bool{}
	for _, perm := range perms {
		if perm.Action != action {
			continue
		}
		kind, attribute, identifier := accesscontrol.SplitScope(perm.Scope)
		if kind == "*" || attribute == "*" || identifier == "*" {
			return map[string]bool{"*": true}
		}
		permMap[perm.Scope] = true
	}
	return permMap
}

type staticConfigProvider struct {
	cfg *setting.Cfg
}

func (s staticConfigProvider) Get(context.Context) (*setting.Cfg, error) { return s.cfg, nil }

func (s staticConfigProvider) GetSections(context.Context, ...string) (*ini.File, error) {
	return ini.Empty(), nil
}

var _ configprovider.ConfigProvider = staticConfigProvider{}

// TestOrgAdminCannotChangeUserSpecThroughStatus checks that an organization Admin,
// who holds org.users:write, cannot change spec through users/status while the users
// resource is unified-primary (dual-writer mode 5). PUT and PATCH both reach
// StatusREST.Update with the object after the patch is applied, so one Update of a
// forged object covers both. Server-side apply, dual-writer modes 0-3, and other
// NewRegistryStatusStore resources are not covered here.
func TestOrgAdminCannotChangeUserSpecThroughStatus(t *testing.T) {
	ns := "org-1"
	ac := basicRoleAccessClient{}
	usersAuthz := newUserAuthorizer(ac)

	viewer := &identity.StaticRequester{
		Type:              authlib.TypeUser,
		UserUID:           "viewer",
		Login:             "viewer",
		OrgID:             1,
		OrgRole:           identity.RoleViewer,
		Namespace:         ns,
		AccessTokenClaims: sessionAccessClaims(),
	}
	viewerCtx := identity.WithRequester(context.Background(), viewer)
	decision, _, err := usersAuthz.Authorize(viewerCtx, statusAttrs(ns, "victim", utils.VerbUpdate))
	require.NoError(t, err)
	require.Equal(t, authorizerDecisionDeny, decision, "a viewer must not pass the users status authorizer")

	env := newMode5UserStorage(t, ac)
	orgAdmin := &identity.StaticRequester{
		Type:              authlib.TypeUser,
		UserUID:           "org-admin",
		Login:             "org-admin",
		OrgID:             1,
		OrgRole:           identity.RoleAdmin,
		Namespace:         ns,
		AccessTokenClaims: sessionAccessClaims(),
	}

	t.Run("status put keeps grafana admin, disabled, email, login and title", func(t *testing.T) {
		stored := env.createUser(t, &iamv0.User{
			ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: ns},
			Spec: iamv0.UserSpec{
				Login:        "victim",
				Email:        "victim@example.com",
				Title:        "Victim",
				Role:         string(identity.RoleViewer),
				Disabled:     true,
				GrafanaAdmin: false,
			},
			Status: iamv0.UserStatus{LastSeenAt: 1},
		})

		forged := stored.DeepCopy()
		forged.Spec.GrafanaAdmin = true
		forged.Spec.Disabled = false
		forged.Spec.Email = "attacker@example.com"
		forged.Spec.Login = "attacker"
		forged.Spec.Title = "Attacker"
		forged.Spec.Role = string(identity.RoleAdmin)
		forged.Status.LastSeenAt = 99

		env.updateStatus(t, orgAdmin, forged, stored.Spec)
	})

	t.Run("status put of lastSeenAt still persists status", func(t *testing.T) {
		stored := env.createUser(t, &iamv0.User{
			ObjectMeta: metav1.ObjectMeta{Name: "seen", Namespace: ns},
			Spec: iamv0.UserSpec{
				Login: "seen",
				Email: "seen@example.com",
				Title: "Seen",
				Role:  string(identity.RoleViewer),
			},
			Status: iamv0.UserStatus{LastSeenAt: 1},
		})
		updated := stored.DeepCopy()
		updated.Status.LastSeenAt = 50

		got, applied := env.updateStatus(t, orgAdmin, updated, stored.Spec)
		if applied {
			require.Equal(t, int64(50), got.Status.LastSeenAt)
		}
	})

	t.Run("main resource update still rejects grafana admin and email changes", func(t *testing.T) {
		stored := env.createUser(t, &iamv0.User{
			ObjectMeta: metav1.ObjectMeta{Name: "main", Namespace: ns},
			Spec: iamv0.UserSpec{
				Login:        "main",
				Email:        "main@example.com",
				Title:        "Main",
				Role:         string(identity.RoleViewer),
				GrafanaAdmin: false,
			},
		})
		forged := stored.DeepCopy()
		forged.Spec.GrafanaAdmin = true
		forged.Spec.Email = "attacker@example.com"

		ctx := requestCtx(ns, orgAdmin)
		decision, _, err := usersAuthz.Authorize(ctx, resourceAttrs(ns, forged.Name, utils.VerbUpdate))
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		_, _, err = env.users.Update(
			ctx,
			forged.Name,
			k8srest.DefaultUpdatedObjectInfo(forged),
			nil,
			env.updateValidation(ns, forged.Name, ""),
			false,
			&metav1.UpdateOptions{},
		)
		require.Error(t, err)
		require.True(t, apierrors.IsForbidden(err), "main resource update returned %v", err)

		got := env.get(t, ctx, forged.Name)
		require.Equal(t, stored.Spec, got.Spec)
	})
}

const authorizerDecisionDeny = authorizer.DecisionDeny

type mode5UserStorage struct {
	t      *testing.T
	users  k8srest.CreaterUpdater
	status k8srest.Updater
	getter k8srest.Getter
	b      *IdentityAccessManagementAPIBuilder
}

func newMode5UserStorage(t *testing.T, ac authlib.AccessClient) *mode5UserStorage {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, iamv0.AddToScheme(scheme))
	codecs := serializer.NewCodecFactory(scheme)

	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true).WithLogger(nil))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	backend, err := resource.NewKVStorageBackend(resource.KVBackendOptions{
		KvStore:                resource.NewBadgerKV(db),
		DisableStorageServices: true,
	})
	require.NoError(t, err)
	server, err := resource.NewResourceServer(resource.ResourceServerOptions{
		Backend:      backend,
		AccessClient: ac,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Stop(context.Background()) })

	optsGetter := apistore.NewRESTOptionsGetterForClient(
		resource.NewLocalResourceClient(server),
		nil,
		storagebackend.Config{Codec: codecs.LegacyCodec(iamv0.SchemeGroupVersion)},
		nil,
		nil,
	)

	gr := iamv0.UserResourceInfo.GroupResource().String()
	cfg := &setting.Cfg{UnifiedStorage: map[string]setting.UnifiedStorageConfig{
		gr: {DualWriterMode: grafanarest.Mode5},
	}}
	b := &IdentityAccessManagementAPIBuilder{
		logger:          log.New("iam-status-test"),
		features:        &Features{},
		dual:            dualwrite.NewMockService(t),
		unified:         resource.NewMockResourceClient(t),
		cfgProvider:     staticConfigProvider{cfg: cfg},
		userLegacyStore: iamuser.NewLegacyStore(nil, ac, tracing.InitializeTracerForTest()),
		tracing:         tracing.InitializeTracerForTest(),
	}
	storage := map[string]k8srest.Storage{}
	err = b.UpdateUsersAPIGroup(builder.APIGroupOptions{
		Scheme:     scheme,
		OptsGetter: optsGetter,
		DualWriteBuilder: func(_ schema.GroupResource, _, unified grafanarest.Storage) (grafanarest.Storage, error) {
			// Mode 4 and 5 return the unified store. See storageService.NewStorage.
			return unified, nil
		},
		StorageOptsRegister: func(schema.GroupResource, apistore.StorageOptions) {},
	}, storage, false, false)
	require.NoError(t, err)

	users, ok := storage[iamv0.UserResourceInfo.StoragePath()].(k8srest.CreaterUpdater)
	require.True(t, ok, "users storage type %T", storage[iamv0.UserResourceInfo.StoragePath()])
	status, ok := storage[iamv0.UserResourceInfo.StoragePath("status")].(k8srest.Updater)
	require.True(t, ok, "status storage type %T", storage[iamv0.UserResourceInfo.StoragePath("status")])
	getter, ok := storage[iamv0.UserResourceInfo.StoragePath()].(k8srest.Getter)
	require.True(t, ok)

	return &mode5UserStorage{t: t, users: users, status: status, getter: getter, b: b}
}

func (e *mode5UserStorage) createUser(t *testing.T, obj *iamv0.User) *iamv0.User {
	t.Helper()
	obj.APIVersion = iamv0.APIVERSION
	obj.Kind = iamv0.UserResourceInfo.GroupVersionKind().Kind
	creator := &identity.StaticRequester{
		Type:              authlib.TypeUser,
		UserUID:           "server-admin",
		Login:             "server-admin",
		OrgID:             1,
		OrgRole:           identity.RoleAdmin,
		IsGrafanaAdmin:    true,
		Namespace:         obj.Namespace,
		AccessTokenClaims: sessionAccessClaims(),
	}
	ctx := requestCtx(obj.Namespace, creator)
	created, err := e.users.Create(ctx, obj, nil, &metav1.CreateOptions{})
	require.NoError(t, err)
	return created.(*iamv0.User)
}

// updateStatus reports whether the status store accepted the write. A refusal is a
// valid outcome only when the stored spec is still the original one.
func (e *mode5UserStorage) updateStatus(t *testing.T, caller *identity.StaticRequester, forged *iamv0.User, original iamv0.UserSpec) (*iamv0.User, bool) {
	t.Helper()
	ctx := requestCtx(forged.Namespace, caller)
	authz := newUserAuthorizer(basicRoleAccessClient{})
	decision, reason, err := authz.Authorize(ctx, statusAttrs(forged.Namespace, forged.Name, utils.VerbUpdate))
	require.NoError(t, err)

	if decision != authorizer.DecisionAllow {
		got := e.get(t, ctx, forged.Name)
		require.Equal(t, original, got.Spec, "status update denied (%s) but spec changed", reason)
		return got, false
	}

	updated, _, err := e.status.Update(
		ctx,
		forged.Name,
		k8srest.DefaultUpdatedObjectInfo(forged),
		nil,
		e.updateValidation(forged.Namespace, forged.Name, "status"),
		false,
		&metav1.UpdateOptions{},
	)
	if err != nil {
		got := e.get(t, ctx, forged.Name)
		require.Equal(t, original, got.Spec, "rejected status update still changed spec: %v", err)
		return got, false
	}
	got := updated.(*iamv0.User)
	require.Equal(t, forged.Name, got.Name)
	require.Equal(t, original, got.Spec, "status update persisted spec changes (grafanaAdmin=%v disabled=%v email=%s login=%s)",
		got.Spec.GrafanaAdmin, got.Spec.Disabled, got.Spec.Email, got.Spec.Login)
	return got, true
}

func (e *mode5UserStorage) updateValidation(namespace, name, subresource string) k8srest.ValidateObjectUpdateFunc {
	admit := builder.NewAdmissionFromBuilders([]builder.APIGroupBuilder{e.b})
	attrs := admission.NewAttributesRecord(
		nil, nil,
		iamv0.UserResourceInfo.GroupVersionKind(),
		namespace, name,
		iamv0.UserResourceInfo.GroupVersionResource(),
		subresource,
		admission.Update,
		&metav1.UpdateOptions{},
		false,
		&k8suser.DefaultInfo{Name: name},
	)
	return k8srest.AdmissionToValidateObjectUpdateFunc(admit, attrs, nil)
}

func (e *mode5UserStorage) get(t *testing.T, ctx context.Context, name string) *iamv0.User {
	t.Helper()
	obj, err := e.getter.Get(ctx, name, &metav1.GetOptions{})
	require.NoError(t, err)
	return obj.(*iamv0.User)
}

func requestCtx(namespace string, requester identity.Requester) context.Context {
	ctx := genericapirequest.WithNamespace(context.Background(), namespace)
	return identity.WithRequester(ctx, requester)
}

func statusAttrs(namespace, name, verb string) authorizer.Attributes {
	return authorizer.AttributesRecord{
		User:            &k8suser.DefaultInfo{Name: name},
		Verb:            verb,
		APIGroup:        iamv0.UserResourceInfo.GroupResource().Group,
		Resource:        iamv0.UserResourceInfo.GroupResource().Resource,
		Subresource:     "status",
		Name:            name,
		Namespace:       namespace,
		ResourceRequest: true,
	}
}

func resourceAttrs(namespace, name, verb string) authorizer.Attributes {
	return authorizer.AttributesRecord{
		User:            &k8suser.DefaultInfo{Name: name},
		Verb:            verb,
		APIGroup:        iamv0.UserResourceInfo.GroupResource().Group,
		Resource:        iamv0.UserResourceInfo.GroupResource().Resource,
		Name:            name,
		Namespace:       namespace,
		ResourceRequest: true,
	}
}
