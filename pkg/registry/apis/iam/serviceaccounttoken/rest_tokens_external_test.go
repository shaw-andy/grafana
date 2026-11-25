package serviceaccounttoken

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	authlib "github.com/grafana/authlib/types"
	iamv0alpha1 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/iam/legacy"
	"github.com/grafana/grafana/pkg/services/serviceaccounts"
	"github.com/grafana/grafana/pkg/setting"
)

// These tests specify that the Kubernetes tokens subresource must refuse POST and
// DELETE against external (plugin-managed) service accounts for non-service
// identities, matching the legacy ServiceAccountsProxy. They fail until that
// guard is implemented.

func TestConnectCreateTokenRejectsExternalServiceAccountForOrgAdmin(t *testing.T) {
	t.Run("by plugin field", func(t *testing.T) {
		runConnectCreateExternalTokenTest(t, externalServiceAccountByPlugin())
	})
	t.Run("by extsvc title prefix", func(t *testing.T) {
		runConnectCreateExternalTokenTest(t, externalServiceAccountByTitlePrefix())
	})
}

func TestConnectDeleteTokenRejectsExternalServiceAccountForOrgAdmin(t *testing.T) {
	t.Run("by plugin field", func(t *testing.T) {
		runConnectDeleteExternalTokenTest(t, externalServiceAccountByPlugin())
	})
	t.Run("by extsvc title prefix", func(t *testing.T) {
		runConnectDeleteExternalTokenTest(t, externalServiceAccountByTitlePrefix())
	})
}

func runConnectCreateExternalTokenTest(t *testing.T, sa *iamv0alpha1.ServiceAccount) {
	t.Helper()

	store := &trackingLegacyStore{}
	provider := &fakeConfigProvider{cfg: &setting.Cfg{
		ApiKeyMaxSecondsToLive:    -1,
		SATokenExpirationDayLimit: -1,
	}}
	restHandler := NewTokensREST(
		&fakeServiceAccountGetter{sa: sa},
		store,
		noop.NewTracerProvider().Tracer("test"),
		provider,
		nil,
	)

	orgID := int64(1)
	saUID := "ext-sa-uid"
	ctx := connectTestContext(t, orgID, identity.RoleAdmin)
	responder := &recorderResponder{}

	handler, err := restHandler.Connect(ctx, saUID, nil, responder)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewBufferString(`{"tokenName":"attacker-token"}`))
	req = req.WithContext(connectRequestContext(req.Context(), saUID, ""))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.False(t, store.createCalled, "legacy store must not persist a token for an external service account")
	require.Error(t, responder.err, "expected forbidden error for external service account token create")
	assert.True(t, apierrors.IsForbidden(responder.err), "expected forbidden, got %v", responder.err)
}

func runConnectDeleteExternalTokenTest(t *testing.T, sa *iamv0alpha1.ServiceAccount) {
	t.Helper()

	store := &trackingLegacyStore{}
	restHandler := NewTokensREST(
		&fakeServiceAccountGetter{sa: sa},
		store,
		noop.NewTracerProvider().Tracer("test"),
		&fakeConfigProvider{cfg: &setting.Cfg{}},
		nil,
	)

	orgID := int64(1)
	saUID := "ext-sa-uid"
	tokenName := "plugin-token"
	ctx := connectTestContext(t, orgID, identity.RoleAdmin)
	responder := &recorderResponder{}

	handler, err := restHandler.Connect(ctx, saUID, nil, responder)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/tokens/"+tokenName, nil)
	req = req.WithContext(connectRequestContext(req.Context(), saUID, tokenName))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.False(t, store.deleteCalled, "legacy store must not delete a token for an external service account")
	require.Error(t, responder.err, "expected forbidden error for external service account token delete")
	assert.True(t, apierrors.IsForbidden(responder.err), "expected forbidden, got %v", responder.err)
}

func externalServiceAccountByPlugin() *iamv0alpha1.ServiceAccount {
	return &iamv0alpha1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "ext-sa-uid"},
		Spec: iamv0alpha1.ServiceAccountSpec{
			Title:  "extsvc-grafana-plugin",
			Role:   iamv0alpha1.ServiceAccountOrgRoleNone,
			Plugin: "grafana-plugin",
		},
	}
}

func externalServiceAccountByTitlePrefix() *iamv0alpha1.ServiceAccount {
	return &iamv0alpha1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "ext-sa-uid"},
		Spec: iamv0alpha1.ServiceAccountSpec{
			Title: serviceaccounts.ExtSvcPrefix + "legacy-plugin",
			Role:  iamv0alpha1.ServiceAccountOrgRoleViewer,
		},
	}
}

func connectTestContext(t *testing.T, orgID int64, orgRole identity.RoleType) context.Context {
	t.Helper()
	ctx := k8srequest.WithNamespace(context.Background(), authlib.OrgNamespaceFormatter(orgID))
	requester := &identity.StaticRequester{
		Type:    authlib.TypeUser,
		UserID:  1,
		OrgID:   orgID,
		OrgRole: orgRole,
	}
	return identity.WithRequester(ctx, requester)
}

func connectRequestContext(ctx context.Context, saUID, tokenName string) context.Context {
	parts := []string{"serviceaccounts", saUID, "tokens"}
	if tokenName != "" {
		parts = append(parts, tokenName)
	}
	return k8srequest.WithRequestInfo(ctx, &k8srequest.RequestInfo{
		Parts: parts,
	})
}

var _ rest.Getter = (*fakeServiceAccountGetter)(nil)

type fakeServiceAccountGetter struct {
	sa  *iamv0alpha1.ServiceAccount
	err error
}

func (f *fakeServiceAccountGetter) Get(_ context.Context, _ string, _ *metav1.GetOptions) (runtime.Object, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.sa, nil
}

type trackingLegacyStore struct {
	legacy.LegacyIdentityStore
	createCalled bool
	deleteCalled bool
}

func (f *trackingLegacyStore) CreateServiceAccountTokenWithHash(context.Context, authlib.NamespaceInfo, legacy.CreateServiceAccountTokenWithHashCommand) error {
	f.createCalled = true
	return nil
}

func (f *trackingLegacyStore) GetServiceAccountInternalID(context.Context, authlib.NamespaceInfo, legacy.GetServiceAccountInternalIDQuery) (*legacy.GetServiceAccountInternalIDResult, error) {
	return &legacy.GetServiceAccountInternalIDResult{ID: 99}, nil
}

func (f *trackingLegacyStore) DeleteServiceAccountToken(context.Context, authlib.NamespaceInfo, legacy.DeleteServiceAccountTokenCommand) (int64, error) {
	f.deleteCalled = true
	return 1, nil
}

type recorderResponder struct {
	rest.Responder
	err error
}

func (r *recorderResponder) Object(int, runtime.Object) {}

func (r *recorderResponder) Error(err error) {
	r.err = err
}