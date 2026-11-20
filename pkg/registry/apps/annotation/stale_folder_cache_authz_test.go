package annotation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/fullstorydev/grpchan/inprocgrpc"
	authnlib "github.com/grafana/authlib/authn"
	authzlib "github.com/grafana/authlib/authz"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	authtypes "github.com/grafana/authlib/types"
	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	grpcAuth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	authnclaims "github.com/go-jose/go-jose/v4/jwt"
	annotationV0 "github.com/grafana/grafana/apps/annotation/pkg/apis/annotation/v0alpha1"
	dashboardv1 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authz"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/authz/rbac/store"
)

const (
	staleFolderNamespace = "default"
	staleFolderUserUID   = "folder-editor"
	staleFolderDashboard = "dash-d"
	staleFolderPrevious  = "folder-a"
	staleFolderCurrent   = "folder-b"
	staleFolderNoteName  = "note-1"
	staleFolderNoteText  = "incident note while the dashboard was in folder-a"
	staleFolderRewrite   = "rewritten after the dashboard moved"
	staleFolderCreated   = "created after the dashboard moved"
)

// TestStaleDashboardFolderCacheLetsPreviousFolderEditorAccessAnnotations is the
// spec for authorization of dashboard annotations. It fails while a cached
// parent folder is still sent into the permission check after the dashboard
// has moved.
//
// The signed-in user holds folders:edit on folder-a and nothing on folder-b.
// Graphite events and the tags route are not covered: they authorize an
// organization annotation and never resolve a dashboard folder. The adapter
// does not implement watch.
func TestStaleDashboardFolderCacheLetsPreviousFolderEditorAccessAnnotations(t *testing.T) {
	svc := rbac.NewTestService(staleFolderUserUID, []accesscontrol.Permission{{
		Action:     "folders:edit",
		Scope:      "folders:uid:" + staleFolderPrevious,
		Kind:       "folders",
		Attribute:  "uid",
		Identifier: staleFolderPrevious,
	}}, []store.Folder{{UID: staleFolderPrevious}, {UID: staleFolderCurrent}})
	accessClient := newInProcRBACAccessClient(t, svc)

	resolver, fakeDyn := newTestDashboardFolderResolver(true, newFakeDashboard(staleFolderNamespace, staleFolderDashboard, staleFolderPrevious))
	resolver.cacheTTL = 30 * time.Second
	adapter := newTestAdapter(NewMemoryStore(), accessClient, resolver)
	ctx := folderEditorContext()

	decision, _, err := (&AppInstaller{}).GetAuthorizer().Authorize(ctx, authorizer.AttributesRecord{
		Verb:            "get",
		ResourceRequest: true,
		APIGroup:        annotationV0.AnnotationKind().Group(),
		Resource:        annotationV0.AnnotationKind().Plural(),
		Name:            staleFolderNoteName,
		Namespace:       staleFolderNamespace,
	})
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)

	note := dashboardAnnotation(staleFolderNoteName, staleFolderNoteText)
	_, err = adapter.store.Create(ctx, note.DeepCopy())
	require.NoError(t, err)

	t.Run("editor of the current folder can read the note", func(t *testing.T) {
		got, err := adapter.Get(ctx, staleFolderNoteName, &metav1.GetOptions{})
		require.NoError(t, err)
		require.Equal(t, staleFolderNoteText, got.(*annotationV0.Annotation).Spec.Text)
	})

	gvr := dashboardv1.DashboardResourceInfo.GroupVersionResource()
	moved, err := fakeDyn.Resource(gvr).Namespace(staleFolderNamespace).Get(ctx, staleFolderDashboard, metav1.GetOptions{})
	require.NoError(t, err)
	moved.SetAnnotations(map[string]string{"grafana.app/folder": staleFolderCurrent})
	_, err = fakeDyn.Resource(gvr).Namespace(staleFolderNamespace).Update(ctx, moved, metav1.UpdateOptions{})
	require.NoError(t, err)

	t.Run("get does not return the note after the move", func(t *testing.T) {
		got, err := adapter.Get(ctx, staleFolderNoteName, &metav1.GetOptions{})
		require.Error(t, err)
		require.True(t, apierrors.IsNotFound(err))
		require.Nil(t, got)
	})

	t.Run("list does not return the note after the move", func(t *testing.T) {
		got, err := adapter.List(ctx, &internalversion.ListOptions{})
		require.NoError(t, err)
		list := got.(*annotationV0.AnnotationList)
		require.Empty(t, list.Items)
	})

	t.Run("search does not return the note after the move", func(t *testing.T) {
		handler := newSearchHandler(adapter.store, testTracer, accessClient, resolver, ProvideMetrics(nil), log.NewNopLogger())
		writer := &mockResponseWriter{header: make(http.Header), body: &bytes.Buffer{}}
		err := handler(ctx, writer, &app.CustomRouteRequest{
			ResourceIdentifier: resource.FullIdentifier{Namespace: staleFolderNamespace},
			URL:                &url.URL{RawQuery: "dashboardUID=" + staleFolderDashboard},
			Method:             http.MethodGet,
		})
		require.NoError(t, err)
		var listed annotationV0.AnnotationList
		require.NoError(t, json.Unmarshal(writer.body.Bytes(), &listed))
		require.Empty(t, listed.Items)
		require.NotContains(t, writer.body.String(), staleFolderNoteText)
	})

	t.Run("update does not change the note after the move", func(t *testing.T) {
		updated := dashboardAnnotation(staleFolderNoteName, staleFolderRewrite)
		got, _, err := adapter.Update(ctx, staleFolderNoteName, &updatedObjectInfo{obj: updated}, nil, nil, false, &metav1.UpdateOptions{})
		require.Error(t, err)
		require.True(t, apierrors.IsForbidden(err))
		require.Nil(t, got)
		stored, err := adapter.store.Get(ctx, staleFolderNamespace, staleFolderNoteName)
		require.NoError(t, err)
		require.Equal(t, staleFolderNoteText, stored.Spec.Text)
	})

	t.Run("delete does not remove the note after the move", func(t *testing.T) {
		got, _, err := adapter.Delete(ctx, staleFolderNoteName, nil, &metav1.DeleteOptions{})
		require.Error(t, err)
		require.True(t, apierrors.IsNotFound(err))
		require.Nil(t, got)
		stored, err := adapter.store.Get(ctx, staleFolderNamespace, staleFolderNoteName)
		require.NoError(t, err)
		require.Equal(t, staleFolderNoteText, stored.Spec.Text)
	})

	t.Run("create does not write a note after the move", func(t *testing.T) {
		created, err := adapter.Create(ctx, dashboardAnnotation("note-2", staleFolderCreated), nil, &metav1.CreateOptions{})
		require.Error(t, err)
		require.True(t, apierrors.IsForbidden(err))
		require.Nil(t, created)
		_, err = adapter.store.Get(ctx, staleFolderNamespace, "note-2")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("reading the dashboard's current folder denies the same user", func(t *testing.T) {
		freshStore := NewMemoryStore()
		_, err := freshStore.Create(ctx, note.DeepCopy())
		require.NoError(t, err)
		fresh, _ := newTestDashboardFolderResolver(false, newFakeDashboard(staleFolderNamespace, staleFolderDashboard, staleFolderCurrent))
		freshAdapter := newTestAdapter(freshStore, accessClient, fresh)
		got, err := freshAdapter.Get(ctx, staleFolderNoteName, &metav1.GetOptions{})
		require.Error(t, err)
		require.True(t, apierrors.IsNotFound(err))
		require.Nil(t, got)
		stored, err := freshStore.Get(ctx, staleFolderNamespace, staleFolderNoteName)
		require.NoError(t, err)
		require.Equal(t, staleFolderNoteText, stored.Spec.Text)
	})
}

func dashboardAnnotation(name, text string) *annotationV0.Annotation {
	dash := staleFolderDashboard
	return &annotationV0.Annotation{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: staleFolderNamespace},
		Spec: annotationV0.AnnotationSpec{
			Text:         text,
			Time:         1_000,
			DashboardUID: &dash,
		},
	}
}

func folderEditorContext() context.Context {
	user := &identity.StaticRequester{
		Type:      authtypes.TypeUser,
		UserID:    1,
		UserUID:   staleFolderUserUID,
		OrgID:     1,
		Namespace: staleFolderNamespace,
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{
				DelegatedPermissions: identity.ServiceIdentityClaims.Rest.DelegatedPermissions,
			},
		},
	}
	return k8srequest.WithNamespace(identity.WithRequester(context.Background(), user), staleFolderNamespace)
}

// newInProcRBACAccessClient is the in-process client wiring from ProvideAuthZClients:
// the authlib client copies each check, including its folder, onto the RBAC service.
func newInProcRBACAccessClient(t *testing.T, svc *rbac.Service) authtypes.AccessClient {
	t.Helper()
	channel := &inprocgrpc.Channel{}
	authenticate := func(ctx context.Context) (context.Context, error) {
		ctx = authtypes.WithAuthInfo(ctx, authnlib.NewAccessTokenAuthInfo(authnlib.Claims[authnlib.AccessTokenClaims]{
			Claims: authnclaims.Claims{
				Subject: authtypes.NewTypeID(authtypes.TypeAccessPolicy, "grafana"),
			},
			Rest: authnlib.AccessTokenClaims{Namespace: "*"},
		}))
		return ctx, nil
	}
	interceptor := grpcAuth.UnaryServerInterceptor(authenticate)
	channel.WithServerUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return interceptor(ctx, req, info, handler)
	})
	authzv1.RegisterAuthzServiceServer(channel, svc)
	return authzlib.NewClient(channel, authzlib.WithCacheClientOption(&authz.NoopCache{}), authzlib.WithTracerClientOption(testTracer))
}
