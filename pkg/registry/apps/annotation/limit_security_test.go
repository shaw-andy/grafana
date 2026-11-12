package annotation

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"testing"

	authtypes "github.com/grafana/authlib/types"
	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	annotationV0 "github.com/grafana/grafana/apps/annotation/pkg/apis/annotation/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	storev1 "github.com/grafana/grafana/pkg/registry/apps/annotation/storepb/v1"
	"github.com/grafana/grafana/pkg/services/annotations"
)

// maxAnnotationLimit matches the cap enforced by dashboard search.
const maxAnnotationLimit int64 = 5000

func TestSearchHandlerBoundsLimit(t *testing.T) {
	store := &recordingAnnotationStore{}
	handler := newSearchHandler(store, testTracer, nil, nil, ProvideMetrics(nil), log.NewNopLogger())

	u := &url.URL{RawQuery: "dashboardUID=any&limit=2000000000"}
	err := handler(t.Context(), &mockResponseWriter{header: make(http.Header), body: &bytes.Buffer{}}, &app.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{Namespace: metav1.NamespaceDefault},
		URL:                u,
		Method:             http.MethodGet,
	})
	assertBoundedOrRejected(t, err, store.listed, store.limit, maxAnnotationLimit)
}

func TestTagsHandlerBoundsLimit(t *testing.T) {
	tags := &recordingTagProvider{}
	allow := &fakeAccessClient{fn: func(authtypes.BatchCheckItem) bool { return true }}
	handler := newTagsHandler(tags, testTracer, allow, ProvideMetrics(nil), log.NewNopLogger())

	ctx := k8srequest.WithNamespace(identity.WithServiceIdentityContext(t.Context(), 1), metav1.NamespaceDefault)
	u := &url.URL{RawQuery: "limit=2000000000"}
	err := handler(ctx, &mockResponseWriter{header: make(http.Header), body: &bytes.Buffer{}}, &app.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{Namespace: metav1.NamespaceDefault},
		URL:                u,
		Method:             http.MethodGet,
	})
	assertBoundedOrRejected(t, err, tags.called, int64(tags.limit), maxAnnotationLimit)
}

func TestK8sAdapterListBoundsLimit(t *testing.T) {
	store := &recordingAnnotationStore{}
	adapter := newTestAdapter(store, &fakeAccessClient{fn: func(authtypes.BatchCheckItem) bool { return true }})
	ctx := k8srequest.WithNamespace(identity.WithServiceIdentityContext(t.Context(), 1), "org-1")

	_, err := adapter.List(ctx, &internalversion.ListOptions{Limit: 2_000_000_000})
	assertBoundedOrRejected(t, err, store.listed, store.limit, maxAnnotationLimit)
}

func TestSQLAdapterBoundsLimit(t *testing.T) {
	repo := &recordingLegacyRepo{}
	adapter := NewSQLAdapter(repo, nil, annotations.CleanupSettings{})
	ctx := identity.WithRequester(t.Context(), &identity.StaticRequester{OrgID: 1})

	_, err := adapter.List(ctx, "default", ListOptions{DashboardUID: "any", Limit: 2_000_000_000})
	// List asks for one extra row to detect the next page, so the repository
	// may see one more than the public cap.
	assertBoundedOrRejected(t, err, repo.findCalls > 0, repo.findLimit, maxAnnotationLimit+1)

	_, err = adapter.ListTags(ctx, "default", TagListOptions{Limit: 2_000_000_000})
	assertBoundedOrRejected(t, err, repo.tagCalls > 0, repo.tagLimit, maxAnnotationLimit)
}

func TestBuildListQueryBoundsLimit(t *testing.T) {
	_, args := buildListQuery("default", ListOptions{DashboardUID: "any"}, 0, 2_000_000_000)
	for _, arg := range args {
		limit, ok := arg.(int64)
		if !ok {
			continue
		}
		require.GreaterOrEqual(t, limit, int64(0))
		require.LessOrEqual(t, limit, maxAnnotationLimit+1)
	}
}

func TestProtoListOptionsBoundLimit(t *testing.T) {
	proto := toProtoListOptions(ListOptions{DashboardUID: "any", Limit: 2_000_000_000})
	require.LessOrEqual(t, proto.GetLimit(), maxAnnotationLimit)
	require.GreaterOrEqual(t, proto.GetLimit(), int64(0))

	decoded := fromProtoListOptions(&storev1.ListOptions{Limit: 2_000_000_000, DashboardUid: "any"})
	require.LessOrEqual(t, decoded.Limit, maxAnnotationLimit)
	require.GreaterOrEqual(t, decoded.Limit, int64(0))

	tags := toProtoTagListOptions(TagListOptions{Limit: 2_000_000_000})
	require.LessOrEqual(t, int64(tags.GetLimit()), maxAnnotationLimit)
	require.GreaterOrEqual(t, tags.GetLimit(), int32(0))

	decodedTags := fromProtoTagListOptions(&storev1.TagListOptions{Limit: 2_000_000_000})
	require.LessOrEqual(t, int64(decodedTags.Limit), maxAnnotationLimit)
	require.GreaterOrEqual(t, decodedTags.Limit, 0)
}

func assertBoundedOrRejected(t *testing.T, err error, called bool, limit, max int64) {
	t.Helper()
	if called {
		require.GreaterOrEqual(t, limit, int64(0))
		require.LessOrEqual(t, limit, max)
	}
	if err != nil {
		return
	}
	require.True(t, called, "request succeeded without applying the caller limit")
}

type recordingAnnotationStore struct {
	listed bool
	limit  int64
}

func (s *recordingAnnotationStore) Get(context.Context, string, string) (*annotationV0.Annotation, error) {
	return nil, ErrNotFound
}

func (s *recordingAnnotationStore) List(_ context.Context, _ string, opts ListOptions) (*AnnotationList, error) {
	s.listed = true
	s.limit = opts.Limit
	return &AnnotationList{}, nil
}

func (s *recordingAnnotationStore) Create(context.Context, *annotationV0.Annotation) (*annotationV0.Annotation, error) {
	return nil, nil
}

func (s *recordingAnnotationStore) Update(_ context.Context, anno *annotationV0.Annotation) (*annotationV0.Annotation, error) {
	return anno, nil
}

func (s *recordingAnnotationStore) Delete(context.Context, string, string) error { return nil }

func (s *recordingAnnotationStore) Close() error { return nil }

type recordingTagProvider struct {
	called bool
	limit  int
}

func (p *recordingTagProvider) ListTags(_ context.Context, _ string, opts TagListOptions) ([]Tag, error) {
	p.called = true
	p.limit = opts.Limit
	return nil, nil
}

type recordingLegacyRepo struct {
	findCalls int
	findLimit int64
	tagCalls  int
	tagLimit  int64
}

func (r *recordingLegacyRepo) Find(_ context.Context, query *annotations.ItemQuery) ([]*annotations.ItemDTO, error) {
	r.findCalls++
	r.findLimit = query.Limit
	return nil, nil
}

func (r *recordingLegacyRepo) Save(context.Context, *annotations.Item) error { return nil }

func (r *recordingLegacyRepo) SaveMany(context.Context, []annotations.Item) error { return nil }

func (r *recordingLegacyRepo) Update(context.Context, *annotations.Item) error { return nil }

func (r *recordingLegacyRepo) Delete(context.Context, *annotations.DeleteParams) error { return nil }

func (r *recordingLegacyRepo) FindTags(_ context.Context, query *annotations.TagsQuery) (annotations.FindTagsResult, error) {
	r.tagCalls++
	r.tagLimit = query.Limit
	return annotations.FindTagsResult{}, nil
}
