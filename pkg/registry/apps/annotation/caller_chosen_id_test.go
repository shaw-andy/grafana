package annotation

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/bwmarrin/snowflake"
	authtypes "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	annotationV0 "github.com/grafana/grafana/apps/annotation/pkg/apis/annotation/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/annotations/annotationsimpl"
	"github.com/grafana/grafana/pkg/services/tag/tagimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// editorOrgAnnotationCreate models the built-in Editor grant
// fixed:annotations:writer (annotations:create on annotations:type:organization).
// The RBAC mapper turns a create on annotation.grafana.app/annotations named
// "organization" into that action and scope.
func editorOrgAnnotationCreate(item authtypes.BatchCheckItem) bool {
	return item.Verb == utils.VerbCreate &&
		item.Group == "annotation.grafana.app" &&
		item.Resource == "annotations" &&
		item.Subresource == "" &&
		item.Name == "organization"
}

// TestIntegrationCallerChosenAnnotationPrimaryKey is the spec for annotation
// creates on the default legacy SQL backend. A caller-supplied metadata.name
// of the form a-<number> must not become the annotation table primary key.
// While that happens, one create at the maximum signed 64-bit id exhausts
// AUTOINCREMENT (SQLite) and AUTO_INCREMENT (MySQL), and later inserts into
// the shared table fail. These tests fail until that stops.
func TestIntegrationCallerChosenAnnotationPrimaryKey(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("explicit name is not stored as the primary key", func(t *testing.T) {
		stack := newLegacySQLAnnotationStack(t)
		const chosen = int64(424242)
		created, err := stack.create(t, fmt.Sprintf("a-%d", chosen), "chosen-id")
		assertCallerDidNotChooseID(t, stack, err, created, chosen, "chosen-id", "organization", "annotation.grafana.app", "")
	})

	t.Run("dashboard annotation name is not stored as the primary key", func(t *testing.T) {
		stack := newLegacySQLAnnotationStack(t)
		const dash = "dashuid"
		stack.access.fn = func(item authtypes.BatchCheckItem) bool {
			return item.Verb == utils.VerbCreate &&
				item.Group == "dashboard.grafana.app" &&
				item.Resource == "dashboards" &&
				item.Subresource == "annotations" &&
				item.Name == dash
		}
		uid := dash
		created, err := stack.adapter.Create(stack.ctx, &annotationV0.Annotation{
			ObjectMeta: metav1.ObjectMeta{Name: "a-424242", Namespace: stack.namespace},
			Spec:       annotationV0.AnnotationSpec{Text: "dash-chosen", Time: time.Now().UnixMilli(), DashboardUID: &uid},
		}, nil, &metav1.CreateOptions{})
		assertCallerDidNotChooseID(t, stack, err, created, 424242, "dash-chosen", dash, "dashboard.grafana.app", dash)
	})

	t.Run("maximum signed id does not exhaust later inserts", func(t *testing.T) {
		stack := newLegacySQLAnnotationStack(t)
		created, err := stack.create(t, fmt.Sprintf("a-%d", int64(math.MaxInt64)), "exhaust")
		assertCallerDidNotChooseID(t, stack, err, created, math.MaxInt64, "exhaust", "organization", "annotation.grafana.app", "")

		// Legacy POST /api/annotations and App Platform creates share this table.
		require.NoError(t, stack.repo.Save(context.Background(), &annotations.Item{
			OrgID: 1,
			Text:  "legacy-create",
			Epoch: time.Now().UnixMilli(),
			Type:  "annotation",
		}))

		// Graphite events are created with generateName, then the same REST Create.
		_, err = stack.adapter.Create(stack.ctx, &annotationV0.Annotation{
			ObjectMeta: metav1.ObjectMeta{Namespace: stack.namespace, GenerateName: "a-"},
			Spec:       annotationV0.AnnotationSpec{Text: "graphite", Time: time.Now().UnixMilli()},
		}, nil, &metav1.CreateOptions{})
		require.NoError(t, err)

		// Alert state history writes annotations through SaveMany on the same table.
		require.NoError(t, stack.repo.SaveMany(context.Background(), []annotations.Item{{
			OrgID: 1,
			Text:  "alert-state",
			Epoch: time.Now().UnixMilli(),
			Type:  "alert",
		}}))

		require.False(t, stack.annotationIDExists(t, math.MaxInt64), "maximum id must not remain in the annotation table")
	})

	t.Run("legacy id generation still ignores a caller-supplied name", func(t *testing.T) {
		stack := newLegacySQLAnnotationStack(t)
		stack.adapter.snowflakeNode = mustSnowflake(t)
		created, err := stack.create(t, fmt.Sprintf("a-%d", int64(math.MaxInt64)), "with-legacy-id")
		assertCallerDidNotChooseID(t, stack, err, created, math.MaxInt64, "with-legacy-id", "organization", "annotation.grafana.app", "")
		require.NoError(t, stack.repo.Save(context.Background(), &annotations.Item{
			OrgID: 1,
			Text:  "after-legacy-id",
			Epoch: time.Now().UnixMilli(),
			Type:  "annotation",
		}))
	})

	t.Run("caller without organization create permission does not insert", func(t *testing.T) {
		stack := newLegacySQLAnnotationStack(t)
		stack.access.fn = func(authtypes.BatchCheckItem) bool { return false }
		_, err := stack.create(t, fmt.Sprintf("a-%d", int64(math.MaxInt64)), "denied")
		require.Error(t, err)
		require.True(t, apierrors.IsForbidden(err), "got %v", err)
		require.False(t, stack.annotationIDExists(t, math.MaxInt64))
		require.False(t, stack.textExists(t, "denied"), "a denied create must not write a row")
		require.NoError(t, stack.repo.Save(context.Background(), &annotations.Item{
			OrgID: 1,
			Text:  "after-deny",
			Epoch: time.Now().UnixMilli(),
			Type:  "annotation",
		}))
	})
}

func assertCallerDidNotChooseID(t *testing.T, stack *legacySQLAnnotationStack, err error, created runtime.Object, chosen int64, text, authorizedName, authorizedGroup, dashboardUID string) {
	t.Helper()
	require.False(t, stack.annotationIDExists(t, chosen), "annotation id %d was taken from metadata.name", chosen)
	if err != nil {
		// Rejecting the name is enough only when nothing was written first.
		// Validation runs before the permission check, so a rejection need not have been authorized.
		require.True(t, apierrors.IsBadRequest(err), "explicit name must be rejected or ignored, got %v", err)
		require.False(t, stack.textExists(t, text), "rejecting the name must not leave a row behind")
		return
	}
	anno, ok := created.(*annotationV0.Annotation)
	require.True(t, ok)
	require.NotEqual(t, fmt.Sprintf("a-%d", chosen), anno.Name)
	id, parseErr := parseAnnotationID(anno.Name)
	require.NoError(t, parseErr)
	require.NotEqual(t, chosen, id)
	require.Positive(t, id)
	require.Equal(t, text, anno.Spec.Text)
	// The row written is the annotation the permission check allowed.
	require.Equal(t, authorizedName, stack.access.seen.Name)
	require.Equal(t, authorizedGroup, stack.access.seen.Group)
	require.Equal(t, utils.VerbCreate, stack.access.seen.Verb)
	row, ok := stack.rowForText(t, text)
	require.True(t, ok)
	require.Equal(t, int64(1), row.OrgID)
	require.Equal(t, dashboardUID, row.DashboardUID)
	require.Equal(t, id, row.ID)
}

type recordingAccess struct {
	fn   func(authtypes.BatchCheckItem) bool
	seen authtypes.BatchCheckItem
}

func (c *recordingAccess) Check(_ context.Context, _ authtypes.AuthInfo, req authtypes.CheckRequest, _ string) (authtypes.CheckResponse, error) {
	item := authtypes.BatchCheckItem{
		Verb: req.Verb, Group: req.Group, Resource: req.Resource, Subresource: req.Subresource, Name: req.Name,
	}
	c.seen = item
	return authtypes.CheckResponse{Allowed: c.fn(item)}, nil
}

func (c *recordingAccess) Compile(context.Context, authtypes.AuthInfo, authtypes.ListRequest) (authtypes.ItemChecker, authtypes.Zookie, error) {
	return nil, nil, nil
}

func (c *recordingAccess) BatchCheck(_ context.Context, _ authtypes.AuthInfo, req authtypes.BatchCheckRequest) (authtypes.BatchCheckResponse, error) {
	results := make(map[string]authtypes.BatchCheckResult, len(req.Checks))
	for _, item := range req.Checks {
		c.seen = item
		results[item.CorrelationID] = authtypes.BatchCheckResult{Allowed: c.fn(item)}
	}
	return authtypes.BatchCheckResponse{Results: results}, nil
}

type legacySQLAnnotationStack struct {
	sql       db.DB
	repo      *annotationsimpl.RepositoryImpl
	adapter   *k8sRESTAdapter
	access    *recordingAccess
	ctx       context.Context
	namespace string
}

func newLegacySQLAnnotationStack(t *testing.T) *legacySQLAnnotationStack {
	t.Helper()
	sqlStore := db.NewTestStore(t)
	cfg := setting.NewCfg()
	cfg.AnnotationMaximumTagsLength = 500
	xormStore := annotationsimpl.NewXormStore(cfg, log.New("annotation.test"), sqlStore, tagimpl.ProvideService(sqlStore), nil)
	repo := annotationsimpl.NewRepositoryImpl(nil, nil, xormStore, xormStore)
	sqlAdapter := NewSQLAdapter(repo, nil, annotations.CleanupSettings{})
	access := &recordingAccess{fn: editorOrgAnnotationCreate}
	store := newInstrumentedStore(sqlAdapter, testTracer, ProvideMetrics(nil), log.NewNopLogger())
	adapter := newTestAdapter(store, access)

	const namespace = "default" // org 1
	user := &identity.StaticRequester{
		Type:    authtypes.TypeUser,
		UserID:  7,
		UserUID: "editor",
		OrgID:   1,
		OrgRole: identity.RoleEditor,
	}
	ctx := k8srequest.WithNamespace(identity.WithRequester(context.Background(), user), namespace)
	return &legacySQLAnnotationStack{
		sql:       sqlStore,
		repo:      repo,
		adapter:   adapter,
		access:    access,
		ctx:       ctx,
		namespace: namespace,
	}
}

func (s *legacySQLAnnotationStack) create(t *testing.T, name, text string) (runtime.Object, error) {
	t.Helper()
	return s.adapter.Create(s.ctx, &annotationV0.Annotation{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.namespace},
		Spec:       annotationV0.AnnotationSpec{Text: text, Time: time.Now().UnixMilli()},
	}, nil, &metav1.CreateOptions{})
}

func (s *legacySQLAnnotationStack) annotationIDExists(t *testing.T, id int64) bool {
	t.Helper()
	var exists bool
	err := s.sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		var err error
		exists, err = sess.Table("annotation").Where("id = ?", id).Exist()
		return err
	})
	require.NoError(t, err)
	return exists
}

type storedAnnotation struct {
	ID           int64  `xorm:"id"`
	OrgID        int64  `xorm:"org_id"`
	DashboardUID string `xorm:"dashboard_uid"`
}

func (s *legacySQLAnnotationStack) textExists(t *testing.T, text string) bool {
	t.Helper()
	_, ok := s.rowForText(t, text)
	return ok
}

func (s *legacySQLAnnotationStack) rowForText(t *testing.T, text string) (storedAnnotation, bool) {
	t.Helper()
	var row storedAnnotation
	var found bool
	err := s.sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		var err error
		found, err = sess.SQL("SELECT id, org_id, dashboard_uid FROM annotation WHERE text = ?", text).Get(&row)
		return err
	})
	require.NoError(t, err)
	return row, found
}

func mustSnowflake(t *testing.T) *snowflake.Node {
	t.Helper()
	node, err := snowflake.NewNode(1)
	require.NoError(t, err)
	return node
}
