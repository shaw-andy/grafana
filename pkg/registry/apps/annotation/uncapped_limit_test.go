package annotation

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	authtypes "github.com/grafana/authlib/types"
	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metainternalversionscheme "k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metainternalversionvalidation "k8s.io/apimachinery/pkg/apis/meta/internalversion/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	k8suser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	annotationV0 "github.com/grafana/grafana/apps/annotation/pkg/apis/annotation/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/annotations/accesscontrol"
	"github.com/grafana/grafana/pkg/services/annotations/annotationsimpl"
	grafauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
	"github.com/grafana/grafana/pkg/services/sqlstore/session"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/xorm"
	"github.com/grafana/grafana/pkg/util/xorm/core"

	_ "github.com/grafana/grafana/pkg/util/sqlite"
)

// maxAnnotationReadPage is the largest page a caller-supplied limit may cause
// an annotation read to query or allocate. A few hundred rows serves the API.
// Queries may fetch one extra row to detect another page.
const maxAnnotationReadPage int64 = 500

const attackerLimit = int64(10_000_000)

var limitClause = regexp.MustCompile(`LIMIT\s+(-?\d+)`)

func TestAcceptedSearchLimitReachesStore(t *testing.T) {
	store := &recordingStore{}
	handler := searchHandler(store, allowAllAccess())
	err := handler(signedInCtx(), responseWriter(), searchRequest("limit", "10"))
	require.NoError(t, err)
	require.Equal(t, []int64{10}, store.limits)

	err, sqls := runLegacy(t, func(adapter *sqlAdapter) error {
		return searchHandler(adapter, allowAllAccess())(signedInCtx(), responseWriter(), searchRequest("limit", "10"))
	})
	assertPageBounded(t, err, sqls)
}

func TestSearchLimitIsBoundedForSignedInCaller(t *testing.T) {
	t.Run("route authorizer allows a signed-in user with no annotation permission", func(t *testing.T) {
		decision, reason, err := authorizeSearch(t, unprivilegedUser())
		require.NoError(t, err)
		if decision != authorizer.DecisionAllow {
			t.Fatalf("search route authorizer denied a signed-in user before the handler (%s): %s", decision, reason)
		}

		store := &recordingStore{}
		err = searchHandler(store, denyAllAccess())(signedInCtx(), responseWriter(), searchRequest("limit", strconv.FormatInt(attackerLimit, 10)))
		assertCallerLimits(t, err, store.limits, true)
	})

	t.Run("allowed reader still cannot choose the page size", func(t *testing.T) {
		store := &recordingStore{}
		err := searchHandler(store, allowAllAccess())(readerCtx(), responseWriter(), searchRequest("limit", strconv.FormatInt(attackerLimit, 10)))
		assertCallerLimits(t, err, store.limits, false)
	})

	t.Run("legacy sql page is bounded when the route authorizer allows the call", func(t *testing.T) {
		decision, _, err := authorizeSearch(t, unprivilegedUser())
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		err, sqls := runLegacy(t, func(adapter *sqlAdapter) error {
			return searchHandler(adapter, denyAllAccess())(signedInCtx(), responseWriter(), searchRequest("limit", strconv.FormatInt(attackerLimit, 10)))
		})
		assertPageBounded(t, err, sqls)
	})

	t.Run("continue token cannot carry an uncapped limit", func(t *testing.T) {
		token := encodeContinueToken(0, attackerLimit)
		store := &recordingStore{}
		err := searchHandler(store, allowAllAccess())(readerCtx(), responseWriter(), searchRequest("limit", strconv.FormatInt(attackerLimit, 10), "continue", token))
		assertCallerLimits(t, err, store.limits, false)

		err, sqls := runLegacy(t, func(adapter *sqlAdapter) error {
			return searchHandler(adapter, allowAllAccess())(readerCtx(), responseWriter(), searchRequest("limit", strconv.FormatInt(attackerLimit, 10), "continue", token))
		})
		assertPageBounded(t, err, sqls)
	})
}

func TestSearchDashboardLimitDoesNotPreallocate(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	err, sqls := runLegacy(t, func(adapter *sqlAdapter) error {
		return searchHandler(adapter, allowAllAccess())(readerCtx(), responseWriter(), searchRequest("dashboardUID", "dash-1", "limit", "4000000"))
	})
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 4<<20 {
		t.Errorf("dashboard search allocated %d bytes for a caller-supplied limit before the read was bounded", grew)
	}
	assertPageBounded(t, err, sqls)
}

func TestListLimitIsBounded(t *testing.T) {
	opts := decodedListOptions(t, "10000000")

	store := &recordingStore{}
	_, err := newTestAdapter(store, denyAllAccess()).List(signedInCtx(), &opts)
	assertCallerLimits(t, err, store.limits, true)

	reader := &recordingStore{}
	_, err = newTestAdapter(reader, allowAllAccess()).List(readerCtx(), &opts)
	assertCallerLimits(t, err, reader.limits, false)

	err, sqls := runLegacy(t, func(adapter *sqlAdapter) error {
		_, listErr := newTestAdapter(adapter, allowAllAccess()).List(readerCtx(), &opts)
		return listErr
	})
	assertPageBounded(t, err, sqls)

	err, direct := runLegacy(t, func(adapter *sqlAdapter) error {
		_, listErr := adapter.List(readerCtx(), "default", ListOptions{Limit: attackerLimit})
		return listErr
	})
	assertPageBounded(t, err, direct)
}

func TestTagsLimitIsBounded(t *testing.T) {
	tags := &recordingTags{}
	err := tagsHandler(tags, allowOrgTags())(readerCtx(), responseWriter(), tagsRequest(strconv.FormatInt(attackerLimit, 10)))
	assertCallerLimits(t, err, intLimits(tags.limits), false)

	err, sqls := runLegacy(t, func(adapter *sqlAdapter) error {
		return tagsHandler(adapter, allowOrgTags())(readerCtx(), responseWriter(), tagsRequest(strconv.FormatInt(attackerLimit, 10)))
	})
	assertPageBounded(t, err, sqls)

	err, direct := runLegacy(t, func(adapter *sqlAdapter) error {
		_, tagsErr := adapter.ListTags(readerCtx(), "default", TagListOptions{Limit: int(attackerLimit)})
		return tagsErr
	})
	assertPageBounded(t, err, direct)
}

func TestPostgresListQueryCapsPageSize(t *testing.T) {
	query, args := buildListQuery("default", ListOptions{Limit: attackerLimit}, 0, attackerLimit)
	for _, arg := range args {
		n, ok := arg.(int64)
		if !ok {
			continue
		}
		if n < 0 || n > maxAnnotationReadPage+1 {
			t.Fatalf("postgres list page argument %d exceeds %d in %s", n, maxAnnotationReadPage+1, query)
		}
	}
	for _, n := range limitNumbers(query) {
		if n < 0 || n > maxAnnotationReadPage+1 {
			t.Fatalf("postgres list SQL page %d exceeds %d: %s", n, maxAnnotationReadPage+1, query)
		}
	}
}

func authorizeSearch(t *testing.T, user identity.Requester) (authorizer.Decision, string, error) {
	t.Helper()
	const path = "/apis/annotation.grafana.app/v0alpha1/namespaces/default/search"
	factory := &k8srequest.RequestInfoFactory{
		APIPrefixes:          sets.NewString("apis", "api"),
		GrouplessAPIPrefixes: sets.NewString("api"),
	}
	req, err := http.NewRequest(http.MethodGet, path+"?limit="+strconv.FormatInt(attackerLimit, 10), nil)
	require.NoError(t, err)
	info, err := factory.NewRequestInfo(req)
	require.NoError(t, err)
	require.True(t, info.IsResourceRequest)
	require.Equal(t, "search", info.Resource)
	require.Equal(t, "list", info.Verb)

	ctx := identity.WithRequester(context.Background(), user)
	ctx = k8srequest.WithUser(ctx, &k8suser.DefaultInfo{Name: user.GetIdentifier(), Groups: []string{"system:authenticated"}})
	ctx = k8srequest.WithRequestInfo(ctx, info)
	attrs, err := filters.GetAuthorizerAttributes(ctx)
	require.NoError(t, err)

	chain := grafauthorizer.NewGrafanaBuiltInSTAuthorizer()
	chain.Register(annotationV0.GroupVersion, (&AppInstaller{}).GetAuthorizer())
	return chain.Authorize(ctx, attrs)
}

func assertCallerLimits(t *testing.T, err error, limits []int64, allowForbidden bool) {
	t.Helper()
	for _, n := range limits {
		if n < 0 || n > maxAnnotationReadPage+1 {
			t.Errorf("store received caller limit %d, max page is %d (err=%v)", n, maxAnnotationReadPage, err)
		}
	}
	if err != nil {
		if isLimitRejection(err) || (allowForbidden && errors.IsForbidden(err) && len(limits) == 0) {
			return
		}
		t.Errorf("read failed without a bounded page: %v", err)
		return
	}
	if len(limits) == 0 {
		t.Error("handler returned success without reading a bounded page")
	}
}

func assertPageBounded(t *testing.T, err error, sqls []string) {
	t.Helper()
	for _, query := range sqls {
		for _, n := range limitNumbers(query) {
			if n < 0 || n > maxAnnotationReadPage+1 {
				t.Errorf("SQL page %d exceeds %d: %s (err=%v)", n, maxAnnotationReadPage+1, query, err)
			}
		}
	}
	if err != nil {
		if isLimitRejection(err) {
			return
		}
		t.Errorf("read failed before a bounded query: %v", err)
		return
	}
	if len(limitNumbers(strings.Join(sqls, "\n"))) == 0 {
		t.Error("read succeeded without a LIMIT")
	}
}

func isLimitRejection(err error) bool {
	if err == nil {
		return false
	}
	if errors.IsBadRequest(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "limit")
}

func limitNumbers(query string) []int64 {
	matches := limitClause.FindAllStringSubmatch(query, -1)
	out := make([]int64, 0, len(matches))
	for _, match := range matches {
		n, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

func intLimits(values []int) []int64 {
	out := make([]int64, len(values))
	for i, n := range values {
		out[i] = int64(n)
	}
	return out
}

func searchHandler(store Store, access authtypes.AccessClient) func(context.Context, app.CustomRouteResponseWriter, *app.CustomRouteRequest) error {
	return newSearchHandler(store, testTracer, access, newFakeFolderResolver(nil), ProvideMetrics(nil), log.NewNopLogger())
}

func tagsHandler(tags TagProvider, access authtypes.AccessClient) func(context.Context, app.CustomRouteResponseWriter, *app.CustomRouteRequest) error {
	return newTagsHandler(tags, testTracer, access, ProvideMetrics(nil), log.NewNopLogger())
}

func searchRequest(pairs ...string) *app.CustomRouteRequest {
	values := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		values.Add(pairs[i], pairs[i+1])
	}
	return &app.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{Namespace: "default"},
		URL: &url.URL{
			Scheme:   "http",
			Host:     "localhost",
			Path:     "/apis/annotation.grafana.app/v0alpha1/namespaces/default/search",
			RawQuery: values.Encode(),
		},
		Method: http.MethodGet,
	}
}

func tagsRequest(limit string) *app.CustomRouteRequest {
	return &app.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{Namespace: "default"},
		URL: &url.URL{
			Scheme:   "http",
			Host:     "localhost",
			Path:     "/apis/annotation.grafana.app/v0alpha1/namespaces/default/tags",
			RawQuery: url.Values{"limit": []string{limit}}.Encode(),
		},
		Method: http.MethodGet,
	}
}

func responseWriter() *mockResponseWriter {
	return &mockResponseWriter{header: make(http.Header), body: &bytes.Buffer{}}
}

func unprivilegedUser() *identity.StaticRequester {
	return &identity.StaticRequester{
		Type:      authtypes.TypeUser,
		UserID:    7,
		UserUID:   "user-7",
		OrgID:     1,
		OrgRole:   identity.RoleNone,
		Namespace: "default",
		Login:     "signed-in",
	}
}

func readerUser() *identity.StaticRequester {
	user := unprivilegedUser()
	user.OrgRole = identity.RoleViewer
	user.Permissions = map[int64]map[string][]string{
		1: {"annotations:read": {"annotations:*"}},
	}
	return user
}

func signedInCtx() context.Context {
	return k8srequest.WithNamespace(identity.WithRequester(context.Background(), unprivilegedUser()), "default")
}

func readerCtx() context.Context {
	return k8srequest.WithNamespace(identity.WithRequester(context.Background(), readerUser()), "default")
}

func allowAllAccess() *fakeAccessClient {
	return &fakeAccessClient{fn: func(authtypes.BatchCheckItem) bool { return true }}
}

func denyAllAccess() *fakeAccessClient {
	return &fakeAccessClient{fn: func(authtypes.BatchCheckItem) bool { return false }}
}

func allowOrgTags() *fakeAccessClient {
	return &fakeAccessClient{fn: func(item authtypes.BatchCheckItem) bool {
		return item.Group == "annotation.grafana.app" && item.Resource == "annotations" && item.Name == "organization" && item.Verb == "list"
	}}
}

func decodedListOptions(t *testing.T, limit string) metainternalversion.ListOptions {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/apis/annotation.grafana.app/v0alpha1/namespaces/default/annotations?limit="+limit, nil)
	require.NoError(t, err)
	// listOpts in k8s.io/apiserver v0.37.0 pkg/endpoints/handlers/get.go decodes the
	// query, applies defaults, and validates before handleList calls storage.List.
	opts := metainternalversion.ListOptions{}
	err = metainternalversionscheme.ParameterCodec.DecodeParameters(req.URL.Query(), metav1.SchemeGroupVersion, &opts)
	require.NoError(t, err)
	metainternalversion.SetListOptionsDefaults(&opts, false)
	require.Empty(t, metainternalversionvalidation.ValidateListOptions(&opts, false))
	parsed, err := strconv.ParseInt(limit, 10, 64)
	require.NoError(t, err)
	require.Equal(t, parsed, opts.Limit)
	return opts
}

type recordingStore struct {
	limits []int64
}

func (s *recordingStore) List(_ context.Context, _ string, opts ListOptions) (*AnnotationList, error) {
	s.limits = append(s.limits, opts.Limit)
	return &AnnotationList{}, nil
}

func (s *recordingStore) Get(context.Context, string, string) (*annotationV0.Annotation, error) {
	return nil, ErrNotFound
}

func (s *recordingStore) Create(context.Context, *annotationV0.Annotation) (*annotationV0.Annotation, error) {
	return nil, ErrInvalidInput
}

func (s *recordingStore) Update(context.Context, *annotationV0.Annotation) (*annotationV0.Annotation, error) {
	return nil, ErrInvalidInput
}

func (s *recordingStore) Delete(context.Context, string, string) error { return ErrNotFound }

func (s *recordingStore) Close() error { return nil }

type recordingTags struct {
	limits []int
}

func (r *recordingTags) ListTags(_ context.Context, _ string, opts TagListOptions) ([]Tag, error) {
	r.limits = append(r.limits, opts.Limit)
	return nil, nil
}

type allowAnnotationRead struct{}

func (allowAnnotationRead) Authorize(context.Context, annotations.ItemQuery) (*accesscontrol.AccessResources, error) {
	return &accesscontrol.AccessResources{CanAccessOrgAnnotations: true, Dashboards: map[string]int64{}}, nil
}

func runLegacy(t *testing.T, fn func(*sqlAdapter) error) (error, []string) {
	t.Helper()
	database := newSQLiteAnnotationDB(t)
	store := annotationsimpl.NewXormStore(setting.NewCfg(), log.NewNopLogger(), database, nil, nil)
	repo := annotationsimpl.NewRepositoryImpl(allowAnnotationRead{}, nil, store, store)
	adapter := NewSQLAdapter(repo, nil, annotations.CleanupSettings{})
	err := fn(adapter)
	return err, database.log.snapshot()
}

type sqlCapture struct {
	mu   sync.Mutex
	sqls []string
	show bool
}

func (l *sqlCapture) Debug(v ...interface{})                {}
func (l *sqlCapture) Debugf(string, ...interface{})         {}
func (l *sqlCapture) Error(v ...interface{})                {}
func (l *sqlCapture) Errorf(string, ...interface{})         {}
func (l *sqlCapture) Info(v ...interface{})                 {}
func (l *sqlCapture) Warn(v ...interface{})                 {}
func (l *sqlCapture) Warnf(string, ...interface{})          {}
func (l *sqlCapture) Level() core.LogLevel                  { return core.LOG_INFO }
func (l *sqlCapture) SetLevel(core.LogLevel)                {}
func (l *sqlCapture) ShowSQL(show ...bool)                  { l.show = len(show) == 0 || show[0] }
func (l *sqlCapture) IsShowSQL() bool                       { return true }
func (l *sqlCapture) Infof(format string, v ...interface{}) { l.record(fmt.Sprintf(format, v...)) }

func (l *sqlCapture) record(msg string) {
	l.mu.Lock()
	l.sqls = append(l.sqls, msg)
	l.mu.Unlock()
}

func (l *sqlCapture) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.sqls))
	copy(out, l.sqls)
	return out
}

type captureDB struct {
	engine  *xorm.Engine
	dialect migrator.Dialect
	log     *sqlCapture
}

func newSQLiteAnnotationDB(t *testing.T) *captureDB {
	t.Helper()
	engine, err := xorm.NewEngine("sqlite3", t.TempDir()+"/annotations.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = engine.Close() })
	schema := []string{
		`CREATE TABLE annotation (
			id INTEGER PRIMARY KEY,
			org_id INTEGER,
			epoch INTEGER,
			epoch_end INTEGER,
			dashboard_uid TEXT,
			dashboard_id INTEGER,
			panel_id INTEGER,
			new_state TEXT,
			prev_state TEXT,
			alert_id INTEGER,
			text TEXT,
			tags TEXT,
			data TEXT,
			created INTEGER,
			updated INTEGER,
			user_id INTEGER
		)`,
		"CREATE TABLE `user` (id INTEGER PRIMARY KEY, email TEXT, login TEXT, uid TEXT, org_id INTEGER)",
		`CREATE TABLE alert_rule (id INTEGER PRIMARY KEY, title TEXT, uid TEXT, org_id INTEGER)`,
		"CREATE TABLE tag (id INTEGER PRIMARY KEY, `key` TEXT, value TEXT)",
		`CREATE TABLE annotation_tag (annotation_id INTEGER, tag_id INTEGER)`,
	}
	for _, stmt := range schema {
		_, err = engine.Exec(stmt)
		require.NoError(t, err)
	}
	logger := &sqlCapture{}
	engine.SetLogger(logger)
	engine.ShowSQL(true)
	return &captureDB{engine: engine, dialect: migrator.NewDialect(migrator.SQLite), log: logger}
}

func (d *captureDB) WithDbSession(ctx context.Context, callback sqlstore.DBTransactionFunc) error {
	sess := d.engine.NewSession()
	defer sess.Close()
	return callback(&sqlstore.DBSession{Session: sess.Context(ctx)})
}

func (d *captureDB) WithTransactionalDbSession(ctx context.Context, callback sqlstore.DBTransactionFunc) error {
	return d.WithDbSession(ctx, callback)
}

func (d *captureDB) GetDialect() migrator.Dialect { return d.dialect }

func (d *captureDB) GetDBType() core.DbType { return core.SQLITE }

func (d *captureDB) GetEngine() *xorm.Engine { return d.engine }

func (d *captureDB) GetSqlxSession() *session.SessionDB { return nil }

func (d *captureDB) InTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (d *captureDB) Quote(value string) string { return d.engine.Quote(value) }

func (d *captureDB) RecursiveQueriesAreSupported() (bool, error) { return false, nil }

var _ db.DB = (*captureDB)(nil)
