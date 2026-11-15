package dashboard

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	authnlib "github.com/grafana/authlib/authn"
	"github.com/grafana/authlib/types"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"modernc.org/sqlite"

	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/registry/apis/dashboard/legacy"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	grafanarequest "github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/libraryelements"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
	"github.com/grafana/grafana/pkg/services/sqlstore/session"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/storage/legacysql/dualwrite"
	"github.com/grafana/grafana/pkg/util/xorm"
	"github.com/grafana/grafana/pkg/util/xorm/core"
)

const (
	libraryPanelModelCounterDriver = "librarypanelmodelcount"
	// A list must not ask the database for more library-panel models than this,
	// whatever limit the client sends. The fixture count is larger on purpose.
	libraryPanelListPageCap = int64(100)
	// The page may over-read by a few rows to build a continue token.
	libraryPanelPageOverfetch = int64(5)
	libraryPanelFixtureCount  = 120
)

func init() {
	sql.Register(libraryPanelModelCounterDriver, panelModelCounter)
}

// panelModelCounter wraps the SQLite driver and counts rows returned by
// library-panel SELECTs that include the model column.
var panelModelCounter = &modelCountingDriver{inner: &sqlite.Driver{}}

type capturedQuery struct {
	SQL  string
	Args []driver.NamedValue
}

type modelCountingDriver struct {
	inner driver.Driver

	mu        sync.Mutex
	queries   []capturedQuery
	modelRows int64
}

func (d *modelCountingDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &modelCountingConn{inner: conn, stats: d}, nil
}

func (d *modelCountingDriver) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queries = nil
	d.modelRows = 0
}

func (d *modelCountingDriver) snapshot() ([]capturedQuery, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]capturedQuery(nil), d.queries...), d.modelRows
}

func (d *modelCountingDriver) record(query string, args []driver.NamedValue) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queries = append(d.queries, capturedQuery{SQL: query, Args: args})
}

func (d *modelCountingDriver) addModelRow(query string) {
	if !libraryPanelModelQuery(query) {
		return
	}
	d.mu.Lock()
	d.modelRows++
	d.mu.Unlock()
}

func libraryPanelModelQuery(query string) bool {
	lower := strings.ToLower(query)
	return strings.Contains(lower, "library_element") && strings.Contains(lower, "model")
}

type modelCountingConn struct {
	inner driver.Conn
	stats *modelCountingDriver
}

func (c *modelCountingConn) Prepare(query string) (driver.Stmt, error) {
	return c.inner.Prepare(query)
}

func (c *modelCountingConn) Close() error { return c.inner.Close() }

func (c *modelCountingConn) Begin() (driver.Tx, error) { return c.inner.Begin() }

func (c *modelCountingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if begin, ok := c.inner.(driver.ConnBeginTx); ok {
		return begin.BeginTx(ctx, opts)
	}
	return c.inner.Begin()
}

func (c *modelCountingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if prep, ok := c.inner.(driver.ConnPrepareContext); ok {
		return prep.PrepareContext(ctx, query)
	}
	return c.inner.Prepare(query)
}

func (c *modelCountingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	exec, ok := c.inner.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return exec.ExecContext(ctx, query, args)
}

func (c *modelCountingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.inner.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	copied := append([]driver.NamedValue(nil), args...)
	c.stats.record(query, copied)
	rows, err := queryer.QueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return &modelCountingRows{Rows: rows, query: query, stats: c.stats}, nil
}

type modelCountingRows struct {
	driver.Rows
	query string
	stats *modelCountingDriver
}

func (r *modelCountingRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == nil {
		r.stats.addModelRow(r.query)
	}
	return err
}

func (r *modelCountingRows) ColumnTypeDatabaseTypeName(index int) string {
	if cols, ok := r.Rows.(driver.RowsColumnTypeDatabaseTypeName); ok {
		return cols.ColumnTypeDatabaseTypeName(index)
	}
	return ""
}

func (r *modelCountingRows) ColumnTypeLength(index int) (int64, bool) {
	if cols, ok := r.Rows.(driver.RowsColumnTypeLength); ok {
		return cols.ColumnTypeLength(index)
	}
	return 0, false
}

func (r *modelCountingRows) ColumnTypeNullable(index int) (bool, bool) {
	if cols, ok := r.Rows.(driver.RowsColumnTypeNullable); ok {
		return cols.ColumnTypeNullable(index)
	}
	return false, false
}

func (r *modelCountingRows) ColumnTypePrecisionScale(index int) (int64, int64, bool) {
	if cols, ok := r.Rows.(driver.RowsColumnTypePrecisionScale); ok {
		return cols.ColumnTypePrecisionScale(index)
	}
	return 0, 0, false
}

func (r *modelCountingRows) ColumnTypeScanType(index int) reflect.Type {
	if cols, ok := r.Rows.(driver.RowsColumnTypeScanType); ok {
		return cols.ColumnTypeScanType(index)
	}
	return reflect.TypeOf("")
}

type libraryPanelSQLDB struct {
	sqlDB  *sql.DB
	sess   *session.SessionDB
	engine *xorm.Engine
}

func (d *libraryPanelSQLDB) WithTransactionalDbSession(context.Context, sqlstore.DBTransactionFunc) error {
	return nil
}

func (d *libraryPanelSQLDB) WithDbSession(_ context.Context, callback sqlstore.DBTransactionFunc) error {
	sess := d.engine.NewSession()
	defer sess.Close()
	return callback(&sqlstore.DBSession{Session: sess})
}

func (d *libraryPanelSQLDB) GetDialect() migrator.Dialect {
	return migrator.NewDialect(migrator.SQLite)
}

func (d *libraryPanelSQLDB) GetDBType() core.DbType { return core.SQLITE }

func (d *libraryPanelSQLDB) GetEngine() *xorm.Engine { return d.engine }

func (d *libraryPanelSQLDB) GetSqlxSession() *session.SessionDB { return d.sess }

func (d *libraryPanelSQLDB) InTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (d *libraryPanelSQLDB) Quote(value string) string { return `"` + value + `"` }

func (d *libraryPanelSQLDB) RecursiveQueriesAreSupported() (bool, error) { return true, nil }

func openLibraryPanelDB(t *testing.T) (*libraryPanelSQLDB, *sql.DB) {
	t.Helper()
	panelModelCounter.reset()
	dsn := filepath.Join(t.TempDir(), "library.db") + "?_time_format=sqlite"
	sqlDB, err := sql.Open(libraryPanelModelCounterDriver, dsn)
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	engine, err := xorm.NewEngine("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = engine.Close() })

	_, err = sqlDB.Exec(`CREATE TABLE library_element (
		id INTEGER PRIMARY KEY,
		org_id INTEGER NOT NULL,
		folder_id INTEGER NOT NULL,
		folder_uid TEXT,
		uid TEXT NOT NULL,
		name TEXT NOT NULL,
		kind INTEGER NOT NULL,
		type TEXT NOT NULL,
		description TEXT NOT NULL,
		model TEXT NOT NULL,
		created DATETIME NOT NULL,
		created_by INTEGER NOT NULL,
		updated DATETIME NOT NULL,
		updated_by INTEGER NOT NULL,
		version INTEGER NOT NULL
	)`)
	require.NoError(t, err)
	_, err = sqlDB.Exec(`CREATE TABLE "user" (id INTEGER PRIMARY KEY, uid TEXT)`)
	require.NoError(t, err)

	return &libraryPanelSQLDB{
		sqlDB:  sqlDB,
		sess:   session.GetSession(sqlx.NewDb(sqlDB, "sqlite3")),
		engine: engine,
	}, sqlDB
}

func insertLibraryPanels(t *testing.T, sqlDB *sql.DB, n int) {
	t.Helper()
	stamp := time.Now().UTC().Format("2006-01-02 15:04:05")
	for i := 1; i <= n; i++ {
		model := fmt.Sprintf(`{"type":"text","title":"panel-%d","description":"%s","options":{},"fieldConfig":{}}`, i, strings.Repeat("x", 1024))
		_, err := sqlDB.Exec(`INSERT INTO library_element (
			org_id, folder_id, folder_uid, uid, name, kind, type, description, model,
			created, created_by, updated, updated_by, version
		) VALUES (1, 0, 'secret-folder', ?, ?, 1, 'text', 'desc', ?, ?, 0, ?, 0, 1)`,
			fmt.Sprintf("panel-%d", i), fmt.Sprintf("Panel %d", i), model, stamp, stamp)
		require.NoError(t, err)
	}
}

func viewer(perms map[string][]string) *identity.StaticRequester {
	delegated := append([]string(nil), identity.ServiceIdentityClaims.Rest.DelegatedPermissions...)
	return &identity.StaticRequester{
		Type:      types.TypeUser,
		UserID:    7,
		UserUID:   "viewer",
		OrgID:     1,
		OrgRole:   identity.RoleViewer,
		Namespace: "default",
		Permissions: map[int64]map[string][]string{
			1: perms,
		},
		AccessTokenClaims: &authnlib.Claims[authnlib.AccessTokenClaims]{
			Rest: authnlib.AccessTokenClaims{DelegatedPermissions: delegated},
		},
	}
}

func listContext(user identity.Requester) context.Context {
	ctx := identity.WithRequester(context.Background(), user)
	return k8srequest.WithNamespace(ctx, user.GetNamespace())
}

func newLibraryPanelStore(database db.DB) *LibraryPanelStore {
	return &LibraryPanelStore{
		Access: legacy.NewDashboardSQLAccess(
			legacysql.NewDatabaseProvider(database),
			grafanarequest.GetNamespaceMapper(&setting.Cfg{}),
			nil,
			acimpl.ProvideAccessControlTest(),
		),
		ResourceInfo: dashv0.LibraryPanelResourceInfo,
	}
}

func libraryPanelModelRead(queries []capturedQuery) (capturedQuery, bool) {
	var found capturedQuery
	ok := false
	for _, query := range queries {
		if libraryPanelModelQuery(query.SQL) {
			found = query
			ok = true
		}
	}
	return found, ok
}

func sqlLimit(query capturedQuery) (int64, bool) {
	idx := strings.LastIndex(strings.ToUpper(query.SQL), "LIMIT")
	if idx < 0 {
		return 0, false
	}
	argIndex := strings.Count(query.SQL[:idx], "?")
	if argIndex >= len(query.Args) {
		return 0, false
	}
	switch value := query.Args[argIndex].Value.(type) {
	case int64:
		return value, true
	case int:
		return int64(value), true
	case int32:
		return int64(value), true
	default:
		return 0, false
	}
}

// boundFor is the most model rows a list of the requested size may read.
// A non-positive request is the storage default page, which is still capped.
func boundFor(requested int64) int64 {
	page := requested
	if page < 1 {
		page = 25
	}
	if page > libraryPanelListPageCap {
		page = libraryPanelListPageCap
	}
	return page + libraryPanelPageOverfetch
}

func requireBoundedModelRead(t *testing.T, requested int64) {
	t.Helper()
	queries, modelRows := panelModelCounter.snapshot()
	query, ok := libraryPanelModelRead(queries)
	require.Truef(t, ok, "list did not query library panel models; queries=%v", queries)
	limit, hasLimit := sqlLimit(query)
	require.Truef(t, hasLimit, "library panel list SQL has no row limit (model rows read: %d):\n%s", modelRows, query.SQL)
	bound := boundFor(requested)
	require.LessOrEqualf(t, limit, bound, "SQL limit %d exceeds the page bound %d for requested limit %d", limit, bound, requested)
	require.LessOrEqualf(t, modelRows, bound, "read %d library panel models for requested limit %d (bound %d)", modelRows, requested, bound)
}

func TestSignedInViewerLibraryPanelListIsAuthorized(t *testing.T) {
	user := viewer(nil)
	ctx := listContext(user)
	chain := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	chain.Register(dashv0.LibraryPanelResourceInfo.GroupVersion(), (&DashboardsAPIBuilder{
		accessControl: acimpl.ProvideAccessControlTest(),
	}).GetAuthorizer())

	decision, reason, err := chain.Authorize(ctx, authorizer.AttributesRecord{
		User:            user,
		Verb:            "list",
		APIGroup:        dashv0.GROUP,
		APIVersion:      dashv0.VERSION,
		Resource:        dashv0.LIBRARY_PANEL_RESOURCE,
		Namespace:       "default",
		ResourceRequest: true,
	})
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision, "reason: %s", reason)
}

func TestDefaultLibraryPanelStorageModeIsLegacy(t *testing.T) {
	svc := dualwrite.ProvideServiceForTests(&setting.Cfg{})
	gr := schema.GroupResource{Group: dashv0.GROUP, Resource: dashv0.LIBRARY_PANEL_RESOURCE}
	legacyStore := &LibraryPanelStore{ResourceInfo: dashv0.LibraryPanelResourceInfo}
	got, err := svc.NewStorage(gr, legacyStore, legacyStore)
	require.NoError(t, err)
	require.Equal(t, legacyStore, got)
}

func TestLibraryPanelListLimitOneDoesNotReadEveryModel(t *testing.T) {
	database, sqlDB := openLibraryPanelDB(t)
	insertLibraryPanels(t, sqlDB, libraryPanelFixtureCount)
	panelModelCounter.reset()

	store := newLibraryPanelStore(database)
	obj, err := store.List(listContext(viewer(nil)), &internalversion.ListOptions{Limit: 1})
	require.NoError(t, err)
	list, ok := obj.(*dashv0.LibraryPanelList)
	require.True(t, ok)
	require.LessOrEqual(t, len(list.Items), 1)
	requireBoundedModelRead(t, 1)
}

func TestLibraryPanelListReadableViewerStillUsesBoundedSQL(t *testing.T) {
	database, sqlDB := openLibraryPanelDB(t)
	insertLibraryPanels(t, sqlDB, libraryPanelFixtureCount)
	panelModelCounter.reset()

	user := viewer(map[string][]string{
		libraryelements.ActionLibraryPanelsRead: {libraryelements.ScopeLibraryPanelsAll},
	})
	store := newLibraryPanelStore(database)
	obj, err := store.List(listContext(user), &internalversion.ListOptions{Limit: 1})
	require.NoError(t, err)
	list, ok := obj.(*dashv0.LibraryPanelList)
	require.True(t, ok)
	require.Len(t, list.Items, 1)
	requireBoundedModelRead(t, 1)
}

func TestLibraryPanelListCapsClientLimit(t *testing.T) {
	database, sqlDB := openLibraryPanelDB(t)
	insertLibraryPanels(t, sqlDB, libraryPanelFixtureCount)
	panelModelCounter.reset()

	store := newLibraryPanelStore(database)
	_, err := store.List(listContext(viewer(nil)), &internalversion.ListOptions{Limit: 100000})
	require.NoError(t, err)
	requireBoundedModelRead(t, 100000)
}

func TestLibraryPanelListDefaultPageIsBounded(t *testing.T) {
	database, sqlDB := openLibraryPanelDB(t)
	insertLibraryPanels(t, sqlDB, libraryPanelFixtureCount)
	panelModelCounter.reset()

	store := newLibraryPanelStore(database)
	_, err := store.List(listContext(viewer(nil)), &internalversion.ListOptions{})
	require.NoError(t, err)
	requireBoundedModelRead(t, 0)
}

func TestLibraryPanelGetByUIDDoesNotReadOtherModels(t *testing.T) {
	database, sqlDB := openLibraryPanelDB(t)
	insertLibraryPanels(t, sqlDB, libraryPanelFixtureCount)
	panelModelCounter.reset()

	store := newLibraryPanelStore(database)
	obj, err := store.Get(listContext(viewer(map[string][]string{
		libraryelements.ActionLibraryPanelsRead: {libraryelements.ScopeLibraryPanelsAll},
	})), "panel-3", &metav1.GetOptions{})
	require.NoError(t, err)
	panel, ok := obj.(*dashv0.LibraryPanel)
	require.True(t, ok)
	require.Equal(t, "panel-3", panel.Name)

	_, modelRows := panelModelCounter.snapshot()
	require.LessOrEqual(t, modelRows, int64(1))
}
