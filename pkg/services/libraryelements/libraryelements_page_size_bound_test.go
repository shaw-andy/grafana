package libraryelements

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/open-feature/go-sdk/openfeature"
	"github.com/open-feature/go-sdk/openfeature/memprovider"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/util/xorm"
	"github.com/grafana/grafana/pkg/util/xorm/core"
	"github.com/grafana/grafana/pkg/web"
)

// libraryElementMaxPageSize is the largest perPage GET /api/library-elements may
// turn into a SQL limit or a response page. The handler's documented default is
// 100, and that is the fixed maximum a caller-supplied perPage must be capped to
// before the limit and the offset are built.
const libraryElementMaxPageSize = 100

// libraryElementModelColumn is selected by both the page query and the count query.
// An unbounded result therefore buffers every panel model in memory.
const libraryElementModelColumn = "le.model"

var libraryElementLimitPattern = regexp.MustCompile(`(?i)\bLIMIT\s+(-?\d+)(?:\s+OFFSET\s+(-?\d+))?`)

// TestIntegrationLibraryElementPageSizeBound covers GET /api/library-elements.
// The handler reads perPage and page with QueryInt and, when perPage is
// positive, uses that value as the SQL limit and as the multiplier for the
// offset. These tests call that handler and read the SQL the database executes.
func TestIntegrationLibraryElementPageSizeBound(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("a page inside the maximum returns one page and does not buffer every model", func(t *testing.T) {
		sc := setupTestScenario(t)
		createLibraryPanels(t, sc, 2)
		stored := countStoredLibraryElements(t, sc)

		result, queries := listLibraryElements(t, sc, viewerPermissions(sc), "perPage=1&page=1")

		require.Equal(t, http.StatusOK, result.status)
		require.Equal(t, 1, result.page.Result.PerPage)
		require.Len(t, result.page.Result.Elements, 1)
		require.Equal(t, int64(stored), result.page.Result.TotalCount)
		require.NotEmpty(t, result.page.Result.Elements[0].Model)
		assertModelSelectsBounded(t, queries)
	})

	t.Run("a viewer perPage of one billion is bounded before the model query", func(t *testing.T) {
		sc := setupTestScenario(t)
		createLibraryPanels(t, sc, libraryElementMaxPageSize+1)
		stored := countStoredLibraryElements(t, sc)
		require.Greater(t, stored, libraryElementMaxPageSize)

		// The route authorizes any signed-in user who has library.panels:read,
		// which the Viewer builtin role grants, and then calls getAllHandler.
		result, queries := listLibraryElements(t, sc, viewerPermissions(sc), "perPage=1000000000&page=1")

		if result.status == http.StatusOK {
			require.LessOrEqual(t, len(result.page.Result.Elements), libraryElementMaxPageSize, "returned %d elements out of %d with perPage %d; queries:\n%s", len(result.page.Result.Elements), stored, result.page.Result.PerPage, strings.Join(queries, "\n---\n"))
			require.LessOrEqual(t, result.page.Result.PerPage, libraryElementMaxPageSize)
			require.Equal(t, int64(stored), result.page.Result.TotalCount, "counting matches must not drop rows to hide an unbounded read")
			for _, element := range result.page.Result.Elements {
				require.NotEmpty(t, element.Model)
			}
		} else {
			require.GreaterOrEqual(t, result.status, 400)
			require.Less(t, result.status, 500)
		}
		assertModelSelectsBounded(t, queries)
	})

	t.Run("a page and perPage whose product overflows is rejected before the query", func(t *testing.T) {
		sc := setupTestScenario(t)
		createLibraryPanels(t, sc, 1)

		perPage := 1_000_000_000
		// (page-1)*perPage does not fit in the platform int that QueryInt returns
		// and that writePerPageSQL multiplies.
		page := int(math.MaxInt/int64(perPage)) + 2
		require.Greater(t, page, 1)
		require.True(t, multiplyOverflowsInt(perPage, page-1), "fixture must overflow int multiplication")

		result, queries := listLibraryElements(t, sc, viewerPermissions(sc), fmt.Sprintf("perPage=%d&page=%d", perPage, page))

		require.GreaterOrEqual(t, result.status, 400, "overflow was executed: status %d body %s queries:\n%s", result.status, result.raw, strings.Join(queries, "\n---\n"))
		require.Less(t, result.status, 500, "overflow must be rejected, not executed as a wrapped offset: status %d body %s queries:\n%s", result.status, result.raw, strings.Join(queries, "\n---\n"))
		assertModelSelectsBounded(t, queries)
		for _, query := range queries {
			if !strings.Contains(query, libraryElementModelColumn) {
				continue
			}
			for _, match := range libraryElementLimitPattern.FindAllStringSubmatch(query, -1) {
				offset, err := strconv.ParseInt(match[2], 10, 64)
				if err == nil {
					require.GreaterOrEqual(t, offset, int64(0), "query %s", query)
				}
			}
		}
	})
}

// TestLibraryElementKubernetesPageSizeBound covers the same query parameters on
// the kubernetes library panel list. getAllHandler forwards perPage unchanged
// when that path is enabled, and the response then contains every listed panel.
func TestLibraryElementKubernetesPageSizeBound(t *testing.T) {
	const panels = libraryElementMaxPageSize + 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(kubernetesLibraryPanelList(panels)))
	}))
	t.Cleanup(server.Close)

	flag := featuremgmt.FlagLibraryelementsKubernetesLibraryPanels
	require.NoError(t, openfeature.SetProviderAndWait(memprovider.NewInMemoryProvider(map[string]memprovider.InMemoryFlag{
		flag: {
			Key:            flag,
			DefaultVariant: "enabled",
			Variants:       map[string]any{"enabled": true},
		},
	})))
	t.Cleanup(func() { _ = openfeature.SetProviderAndWait(openfeature.NoopProvider{}) })

	dash := dashboards.NewFakeDashboardService(t)
	dash.On("GetDashboardsByLibraryPanelUID", mock.Anything, mock.Anything, mock.Anything).Return([]*dashboards.DashboardRef{}, nil)

	service := &LibraryElementService{
		k8sHandler: newLibraryElementsK8sHandler(nil, testDirectRestConfigProvider{host: server.URL}, nil, nil, dash),
		log:        log.NewNopLogger(),
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/library-elements?perPage=1000000000&page=1", nil)
	viewer := &user.SignedInUser{
		UserID:  1,
		OrgID:   1,
		OrgRole: org.RoleViewer,
		Permissions: map[int64]map[string][]string{
			1: {ActionLibraryPanelsRead: {folder.ScopeFoldersProvider.GetResourceScopeUID(ac.GeneralFolderUID)}},
		},
	}
	req = req.WithContext(identity.WithRequester(req.Context(), viewer))
	reqContext := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  req,
			Resp: web.NewResponseWriter(http.MethodGet, recorder),
		},
		SignedInUser: viewer,
		Logger:       log.NewNopLogger(),
		IsSignedIn:   true,
	}

	// Same route gate as the SQL path: library.panels:read with no scope.
	require.True(t, ac.EvalPermission(ActionLibraryPanelsRead).Evaluate(viewer.GetPermissions()), "a Viewer with library.panels:read must pass the list route")

	resp := service.getAllHandler(reqContext)
	require.Nil(t, resp, "the kubernetes branch writes the response itself")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	var page libraryElementsSearch
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &page))
	require.LessOrEqual(t, len(page.Result.Elements), libraryElementMaxPageSize, "returned %d elements and perPage %d", len(page.Result.Elements), page.Result.PerPage)
	require.LessOrEqual(t, page.Result.PerPage, libraryElementMaxPageSize)
	require.Equal(t, int64(panels), page.Result.TotalCount)
	for _, element := range page.Result.Elements {
		require.NotEmpty(t, element.Model)
	}
}

type libraryElementListResult struct {
	status int
	raw    []byte
	page   libraryElementsSearch
}

func listLibraryElements(t *testing.T, sc scenarioContext, permissions map[string][]string, rawQuery string) (libraryElementListResult, []string) {
	t.Helper()

	require.NoError(t, openfeature.SetProviderAndWait(openfeature.NoopProvider{}))
	t.Cleanup(func() { _ = openfeature.SetProviderAndWait(openfeature.NoopProvider{}) })

	sc.reqContext.OrgRole = org.RoleViewer
	sc.reqContext.IsSignedIn = true
	sc.reqContext.Logger = log.NewNopLogger()
	sc.reqContext.Permissions[sc.reqContext.OrgID] = permissions

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/library-elements?"+rawQuery, nil)
	req = req.WithContext(identity.WithRequester(req.Context(), sc.reqContext.SignedInUser))
	sc.reqContext.Req = req
	sc.reqContext.Resp = web.NewResponseWriter(http.MethodGet, recorder)

	ac.Middleware(sc.service.AccessControl)(ac.EvalPermission(ActionLibraryPanelsRead)).(func(*contextmodel.ReqContext))(sc.reqContext)
	require.Empty(t, recorder.Body.String(), "Viewer with library.panels:read must pass the list route, got %s", recorder.Body.String())

	var queries []string
	var resp response.Response
	queries = captureSQL(t, sc.sqlStore, func() {
		resp = sc.service.getAllHandler(sc.reqContext)
	})
	require.NotNil(t, resp)

	parsed := libraryElementListResult{status: resp.Status(), raw: resp.Body()}
	if parsed.status == http.StatusOK {
		require.NoError(t, json.Unmarshal(parsed.raw, &parsed.page))
	}
	return parsed, queries
}

func viewerPermissions(sc scenarioContext) map[string][]string {
	folderScope := folder.ScopeFoldersProvider.GetResourceScopeUID(sc.folder.UID)
	generalScope := folder.ScopeFoldersProvider.GetResourceScopeUID(ac.GeneralFolderUID)
	// Viewer is granted library.panels:read on the root folder. Folder view
	// grants the same action on the folder that holds the panels.
	return map[string][]string{
		ActionLibraryPanelsRead:  {generalScope, folderScope},
		folder.ActionFoldersRead: {generalScope, folderScope},
	}
}

func createLibraryPanels(t *testing.T, sc scenarioContext, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		command := getCreatePanelCommand(sc.folder.ID, sc.folder.UID, fmt.Sprintf("Bounded page panel %d", i))
		sc.reqContext.Req.Body = mockRequestBody(command)
		resp := sc.service.createHandler(sc.reqContext)
		require.Equal(t, http.StatusOK, resp.Status(), string(resp.Body()))
	}
}

func countStoredLibraryElements(t *testing.T, sc scenarioContext) int {
	t.Helper()
	var count int
	err := sc.sqlStore.WithDbSession(t.Context(), func(session *db.Session) error {
		has, err := session.SQL("SELECT COUNT(*) FROM library_element WHERE org_id=?", sc.reqContext.OrgID).Get(&count)
		if err != nil {
			return err
		}
		if !has {
			count = 0
		}
		return nil
	})
	require.NoError(t, err)
	return count
}

func assertModelSelectsBounded(t *testing.T, queries []string) {
	t.Helper()
	sawModelSelect := false
	for _, query := range queries {
		if !strings.Contains(query, libraryElementModelColumn) {
			continue
		}
		sawModelSelect = true
		matches := libraryElementLimitPattern.FindAllStringSubmatch(query, -1)
		require.NotEmpty(t, matches, "query selects %s without a LIMIT:\n%s", libraryElementModelColumn, query)
		for _, match := range matches {
			limit, err := strconv.ParseInt(match[1], 10, 64)
			require.NoError(t, err)
			require.Greater(t, limit, int64(0), "query %s", query)
			require.LessOrEqual(t, limit, int64(libraryElementMaxPageSize), "caller page size reached the model query as LIMIT %d:\n%s", limit, query)
			if match[2] != "" {
				offset, err := strconv.ParseInt(match[2], 10, 64)
				require.NoError(t, err)
				require.GreaterOrEqual(t, offset, int64(0), "offset wrapped through int multiplication:\n%s", query)
			}
		}
	}
	require.True(t, sawModelSelect, "the list request never selected library element models; queries: %v", queries)
}

func multiplyOverflowsInt(a, b int) bool {
	if a == 0 || b == 0 {
		return false
	}
	if a > 0 && b > 0 {
		return b > math.MaxInt/a
	}
	if a < 0 && b < 0 {
		return a < math.MaxInt/b
	}
	if a > 0 && b < 0 {
		return b < math.MinInt/a
	}
	return a < math.MinInt/b
}

func captureSQL(t *testing.T, store db.DB, fn func()) []string {
	t.Helper()
	logger := &sqlCaptureLogger{}
	engine := store.GetEngine()
	engine.SetLogger(logger)
	engine.ShowSQL(true)
	t.Cleanup(func() {
		engine.SetLogger(&xorm.DiscardLogger{})
	})
	fn()
	return logger.queries()
}

type sqlCaptureLogger struct {
	mu   sync.Mutex
	sqls []string
}

func (l *sqlCaptureLogger) queries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.sqls))
	copy(out, l.sqls)
	return out
}

func (l *sqlCaptureLogger) record(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sqls = append(l.sqls, fmt.Sprintf(format, args...))
}

func (l *sqlCaptureLogger) Debug(v ...any)                {}
func (l *sqlCaptureLogger) Debugf(string, ...any)         {}
func (l *sqlCaptureLogger) Error(v ...any)                {}
func (l *sqlCaptureLogger) Errorf(string, ...any)         {}
func (l *sqlCaptureLogger) Info(v ...any)                 {}
func (l *sqlCaptureLogger) Infof(format string, v ...any) { l.record(format, v...) }
func (l *sqlCaptureLogger) Warn(v ...any)                 {}
func (l *sqlCaptureLogger) Warnf(string, ...any)          {}
func (l *sqlCaptureLogger) Level() core.LogLevel          { return core.LOG_INFO }
func (l *sqlCaptureLogger) SetLevel(core.LogLevel)        {}
func (l *sqlCaptureLogger) ShowSQL(...bool)               {}
func (l *sqlCaptureLogger) IsShowSQL() bool               { return true }

func kubernetesLibraryPanelList(count int) string {
	items := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, map[string]any{
			"apiVersion": "dashboard.grafana.app/v0alpha1",
			"kind":       "LibraryPanel",
			"metadata": map[string]any{
				"name":       fmt.Sprintf("panel-%d", i),
				"generation": 1,
			},
			"spec": map[string]any{
				"type":        "text",
				"title":       fmt.Sprintf("Panel %d", i),
				"options":     map[string]any{},
				"fieldConfig": map[string]any{},
			},
		})
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": "dashboard.grafana.app/v0alpha1",
		"kind":       "LibraryPanelList",
		"metadata":   map[string]any{},
		"items":      items,
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}
