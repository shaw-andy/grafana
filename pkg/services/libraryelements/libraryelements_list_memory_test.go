package libraryelements

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/libraryelements/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/util/xorm"
	"github.com/grafana/grafana/pkg/util/xorm/core"
	"github.com/grafana/grafana/pkg/web"
)

// TestIntegration_LibraryElementListDoesNotMaterializeEveryModel locks the
// list endpoint to a page-sized read of library panel models.
//
// GET /api/library-elements, and LibraryElementService.GetAllElements behind it,
// answers totalCount from a second query. That query selects every library
// element in the organization, including the model column, and counts the rows
// in process. perPage limits only the page query. The route authorizes an
// unscoped library.panels:read, which the built-in Viewer grant on the root
// folder satisfies, so a Viewer reaches the scan. Models stored in folders the
// viewer cannot list are included.
//
// Editors persist those models. The built-in Editor grant creates panels in the
// root folder. Folder edit grants create and write on one folder. Create and
// patch both bind the body through web.Bind and store the model column as given.
//
// A call fails this test while it still allocates model bytes for rows it does
// not return. It passes when the same calls keep the counts and page contents,
// an editor can still store a large model, and listing no longer reads those bytes.
func TestIntegration_LibraryElementListDoesNotMaterializeEveryModel(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	// Shipped default. The handler stays on the legacy SQL path unless this flag is on.
	require.False(t, useKubernetesLibraryPanels(context.Background()),
		"legacy SQL list path is the one under test")

	sc := setupTestScenario(t)
	generalScope := folder.ScopeFoldersProvider.GetResourceScopeUID(ac.GeneralFolderUID)
	private := &folder.Folder{ID: 42, OrgID: sc.user.OrgID, UID: "private-folder", Title: "Private"}
	sc.folderSvc.AddFolder(&folder.Folder{ID: 0, OrgID: sc.user.OrgID, UID: ac.GeneralFolderUID, Title: "General"})
	sc.folderSvc.AddFolder(private)
	privateScope := folder.ScopeFoldersProvider.GetResourceScopeUID(private.UID)

	editor := &user.SignedInUser{
		UserID:  2,
		UserUID: "editor-user",
		OrgID:   sc.user.OrgID,
		OrgRole: org.RoleEditor,
		Login:   "editor",
		Permissions: map[int64]map[string][]string{
			sc.user.OrgID: {
				// fixed:library.panels:general.writer, granted to Editor.
				ActionLibraryPanelsCreate: {generalScope},
				ActionLibraryPanelsRead:   {generalScope},
				ActionLibraryPanelsWrite:  {generalScope},
			},
		},
	}

	// Root-folder create stores a model. A folder the editor cannot write is
	// refused before a row is inserted.
	visible := createPanel(t, sc, editor, ac.GeneralFolderUID, "a-visible", tinyPanelModel("visible-panel"))
	require.Equal(t, int64(0), libraryElementFolderID(t, sc, visible.UID))
	denied := createPanelRaw(t, sc, editor, private.UID, "z-hidden-denied", tinyPanelModel("denied"))
	require.Equal(t, http.StatusForbidden, denied.Status())
	require.Equal(t, int64(1), countLibraryElements(t, sc))

	// Folder edit grants library.panels:create and library.panels:write on that folder.
	editor.Permissions[sc.user.OrgID][ActionLibraryPanelsCreate] = []string{generalScope, privateScope}
	editor.Permissions[sc.user.OrgID][ActionLibraryPanelsRead] = []string{generalScope, privateScope}
	editor.Permissions[sc.user.OrgID][ActionLibraryPanelsWrite] = []string{generalScope, privateScope}
	hiddenOne := createPanel(t, sc, editor, private.UID, "z-hidden-1", tinyPanelModel("hidden-1"))
	hiddenTwo := createPanel(t, sc, editor, private.UID, "z-hidden-2", tinyPanelModel("hidden-2"))
	require.Equal(t, private.UID, libraryElementFolderUID(t, sc, hiddenOne.UID))
	require.Equal(t, private.UID, libraryElementFolderUID(t, sc, hiddenTwo.UID))
	// GetFolders is the viewer's folder tree. The fake returns ExpectedFolders for
	// every caller; drop the private folder so the tree matches a viewer who
	// cannot open it. UID lookup for writes stays on foldersByUID.
	sc.folderSvc.ExpectedFolders = foldersExcept(sc.folderSvc.ExpectedFolders, private.UID)

	viewer := &user.SignedInUser{
		UserID:  3,
		UserUID: "viewer-user",
		OrgID:   sc.user.OrgID,
		OrgRole: org.RoleViewer,
		Login:   "viewer",
		Permissions: map[int64]map[string][]string{
			sc.user.OrgID: {
				// fixed:library.panels:general.reader, granted to Viewer.
				ActionLibraryPanelsRead: {generalScope},
			},
		},
	}
	viewerCtx := identity.WithRequester(context.Background(), viewer)
	mutated, err := ac.EvalPermission(ActionLibraryPanelsRead).MutateScopes(viewerCtx, func(context.Context, string) ([]string, error) {
		t.Fatal("unscoped library.panels:read must not resolve a scope")
		return nil, nil
	})
	require.NoError(t, err)
	allowed, err := sc.service.AccessControl.Evaluate(viewerCtx, viewer, mutated)
	require.NoError(t, err)
	require.True(t, allowed, "Viewer with the root-folder library.panels:read grant can call the list route")

	capture := installSQLCapture(t, sc)
	const perPage = 1
	const modelPadding = 1 << 20
	// Slack covers allocator noise between two runs of the same call. It is far
	// below one stored model, so reading an unreturned model still fails.
	const allocSlack = 256 << 10

	// Warm one-time allocations, then record baselines while every model is tiny.
	_ = listPanels(t, sc, viewer, perPage, "")
	viewerBaseline := listPanels(t, sc, viewer, perPage, "")
	require.Equal(t, int64(1), viewerBaseline.total)
	require.Len(t, viewerBaseline.elements, 1)
	require.Equal(t, "a-visible", viewerBaseline.elements[0].Name)
	searchBaseline := listPanels(t, sc, viewer, perPage, "z-hidden")
	require.Equal(t, int64(0), searchBaseline.total)
	require.Empty(t, searchBaseline.elements)
	adminBaseline := getAllElements(t, sc, &sc.user, model.SearchLibraryElementsQuery{
		PerPage:                perPage,
		Page:                   1,
		SkipFolderTreeForAdmin: true,
	})
	require.Equal(t, int64(3), adminBaseline.total)
	require.Len(t, adminBaseline.elements, perPage)

	const hiddenMarker = "hidden-library-model-marker"
	large := largePanelModel(hiddenMarker, modelPadding)
	// Patch resolves the current folder by id. The fake Get ignores id and
	// returns ExpectedFolder, so point that at the private folder. The stored
	// folder_uid must stay the one the viewer cannot open.
	sc.folderSvc.ExpectedFolder = private
	patchPanelModel(t, sc, editor, hiddenOne, large)
	patchPanelModel(t, sc, editor, hiddenTwo, large)
	require.Equal(t, private.UID, libraryElementFolderUID(t, sc, hiddenOne.UID))
	require.Equal(t, private.UID, libraryElementFolderUID(t, sc, hiddenTwo.UID))
	require.GreaterOrEqual(t, modelColumnBytes(t, sc, hiddenOne.UID), modelPadding)
	require.GreaterOrEqual(t, modelColumnBytes(t, sc, hiddenTwo.UID), modelPadding)
	capture.reset()

	t.Run("viewer page", func(t *testing.T) {
		viewerList := listPanels(t, sc, viewer, perPage, "")
		require.Equal(t, http.StatusOK, viewerList.status)
		require.Equal(t, int64(1), viewerList.total, "totalCount counts panels the viewer can open")
		require.Len(t, viewerList.elements, perPage)
		require.Equal(t, "a-visible", viewerList.elements[0].Name)
		require.NotContains(t, viewerList.body, hiddenMarker)
		assertPageSizedModelRead(t, viewerList, viewerBaseline.alloc, allocSlack, perPage)
	})

	t.Run("viewer search misses inaccessible folders", func(t *testing.T) {
		viewerSearch := listPanels(t, sc, viewer, perPage, "z-hidden")
		require.Equal(t, http.StatusOK, viewerSearch.status)
		require.Equal(t, int64(0), viewerSearch.total, "search does not count panels in folders the viewer cannot open")
		require.Empty(t, viewerSearch.elements)
		require.NotContains(t, viewerSearch.body, hiddenMarker)
		assertPageSizedModelRead(t, viewerSearch, searchBaseline.alloc, allocSlack, perPage)
	})

	// GetAllElements is the same scan. The dashboard library-element index calls
	// it with SkipFolderTreeForAdmin, and cloud-migration snapshots call it to
	// export every panel. perPage still has to bound the model read.
	t.Run("admin get all elements", func(t *testing.T) {
		adminList := getAllElements(t, sc, &sc.user, model.SearchLibraryElementsQuery{
			PerPage:                perPage,
			Page:                   1,
			SkipFolderTreeForAdmin: true,
		})
		require.Equal(t, int64(3), adminList.total, "an admin total still counts every panel")
		require.Len(t, adminList.elements, perPage)
		require.Equal(t, "a-visible", adminList.elements[0].Name)
		assertPageSizedModelRead(t, adminList, adminBaseline.alloc, allocSlack, perPage)
	})
}

type listResult struct {
	status   int
	total    int64
	elements []libraryElement
	body     string
	alloc    uint64
	queries  []string
}

func listPanels(t *testing.T, sc scenarioContext, u *user.SignedInUser, perPage int, search string) listResult {
	t.Helper()
	path := fmt.Sprintf("/api/library-elements?perPage=%d&page=1", perPage)
	if search != "" {
		path += "&searchString=" + search
	}
	rc := userReqContext(u, http.MethodGet, path)

	var resp response.Response
	alloc := allocatedDuring(func() {
		resp = sc.service.getAllHandler(rc)
	})
	require.NotNil(t, resp)
	body := resp.Body()
	var parsed libraryElementsSearch
	if resp.Status() == http.StatusOK {
		require.NoError(t, json.Unmarshal(body, &parsed))
	}
	return listResult{
		status:   resp.Status(),
		total:    parsed.Result.TotalCount,
		elements: parsed.Result.Elements,
		body:     string(body),
		alloc:    alloc,
		queries:  currentSQLCapture(t).reset(),
	}
}

func getAllElements(t *testing.T, sc scenarioContext, u *user.SignedInUser, query model.SearchLibraryElementsQuery) listResult {
	t.Helper()
	ctx := identity.WithRequester(context.Background(), u)
	var result model.LibraryElementSearchResult
	var err error
	alloc := allocatedDuring(func() {
		result, err = sc.service.GetAllElements(ctx, u, query)
	})
	require.NoError(t, err)
	return listResult{
		total:    result.TotalCount,
		elements: dtoNames(result.Elements),
		alloc:    alloc,
		queries:  currentSQLCapture(t).reset(),
	}
}

func dtoNames(in []model.LibraryElementDTO) []libraryElement {
	out := make([]libraryElement, len(in))
	for i, el := range in {
		out[i].Name = el.Name
		out[i].UID = el.UID
	}
	return out
}

func assertPageSizedModelRead(t *testing.T, got listResult, baseline uint64, slack uint64, perPage int) {
	t.Helper()
	require.NotEmpty(t, got.queries, "list issued no SQL; capture did not see the query under test")

	var bad []string
	sawModel := false
	for _, q := range got.queries {
		if !selectsLibraryElementModel(q) {
			continue
		}
		sawModel = true
		limit, ok := sqlLimit(q)
		if !ok || limit > perPage {
			bad = append(bad, q)
		}
	}
	require.Empty(t, bad, "model column was selected without a page-sized limit")
	// A returned page still has to read its own model. An empty page does not.
	if len(got.elements) > 0 {
		require.True(t, sawModel, "returned a library panel without selecting its model")
	}

	// baseline is the same call while every model was tiny, so handler overhead
	// cancels out. Growth past slack is model bytes for rows that were not returned.
	require.Less(t, got.alloc, baseline+slack,
		"list allocated %d bytes after large models were stored, baseline %d", got.alloc, baseline)
}

func selectsLibraryElementModel(sql string) bool {
	lower := strings.ToLower(sql)
	return strings.Contains(lower, "le.model") || strings.Contains(lower, `le."model"`) || strings.Contains(lower, "le.`model`")
}

var limitRegexp = regexp.MustCompile(`(?i)\blimit\s+(\d+)`)

func sqlLimit(sql string) (int, bool) {
	m := limitRegexp.FindStringSubmatch(sql)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

func createPanel(t *testing.T, sc scenarioContext, u *user.SignedInUser, folderUID, name string, panelModel []byte) libraryElement {
	t.Helper()
	resp := createPanelRaw(t, sc, u, folderUID, name, panelModel)
	return validateAndUnMarshalResponse(t, resp).Result
}

func createPanelRaw(t *testing.T, sc scenarioContext, u *user.SignedInUser, folderUID, name string, panelModel []byte) response.Response {
	t.Helper()
	// Same evaluator the POST route registers. The handler then checks create
	// on the target folder and refuses before insert when that check fails.
	allowed, err := sc.service.AccessControl.Evaluate(identity.WithRequester(context.Background(), u), u, ac.EvalPermission(ActionLibraryPanelsCreate))
	require.NoError(t, err)
	require.True(t, allowed, "create route authorization")

	rc := userReqContext(u, http.MethodPost, "/api/library-elements")
	rc.Req.Body = mockRequestBody(model.CreateLibraryElementCommand{
		FolderUID: &folderUID,
		Name:      name,
		Model:     panelModel,
		Kind:      int64(model.PanelElement),
	})
	return sc.service.createHandler(rc)
}

func patchPanelModel(t *testing.T, sc scenarioContext, u *user.SignedInUser, existing libraryElement, panelModel []byte) {
	t.Helper()
	ctx := identity.WithRequester(context.Background(), u)
	allowed, err := sc.service.AccessControl.Evaluate(ctx, u, ac.EvalPermission(
		ActionLibraryPanelsWrite,
		ScopeLibraryPanelsProvider.GetResourceScopeUID(existing.UID),
	))
	require.NoError(t, err)
	require.True(t, allowed, "patch route authorization for %s", existing.UID)

	rc := userReqContext(u, http.MethodPatch, "/api/library-elements/"+existing.UID)
	rc.Req = web.SetURLParams(rc.Req, map[string]string{":uid": existing.UID})
	rc.Req.Body = mockRequestBody(model.PatchLibraryElementCommand{
		FolderID: -1, // nolint:staticcheck // omitted folderId; -1 keeps the current folder
		Name:     existing.Name,
		Model:    panelModel,
		Kind:     int64(model.PanelElement),
		Version:  existing.Version,
	})
	resp := sc.service.patchHandler(rc)
	patched := validateAndUnMarshalResponse(t, resp)
	require.Equal(t, existing.Version+1, patched.Result.Version)
}

func userReqContext(u *user.SignedInUser, method, path string) *contextmodel.ReqContext {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(identity.WithRequester(context.Background(), u))
	return &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: u,
		IsSignedIn:   true,
		Logger:       log.NewNopLogger(),
	}
}

func tinyPanelModel(description string) []byte {
	return []byte(fmt.Sprintf(`{"type":"text","description":%q}`, description))
}

func largePanelModel(marker string, padding int) []byte {
	return []byte(fmt.Sprintf(`{"type":"text","description":%q,"padding":"%s"}`, marker, strings.Repeat("m", padding)))
}

func libraryElementFolderID(t *testing.T, sc scenarioContext, uid string) int64 {
	t.Helper()
	var folderID int64
	err := sc.sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL("SELECT folder_id FROM library_element WHERE uid=?", uid).Get(&folderID)
		return err
	})
	require.NoError(t, err)
	return folderID
}

func libraryElementFolderUID(t *testing.T, sc scenarioContext, uid string) string {
	t.Helper()
	var folderUID string
	err := sc.sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL("SELECT folder_uid FROM library_element WHERE uid=?", uid).Get(&folderUID)
		return err
	})
	require.NoError(t, err)
	return folderUID
}

func modelColumnBytes(t *testing.T, sc scenarioContext, uid string) int {
	t.Helper()
	var n int
	err := sc.sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL("SELECT length(model) FROM library_element WHERE uid=?", uid).Get(&n)
		return err
	})
	require.NoError(t, err)
	return n
}

func countLibraryElements(t *testing.T, sc scenarioContext) int64 {
	t.Helper()
	var n int64
	err := sc.sqlStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL("SELECT count(*) FROM library_element").Get(&n)
		return err
	})
	require.NoError(t, err)
	return n
}

func foldersExcept(in []*folder.Folder, uid string) []*folder.Folder {
	out := make([]*folder.Folder, 0, len(in))
	for _, f := range in {
		if f != nil && f.UID != uid {
			out = append(out, f)
		}
	}
	return out
}

func allocatedDuring(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// sqlCapture records statements xorm logs while showSQL is on.
type sqlCapture struct {
	mu      sync.Mutex
	queries []string
}

func installSQLCapture(t *testing.T, sc scenarioContext) *sqlCapture {
	t.Helper()
	capture := &sqlCapture{}
	engine := sc.sqlStore.GetEngine()
	engine.SetLogger(capture)
	t.Cleanup(func() {
		engine.SetLogger(&xorm.DiscardLogger{})
		activeCapture = nil
	})
	activeCapture = capture
	return capture
}

// activeCapture is set for the duration of the integration test that installs it.
// Tests in this package do not run in parallel.
var activeCapture *sqlCapture

func currentSQLCapture(t *testing.T) *sqlCapture {
	t.Helper()
	require.NotNil(t, activeCapture)
	return activeCapture
}

func (c *sqlCapture) reset() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]string(nil), c.queries...)
	c.queries = nil
	return out
}

func (c *sqlCapture) record(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	if !strings.Contains(msg, "[SQL]") && !strings.Contains(strings.ToLower(msg), "select") {
		return
	}
	c.mu.Lock()
	c.queries = append(c.queries, msg)
	c.mu.Unlock()
}

func (c *sqlCapture) Debug(v ...any)                 {}
func (c *sqlCapture) Debugf(format string, v ...any) { c.record(format, v...) }
func (c *sqlCapture) Error(v ...any)                 {}
func (c *sqlCapture) Errorf(format string, v ...any) {}
func (c *sqlCapture) Info(v ...any)                  {}
func (c *sqlCapture) Infof(format string, v ...any)  { c.record(format, v...) }
func (c *sqlCapture) Warn(v ...any)                  {}
func (c *sqlCapture) Warnf(format string, v ...any)  {}
func (c *sqlCapture) Level() core.LogLevel           { return core.LOG_INFO }
func (c *sqlCapture) SetLevel(core.LogLevel)         {}
func (c *sqlCapture) ShowSQL(...bool)                {}
func (c *sqlCapture) IsShowSQL() bool                { return true }

var _ core.ILogger = (*sqlCapture)(nil)
