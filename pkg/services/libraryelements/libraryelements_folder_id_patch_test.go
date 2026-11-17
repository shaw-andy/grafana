package libraryelements

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/log"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	"github.com/grafana/grafana/pkg/services/libraryelements/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

// idSequenceFolderService resolves folder lookups by numeric id, which the
// stock fake folder service ignores. A queued id returns a different folder on
// each successive lookup so a check that re-reads the id can be told apart
// from a check that keeps the folder it authorized.
type idSequenceFolderService struct {
	*foldertest.FakeService
	byID   map[int64][]*folder.Folder
	idGets []*folder.Folder
}

func (s *idSequenceFolderService) Get(ctx context.Context, q *folder.GetFolderQuery) (*folder.Folder, error) {
	if q != nil && q.ID != nil && *q.ID != 0 {
		queue := s.byID[*q.ID]
		if len(queue) == 0 {
			return nil, folder.ErrFolderNotFound
		}
		resolved := queue[0]
		if len(queue) > 1 {
			s.byID[*q.ID] = queue[1:]
		}
		s.idGets = append(s.idGets, resolved)
		return resolved, nil
	}
	return s.FakeService.Get(ctx, q)
}

// recordingAccessControl records library.panels:create decisions so a test can
// require that the folder written is the folder the check allowed.
type recordingAccessControl struct {
	ac.AccessControl
	createAllowed []string
}

func (r *recordingAccessControl) Evaluate(ctx context.Context, user identity.Requester, evaluator ac.Evaluator) (bool, error) {
	allowed, err := r.AccessControl.Evaluate(ctx, user, evaluator)
	if err == nil && allowed && strings.Contains(evaluator.GoString(), ActionLibraryPanelsCreate) {
		r.createAllowed = append(r.createAllowed, evaluator.GoString())
	}
	return allowed, err
}

func TestIntegration_FolderIDPatchSkipsDestinationAuthorization(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("folderId of a view-only folder is forbidden and the panel stays", func(t *testing.T) {
		sc := newLibraryPanel(t)
		source := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		dest := &folder.Folder{ID: source.FolderID + 100, OrgID: sc.user.OrgID, UID: "uid_for_ViewOnly", Title: "ViewOnly"}
		installFolderIDLookup(t, sc, source, dest)
		restrictLibraryEditor(sc.reqContext.SignedInUser, source.FolderUID, []string{dest.UID}, nil)

		stay := patchThroughRoute(t, sc, sc.initialResult.Result.UID, model.PatchLibraryElementCommand{
			FolderID: -1, // nolint:staticcheck
			Name:     "Renamed in place",
			Kind:     int64(model.PanelElement),
			Version:  sc.initialResult.Result.Version,
		})
		require.Equal(t, http.StatusOK, stay.Status())
		require.Equal(t, source, readStoredFolder(t, sc, sc.initialResult.Result.UID))

		moved := patchThroughRoute(t, sc, sc.initialResult.Result.UID, model.PatchLibraryElementCommand{
			FolderID: dest.ID, // nolint:staticcheck
			Kind:     int64(model.PanelElement),
			Version:  sc.initialResult.Result.Version + 1,
		})
		stored := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		require.Equalf(t, http.StatusForbidden, moved.Status(), "panel is stored in %+v", stored)
		require.Equal(t, source, stored)
	})

	t.Run("folderId 0 is forbidden when the caller cannot create in the general folder", func(t *testing.T) {
		sc := newLibraryPanel(t)
		source := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		installFolderIDLookup(t, sc, source)
		restrictLibraryEditor(sc.reqContext.SignedInUser, source.FolderUID, nil, nil)

		resp := patchThroughRoute(t, sc, sc.initialResult.Result.UID, model.PatchLibraryElementCommand{
			FolderID: 0, // nolint:staticcheck
			Kind:     int64(model.PanelElement),
			Version:  sc.initialResult.Result.Version,
		})
		stored := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		require.Equalf(t, http.StatusForbidden, resp.Status(), "panel is stored in %+v", stored)
		require.Equal(t, source, stored)
	})

	t.Run("a patch that omits folderId does not relocate the panel to the general folder", func(t *testing.T) {
		sc := newLibraryPanel(t)
		source := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		installFolderIDLookup(t, sc, source)
		restrictLibraryEditor(sc.reqContext.SignedInUser, source.FolderUID, nil, nil)

		// The JSON body has no folderId and no folderUid. The binding tag's
		// Default(-1) is what keeps a partial patch in the current folder.
		resp := patchThroughRoute(t, sc, sc.initialResult.Result.UID, map[string]any{
			"kind":    int64(model.PanelElement),
			"version": sc.initialResult.Result.Version,
			"name":    "Renamed without a folder",
		})
		stored := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		require.Equal(t, source.FolderUID, stored.FolderUID)
		require.Equal(t, source.FolderID, stored.FolderID)
		if resp.Status() == http.StatusOK {
			return
		}
		require.Equal(t, http.StatusForbidden, resp.Status())
	})

	t.Run("folderId of a repository-managed folder is rejected", func(t *testing.T) {
		sc := newLibraryPanel(t)
		source := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		managed := &folder.Folder{
			ID:        source.FolderID + 100,
			OrgID:     sc.user.OrgID,
			UID:       "uid_for_Managed",
			Title:     "Managed",
			ManagedBy: utils.ManagerKindRepo,
		}
		installFolderIDLookup(t, sc, source, managed)
		// Create is granted on the managed folder so this is not a permission miss.
		restrictLibraryEditor(sc.reqContext.SignedInUser, source.FolderUID, nil, []string{managed.UID})

		resp := patchThroughRoute(t, sc, sc.initialResult.Result.UID, model.PatchLibraryElementCommand{
			FolderID: managed.ID, // nolint:staticcheck
			Kind:     int64(model.PanelElement),
			Version:  sc.initialResult.Result.Version,
		})
		stored := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		require.Equalf(t, http.StatusConflict, resp.Status(), "panel is stored in %+v", stored)
		require.Equal(t, source, stored)
	})

	t.Run("the stored folder is the folder library.panels:create allowed", func(t *testing.T) {
		sc := newLibraryPanel(t)
		source := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		checked := &folder.Folder{ID: source.FolderID + 100, OrgID: sc.user.OrgID, UID: "uid_for_Checked", Title: "Checked"}
		other := &folder.Folder{
			ID:        checked.ID,
			OrgID:     sc.user.OrgID,
			UID:       "uid_for_Other",
			Title:     "Other",
			ManagedBy: utils.ManagerKindRepo,
		}
		lookup := installFolderIDLookup(t, sc, source)
		lookup.byID[checked.ID] = []*folder.Folder{checked, other}
		restrictLibraryEditor(sc.reqContext.SignedInUser, source.FolderUID, []string{other.UID}, []string{checked.UID})
		recorder := &recordingAccessControl{AccessControl: sc.service.AccessControl}
		sc.service.AccessControl = recorder

		resp := patchThroughRoute(t, sc, sc.initialResult.Result.UID, model.PatchLibraryElementCommand{
			FolderID: checked.ID, // nolint:staticcheck
			Kind:     int64(model.PanelElement),
			Version:  sc.initialResult.Result.Version,
		})
		stored := readStoredFolder(t, sc, sc.initialResult.Result.UID)
		if stored.FolderUID == source.FolderUID && stored.FolderID == source.FolderID {
			require.NotEqual(t, http.StatusOK, resp.Status())
			return
		}
		require.Equal(t, http.StatusOK, resp.Status())
		require.NotEqual(t, other.UID, stored.FolderUID)
		require.NotEqual(t, utils.ManagerKindRepo, managedByUID(lookup, stored.FolderUID))
		scope := folder.ScopeFoldersProvider.GetResourceScopeUID(stored.FolderUID)
		require.NotEmpty(t, recorder.createAllowed)
		require.Contains(t, strings.Join(recorder.createAllowed, " "), scope)
		for _, resolved := range lookup.idGets {
			if resolved.ID != checked.ID {
				continue
			}
			if resolved.UID != stored.FolderUID {
				t.Fatalf("folder id %d was resolved to %q and the panel was stored in %q", checked.ID, resolved.UID, stored.FolderUID)
			}
		}
	})
}

func installFolderIDLookup(t *testing.T, sc scenarioContext, source storedFolder, extras ...*folder.Folder) *idSequenceFolderService {
	t.Helper()
	sourceFolder := &folder.Folder{ID: source.FolderID, OrgID: sc.user.OrgID, UID: source.FolderUID, Title: sc.folder.Title}
	sc.folderSvc.AddFolder(sourceFolder)
	sc.folderSvc.ExpectedFolder = sourceFolder
	lookup := &idSequenceFolderService{
		FakeService: sc.folderSvc,
		byID:        map[int64][]*folder.Folder{source.FolderID: {sourceFolder}},
	}
	for _, extra := range extras {
		sc.folderSvc.AddFolder(extra)
		lookup.byID[extra.ID] = []*folder.Folder{extra}
	}
	sc.service.folderService = lookup
	return lookup
}

func restrictLibraryEditor(user *user.SignedInUser, sourceUID string, readOnly []string, createAlso []string) {
	scope := func(uid string) string {
		return folder.ScopeFoldersProvider.GetResourceScopeUID(uid)
	}
	sourceScope := scope(sourceUID)
	perms := map[string][]string{
		ActionLibraryPanelsRead:   {sourceScope},
		ActionLibraryPanelsWrite:  {sourceScope},
		ActionLibraryPanelsCreate: {sourceScope},
		folder.ActionFoldersRead:  {sourceScope},
	}
	for _, uid := range readOnly {
		perms[ActionLibraryPanelsRead] = append(perms[ActionLibraryPanelsRead], scope(uid))
		perms[folder.ActionFoldersRead] = append(perms[folder.ActionFoldersRead], scope(uid))
	}
	for _, uid := range createAlso {
		perms[ActionLibraryPanelsCreate] = append(perms[ActionLibraryPanelsCreate], scope(uid))
		perms[folder.ActionFoldersRead] = append(perms[folder.ActionFoldersRead], scope(uid))
	}
	user.Permissions = map[int64]map[string][]string{user.OrgID: perms}
	user.OrgRole = org.RoleViewer
}

func patchThroughRoute(t *testing.T, sc scenarioContext, uid string, body any) responseStatus {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/library-elements/"+uid, mockRequestBody(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(identity.WithRequester(req.Context(), sc.reqContext.SignedInUser))
	req = web.SetURLParams(req, map[string]string{":uid": uid})
	sc.reqContext.Req = req
	sc.reqContext.Resp = web.NewResponseWriter(http.MethodPatch, recorder)
	sc.reqContext.Logger = log.NewNopLogger()

	uidScope := ScopeLibraryPanelsProvider.GetResourceScopeUID(ac.Parameter(":uid"))
	guard := sc.service.authorizeLibraryPanelUID(ac.EvalPermission(ActionLibraryPanelsWrite, uidScope)).(func(*contextmodel.ReqContext))
	guard(sc.reqContext)
	require.Emptyf(t, recorder.Body.String(), "library.panels:write on the panel's current folder rejected the caller: %s", recorder.Body.String())

	resp := sc.service.patchHandler(sc.reqContext)
	return responseStatus{status: resp.Status(), body: string(resp.Body())}
}

type responseStatus struct {
	status int
	body   string
}

func (r responseStatus) Status() int { return r.status }

func newLibraryPanel(t *testing.T) scenarioContext {
	t.Helper()
	sc := setupTestScenario(t)
	command := getCreatePanelCommand(sc.folder.ID, sc.folder.UID, "Text - Library Panel")
	sc.reqContext.Req.Body = mockRequestBody(command)
	resp := sc.service.createHandler(sc.reqContext)
	sc.initialResult = validateAndUnMarshalResponse(t, resp)
	return sc
}

func managedByUID(lookup *idSequenceFolderService, uid string) utils.ManagerKind {
	for _, resolved := range lookup.idGets {
		if resolved.UID == uid {
			return resolved.ManagedBy
		}
	}
	return ""
}
