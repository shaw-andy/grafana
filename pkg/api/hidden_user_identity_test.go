package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
	dashver "github.com/grafana/grafana/pkg/services/dashboardversion"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const identityOrgID int64 = 1

const (
	hiddenLogin  = "break-glass"
	hiddenName   = "Break Glass"
	visibleLogin = "dashboard-editor"
	saLogin      = "automation-bot"
	saName       = "Automation Bot"

	hiddenDashUID  = "hidden-dash"
	visibleDashUID = "visible-dash"
	saDashUID      = "sa-dash"
	versionDashUID = "version-dash"

	hiddenFolderUID = "hidden-folder"
	parentFolderUID = "hidden-parent"
	hiddenFolderID  = int64(41)
	parentFolderID  = int64(40)
)

// TestHiddenUsersAreOmittedFromDashboardAndFolderIdentity is the spec for
// hidden_users on dashboard and folder identity fields. It fails while those
// responses copy a hidden account's login, or a hidden service account's name,
// to a caller who is neither a Grafana server admin nor that account.
func TestHiddenUsersAreOmittedFromDashboardAndFolderIdentity(t *testing.T) {
	sqlStore := db.InitTestDB(t)
	userSvc := newLegacyUserService(t, sqlStore)

	ctx := context.Background()
	hidden := createUser(t, ctx, userSvc, hiddenLogin, hiddenName, "hidden@example.com")
	visible := createUser(t, ctx, userSvc, visibleLogin, "Dashboard Editor", "visible@example.com")
	sa := createServiceAccount(t, ctx, userSvc, saLogin, saName)

	requireIdentity(t, ctx, userSvc, hidden, hiddenLogin, hiddenName, false)
	requireIdentity(t, ctx, userSvc, visible, visibleLogin, "Dashboard Editor", false)
	requireIdentity(t, ctx, userSvc, sa, saLogin, saName, true)

	deps := &identityFixtures{
		users: userSvc,
		dashboards: &dashboardsByUIDService{orgID: identityOrgID, items: map[string]*dashboards.Dashboard{
			hiddenDashUID:  newDash(11, hiddenDashUID, "Hidden dashboard", hidden.ID, visible.ID),
			visibleDashUID: newDash(12, visibleDashUID, "Visible dashboard", visible.ID, visible.ID),
			saDashUID:      newDash(13, saDashUID, "Automation dashboard", sa.ID, sa.ID),
			versionDashUID: newDash(14, versionDashUID, "Versioned dashboard", hidden.ID, hidden.ID),
		}},
		versions: &versionsByDashboard{
			orgID: identityOrgID,
			byUID: map[string][]*dashver.DashboardVersionDTO{
				versionDashUID: {
					newVersion(1, versionDashUID, 1, hidden.ID),
					newVersion(2, versionDashUID, 2, visible.ID),
					newVersion(3, versionDashUID, 3, hidden.ID),
					newVersion(4, versionDashUID, 4, sa.ID),
				},
			},
		},
		folders: newFolderLookup(hidden.ID, visible.ID, sa.ID),
	}

	hiddenCfg := setting.NewCfg()
	hiddenCfg.HiddenUsers = map[string]struct{}{hiddenLogin: {}, saLogin: {}}
	server := newIdentityServer(t, hiddenCfg, deps)

	openCfg := setting.NewCfg()
	openServer := newIdentityServer(t, openCfg, deps)

	readPerms := perms(
		perm(dashboards.ActionDashboardsRead, dashboards.ScopeDashboardsProvider.GetResourceScopeUID(hiddenDashUID)),
		perm(dashboards.ActionDashboardsRead, dashboards.ScopeDashboardsProvider.GetResourceScopeUID(visibleDashUID)),
		perm(dashboards.ActionDashboardsRead, dashboards.ScopeDashboardsProvider.GetResourceScopeUID(saDashUID)),
		perm(dashboards.ActionDashboardsRead, dashboards.ScopeDashboardsProvider.GetResourceScopeUID(versionDashUID)),
		perm(folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScopeUID(hiddenFolderUID)),
		perm(folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScopeUID(parentFolderUID)),
		perm(folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScope(strconv.FormatInt(hiddenFolderID, 10))),
		perm(folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScope(strconv.FormatInt(parentFolderID, 10))),
	)
	versionPerms := perms(
		perm(dashboards.ActionDashboardsWrite, dashboards.ScopeDashboardsProvider.GetResourceScopeUID(versionDashUID)),
	)
	folderWritePerms := perms(
		perm(folder.ActionFoldersCreate, folder.ScopeFoldersProvider.GetResourceAllScope()),
		perm(folder.ActionFoldersWrite, folder.ScopeFoldersProvider.GetResourceScopeUID(hiddenFolderUID)),
		perm(folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScopeUID(hiddenFolderUID)),
		perm(folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScopeUID(parentFolderUID)),
	)
	visibleOnly := perms(
		perm(dashboards.ActionDashboardsRead, dashboards.ScopeDashboardsProvider.GetResourceScopeUID(visibleDashUID)),
	)

	viewer := requester(100, "dashboard-viewer", org.RoleViewer, false, readPerms)
	editor := requester(101, "version-editor", org.RoleEditor, false, versionPerms)
	folderEditor := requester(102, "folder-editor", org.RoleEditor, false, folderWritePerms)
	admin := requester(103, "server-admin", org.RoleAdmin, true, readPerms)
	hiddenCaller := requester(hidden.ID, hiddenLogin, org.RoleEditor, false, readPerms)
	saCaller := requester(sa.ID, saLogin, org.RoleEditor, false, readPerms)
	saCaller.IsServiceAccount = true
	stranger := requester(104, "other-viewer", org.RoleViewer, false, visibleOnly)

	t.Run("configured hidden users stay visible when the setting is empty", func(t *testing.T) {
		meta := getDashboardMeta(t, openServer, viewer, hiddenDashUID)
		require.Equal(t, hiddenLogin, meta.CreatedBy)
		require.Equal(t, visibleLogin, meta.UpdatedBy)
	})

	t.Run("viewer dashboard read hides a hidden user and shows everyone else", func(t *testing.T) {
		body, meta := getDashboard(t, server, viewer, hiddenDashUID)
		require.Equal(t, anonString, meta.CreatedBy)
		require.Equal(t, visibleLogin, meta.UpdatedBy)
		requireNoHiddenIdentity(t, body)

		visibleMeta := getDashboardMeta(t, server, viewer, visibleDashUID)
		require.Equal(t, visibleLogin, visibleMeta.CreatedBy)
		require.Equal(t, visibleLogin, visibleMeta.UpdatedBy)

		saBody, saMeta := getDashboard(t, server, viewer, saDashUID)
		require.Equal(t, anonString, saMeta.CreatedBy)
		require.Equal(t, anonString, saMeta.UpdatedBy)
		requireNoHiddenIdentity(t, saBody)
	})

	t.Run("grafana server admin still sees hidden identities", func(t *testing.T) {
		meta := getDashboardMeta(t, server, admin, hiddenDashUID)
		require.Equal(t, hiddenLogin, meta.CreatedBy)
		require.Equal(t, visibleLogin, meta.UpdatedBy)

		saMeta := getDashboardMeta(t, server, admin, saDashUID)
		require.Equal(t, saName, saMeta.CreatedBy)
		require.Equal(t, saName, saMeta.UpdatedBy)
	})

	t.Run("hidden account sees itself and not another hidden account", func(t *testing.T) {
		meta := getDashboardMeta(t, server, hiddenCaller, hiddenDashUID)
		require.Equal(t, hiddenLogin, meta.CreatedBy)
		require.Equal(t, visibleLogin, meta.UpdatedBy)

		saMeta := getDashboardMeta(t, server, hiddenCaller, saDashUID)
		require.Equal(t, anonString, saMeta.CreatedBy)
		require.Equal(t, anonString, saMeta.UpdatedBy)

		own := getDashboardMeta(t, server, saCaller, saDashUID)
		require.Equal(t, saName, own.CreatedBy)
		require.Equal(t, saName, own.UpdatedBy)

		other := getDashboardMeta(t, server, saCaller, hiddenDashUID)
		require.Equal(t, anonString, other.CreatedBy)
		require.Equal(t, visibleLogin, other.UpdatedBy)
	})

	t.Run("read permission on a different dashboard does not reveal this one", func(t *testing.T) {
		body := readResponse(t, do(t, server, http.MethodGet, "/api/dashboards/uid/"+hiddenDashUID, stranger, nil))
		require.Equal(t, http.StatusForbidden, body.status)
		requireNoHiddenIdentity(t, body.raw)
		require.NotContains(t, body.raw, visibleLogin)
	})

	t.Run("dashboard versions hide hidden creators from a writer who is not a server admin", func(t *testing.T) {
		body, listed := getVersions(t, server, editor, versionDashUID)
		require.Len(t, listed.Versions, 4)
		require.Equal(t, anonString, listed.Versions[0].CreatedBy)
		require.Equal(t, visibleLogin, listed.Versions[1].CreatedBy)
		require.Equal(t, anonString, listed.Versions[2].CreatedBy)
		require.Equal(t, anonString, listed.Versions[3].CreatedBy)
		requireNoHiddenIdentity(t, body)

		require.Equal(t, anonString, getVersion(t, server, editor, versionDashUID, 1).CreatedBy)
		require.Equal(t, visibleLogin, getVersion(t, server, editor, versionDashUID, 2).CreatedBy)
		require.Equal(t, anonString, getVersion(t, server, editor, versionDashUID, 3).CreatedBy)
		require.Equal(t, anonString, getVersion(t, server, editor, versionDashUID, 4).CreatedBy)
	})

	t.Run("dashboard reader without write cannot list versions", func(t *testing.T) {
		body := readResponse(t, do(t, server, http.MethodGet, "/api/dashboards/uid/"+versionDashUID+"/versions", viewer, nil))
		require.Equal(t, http.StatusForbidden, body.status)
		requireNoHiddenIdentity(t, body.raw)

		one := readResponse(t, do(t, server, http.MethodGet, "/api/dashboards/uid/"+versionDashUID+"/versions/1", viewer, nil))
		require.Equal(t, http.StatusForbidden, one.status)
		requireNoHiddenIdentity(t, one.raw)
	})

	t.Run("version write on this dashboard does not authorize another dashboard", func(t *testing.T) {
		body := readResponse(t, do(t, server, http.MethodGet, "/api/dashboards/uid/"+hiddenDashUID+"/versions", editor, nil))
		require.Equal(t, http.StatusForbidden, body.status)
		requireNoHiddenIdentity(t, body.raw)
	})

	t.Run("folder reads hide hidden identities including a viewable parent", func(t *testing.T) {
		body, dto := getFolder(t, server, viewer, "/api/folders/"+hiddenFolderUID)
		require.Equal(t, anonString, dto.CreatedBy)
		require.Equal(t, anonString, dto.UpdatedBy)
		require.Equal(t, hiddenFolderUID, dto.UID)
		require.Len(t, dto.Parents, 1)
		require.Equal(t, parentFolderUID, dto.Parents[0].UID)
		require.Equal(t, anonString, dto.Parents[0].CreatedBy)
		require.Equal(t, visibleLogin, dto.Parents[0].UpdatedBy)
		requireNoHiddenIdentity(t, body)

		byID, idDTO := getFolder(t, server, viewer, "/api/folders/id/"+strconv.FormatInt(hiddenFolderID, 10))
		require.Equal(t, hiddenFolderUID, idDTO.UID)
		require.Equal(t, anonString, idDTO.CreatedBy)
		require.Equal(t, anonString, idDTO.UpdatedBy)
		requireNoHiddenIdentity(t, byID)
	})

	t.Run("folder id permission does not authorize a different folder id", func(t *testing.T) {
		onlyChild := requester(105, "id-viewer", org.RoleViewer, false, perms(
			perm(folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScope(strconv.FormatInt(hiddenFolderID, 10))),
		))
		body := readResponse(t, do(t, server, http.MethodGet, "/api/folders/id/"+strconv.FormatInt(parentFolderID, 10), onlyChild, nil))
		require.Equal(t, http.StatusForbidden, body.status)
		requireNoHiddenIdentity(t, body.raw)
	})

	t.Run("folder writes return the same hidden identity fields", func(t *testing.T) {
		createdBody, created := sendFolder(t, server, folderEditor, http.MethodPost, "/api/folders", map[string]any{"title": "Hidden folder"})
		require.Equal(t, anonString, created.CreatedBy)
		require.Equal(t, anonString, created.UpdatedBy)
		require.Equal(t, hiddenFolderUID, created.UID)
		requireNoHiddenIdentity(t, createdBody)

		title := "Hidden folder"
		updatedBody, updated := sendFolder(t, server, folderEditor, http.MethodPut, "/api/folders/"+hiddenFolderUID, map[string]any{"title": title, "version": 1})
		require.Equal(t, anonString, updated.CreatedBy)
		require.Equal(t, anonString, updated.UpdatedBy)
		requireNoHiddenIdentity(t, updatedBody)

		movedBody, moved := sendFolder(t, server, folderEditor, http.MethodPost, "/api/folders/"+hiddenFolderUID+"/move", map[string]any{"parentUid": parentFolderUID})
		require.Equal(t, anonString, moved.CreatedBy)
		require.Equal(t, anonString, moved.UpdatedBy)
		requireNoHiddenIdentity(t, movedBody)
	})

	t.Run("server admin and the hidden account still see folder identities", func(t *testing.T) {
		adminFolder := getFolderDTO(t, server, admin, "/api/folders/"+hiddenFolderUID)
		require.Equal(t, hiddenLogin, adminFolder.CreatedBy)
		require.Equal(t, saName, adminFolder.UpdatedBy)
		require.Equal(t, hiddenLogin, adminFolder.Parents[0].CreatedBy)
		require.Equal(t, visibleLogin, adminFolder.Parents[0].UpdatedBy)

		selfFolder := getFolderDTO(t, server, hiddenCaller, "/api/folders/"+hiddenFolderUID)
		require.Equal(t, hiddenLogin, selfFolder.CreatedBy)
		require.Equal(t, anonString, selfFolder.UpdatedBy)
		require.Equal(t, hiddenLogin, selfFolder.Parents[0].CreatedBy)
	})
}

type identityFixtures struct {
	users      user.Service
	dashboards dashboards.DashboardService
	versions   dashver.Service
	folders    folder.Service
}

func newIdentityServer(t *testing.T, cfg *setting.Cfg, deps *identityFixtures) *webtest.Server {
	t.Helper()
	return SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.log = log.New("hidden-user-identity-test")
		hs.userService = deps.users
		hs.DashboardService = deps.dashboards
		hs.dashboardVersionService = deps.versions
		hs.folderService = deps.folders
		hs.dashboardProvisioningService = mockDashboardProvisioningService{}
	})
}

func newLegacyUserService(t *testing.T, sqlStore db.DB) user.Service {
	t.Helper()
	orgSvc := orgtest.NewOrgServiceFake()
	orgSvc.ExpectedOrgUserID = identityOrgID
	svc, err := userimpl.NewLegacyService(
		legacysql.NewDatabaseProvider(sqlStore),
		orgSvc,
		setting.NewCfg(),
		&teamtest.FakeService{},
		nil,
		tracing.InitializeTracerForTest(),
		quotatest.New(false, nil),
		supportbundlestest.NewFakeBundleService(),
	)
	require.NoError(t, err)
	return svc
}

func createUser(t *testing.T, ctx context.Context, svc user.Service, login, name, email string) *user.User {
	t.Helper()
	created, err := svc.Create(ctx, &user.CreateUserCommand{
		Login:        login,
		Name:         name,
		Email:        email,
		SkipOrgSetup: true,
	})
	require.NoError(t, err)
	require.Equal(t, login, created.Login)
	return created
}

func createServiceAccount(t *testing.T, ctx context.Context, svc user.Service, login, name string) *user.User {
	t.Helper()
	created, err := svc.CreateServiceAccount(ctx, &user.CreateUserCommand{
		Login:          login,
		Name:           name,
		OrgID:          identityOrgID,
		DefaultOrgRole: string(org.RoleViewer),
	})
	require.NoError(t, err)
	require.Equal(t, login, created.Login)
	require.True(t, created.IsServiceAccount)
	return created
}

func requireIdentity(t *testing.T, ctx context.Context, svc user.Service, account *user.User, login, name string, serviceAccount bool) {
	t.Helper()
	got, err := svc.GetSignedInUser(ctx, &user.GetSignedInUserQuery{UserID: account.ID, OrgID: identityOrgID})
	require.NoError(t, err)
	require.Equal(t, account.ID, got.UserID)
	require.Equal(t, login, got.GetLogin())
	require.Equal(t, name, got.GetName())
	require.Equal(t, serviceAccount, got.IsServiceAccount)
}

func newDash(id int64, uid, title string, createdBy, updatedBy int64) *dashboards.Dashboard {
	dash := dashboards.NewDashboard(title)
	dash.ID = id
	dash.UID = uid
	dash.OrgID = identityOrgID
	dash.CreatedBy = createdBy
	dash.UpdatedBy = updatedBy
	dash.Data.Set("uid", uid)
	return dash
}

func newVersion(id int64, uid string, version int, createdBy int64) *dashver.DashboardVersionDTO {
	return &dashver.DashboardVersionDTO{
		ID:           id,
		DashboardID:  14,
		DashboardUID: uid,
		Version:      version,
		CreatedBy:    createdBy,
		Data:         simplejson.New(),
	}
}

func newFolderLookup(hiddenID, visibleID, saID int64) *folderLookup {
	parent := &folder.Folder{
		ID: parentFolderID, OrgID: identityOrgID, UID: parentFolderUID, Title: "Hidden parent",
		CreatedBy: hiddenID, UpdatedBy: visibleID,
	}
	child := &folder.Folder{
		ID: hiddenFolderID, OrgID: identityOrgID, UID: hiddenFolderUID, Title: "Hidden folder",
		ParentUID: parentFolderUID, CreatedBy: hiddenID, UpdatedBy: saID,
	}
	lookup := &folderLookup{
		FakeService: foldertest.NewFakeService(),
		byID:        map[int64]*folder.Folder{parent.ID: parent, child.ID: child},
		byUID:       map[string]*folder.Folder{parent.UID: parent, child.UID: child},
		parents:     map[string][]*folder.Folder{child.UID: {parent}, parent.UID: {}},
	}
	lookup.AddFolder(parent)
	lookup.AddFolder(child)
	return lookup
}

type dashboardsByUIDService struct {
	*dashboards.FakeDashboardService
	orgID int64
	items map[string]*dashboards.Dashboard
}

func (d *dashboardsByUIDService) GetDashboard(_ context.Context, query *dashboards.GetDashboardQuery) (*dashboards.Dashboard, error) {
	if query == nil || query.OrgID != d.orgID || query.UID == "" {
		return nil, dashboards.ErrDashboardNotFound
	}
	dash, ok := d.items[query.UID]
	if !ok || dash.OrgID != query.OrgID || dash.UID != query.UID {
		return nil, dashboards.ErrDashboardNotFound
	}
	return dash, nil
}

type versionsByDashboard struct {
	orgID int64
	byUID map[string][]*dashver.DashboardVersionDTO
}

func (v *versionsByDashboard) List(_ context.Context, query *dashver.ListDashboardVersionsQuery) (*dashver.DashboardVersionResponse, error) {
	if query == nil || query.OrgID != v.orgID {
		return nil, dashver.ErrNoVersionsForDashboardID
	}
	versions, ok := v.byUID[query.DashboardUID]
	if !ok {
		return nil, dashver.ErrNoVersionsForDashboardID
	}
	out := make([]*dashver.DashboardVersionDTO, 0, len(versions))
	for _, version := range versions {
		if version.DashboardUID != query.DashboardUID {
			continue
		}
		out = append(out, version)
	}
	if len(out) == 0 {
		return nil, dashver.ErrNoVersionsForDashboardID
	}
	return &dashver.DashboardVersionResponse{Versions: out}, nil
}

func (v *versionsByDashboard) Get(_ context.Context, query *dashver.GetDashboardVersionQuery) (*dashver.DashboardVersionDTO, error) {
	if query == nil || query.OrgID != v.orgID {
		return nil, dashver.ErrDashboardVersionNotFound
	}
	for _, version := range v.byUID[query.DashboardUID] {
		if version.DashboardUID == query.DashboardUID && int64(version.Version) == query.Version {
			return version, nil
		}
	}
	return nil, dashver.ErrDashboardVersionNotFound
}

func (v *versionsByDashboard) RestoreVersion(context.Context, *dashver.RestoreVersionCommand) (*dashboards.Dashboard, error) {
	return nil, dashver.ErrDashboardVersionNotFound
}

type folderLookup struct {
	*foldertest.FakeService
	byID    map[int64]*folder.Folder
	byUID   map[string]*folder.Folder
	parents map[string][]*folder.Folder
}

func (s *folderLookup) Get(_ context.Context, q *folder.GetFolderQuery) (*folder.Folder, error) {
	if q == nil || q.OrgID != identityOrgID {
		return nil, folder.ErrFolderNotFound
	}
	switch {
	case q.ID != nil:
		f, ok := s.byID[*q.ID]
		if !ok || f.OrgID != q.OrgID || f.ID != *q.ID {
			return nil, folder.ErrFolderNotFound
		}
		return f, nil
	case q.UID != nil && *q.UID != "":
		f, ok := s.byUID[*q.UID]
		if !ok || f.OrgID != q.OrgID || f.UID != *q.UID {
			return nil, folder.ErrFolderNotFound
		}
		return f, nil
	default:
		return nil, folder.ErrFolderNotFound
	}
}

func (s *folderLookup) GetParents(_ context.Context, q folder.GetParentsQuery) ([]*folder.Folder, error) {
	if q.OrgID != identityOrgID {
		return nil, folder.ErrFolderNotFound
	}
	parents, ok := s.parents[q.UID]
	if !ok {
		return nil, folder.ErrFolderNotFound
	}
	return parents, nil
}

func (s *folderLookup) Create(_ context.Context, cmd *folder.CreateFolderCommand) (*folder.Folder, error) {
	if cmd == nil || cmd.OrgID != identityOrgID || cmd.Title != "Hidden folder" || cmd.SignedInUser == nil || cmd.SignedInUser.GetOrgID() != identityOrgID {
		return nil, folder.ErrFolderNotFound
	}
	f, ok := s.byUID[hiddenFolderUID]
	if !ok {
		return nil, folder.ErrFolderNotFound
	}
	return f, nil
}

func (s *folderLookup) Update(_ context.Context, cmd *folder.UpdateFolderCommand) (*folder.Folder, error) {
	if cmd == nil || cmd.OrgID != identityOrgID || cmd.UID != hiddenFolderUID || cmd.SignedInUser == nil || cmd.SignedInUser.GetOrgID() != identityOrgID {
		return nil, folder.ErrFolderNotFound
	}
	f, ok := s.byUID[cmd.UID]
	if !ok || f.UID != cmd.UID || f.OrgID != cmd.OrgID {
		return nil, folder.ErrFolderNotFound
	}
	return f, nil
}

func (s *folderLookup) Move(_ context.Context, cmd *folder.MoveFolderCommand) (*folder.Folder, error) {
	if cmd == nil || cmd.OrgID != identityOrgID || cmd.UID != hiddenFolderUID || cmd.NewParentUID != parentFolderUID || cmd.SignedInUser == nil || cmd.SignedInUser.GetOrgID() != identityOrgID {
		return nil, folder.ErrFolderNotFound
	}
	f, ok := s.byUID[cmd.UID]
	if !ok || f.UID != cmd.UID || f.OrgID != cmd.OrgID {
		return nil, folder.ErrFolderNotFound
	}
	return f, nil
}

func perm(action, scope string) accesscontrol.Permission {
	return accesscontrol.Permission{Action: action, Scope: scope}
}

func perms(permissions ...accesscontrol.Permission) map[int64]map[string][]string {
	return map[int64]map[string][]string{
		identityOrgID: accesscontrol.GroupScopesByActionContext(context.Background(), permissions),
	}
}

func requester(id int64, login string, role org.RoleType, grafanaAdmin bool, permissions map[int64]map[string][]string) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:         id,
		OrgID:          identityOrgID,
		OrgRole:        role,
		Login:          login,
		IsGrafanaAdmin: grafanaAdmin,
		Permissions:    permissions,
	}
}

type httpResult struct {
	status int
	raw    string
}

func do(t *testing.T, server *webtest.Server, method, path string, caller *user.SignedInUser, payload any) *http.Response {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		require.NoError(t, err)
		body = bytes.NewReader(encoded)
	}
	req := server.NewRequest(method, path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req = webtest.RequestWithSignedInUser(req, caller)
	resp, err := server.Send(req)
	require.NoError(t, err)
	return resp
}

func readResponse(t *testing.T, resp *http.Response) httpResult {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return httpResult{status: resp.StatusCode, raw: string(raw)}
}

func requireOK(t *testing.T, result httpResult) {
	t.Helper()
	require.Equalf(t, http.StatusOK, result.status, "body: %s", result.raw)
}

func requireNoHiddenIdentity(t *testing.T, body string) {
	t.Helper()
	require.NotContains(t, body, hiddenLogin)
	require.NotContains(t, body, hiddenName)
	require.NotContains(t, body, saLogin)
	require.NotContains(t, body, saName)
}

func getDashboard(t *testing.T, server *webtest.Server, caller *user.SignedInUser, uid string) (string, dtos.DashboardMeta) {
	t.Helper()
	result := readResponse(t, do(t, server, http.MethodGet, "/api/dashboards/uid/"+uid, caller, nil))
	requireOK(t, result)
	var dto dtos.DashboardFullWithMeta
	require.NoError(t, json.Unmarshal([]byte(result.raw), &dto))
	require.Equal(t, uid, dto.Dashboard.Get("uid").MustString())
	return result.raw, dto.Meta
}

func getDashboardMeta(t *testing.T, server *webtest.Server, caller *user.SignedInUser, uid string) dtos.DashboardMeta {
	t.Helper()
	_, meta := getDashboard(t, server, caller, uid)
	return meta
}

func getVersions(t *testing.T, server *webtest.Server, caller *user.SignedInUser, uid string) (string, dashver.DashboardVersionResponseMeta) {
	t.Helper()
	result := readResponse(t, do(t, server, http.MethodGet, "/api/dashboards/uid/"+uid+"/versions", caller, nil))
	requireOK(t, result)
	var listed dashver.DashboardVersionResponseMeta
	require.NoError(t, json.Unmarshal([]byte(result.raw), &listed))
	for _, version := range listed.Versions {
		require.Equal(t, uid, version.DashboardUID)
	}
	return result.raw, listed
}

func getVersion(t *testing.T, server *webtest.Server, caller *user.SignedInUser, uid string, version int) dashver.DashboardVersionMeta {
	t.Helper()
	result := readResponse(t, do(t, server, http.MethodGet, fmt.Sprintf("/api/dashboards/uid/%s/versions/%d", uid, version), caller, nil))
	requireOK(t, result)
	var meta dashver.DashboardVersionMeta
	require.NoError(t, json.Unmarshal([]byte(result.raw), &meta))
	require.Equal(t, uid, meta.DashboardUID)
	require.Equal(t, version, meta.Version)
	return meta
}

func getFolder(t *testing.T, server *webtest.Server, caller *user.SignedInUser, path string) (string, dtos.Folder) {
	t.Helper()
	result := readResponse(t, do(t, server, http.MethodGet, path, caller, nil))
	requireOK(t, result)
	var dto dtos.Folder
	require.NoError(t, json.Unmarshal([]byte(result.raw), &dto))
	return result.raw, dto
}

func getFolderDTO(t *testing.T, server *webtest.Server, caller *user.SignedInUser, path string) dtos.Folder {
	t.Helper()
	_, dto := getFolder(t, server, caller, path)
	return dto
}

func sendFolder(t *testing.T, server *webtest.Server, caller *user.SignedInUser, method, path string, payload map[string]any) (string, dtos.Folder) {
	t.Helper()
	result := readResponse(t, do(t, server, method, path, caller, payload))
	requireOK(t, result)
	var dto dtos.Folder
	require.NoError(t, json.Unmarshal([]byte(result.raw), &dto))
	return result.raw, dto
}
