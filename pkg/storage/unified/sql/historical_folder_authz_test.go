package sql

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/grafana/dskit/services"
	"github.com/stretchr/testify/require"

	authlib "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	infraDB "github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/sql/db/dbimpl"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// These requests carry the same fields apistore.toListRequest sets for
// grafana.app/get-history plus metadata.name, for a resourceVersion query, and
// for a continue token. The KV cases call toListRequest. It is unexported, and
// this package does not import apistore, so the fields are set here.
const (
	histGroup     = "dashboard.grafana.app"
	histResource  = "dashboards"
	histNamespace = "default"
	histVersion   = "v1beta1"

	folderShared     = "shared"
	folderRestricted = "restricted"

	// Bodies saved with the dashboard. They are the contents a later folder
	// move or deletion is supposed to hide.
	secretShared     = "SECRET_SHARED_BODY"
	secretRestricted = "SECRET_RESTRICTED_BODY"
)

// folderGrantClient is the folder check the RBAC service applies to a dashboard
// get: allow when the folder on the check is one this user can read
// (folders:uid:<folder>), and allow delete only on a folder this user can
// delete. It has no notion of "current" versus "historical" folder. Trash
// admin (set_permissions) is denied for every non-admin, which is the
// folder-admin half of the trash rule.
type folderGrantClient struct {
	admins map[string]bool
	read   map[string]map[string]bool
	del    map[string]map[string]bool
}

func (c folderGrantClient) allow(info authlib.AuthInfo, verb, folder string) bool {
	if info == nil {
		return false
	}
	if c.admins[info.GetUID()] {
		return true
	}
	switch verb {
	case utils.VerbGet, utils.VerbList, utils.VerbWatch:
		return c.read[info.GetUID()][folder]
	case utils.VerbDelete:
		return c.del[info.GetUID()][folder]
	default:
		return false
	}
}

func (c folderGrantClient) Check(_ context.Context, info authlib.AuthInfo, req authlib.CheckRequest, folder string) (authlib.CheckResponse, error) {
	return authlib.CheckResponse{Allowed: c.allow(info, req.Verb, folder)}, nil
}

func (c folderGrantClient) BatchCheck(_ context.Context, info authlib.AuthInfo, req authlib.BatchCheckRequest) (authlib.BatchCheckResponse, error) {
	results := make(map[string]authlib.BatchCheckResult, len(req.Checks))
	for _, item := range req.Checks {
		results[item.CorrelationID] = authlib.BatchCheckResult{Allowed: c.allow(info, item.Verb, item.Folder)}
	}
	return authlib.BatchCheckResponse{Results: results}, nil
}

func (c folderGrantClient) Compile(_ context.Context, info authlib.AuthInfo, req authlib.ListRequest) (authlib.ItemChecker, authlib.Zookie, error) {
	return func(_, folder string) bool {
		return c.allow(info, req.Verb, folder)
	}, authlib.NoopZookie{}, nil
}

func histUser(uid string, role identity.RoleType) *identity.StaticRequester {
	return &identity.StaticRequester{
		Type:      authlib.TypeUser,
		UserID:    1,
		UserUID:   uid,
		OrgID:     1,
		OrgRole:   role,
		Namespace: histNamespace,
		Login:     uid,
	}
}

func histCtx(user *identity.StaticRequester) context.Context {
	return identity.WithRequester(context.Background(), user)
}

func dashboardBody(name, folder, secret string) []byte {
	raw, err := json.Marshal(map[string]any{
		"apiVersion": histGroup + "/" + histVersion,
		"kind":       "Dashboard",
		"metadata": map[string]any{
			"name":      name,
			"namespace": histNamespace,
			"annotations": map[string]any{
				utils.AnnoKeyFolder: folder,
			},
		},
		"spec": map[string]any{"title": secret},
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func histKey(name string) *resourcepb.ResourceKey {
	return &resourcepb.ResourceKey{
		Group:     histGroup,
		Resource:  histResource,
		Namespace: histNamespace,
		Name:      name,
	}
}

func dashboardHistoryRequest(t *testing.T, name string) *resourcepb.ListRequest {
	t.Helper()
	return &resourcepb.ListRequest{
		VersionMatchV2: resourcepb.ResourceVersionMatchV2_Unset,
		Source:         resourcepb.ListRequest_HISTORY,
		Options:        &resourcepb.ListOptions{Key: histKey(name)},
	}
}

func revisionListRequest(t *testing.T, rv int64) *resourcepb.ListRequest {
	t.Helper()
	return &resourcepb.ListRequest{
		VersionMatchV2:  resourcepb.ResourceVersionMatchV2_Unset,
		ResourceVersion: rv,
		Options:         &resourcepb.ListOptions{Key: histKey("")},
	}
}

func continueListRequest(t *testing.T, name string, rv int64) *resourcepb.ListRequest {
	t.Helper()
	return &resourcepb.ListRequest{
		VersionMatchV2: resourcepb.ResourceVersionMatchV2_Unset,
		NextPageToken:  resource.ContinueToken{Name: name, ResourceVersion: rv}.String(),
		Options:        &resourcepb.ListOptions{Key: histKey("")},
	}
}

func latestListRequest(t *testing.T) *resourcepb.ListRequest {
	t.Helper()
	return &resourcepb.ListRequest{
		VersionMatchV2: resourcepb.ResourceVersionMatchV2_Unset,
		Options:        &resourcepb.ListOptions{Key: histKey("")},
	}
}

func openSQLBackend(t *testing.T) resource.StorageBackend {
	t.Helper()
	dbstore := infraDB.InitTestDB(t)
	provider, err := dbimpl.ProvideResourceDB(dbstore, setting.NewCfg(), nil)
	require.NoError(t, err)
	backend, err := NewBackend(BackendOptions{
		DBProvider:    provider,
		DisablePruner: true,
	})
	require.NoError(t, err)
	svc, ok := backend.(services.Service)
	require.True(t, ok)
	ctx := testutil.NewTestContext(t, time.Now().Add(time.Minute))
	require.NoError(t, services.StartAndAwaitRunning(ctx, svc))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = services.StopAndAwaitTerminated(stopCtx, svc)
	})
	return backend
}

func newHistServer(t *testing.T, backend resource.StorageBackend, access authlib.AccessClient) resource.ResourceServer {
	t.Helper()
	srv, err := resource.NewResourceServer(resource.ResourceServerOptions{
		Backend:      backend,
		AccessClient: access,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Stop(stopCtx)
	})
	return srv
}

func mustCreate(t *testing.T, srv resource.ResourceServer, ctx context.Context, name, folder, secret string) int64 {
	t.Helper()
	rsp, err := srv.Create(ctx, &resourcepb.CreateRequest{
		Key:   histKey(name),
		Value: dashboardBody(name, folder, secret),
	})
	require.NoError(t, err)
	require.Nil(t, rsp.Error)
	require.Positive(t, rsp.ResourceVersion)
	return rsp.ResourceVersion
}

func mustUpdate(t *testing.T, srv resource.ResourceServer, ctx context.Context, name, folder, secret string, rv int64) int64 {
	t.Helper()
	rsp, err := srv.Update(ctx, &resourcepb.UpdateRequest{
		Key:             histKey(name),
		ResourceVersion: rv,
		Value:           dashboardBody(name, folder, secret),
	})
	require.NoError(t, err)
	require.Nil(t, rsp.Error)
	require.Positive(t, rsp.ResourceVersion)
	return rsp.ResourceVersion
}

func mustDelete(t *testing.T, srv resource.ResourceServer, ctx context.Context, name string, rv int64) {
	t.Helper()
	rsp, err := srv.Delete(ctx, &resourcepb.DeleteRequest{
		Key:             histKey(name),
		ResourceVersion: rv,
	})
	require.NoError(t, err)
	require.Nil(t, rsp.Error)
}

func assertListHides(t *testing.T, rsp *resourcepb.ListResponse, err error, secret string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, rsp)
	if rsp.Error != nil {
		require.Contains(t, []int32{http.StatusForbidden, http.StatusUnauthorized}, rsp.Error.Code)
	}
	for _, item := range rsp.Items {
		require.NotContains(t, string(item.Value), secret, "item %s rv %d", item.Name, item.ResourceVersion)
	}
}

func assertListShows(t *testing.T, rsp *resourcepb.ListResponse, err error, secret string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, rsp)
	require.Nil(t, rsp.Error)
	for _, item := range rsp.Items {
		if bytes.Contains(item.Value, []byte(secret)) {
			return
		}
	}
	t.Fatalf("list did not return %q", secret)
}

func assertReadHides(t *testing.T, rsp *resourcepb.ReadResponse, err error, secret string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, rsp)
	require.NotContains(t, string(rsp.Value), secret)
	if rsp.Error == nil {
		t.Fatal("historical read returned the object")
	}
	require.Contains(t, []int32{http.StatusForbidden, http.StatusNotFound, http.StatusUnauthorized}, rsp.Error.Code)
}

func assertReadShows(t *testing.T, rsp *resourcepb.ReadResponse, err error, secret string) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, rsp)
	require.Nil(t, rsp.Error)
	require.Contains(t, string(rsp.Value), secret)
}

// TestHistoricalFolderDoesNotAuthorizeDashboardVersions is the storage behavior
// for the two ways a caller asks for an older dashboard: history
// (grafana.app/get-history plus metadata.name) and a list or get at an older
// resource version, including a continue token that carries that version.
//
// A caller who can read only the folder the dashboard used to live in must not
// receive versions saved there after the dashboard moves. A caller who can no
// longer see a deleted dashboard through the trash rule (admin of the folder,
// or the deleter) must not receive it by asking for an older resource version.
// A caller who can read the dashboard where it lives now still receives the
// older bodies. The deleter still receives the deleted body.
func TestHistoricalFolderDoesNotAuthorizeDashboardVersions(t *testing.T) {
	admin := histUser("admin", identity.RoleAdmin)
	sharedReader := histUser("shared-reader", identity.RoleViewer)
	restrictedReader := histUser("restricted-reader", identity.RoleViewer)
	deleter := histUser("deleter", identity.RoleEditor)

	access := folderGrantClient{
		admins: map[string]bool{admin.GetUID(): true},
		read: map[string]map[string]bool{
			sharedReader.GetUID():     {folderShared: true},
			restrictedReader.GetUID(): {folderRestricted: true},
			deleter.GetUID():          {folderShared: true, folderRestricted: true},
		},
		del: map[string]map[string]bool{
			deleter.GetUID(): {folderShared: true, folderRestricted: true},
		},
	}

	adminCtx := histCtx(admin)
	sharedCtx := histCtx(sharedReader)
	restrictedCtx := histCtx(restrictedReader)
	deleterCtx := histCtx(deleter)

	backends := []struct {
		name string
		open func(t *testing.T) resource.StorageBackend
	}{
		{name: "sql", open: openSQLBackend},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			t.Run("moved dashboard", func(t *testing.T) {
				srv := newHistServer(t, backend.open(t), access)
				const name = "moved-dash"
				createdRV := mustCreate(t, srv, adminCtx, name, folderShared, secretShared)
				mustUpdate(t, srv, adminCtx, name, folderRestricted, secretRestricted, createdRV)

				history := dashboardHistoryRequest(t, name)
				require.Equal(t, resourcepb.ListRequest_HISTORY, history.Source)
				require.Equal(t, name, history.Options.Key.Name)
				require.Empty(t, history.Options.Labels)
				require.Empty(t, history.Options.Fields)

				// Latest list still follows the current folder.
				t.Run("latest list uses the current folder", func(t *testing.T) {
					latest, err := srv.List(sharedCtx, latestListRequest(t))
					assertListHides(t, latest, err, secretShared)
					assertListHides(t, latest, err, secretRestricted)
					latest, err = srv.List(restrictedCtx, latestListRequest(t))
					assertListShows(t, latest, err, secretRestricted)
				})
				t.Run("history hides versions from the old folder", func(t *testing.T) {
					sharedHist, err := srv.List(sharedCtx, dashboardHistoryRequest(t, name))
					assertListHides(t, sharedHist, err, secretShared)
					assertListHides(t, sharedHist, err, secretRestricted)
				})
				t.Run("history keeps versions for a current reader", func(t *testing.T) {
					restrictedHist, err := srv.List(restrictedCtx, dashboardHistoryRequest(t, name))
					assertListShows(t, restrictedHist, err, secretShared)
				})
				t.Run("revision list hides the old folder", func(t *testing.T) {
					atOld, err := srv.List(sharedCtx, revisionListRequest(t, createdRV))
					assertListHides(t, atOld, err, secretShared)
				})
				t.Run("revision list keeps the old body for a current reader", func(t *testing.T) {
					atOld, err := srv.List(restrictedCtx, revisionListRequest(t, createdRV))
					assertListShows(t, atOld, err, secretShared)
				})
				t.Run("read at the old version hides the old folder", func(t *testing.T) {
					readOld, err := srv.Read(sharedCtx, &resourcepb.ReadRequest{
						Key:             histKey(name),
						ResourceVersion: createdRV,
					})
					assertReadHides(t, readOld, err, secretShared)
				})
				t.Run("read at the old version stays available to a current reader", func(t *testing.T) {
					readOld, err := srv.Read(restrictedCtx, &resourcepb.ReadRequest{
						Key:             histKey(name),
						ResourceVersion: createdRV,
					})
					assertReadShows(t, readOld, err, secretShared)
				})
			})

			t.Run("deleted dashboard", func(t *testing.T) {
				srv := newHistServer(t, backend.open(t), access)
				const name = "deleted-dash"
				createdRV := mustCreate(t, srv, adminCtx, name, folderShared, secretShared)
				mustDelete(t, srv, deleterCtx, name, createdRV)

				// A reader of the folder it was deleted from is not the deleter
				// and is not a folder admin, so the trash rule excludes them.
				t.Run("revision list", func(t *testing.T) {
					listed, err := srv.List(sharedCtx, revisionListRequest(t, createdRV))
					assertListHides(t, listed, err, secretShared)
				})
				t.Run("continue token", func(t *testing.T) {
					continued, err := srv.List(sharedCtx, continueListRequest(t, name, createdRV))
					assertListHides(t, continued, err, secretShared)
				})
				t.Run("read", func(t *testing.T) {
					readOld, err := srv.Read(sharedCtx, &resourcepb.ReadRequest{
						Key:             histKey(name),
						ResourceVersion: createdRV,
					})
					assertReadHides(t, readOld, err, secretShared)
				})
				t.Run("deleter revision list", func(t *testing.T) {
					listed, err := srv.List(deleterCtx, revisionListRequest(t, createdRV))
					assertListShows(t, listed, err, secretShared)
				})
				t.Run("deleter read", func(t *testing.T) {
					readOld, err := srv.Read(deleterCtx, &resourcepb.ReadRequest{
						Key:             histKey(name),
						ResourceVersion: createdRV,
					})
					assertReadShows(t, readOld, err, secretShared)
				})
			})

			t.Run("deleted from the folder the caller can still read", func(t *testing.T) {
				srv := newHistServer(t, backend.open(t), access)
				const name = "deleted-restricted"
				createdRV := mustCreate(t, srv, adminCtx, name, folderRestricted, secretRestricted)
				mustDelete(t, srv, deleterCtx, name, createdRV)

				// Read access to the folder stored on the old version is not
				// enough once the dashboard is gone.
				t.Run("revision list", func(t *testing.T) {
					listed, err := srv.List(restrictedCtx, revisionListRequest(t, createdRV))
					assertListHides(t, listed, err, secretRestricted)
				})
				t.Run("continue token", func(t *testing.T) {
					continued, err := srv.List(restrictedCtx, continueListRequest(t, name, createdRV))
					assertListHides(t, continued, err, secretRestricted)
				})
				t.Run("read", func(t *testing.T) {
					readOld, err := srv.Read(restrictedCtx, &resourcepb.ReadRequest{
						Key:             histKey(name),
						ResourceVersion: createdRV,
					})
					assertReadHides(t, readOld, err, secretRestricted)
				})
				t.Run("deleter revision list", func(t *testing.T) {
					listed, err := srv.List(deleterCtx, revisionListRequest(t, createdRV))
					assertListShows(t, listed, err, secretRestricted)
				})
			})
		})
	}
}
