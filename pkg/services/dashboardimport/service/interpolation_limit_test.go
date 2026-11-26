package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboardimport"
	"github.com/grafana/grafana/pkg/services/dashboardimport/api"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/plugindashboards"
	"github.com/grafana/grafana/pkg/services/quota"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web/webtest"
)

func TestImportDashboardStopsOversizedInterpolationBeforeSave(t *testing.T) {
	folderSvc := &countingFolder{FakeService: &foldertest.FakeService{
		ExpectedFolder: &folder.Folder{UID: "folderUID", ID: 7},
	}}
	var libraryCalls, saveCalls int
	svc := &ImportDashboardService{
		dashboardService: &dashboardServiceMock{
			importDashboardFunc: func(ctx context.Context, dto *dashboards.SaveDashboardDTO) (*dashboards.Dashboard, error) {
				saveCalls++
				return &dashboards.Dashboard{UID: "uid", Slug: "slug", Title: "title", Data: simplejson.New()}, nil
			},
		},
		libraryPanelService: &libraryPanelServiceMock{
			importLibraryPanelsForDashboardFunc: func(ctx context.Context, signedInUser identity.Requester, libraryPanels *simplejson.Json, panels []any, folderID int64, folderUID string) error {
				libraryCalls++
				return nil
			},
		},
		folderService: folderSvc,
		features:      featuremgmt.WithFeatures(),
	}

	_, err := svc.ImportDashboard(context.Background(), &dashboardimport.ImportDashboardRequest{
		Dashboard: oversizedDashboard(),
		Inputs:    constantInputs(strings.Repeat("v", 64<<10)),
		FolderUid: "folderUID",
		User:      editor(),
	})
	require.Error(t, err)
	require.Zero(t, folderSvc.gets, "folder lookup runs after interpolation")
	require.Zero(t, libraryCalls, "library panel import runs after interpolation")
	require.Zero(t, saveCalls, "dashboard save runs after interpolation")
}

func TestInterpolateDashboardRejectsOversizedDashboard(t *testing.T) {
	svc := &ImportDashboardService{features: featuremgmt.WithFeatures()}
	res, err := svc.InterpolateDashboard(context.Background(), &dashboardimport.ImportDashboardRequest{
		Dashboard: oversizedDashboard(),
		Inputs:    constantInputs(strings.Repeat("v", 64<<10)),
	})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestInterpolateDashboardRejectsOversizedPluginTemplate(t *testing.T) {
	svc := &ImportDashboardService{
		pluginDashboardService: &pluginDashboardServiceMock{
			loadPluginDashboardFunc: func(ctx context.Context, req *plugindashboards.LoadPluginDashboardRequest) (*plugindashboards.LoadPluginDashboardResponse, error) {
				return &plugindashboards.LoadPluginDashboardResponse{
					Dashboard: dashboards.NewDashboardFromJson(oversizedDashboard()),
				}, nil
			},
		},
		features: featuremgmt.WithFeatures(),
	}
	res, err := svc.InterpolateDashboard(context.Background(), &dashboardimport.ImportDashboardRequest{
		PluginId: "demo",
		Path:     "dashboards/demo.json",
		Inputs:   constantInputs(strings.Repeat("v", 64<<10)),
	})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestImportAPIRejectsOversizedDashboardForEditor(t *testing.T) {
	srv, saveCalls := newImportAPI(t, featuremgmt.WithFeatures())
	resp := postJSON(t, srv, "/api/dashboards/import", oversizedImportBody(t), editorWithCreatePermission())
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Zero(t, *saveCalls)
}

func TestInterpolateAPIRejectsOversizedDashboard(t *testing.T) {
	// suggestedDashboards and dashboardTemplates register this same handler.
	srv, _ := newImportAPI(t, featuremgmt.WithFeatures(featuremgmt.FlagDashboardLibrary))
	resp := postJSON(t, srv, "/api/dashboards/interpolate", oversizedImportBody(t), editorWithCreatePermission())
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestImportAPIDeniesUserWithoutCreatePermission(t *testing.T) {
	srv, saveCalls := newImportAPI(t, featuremgmt.WithFeatures())
	viewer := editor()
	viewer.Permissions = map[int64]map[string][]string{1: {}}
	resp := postJSON(t, srv, "/api/dashboards/import", oversizedImportBody(t), viewer)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Zero(t, *saveCalls)
}

type countingFolder struct {
	*foldertest.FakeService
	gets int
}

func (f *countingFolder) Get(ctx context.Context, q *folder.GetFolderQuery) (*folder.Folder, error) {
	f.gets++
	return f.FakeService.Get(ctx, q)
}

type allowQuota struct{}

func (allowQuota) QuotaReached(*contextmodel.ReqContext, quota.TargetSrv) (bool, error) {
	return false, nil
}

func newImportAPI(t *testing.T, features featuremgmt.FeatureToggles) (*webtest.Server, *int) {
	t.Helper()
	var saveCalls int
	svc := &ImportDashboardService{
		dashboardService: &dashboardServiceMock{
			importDashboardFunc: func(ctx context.Context, dto *dashboards.SaveDashboardDTO) (*dashboards.Dashboard, error) {
				saveCalls++
				return &dashboards.Dashboard{UID: "uid", Slug: "slug", Title: "title", Data: simplejson.New()}, nil
			},
		},
		libraryPanelService: &libraryPanelServiceMock{},
		folderService: &foldertest.FakeService{
			ExpectedFolder: &folder.Folder{UID: "folderUID", ID: 7},
		},
		features: features,
	}
	importAPI := api.New(svc, allowQuota{}, nil, acimpl.ProvideAccessControlTest(), features)
	routeRegister := routing.NewRouteRegister()
	importAPI.RegisterAPIEndpoints(routeRegister)
	return webtest.NewServer(t, routeRegister), &saveCalls
}

func postJSON(t *testing.T, srv *webtest.Server, path string, body []byte, usr *user.SignedInUser) *http.Response {
	t.Helper()
	req := srv.NewPostRequest(path, bytes.NewReader(body))
	webtest.RequestWithSignedInUser(req, usr)
	resp, err := srv.SendJSON(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	return resp
}

func editor() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  1,
		OrgID:   1,
		OrgRole: org.RoleEditor,
	}
}

func editorWithCreatePermission() *user.SignedInUser {
	usr := editor()
	scope := folder.ScopeFoldersProvider.GetResourceScopeUID(folder.GeneralFolderUID)
	usr.Permissions = map[int64]map[string][]string{
		1: {dashboards.ActionDashboardsCreate: {scope}},
	}
	return usr
}

func oversizedDashboard() *simplejson.Json {
	dash := simplejson.New()
	dash.Set("__inputs", []any{
		map[string]any{"name": "a", "type": "constant"},
	})
	// 1024 substitutions of a 64 KiB value expand to 64 MiB.
	dash.Set("title", strings.Repeat("${a}", 1024))
	return dash
}

func constantInputs(value string) []dashboardimport.ImportDashboardInput {
	return []dashboardimport.ImportDashboardInput{{
		Name:  "a",
		Type:  "constant",
		Value: value,
	}}
}

func oversizedImportBody(t *testing.T) []byte {
	t.Helper()
	payload := map[string]any{
		"folderUid": "folderUID",
		"dashboard": oversizedDashboard(),
		"inputs":    constantInputs(strings.Repeat("v", 64<<10)),
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	return body
}
