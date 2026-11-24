package api_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/api"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/seeding"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/store"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/grafanads"
)

const wrapperListHelperFrame = ".List.func1"

func TestViewerBuiltinDatasourceRoleCanListAndDoesNotLeakGoroutines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Datasource permission enforcement is on, so Viewer does not receive
	// datasources:query on every datasource. The hidden built-in reader role is
	// still granted to Viewer.
	viewer := viewerFromFixedRoles(t, true)
	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())

	allowed, err := ac.Evaluate(ctx, viewer, accesscontrol.EvalPermission(datasources.ActionQuery))
	require.NoError(t, err)
	require.True(t, allowed, "route gate for POST /api/ds/query")

	allowed, err = ac.Evaluate(ctx, viewer, accesscontrol.EvalPermission(
		datasources.ActionQuery, datasources.ScopePrefix+grafanads.DatasourceUID,
	))
	require.NoError(t, err)
	require.True(t, allowed, "query client check for the grafana datasource")

	cfg := &setting.Cfg{
		StaticRootPath: grafanaPublicDir(t),
		DataPath:       t.TempDir(),
		Env:            setting.Prod,
	}
	storageSvc, err := store.ProvideService(nil, cfg, nil)
	require.NoError(t, err)
	graf := grafanads.ProvideService(storageSvc, featuremgmt.WithFeatures())

	body, err := json.Marshal(map[string]string{"path": "img"})
	require.NoError(t, err)
	req := &backend.QueryDataRequest{Queries: []backend.DataQuery{{
		RefID:         "A",
		QueryType:     "list",
		MaxDataPoints: 20,
		JSON:          body,
	}}}

	baseline := listHelperGoroutines()
	resp, err := graf.QueryData(ctx, req)
	require.NoError(t, err)
	one := resp.Responses["A"]
	require.NoError(t, one.Error)
	require.NotEmpty(t, one.Frames)
	rows, err := one.Frames[0].RowLen()
	require.NoError(t, err)
	require.Greater(t, rows, 0)

	cancel()
	requireListHelpersFinished(t, baseline)
}

func viewerFromFixedRoles(t *testing.T, dsPermissionsEnforced bool) *user.SignedInUser {
	t.Helper()
	desired := map[accesscontrol.SeedPermission]struct{}{}
	for _, reg := range api.FixedRoleRegistrations(false, dsPermissionsEnforced) {
		seeding.AppendDesiredPermissions(desired, log.NewNopLogger(), &reg.Role, reg.Grants, reg.Exclude)
	}

	var perms []accesscontrol.Permission
	for sp := range desired {
		if sp.BuiltInRole == string(org.RoleViewer) {
			perms = append(perms, accesscontrol.Permission{Action: sp.Action, Scope: sp.Scope})
		}
	}
	grouped := accesscontrol.GroupScopesByAction(perms)
	scopes := grouped[datasources.ActionQuery]
	require.Contains(t, scopes, datasources.ScopePrefix+grafanads.DatasourceUID)
	if dsPermissionsEnforced {
		require.NotContains(t, scopes, datasources.ScopeAll)
	}

	return &user.SignedInUser{
		UserID:      7,
		OrgID:       1,
		OrgRole:     org.RoleViewer,
		Permissions: map[int64]map[string][]string{1: grouped},
	}
}

func grafanaPublicDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "public"))
	info, err := os.Stat(filepath.Join(dir, "img"))
	require.NoError(t, err)
	require.True(t, info.IsDir())
	return dir
}

func listHelperGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), wrapperListHelperFrame)
		}
		buf = make([]byte, len(buf)*2)
	}
}

func listHelperStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, len(buf)*2)
	}
	var b strings.Builder
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(stack, "filestorage") {
			b.WriteString(stack)
			b.WriteString("\n\n")
		}
	}
	return b.String()
}

func requireListHelpersFinished(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if extra := listHelperGoroutines() - baseline; extra > 0 {
		t.Fatalf("grafana datasource list left %d filestorage wrapper helper goroutine(s) running\n%s", extra, listHelperStacks())
	}
}
