package query

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/backendplugin/coreplugin"
	pluglog "github.com/grafana/grafana/pkg/plugins/log"
	pluginclient "github.com/grafana/grafana/pkg/plugins/manager/client"
	"github.com/grafana/grafana/pkg/plugins/manager/registry"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/dsquerierclient"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/store"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/grafanads"
)

const wrapperListHelperFrame = ".List.func1"

func TestGrafanaDatasourceListQueryDoesNotLeakGoroutines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	viewer := viewerWithBuiltinDatasourceQuery()
	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())

	// POST /api/ds/query is gated by datasources:query with no scope. Holding
	// that action on datasources:uid:grafana is enough to pass the gate, and it
	// is also enough for the query-service client's per-datasource check.
	routeAllowed, err := ac.Evaluate(ctx, viewer, accesscontrol.EvalPermission(datasources.ActionQuery))
	require.NoError(t, err)
	require.True(t, routeAllowed)

	scopedAllowed, err := ac.Evaluate(ctx, viewer, accesscontrol.EvalPermission(
		datasources.ActionQuery, "datasources:uid:"+grafanads.DatasourceUID,
	))
	require.NoError(t, err)
	require.True(t, scopedAllowed)

	graf := grafanads.ProvideService(publicStaticStorage(t), featuremgmt.WithFeatures())

	qs := &ServiceImpl{
		log:                        log.New("query_data"),
		dataSourceRequestValidator: validations.ProvideValidator(),
		qsDatasourceClientBuilder:  dsquerierclient.NewNullQSDatasourceClientBuilder(),
	}
	parsed, err := qs.parseMetricRequest(ctx, viewer, false, attackerListRequest(t, 8), false)
	require.NoError(t, err)

	queries := parsed.getFlattenedQueries()
	require.Len(t, queries, 8)
	ds := queries[0].datasource
	require.Equal(t, grafanads.DatasourceUID, ds.UID)
	require.Equal(t, "grafana", ds.Type)
	require.NoError(t, qs.dataSourceRequestValidator.Validate(ds.URL, ds.JsonDataMap(), nil))

	// Single-tenant Grafana keeps the built-in datasource in-process.
	_, delegated, err := qs.qsDatasourceClientBuilder.BuildClient(ds.Type, ds.UID)
	require.NoError(t, err)
	require.False(t, delegated)

	req := &backend.QueryDataRequest{PluginContext: backend.PluginContext{PluginID: "grafana"}}
	for _, q := range queries {
		require.Equal(t, "list", q.query.QueryType)
		req.Queries = append(req.Queries, q.query)
	}

	baseline := listHelperGoroutines()
	resp, err := grafanaPluginClient(t, graf).QueryData(ctx, req)
	require.NoError(t, err)
	require.Len(t, resp.Responses, 8)
	for refID, one := range resp.Responses {
		require.NoErrorf(t, one.Error, "refId %s", refID)
		require.NotEmpty(t, one.Frames, refID)
		rows, rowErr := one.Frames[0].RowLen()
		require.NoError(t, rowErr)
		require.Greater(t, rows, 0, refID)
	}

	// The HTTP server cancels the request context when the handler returns.
	cancel()
	requireListHelpersFinished(t, baseline)
}

func attackerListRequest(t *testing.T, n int) dtos.MetricRequest {
	t.Helper()
	queries := make([]*simplejson.Json, 0, n)
	for i := range n {
		body, err := simplejson.NewJson([]byte(fmt.Sprintf(
			`{"refId":"A%d","queryType":"list","path":"img","maxDataPoints":20,"datasource":{"type":"grafana","uid":%q}}`,
			i, grafanads.DatasourceUID,
		)))
		require.NoError(t, err)
		queries = append(queries, body)
	}
	return dtos.MetricRequest{From: "now-1h", To: "now", Queries: queries}
}

func viewerWithBuiltinDatasourceQuery() *user.SignedInUser {
	scope := datasources.ScopePrefix + grafanads.DatasourceUID
	return &user.SignedInUser{
		UserID:  7,
		OrgID:   1,
		OrgRole: org.RoleViewer,
		Permissions: map[int64]map[string][]string{
			1: {datasources.ActionQuery: {scope}},
		},
	}
}

func publicStaticStorage(t *testing.T) store.StorageService {
	t.Helper()
	cfg := &setting.Cfg{
		StaticRootPath: grafanaPublicDir(t),
		DataPath:       t.TempDir(),
		Env:            setting.Prod,
	}
	svc, err := store.ProvideService(nil, cfg, nil)
	require.NoError(t, err)
	return svc
}

func grafanaPublicDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "..", "public")
	info, err := os.Stat(filepath.Join(dir, "img"))
	require.NoError(t, err)
	require.True(t, info.IsDir())
	return dir
}

func grafanaPluginClient(t *testing.T, graf *grafanads.Service) plugins.Client {
	t.Helper()
	factory := coreplugin.New(backend.ServeOpts{QueryDataHandler: graf})
	backendPlugin, err := factory("grafana", pluglog.New("test"), nil, nil)
	require.NoError(t, err)

	plugin := &plugins.Plugin{JSONData: plugins.JSONData{ID: "grafana", Type: plugins.TypeDataSource, Backend: true}}
	plugin.RegisterClient(backendPlugin)

	reg := registry.NewInMemory()
	require.NoError(t, reg.Add(context.Background(), plugin))
	return pluginclient.ProvideService(reg)
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
