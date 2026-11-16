package datasource

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/plugins"
	testdatasource "github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource"
)

// The datasource apiserver resource connect handler forwards the caller-supplied
// subpath to the plugin CallResource handler. TestData's boom route must not panic
// when that subpath is boom.
func TestTestDataApiserverBoomResourceDoesNotPanic(t *testing.T) {
	svc := testdatasource.ProvideService()
	builder := &DataSourceAPIBuilder{
		pluginJSON: plugins.JSONData{ID: "grafana-testdata-datasource"},
		client:     svc,
		datasources: &resourceMockDatasourceProvider{
			instanceSettings: &backend.DataSourceInstanceSettings{
				UID:  "testdata",
				Type: "grafana-testdata-datasource",
				Name: "TestData",
			},
		},
		contextProvider: &resourceMockContextProvider{
			pluginCtx: backend.PluginContext{PluginID: "grafana-testdata-datasource"},
		},
	}
	resource := &subResourceREST{builder: builder}

	ctx := request.WithNamespace(t.Context(), "default")
	handler, err := resource.Connect(ctx, "testdata", nil, &resourceMockResponder{})
	require.NoError(t, err)

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/apis/testdata.datasource.grafana.app/v0alpha1/namespaces/default/datasources/testdata/resources/boom", nil)
			rec := httptest.NewRecorder()
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("%s apiserver resources/boom panicked: %v", method, recovered)
				}
			}()
			handler.ServeHTTP(rec, req)
			require.NotEqual(t, http.StatusInternalServerError, rec.Code, "body: %s", rec.Body.String())
		})
	}
}
