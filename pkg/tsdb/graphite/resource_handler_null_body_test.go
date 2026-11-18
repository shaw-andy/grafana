package graphite

import (
	"context"
	"net/http"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana-plugin-sdk-go/backend/resource/httpadapter"
	"github.com/stretchr/testify/require"
)

// Routes whose handlers read fields from the decoded body. /functions and
// /version discard that pointer, so a JSON null body does not reach a field read.
var graphiteBodyResourceRoutes = []struct {
	path     string
	body     []byte
	upstream []byte
}{
	{path: "events", body: []byte(`{"from":"now-1h","until":"now"}`), upstream: []byte(`[]`)},
	{path: "metrics/find", body: []byte(`{"query":"servers.*"}`), upstream: []byte(`[]`)},
	{path: "metrics/expand", body: []byte(`{"query":"servers.*"}`), upstream: []byte(`{"results":[]}`)},
	{path: "tags/autoComplete/tags", body: []byte(`{"from":"now-1h","until":"now","limit":10}`), upstream: []byte(`[]`)},
	{path: "tags/autoComplete/values", body: []byte(`{"expr":["servers"],"tag":"env","from":"now-1h","until":"now"}`), upstream: []byte(`[]`)},
}

func graphiteServiceForResourceCall(transport *mockRoundTripper) *Service {
	svc := &Service{
		logger: log.NewNullLogger(),
		im: &mockInstanceManager{instance: datasourceInfo{
			Id:         1,
			URL:        "http://graphite.example",
			HTTPClient: &http.Client{Transport: transport},
		}},
	}
	svc.resourceHandler = httpadapter.New(svc.newResourceMux())
	return svc
}

func callGraphiteResource(svc *Service, path string, body []byte) (resp *backend.CallResourceResponse, callErr error, panicked any) {
	func() {
		defer func() { panicked = recover() }()
		callErr = svc.CallResource(context.Background(), &backend.CallResourceRequest{
			PluginContext: backend.PluginContext{},
			Path:          path,
			Method:        http.MethodPost,
			URL:           path,
			Body:          body,
		}, backend.CallResourceResponseSenderFunc(func(r *backend.CallResourceResponse) error {
			if resp == nil {
				copied := *r
				copied.Body = append([]byte(nil), r.Body...)
				resp = &copied
				return nil
			}
			resp.Body = append(resp.Body, r.Body...)
			return nil
		}))
	}()
	return resp, callErr, panicked
}

func TestGraphiteResourceRoutesRejectJSONNullWithoutCallingGraphite(t *testing.T) {
	bodies := []struct {
		name string
		body []byte
	}{
		{name: "json null", body: []byte("null")},
		{name: "json null with whitespace", body: []byte(" \nnull\n")},
		{name: "empty body", body: nil},
	}

	for _, route := range graphiteBodyResourceRoutes {
		for _, body := range bodies {
			t.Run(route.path+"/"+body.name, func(t *testing.T) {
				transport := &mockRoundTripper{status: http.StatusOK, respBody: route.upstream}
				svc := graphiteServiceForResourceCall(transport)

				resp, err, panicked := callGraphiteResource(svc, route.path, body.body)

				require.Nil(t, transport.lastRequest, "Graphite was contacted")
				require.Nilf(t, panicked, "resource call panicked: %v", panicked)
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, http.StatusBadRequest, resp.Status)
			})
		}
	}
}

func TestGraphiteResourceHandlersRejectNilBodyWithoutCallingGraphite(t *testing.T) {
	handlers := []struct {
		name string
		call func(*Service, *datasourceInfo) ([]byte, int, error)
	}{
		{name: "events", call: func(s *Service, ds *datasourceInfo) ([]byte, int, error) {
			return s.handleEvents(context.Background(), ds, nil)
		}},
		{name: "metrics/find", call: func(s *Service, ds *datasourceInfo) ([]byte, int, error) {
			return s.handleMetricsFind(context.Background(), ds, nil)
		}},
		{name: "metrics/expand", call: func(s *Service, ds *datasourceInfo) ([]byte, int, error) {
			return s.handleMetricsExpand(context.Background(), ds, nil)
		}},
		{name: "tags/autoComplete/tags", call: func(s *Service, ds *datasourceInfo) ([]byte, int, error) {
			return s.handleTagsAutocomplete(context.Background(), ds, nil)
		}},
		{name: "tags/autoComplete/values", call: func(s *Service, ds *datasourceInfo) ([]byte, int, error) {
			return s.handleTagValuesAutocomplete(context.Background(), ds, nil)
		}},
	}

	for _, handler := range handlers {
		t.Run(handler.name, func(t *testing.T) {
			transport := &mockRoundTripper{status: http.StatusOK, respBody: []byte(`[]`)}
			ds := &datasourceInfo{
				Id:         1,
				URL:        "http://graphite.example",
				HTTPClient: &http.Client{Transport: transport},
			}
			svc := &Service{logger: log.NewNullLogger()}

			var (
				body     []byte
				status   int
				err      error
				panicked any
			)
			func() {
				defer func() { panicked = recover() }()
				body, status, err = handler.call(svc, ds)
			}()

			require.Nil(t, transport.lastRequest, "Graphite was contacted")
			require.Nilf(t, panicked, "handler panicked: %v", panicked)
			require.Error(t, err)
			require.Equal(t, http.StatusBadRequest, status)
			require.Nil(t, body)
		})
	}
}

func TestGraphiteResourceRoutesForwardJSONObjectToGraphite(t *testing.T) {
	for _, route := range graphiteBodyResourceRoutes {
		t.Run(route.path, func(t *testing.T) {
			transport := &mockRoundTripper{status: http.StatusOK, respBody: route.upstream}
			svc := graphiteServiceForResourceCall(transport)

			resp, err, panicked := callGraphiteResource(svc, route.path, route.body)

			require.Nilf(t, panicked, "resource call panicked: %v", panicked)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, http.StatusOK, resp.Status)
			require.NotNil(t, transport.lastRequest)
			require.Contains(t, transport.lastRequest.URL.String(), "http://graphite.example/")
		})
	}
}
