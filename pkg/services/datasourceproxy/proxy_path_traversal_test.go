package datasourceproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/pluginproxy"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasource "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/tracing"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/web"
)

// TestDataSourceProxyPathStaysUnderURL covers the datasource proxy director.
// getProxyPath keeps the escaped suffix, and the director joins it onto the
// datasource URL and percent-decodes the result before the request is sent,
// together with the datasource basic-auth credential.
func TestDataSourceProxyPathStaysUnderURL(t *testing.T) {
	const prefix = "/api/v1"

	t.Run("suffix under the datasource url is proxied with basic auth", func(t *testing.T) {
		hits, status, body := proxyDataSource(t, "/api/datasources/proxy/uid/abc/query")
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		require.Len(t, hits, 1)
		require.Equal(t, "/api/v1/query", dsRequestPath(hits[0].requestURI))
		require.NotEmpty(t, hits[0].authorization)
	})

	for _, tc := range []struct {
		name string
		in   string
	}{
		{name: "percent-encoded parent segments", in: "/api/datasources/proxy/uid/abc/%2e%2e/%2e%2e/admin"},
		{name: "literal parent segments", in: "/api/datasources/proxy/uid/abc/../../admin"},
		{name: "percent-encoded slash and parent segments", in: "/api/datasources/proxy/uid/abc/%2e%2e%2f%2e%2e%2fadmin"},
		{name: "single parent segment", in: "/api/datasources/proxy/uid/abc/../admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits, status, body := proxyDataSource(t, tc.in)
			for _, hit := range hits {
				got := dsRequestPath(hit.requestURI)
				require.False(t, dsHasDotSegment(got), "upstream received %q; authorization header present: %v", got, hit.authorization != "")
				require.True(t, dsUnderPrefix(got, prefix), "upstream received %q outside %q; authorization header present: %v", got, prefix, hit.authorization != "")
			}
			if len(hits) == 0 {
				require.GreaterOrEqual(t, status, 400, "body: %s", body)
			}
		})
	}
}

type dsHit struct {
	requestURI    string
	authorization string
}

func proxyDataSource(t *testing.T, incomingPath string) ([]dsHit, int, string) {
	t.Helper()

	hits := make(chan dsHit, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- dsHit{requestURI: r.RequestURI, authorization: r.Header.Get("Authorization")}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream"))
	}))
	t.Cleanup(upstream.Close)

	ds := &datasource.DataSource{}
	ds.Spec.SetURL(upstream.URL + "/api/v1")
	ds.Spec.SetBasicAuth(true)
	ds.Spec.SetBasicAuthUser("ds-basic-user")

	loader := stubDataSourceLoader{ds: ds, password: "placeholder-not-a-secret"}
	caller := &user.SignedInUser{UserID: 1, Login: "caller", OrgID: 1}
	req := httptest.NewRequest(http.MethodGet, incomingPath, nil)
	req = req.WithContext(identity.WithRequester(req.Context(), caller))
	recorder := httptest.NewRecorder()
	responseWriter := web.NewResponseWriter(http.MethodGet, recorder)
	ctx := &contextmodel.ReqContext{Context: &web.Context{Req: req, Resp: responseWriter}, SignedInUser: caller}

	proxy, err := pluginproxy.NewDataSourceProxy(
		loader,
		nil,
		pluginproxy.HTTPContext{Req: req, Resp: responseWriter},
		getProxyPath(ctx),
		&pluginproxy.DataSourceProxySettings{},
		httpclient.NewProvider(),
		nil,
		tracing.InitializeTracerForTest(),
		featuremgmt.WithFeatures(),
	)
	require.NoError(t, err)
	proxy.HandleRequest()

	var got []dsHit
	for {
		select {
		case hit := <-hits:
			got = append(got, hit)
		default:
			return got, recorder.Code, recorder.Body.String()
		}
	}
}

type stubDataSourceLoader struct {
	ds       *datasource.DataSource
	password string
}

func (s stubDataSourceLoader) PluginType() string { return datasources.DS_GRAPHITE }

func (s stubDataSourceLoader) DataSource(context.Context) (*datasource.DataSource, error) {
	return s.ds, nil
}

func (s stubDataSourceLoader) GetHTTPTransport(context.Context, httpclient.Provider) (http.RoundTripper, error) {
	return &http.Transport{}, nil
}

func (s stubDataSourceLoader) DecryptedPassword(context.Context) (string, error) {
	return "", nil
}

func (s stubDataSourceLoader) DecryptedBasicAuthPassword(context.Context) (string, error) {
	return s.password, nil
}

func (s stubDataSourceLoader) DecryptedValues(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

func dsRequestPath(requestURI string) string {
	if i := strings.Index(requestURI, "?"); i >= 0 {
		return requestURI[:i]
	}
	return requestURI
}

func dsHasDotSegment(raw string) bool {
	decoded, err := url.PathUnescape(dsRequestPath(raw))
	if err != nil {
		decoded = dsRequestPath(raw)
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func dsUnderPrefix(raw, prefix string) bool {
	decoded, err := url.PathUnescape(dsRequestPath(raw))
	if err != nil {
		return false
	}
	cleaned := path.Clean(decoded)
	base := path.Clean(prefix)
	if cleaned == base {
		return true
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return strings.HasPrefix(cleaned, base)
}
