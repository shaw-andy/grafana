package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/apps/shorturl/pkg/apis/shorturl/v1beta1"
	"github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/setting"
)

const encodedDotRoot = "http://localhost:3000/grafana/"

// browserRequestPath is the path Chrome requests for an absolute URL.
//
// Verified against Chrome 157.0.8103.50: %2e and %2E are ".", "\" is a
// separator, and %2f is not. /grafana/%2e%2e/other-app/action is requested as
// /other-app/action.
func browserRequestPath(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	escaped := strings.ReplaceAll(u.EscapedPath(), `\`, "/")
	var stack []string
	for _, seg := range strings.Split(escaped, "/") {
		dot := strings.ReplaceAll(seg, "%2e", ".")
		dot = strings.ReplaceAll(dot, "%2E", ".")
		switch dot {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, seg)
		}
	}
	if len(stack) == 0 {
		return "/", nil
	}
	return "/" + strings.Join(stack, "/"), nil
}

func locationStaysUnderRoot(t *testing.T, location string) {
	t.Helper()
	if location == "" {
		return
	}
	root, err := browserRequestPath(encodedDotRoot)
	require.NoError(t, err)
	requested, err := browserRequestPath(location)
	require.NoError(t, err)
	loc, err := url.Parse(location)
	require.NoError(t, err)
	app, err := url.Parse(encodedDotRoot)
	require.NoError(t, err)
	if loc.IsAbs() {
		require.Truef(t, strings.EqualFold(loc.Host, app.Host), "location host %s", loc.Host)
	}
	root = strings.TrimSuffix(root, "/")
	require.Truef(t, requested == root || strings.HasPrefix(requested, root+"/"),
		"Location %s is requested as %s, outside %s", location, requested, root)
}

func TestKubernetesRedirectEncodedDotSegmentStaysUnderRoot(t *testing.T) {
	const validUID = "abcdef1234"

	newHandler := func(t *testing.T, body []byte, status int) *shortURLK8sHandler {
		t.Helper()
		cfg := setting.NewCfg()
		cfg.AppURL = encodedDotRoot
		return &shortURLK8sHandler{
			gvr:        v1beta1.ShortURLKind().GroupVersionResource(),
			namespacer: request.GetNamespaceMapper(cfg),
			clientConfigProvider: &mockDirectRestConfigProvider{
				host:      "http://localhost",
				transport: &mockRoundTripper{statusCode: status, responseBody: body},
			},
			cfg: cfg,
		}
	}

	t.Run("path inside the root is redirected", func(t *testing.T) {
		target := "http://localhost:3000/grafana/d/abc/dashboard"
		handler := newHandler(t, mustMarshal(t, v1beta1.GetGotoResponse{Url: target}), http.StatusOK)
		ctx, recorder := newTestContext(t, http.MethodGet, "/goto/"+validUID, map[string]string{":uid": validUID})
		handler.getKubernetesRedirectFromShortURL(ctx)
		require.Equal(t, http.StatusFound, recorder.Code)
		require.Equal(t, target, recorder.Header().Get("Location"))
		locationStaysUnderRoot(t, recorder.Header().Get("Location"))
	})

	// The handler parses the absolute URL from the goto subresource and only
	// compares its host with the Grafana host. These URLs have that host, and
	// the path still leaves /grafana once the browser removes dot segments.
	// Re-checking the raw string for "../" between that host comparison and
	// writing Location still fails this test.
	outside := []string{
		"http://localhost:3000/grafana/..",
		"http://localhost:3000/grafana/%2e%2e",
		"http://localhost:3000/grafana/%2e%2e/other-app/action",
		"http://localhost:3000/grafana/%2E%2E/other-app/action",
		"http://localhost:3000/grafana/%2e./other-app/action",
		"http://localhost:3000/grafana/.%2e/other-app/action",
		"http://localhost:3000/grafana/d/%2e%2e/%2e%2e/other-app/action",
	}
	for _, target := range outside {
		t.Run(target, func(t *testing.T) {
			handler := newHandler(t, mustMarshal(t, v1beta1.GetGotoResponse{Url: target}), http.StatusOK)
			ctx, recorder := newTestContext(t, http.MethodGet, "/goto/"+validUID, map[string]string{":uid": validUID})
			handler.getKubernetesRedirectFromShortURL(ctx)

			location := recorder.Header().Get("Location")
			if location == "" {
				require.NotContains(t, []int{
					http.StatusFound,
					http.StatusMovedPermanently,
					http.StatusTemporaryRedirect,
					http.StatusPermanentRedirect,
				}, recorder.Code)
				return
			}
			locationStaysUnderRoot(t, location)
		})
	}
}
