package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"

	sdkapp "github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	"github.com/grafana/grafana/apps/shorturl/pkg/apis"
	shorturlv1beta1 "github.com/grafana/grafana/apps/shorturl/pkg/apis/shorturl/v1beta1"
)

const encodedDotAppURL = "http://127.0.0.1:3000/grafana"

// browserRequestPath is the path Chrome requests for an absolute URL.
//
// Verified against Chrome 157.0.8103.50 by following Location redirects and
// reading the raw request line: percent-encoded dots (%2e / %2E) are ".",
// "\" is a separator, and %2f is not a separator. So
// /grafana/%2e%2e/other-app/action is requested as /other-app/action, while
// /grafana/%2e%2e%2fother-app/action is requested with that encoding intact.
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

func pathStaysUnderAppRoot(appURL, location string) bool {
	root, err := browserRequestPath(appURL)
	if err != nil || root == "" {
		return false
	}
	requested, err := browserRequestPath(location)
	if err != nil {
		return false
	}
	loc, err := url.Parse(location)
	if err != nil {
		return false
	}
	app, err := url.Parse(appURL)
	if err != nil {
		return false
	}
	if loc.IsAbs() && !strings.EqualFold(loc.Host, app.Host) {
		return false
	}
	root = strings.TrimSuffix(root, "/")
	if root == "" {
		return true
	}
	return requested == root || strings.HasPrefix(requested, root+"/")
}

type routeRecorder struct {
	header http.Header
	body   strings.Builder
	code   int
}

func (r *routeRecorder) Header() http.Header {
	if r.header == nil {
		r.header = http.Header{}
	}
	return r.header
}

func (r *routeRecorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(b)
}

func (r *routeRecorder) WriteHeader(statusCode int) {
	r.code = statusCode
}

type kubeFake struct {
	mu     sync.Mutex
	path   string
	writes int
	urls   []string
}

func (k *kubeFake) handler(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	k.urls = append(k.urls, r.Method+" "+r.URL.RequestURI())
	if r.Method != http.MethodGet {
		k.writes++
	}
	stored := k.path
	k.mu.Unlock()

	body, err := json.Marshal(map[string]any{
		"apiVersion": shorturlv1beta1.APIGroup + "/" + shorturlv1beta1.APIVersion,
		"kind":       "ShortURL",
		"metadata": map[string]any{
			"name":            "abc",
			"namespace":       "stacks-123",
			"resourceVersion": "1",
		},
		"spec":   map[string]any{"path": stored},
		"status": map[string]any{"lastSeenAt": 0},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (k *kubeFake) writeCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.writes
}

func newShortURLApp(t *testing.T, fake *kubeFake) sdkapp.App {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	t.Cleanup(srv.Close)

	manifest := apis.LocalManifest().ManifestData
	require.NotNil(t, manifest)

	instance, err := New(sdkapp.Config{
		KubeConfig:     rest.Config{Host: srv.URL},
		ManifestData:   *manifest,
		SpecificConfig: &Config{AppURL: encodedDotAppURL},
	})
	require.NoError(t, err)
	return instance
}

func callGoto(t *testing.T, instance sdkapp.App, redirectFalse bool) (string, int, error) {
	t.Helper()
	raw := "http://127.0.0.1/apis/shorturl.grafana.app/v1beta1/namespaces/stacks-123/shorturls/abc/goto"
	if redirectFalse {
		raw += "?redirect=false"
	}
	u, err := url.Parse(raw)
	require.NoError(t, err)

	rec := &routeRecorder{}
	err = instance.CallCustomRoute(context.Background(), rec, &sdkapp.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{
			Namespace: "stacks-123",
			Name:      "abc",
			Group:     shorturlv1beta1.APIGroup,
			Version:   shorturlv1beta1.APIVersion,
			Kind:      "ShortURL",
			Plural:    "shorturls",
		},
		Path:   "goto",
		URL:    u,
		Method: http.MethodGet,
		Body:   io.NopCloser(strings.NewReader("")),
	})
	if err != nil {
		return "", rec.code, err
	}
	if redirectFalse {
		var resp shorturlv1beta1.GetGotoResponse
		require.NoError(t, json.Unmarshal([]byte(rec.body.String()), &resp))
		return resp.Url, rec.code, nil
	}
	return rec.Header().Get("Location"), rec.code, nil
}

func TestShortURLAdmissionAndGotoRejectEncodedDotSegments(t *testing.T) {
	paths := []string{
		"..",
		"%2e%2e",
		"%2e%2e/other-app/action",
		"%2E%2E/other-app/action",
		"%2e./other-app/action",
		".%2e/other-app/action",
		"d/%2e%2e/%2e%2e/other-app/action",
		"%2e%2e%2fother-app/action",
		"..%2fother-app/action",
	}

	t.Run("admission validate refuses the path", func(t *testing.T) {
		instance := newShortURLApp(t, &kubeFake{})
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				obj := shorturlv1beta1.NewShortURL()
				obj.Spec.Path = path
				err := instance.Validate(context.Background(), &sdkapp.AdmissionRequest{
					Action:  resource.AdmissionActionCreate,
					Kind:    "ShortURL",
					Group:   shorturlv1beta1.APIGroup,
					Version: shorturlv1beta1.APIVersion,
					Object:  obj,
				})
				require.Error(t, err)
			})
		}
	})

	t.Run("ordinary path redirects inside the root", func(t *testing.T) {
		fake := &kubeFake{path: "d/abc/dashboard?orgId=1"}
		instance := newShortURLApp(t, fake)
		for _, redirectFalse := range []bool{true, false} {
			got, _, err := callGoto(t, instance, redirectFalse)
			require.NoError(t, err)
			require.Truef(t, pathStaysUnderAppRoot(encodedDotAppURL, got), "location %s", got)
			require.Contains(t, got, "d/abc/dashboard")
		}
	})

	// The stored path is read back and placed on the redirect after the same
	// literal "../" check. The URL the handler returns is what /goto sends to
	// the browser, so a second look for the characters "../" does not help
	// when the emitted string still resolves outside the root.
	for _, path := range paths {
		t.Run("goto "+path, func(t *testing.T) {
			for _, redirectFalse := range []bool{true, false} {
				fake := &kubeFake{path: path}
				instance := newShortURLApp(t, fake)
				writesBefore := fake.writeCount()
				got, _, err := callGoto(t, instance, redirectFalse)
				if err != nil {
					require.Equal(t, writesBefore, fake.writeCount(), "status was written before the redirect was refused")
					continue
				}
				require.Truef(t, pathStaysUnderAppRoot(encodedDotAppURL, got),
					"redirect %q for stored path %q is requested outside %s", got, path, encodedDotAppURL)
			}
		})
	}
}
