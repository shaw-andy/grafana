package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/middleware"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// placeholderGrafanaComProxyToken is a stand-in for grafana_com proxy_token / sso_api_token.
// It is not a real credential.
const placeholderGrafanaComProxyToken = "placeholder-grafana-com-proxy-token"

const (
	gnetSensitiveBody = "sensitive-upstream-body"
	gnetCatalogBody   = "catalog-upstream-body"
	gnetPublicBody    = "public-upstream-body"
)

// gnetUpstream is the configured grafana.com API. It resolves dot segments in the
// raw request target with path.Clean before choosing a resource, then returns that
// resource. path.Clean is the dot-segment removal Go's HTTP server uses in
// cleanPath; this server applies it and serves the result instead of redirecting.
type gnetUpstream struct {
	server    *httptest.Server
	apiPrefix string

	mu   sync.Mutex
	seen []gnetCapturedRequest
}

type gnetCapturedRequest struct {
	requestURI    string
	resolvedPath  string
	tokenAttached bool
}

func newGnetUpstream(t *testing.T) *gnetUpstream {
	t.Helper()

	up := &gnetUpstream{apiPrefix: "/api"}
	up.server = httptest.NewServer(http.HandlerFunc(up.serve))
	t.Cleanup(up.server.Close)
	return up
}

func (u *gnetUpstream) serve(w http.ResponseWriter, r *http.Request) {
	resolved, tokenAttached := u.record(r)
	switch {
	case tokenAttached && !gnetResolvedPathAllowlisted(u.apiPrefix, resolved):
		_, _ = io.WriteString(w, gnetSensitiveBody)
	case tokenAttached && gnetResolvedPathAllowlisted(u.apiPrefix, resolved):
		_, _ = io.WriteString(w, gnetCatalogBody)
	default:
		_, _ = io.WriteString(w, gnetPublicBody)
	}
}

func (u *gnetUpstream) record(r *http.Request) (string, bool) {
	rawPath, err := requestTargetPath(r.RequestURI)
	resolved := rawPath
	if err == nil {
		resolved = path.Clean(rawPath)
	}
	tokenAttached := r.Header.Get("Authorization") == "Bearer "+placeholderGrafanaComProxyToken

	u.mu.Lock()
	u.seen = append(u.seen, gnetCapturedRequest{
		requestURI:    r.RequestURI,
		resolvedPath:  resolved,
		tokenAttached: tokenAttached,
	})
	u.mu.Unlock()
	return resolved, tokenAttached
}

func (u *gnetUpstream) reset() {
	u.mu.Lock()
	u.seen = nil
	u.mu.Unlock()
}

func (u *gnetUpstream) snapshot() []gnetCapturedRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]gnetCapturedRequest, len(u.seen))
	copy(out, u.seen)
	return out
}

func requestTargetPath(requestURI string) (string, error) {
	target := requestURI
	if target == "" {
		target = "/"
	}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}
	return url.PathUnescape(target)
}

// gnetResolvedPathAllowlisted reports whether resolved is a canonical path under
// the grafana.com API prefix that the proxy allowlist accepts. resolved must
// already have had dot segments removed.
func gnetResolvedPathAllowlisted(apiPrefix, resolved string) bool {
	if resolved != path.Clean(resolved) {
		return false
	}
	if apiPrefix != "" && apiPrefix != "/" {
		if resolved != apiPrefix && !strings.HasPrefix(resolved, apiPrefix+"/") {
			return false
		}
	}
	rel := strings.TrimPrefix(resolved, apiPrefix)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" || rel == "." {
		return false
	}
	return ssoTokenAllowedPath(rel)
}

func tokenPathViolation(apiPrefix string, got gnetCapturedRequest) string {
	if !got.tokenAttached {
		return ""
	}
	rawPath, err := requestTargetPath(got.requestURI)
	if err != nil {
		return "proxy token was attached to an unparseable request target"
	}
	resolved := path.Clean(rawPath)
	if resolved != rawPath {
		return "proxy token was attached to non-canonical request target " + rawPath + ", which resolves to " + resolved
	}
	if !gnetResolvedPathAllowlisted(apiPrefix, resolved) {
		return "proxy token was attached to " + resolved + ", which is outside the grafana.com allowlist"
	}
	return ""
}

func TestGnetProxyTokenFollowsResolvedPath(t *testing.T) {
	upstream := newGnetUpstream(t)
	hs := &HTTPServer{
		Cfg: &setting.Cfg{
			BuildVersion:            "test",
			GrafanaComAPIURL:        upstream.server.URL + upstream.apiPrefix,
			GrafanaComProxyAPIToken: placeholderGrafanaComProxyToken,
		},
	}

	rr := routing.NewRouteRegister()
	rr.Any("/api/gnet/*", middleware.ReqSignedIn, hs.ProxyGnetRequest)
	srv := webtest.NewServer(t, rr)

	viewer := &user.SignedInUser{
		UserID:  2,
		OrgID:   1,
		Login:   "viewer",
		OrgRole: identity.RoleViewer,
	}

	send := func(t *testing.T, method, urlPath string, signedIn bool) (int, string) {
		t.Helper()
		upstream.reset()

		var req *http.Request
		switch method {
		case http.MethodPost:
			req = srv.NewPostRequest(urlPath, nil)
		default:
			req = srv.NewRequest(method, urlPath, nil)
		}
		if signedIn {
			req = webtest.RequestWithSignedInUser(req, viewer)
		} else {
			req = webtest.RequestWithWebContext(req, &contextmodel.ReqContext{})
		}
		ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		resp, err := srv.Send(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		require.NoError(t, err)
		return resp.StatusCode, string(body)
	}

	requireNoTokenLeak := func(t *testing.T, status int, body string) {
		t.Helper()
		require.NotContains(t, body, gnetSensitiveBody, "status %d, upstream %#v", status, upstream.snapshot())
		for _, got := range upstream.snapshot() {
			if violation := tokenPathViolation(upstream.apiPrefix, got); violation != "" {
				t.Fatalf("%s (status %d, body %q)", violation, status, body)
			}
		}
	}

	t.Run("allowlisted plugin version still receives the proxy token", func(t *testing.T) {
		status, body := send(t, http.MethodGet, "/api/gnet/plugins/grafana-clock-panel/versions", true)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, gnetCatalogBody, body)
		seen := upstream.snapshot()
		require.NotEmpty(t, seen)
		require.True(t, seen[0].tokenAttached)
		require.Equal(t, "/api/plugins/grafana-clock-panel/versions", seen[0].resolvedPath)
		requireNoTokenLeak(t, status, body)
	})

	// Each path matches an allowlist rule before dot segments are removed, and
	// resolves outside that rule afterwards. A signed-in Viewer sends them.
	attacks := []struct {
		name string
		path string
	}{
		{
			name: "images prefix traverses to orgs",
			path: "/api/gnet/plugins/some-plugin/versions/1.0.0/images/../../../../../orgs",
		},
		{
			name: "images prefix traverses to plugins orgs",
			path: "/api/gnet/plugins/some-plugin/versions/1.0.0/images/../../../../orgs",
		},
		{
			name: "images prefix traverses to install",
			path: "/api/gnet/plugins/some-plugin/versions/1.0.0/images/../../../install",
		},
		{
			name: "encoded dot segments in the images prefix",
			path: "/api/gnet/plugins/some-plugin/versions/1.0.0/images/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/orgs",
		},
		{
			name: "plugin id segment is dotdot",
			path: "/api/gnet/plugins/..",
		},
		{
			name: "entitlement id segment is dotdot",
			path: "/api/gnet/plugins/../entitlement",
		},
		{
			name: "versions id segment is dotdot",
			path: "/api/gnet/plugins/../versions",
		},
		{
			name: "version id segment is dotdot",
			path: "/api/gnet/plugins/../versions/1.0.0",
		},
		{
			name: "logo id segment is dotdot",
			path: "/api/gnet/plugins/../versions/1.0.0/logos/logo.png",
		},
		{
			name: "insights id segment is dotdot",
			path: "/api/gnet/plugins/../versions/1.0.0/insights",
		},
		{
			name: "dashboard id segment is dotdot",
			path: "/api/gnet/dashboards/..",
		},
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			status, body := send(t, http.MethodGet, tt.path, true)
			requireNoTokenLeak(t, status, body)
		})
	}

	t.Run("anonymous caller is rejected before the proxy", func(t *testing.T) {
		status, body := send(t, http.MethodGet, "/api/gnet/plugins/some-plugin/versions/1.0.0/images/../../../../../orgs", false)
		require.Equal(t, http.StatusUnauthorized, status)
		require.NotContains(t, body, gnetSensitiveBody)
		require.Empty(t, upstream.snapshot())
	})

	t.Run("post does not attach the proxy token to a traversed path", func(t *testing.T) {
		status, body := send(t, http.MethodPost, "/api/gnet/plugins/some-plugin/versions/1.0.0/images/../../../../../orgs", true)
		requireNoTokenLeak(t, status, body)
	})
}
