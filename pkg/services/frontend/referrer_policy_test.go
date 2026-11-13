package frontend

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

func TestFrontendServiceIndexReferrerPolicyStripsSameOriginQuery(t *testing.T) {
	publicDir := setupTestWebAssets(t)
	cfg := &setting.Cfg{
		Raw:            ini.Empty(),
		HTTPPort:       "3000",
		StaticRootPath: publicDir,
	}
	service := createTestService(t, cfg)
	mux := web.New()
	service.addMiddlewares(mux)
	service.registerRoutes(mux)

	for _, path := range []string{"/", "/d/abc/overview"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)

			require.Equal(t, http.StatusOK, recorder.Code)
			require.Contains(t, recorder.Body.String(), "<div id=\"reactRoot\"></div>")
			requireFrontendReferrerPolicyStripsSameOriginQuery(t, recorder.Header(), recorder.Body.String())
		})
	}
}

var frontendQueryLeakingReferrerPolicies = map[string]struct{}{
	"no-referrer-when-downgrade":      {},
	"strict-origin-when-cross-origin": {},
	"same-origin":                     {},
	"origin-when-cross-origin":        {},
	"unsafe-url":                      {},
}

var frontendMetaReferrerTag = regexp.MustCompile(`(?i)<meta\b[^>]*>`)
var frontendMetaAttr = regexp.MustCompile(`(?i)(name|http-equiv|content)\s*=\s*["']([^"']*)["']`)

func requireFrontendReferrerPolicyStripsSameOriginQuery(t *testing.T, header http.Header, body string) {
	t.Helper()

	policy := frontendEffectiveReferrerPolicy(header.Values("Referrer-Policy"))
	if policy == "" {
		policy = frontendMetaReferrerPolicy(body)
	}
	if !frontendReferrerPolicyStripsQuery(policy) {
		t.Fatalf("index document referrer policy %q sends the page query string on same-origin requests", policy)
	}
}

func frontendEffectiveReferrerPolicy(values []string) string {
	var policy string
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			token = strings.ToLower(strings.TrimSpace(token))
			if token == "" {
				continue
			}
			if _, leaks := frontendQueryLeakingReferrerPolicies[token]; leaks || frontendReferrerPolicyStripsQuery(token) {
				policy = token
			}
		}
	}
	return policy
}

func frontendMetaReferrerPolicy(body string) string {
	var policy string
	for _, tag := range frontendMetaReferrerTag.FindAllString(body, -1) {
		attrs := map[string]string{}
		for _, match := range frontendMetaAttr.FindAllStringSubmatch(tag, -1) {
			attrs[strings.ToLower(match[1])] = strings.ToLower(strings.TrimSpace(match[2]))
		}
		kind := attrs["name"]
		if kind == "" {
			kind = attrs["http-equiv"]
		}
		if kind != "referrer" && kind != "referrer-policy" {
			continue
		}
		if content := attrs["content"]; content != "" {
			policy = frontendEffectiveReferrerPolicy([]string{content})
		}
	}
	return policy
}

func frontendReferrerPolicyStripsQuery(policy string) bool {
	switch policy {
	case "no-referrer", "origin", "strict-origin":
		return true
	default:
		return false
	}
}
