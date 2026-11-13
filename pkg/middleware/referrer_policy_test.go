package middleware

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/dtos"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/navtree"
)

func TestDashboardIndexReferrerPolicyStripsSameOriginQuery(t *testing.T) {
	middlewareScenario(t, "dashboard index document must not send its query string on same-origin requests", func(t *testing.T, sc *scenarioContext) {
		sc.handlerFunc = func(c *contextmodel.ReqContext) {
			data := &dtos.IndexViewData{
				User:     &dtos.CurrentUser{},
				Settings: &dtos.FrontendSettingsDTO{},
				NavTree:  &navtree.NavTreeRoot{},
				Assets: &dtos.EntryPointAssets{
					JSFiles: []dtos.EntryPointAsset{},
					Dark:    "dark.css",
					Light:   "light.css",
				},
			}
			c.HTML(http.StatusOK, "index", data)
		}
		// Index renders this same template for / and for /d/:uid/:slug.
		sc.fakeReq("GET", "/").exec()
		require.Equal(t, http.StatusOK, sc.resp.Code)
		requireReferrerPolicyStripsSameOriginQuery(t, sc.resp.Header(), sc.resp.Body.String())
	})
}

// Policies that still send the full URL, including the query, for a same-origin fetch.
var queryLeakingReferrerPolicies = map[string]struct{}{
	"no-referrer-when-downgrade":      {},
	"strict-origin-when-cross-origin": {},
	"same-origin":                     {},
	"origin-when-cross-origin":        {},
	"unsafe-url":                      {},
}

var metaReferrerTag = regexp.MustCompile(`(?i)<meta\b[^>]*>`)
var metaAttr = regexp.MustCompile(`(?i)(name|http-equiv|content)\s*=\s*["']([^"']*)["']`)

func requireReferrerPolicyStripsSameOriginQuery(t *testing.T, header http.Header, body string) {
	t.Helper()

	policy := effectiveReferrerPolicy(header.Values("Referrer-Policy"))
	if policy == "" {
		policy = metaReferrerPolicy(body)
	}
	if !referrerPolicyStripsQuery(policy) {
		t.Fatalf("dashboard document referrer policy %q sends the page query string on same-origin requests", policy)
	}
}

func effectiveReferrerPolicy(values []string) string {
	var policy string
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			token = strings.ToLower(strings.TrimSpace(token))
			if token == "" {
				continue
			}
			if _, leaks := queryLeakingReferrerPolicies[token]; leaks || referrerPolicyStripsQuery(token) {
				policy = token
			}
		}
	}
	return policy
}

func metaReferrerPolicy(body string) string {
	var policy string
	for _, tag := range metaReferrerTag.FindAllString(body, -1) {
		attrs := map[string]string{}
		for _, match := range metaAttr.FindAllStringSubmatch(tag, -1) {
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
			policy = effectiveReferrerPolicy([]string{content})
		}
	}
	return policy
}

func referrerPolicyStripsQuery(policy string) bool {
	switch policy {
	case "no-referrer", "origin", "strict-origin":
		return true
	default:
		return false
	}
}
