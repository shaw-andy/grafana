package notifier

import (
	"context"
	"html"
	"net/url"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	alertingNotify "github.com/grafana/alerting/notify"
	alertingTemplates "github.com/grafana/alerting/templates"
	"github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/tracing"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/api/validation"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	statetemplate "github.com/grafana/grafana/pkg/services/ngalert/state/template"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/setting"
)

// TestAlertEmailDoesNotLinkRunbookToThisGrafanaServer follows the path an editor-supplied
// runbook annotation takes into the default alert notification email. A runbook may be an
// external http or https URL. It must not be emitted, as a link or as text a mail client
// will linkify, when its host is this Grafana server. Both the firing and resolved copies
// of the notification are covered, and both the HTML and plain-text bodies.
func TestAlertEmailDoesNotLinkRunbookToThisGrafanaServer(t *testing.T) {
	httpServer, err := url.Parse("http://localhost:3000/")
	require.NoError(t, err)
	httpsServer, err := url.Parse("https://grafana.example/")
	require.NoError(t, err)
	subpathServer, err := url.Parse("http://localhost:3000/grafana/")
	require.NoError(t, err)

	cases := []struct {
		name     string
		server   *url.URL
		runbook  string
		resolved bool
		// link means the address is an external runbook and must still be linked.
		link bool
	}{
		{
			name:    "external https runbook stays linked",
			server:  httpServer,
			runbook: "https://runbooks.example/oncall#cpu",
			link:    true,
		},
		{
			name:    "external url that mentions this server in the query stays linked",
			server:  httpServer,
			runbook: "https://runbooks.example/go?next=http://localhost:3000/logout",
			link:    true,
		},
		{
			name:    "firing alert links the logout url",
			server:  httpServer,
			runbook: "http://localhost:3000/logout",
		},
		{
			name:     "resolved alert links the logout url",
			server:   httpServer,
			runbook:  "http://localhost:3000/logout",
			resolved: true,
		},
		{
			name:    "logout url with userinfo",
			server:  httpServer,
			runbook: "http://editor@localhost:3000/logout",
		},
		{
			name:    "logout url with mixed-case scheme and host",
			server:  httpServer,
			runbook: "HTTP://LocalHost:3000/logout",
		},
		{
			name:    "logout url with query and fragment",
			server:  httpServer,
			runbook: "http://localhost:3000/logout?redirect=%2F#done",
		},
		{
			name:    "same host with a trailing slash",
			server:  httpServer,
			runbook: "http://localhost:3000/logout/",
		},
		{
			name:    "same host with a trailing dot",
			server:  httpServer,
			runbook: "http://localhost.:3000/logout",
		},
		{
			name:    "any path on this server",
			server:  httpServer,
			runbook: "http://localhost:3000/api/user",
		},
		{
			name:    "https logout url on this server",
			server:  httpsServer,
			runbook: "https://grafana.example/logout",
		},
		{
			name:    "logout url under the server subpath",
			server:  subpathServer,
			runbook: "http://localhost:3000/grafana/logout",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stored := runbookSavedOnRule(t, tc.runbook)
			if stored == "" {
				// The rule API refused the annotation, so it never reaches a notification.
				require.False(t, tc.link, "an external runbook must still be saveable")
				return
			}

			htmlBody, textBody := renderAlertEmail(t, tc.server, stored, tc.resolved)
			if tc.link {
				require.Truef(t, hrefNavigatesTo(htmlBody, tc.runbook), "external runbook was not linked: %s", tc.runbook)
				require.Truef(t, bodyNavigatesTo(textBody, tc.runbook), "external runbook missing from text body")
				return
			}
			require.Falsef(t, bodyNavigatesTo(textBody, tc.runbook), "text body still navigates to the runbook %s", tc.runbook)
			require.Falsef(t, bodyNavigatesTo(htmlBody, tc.runbook), "html body still navigates to the runbook %s", tc.runbook)
		})
	}
}

// runbookSavedOnRule returns the runbook annotation value a saved alert rule keeps.
// An empty result means the rule API rejected the annotation.
func runbookSavedOnRule(t *testing.T, runbook string) string {
	t.Helper()
	node := &apimodels.PostableExtendedRuleNode{
		ApiRuleNode: &apimodels.ApiRuleNode{
			Annotations: map[string]string{"runbook_url": runbook},
			Labels:      map[string]string{"severity": "warning"},
		},
		GrafanaManagedAlert: &apimodels.PostableGrafanaRule{
			Title:     "CPU high",
			Condition: "A",
			Data: []apimodels.AlertQuery{{
				RefID:         "A",
				DatasourceUID: "testdata",
				Model:         []byte(`{}`),
				RelativeTimeRange: apimodels.RelativeTimeRange{
					From: 600,
					To:   0,
				},
			}},
			NoDataState:  apimodels.NoData,
			ExecErrState: apimodels.ErrorErrState,
		},
	}
	limits := validation.RuleLimits{
		BaseInterval:                  time.Minute,
		DefaultRuleEvaluationInterval: time.Minute,
	}
	rule, err := validation.ValidateRuleNode(node, "cpu", time.Minute, 1, "folder", limits)
	if err != nil {
		return ""
	}
	return rule.Annotations["runbook_url"]
}

// renderAlertEmail expands the saved annotation, converts the firing or resolved state
// into the alert the email notifier receives, and returns the HTML and text bodies.
func renderAlertEmail(t *testing.T, server *url.URL, runbook string, resolved bool) (string, string) {
	t.Helper()
	ctx := context.Background()
	expanded, err := statetemplate.Expand(ctx, "CPU high", runbook, statetemplate.NewData(nil, eval.Result{}), server, time.Now())
	require.NoError(t, err)

	now := time.Now()
	endsAt := now.Add(time.Hour)
	st := eval.Alerting
	if resolved {
		endsAt = now.Add(-time.Minute)
		st = eval.Normal
	}
	transition := state.StateTransition{
		State: &state.State{
			OrgID:        1,
			AlertRuleUID: "cpu-high",
			State:        st,
			Annotations:  map[string]string{"runbook_url": expanded},
			Labels:       map[string]string{"alertname": "CPUHigh", "severity": "warning"},
			StartsAt:     now.Add(-time.Minute),
			EndsAt:       endsAt,
		},
		PreviousState: eval.Alerting,
	}
	postable := state.StateToPostableAlert(transition, server)
	require.Equal(t, expanded, string(postable.Annotations["runbook_url"]))

	alerts, validationErr := alertingNotify.PostableAlertsToAlertmanagerAlerts(models.PostableAlerts{postable}, now)
	if validationErr != nil {
		require.NoError(t, validationErr)
	}
	require.Len(t, alerts, 1)
	require.Equal(t, model.LabelValue(expanded), alerts[0].Annotations["runbook_url"])

	sender := createEmailSenderFor(t, server.String())
	emailTmpl := alertingTemplates.ForTests(t)
	emailTmpl.ExternalURL = server
	notifier := createSut(t, "", "", emailTmpl, sender)
	ok, err := notifier.Notify(ctx, alerts...)
	require.NoError(t, err)
	require.True(t, ok)

	sent := getSingleSentMessage(t, sender)
	return sent.Body["text/html"], sent.Body["text/plain"]
}

func createEmailSenderFor(t *testing.T, appURL string) *emailSender {
	t.Helper()
	tracer := tracing.InitializeTracerForTest()
	bus := bus.ProvideBus(tracer)
	cfg := setting.NewCfg()
	cfg.StaticRootPath = "../../../../public/"
	cfg.BuildVersion = "4.0.0"
	cfg.AppURL = appURL
	cfg.Smtp.Enabled = true
	cfg.Smtp.TemplatesPatterns = []string{"emails/*.html", "emails/*.txt"}
	cfg.Smtp.FromAddress = "from@address.com"
	cfg.Smtp.FromName = "Grafana Admin"
	cfg.Smtp.ContentTypes = []string{"text/html", "text/plain"}
	cfg.Smtp.Host = "localhost:1234"
	ns, err := notifications.ProvideService(bus, cfg, notifications.NewFakeMailer(), nil)
	require.NoError(t, err)
	return &emailSender{ns: ns}
}

var urlPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

// bodyNavigatesTo reports whether body contains an http(s) URL that takes a browser
// to the same host, port, path, and query as target. Userinfo, fragments, host case,
// and a trailing dot on the host are ignored.
func bodyNavigatesTo(body, target string) bool {
	want, err := url.Parse(target)
	if err != nil {
		return strings.Contains(strings.ToLower(html.UnescapeString(body)), strings.ToLower(target))
	}
	body = html.UnescapeString(body)
	if strings.Contains(strings.ToLower(body), strings.ToLower(target)) {
		return true
	}
	for _, raw := range urlPattern.FindAllString(body, -1) {
		raw = strings.TrimRight(raw, ".,);")
		if sameNavigation(want, raw) {
			return true
		}
	}
	return false
}

func hrefNavigatesTo(body, target string) bool {
	want, err := url.Parse(target)
	if err != nil {
		return false
	}
	body = html.UnescapeString(body)
	for _, match := range regexp.MustCompile(`(?i)href="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		if sameNavigation(want, html.UnescapeString(match[1])) {
			return true
		}
	}
	return false
}

func sameNavigation(want *url.URL, raw string) bool {
	got, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !strings.EqualFold(got.Scheme, want.Scheme) {
		return false
	}
	if !strings.EqualFold(trimTrailingDots(got.Hostname()), trimTrailingDots(want.Hostname())) {
		return false
	}
	if effectivePort(got) != effectivePort(want) {
		return false
	}
	if path.Clean(got.Path) != path.Clean(want.Path) {
		return false
	}
	return got.RawQuery == want.RawQuery
}

func trimTrailingDots(host string) string {
	return strings.TrimRight(host, ".")
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
