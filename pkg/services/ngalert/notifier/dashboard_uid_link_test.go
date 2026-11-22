package notifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	kitlog "github.com/go-kit/log"
	alertingImages "github.com/grafana/alerting/images"
	"github.com/grafana/alerting/receivers"
	alertingWebhook "github.com/grafana/alerting/receivers/webhook/v1"
	alertingTemplates "github.com/grafana/alerting/templates"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"

	"github.com/grafana/grafana/pkg/infra/log/logtest"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	ngtemplate "github.com/grafana/grafana/pkg/services/ngalert/state/template"
)

func TestNotificationDashboardLinksStayUnderDashboardPath(t *testing.T) {
	external, err := url.Parse("http://localhost:3000/")
	require.NoError(t, err)
	subpath, err := url.Parse("http://localhost:3000/grafana/")
	require.NoError(t, err)

	cases := []struct {
		name     string
		uid      string
		panelID  string
		external *url.URL
		resolved bool
		safe     bool
	}{
		{name: "parent segments reach logout", uid: "../../logout", panelID: "1", external: external},
		{name: "parent segments reach organization switch", uid: "../../profile/switch-org/2", panelID: "1", external: external},
		{name: "nested parent segments reach logout", uid: "foo/../../logout", panelID: "1", external: external},
		{name: "subpath root still cannot be left", uid: "../../logout", panelID: "1", external: subpath},
		{name: "resolved alert uses the same links", uid: "../../logout", panelID: "1", external: external, resolved: true},
		{name: "dashboard uid alone is enough for the dashboard link", uid: "../../logout", external: external},
		{name: "ordinary uid stays on the dashboard", uid: "abc-DEF_1", panelID: "5", external: external, safe: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alert := alertFromRuleAnnotations(t, tc.uid, tc.panelID, tc.external, tc.resolved)

			dashboardHrefs, panelHrefs := renderEmailLinks(t, []*types.Alert{alert}, tc.external)
			if tc.safe {
				require.NotEmpty(t, dashboardHrefs)
				if tc.panelID != "" {
					require.NotEmpty(t, panelHrefs)
				}
			}
			for _, href := range append(dashboardHrefs, panelHrefs...) {
				requireDashboardPath(t, href, tc.external)
			}

			dashboardURL, panelURL := renderWebhookLinks(t, []*types.Alert{alert}, tc.external)
			if tc.safe {
				require.NotEmpty(t, dashboardURL)
				if tc.panelID != "" {
					require.NotEmpty(t, panelURL)
				}
			}
			if dashboardURL != "" {
				requireDashboardPath(t, dashboardURL, tc.external)
			}
			if panelURL != "" {
				requireDashboardPath(t, panelURL, tc.external)
			}
		})
	}
}

func alertFromRuleAnnotations(t *testing.T, dashboardUID, panelID string, appURL *url.URL, resolved bool) *types.Alert {
	t.Helper()

	raw := map[string]string{ngmodels.DashboardUIDAnnotation: dashboardUID}
	if panelID != "" {
		raw[ngmodels.PanelIDAnnotation] = panelID
	}
	annotations := make(map[string]string, len(raw))
	for key, value := range raw {
		expanded, err := ngtemplate.Expand(context.Background(), "rule", value, ngtemplate.Data{}, appURL, time.Now())
		require.NoError(t, err)
		annotations[key] = expanded
	}

	starts := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond)
	st := &state.State{
		OrgID:        1,
		AlertRuleUID: "rule-uid",
		State:        eval.Alerting,
		Annotations:  annotations,
		Labels:       data.Labels{"alertname": "cpu"},
		StartsAt:     starts,
		FiredAt:      &starts,
	}
	transition := state.StateTransition{State: st}
	if resolved {
		ends := starts.Add(time.Minute)
		st.EndsAt = ends
		st.ResolvedAt = &ends
		st.State = eval.Normal
		transition.PreviousState = eval.Alerting
	}

	postable := state.StateToPostableAlert(transition, appURL)
	require.Equal(t, dashboardUID, postable.Annotations[ngmodels.DashboardUIDAnnotation])
	return postableToNotifyAlert(postable)
}

func renderEmailLinks(t *testing.T, alerts []*types.Alert, external *url.URL) (dashboard, panel []string) {
	t.Helper()

	sender := createEmailSender(t)
	tmpl := alertingTemplates.ForTests(t)
	tmpl.ExternalURL = external
	emailNotifier := createSut(t, "", "", tmpl, sender)

	ok, err := emailNotifier.Notify(context.Background(), alerts...)
	require.NoError(t, err)
	require.True(t, ok)

	body := getSingleSentMessage(t, sender).Body["text/html"]
	return hrefsByText(t, body, "View dashboard"), hrefsByText(t, body, "View panel")
}

func renderWebhookLinks(t *testing.T, alerts []*types.Alert, external *url.URL) (dashboardURL, panelURL string) {
	t.Helper()

	tmpl := alertingTemplates.ForTests(t)
	tmpl.ExternalURL = external
	captured := &captureWebhook{}
	webhook := alertingWebhook.New(alertingWebhook.Config{
		URL:        "http://example.com/hook",
		HTTPMethod: http.MethodPost,
	}, receivers.Metadata{}, tmpl, captured, &alertingImages.UnavailableProvider{}, &logtest.Fake{}, 1)

	ctx := notify.WithGroupKey(context.Background(), "rule-uid")
	ctx = notify.WithReceiverName(ctx, "webhook")
	ok, err := webhook.Notify(ctx, alerts...)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, captured.bodies, 1)

	var payload struct {
		Alerts []struct {
			DashboardURL string `json:"dashboardURL"`
			PanelURL     string `json:"panelURL"`
		} `json:"alerts"`
	}
	require.NoError(t, json.Unmarshal([]byte(captured.bodies[0]), &payload))
	require.Len(t, payload.Alerts, 1)
	return payload.Alerts[0].DashboardURL, payload.Alerts[0].PanelURL
}

type captureWebhook struct {
	bodies []string
}

func (c *captureWebhook) SendWebhook(_ context.Context, _ kitlog.Logger, cmd *receivers.SendWebhookSettings) error {
	c.bodies = append(c.bodies, cmd.Body)
	return nil
}

func hrefsByText(t *testing.T, htmlBody, text string) []string {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(htmlBody))
	require.NoError(t, err)

	var hrefs []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" && strings.EqualFold(strings.TrimSpace(nodeText(n)), text) {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					hrefs = append(hrefs, attr.Val)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return hrefs
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return b.String()
}

// requireDashboardPath checks the URL a browser requests for a notification link.
// The dashboard uid has to occupy exactly one path segment under <root>/d/.
func requireDashboardPath(t *testing.T, raw string, external *url.URL) {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	resolved := external.ResolveReference(parsed)
	require.Equal(t, external.Scheme, resolved.Scheme, "link %s", raw)
	require.Equal(t, external.Host, resolved.Host, "link %s", raw)

	prefix := strings.TrimRight(external.EscapedPath(), "/") + "/d/"
	escaped := resolved.EscapedPath()
	require.Truef(t, strings.HasPrefix(escaped, prefix), "link %s resolved to %s", raw, escaped)
	segment := strings.TrimPrefix(escaped, prefix)
	require.NotEmpty(t, segment, "link %s", raw)
	require.NotContains(t, segment, "/", "link %s", raw)
	require.NotEqual(t, ".", segment, "link %s", raw)
	require.NotEqual(t, "..", segment, "link %s", raw)
}

func postableToNotifyAlert(postable *models.PostableAlert) *types.Alert {
	labels := make(model.LabelSet, len(postable.Labels))
	for key, value := range postable.Labels {
		labels[model.LabelName(key)] = model.LabelValue(value)
	}
	annotations := make(model.LabelSet, len(postable.Annotations))
	for key, value := range postable.Annotations {
		annotations[model.LabelName(key)] = model.LabelValue(value)
	}
	return &types.Alert{Alert: model.Alert{
		Labels:       labels,
		Annotations:  annotations,
		StartsAt:     time.Time(postable.StartsAt),
		EndsAt:       time.Time(postable.EndsAt),
		GeneratorURL: string(postable.GeneratorURL),
	}}
}
