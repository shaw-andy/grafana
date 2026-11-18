package snapshot

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	commonv0 "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/services/dashboardsnapshots"
	"github.com/grafana/grafana/pkg/setting"
)

// browserPath matches the resolver in pkg/services/dashboardsnapshots/snapshot_key_test.go.
func browserPath(raw string) string {
	raw = strings.ReplaceAll(raw, "\\", "/")
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	var out []string
	for _, seg := range strings.Split(parsed.EscapedPath(), "/") {
		switch strings.ToLower(seg) {
		case "", ".", "%2e":
			if seg == "" && len(out) == 0 {
				out = append(out, "")
			}
		case "..", "%2e%2e", ".%2e", "%2e.":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	path := strings.Join(out, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func TestK8sLocalSnapshotCreateCannotPublishLogoutLink(t *testing.T) {
	origAppURL := setting.AppUrl
	setting.AppUrl = "http://localhost:3000/"
	t.Cleanup(func() { setting.AppUrl = origAppURL })

	const appURL = "http://localhost:3000/"
	keys := []string{
		"../../logout",
		`..\..\logout`,
		"%2e%2e/%2e%2e/logout",
		// Enough parent segments to climb out of the k8s delete URL as well as the list link.
		"../../../../../../../logout",
	}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			cmd := dashboardsnapshots.CreateDashboardSnapshotCommand{
				DashboardCreateCommand: dashv0.DashboardCreateCommand{
					Name: "Quarterly review",
					Dashboard: &commonv0.Unstructured{Object: map[string]any{
						"uid": "test-dashboard-uid",
					}},
				},
				Key:       key,
				DeleteKey: key,
			}

			// Same order as the local branch of the k8s snapshot create route:
			// PrepareLocalSnapshot mutates cmd, then the command is stored as a Snapshot.
			snapshotURL, err := dashboardsnapshots.PrepareLocalSnapshot(&cmd, "/d/test-dashboard-uid")
			if err != nil {
				return
			}

			snap := convertCreateCmdToK8sSnapshot(&cmd, "default")
			require.NotEqual(t, "/logout", browserPath(appURL+"dashboard/snapshot/"+snap.Name), "snapshot name %q", snap.Name)
			require.NotEqual(t, "/logout", browserPath(snapshotURL))
			require.NotNil(t, snap.Spec.DeleteKey)
			deleteURL := setting.ToAbsUrl("apis/" + dashv0.GROUP + "/" + dashv0.VERSION + "/namespaces/default/" + dashv0.SnapshotResourceInfo.GroupResource().Resource + "/delete/" + *snap.Spec.DeleteKey)
			require.NotEqual(t, "/logout", browserPath(appURL+"api/snapshots-delete/"+*snap.Spec.DeleteKey))
			// A deeper delete URL still must not collapse to the logout route.
			require.NotEqual(t, "/logout", browserPath(deleteURL))
			require.Equal(t, "Quarterly review", *snap.Spec.Title)
		})
	}
}
