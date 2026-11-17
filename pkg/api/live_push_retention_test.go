package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/permreg"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/live"
	"github.com/grafana/grafana/pkg/services/live/pushhttp"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	maxPushStreamsPerNamespace  = 32
	maxPushChannelsPerNamespace = 64
	maxFramesPerPush            = 32
)

func TestLivePushRetention(t *testing.T) {
	editorPerms, viewerPerms := livePushRolePermissions(t)

	t.Run("viewer is denied and stores nothing", func(t *testing.T) {
		gl, server := newLivePushServer(t)
		res := postLivePush(t, server, signedInWithRole(t, org.RoleViewer, "default", viewerPerms), "denied", "cpu v=1\n")
		require.Equal(t, http.StatusForbidden, res)
		require.Empty(t, pushedChannels(t, gl, "default"))
	})

	t.Run("repeating one measurement does not accumulate frames", func(t *testing.T) {
		gl, server := newLivePushServer(t)
		editor := signedInWithRole(t, org.RoleEditor, "default", editorPerms)
		for range 5 {
			require.Equal(t, http.StatusOK, postLivePush(t, server, editor, "steady", "cpu v=1\n"))
		}
		require.Equal(t, []string{"stream/steady/cpu"}, pushedChannels(t, gl, "default"))
	})

	t.Run("one labels_column body cannot store unbounded measurements", func(t *testing.T) {
		gl, server := newLivePushServer(t)
		editor := signedInWithRole(t, org.RoleEditor, "default", editorPerms)
		status := postLivePush(t, server, editor, "batch", measurementBody(maxFramesPerPush+8, "p"))
		batch := channelsWithPrefix(pushedChannels(t, gl, "default"), "stream/batch/")
		if status != http.StatusOK {
			require.Empty(t, batch, "rejected push left frames in the cache")
		}
		require.LessOrEqualf(t, len(batch), maxFramesPerPush, "one push stored %d frames", len(batch))
	})

	t.Run("one wide body cannot store unbounded measurements", func(t *testing.T) {
		gl, server := newLivePushServer(t)
		editor := signedInWithRole(t, org.RoleEditor, "default", editorPerms)
		status := postLivePushURL(t, server, editor, "/api/live/push/wide?gf_live_frame_format=wide", measurementBody(maxFramesPerPush+8, "w"))
		wide := channelsWithPrefix(pushedChannels(t, gl, "default"), "stream/wide/")
		if status != http.StatusOK {
			require.Empty(t, wide, "rejected wide push left frames in the cache")
		}
		require.LessOrEqualf(t, len(wide), maxFramesPerPush, "wide push stored %d frames", len(wide))
	})

	t.Run("distinct stream ids cannot grow one namespace without a bound", func(t *testing.T) {
		gl, server := newLivePushServer(t)
		editor := signedInWithRole(t, org.RoleEditor, "default", editorPerms)
		other := signedInWithRole(t, org.RoleEditor, "org-2", editorPerms)
		require.Equal(t, http.StatusOK, postLivePush(t, server, other, "kept", "cpu v=1\n"))

		for i := 0; i < maxPushChannelsPerNamespace+8; i++ {
			streamID := fmt.Sprintf("s%d", i)
			status := postLivePush(t, server, editor, streamID, fmt.Sprintf("m%d v=1\n", i))
			if status != http.StatusOK {
				name := fmt.Sprintf("stream/%s/m%d", streamID, i)
				require.NotContainsf(t, pushedChannels(t, gl, "default"), name,
					"channel %s stored after push returned %d", name, status)
			}
		}

		stored := pushedChannels(t, gl, "default")
		require.LessOrEqualf(t, len(stored), maxPushChannelsPerNamespace,
			"editor push kept %d channels in one namespace", len(stored))
		require.LessOrEqualf(t, countDistinctStreams(stored), maxPushStreamsPerNamespace,
			"editor push kept %d streams", countDistinctStreams(stored))
		require.Equal(t, []string{"stream/kept/cpu"}, pushedChannels(t, gl, "org-2"),
			"pushes from default were written into org-2 or evicted org-2")
	})
}

func measurementBody(n int, prefix string) string {
	var body strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&body, "%s%d v=1\n", prefix, i)
	}
	return body.String()
}

func livePushRolePermissions(t *testing.T) (editor, viewer []accesscontrol.Permission) {
	t.Helper()
	svc := acimpl.ProvideOSSService(
		setting.NewCfg(),
		nil,
		nil,
		nil,
		featuremgmt.WithFeatures(),
		tracing.InitializeTracerForTest(),
		nil,
		permreg.ProvidePermissionRegistry(),
		nil,
	)
	require.NoError(t, svc.DeclareFixedRoles(FixedRoleRegistrations(false, false)...))
	require.NoError(t, svc.RegisterFixedRoles(context.Background()))

	roles := svc.GetStaticRoles(context.Background())
	require.NotNil(t, roles[string(org.RoleEditor)])
	require.NotNil(t, roles[string(org.RoleViewer)])
	require.NotNil(t, roles[string(org.RoleAdmin)])

	require.True(t, permissionsContain(roles[string(org.RoleEditor)].Permissions, accesscontrol.ActionLivePush),
		"fixed:live:writer was not granted to Editor")
	require.True(t, permissionsContain(roles[string(org.RoleAdmin)].Permissions, accesscontrol.ActionLivePush),
		"fixed:live:writer was not granted to Admin")
	require.False(t, permissionsContain(roles[string(org.RoleViewer)].Permissions, accesscontrol.ActionLivePush),
		"Viewer was granted live:push")

	return roles[string(org.RoleEditor)].Permissions, roles[string(org.RoleViewer)].Permissions
}

func permissionsContain(perms []accesscontrol.Permission, action string) bool {
	for _, perm := range perms {
		if perm.Action == action {
			return true
		}
	}
	return false
}

func newLivePushServer(t *testing.T) (*live.GrafanaLive, *webtest.Server) {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.AppURL = "http://localhost:3000/"
	gl, err := live.ProvideService(cfg,
		routing.NewRouteRegister(),
		nil, nil, nil, nil,
		&usagestats.UsageStatsMock{T: t},
		featuremgmt.WithFeatures(),
		&dashboards.FakeDashboardService{}, nil)
	require.NoError(t, err)
	gateway := pushhttp.ProvideService(cfg, gl)
	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.Cfg = cfg
		hs.Live = gl
		hs.LivePushGateway = gateway
		hs.AccessControl = acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	})
	return gl, server
}

func signedInWithRole(t *testing.T, role org.RoleType, namespace string, perms []accesscontrol.Permission) *user.SignedInUser {
	t.Helper()
	return &user.SignedInUser{
		UserID:      11,
		OrgID:       1,
		OrgRole:     role,
		Namespace:   namespace,
		Permissions: map[int64]map[string][]string{1: accesscontrol.GroupScopesByActionContext(context.Background(), perms)},
	}
}

func postLivePush(t *testing.T, server *webtest.Server, usr *user.SignedInUser, streamID, body string) int {
	t.Helper()
	return postLivePushURL(t, server, usr, "/api/live/push/"+streamID, body)
}

func postLivePushURL(t *testing.T, server *webtest.Server, usr *user.SignedInUser, url, body string) int {
	t.Helper()
	req := server.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req = webtest.RequestWithSignedInUser(req, usr)
	res, err := server.Send(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

func pushedChannels(t *testing.T, gl *live.GrafanaLive, namespace string) []string {
	t.Helper()
	channels, err := gl.ManagedStreamRunner.GetManagedChannels(namespace)
	require.NoError(t, err)
	names := make([]string, 0, len(channels))
	for _, channel := range channels {
		if strings.HasPrefix(channel.Channel, "plugin/testdata/") {
			continue
		}
		names = append(names, channel.Channel)
	}
	return names
}

func channelsWithPrefix(channels []string, prefix string) []string {
	out := make([]string, 0)
	for _, channel := range channels {
		if strings.HasPrefix(channel, prefix) {
			out = append(out, channel)
		}
	}
	return out
}

func countDistinctStreams(channels []string) int {
	streams := map[string]struct{}{}
	for _, channel := range channels {
		parts := strings.SplitN(channel, "/", 3)
		if len(parts) >= 2 {
			streams[parts[0]+"/"+parts[1]] = struct{}{}
		}
	}
	return len(streams)
}
