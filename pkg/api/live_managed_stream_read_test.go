package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/live"
	"github.com/grafana/grafana/pkg/services/live/pushhttp"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// Live push measurements are readable only by a caller who holds live:push in
// the same organization. The permission is checked on the list response and on
// the websocket subscription that returns the cached frame and later samples.
// A check against a different organization, or a subscription that is accepted
// and then fed from another channel, still fails these assertions.

const (
	liveStreamAlpha       = "zzalpha"
	liveStreamBeta        = "zzbeta"
	liveMeasAlpha         = "zzprivmeas"
	liveMeasBeta          = "zzothermeas"
	liveMeasOtherOrg      = "zzorg2meas"
	liveFieldAlpha        = "zzprivfield"
	liveFieldBeta         = "zzotherfield"
	liveFieldOtherOrg     = "zzorg2field"
	liveSampleAlpha       = "42.125"
	liveSampleAlphaUpdate = "99.875"
	liveSampleAlphaLater  = "77.625"
	liveSampleBeta        = "13.375"
	liveSampleOtherOrg    = "55.5"
)

func TestManagedStreamPush_ReadRequiresLivePushInSameOrg(t *testing.T) {
	cfg := setting.NewCfg()
	cfg.AppURL = "http://localhost:3000/"
	// conf/defaults.ini [live] max_connections. Zero disables new connections.
	cfg.LiveMaxConnections = 100

	routeRegister := routing.NewRouteRegister()
	gLive, err := live.ProvideService(cfg,
		routeRegister,
		nil, nil, nil, nil,
		&usagestats.UsageStatsMock{T: t},
		featuremgmt.WithFeatures(),
		&dashboards.FakeDashboardService{}, nil)
	require.NoError(t, err)
	gateway := pushhttp.ProvideService(cfg, gLive)

	server := SetupAPITestServer(t, func(hs *HTTPServer) {
		hs.RouteRegister = routeRegister
		hs.Cfg = cfg
		hs.Live = gLive
		hs.LivePushGateway = gateway
		hs.AccessControl = acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	})

	writer := liveUser(1, 1, org.RoleEditor, accesscontrol.Permission{Action: accesscontrol.ActionLivePush})
	viewer := liveUser(2, 1, org.RoleViewer)
	otherOrgWriter := liveUser(3, 2, org.RoleEditor, accesscontrol.Permission{Action: accesscontrol.ActionLivePush})

	pushStatus, pushBody := postLivePush(t, server, writer, liveStreamAlpha, liveMeasAlpha+" "+liveFieldAlpha+"="+liveSampleAlpha)
	require.Equal(t, http.StatusOK, pushStatus, "writer push: %s", pushBody)
	pushStatus, pushBody = postLivePush(t, server, writer, liveStreamBeta, liveMeasBeta+" "+liveFieldBeta+"="+liveSampleBeta)
	require.Equal(t, http.StatusOK, pushStatus, "writer push: %s", pushBody)
	pushStatus, pushBody = postLivePush(t, server, otherOrgWriter, liveStreamAlpha, liveMeasOtherOrg+" "+liveFieldOtherOrg+"="+liveSampleOtherOrg)
	require.Equal(t, http.StatusOK, pushStatus, "other org push: %s", pushBody)

	t.Run("anonymous list is rejected", func(t *testing.T) {
		req := server.NewGetRequest("/api/live/list")
		req = webtest.RequestWithWebContext(req, &contextmodel.ReqContext{
			SignedInUser: &user.SignedInUser{},
			IsSignedIn:   false,
		})
		res, err := server.Send(req)
		require.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		payload, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, res.StatusCode, string(payload))
		assertNoManagedSamples(t, string(payload))
	})

	t.Run("viewer list omits pushed channels from every stream", func(t *testing.T) {
		status, body := getLiveList(t, server, viewer)
		require.NotContains(t, body, liveMeasAlpha, "status %d body %s", status, body)
		require.NotContains(t, body, liveMeasBeta, "status %d body %s", status, body)
		require.NotContains(t, body, liveFieldAlpha, "status %d body %s", status, body)
		require.NotContains(t, body, liveFieldBeta, "status %d body %s", status, body)
		require.NotContains(t, body, liveMeasOtherOrg, "status %d body %s", status, body)
		require.NotContains(t, body, "stream/"+liveStreamAlpha+"/", "status %d body %s", status, body)
		require.NotContains(t, body, "stream/"+liveStreamBeta+"/", "status %d body %s", status, body)
	})

	t.Run("writer list returns only this org streams", func(t *testing.T) {
		status, body := getLiveList(t, server, writer)
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, "stream/"+liveStreamAlpha+"/"+liveMeasAlpha)
		require.Contains(t, body, "stream/"+liveStreamBeta+"/"+liveMeasBeta)
		require.Contains(t, body, liveFieldAlpha)
		require.Contains(t, body, liveFieldBeta)
		require.NotContains(t, body, liveMeasOtherOrg)
		require.NotContains(t, body, liveFieldOtherOrg)
	})

	t.Run("other org writer cannot list this org streams", func(t *testing.T) {
		status, body := getLiveList(t, server, otherOrgWriter)
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, "stream/"+liveStreamAlpha+"/"+liveMeasOtherOrg)
		require.NotContains(t, body, liveMeasAlpha)
		require.NotContains(t, body, liveMeasBeta)
		require.NotContains(t, body, liveFieldAlpha)
	})

	alphaChannel := writer.GetNamespace() + "/stream/" + liveStreamAlpha + "/" + liveMeasAlpha
	betaChannel := writer.GetNamespace() + "/stream/" + liveStreamBeta + "/" + liveMeasBeta
	otherOrgChannel := otherOrgWriter.GetNamespace() + "/stream/" + liveStreamAlpha + "/" + liveMeasOtherOrg

	t.Run("writer subscription receives the cached sample and a later push", func(t *testing.T) {
		conn := dialLive(t, server, writer)
		connectLive(t, conn)
		subscribeLive(t, conn, 2, alphaChannel)
		initial := readLiveUntil(t, conn, liveSampleAlpha, 3*time.Second)
		require.Contains(t, initial, liveSampleAlpha, initial)
		require.Contains(t, initial, liveFieldAlpha, initial)
		require.NotContains(t, initial, liveSampleBeta, initial)
		require.NotContains(t, initial, liveSampleOtherOrg, initial)

		status, body := postLivePush(t, server, writer, liveStreamAlpha, liveMeasAlpha+" "+liveFieldAlpha+"="+liveSampleAlphaUpdate)
		require.Equal(t, http.StatusOK, status, body)
		update := readLiveUntil(t, conn, liveSampleAlphaUpdate, 3*time.Second)
		require.Contains(t, update, liveSampleAlphaUpdate, update)
		require.NotContains(t, update, liveSampleOtherOrg, update)
	})

	t.Run("viewer subscription does not receive cached samples or later pushes", func(t *testing.T) {
		conn := dialLive(t, server, viewer)
		connectLive(t, conn)
		subscribeLive(t, conn, 2, alphaChannel)
		subscribeLive(t, conn, 3, betaChannel)
		// Also the legacy org-id prefix the older client sends for org 1.
		subscribeLive(t, conn, 4, "1/stream/"+liveStreamAlpha+"/"+liveMeasAlpha)
		cached := readLiveUntilAll(t, conn, []string{`"id":2`, `"id":3`, `"id":4`}, 3*time.Second)

		status, body := postLivePush(t, server, writer, liveStreamAlpha, liveMeasAlpha+" "+liveFieldAlpha+"="+liveSampleAlphaLater)
		require.Equal(t, http.StatusOK, status, body)
		later := readLiveUntil(t, conn, liveSampleAlphaLater, time.Second)
		assertNoManagedSamples(t, "cached:\n"+cached+"\nlater:\n"+later)
	})

	t.Run("live:push in another org does not authorize this org channel", func(t *testing.T) {
		conn := dialLive(t, server, otherOrgWriter)
		connectLive(t, conn)
		subscribeLive(t, conn, 2, alphaChannel)
		subscribeLive(t, conn, 3, "1/stream/"+liveStreamAlpha+"/"+liveMeasAlpha)
		foreign := readLiveUntilAll(t, conn, []string{`"id":2`, `"id":3`}, 3*time.Second)
		require.NotContains(t, foreign, liveSampleAlpha, foreign)
		require.NotContains(t, foreign, liveSampleAlphaUpdate, foreign)
		require.NotContains(t, foreign, liveSampleAlphaLater, foreign)
		require.NotContains(t, foreign, liveFieldAlpha, foreign)
		require.NotContains(t, foreign, liveSampleBeta, foreign)

		subscribeLive(t, conn, 4, otherOrgChannel)
		own := readLiveUntil(t, conn, liveSampleOtherOrg, 3*time.Second)
		require.Contains(t, own, liveSampleOtherOrg, own)
		require.NotContains(t, own, liveSampleAlpha, own)
		require.NotContains(t, own, liveSampleAlphaUpdate, own)
		require.NotContains(t, own, liveSampleAlphaLater, own)
	})

	t.Run("viewer list stays empty when the HA survey branch is used", func(t *testing.T) {
		cfg.LiveHAEngine = "redis"
		t.Cleanup(func() { cfg.LiveHAEngine = "" })
		require.True(t, gLive.IsHA())

		status, body := getLiveList(t, server, writer)
		require.Equal(t, http.StatusOK, status, body)
		require.Contains(t, body, "stream/"+liveStreamAlpha+"/"+liveMeasAlpha, body)

		status, body = getLiveList(t, server, viewer)
		require.NotContains(t, body, liveMeasAlpha, "status %d body %s", status, body)
		require.NotContains(t, body, liveMeasBeta, "status %d body %s", status, body)
		require.NotContains(t, body, liveFieldAlpha, "status %d body %s", status, body)
		require.NotContains(t, body, "stream/"+liveStreamAlpha+"/", "status %d body %s", status, body)
	})
}

func liveUser(userID, orgID int64, role org.RoleType, permissions ...accesscontrol.Permission) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:    userID,
		OrgID:     orgID,
		OrgRole:   role,
		Namespace: types.OrgNamespaceFormatter(orgID),
		Login:     "user",
		Permissions: map[int64]map[string][]string{
			orgID: accesscontrol.GroupScopesByActionContext(context.Background(), permissions),
		},
	}
}

func postLivePush(t *testing.T, server *webtest.Server, usr *user.SignedInUser, streamID, body string) (int, string) {
	t.Helper()
	req := server.NewRequest(http.MethodPost, "/api/live/push/"+streamID, strings.NewReader(body))
	req = webtest.RequestWithSignedInUser(req, usr)
	res, err := server.Send(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	payload, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(payload)
}

func getLiveList(t *testing.T, server *webtest.Server, usr *user.SignedInUser) (int, string) {
	t.Helper()
	req := server.NewGetRequest("/api/live/list")
	if usr != nil {
		req = webtest.RequestWithSignedInUser(req, usr)
	}
	res, err := server.Send(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	payload, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(payload)
}

func dialLive(t *testing.T, server *webtest.Server, usr *user.SignedInUser) *websocket.Conn {
	t.Helper()
	req := server.NewRequest(http.MethodGet, "/api/live/ws", nil)
	req = webtest.RequestWithSignedInUser(req, usr)
	header := http.Header{}
	header.Set("X-GRAFANA-WEB-TEST-ID", req.Header.Get("X-GRAFANA-WEB-TEST-ID"))
	wsURL := "ws" + strings.TrimPrefix(server.TestServer.URL, "http") + "/api/live/ws"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	require.NoError(t, err)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func connectLive(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`{"id":1,"connect":{}}`)))
	reply := readLiveUntil(t, conn, `"connect"`, 3*time.Second)
	require.Contains(t, reply, `"connect"`, reply)
}

func subscribeLive(t *testing.T, conn *websocket.Conn, id int, channel string) {
	t.Helper()
	payload := `{"id":` + itoa(id) + `,"subscribe":{"channel":"` + channel + `"}}`
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(payload)))
}

func readLiveUntil(t *testing.T, conn *websocket.Conn, needle string, wait time.Duration) string {
	t.Helper()
	var b strings.Builder
	deadline := time.Now().Add(wait)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		b.Write(msg)
		b.WriteByte('\n')
		if strings.Contains(b.String(), needle) {
			return b.String()
		}
	}
	return b.String()
}

func readLiveUntilAll(t *testing.T, conn *websocket.Conn, needles []string, wait time.Duration) string {
	t.Helper()
	var b strings.Builder
	deadline := time.Now().Add(wait)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		b.Write(msg)
		b.WriteByte('\n')
		got := b.String()
		complete := true
		for _, needle := range needles {
			if !strings.Contains(got, needle) {
				complete = false
				break
			}
		}
		if complete {
			return got
		}
	}
	return b.String()
}

func assertNoManagedSamples(t *testing.T, body string) {
	t.Helper()
	for _, secret := range []string{
		liveMeasAlpha, liveMeasBeta, liveMeasOtherOrg,
		liveFieldAlpha, liveFieldBeta, liveFieldOtherOrg,
		liveSampleAlpha, liveSampleAlphaUpdate, liveSampleAlphaLater, liveSampleBeta, liveSampleOtherOrg,
		"stream/" + liveStreamAlpha + "/",
		"stream/" + liveStreamBeta + "/",
	} {
		require.NotContains(t, body, secret, body)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
