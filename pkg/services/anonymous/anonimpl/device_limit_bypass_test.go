package anonimpl

import (
	"context"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/anonymous/validator"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// These tests exercise anonymous authentication the way an HTTP client reaches it:
// the auth service tries credentialed clients first, then the anonymous client, and
// the signed-in middleware used by dashboard pages and signed-in APIs decides
// whether that identity may continue. A missing device header has to be denied
// the same way a new device is denied once device_limit is in force. Checking
// TagDevice alone is not enough: Authenticate still returns an anonymous identity
// unless the error is the device-limit error.

const (
	anonOrgName = "Main Org."
	anonOrgID   = int64(1)
)

func TestIntegrationAnonymousDeviceLimit_OmittedHeader(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("headerless clients cannot outnumber the cap", func(t *testing.T) {
		f := newAnonLimitFixture(t, 1)

		first := f.request(t, "/api/search/", nil, "10.1.0.1")
		second := f.request(t, "/api/search/", nil, "10.1.0.2")

		successes := 0
		for _, res := range []anonHTTPResult{first, second} {
			if res.status == http.StatusOK {
				successes++
				res.requireAnonymousViewer(t)
			} else {
				require.Equal(t, http.StatusUnauthorized, res.status)
				require.False(t, res.handlerCalled)
			}
		}

		require.LessOrEqual(t, successes, 1)
		require.GreaterOrEqual(t, f.deviceCount(t), int64(successes))
		require.NotEqual(t, http.StatusOK, second.status, "a second headerless client was authenticated without consuming a device slot")
	})

	t.Run("omitted header is denied once counted devices fill the cap", func(t *testing.T) {
		f := newAnonLimitFixture(t, 1)
		browser := "browser-device-1"

		allowed := f.request(t, "/d/test-dash", &browser, "10.0.0.8")
		require.Equal(t, http.StatusOK, allowed.status)
		allowed.requireAnonymousViewer(t)
		require.Equal(t, []string{browser}, f.deviceIDs(t))

		otherBrowser := "browser-device-2"
		blockedBrowser := f.request(t, "/api/search/", &otherBrowser, "10.0.0.9")
		require.Equal(t, http.StatusUnauthorized, blockedBrowser.status)
		require.False(t, blockedBrowser.handlerCalled)
		require.Equal(t, []string{browser}, f.deviceIDs(t))

		before := f.deviceIDs(t)
		// No device header at all, then an explicitly empty one, from new addresses
		// and from the same address. None of these may reach a dashboard page or an
		// API route guarded by the signed-in middleware, and none may be stored.
		attacks := []struct {
			path       string
			deviceID   *string
			forwarded  string
			wantStatus int
		}{
			{path: "/d/test-dash", deviceID: nil, forwarded: "10.9.0.1", wantStatus: http.StatusFound},
			{path: "/api/search/", deviceID: nil, forwarded: "10.9.0.2", wantStatus: http.StatusUnauthorized},
			{path: "/api/search/", deviceID: nil, forwarded: "10.9.0.2", wantStatus: http.StatusUnauthorized},
			{path: "/d/other-dash", deviceID: nil, forwarded: "", wantStatus: http.StatusFound},
			{path: "/api/search/", deviceID: new(string), forwarded: "10.9.0.3", wantStatus: http.StatusUnauthorized},
		}
		for _, attack := range attacks {
			res := f.request(t, attack.path, attack.deviceID, attack.forwarded)
			require.Equal(t, attack.wantStatus, res.status)
			require.False(t, res.handlerCalled)
			if attack.wantStatus == http.StatusFound {
				require.Contains(t, res.location, "/login")
			}
			require.Equal(t, before, f.deviceIDs(t))
		}

		stillAllowed := f.request(t, "/api/search/", &browser, "10.0.0.8")
		require.Equal(t, http.StatusOK, stillAllowed.status)
		stillAllowed.requireAnonymousViewer(t)
		require.Equal(t, before, f.deviceIDs(t))
	})

	t.Run("device limit of zero still authenticates a headerless viewer", func(t *testing.T) {
		f := newAnonLimitFixture(t, 0)

		apiRes := f.request(t, "/api/search/", nil, "10.4.0.1")
		require.Equal(t, http.StatusOK, apiRes.status)
		apiRes.requireAnonymousViewer(t)

		pageRes := f.request(t, "/d/test-dash", nil, "10.4.0.1")
		require.Equal(t, http.StatusOK, pageRes.status)
		pageRes.requireAnonymousViewer(t)
	})
}

type anonHTTPResult struct {
	status        int
	location      string
	handlerCalled bool
	anonymous     bool
	allowAnon     bool
	signedIn      bool
	role          org.RoleType
	orgID         int64
}

func (r anonHTTPResult) requireAnonymousViewer(t *testing.T) {
	t.Helper()
	require.True(t, r.handlerCalled)
	require.True(t, r.anonymous)
	require.True(t, r.allowAnon)
	require.False(t, r.signedIn)
	require.Equal(t, org.RoleViewer, r.role)
	require.Equal(t, anonOrgID, r.orgID)
}

type anonLimitFixture struct {
	anon   *AnonDeviceService
	server *webtest.Server
	hit    anonHTTPResult
}

func newAnonLimitFixture(t *testing.T, deviceLimit int64) *anonLimitFixture {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.Anonymous.Enabled = true
	cfg.Anonymous.OrgName = anonOrgName
	cfg.Anonymous.OrgRole = string(org.RoleViewer)
	cfg.Anonymous.DeviceLimit = deviceLimit

	store := db.NewTestStore(t)
	routeRegister := routing.NewRouteRegister()
	authnSvc := authnimpl.ProvideService(
		cfg,
		tracing.InitializeTracerForTest(),
		nil,
		&usagestats.UsageStatsMock{},
		nil,
		nil,
	)
	// A credentialed client runs before anonymous auth. Requests in these tests
	// carry no Authorization header, so this client does not match and the
	// request falls through to the anonymous client, as it does for a browser
	// or API call with no session.
	var passwordClient authn.PasswordClient
	authnSvc.RegisterClient(clients.ProvideBasic(passwordClient))

	orgSvc := &orgtest.FakeOrgService{ExpectedOrg: &org.Org{ID: anonOrgID, Name: anonOrgName}}
	anonSvc := ProvideAnonymousDeviceService(
		&usagestats.UsageStatsMock{},
		authnSvc,
		store,
		cfg,
		orgSvc,
		nil,
		actest.FakeAccessControl{},
		routeRegister,
		validator.ProvideAnonUserLimitValidator(),
	)

	f := &anonLimitFixture{anon: anonSvc}
	server := webtest.NewServer(t, routeRegister)
	server.HttpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	server.Mux.Use(contexthandler.ProvideService(cfg, authnSvc, featuremgmt.WithFeatures()).Middleware)

	record := func(c *contextmodel.ReqContext) {
		f.hit.handlerCalled = true
		f.hit.anonymous = c.IsAnonymous
		f.hit.allowAnon = c.AllowAnonymous
		f.hit.signedIn = c.IsSignedIn
		f.hit.role = c.OrgRole
		f.hit.orgID = c.OrgID
		c.JSON(http.StatusOK, map[string]string{"status": "reached"})
	}
	// Same signed-in gate as dashboard pages (/d/:uid) and signed-in API routes.
	server.Mux.Get("/d/:uid", middleware.ReqSignedIn, record)
	server.Mux.Get("/api/search/", middleware.ReqSignedIn, record)

	f.server = server
	return f
}

// request issues one GET. A nil deviceID omits X-Grafana-Device-Id. A non-nil
// deviceID sets that header, including when the value is empty.
func (f *anonLimitFixture) request(t *testing.T, path string, deviceID *string, forwardedFor string) anonHTTPResult {
	t.Helper()

	f.hit = anonHTTPResult{}
	req := f.server.NewGetRequest(path)
	if deviceID != nil {
		req.Header.Set(deviceIDHeader, *deviceID)
	}
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}

	resp, err := f.server.Send(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = resp.Body.Close()
	})
	_, _ = io.Copy(io.Discard, resp.Body)

	f.hit.status = resp.StatusCode
	f.hit.location = resp.Header.Get("Location")
	return f.hit
}

func (f *anonLimitFixture) deviceCount(t *testing.T) int64 {
	t.Helper()
	to := time.Now().Add(time.Minute)
	from := to.Add(-thirtyDays)
	count, err := f.anon.CountDevices(context.Background(), from, to)
	require.NoError(t, err)
	return count
}

func (f *anonLimitFixture) deviceIDs(t *testing.T) []string {
	t.Helper()
	devices, err := f.anon.ListDevices(context.Background(), nil, nil)
	require.NoError(t, err)
	ids := make([]string, 0, len(devices))
	for _, device := range devices {
		ids = append(ids, device.DeviceID)
	}
	slices.Sort(ids)
	return ids
}
