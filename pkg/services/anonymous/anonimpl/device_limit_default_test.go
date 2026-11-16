package anonimpl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/anonymous/anonimpl/anonstore"
	"github.com/grafana/grafana/pkg/services/anonymous/anonimpl/api"
	"github.com/grafana/grafana/pkg/services/anonymous/validator"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

// requiredAnonymousDeviceLimit is the cap that must apply when
// auth.anonymous.device_limit is missing, empty, or zero.
const requiredAnonymousDeviceLimit int64 = 100

// maxAnonymousDeviceIDLen is the anon_device.device_id column width. A longer
// X-Grafana-Device-Id must not be stored or used as a cache key.
const maxAnonymousDeviceIDLen = 127

const deviceTestUserAgent = "anon-device-limit-test"

func TestShippedAnonymousDeviceLimitIsFinite(t *testing.T) {
	t.Run("defaults.ini", func(t *testing.T) {
		cfg := loadGrafanaCfg(t, "")
		require.False(t, cfg.Anonymous.Enabled)
		require.Equal(t, requiredAnonymousDeviceLimit, cfg.Anonymous.DeviceLimit)
	})

	t.Run("enabled with device_limit left unset", func(t *testing.T) {
		cfg := loadGrafanaCfg(t, "[auth.anonymous]\nenabled = true\n")
		require.True(t, cfg.Anonymous.Enabled)
		require.Equal(t, requiredAnonymousDeviceLimit, cfg.Anonymous.DeviceLimit)
	})

	t.Run("explicit zero is the same finite default", func(t *testing.T) {
		cfg := loadGrafanaCfg(t, "[auth.anonymous]\nenabled = true\ndevice_limit = 0\n")
		require.True(t, cfg.Anonymous.Enabled)
		require.Equal(t, requiredAnonymousDeviceLimit, cfg.Anonymous.DeviceLimit)
	})

	t.Run("explicit positive limit is kept", func(t *testing.T) {
		cfg := loadGrafanaCfg(t, "[auth.anonymous]\nenabled = true\ndevice_limit = 2\n")
		require.Equal(t, int64(2), cfg.Anonymous.DeviceLimit)
	})
}

func TestIntegrationAnonymousDeviceFloodIsCapped(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("unset device_limit", func(t *testing.T) {
		cfg := loadGrafanaCfg(t, "[auth.anonymous]\nenabled = true\n")
		assertDeviceFloodCapped(t, cfg, requiredAnonymousDeviceLimit)
	})

	t.Run("explicit zero device_limit", func(t *testing.T) {
		cfg := loadGrafanaCfg(t, "[auth.anonymous]\nenabled = true\ndevice_limit = 0\n")
		assertDeviceFloodCapped(t, cfg, requiredAnonymousDeviceLimit)
	})

	t.Run("explicit small device_limit", func(t *testing.T) {
		cfg := loadGrafanaCfg(t, "[auth.anonymous]\nenabled = true\ndevice_limit = 2\n")
		assertDeviceFloodCapped(t, cfg, 2)
	})

	t.Run("device id longer than the column", func(t *testing.T) {
		cfg := loadGrafanaCfg(t, "[auth.anonymous]\nenabled = true\ndevice_limit = 2\n")
		svc, authnSvc := newAnonymousAuth(t, cfg)
		longID := strings.Repeat("a", maxAnonymousDeviceIDLen+1)

		_, _ = authnSvc.Authenticate(context.Background(), anonDeviceRequest(t, longID))
		assertNoOversizedDevice(t, svc, longID)

		_, _ = authnSvc.Authenticate(context.Background(), anonDeviceRequest(t, longID))
		assertNoOversizedDevice(t, svc, longID)
	})
}

func assertDeviceFloodCapped(t *testing.T, cfg *setting.Cfg, limit int64) {
	t.Helper()

	svc, authnSvc := newAnonymousAuth(t, cfg)
	ctx := context.Background()

	var firstID string
	for i := int64(0); i < limit; i++ {
		deviceID := fmt.Sprintf("device-%d", i)
		if firstID == "" {
			firstID = deviceID
		}
		identity, err := authnSvc.Authenticate(ctx, anonDeviceRequest(t, deviceID))
		require.NoError(t, err)
		require.NotNil(t, identity)
		require.Equal(t, "0", identity.ID)
		require.True(t, identity.IsIdentityType(claims.TypeAnonymous))
	}

	identity, err := authnSvc.Authenticate(ctx, anonDeviceRequest(t, firstID))
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.Equal(t, limit, countStoredDevices(t, svc))
	stored, err := svc.ListDevices(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, stored, int(limit))
	requireStoredAttackerFields(t, stored, firstID)

	search, err := svc.SearchDevices(ctx, &anonstore.SearchDeviceQuery{Page: 1, Limit: 1})
	require.NoError(t, err)
	require.NotNil(t, search)
	require.Equal(t, limit, search.TotalCount)
	require.Len(t, search.Devices, 1)
	assertDeviceAPIsReturnCappedSet(t, cfg, svc, limit)

	const extra = 5
	rejected := make([]string, 0, extra)
	for i := int64(0); i < extra; i++ {
		deviceID := fmt.Sprintf("overflow-%d", i)
		rejected = append(rejected, deviceID)
		identity, err = authnSvc.Authenticate(ctx, anonDeviceRequest(t, deviceID))
		require.ErrorIs(t, err, anonstore.ErrDeviceLimitReached)
		require.Nil(t, identity)
		require.Equal(t, limit, countStoredDevices(t, svc))
		_, cached := svc.localCache.Get((&anonstore.Device{DeviceID: deviceID}).CacheKey())
		require.False(t, cached, "rejected device id was cached")
	}

	for _, deviceID := range rejected {
		identity, err = authnSvc.Authenticate(ctx, anonDeviceRequest(t, deviceID))
		require.ErrorIs(t, err, anonstore.ErrDeviceLimitReached)
		require.Nil(t, identity)
		require.Equal(t, limit, countStoredDevices(t, svc))
		_, cached := svc.localCache.Get((&anonstore.Device{DeviceID: deviceID}).CacheKey())
		require.False(t, cached, "rejected device id was cached on retry")
	}

	identity, err = authnSvc.Authenticate(ctx, anonDeviceRequest(t, firstID))
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.Equal(t, limit, countStoredDevices(t, svc))
}

func assertNoOversizedDevice(t *testing.T, svc *AnonDeviceService, longID string) {
	t.Helper()

	devices, err := svc.anonStore.ListDevices(context.Background(), nil, nil)
	require.NoError(t, err)
	for _, device := range devices {
		require.LessOrEqual(t, len(device.DeviceID), maxAnonymousDeviceIDLen)
		require.NotEqual(t, longID, device.DeviceID)
	}

	_, cached := svc.localCache.Get((&anonstore.Device{DeviceID: longID}).CacheKey())
	require.False(t, cached, "uncapped device id was used as a cache key")
}

func assertDeviceAPIsReturnCappedSet(t *testing.T, cfg *setting.Cfg, svc *AnonDeviceService, limit int64) {
	t.Helper()

	anonAPI := api.NewAnonDeviceServiceAPI(cfg, svc.anonStore, actest.FakeAccessControl{}, &routing.RouteRegisterImpl{})

	listReq := httptest.NewRequest(http.MethodGet, "/api/anonymous/devices", nil)
	listResp := anonAPI.ListDevices(reqContext(listReq))
	require.Equal(t, http.StatusOK, listResp.Status())
	var listed []struct {
		DeviceID string `json:"deviceId"`
	}
	require.NoError(t, json.Unmarshal(listResp.Body(), &listed))
	require.Len(t, listed, int(limit))

	searchReq := httptest.NewRequest(http.MethodGet, "/api/anonymous/search?perpage=1&page=1", nil)
	searchResp := anonAPI.SearchDevices(reqContext(searchReq))
	require.Equal(t, http.StatusOK, searchResp.Status())
	var found anonstore.SearchDeviceQueryResult
	require.NoError(t, json.Unmarshal(searchResp.Body(), &found))
	require.Equal(t, limit, found.TotalCount)
	require.Len(t, found.Devices, 1)
}

func requireStoredAttackerFields(t *testing.T, devices []*anonstore.Device, deviceID string) {
	t.Helper()
	for _, device := range devices {
		require.LessOrEqual(t, len(device.DeviceID), maxAnonymousDeviceIDLen)
		if device.DeviceID == deviceID {
			require.Equal(t, "192.0.2.10", device.ClientIP)
			require.Equal(t, deviceTestUserAgent, device.UserAgent)
			return
		}
	}
	t.Fatalf("stored devices did not include %s", deviceID)
}

func countStoredDevices(t *testing.T, svc *AnonDeviceService) int64 {
	t.Helper()
	devices, err := svc.anonStore.ListDevices(context.Background(), nil, nil)
	require.NoError(t, err)
	return int64(len(devices))
}

func newAnonymousAuth(t *testing.T, cfg *setting.Cfg) (*AnonDeviceService, *authnimpl.Service) {
	t.Helper()

	store := db.NewTestStore(t)
	tracer := tracing.InitializeTracerForTest()
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	authnSvc := authnimpl.ProvideService(cfg, tracer, nil, &usagestats.UsageStatsMock{}, nil, nil)
	authnSvc.RegisterClient(clients.ProvideSession(cfgProvider, nil, nil, tracer))

	orgSvc := &orgtest.FakeOrgService{ExpectedOrg: &org.Org{ID: 1, Name: cfg.Anonymous.OrgName}}
	deviceSvc := ProvideAnonymousDeviceService(
		&usagestats.UsageStatsMock{},
		authnSvc,
		store,
		cfg,
		orgSvc,
		nil,
		actest.FakeAccessControl{},
		&routing.RouteRegisterImpl{},
		validator.ProvideAnonUserLimitValidator(),
	)
	require.True(t, cfg.Anonymous.Enabled)
	return deviceSvc, authnSvc
}

func anonDeviceRequest(t *testing.T, deviceID string) *authn.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboards/home", nil)
	req.RemoteAddr = "192.0.2.10:4242"
	req.Header.Set("User-Agent", deviceTestUserAgent)
	req.Header.Set(deviceIDHeader, deviceID)
	return &authn.Request{HTTPRequest: req}
}

func reqContext(req *http.Request) *contextmodel.ReqContext {
	return &contextmodel.ReqContext{
		Context: &web.Context{Req: req},
		Logger:  log.New("anon-device-limit-test"),
	}
}

func loadGrafanaCfg(t *testing.T, customINI string) *setting.Cfg {
	t.Helper()

	wd, err := os.Getwd()
	require.NoError(t, err)
	root := filepath.Clean(filepath.Join(wd, "..", "..", "..", ".."))
	require.FileExists(t, filepath.Join(root, "conf", "defaults.ini"))

	args := setting.CommandLineArgs{HomePath: root}
	if customINI != "" {
		path := filepath.Join(t.TempDir(), "custom.ini")
		require.NoError(t, os.WriteFile(path, []byte(customINI), 0o644))
		args.Config = path
	}

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(args))
	return cfg
}
