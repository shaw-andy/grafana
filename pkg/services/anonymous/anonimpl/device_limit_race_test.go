package anonimpl

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/anonymous"
	"github.com/grafana/grafana/pkg/services/anonymous/anonimpl/anonstore"
	"github.com/grafana/grafana/pkg/services/anonymous/validator"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/util/xorm"
	"github.com/grafana/grafana/pkg/util/xorm/core"
)

const (
	raceBurst        = 8
	raceDeviceLimit  = int64(1)
	raceCountWait    = 3 * time.Second
	raceUserAgent    = "grafana-device-limit-test"
	raceRemoteAddr   = "192.0.2.8:40000"
	raceOrgName      = "Main Org."
	raceSeedDeviceID = "seed-device"
)

// TestIntegrationDeviceLimitRace is the spec for auth.anonymous device_limit.
// The cap is counted and then applied in separate database sessions. These tests
// hold every concurrent count of anon_device until the other callers have counted
// too, which is the window a second lookup in a later session would still lose.
// A single statement, or one session that rechecks the count and writes under the
// same lock, is not held. The race subtests fail while that window can admit
// more devices than the cap.
func TestIntegrationDeviceLimitRace(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("sequential cap rejects a new device and keeps the row out", func(t *testing.T) {
		fx := newRaceFixture(t, raceDeviceLimit, raceBurst)
		fx.logger.setGate(nil)

		ctx := context.Background()
		require.NoError(t, fx.plain.CreateOrUpdateDevice(ctx, newDevice("device-kept")))

		err := fx.plain.CreateOrUpdateDevice(ctx, newDevice("device-rejected"))
		require.ErrorIs(t, err, anonstore.ErrDeviceLimitReached)

		devices := fx.listDevices(ctx)
		require.Len(t, devices, 1)
		require.Equal(t, "device-kept", devices[0].DeviceID)

		// A device already inside the cap is refreshed, and that refresh must not add a row.
		kept := newDevice("device-kept")
		kept.ClientIP = "192.0.2.9"
		require.NoError(t, fx.plain.CreateOrUpdateDevice(ctx, kept))
		devices = fx.listDevices(ctx)
		require.Len(t, devices, 1)
		require.Equal(t, "192.0.2.9", devices[0].ClientIP)
	})

	t.Run("concurrent store inserts stay within the cap", func(t *testing.T) {
		fx := newRaceFixture(t, raceDeviceLimit, raceBurst)
		admitted := fx.burst(func(i int) error {
			return fx.gated.CreateOrUpdateDevice(context.Background(), newDevice(raceDeviceID(i)))
		})
		fx.assertWithinCap(admitted, nil)
	})

	t.Run("concurrent tag device stays within the cap", func(t *testing.T) {
		fx := newRaceFixture(t, raceDeviceLimit, raceBurst)
		admitted := fx.burst(func(i int) error {
			return fx.service.TagDevice(context.Background(), raceRequest(raceDeviceID(i)), anonymous.AnonDeviceUI)
		})
		fx.assertWithinCap(admitted, nil)
	})

	t.Run("concurrent anonymous authentication stays within the cap", func(t *testing.T) {
		fx := newRaceFixture(t, raceDeviceLimit, raceBurst)
		admitted := fx.burst(func(i int) error {
			id, err := fx.client.Authenticate(context.Background(), &authn.Request{HTTPRequest: raceRequest(raceDeviceID(i))})
			if err != nil {
				return err
			}
			requireAnonymousViewer(t, id, fx.org)
			return nil
		})
		fx.assertWithinCap(admitted, nil)
	})

	t.Run("unauthenticated request falls through to anonymous and stays within the cap", func(t *testing.T) {
		fx := newRaceFixture(t, raceDeviceLimit, raceBurst)
		authnSvc := authnimpl.ProvideService(
			fx.cfg,
			tracing.InitializeTracerForTest(),
			nil,
			&usagestats.UsageStatsMock{},
			nil,
			nil,
		)
		// Higher priority than anonymous, and it does not claim a request that only
		// carries a device id. That is the session/basic/api-key shape of an
		// unauthenticated request: Test is false, so authentication continues.
		authnSvc.RegisterClient(inactiveAuthClient{})
		authnSvc.RegisterClient(fx.client)

		admitted := fx.burst(func(i int) error {
			id, err := authnSvc.Authenticate(context.Background(), &authn.Request{HTTPRequest: raceRequest(raceDeviceID(i))})
			if err != nil {
				return err
			}
			requireAnonymousViewer(t, id, fx.org)
			return nil
		})
		fx.assertWithinCap(admitted, nil)
	})

	t.Run("concurrent inserts stay within the cap when one slot is already used", func(t *testing.T) {
		const limit = int64(2)
		fx := newRaceFixture(t, limit, raceBurst)
		fx.logger.setGate(nil)
		require.NoError(t, fx.plain.CreateOrUpdateDevice(context.Background(), newDevice(raceSeedDeviceID)))
		fx.logger.setGate(fx.gate)

		admitted := fx.burst(func(i int) error {
			return fx.gated.CreateOrUpdateDevice(context.Background(), newDevice(raceDeviceID(i)))
		})
		fx.assertWithinCap(admitted, []string{raceSeedDeviceID})
	})
}

func requireAnonymousViewer(t *testing.T, id *authn.Identity, want *org.Org) {
	t.Helper()
	require.NotNil(t, id)
	require.Equal(t, claims.TypeAnonymous, id.Type)
	require.Equal(t, want.ID, id.OrgID)
	require.Equal(t, want.Name, id.OrgName)
	require.Equal(t, org.RoleViewer, id.GetOrgRole())
}

type raceFixture struct {
	t       *testing.T
	limit   int64
	plain   *anonstore.AnonDBStore
	gated   *anonstore.AnonDBStore
	logger  *capturingLogger
	gate    *waveGate
	cfg     *setting.Cfg
	org     *org.Org
	service *AnonDeviceService
	client  *Anonymous
}

func newRaceFixture(t *testing.T, limit int64, burst int) *raceFixture {
	t.Helper()

	inner := db.NewTestStore(t)
	logger := newCapturingLogger()
	engine := inner.GetEngine()
	engine.SetLogger(logger)
	engine.ShowSQL(true)
	engine.ShowExecTime(true)

	cfg := setting.NewCfg()
	cfg.Anonymous.Enabled = true
	cfg.Anonymous.DeviceLimit = limit
	cfg.Anonymous.OrgName = raceOrgName
	cfg.Anonymous.OrgRole = string(org.RoleViewer)

	orgRecord := &org.Org{ID: 1, Name: cfg.Anonymous.OrgName}
	gate := newWaveGate(burst)
	logger.setGate(gate)
	gatedDB := &gatingDB{DB: inner}

	plain := anonstore.ProvideAnonDBStore(inner, limit)
	gated := anonstore.ProvideAnonDBStore(gatedDB, limit)
	orgService := &orgtest.FakeOrgService{ExpectedOrg: orgRecord}
	service := ProvideAnonymousDeviceService(
		&usagestats.UsageStatsMock{},
		&authntest.FakeService{},
		gatedDB,
		cfg,
		orgService,
		nil,
		actest.FakeAccessControl{},
		&routing.RouteRegisterImpl{},
		validator.FakeAnonUserLimitValidator{},
	)

	return &raceFixture{
		t:       t,
		limit:   limit,
		plain:   plain,
		gated:   gated,
		logger:  logger,
		gate:    gate,
		cfg:     cfg,
		org:     orgRecord,
		service: service,
		client: &Anonymous{
			cfg:               cfg,
			log:               log.NewNopLogger(),
			orgService:        orgService,
			anonDeviceService: service,
		},
	}
}

func (f *raceFixture) burst(call func(i int) error) map[string]struct{} {
	f.t.Helper()

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := make(map[string]struct{}, raceBurst)
	wg.Add(raceBurst)
	for i := 0; i < raceBurst; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			if err := call(i); err != nil {
				return
			}
			mu.Lock()
			admitted[raceDeviceID(i)] = struct{}{}
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()
	f.logger.setGate(nil)
	return admitted
}

func (f *raceFixture) listDevices(ctx context.Context) []*anonstore.Device {
	f.t.Helper()
	devices, err := f.plain.ListDevices(ctx, nil, nil)
	require.NoError(f.t, err)
	return devices
}

func (f *raceFixture) assertWithinCap(admitted map[string]struct{}, alreadyStored []string) {
	f.t.Helper()

	devices := f.listDevices(context.Background())
	allowed := make(map[string]struct{}, len(alreadyStored))
	for _, id := range alreadyStored {
		allowed[id] = struct{}{}
	}

	require.LessOrEqualf(f.t, int64(len(devices)), f.limit,
		"anon_device grew to %d rows with device_limit %d (admitted %d, count queries held %d)",
		len(devices), f.limit, len(admitted), f.gate.arrivals.Load())
	require.LessOrEqualf(f.t, int64(len(admitted)), f.limit,
		"admitted %d callers with device_limit %d", len(admitted), f.limit)
	require.NotEmpty(f.t, devices, "device_limit must still admit devices that fit")

	for id := range admitted {
		found := false
		for _, device := range devices {
			if device.DeviceID == id {
				found = true
				break
			}
		}
		require.Truef(f.t, found, "caller for %s was admitted but no anon_device row was stored", id)
	}
	for _, device := range devices {
		_, okAdmitted := admitted[device.DeviceID]
		_, okAllowed := allowed[device.DeviceID]
		require.Truef(f.t, okAdmitted || okAllowed,
			"anon_device row %s was stored without a successful admission", device.DeviceID)
	}
}

func newDevice(id string) *anonstore.Device {
	now := time.Now().UTC()
	return &anonstore.Device{
		DeviceID:  id,
		ClientIP:  "192.0.2.8",
		UserAgent: raceUserAgent,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func raceDeviceID(i int) string {
	return fmt.Sprintf("anon-device-%02d", i)
}

func raceRequest(deviceID string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/api/dashboards/home", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set(deviceIDHeader, deviceID)
	req.Header.Set("User-Agent", raceUserAgent)
	req.RemoteAddr = raceRemoteAddr
	return req
}

// inactiveAuthClient stands in for an earlier authenticator that does not match
// a request with no credentials. Priority is lower than anonymous so it is tried first.
type inactiveAuthClient struct{}

func (inactiveAuthClient) Name() string { return authn.ClientSession }

func (inactiveAuthClient) IsEnabled(context.Context) bool { return true }

func (inactiveAuthClient) Authenticate(context.Context, *authn.Request) (*authn.Identity, error) {
	return nil, fmt.Errorf("inactive client must not authenticate this request")
}

func (inactiveAuthClient) Test(context.Context, *authn.Request) bool { return false }

func (inactiveAuthClient) Priority() uint { return 10 }

// gatingDB is the real database. The race window is widened in the SQL logger,
// which runs after a device-count query returns and before the caller continues.
type gatingDB struct {
	db.DB
}

type capturingLogger struct {
	xorm.DiscardLogger
	mu   sync.Mutex
	gate *waveGate
}

func newCapturingLogger() *capturingLogger {
	return &capturingLogger{}
}

func (l *capturingLogger) setGate(gate *waveGate) {
	l.mu.Lock()
	l.gate = gate
	l.mu.Unlock()
}

func (l *capturingLogger) IsShowSQL() bool { return true }

func (l *capturingLogger) Infof(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	gate := l.gate
	l.mu.Unlock()
	if gate != nil && isDeviceCountSQL(msg) {
		gate.arrive()
	}
}

func isDeviceCountSQL(msg string) bool {
	upper := strings.ToUpper(msg)
	return strings.Contains(upper, "COUNT") && strings.Contains(upper, "ANON_DEVICE")
}

type waveGate struct {
	n        int
	mu       sync.Mutex
	waiting  int
	release  chan struct{}
	arrivals atomic.Int32
}

func newWaveGate(n int) *waveGate {
	return &waveGate{n: n, release: make(chan struct{})}
}

func (g *waveGate) arrive() {
	g.arrivals.Add(1)
	g.mu.Lock()
	g.waiting++
	if g.waiting == g.n {
		rel := g.release
		g.waiting = 0
		g.release = make(chan struct{})
		g.mu.Unlock()
		close(rel)
		return
	}
	rel := g.release
	g.mu.Unlock()

	timer := time.NewTimer(raceCountWait)
	defer timer.Stop()
	select {
	case <-rel:
	case <-timer.C:
		g.mu.Lock()
		if g.release == rel {
			close(g.release)
			g.release = make(chan struct{})
			g.waiting = 0
		}
		g.mu.Unlock()
	}
}

var _ core.ILogger = (*capturingLogger)(nil)
var _ authn.ContextAwareClient = inactiveAuthClient{}
