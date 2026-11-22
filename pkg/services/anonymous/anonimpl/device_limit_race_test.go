package anonimpl

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/anonymous"
	"github.com/grafana/grafana/pkg/services/anonymous/anonimpl/anonstore"
	"github.com/grafana/grafana/pkg/services/anonymous/validator"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// gatingAnonStore pauses inside CreateOrUpdateDevice so a second authentication
// can run after the device cache has been written and before the database
// result is stored. The pause is the only added behavior: the limit decision
// is still the real store.
type gatingAnonStore struct {
	anonstore.AnonStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatingAnonStore) CreateOrUpdateDevice(ctx context.Context, device *anonstore.Device) error {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return g.AnonStore.CreateOrUpdateDevice(ctx, device)
}

func TestIntegrationAnonymousDeviceLimitOverlap(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	ctx := context.Background()
	sqlStore := db.InitTestDB(t) //nolint:staticcheck // same setup as the other anon-device integration tests
	cfg := setting.NewCfg()
	cfg.Anonymous.Enabled = true
	cfg.Anonymous.OrgName = "Main Org."
	cfg.Anonymous.OrgRole = string(org.RoleViewer)
	cfg.Anonymous.DeviceLimit = 1

	anonOrg := &org.Org{ID: 1, Name: cfg.Anonymous.OrgName}
	deviceService := ProvideAnonymousDeviceService(
		&usagestats.UsageStatsMock{},
		&authntest.FakeService{},
		sqlStore,
		cfg,
		&orgtest.FakeOrgService{ExpectedOrg: anonOrg},
		nil,
		actest.FakeAccessControl{},
		&routing.RouteRegisterImpl{},
		validator.ProvideAnonUserLimitValidator(),
	)

	now := time.Now()
	err := deviceService.anonStore.CreateOrUpdateDevice(ctx, &anonstore.Device{
		DeviceID:  "counted-device",
		ClientIP:  "203.0.113.10",
		UserAgent: "seed",
		CreatedAt: now,
		UpdatedAt: now,
	})
	require.NoError(t, err)

	// A single new device is denied once the cap is full. This is the result
	// the overlapping request must also get.
	err = deviceService.TagDevice(ctx, deviceRequest("sequential-device").HTTPRequest, anonymous.AnonDeviceUI)
	require.ErrorIs(t, err, anonstore.ErrDeviceLimitReached)

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseStore := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseStore)

	realStore := deviceService.anonStore
	gate := &gatingAnonStore{
		AnonStore: realStore,
		entered:   make(chan struct{}),
		release:   release,
	}
	deviceService.anonStore = gate

	client := &Anonymous{
		cfg:               cfg,
		log:               log.NewNopLogger(),
		orgService:        &orgtest.FakeOrgService{ExpectedOrg: anonOrg},
		anonDeviceService: deviceService,
	}

	type authResult struct {
		identity *authn.Identity
		err      error
	}
	firstDone := make(chan authResult, 1)
	secondDone := make(chan authResult, 1)

	go func() {
		identity, authErr := client.Authenticate(ctx, deviceRequest("overlapping-device"))
		firstDone <- authResult{identity: identity, err: authErr}
	}()

	select {
	case <-gate.entered:
	case res := <-firstDone:
		t.Fatalf("first authentication finished before the device insert ran: identity=%v err=%v", res.identity, res.err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the device insert to start")
	}

	go func() {
		identity, authErr := client.Authenticate(ctx, deviceRequest("overlapping-device"))
		secondDone <- authResult{identity: identity, err: authErr}
	}()

	var secondEarly *authResult
	select {
	case res := <-secondDone:
		secondEarly = &res
	case <-time.After(2 * time.Second):
	}

	releaseStore()

	var first authResult
	select {
	case first = <-firstDone:
	case <-time.After(10 * time.Second):
		t.Fatal("first authentication did not finish after the device insert was released")
	}

	var second authResult
	if secondEarly != nil {
		second = *secondEarly
	} else {
		select {
		case second = <-secondDone:
		case <-time.After(10 * time.Second):
			t.Fatal("overlapping authentication did not finish")
		}
	}

	assertDeviceLimitDenied := func(which string, res authResult) {
		t.Helper()
		if res.err == nil {
			id := ""
			role := ""
			if res.identity != nil {
				id = res.identity.GetID()
				role = string(res.identity.GetOrgRole())
			}
			t.Fatalf("%s authentication succeeded while auth.anonymous device_limit was already full: identity=%s role=%s", which, id, role)
		}
		require.ErrorIs(t, res.err, anonstore.ErrDeviceLimitReached)
		require.Nil(t, res.identity)
	}
	assertDeviceLimitDenied("first", first)
	assertDeviceLimitDenied("overlapping", second)

	devices, err := realStore.ListDevices(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	require.Equal(t, "counted-device", devices[0].DeviceID)
}

func deviceRequest(deviceID string) *authn.Request {
	return &authn.Request{
		HTTPRequest: &http.Request{
			RemoteAddr: "203.0.113.50:443",
			Header: http.Header{
				"User-Agent":          []string{"Mozilla/5.0"},
				"X-Forwarded-For":     []string{"203.0.113.50"},
				"X-Grafana-Device-Id": []string{deviceID},
			},
		},
	}
}
