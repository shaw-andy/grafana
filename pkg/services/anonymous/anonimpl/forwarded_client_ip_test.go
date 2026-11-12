package anonimpl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/anonymous/validator"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/setting"
)

func TestAnonymousDeviceRecordsTCPPeerNotForwardingHeader(t *testing.T) {
	const (
		peerAddr = "203.0.113.10:4242"
		peerIP   = "203.0.113.10"
		orgName  = "Main Org."
	)

	sqlStore := db.NewTestStore(t)
	cfg := setting.NewCfg()
	cfg.Anonymous.Enabled = true
	cfg.Anonymous.OrgName = orgName
	cfg.Anonymous.OrgRole = "Viewer"

	orgService := orgtest.NewOrgServiceFake()
	orgService.ExpectedOrg = &org.Org{ID: 1, Name: orgName}

	deviceService := ProvideAnonymousDeviceService(
		&usagestats.UsageStatsMock{},
		&authntest.FakeService{},
		sqlStore,
		cfg,
		orgService,
		nil,
		actest.FakeAccessControl{},
		&routing.RouteRegisterImpl{},
		validator.FakeAnonUserLimitValidator{},
	)
	client := &Anonymous{
		cfg:               cfg,
		log:               deviceService.log,
		orgService:        orgService,
		anonDeviceService: deviceService,
	}

	cases := []struct {
		name         string
		deviceID     string
		realIP       string
		forwardedFor string
	}{
		{name: "X-Real-IP", deviceID: "device-real-ip", realIP: "198.51.100.9", forwardedFor: "198.51.100.8"},
		{name: "X-Forwarded-For", deviceID: "device-forwarded-for", forwardedFor: "198.51.100.7, 198.51.100.70"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = peerAddr
			req.Header.Set("User-Agent", "anon-test")
			req.Header.Set(deviceIDHeader, tc.deviceID)
			if tc.realIP != "" {
				req.Header.Set("X-Real-IP", tc.realIP)
			}
			if tc.forwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tc.forwardedFor)
			}

			identity, err := client.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
			require.NoError(t, err)
			require.NotNil(t, identity)

			devices, err := deviceService.ListDevices(context.Background(), nil, nil)
			require.NoError(t, err)

			var matched bool
			for _, device := range devices {
				if device.DeviceID != tc.deviceID {
					continue
				}
				matched = true
				require.Equal(t, peerIP, device.ClientIP)
			}
			require.True(t, matched, "device %s was not recorded", tc.deviceID)
		})
	}
}
