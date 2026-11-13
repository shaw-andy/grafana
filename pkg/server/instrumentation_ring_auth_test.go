package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/grafana/dskit/kv"
	"github.com/grafana/dskit/ring"
	"github.com/grafana/dskit/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/modules"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/grpcserver"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resource"
	"github.com/grafana/grafana/pkg/storage/unified/sql"
)

// notACredential is an obvious placeholder. It is not a configured Grafana
// credential and must not be treated as one.
const notACredential = "Bearer placeholder-not-a-credential"

// ringControlBackend satisfies the storage backend dependency of the sharded
// storage and search services without opening a database. The ring-control
// HTTP handlers do not call it.
type ringControlBackend struct {
	resource.UnimplementedStorageBackend
}

func (ringControlBackend) GetResourceStatsWithLimit(context.Context, resource.NamespacedResource, int, int) ([]resource.ResourceStats, error) {
	return nil, nil
}

// TestShardedModuleInstrumentationRejectsUnauthenticatedRingControl exercises the
// instrumentation HTTP server that storage-server and search-server start when
// unified storage sharding is enabled. Unauthenticated requests must not change
// ring lifecycle state, must not remove a ring member, and must be rejected.
//
// /metrics, /livez, and /readyz are left unchecked: the instrumentation server
// already serves them without credentials, and that is covered separately from
// ring control. The search-server-distributor target mounts the same /ring and
// /memberlist handlers through initSearchServerRing and initMemberlistKV.
func TestShardedModuleInstrumentationRejectsUnauthenticatedRingControl(t *testing.T) {
	for _, target := range []string{modules.StorageServer, modules.SearchServer} {
		t.Run(target, func(t *testing.T) {
			fx := startShardedInstrumentation(t, target)
			assertPrepareDownscaleRejected(t, fx)
			fx.startService(t)
			assertPrepareDownscaleRejected(t, fx)
			assertRingControlRejected(t, fx)
			assertMemberlistControlRejected(t, fx)

			// One unauthenticated POST, with no test reset after it, then the
			// shutdown the attack relies on. The instance must stay registered.
			setLifecyclerKeep(t, fx.svc, true)
			resp := fx.request(t, http.MethodPost, "/prepare-downscale", "", nil)
			if !lifecyclerKeepsInstance(t, fx.svc) {
				t.Errorf("POST /prepare-downscale cleared keep-in-ring (status %d)", resp.StatusCode)
			}
			requireAuthRejection(t, resp)
			fx.stopService(t)
			if !fx.ringHas(t, fx.instanceID) {
				t.Errorf("instance %s left the ring on shutdown after unauthenticated POST /prepare-downscale", fx.instanceID)
			}
		})
	}
}

type shardedFixture struct {
	baseURL    string
	client     *http.Client
	svc        services.Service
	ringKV     kv.Client
	instanceID string
	started    bool
	ms         *ModuleServer
	instr      *instrumentationService
	memberlist services.Service
	ringSvc    services.Service
}

func startShardedInstrumentation(t *testing.T, target string) *shardedFixture {
	t.Helper()

	httpPort := getRandomPort()
	memberlistPort := getRandomPort()
	instanceID := target + "-under-test"

	reg := prometheus.NewRegistry()
	cfg := setting.NewCfg()
	cfg.Target = []string{target}
	cfg.HTTPAddr = "127.0.0.1"
	cfg.HTTPPort = strconv.Itoa(httpPort)
	cfg.GRPCServer.Network = "tcp"
	cfg.GRPCServer.Address = "127.0.0.1:" + strconv.Itoa(getRandomPort())
	cfg.EnableSharding = true
	cfg.SearchRingReplicationFactor = 1
	cfg.InstanceID = instanceID
	cfg.MemberlistBindAddr = "127.0.0.1"
	cfg.MemberlistAdvertiseAddr = "127.0.0.1"
	cfg.MemberlistAdvertisePort = memberlistPort
	cfg.MemberlistJoinMember = "127.0.0.1:" + strconv.Itoa(memberlistPort)
	cfg.ResourceServerJoinRingTimeout = 30 * time.Second
	cfg.DataPath = t.TempDir()
	cfg.IndexPath = t.TempDir()
	cfg.IndexFileThreshold = 1000
	cfg.IndexWorkers = 1
	cfg.IndexRebuildWorkers = 1

	logger := log.New("instrumentation-ring-auth-test")
	ms := &ModuleServer{
		log:          logger,
		cfg:          cfg,
		features:     featuremgmt.WithFeatures(),
		registerer:   reg,
		promGatherer: reg,
	}

	instr, err := ms.initInstrumentationServer()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, services.StartAndAwaitRunning(ctx, instr))

	memberlistSvc, err := ms.initMemberlistKV()
	require.NoError(t, err)
	require.NoError(t, services.StartAndAwaitRunning(ctx, memberlistSvc))

	ringSvc, err := ms.initSearchServerRing()
	require.NoError(t, err)
	require.NotNil(t, ringSvc)
	require.NoError(t, services.StartAndAwaitRunning(ctx, ringSvc))

	grpcSvc, err := grpcserver.ProvideDSKitService(cfg, otel.Tracer("instrumentation-ring-auth-test"), reg, modules.GRPCServer)
	require.NoError(t, err)
	ms.grpcService = grpcSvc

	backend := ringControlBackend{}
	var svc services.Service
	switch target {
	case modules.StorageServer:
		cfg.EnableSearch = false
		svc, err = sql.ProvideUnifiedStorageGrpcService(
			cfg, ms.features, logger, reg,
			nil, resource.ProvideStorageMetrics(reg), nil, nil,
			ms.searchServerRing, ms.MemberlistKVConfig, ms.httpServerRouter,
			backend, nil, nil, nil, nil, grpcSvc,
		)
	case modules.SearchServer:
		cfg.EnableSearch = true
		svc, err = sql.ProvideSearchGRPCService(
			cfg, ms.features, logger, reg,
			&resource.TestDocumentBuilderSupplier{GroupsResources: map[string]string{
				"playlist.grafana.app": "playlists",
			}},
			resource.ProvideIndexMetrics(reg), nil,
			ms.searchServerRing, ms.MemberlistKVConfig, ms.httpServerRouter,
			backend, nil, nil, nil, grpcSvc,
		)
	default:
		t.Fatalf("unsupported target %s", target)
	}
	require.NoError(t, err)

	ringKV, err := kv.NewClient(ms.MemberlistKVConfig, ring.GetCodec(), nil, logger)
	require.NoError(t, err)

	fx := &shardedFixture{
		baseURL:    "http://127.0.0.1:" + strconv.Itoa(httpPort),
		client:     &http.Client{Timeout: 5 * time.Second, CheckRedirect: refuseRedirect},
		svc:        svc,
		ringKV:     ringKV,
		instanceID: instanceID,
		ms:         ms,
		instr:      instr,
		memberlist: memberlistSvc,
		ringSvc:    ringSvc,
	}
	waitForHTTP(t, fx)
	// Startup keeps the instance in the ring across shutdown until a
	// prepare-downscale request says otherwise.
	require.True(t, lifecyclerKeepsInstance(t, svc))

	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopCancel()
		if fx.started {
			_ = services.StopAndAwaitTerminated(stopCtx, fx.svc)
		}
		if fx.ms.searchServerRing != nil {
			fx.ms.searchServerRing.StopAsync()
			_ = fx.ms.searchServerRing.AwaitTerminated(stopCtx)
		}
		if fx.ms.searchServerRingClientPool != nil {
			_ = services.StopAndAwaitTerminated(stopCtx, fx.ms.searchServerRingClientPool)
		}
		_ = services.StopAndAwaitTerminated(stopCtx, fx.ringSvc)
		_ = services.StopAndAwaitTerminated(stopCtx, fx.memberlist)
		_ = services.StopAndAwaitTerminated(stopCtx, fx.instr)
	})
	return fx
}

func (fx *shardedFixture) startService(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	require.NoError(t, services.StartAndAwaitRunning(ctx, fx.svc))
	fx.started = true
	require.Eventually(t, func() bool {
		return fx.ringHas(t, fx.instanceID)
	}, 20*time.Second, 200*time.Millisecond)
}

func (fx *shardedFixture) stopService(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, services.StopAndAwaitTerminated(ctx, fx.svc))
	fx.started = false
}

func assertPrepareDownscaleRejected(t *testing.T, fx *shardedFixture) {
	t.Helper()
	for _, header := range []string{"", notACredential} {
		setLifecyclerKeep(t, fx.svc, true)
		resp := fx.request(t, http.MethodPost, "/prepare-downscale", header, nil)
		if lifecyclerKeepsInstance(t, fx.svc) == false {
			t.Errorf("POST /prepare-downscale with Authorization %q cleared keep-in-ring (status %d, body %s)",
				header, resp.StatusCode, resp.body)
		}
		requireAuthRejection(t, resp)

		// DELETE is the inverse write. Startup leaves the flag true, so force
		// it false first; otherwise a handler that sets it true is invisible.
		setLifecyclerKeep(t, fx.svc, false)
		resp = fx.request(t, http.MethodDelete, "/prepare-downscale", header, nil)
		if lifecyclerKeepsInstance(t, fx.svc) {
			t.Errorf("DELETE /prepare-downscale with Authorization %q set keep-in-ring (status %d, body %s)",
				header, resp.StatusCode, resp.body)
		}
		requireAuthRejection(t, resp)

		setLifecyclerKeep(t, fx.svc, true)
		resp = fx.request(t, http.MethodGet, "/prepare-downscale", header, nil)
		if !lifecyclerKeepsInstance(t, fx.svc) {
			t.Errorf("GET /prepare-downscale with Authorization %q changed keep-in-ring", header)
		}
		requireAuthRejection(t, resp)
	}
}

func assertRingControlRejected(t *testing.T, fx *shardedFixture) {
	t.Helper()
	// Seed every victim before the first forget. Re-adding an id that was just
	// removed is invisible to the ring merge until its timestamp moves.
	victims := []string{"victim-no-header", "victim-placeholder-header"}
	require.NoError(t, fx.ringKV.CAS(context.Background(), resource.RingKey, func(in interface{}) (interface{}, bool, error) {
		desc := ring.GetOrCreateRingDesc(in)
		for i, id := range victims {
			desc.AddIngester(id, "127.0.0.1:1", "", []uint32{uint32(100 + i)}, ring.ACTIVE, time.Now(), false, time.Time{}, nil)
		}
		return desc, false, nil
	}))
	require.Eventually(t, func() bool {
		return fx.ringHas(t, victims[0]) && fx.ringHas(t, victims[1])
	}, 10*time.Second, 100*time.Millisecond)

	for i, header := range []string{"", notACredential} {
		victim := victims[i]
		resp := fx.request(t, http.MethodGet, "/ring", header, nil)
		requireAuthRejection(t, resp)
		if strings.Contains(resp.body, victim) || strings.Contains(resp.body, fx.instanceID) {
			t.Errorf("GET /ring with Authorization %q returned ring membership (status %d)", header, resp.StatusCode)
		}

		form := url.Values{}
		form.Set("forget", victim)
		resp = fx.request(t, http.MethodPost, "/ring", header, []byte(form.Encode()))
		requireAuthRejection(t, resp)
		if !fx.ringHas(t, victim) {
			t.Errorf("POST /ring forget=%s with Authorization %q removed the instance (status %d)",
				victim, header, resp.StatusCode)
		}
		if !fx.ringHas(t, fx.instanceID) {
			t.Errorf("POST /ring removed %s", fx.instanceID)
		}
	}
}

func assertMemberlistControlRejected(t *testing.T, fx *shardedFixture) {
	t.Helper()
	for _, header := range []string{"", notACredential} {
		resp := fx.request(t, http.MethodGet, "/memberlist", header, nil)
		requireAuthRejection(t, resp)
		if strings.Contains(resp.body, resource.RingKey) {
			t.Errorf("GET /memberlist with Authorization %q exposed the ring KV key (status %d)", header, resp.StatusCode)
		}

		// Same handler serves the ring value and its raw bytes from the query string.
		resp = fx.request(t, http.MethodGet, "/memberlist?viewKey="+resource.RingKey+"&format=json", header, nil)
		requireAuthRejection(t, resp)
		if strings.Contains(resp.body, fx.instanceID) {
			t.Errorf("GET /memberlist viewKey with Authorization %q returned the ring value (status %d)", header, resp.StatusCode)
		}
		resp = fx.request(t, http.MethodGet, "/memberlist?downloadKey="+resource.RingKey, header, nil)
		requireAuthRejection(t, resp)

		resp = fx.request(t, http.MethodGet, "/memberlist?deleteMessages=true", header, nil)
		requireAuthRejection(t, resp)
		if resp.StatusCode == http.StatusFound {
			t.Errorf("GET /memberlist?deleteMessages=true with Authorization %q cleared message history", header)
		}

		form := url.Values{}
		form.Set("deleteMessages", "true")
		resp = fx.request(t, http.MethodPost, "/memberlist", header, []byte(form.Encode()))
		requireAuthRejection(t, resp)
		if resp.StatusCode == http.StatusFound {
			t.Errorf("POST /memberlist deleteMessages=true with Authorization %q cleared message history", header)
		}
	}
}

type recordedResponse struct {
	StatusCode int
	body       string
}

func (fx *shardedFixture) request(t *testing.T, method, path, authorization string, body []byte) recordedResponse {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, fx.baseURL+path, reader)
	require.NoError(t, err)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := fx.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	return recordedResponse{StatusCode: resp.StatusCode, body: string(payload)}
}

func requireAuthRejection(t *testing.T, resp recordedResponse) {
	t.Helper()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("unauthenticated ring-control request returned %d, want 401 or 403; body: %s", resp.StatusCode, truncate(resp.body, 180))
	}
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func waitForHTTP(t *testing.T, fx *shardedFixture) {
	t.Helper()
	require.Eventually(t, func() bool {
		resp, err := fx.client.Get(fx.baseURL + "/metrics")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	}, 5*time.Second, 50*time.Millisecond)
}

func (fx *shardedFixture) ringHas(t *testing.T, id string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	val, err := fx.ringKV.Get(ctx, resource.RingKey)
	if err != nil || val == nil {
		return false
	}
	desc, ok := val.(*ring.Desc)
	if !ok {
		t.Fatalf("ring value type %T", val)
	}
	_, found := desc.Ingesters[id]
	return found
}

func lifecyclerOf(t *testing.T, svc services.Service) *ring.BasicLifecycler {
	t.Helper()
	rv := reflect.ValueOf(svc)
	require.Equal(t, reflect.Ptr, rv.Kind())
	field := rv.Elem().FieldByName("ringLifecycler")
	require.True(t, field.IsValid(), "ring lifecycler field missing")
	require.False(t, field.IsNil(), "ring lifecycler was not created")
	exported := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	lc, ok := exported.Interface().(*ring.BasicLifecycler)
	require.True(t, ok, "lifecycler type %T", exported.Interface())
	return lc
}

func lifecyclerKeepsInstance(t *testing.T, svc services.Service) bool {
	t.Helper()
	return lifecyclerOf(t, svc).ShouldKeepInstanceInTheRingOnShutdown()
}

func setLifecyclerKeep(t *testing.T, svc services.Service, keep bool) {
	t.Helper()
	lifecyclerOf(t, svc).SetKeepInstanceInTheRingOnShutdown(keep)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
