package testdatasource

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/live/runstream"
	"github.com/grafana/grafana/pkg/services/user"
)

func TestMain(m *testing.M) {
	if child := os.Getenv("GRAFANA_FLIGHT_PERIOD_CHILD"); child != "" {
		switch child {
		case "live":
			liveFlightPeriodChild()
		case "chunked":
			chunkedFlightPeriodChild()
		case "recover":
			runStreamPanicChild()
		default:
			fmt.Fprintf(os.Stderr, "unknown flight period child %q\n", child)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestFlightResourceRejectsNonPositivePeriod(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{name: "zero", body: `{"period":0}`},
		{name: "negative", body: `{"period":-5}`},
		{name: "subnanosecond", body: `{"period":1e-18}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := ProvideService()
			path := "sim/flight/10hz/" + tc.name

			prime := callResource(t, svc, http.MethodGet, path, nil)
			require.Equal(t, http.StatusOK, prime.status)
			require.InDelta(t, 10, periodFromState(t, prime.body), 0.001)

			updated := callResource(t, svc, http.MethodPost, path, []byte(tc.body))
			require.GreaterOrEqual(t, updated.status, 400)
			require.Less(t, updated.status, 500)

			again := callResource(t, svc, http.MethodGet, path, nil)
			require.Equal(t, http.StatusOK, again.status)
			require.InDelta(t, 10, periodFromState(t, again.body), 0.001)

			mustNotPanic(t, func() {
				resp, err := svc.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{Path: path})
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, backend.SubscribeStreamStatusOK, resp.Status)
			})
		})
	}
}

func TestFlightQueryConfigDoesNotInstallNonPositivePeriod(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		queryType string
		config    string
		wantError bool
	}{
		{name: "typed-zero", queryType: "simulation", config: `{"period":0}`, wantError: true},
		{name: "typed-negative", queryType: "simulation", config: `{"period":-5}`, wantError: true},
		{name: "typed-subnanosecond", queryType: "simulation", config: `{"period":1e-18}`, wantError: true},
		{name: "fallback-zero", queryType: "", config: `{"period":0}`},
		{name: "fallback-negative", queryType: "", config: `{"period":-5}`},
		{name: "fallback-subnanosecond", queryType: "", config: `{"period":1e-18}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := ProvideService()
			raw := []byte(fmt.Sprintf(
				`{"scenarioId":"simulation","sim":{"key":{"type":"flight","tick":10,"uid":%q},"config":%s,"last":true}}`,
				tc.name, tc.config,
			))
			req := &backend.QueryDataRequest{
				Queries: []backend.DataQuery{{
					RefID:     "A",
					QueryType: tc.queryType,
					TimeRange: backend.TimeRange{
						From: time.Now().Add(-time.Minute),
						To:   time.Now(),
					},
					JSON: raw,
				}},
			}

			var queryErr error
			mustNotPanic(t, func() {
				_, queryErr = svc.QueryData(context.Background(), req)
			})
			if tc.wantError {
				require.Error(t, queryErr)
			}
			require.False(t, flightPeriodPanics(storedFlightPeriod(t, svc, tc.name)))

			mustNotPanic(t, func() {
				resp, err := svc.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{
					Path: "sim/flight/10hz/" + tc.name,
				})
				require.NoError(t, err)
				require.Equal(t, backend.SubscribeStreamStatusOK, resp.Status)
			})
		})
	}
}

func TestLiveFlightPeriodZeroDoesNotKillProcess(t *testing.T) {
	out, err := runFlightChild(t, "live")
	require.NoErrorf(t, err, "live flight stream exited the process:\n%s", out)
}

func TestChunkedFlightPeriodZeroDoesNotKillProcess(t *testing.T) {
	out, err := runFlightChild(t, "chunked")
	require.NoErrorf(t, err, "chunked flight query exited the process:\n%s", out)
}

func TestRunStreamPanicDoesNotKillProcess(t *testing.T) {
	out, err := runFlightChild(t, "recover")
	require.NoErrorf(t, err, "runStream did not recover a plugin panic:\n%s", out)
}

func runFlightChild(t *testing.T, kind string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "GRAFANA_FLIGHT_PERIOD_CHILD="+kind)
	return cmd.CombinedOutput()
}

func liveFlightPeriodChild() {
	svc := ProvideService()
	path := "sim/flight/10hz/crash"

	sub, err := svc.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{Path: path})
	if err != nil || sub == nil || sub.Status != backend.SubscribeStreamStatusOK {
		fmt.Fprintf(os.Stderr, "subscribe failed before the period change: err=%v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := runstream.NewManager(allowPublisher{}, oneSubscriber{}, staticPluginContext{})
	go func() {
		_ = manager.Run(ctx)
	}()

	pCtx := backend.PluginContext{
		OrgID:    1,
		PluginID: "grafana-testdata-datasource",
		DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
			UID: "testdata",
		},
	}
	_, err = manager.SubmitStream(context.Background(), &user.SignedInUser{
		UserID:  2,
		OrgID:   1,
		OrgRole: identity.RoleViewer,
	}, "ds/testdata/sim/flight/10hz/crash", path, nil, pCtx, svc, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "submit stream: %v\n", err)
		os.Exit(1)
	}

	// Let the stream arm, then apply the posted period the next tick reads.
	// The wait after the post is long enough for a 10Hz tick. A zero period
	// panics that goroutine and exits the process before the checks below.
	time.Sleep(50 * time.Millisecond)
	updated := callResource(nil, svc, http.MethodPost, path, []byte(`{"period":0}`))
	time.Sleep(300 * time.Millisecond)
	if updated.status < 400 || updated.status >= 500 {
		fmt.Fprintf(os.Stderr, "period 0 was not refused: status=%d body=%s\n", updated.status, updated.body)
		os.Exit(1)
	}

	if period := storedFlightPeriod(nil, svc, "crash"); period != 10 {
		fmt.Fprintf(os.Stderr, "running flight period changed to %v\n", period)
		os.Exit(1)
	}
}

func chunkedFlightPeriodChild() {
	svc := ProvideService()
	writer := &captureChunkWriter{}

	raw := []byte(`{"scenarioId":"simulation","sim":{"key":{"type":"flight","tick":10,"uid":"chunk-fallback"},"config":{"period":0},"last":true}}`)
	err := svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
		Queries: []backend.DataQuery{{
			RefID: "A",
			TimeRange: backend.TimeRange{
				From: time.Now().Add(-time.Minute),
				To:   time.Now(),
			},
			JSON: raw,
		}},
	}, writer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fallback chunked query: %v\n", err)
		os.Exit(1)
	}
	if flightPeriodPanics(storedFlightPeriod(nil, svc, "chunk-fallback")) {
		fmt.Fprintf(os.Stderr, "fallback chunked query stored a flight period that divides by zero\n")
		os.Exit(1)
	}

	raw = []byte(`{"sim":{"key":{"type":"flight","tick":10,"uid":"chunk-typed"},"config":{"period":1e-18},"last":true}}`)
	err = svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
		Queries: []backend.DataQuery{{
			RefID:     "A",
			QueryType: "simulation",
			TimeRange: backend.TimeRange{
				From: time.Now().Add(-time.Minute),
				To:   time.Now(),
			},
			JSON: raw,
		}},
	}, writer)
	if err == nil {
		fmt.Fprintf(os.Stderr, "typed chunked query accepted a sub-nanosecond period\n")
		os.Exit(1)
	}
	if flightPeriodPanics(storedFlightPeriod(nil, svc, "chunk-typed")) {
		fmt.Fprintf(os.Stderr, "typed chunked query stored a flight period that divides by zero\n")
		os.Exit(1)
	}
}

func runStreamPanicChild() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := runstream.NewManager(allowPublisher{}, oneSubscriber{}, staticPluginContext{})
	go func() {
		_ = manager.Run(ctx)
	}()

	_, err := manager.SubmitStream(context.Background(), &user.SignedInUser{
		UserID:  2,
		OrgID:   1,
		OrgRole: identity.RoleViewer,
	}, "ds/testdata/sim/panic", "sim/panic", nil, backend.PluginContext{
		OrgID:    1,
		PluginID: "grafana-testdata-datasource",
	}, panickingRunner{}, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "submit panicking stream: %v\n", err)
		os.Exit(1)
	}
	time.Sleep(200 * time.Millisecond)
}

type resourceResult struct {
	status int
	body   []byte
}

func callResource(t *testing.T, svc *Service, method, path string, body []byte) resourceResult {
	if t != nil {
		t.Helper()
	}
	var result resourceResult
	err := svc.CallResource(context.Background(), &backend.CallResourceRequest{
		PluginContext: backend.PluginContext{PluginID: "grafana-testdata-datasource"},
		Path:          path,
		Method:        method,
		URL:           path,
		Body:          body,
	}, backend.CallResourceResponseSenderFunc(func(resp *backend.CallResourceResponse) error {
		if resp.Status != 0 {
			result.status = resp.Status
		}
		result.body = append(result.body, resp.Body...)
		return nil
	}))
	if err != nil {
		if t != nil {
			require.NoError(t, err)
		}
		fmt.Fprintf(os.Stderr, "call resource: %v\n", err)
		os.Exit(1)
	}
	return result
}

func periodFromState(t *testing.T, body []byte) float64 {
	t.Helper()
	period, err := periodInState(body)
	require.NoError(t, err)
	return period
}

func storedFlightPeriod(t *testing.T, svc *Service, uid string) float64 {
	if t != nil {
		t.Helper()
	}
	resp := callResource(t, svc, http.MethodGet, "sim/flight/10hz/"+uid, nil)
	period, err := periodInState(resp.body)
	if err != nil {
		if t != nil {
			require.NoError(t, err)
		}
		fmt.Fprintf(os.Stderr, "flight state: %v body=%s\n", err, resp.body)
		os.Exit(1)
	}
	return period
}

func periodInState(body []byte) (float64, error) {
	var state struct {
		Config struct {
			Period float64 `json:"period"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return 0, err
	}
	return state.Config.Period, nil
}

// flightPeriodPanics reports whether getNextPoint would use this period as a
// zero divisor. The value that is checked has to be that divisor: a period
// that is merely greater than zero can still truncate to zero nanoseconds.
func flightPeriodPanics(period float64) bool {
	if math.IsNaN(period) || math.IsInf(period, 0) {
		return true
	}
	return int64(period*float64(time.Second)) <= 0
}

func mustNotPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("panic: %v", recovered)
		}
	}()
	fn()
}

type allowPublisher struct{}

func (allowPublisher) PublishLocal(string, []byte) error { return nil }

type oneSubscriber struct{}

func (oneSubscriber) GetNumLocalSubscribers(string) (int, error) { return 1, nil }

type staticPluginContext struct{}

func (staticPluginContext) GetPluginContext(context.Context, identity.Requester, string, string, bool) (backend.PluginContext, error) {
	return backend.PluginContext{OrgID: 1, PluginID: "grafana-testdata-datasource"}, nil
}

type panickingRunner struct{}

func (panickingRunner) RunStream(context.Context, *backend.RunStreamRequest, *backend.StreamSender) error {
	panic("flight stream panic")
}

type captureChunkWriter struct{}

func (captureChunkWriter) WriteFrame(context.Context, string, string, *data.Frame) error {
	return nil
}

func (captureChunkWriter) WriteError(context.Context, string, backend.Status, error) error {
	return nil
}
