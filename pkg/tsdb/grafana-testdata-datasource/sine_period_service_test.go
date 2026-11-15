package testdatasource

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"
)

func TestServiceQueryRoutesSubMillisecondSineToARefusal(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	raw := []byte(`{"scenarioId":"simulation","sim":{"key":{"type":"sine","tick":10,"uid":"routed"},"config":{"period":0.0001},"last":true}}`)

	t.Run("query type", func(t *testing.T) {
		svc := ProvideService()
		resp, err := queryService(t, svc, "simulation", raw, now)
		requireRefusedOrPanicFree(t, resp, err)
		requireSubscribeAndRunDoNotPanic(t, svc, "sim/sine/10hz/routed")
	})

	// An empty query type falls through to scenarioId. That handler swallows a
	// returned error, so the observable requirement is that the shared
	// simulation is not left able to crash the next live read.
	t.Run("scenario id fallback", func(t *testing.T) {
		svc := ProvideService()
		resp, err := queryService(t, svc, "", raw, now)
		require.NotNil(t, resp)
		require.NoError(t, err)
		requireSubscribeAndRunDoNotPanic(t, svc, "sim/sine/10hz/routed")
	})
}

func TestSubscribeAfterRecoveredSineQueryDoesNotPanic(t *testing.T) {
	// The HTTP recovery middleware turns the query panic into a 500 and leaves
	// the instance in the process-wide map. The next live subscribe must not
	// panic on that instance.
	svc := ProvideService()
	now := time.Unix(1_700_000_000, 0).UTC()
	func() {
		defer func() { _ = recover() }()
		_, _ = svc.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{{
				RefID:     "A",
				QueryType: "simulation",
				TimeRange: backend.TimeRange{From: now.Add(-time.Minute), To: now},
				Interval:  time.Second,
				JSON:      []byte(`{"scenarioId":"simulation","sim":{"key":{"type":"sine","tick":10,"uid":"poison"},"config":{"period":0.0001},"last":true}}`),
			}},
		})
	}()
	requireSubscribeAndRunDoNotPanic(t, svc, "sim/sine/10hz/poison")
}

func TestChunkedSimulationQueryDoesNotCrashProcess(t *testing.T) {
	if os.Getenv("TESTDATA_CHUNKED_CHILD") == "1" {
		svc := ProvideService()
		now := time.Unix(1_700_000_000, 0).UTC()
		err := svc.QueryChunkedData(context.Background(), &backend.QueryChunkedDataRequest{
			Queries: []backend.DataQuery{{
				RefID:     "A",
				QueryType: "simulation",
				TimeRange: backend.TimeRange{From: now.Add(-time.Minute), To: now},
				Interval:  time.Second,
				JSON:      []byte(`{"sim":{"key":{"type":"sine","tick":10,"uid":"chunked"},"config":{"period":0.0001},"last":true}}`),
			}},
		}, discardChunks{})
		if err != nil {
			t.Log(err)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestChunkedSimulationQueryDoesNotCrashProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "TESTDATA_CHUNKED_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("chunked simulation query crashed the process:\n%s\n%v", out, err)
	}
}

func queryService(t *testing.T, svc *Service, queryType string, raw []byte, now time.Time) (*backend.QueryDataResponse, error) {
	t.Helper()
	var resp *backend.QueryDataResponse
	var err error
	require.NotPanics(t, func() {
		resp, err = svc.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{{
				RefID:     "A",
				QueryType: queryType,
				TimeRange: backend.TimeRange{From: now.Add(-time.Minute), To: now},
				Interval:  time.Second,
				JSON:      raw,
			}},
		})
	})
	return resp, err
}

func requireRefusedOrPanicFree(t *testing.T, resp *backend.QueryDataResponse, err error) {
	t.Helper()
	if err != nil {
		return
	}
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Responses)
	for _, r := range resp.Responses {
		require.Error(t, r.Error)
	}
}

func requireSubscribeAndRunDoNotPanic(t *testing.T, svc *Service, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	require.NotPanics(t, func() {
		_, err := svc.SubscribeStream(ctx, &backend.SubscribeStreamRequest{Path: path})
		require.NoError(t, err)
		err = svc.RunStream(ctx, &backend.RunStreamRequest{Path: path}, backend.NewStreamSender(discardStream{}))
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

type discardStream struct{}

func (discardStream) Send(*backend.StreamPacket) error { return nil }

type discardChunks struct{}

func (discardChunks) WriteFrame(context.Context, string, string, *data.Frame) error { return nil }
func (discardChunks) WriteError(context.Context, string, backend.Status, error) error {
	return nil
}
