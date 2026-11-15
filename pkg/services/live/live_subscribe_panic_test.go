package live

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource/sims"
	"github.com/stretchr/testify/require"
)

func TestLiveSubscribeWorkerSurvivesPoisonedSine(t *testing.T) {
	if os.Getenv("LIVE_SINE_PANIC_CHILD") == "1" {
		runPoisonedSineOnSubscribeWorker()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLiveSubscribeWorkerSurvivesPoisonedSine$", "-test.count=1")
	cmd.Env = append(os.Environ(), "LIVE_SINE_PANIC_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Grafana Live subscribe worker exited the process:\n%s\n%v", out, err)
	}
}

// runPoisonedSineOnSubscribeWorker follows the attack after the query has been
// recovered by HTTP middleware: the sine instance is already stored, and
// SubscribeStream runs on the live client worker (concurrency 12), which does
// not recover.
func runPoisonedSineOnSubscribeWorker() {
	engine, err := sims.NewSimulationEngine()
	if err != nil {
		panic(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	func() {
		defer func() { _ = recover() }()
		_, _ = engine.QueryData(context.Background(), &backend.QueryDataRequest{
			Queries: []backend.DataQuery{{
				RefID: "A",
				TimeRange: backend.TimeRange{
					From: now.Add(-time.Minute),
					To:   now,
				},
				Interval: time.Second,
				JSON:     []byte(`{"sim":{"key":{"type":"sine","tick":10,"uid":"live"},"config":{"period":0.0001},"last":true}}`),
			}},
		})
	}()

	semaphore := make(chan struct{}, clientConcurrency)
	err = runConcurrentlyIfNeeded(context.Background(), semaphore, func() {
		_, _ = engine.SubscribeStream(context.Background(), &backend.SubscribeStreamRequest{
			Path: "sim/sine/10hz/live",
		})
	})
	if err != nil {
		panic(err)
	}
	time.Sleep(300 * time.Millisecond)
}

func TestRunStreamManagerDoesNotExitOnSinePanic(t *testing.T) {
	if os.Getenv("LIVE_SINE_RUN_CHILD") == "1" {
		engine, err := sims.NewSimulationEngine()
		if err != nil {
			panic(err)
		}
		now := time.Unix(1_700_000_000, 0).UTC()
		func() {
			defer func() { _ = recover() }()
			_, _ = engine.QueryData(context.Background(), &backend.QueryDataRequest{
				Queries: []backend.DataQuery{{
					RefID: "A",
					TimeRange: backend.TimeRange{
						From: now.Add(-time.Minute),
						To:   now,
					},
					Interval: time.Second,
					JSON:     []byte(`{"sim":{"key":{"type":"sine","tick":10,"uid":"run"},"config":{"period":0.0001},"last":true}}`),
				}},
			})
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = engine.RunStream(ctx, &backend.RunStreamRequest{Path: "sim/sine/10hz/run"}, backend.NewStreamSender(nopPacketSender{}))
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestRunStreamManagerDoesNotExitOnSinePanic$", "-test.count=1")
	cmd.Env = append(os.Environ(), "LIVE_SINE_RUN_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("simulation RunStream exited the process:\n%s\n%v", out, err)
	}
}

type nopPacketSender struct{}

func (nopPacketSender) Send(*backend.StreamPacket) error { return nil }

func TestClientConcurrencyStartsAGoroutine(t *testing.T) {
	require.Greater(t, clientConcurrency, 1)
}
