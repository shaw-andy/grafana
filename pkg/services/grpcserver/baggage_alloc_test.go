package grpcserver

import (
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/grpcserver/interceptors"
	"github.com/grafana/grafana/pkg/setting"
)

const maxDenseBaggageAllocDelta = 128 * 1024

func TestGRPCDenseBaggageAllocation(t *testing.T) {
	prev := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })
	tracer := tracing.NewNoopTracerService()
	header := denseBaggageHeader()
	require.Equal(t, 8191, len(header))

	t.Run("unauthenticated health check", func(t *testing.T) {
		member, code, delta := callHealth(t, tracer, header)
		require.Equal(t, "v", member)
		require.Equal(t, codes.OK, code)
		require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
			"public grpc health check allocated %d extra bytes parsing baggage", delta)
	})

	t.Run("auth rejection happens after extract", func(t *testing.T) {
		var seen string
		auth := interceptors.AuthenticatorFunc(func(ctx context.Context) (context.Context, error) {
			seen = baggage.FromContext(ctx).Member("namespace").Value()
			return ctx, status.Error(codes.Unauthenticated, "rejected")
		})
		code, delta := callStockHealth(t, tracer, auth, header)
		require.Equal(t, codes.Unauthenticated, code)
		require.Equal(t, "v", seen, "baggage was extracted before authentication rejected the call")
		require.LessOrEqualf(t, delta, int64(maxDenseBaggageAllocDelta),
			"rejected grpc call allocated %d extra bytes parsing baggage", delta)
	})
}

type observingHealth struct {
	*HealthService
	member string
}

func (s *observingHealth) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	s.member = baggage.FromContext(ctx).Member("namespace").Value()
	return s.HealthService.Check(ctx, req)
}

func callHealth(t *testing.T, tracer tracing.Tracer, header string) (string, codes.Code, int64) {
	t.Helper()

	lis := listenLocal(t)
	svc := newTestServer(t, lis, tracer, interceptors.AuthenticatorFunc(func(ctx context.Context) (context.Context, error) {
		return ctx, status.Error(codes.Unauthenticated, "rejected")
	}))
	healthSvc := &observingHealth{HealthService: newHealthService()}
	healthSvc.setServingStatus("grafana", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(svc.GetServer(), healthSvc)
	serve(t, svc)

	conn := dial(t, lis.Addr().String())
	client := grpc_health_v1.NewHealthClient(conn)
	call := func(baggageHeader string) codes.Code {
		ctx := metadata.AppendToOutgoingContext(context.Background(), "baggage", baggageHeader)
		_, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "grafana"})
		return status.Code(err)
	}

	require.Equal(t, codes.OK, call("namespace=v"))
	require.Equal(t, "v", healthSvc.member)
	code := call(header)
	delta := allocDelta(func() { call("namespace=v") }, func() { call(header) })
	return healthSvc.member, code, delta
}

func callStockHealth(t *testing.T, tracer tracing.Tracer, auth interceptors.Authenticator, header string) (codes.Code, int64) {
	t.Helper()

	lis := listenLocal(t)
	svc := newTestServer(t, lis, tracer, auth)
	// stockHealth has no AuthFuncOverride, so the server authenticator runs.
	grpc_health_v1.RegisterHealthServer(svc.GetServer(), &stockHealth{})
	serve(t, svc)

	conn := dial(t, lis.Addr().String())
	client := grpc_health_v1.NewHealthClient(conn)
	call := func(baggageHeader string) codes.Code {
		ctx := metadata.AppendToOutgoingContext(context.Background(), "baggage", baggageHeader)
		_, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		return status.Code(err)
	}

	require.Equal(t, codes.Unauthenticated, call("namespace=v"))
	code := call(header)
	delta := allocDelta(func() { call("namespace=v") }, func() { call(header) })
	return code, delta
}

// stockHealth embeds the generated health server without AuthFuncOverride so
// the process-wide authenticator runs.
type stockHealth struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (stockHealth) Check(context.Context, *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func newTestServer(t *testing.T, lis net.Listener, tracer tracing.Tracer, auth interceptors.Authenticator) *gPRCServerService {
	t.Helper()

	cfg := &setting.Cfg{}
	cfg.GRPCServer.Network = "tcp"
	cfg.GRPCServer.Address = lis.Addr().String()
	cfg.GRPCServer.Enabled = true
	cfg.GRPCServer.GracefulShutdownTimeout = 2 * time.Second

	svc, err := provideService(cfg, auth, tracer, prometheus.NewRegistry(), false, lis)
	require.NoError(t, err)
	return svc
}

func serve(t *testing.T, svc *gPRCServerService) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Run(ctx)
	}()
	select {
	case <-svc.startedChan:
	case err := <-errCh:
		t.Fatalf("grpc server stopped before accepting: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("grpc server did not start")
	}
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	return lis
}

func dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func denseBaggageHeader() string {
	const want = 8191
	prefix := "namespace=v"
	prop := ";a"
	n := (want - len(prefix)) / len(prop)
	header := prefix + strings.Repeat(prop, n)
	if len(header) != want {
		panic("dense baggage header has unexpected length")
	}
	return header
}

func allocDelta(small, dense func()) int64 {
	small()
	dense()
	return int64(minAllocated(3, dense)) - int64(minAllocated(3, small))
}

func minAllocated(n int, fn func()) uint64 {
	var min uint64
	for i := range n {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		delta := after.TotalAlloc - before.TotalAlloc
		if i == 0 || delta < min {
			min = delta
		}
	}
	return min
}
