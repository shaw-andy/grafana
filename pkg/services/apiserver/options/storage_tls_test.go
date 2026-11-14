package options

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// ApplyTo and buildGrpcDialOptions are the apiserver dial of the same remote
// resource store. A non-loopback address with no TLS settings must be refused
// before a connection is accepted, and the dial options must not put a resource
// body on the TCP path in the clear. The error has to say "tls" or
// "transport security".

const dialPlaintextMarker = `{"kind":"Dashboard","title":"apiserver-plaintext-create-marker"}`

func TestStorageOptionsApplyToRefusesRemotePlaintext(t *testing.T) {
	host := nonLoopbackHost(t)
	storageLn := listenCount(t, host)
	searchLn := listenCount(t, host)

	opts := &StorageOptions{
		StorageType:                              StorageTypeUnifiedGrpc,
		Address:                                  storageLn.Addr().String(),
		SearchServerAddress:                      searchLn.Addr().String(),
		GrpcClientAuthenticationToken:            "placeholder-token",
		GrpcClientAuthenticationTokenExchangeURL: "http://127.0.0.1:9/token-exchange",
		GrpcClientAuthenticationTokenNamespace:   "stack",
	}
	err := opts.ApplyTo(&genericapiserver.RecommendedConfig{}, &genericoptions.EtcdOptions{}, tracing.InitializeTracerForTest(), nil)
	require.Zero(t, storageLn.n.Load(), "resource store was dialed before plaintext was refused")
	require.Zero(t, searchLn.n.Load(), "search server was dialed before plaintext was refused")
	require.Error(t, err)
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "tls") && !strings.Contains(msg, "transport security") {
		t.Fatalf("refusal error must name tls or transport security, got %v", err)
	}
}

func TestBuildGrpcDialOptionsDoesNotExposeResourceBody(t *testing.T) {
	host := nonLoopbackHost(t)
	backend := startPlainResourceServer(t)
	proxy, tap := startDialProxy(t, host, backend)

	opts := (&StorageOptions{Address: proxy}).buildGrpcDialOptions()
	conn, err := grpc.NewClient(proxy, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = resourcepb.NewResourceStoreClient(conn).Create(ctx, &resourcepb.CreateRequest{Value: []byte(dialPlaintextMarker)})
	raw := tap.snapshot()
	if bytes.Contains(raw, []byte("PRI * HTTP/2.0")) || bytes.Contains(raw, []byte(dialPlaintextMarker)) {
		t.Fatalf("resource create was readable on the TCP path (http2 preface=%v body=%v rpc err=%v)",
			bytes.Contains(raw, []byte("PRI * HTTP/2.0")), bytes.Contains(raw, []byte(dialPlaintextMarker)), err)
	}
}

type dialTape struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (t *dialTape) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.b.Write(p)
}

func (t *dialTape) snapshot() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.b.Bytes()...)
}

type countLn struct {
	net.Listener
	n atomic.Int32
}

func (c *countLn) Accept() (net.Conn, error) {
	conn, err := c.Listener.Accept()
	if err == nil {
		c.n.Add(1)
	}
	return conn, err
}

func listenCount(t *testing.T, host string) *countLn {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	cl := &countLn{Listener: ln}
	go func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return cl
}

func startPlainResourceServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		var req resourcepb.CreateRequest
		if err := stream.RecvMsg(&req); err != nil {
			return err
		}
		return stream.SendMsg(&resourcepb.CreateResponse{})
	}))
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func startDialProxy(t *testing.T, host, backend string) (string, *dialTape) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	tap := &dialTape{}
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				server, dialErr := net.Dial("tcp", backend)
				if dialErr != nil {
					return
				}
				defer server.Close()
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = io.Copy(server, io.TeeReader(c, tap))
					_ = server.Close()
				}()
				go func() {
					defer wg.Done()
					_, _ = io.Copy(c, server)
					_ = c.Close()
				}()
				wg.Wait()
			}(c)
		}
	}()
	return ln.Addr().String(), tap
}

func nonLoopbackHost(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		require.NoError(t, err)
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			probe, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
			if err != nil {
				continue
			}
			_ = probe.Close()
			return ip.String()
		}
	}
	t.Fatal("no non-loopback IPv4 address")
	return ""
}
