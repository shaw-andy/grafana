package nats

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsclient "github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/setting"
)

// placeholderNATSToken is an obvious placeholder. Tests never read a real
// credential; they only check that whatever string is configured as the token
// is the one the embedded server demands.
const placeholderNATSToken = "placeholder-nats-auth"

func TestEmbeddedNATSTokenAuthRejectsUnauthenticatedClients(t *testing.T) {
	for _, listen := range []string{"127.0.0.1", "0.0.0.0"} {
		t.Run(listen, func(t *testing.T) {
			srv, clientURL := startAuthenticatedServer(t, setting.NATSSettings{
				ListenAddress: listen,
				Auth: setting.NATSAuthSettings{
					Mode:  setting.NATSAuthModeToken,
					Token: placeholderNATSToken,
				},
			})

			dialURL := dialableClientURL(t, clientURL)
			subject := "us.watch.v1.folder.grafana.app.default.folders"

			// The configured token is the same credential Grafana's own publisher
			// and subscriber present. A client that presents it can publish and
			// subscribe; that is what a fix has to keep working.
			holder := connectClient(t, dialURL, natsclient.Token(placeholderNATSToken))
			received := make(chan []byte, 1)
			_, err := holder.Subscribe(subject, func(msg *natsclient.Msg) {
				select {
				case received <- append([]byte(nil), msg.Data...):
				default:
				}
			})
			require.NoError(t, err)
			require.NoError(t, holder.Flush())

			require.Eventually(t, func() bool {
				if err := holder.Publish(subject, []byte("from-token-holder")); err != nil {
					return false
				}
				_ = holder.Flush()
				select {
				case got := <-received:
					require.Equal(t, []byte("from-token-holder"), got)
					return true
				case <-time.After(20 * time.Millisecond):
					return false
				}
			}, 5*time.Second, time.Millisecond)

			// Separate subtests so each rejected client is attempted. A failure of
			// one must not skip the others.
			t.Run("no credentials", func(t *testing.T) {
				requireRejectedClient(t, dialURL)
			})
			t.Run("wrong token", func(t *testing.T) {
				requireRejectedClient(t, dialURL, natsclient.Token("placeholder-nats-auth-rejected"))
			})
			// In-process connections use the same server authorization as TCP.
			// Grafana's own clients dial this way, so a missing credential has
			// to be rejected here too, while the configured token still works.
			raw := runningNATS(t, srv)
			t.Run("in-process without token", func(t *testing.T) {
				requireRejectedClient(t, dialURL, natsclient.InProcessServer(raw))
			})
			inProc := connectClient(t, dialURL, natsclient.InProcessServer(raw), natsclient.Token(placeholderNATSToken))
			require.NoError(t, inProc.Publish(subject, []byte("in-process-token")))
			require.NoError(t, inProc.Flush())
		})
	}
}

func TestEmbeddedNATSTokenAuthRejectsUnauthenticatedRoutes(t *testing.T) {
	srv, _ := startAuthenticatedServer(t, setting.NATSSettings{
		ListenAddress: "127.0.0.1",
		Auth: setting.NATSAuthSettings{
			Mode:  setting.NATSAuthModeToken,
			Token: placeholderNATSToken,
		},
	})
	raw := runningNATS(t, srv)
	cluster := raw.ClusterAddr()
	require.NotNil(t, cluster, "embedded server did not open a cluster port")

	// A second server solicits a route with no credentials. The embedded
	// cluster port must not accept it, and a message published on the peer
	// must not cross onto the embedded server.
	peerURL, peer := startRoutePeer(t, "nats://127.0.0.1:"+strconv.Itoa(cluster.Port))
	peerClient := connectClient(t, peerURL)

	embeddedURL := dialableClientURL(t, raw.ClientURL())
	holder := connectClient(t, embeddedURL, natsclient.Token(placeholderNATSToken))
	const subject = "us.watch.v1.folder.grafana.app.default.folders"
	got := make(chan []byte, 4)
	_, err := holder.Subscribe(subject, func(msg *natsclient.Msg) {
		got <- append([]byte(nil), msg.Data...)
	})
	require.NoError(t, err)
	require.NoError(t, holder.Flush())

	var leaked []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		require.NoError(t, peerClient.Publish(subject, []byte("from-unauthenticated-route")))
		_ = peerClient.Flush()
		select {
		case leaked = <-got:
		case <-time.After(20 * time.Millisecond):
		}
		if raw.NumRoutes() > 0 || peer.NumRoutes() > 0 {
			// The route is up. Give one more publish a chance to cross so a
			// formed route that can forward messages fails the test for that too.
			_ = peerClient.Publish(subject, []byte("from-unauthenticated-route"))
			_ = peerClient.Flush()
			select {
			case leaked = <-got:
			case <-time.After(500 * time.Millisecond):
			}
			break
		}
	}
	if len(leaked) > 0 {
		t.Errorf("message published by an unauthenticated cluster peer was delivered: %q", leaked)
	}
	require.Zero(t, raw.NumRoutes(), "unauthenticated route was accepted")
	require.Zero(t, peer.NumRoutes(), "unauthenticated route was accepted")
}

func TestEmbeddedNATSRefusesRoutableListenerWithoutAuth(t *testing.T) {
	for _, listen := range routableListenAddresses(t) {
		t.Run(listen, func(t *testing.T) {
			clientPort := reservePort(t, listen)
			probeAddr := probeAddress(listen)
			accepted := probeAccepts(t, probeAddr, clientPort)

			srv, err := runEmbedded(t, setting.NATSSettings{
				ListenAddress: listen,
				ClientPort:    clientPort,
				Auth:          setting.NATSAuthSettings{Mode: setting.NATSAuthModeNone},
			})
			require.Error(t, err, "auth_mode none must not start a listener on %s", listen)
			require.False(t, accepted(), "a client connected before the server refused to start")
			require.Never(t, func() bool {
				conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(probeAddr, strconv.Itoa(clientPort)), 20*time.Millisecond)
				if dialErr != nil {
					return false
				}
				conn.Close()
				return true
			}, 200*time.Millisecond, 10*time.Millisecond)
			require.Error(t, srv.Health(context.Background()))
		})
	}
}

func TestEmbeddedNATSRefusesRoutableAdvertisementWithoutAuth(t *testing.T) {
	const advertised = "10.1.2.3"
	srv, err := runEmbedded(t, setting.NATSSettings{
		ListenAddress:    "127.0.0.1",
		AdvertiseAddress: advertised,
		Auth:             setting.NATSAuthSettings{Mode: setting.NATSAuthModeNone},
	})
	if err != nil {
		require.Error(t, srv.Health(context.Background()))
		return
	}
	raw := runningNATS(t, srv)
	require.True(t, isLoopbackRouteURL(routeURLForServer(srv.cfg, raw)),
		"auth_mode none advertised a routable route url")
}

func TestEmbeddedNATSLoopbackWithoutAuthStillServesLocalClients(t *testing.T) {
	srv, clientURL := startAuthenticatedServer(t, setting.NATSSettings{
		ListenAddress: "127.0.0.1",
		Auth:          setting.NATSAuthSettings{Mode: setting.NATSAuthModeNone},
	})
	require.NoError(t, srv.Health(context.Background()))
	nc := connectClient(t, dialableClientURL(t, clientURL))
	require.NoError(t, nc.Publish("us.watch.v1.folder.grafana.app.default.folders", []byte("local")))
	require.NoError(t, nc.Flush())
}

func TestEmbeddedNATSCredentialsModeRejectsClientsWithoutCredentials(t *testing.T) {
	// auth_mode credentials is how Grafana's own clients identify themselves.
	// The embedded server has to demand that identity. Refusing to listen is
	// also a pass: a client that never gets a port cannot publish.
	settings := setting.NATSSettings{
		ListenAddress: "0.0.0.0",
		Auth: setting.NATSAuthSettings{
			Mode:            setting.NATSAuthModeCredentials,
			CredentialsFile: t.TempDir() + "/clients.creds",
		},
	}
	assertRoutableListenerRequiresAuth(t, settings, nil)
}

func TestEmbeddedNATSTokenExchangeModeRejectsStaticAndMissingTokens(t *testing.T) {
	// Token exchange presents a minted access token to an external verifier.
	// The bootstrap token is not that access token, and a missing token is not
	// either. The embedded server must not accept either one. Refusing to
	// listen is also a pass.
	settings := setting.NATSSettings{
		ListenAddress: "0.0.0.0",
		Auth: setting.NATSAuthSettings{
			Mode:                   setting.NATSAuthModeTokenExchange,
			TokenExchangeAudiences: []string{"placeholder-audience"},
			TokenExchangeURL:       "http://127.0.0.1:1",
			TokenExchangeToken:     "placeholder-token-exchange-bootstrap",
		},
	}
	assertRoutableListenerRequiresAuth(t, settings, []natsclient.Option{
		natsclient.Token("placeholder-token-exchange-bootstrap"),
		natsclient.Token(placeholderNATSToken),
	})
}

// assertRoutableListenerRequiresAuth fails when a server bound to a routable
// address accepts a client that does not present the mode's credentials.
// extra lists additional client option sets that must also be rejected.
func assertRoutableListenerRequiresAuth(t *testing.T, settings setting.NATSSettings, extra []natsclient.Option) {
	t.Helper()
	clientPort := reservePort(t, settings.ListenAddress)
	settings.ClientPort = clientPort
	probeAddr := probeAddress(settings.ListenAddress)
	accepted := probeAccepts(t, probeAddr, clientPort)

	srv, err := runEmbedded(t, settings)
	if err != nil {
		require.False(t, accepted(), "a client connected before the server refused to start")
		require.Never(t, func() bool {
			conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(probeAddr, strconv.Itoa(clientPort)), 20*time.Millisecond)
			if dialErr != nil {
				return false
			}
			conn.Close()
			return true
		}, 200*time.Millisecond, 10*time.Millisecond)
		require.Error(t, srv.Health(context.Background()))
		return
	}

	require.NoError(t, srv.Health(context.Background()))
	dialURL := dialableClientURL(t, runningNATS(t, srv).ClientURL())
	requireRejectedClient(t, dialURL)
	for _, opt := range extra {
		requireRejectedClient(t, dialURL, opt)
	}
}

func startAuthenticatedServer(t *testing.T, nats setting.NATSSettings) (*Server, string) {
	t.Helper()
	srv, err := runEmbedded(t, nats)
	require.NoError(t, err)
	require.NoError(t, srv.Health(context.Background()))
	srv.mu.RLock()
	raw := srv.server
	srv.mu.RUnlock()
	require.NotNil(t, raw)
	require.True(t, raw.Running())
	return srv, raw.ClientURL()
}

func runEmbedded(t *testing.T, nats setting.NATSSettings) (*Server, error) {
	t.Helper()
	if nats.Mode == "" {
		nats.Mode = setting.NATSModeEmbedded
	}
	nats.Enabled = true
	nats.DiscoveryEnabled = false
	if nats.ClientPort == 0 {
		nats.ClientPort = natsserver.RANDOM_PORT
	}
	if nats.ClusterPort == 0 {
		nats.ClusterPort = natsserver.RANDOM_PORT
	}

	cfg := setting.NewCfg()
	cfg.NATS = nats
	srv, err := ProvideServer(cfg, nil, prometheus.NewRegistry())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	startErr := srv.StartAsync(ctx)
	if startErr == nil {
		startErr = srv.AwaitRunning(ctx)
	}
	t.Cleanup(func() {
		srv.StopAsync()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = srv.AwaitTerminated(stopCtx)
	})
	return srv, startErr
}

func runningNATS(t *testing.T, srv *Server) *natsserver.Server {
	t.Helper()
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	require.NotNil(t, srv.server)
	return srv.server
}

func connectClient(t *testing.T, rawURL string, opts ...natsclient.Option) *natsclient.Conn {
	t.Helper()
	opts = append([]natsclient.Option{
		natsclient.Name("embedded-auth-test"),
		natsclient.Timeout(2 * time.Second),
		natsclient.NoReconnect(),
	}, opts...)
	nc, err := natsclient.Connect(rawURL, opts...)
	require.NoError(t, err)
	require.True(t, nc.IsConnected())
	t.Cleanup(nc.Close)
	return nc
}

func requireRejectedClient(t *testing.T, rawURL string, opts ...natsclient.Option) {
	t.Helper()
	opts = append([]natsclient.Option{
		natsclient.Name("embedded-auth-rejected"),
		natsclient.Timeout(2 * time.Second),
		natsclient.NoReconnect(),
	}, opts...)
	nc, err := natsclient.Connect(rawURL, opts...)
	if nc != nil {
		defer nc.Close()
	}
	if err == nil && nc != nil && nc.IsConnected() {
		pubErr := nc.Publish("us.watch.v1.folder.grafana.app.default.folders", []byte("unauthenticated"))
		sub, subErr := nc.SubscribeSync("us.watch.v1.>")
		if sub != nil {
			_ = sub.Unsubscribe()
		}
		t.Fatalf("client was accepted: connect err=%v publish=%v subscribe=%v", err, pubErr, subErr)
	}
	require.Error(t, err)
}

func dialableClientURL(t *testing.T, clientURL string) string {
	t.Helper()
	u, err := url.Parse(clientURL)
	require.NoError(t, err)
	host := u.Hostname()
	if host == "0.0.0.0" || host == "::" {
		// The process is bound to every interface. Dialing loopback hits that
		// same client accept loop.
		if host == "::" {
			host = "::1"
		} else {
			host = "127.0.0.1"
		}
		u.Host = net.JoinHostPort(host, u.Port())
	}
	return u.String()
}

func startRoutePeer(t *testing.T, routeURL string) (string, *natsserver.Server) {
	t.Helper()
	peer, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "unauthenticated-route-peer",
		Host:       "127.0.0.1",
		Port:       natsserver.RANDOM_PORT,
		NoLog:      true,
		NoSigs:     true,
		Cluster: natsserver.ClusterOpts{
			Name: "grafana",
			Host: "127.0.0.1",
			Port: natsserver.RANDOM_PORT,
		},
		Routes: natsserver.RoutesFromStr(routeURL),
	})
	require.NoError(t, err)
	peer.Start()
	require.True(t, peer.ReadyForConnections(5*time.Second))
	t.Cleanup(func() {
		peer.Shutdown()
		peer.WaitForShutdown()
	})
	return peer.ClientURL(), peer
}

func routableListenAddresses(t *testing.T) []string {
	t.Helper()
	addrs := []string{"0.0.0.0"}
	if ln, err := net.Listen("tcp", "[::]:0"); err == nil {
		_ = ln.Close()
		addrs = append(addrs, "::")
	}
	ifaces, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, addr := range ifaces {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsUnspecified() {
			continue
		}
		ip := ipNet.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		network := "tcp"
		bind := net.JoinHostPort(ip.String(), "0")
		ln, err := net.Listen(network, bind)
		if err != nil {
			continue
		}
		_ = ln.Close()
		addrs = append(addrs, ip.String())
		if len(addrs) >= 4 {
			break
		}
	}
	return addrs
}

func reservePort(t *testing.T, listen string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(listen, "0"))
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func probeAddress(listen string) string {
	switch listen {
	case "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	default:
		return listen
	}
}

// probeAccepts dials for the whole start attempt. A listener that comes up
// and is then closed still counts: the refusal has to happen before accept.
func probeAccepts(t *testing.T, host string, port int) func() bool {
	t.Helper()
	var accepted atomic.Bool
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn, err := net.DialTimeout("tcp", addr, 20*time.Millisecond)
			if err != nil {
				continue
			}
			_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			buf := make([]byte, 4)
			_, _ = conn.Read(buf)
			conn.Close()
			accepted.Store(true)
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})
	return accepted.Load
}
