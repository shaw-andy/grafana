package resource

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsclient "github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/nats"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/storage/unified/resourcewatch"
)

// placeholderNATSToken is an obvious placeholder, not a credential from configuration.
const placeholderNATSToken = "placeholder-nats-auth"

func TestEmbeddedNATSUnauthenticatedClientCannotForgeWatchEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cfg := setting.NewCfg()
	cfg.NATS = setting.NATSSettings{
		Enabled:          true,
		Mode:             setting.NATSModeEmbedded,
		ListenAddress:    "0.0.0.0",
		ClientPort:       natsserver.RANDOM_PORT,
		ClusterPort:      natsserver.RANDOM_PORT,
		DiscoveryEnabled: false,
		Auth: setting.NATSAuthSettings{
			Mode:  setting.NATSAuthModeToken,
			Token: placeholderNATSToken,
		},
	}

	server, err := nats.ProvideServer(cfg, nil, prometheus.NewRegistry())
	require.NoError(t, err)
	startNatsService(t, ctx, server)

	natsCfg := nats.ProvideNATSConfig(cfg, server)
	sub := nats.ProvideSubscriber(natsCfg, prometheus.NewRegistry())
	startNatsService(t, ctx, sub)

	notifier := newNatsNotifier(natsSubscriberAdapter{sub: sub}, nil, log.NewNopLogger())
	out := notifier.Watch(ctx, WatchOptions{SettleDelay: time.Millisecond})

	clientURL := natsCfg.URLs()[0]
	parsed, err := url.Parse(clientURL)
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0", parsed.Hostname(), "embedded server did not bind a routable listen address")
	dialURL := (&url.URL{Scheme: parsed.Scheme, Host: net.JoinHostPort("127.0.0.1", parsed.Port())}).String()

	gvr := schema.GroupVersionResource{Group: "folder.grafana.app", Resource: "folders"}
	subject := resourcewatch.Subject(gvr, "default")

	// A client that presents the configured token can put a watch notification
	// on the bus, and the NATS notifier decodes it into a watch event. This is
	// the path a forged notification takes once a connection is accepted.
	authorized := connectWithToken(t, dialURL, placeholderNATSToken)
	publishNotification(t, authorized, subject, watchNotification("authorized-folder", 2))
	authorizedEvent := waitForNamedEvent(t, out, "authorized-folder")
	require.Equal(t, "folder.grafana.app", authorizedEvent.Group)
	require.Equal(t, "folders", authorizedEvent.Resource)
	require.Equal(t, "default", authorizedEvent.Namespace)
	require.Equal(t, DataActionCreated, authorizedEvent.Action)
	require.Equal(t, int64(2), authorizedEvent.ResourceVersion)

	// The same publish with no credentials must be rejected, and the notifier
	// must not surface it as a watch event.
	rejected, err := natsclient.Connect(dialURL,
		natsclient.Name("unauthenticated-watch-forger"),
		natsclient.Timeout(2*time.Second),
		natsclient.NoReconnect(),
	)
	if rejected != nil {
		defer rejected.Close()
	}
	if err == nil && rejected != nil && rejected.IsConnected() {
		publishNotification(t, rejected, subject, watchNotification("forged-folder", 3))
		forged := waitForNamedEvent(t, out, "forged-folder")
		t.Fatalf("unauthenticated publish was decoded into a watch event: group=%s resource=%s namespace=%s name=%s action=%s rv=%d",
			forged.Group, forged.Resource, forged.Namespace, forged.Name, forged.Action, forged.ResourceVersion)
	}
	require.Error(t, err, "unauthenticated client connected to the embedded client port")
	require.Never(t, func() bool {
		select {
		case evt := <-out:
			return evt.Name == "forged-folder"
		default:
			return false
		}
	}, 1500*time.Millisecond, 20*time.Millisecond)
}

func connectWithToken(t *testing.T, rawURL, token string) *natsclient.Conn {
	t.Helper()
	nc, err := natsclient.Connect(rawURL,
		natsclient.Name("token-watch-publisher"),
		natsclient.Timeout(2*time.Second),
		natsclient.NoReconnect(),
		natsclient.Token(token),
	)
	require.NoError(t, err)
	require.True(t, nc.IsConnected())
	t.Cleanup(nc.Close)
	return nc
}

func watchNotification(name string, rv int64) *resourcepb.WatchNotification {
	return &resourcepb.WatchNotification{
		Type:            resourcepb.WatchNotification_ADDED,
		Group:           "folder.grafana.app",
		Resource:        "folders",
		Namespace:       "default",
		Name:            name,
		ResourceVersion: rv,
		Folder:          "parent",
	}
}

func publishNotification(t *testing.T, nc *natsclient.Conn, subject string, n *resourcepb.WatchNotification) {
	t.Helper()
	payload, err := proto.Marshal(n)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		if err := nc.Publish(subject, payload); err != nil {
			return false
		}
		return nc.Flush() == nil
	}, 5*time.Second, 10*time.Millisecond)
}

func waitForNamedEvent(t *testing.T, out <-chan Event, name string) Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case evt := <-out:
			if evt.Name == name {
				return evt
			}
		case <-deadline:
			t.Fatalf("timed out waiting for watch event %q", name)
			return Event{}
		}
	}
}
