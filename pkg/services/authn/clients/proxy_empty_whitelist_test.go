package clients

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/setting"
)

// These tests specify the safe behavior for an enabled auth proxy whose
// whitelist is empty. They fail while an empty accept list is treated as
// allow-all.

func TestProvideProxyRejectsEmptyWhitelist(t *testing.T) {
	for _, whitelist := range []string{"", " ", "\t", "\n", " \t\n "} {
		t.Run(whitelist, func(t *testing.T) {
			cfg := setting.NewCfg()
			cfg.AuthProxy.Enabled = true
			cfg.AuthProxy.HeaderName = "X-WEBAUTH-USER"
			cfg.AuthProxy.HeaderProperty = "username"
			cfg.AuthProxy.Whitelist = whitelist

			_, err := ProvideProxy(cfg, &fakeCache{data: map[string][]byte{}}, tracing.InitializeTracerForTest())
			require.Error(t, err)
		})
	}
}

func TestProxyAuthenticateEmptyAcceptListDoesNotReadUsername(t *testing.T) {
	cases := []struct {
		desc       string
		remoteAddr string
	}{
		{desc: "ipv4", remoteAddr: "203.0.113.10:40000"},
		{desc: "ipv4 without port", remoteAddr: "203.0.113.10"},
		{desc: "ipv6", remoteAddr: "[2001:db8::10]:443"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			cfg := setting.NewCfg()
			cfg.AuthProxy.Enabled = true
			cfg.AuthProxy.HeaderName = "X-WEBAUTH-USER"
			cfg.AuthProxy.HeaderProperty = "username"
			cfg.AuthProxy.AutoSignUp = true
			cfg.AuthProxy.Whitelist = ""

			var gotUsername string
			called := false
			proxyClient := authntest.MockProxyClient{AuthenticateProxyFunc: func(_ context.Context, _ *authn.Request, username string, _ map[string]string) (*authn.Identity, error) {
				called = true
				gotUsername = username
				return &authn.Identity{Login: username}, nil
			}}

			// acceptedIPs is what Authenticate checks. Building it here, instead of
			// only through ProvideProxy, keeps the assertion on the request path
			// when startup is changed separately from the allow check.
			c := &Proxy{
				log:         log.New("authn.proxy.test"),
				cfg:         cfg,
				cache:       &fakeCache{data: map[string][]byte{}},
				clients:     []authn.ProxyClient{proxyClient},
				acceptedIPs: nil,
				tracer:      tracing.InitializeTracerForTest(),
			}

			req := &authn.Request{HTTPRequest: &http.Request{
				Header:     http.Header{"X-Webauth-User": []string{"server-admin"}},
				RemoteAddr: tc.remoteAddr,
			}}

			identity, err := c.Authenticate(context.Background(), req)
			if err == nil {
				t.Fatalf("empty accept list authenticated login=%q id=%s", identity.Login, identity.GetID())
			}
			require.ErrorIs(t, err, errNotAcceptedIP)
			require.Nil(t, identity)
			assert.False(t, called, "username header was forwarded: %q", gotUsername)
		})
	}
}

func TestProxyAuthenticateCacheHitEmptyAcceptListDoesNotReturnCachedUser(t *testing.T) {
	cfg := setting.NewCfg()
	cfg.AuthProxy.Enabled = true
	cfg.AuthProxy.HeaderName = "X-WEBAUTH-USER"
	cfg.AuthProxy.HeaderProperty = "username"
	cfg.AuthProxy.SyncTTL = 15
	cfg.AuthProxy.Whitelist = ""

	req := &authn.Request{HTTPRequest: &http.Request{
		Header:     http.Header{"X-Webauth-User": []string{"server-admin"}},
		RemoteAddr: "203.0.113.10:40000",
	}}
	additional := getAdditionalProxyHeaders(req, cfg)
	cacheKey, ok := getProxyCacheKey("server-admin", additional)
	require.True(t, ok)

	called := false
	proxyClient := authntest.MockProxyClient{AuthenticateProxyFunc: func(_ context.Context, _ *authn.Request, username string, _ map[string]string) (*authn.Identity, error) {
		called = true
		return &authn.Identity{ID: "99", Login: username}, nil
	}}

	c := &Proxy{
		log:         log.New("authn.proxy.test"),
		cfg:         cfg,
		cache:       &fakeCache{data: map[string][]byte{cacheKey: []byte("42")}},
		clients:     []authn.ProxyClient{proxyClient},
		acceptedIPs: nil,
		tracer:      tracing.InitializeTracerForTest(),
	}

	identity, err := c.Authenticate(context.Background(), req)
	if err == nil {
		t.Fatalf("cached auth proxy identity was returned for an unlisted client: id=%s login=%q", identity.GetID(), identity.Login)
	}
	require.ErrorIs(t, err, errNotAcceptedIP)
	require.Nil(t, identity)
	assert.False(t, called)
}
