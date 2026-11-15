package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grafana/dskit/services"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/modules"
	"github.com/grafana/grafana/pkg/router"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Requests that reach the module instrumentation server do not carry a
// Grafana identity. The single-tenant fallback must not use the operator
// token or dial the instance URL for those requests. /metrics stays open
// because scrapers use that port without an identity.
func TestInstrumentationServerSingleTenantFallbackUnauthenticatedProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
	t.Setenv("all_proxy", "")
	t.Setenv("no_proxy", "")

	const (
		operatorToken = "placeholder-operator-token"
		callerHeader  = "Bearer placeholder-caller-authorization"
		victimBody    = "internal-stack-response"
	)

	var victimHits atomic.Int32
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		victimHits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, victimBody)
	}))
	t.Cleanup(victim.Close)

	var gcomHits atomic.Int32
	gcom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gcomHits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+operatorToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":123,"url":%q}`, victim.URL)
	}))
	t.Cleanup(gcom.Close)

	var discoveryHits atomic.Int32
	discovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoveryHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "discovery-response")
	}))
	t.Cleanup(discovery.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	cfg := setting.NewCfg()
	cfg.Target = []string{modules.Router}
	cfg.HTTPAddr = "127.0.0.1"
	cfg.HTTPPort = strconv.Itoa(port)
	cfg.GrafanaComAPIURL = gcom.URL
	cfg.GrafanaComSSOAPIToken = operatorToken
	section, err := cfg.Raw.NewSection("cloud_router")
	require.NoError(t, err)
	_, err = section.NewKey("st_discovery_url", discovery.URL)
	require.NoError(t, err)

	ms := &ModuleServer{
		log:          log.New("test-logger"),
		cfg:          cfg,
		promGatherer: prometheus.NewRegistry(),
	}
	instrumentation, err := ms.initInstrumentationServer()
	require.NoError(t, err)

	loader, err := router.ProvideCloudRoutesLoaderFactory(cfg, router.PluginDependencies{})
	require.NoError(t, err)
	require.NotNil(t, loader)
	svc, err := router.ProvideService(cfg, featuremgmt.WithFeatures(), loader, prometheus.NewRegistry())
	require.NoError(t, err)
	require.NoError(t, svc.RegisterTargetRoutes(ms.httpServerRouter, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, services.StartAndAwaitRunning(ctx, instrumentation))
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		require.NoError(t, services.StopAndAwaitTerminated(stopCtx, instrumentation))
	})

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("metrics stay unauthenticated", func(t *testing.T) {
		resp, err := client.Get(base + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Zero(t, victimHits.Load())
		require.Zero(t, gcomHits.Load())
	})

	t.Run("namespaced request is not proxied", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, base+"/apis/example.grafana.app/v1/namespaces/stacks-123/widgets?limit=1", strings.NewReader("payload"))
		require.NoError(t, err)
		req.Header.Set("Authorization", callerHeader)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.NotContains(t, string(body), victimBody)
		require.Zero(t, victimHits.Load(), "instance URL was dialed")
		require.Zero(t, gcomHits.Load(), "operator token was used before authentication")
		require.Zero(t, discoveryHits.Load())
	})

	t.Run("unregistered group discovery is not proxied", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, base+"/apis/example.grafana.app/v1", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", callerHeader)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.NotContains(t, string(body), "discovery-response")
		require.Zero(t, discoveryHits.Load(), "discovery URL was dialed")
		require.Zero(t, victimHits.Load())
		require.Zero(t, gcomHits.Load())
	})
}
