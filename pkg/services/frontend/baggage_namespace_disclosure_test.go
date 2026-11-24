package frontend

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/hooks"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Placeholders stand in for the process credential and for tenant analytics
// values. They are not real secrets.
const (
	processTokenPlaceholder   = "process-token-placeholder"
	exchangedTokenPlaceholder = "exchanged-token-placeholder"
)

// tenantOverride is one namespace's security and analytics settings, the
// sections RequestConfigMiddleware asks the settings service for.
type tenantOverride struct {
	namespace       string
	writeKey        string
	dataPlaneURL    string
	sdkURL          string
	v3SdkURL        string
	configURL       string
	integrationsURL string
	batchInterval   string
	embedHosts      string
	formHosts       string
	orgID           string
}

func (t tenantOverride) markers() []string {
	return []string{
		t.namespace,
		t.writeKey,
		t.dataPlaneURL,
		t.sdkURL,
		t.v3SdkURL,
		t.configURL,
		t.integrationsURL,
		t.batchInterval,
		t.embedHosts,
		t.formHosts,
		t.orgID,
	}
}

func (t tenantOverride) settingItems() []settingItem {
	return []settingItem{
		{section: "analytics", key: "rudderstack_write_key", value: t.writeKey},
		{section: "analytics", key: "rudderstack_data_plane_url", value: t.dataPlaneURL},
		{section: "analytics", key: "rudderstack_sdk_url", value: t.sdkURL},
		{section: "analytics", key: "rudderstack_v3_sdk_url", value: t.v3SdkURL},
		{section: "analytics", key: "rudderstack_config_url", value: t.configURL},
		{section: "analytics", key: "rudderstack_integrations_url", value: t.integrationsURL},
		{section: "analytics", key: "rudderstack_batch_interval", value: t.batchInterval},
		{section: "security", key: "allow_embedding_hosts", value: t.embedHosts},
		{section: "security", key: "form_action_additional_hosts", value: t.formHosts},
	}
}

type settingItem struct {
	section string
	key     string
	value   string
}

var (
	tenantA = tenantOverride{
		namespace:       "stacks-victim-a",
		writeKey:        "tenant-a-write-key-placeholder",
		dataPlaneURL:    "https://tenant-a-dataplane.example/v1",
		sdkURL:          "https://tenant-a-sdk.example/v1/sdk.js",
		v3SdkURL:        "https://tenant-a-sdk.example/v3/sdk.js",
		configURL:       "https://tenant-a-config.example/sourceConfig.json",
		integrationsURL: "https://tenant-a-integrations.example/integrations",
		batchInterval:   "481516",
		embedHosts:      "tenant-a-embed.example",
		formHosts:       "tenant-a-form.example",
		orgID:           "tenant-a-org",
	}
	tenantB = tenantOverride{
		namespace:       "stacks-victim-b",
		writeKey:        "tenant-b-write-key-placeholder",
		dataPlaneURL:    "https://tenant-b-dataplane.example/v1",
		sdkURL:          "https://tenant-b-sdk.example/v1/sdk.js",
		v3SdkURL:        "https://tenant-b-sdk.example/v3/sdk.js",
		configURL:       "https://tenant-b-config.example/sourceConfig.json",
		integrationsURL: "https://tenant-b-integrations.example/integrations",
		batchInterval:   "481517",
		embedHosts:      "tenant-b-embed.example",
		formHosts:       "tenant-b-form.example",
		orgID:           "tenant-b-org",
	}
)

// tenantSettingsBackend is a stand-in for the remote settings API and the
// token-exchange endpoint. It follows the response shapes read from
// pkg/services/setting and github.com/grafana/authlib/authn: a settings list
// is SettingList JSON, and token exchange returns {"data":{"token":...}}.
// Each namespace returns only that namespace's settings.
type tenantSettingsBackend struct {
	server *httptest.Server

	mu       sync.Mutex
	tenants  map[string]tenantOverride
	observed []backendCall
}

type backendCall struct {
	path                       string
	namespace                  string
	exchangeNamespace          string
	exchangeAudiences          []string
	presentedProcessCredential bool
	usedExchangedCredential    bool
	isExchange                 bool
}

func newTenantSettingsBackend(t *testing.T, tenants ...tenantOverride) *tenantSettingsBackend {
	t.Helper()
	b := &tenantSettingsBackend{tenants: map[string]tenantOverride{}}
	for _, tenant := range tenants {
		b.tenants[tenant.namespace] = tenant
	}
	b.server = httptest.NewServer(b)
	t.Cleanup(b.server.Close)
	return b
}

func (b *tenantSettingsBackend) URL() string {
	return b.server.URL
}

func (b *tenantSettingsBackend) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.observed = nil
}

func (b *tenantSettingsBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/exchange" {
		b.serveExchange(w, r)
		return
	}
	b.serveSettings(w, r)
}

func (b *tenantSettingsBackend) serveExchange(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var payload struct {
		Namespace string   `json:"namespace"`
		Audiences []string `json:"audiences"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad exchange body", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	b.observed = append(b.observed, backendCall{
		path:                       r.URL.RequestURI(),
		isExchange:                 true,
		exchangeNamespace:          payload.Namespace,
		exchangeAudiences:          append([]string(nil), payload.Audiences...),
		presentedProcessCredential: r.Header.Get("Authorization") == "Bearer "+processTokenPlaceholder,
	})
	b.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data":   map[string]string{"token": exchangedTokenPlaceholder},
	})
}

func (b *tenantSettingsBackend) serveSettings(w http.ResponseWriter, r *http.Request) {
	namespace := namespaceFromSettingsPath(r.URL.Path)
	tenant, ok := b.tenants[namespace]

	b.mu.Lock()
	b.observed = append(b.observed, backendCall{
		path:                    r.URL.RequestURI(),
		namespace:               namespace,
		usedExchangedCredential: r.Header.Get("X-Access-Token") == "Bearer "+exchangedTokenPlaceholder,
	})
	b.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	items := []settingItem{}
	if ok {
		items = tenant.settingItems()
	}
	_, _ = io.WriteString(w, settingListJSON(items))
}

func (b *tenantSettingsBackend) calls() []backendCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]backendCall, len(b.observed))
	copy(out, b.observed)
	return out
}

func namespaceFromSettingsPath(path string) string {
	const marker = "/namespaces/"
	i := strings.Index(path, marker)
	if i < 0 {
		return ""
	}
	rest := path[i+len(marker):]
	namespace, _, _ := strings.Cut(rest, "/")
	return namespace
}

func settingListJSON(items []settingItem) string {
	var sb strings.Builder
	sb.WriteString(`{"apiVersion":"setting.grafana.app/v1beta1","kind":"SettingList","metadata":{"continue":""},"items":[`)
	for i, item := range items {
		if i > 0 {
			sb.WriteString(",")
		}
		labels, _ := json.Marshal(map[string]string{
			"section": item.section,
			"key":     item.key,
			"source":  "us",
		})
		sb.WriteString(`{"apiVersion":"setting.grafana.app/v1beta1","kind":"Setting","metadata":{"name":"`)
		sb.WriteString(item.section)
		sb.WriteString("--")
		sb.WriteString(item.key)
		sb.WriteString(`","labels":`)
		sb.Write(labels)
		sb.WriteString(`},"spec":{"section":"`)
		sb.WriteString(item.section)
		sb.WriteString(`","key":"`)
		sb.WriteString(item.key)
		sb.WriteString(`","value":"`)
		sb.WriteString(item.value)
		sb.WriteString(`"}}`)
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func newFrontendServiceWithSettings(t *testing.T, publicDir, backendURL string) *frontendService {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.HTTPPort = "3000"
	cfg.StaticRootPath = publicDir
	cfg.BuildVersion = "10.3.0"
	cfg.AppURL = "https://grafana.example.com"
	cfg.CSPEnabled = true
	cfg.CSPTemplate = "script-src 'self'; frame-ancestors $ALLOW_EMBEDDING_HOSTS; form-action 'self' $FORM_ACTION_ADDITIONAL_HOSTS"
	cfg.CSPReportOnlyEnabled = true
	cfg.CSPReportOnlyTemplate = "frame-ancestors $ALLOW_EMBEDDING_HOSTS; form-action 'self' $FORM_ACTION_ADDITIONAL_HOSTS"

	// Same keys setupSettingsService reads when the frontend-server module is
	// configured with a settings service and token exchange.
	cfg.Raw.Section("settings_service").Key("url").SetValue(backendURL)
	cfg.Raw.Section("settings_service").Key("cache_ttl").SetValue("-1s")
	cfg.Raw.Section("grpc_client_authentication").Key("token").SetValue(processTokenPlaceholder)
	cfg.Raw.Section("grpc_client_authentication").Key("token_exchange_url").SetValue(backendURL + "/exchange")
	cfg.Raw.Section("frontend_service").Key("baggage_eval_context_keys").SetValue("org_id")

	reg := prometheus.NewRegistry()
	svc, err := ProvideFrontendService(cfg, featuremgmt.WithFeatures(), reg, reg, &licensing.OSSLicensingService{}, hooks.ProvideService())
	require.NoError(t, err)
	require.NotNil(t, svc.settingsService, "settings service must be configured for this test")
	return svc
}

func serveFrontend(service *frontendService) *web.Mux {
	mux := web.New()
	service.addMiddlewares(mux)
	service.registerRoutes(mux)
	return mux
}

// TestUnauthenticatedBaggageDoesNotSelectTenantSettings is the spec for the
// client-supplied baggage namespace. It fails while that header selects
// another tenant's settings, and passes once an unauthenticated request can
// no longer choose the namespace whose settings are fetched or rendered.
func TestUnauthenticatedBaggageDoesNotSelectTenantSettings(t *testing.T) {
	publicDir := setupTestWebAssets(t)
	backend := newTenantSettingsBackend(t, tenantA, tenantB)
	service := newFrontendServiceWithSettings(t, publicDir, backend.URL())
	mux := serveFrontend(service)

	// Every case is an unauthenticated request: no Authorization header and no cookies.
	cases := []struct {
		name    string
		method  string
		path    string
		baggage string
	}{
		{name: "index names tenant a", path: "/", baggage: "namespace=" + tenantA.namespace},
		{name: "index names tenant b", path: "/", baggage: "namespace=" + tenantB.namespace},
		{name: "baggage member list names tenant a", path: "/", baggage: "trace-id=abc,namespace=" + tenantA.namespace + ",org_id=" + tenantA.orgID},
		{name: "percent-encoded namespace names tenant a", path: "/", baggage: "namespace=stacks-victim%2Da,org_id=" + tenantA.orgID},
		{name: "dashboard route names tenant a", path: "/dashboards", baggage: "namespace=" + tenantA.namespace},
		{name: "dashboard uid route names tenant b", path: "/d/de773f33s8qgwf/fep-homepage", baggage: "namespace=" + tenantB.namespace},
		{name: "public dashboard route names tenant a", path: "/public-dashboards/public-access-token-placeholder", baggage: "namespace=" + tenantA.namespace + ",org_id=" + tenantA.orgID},
		{name: "health route names tenant a", path: "/-/health", baggage: "namespace=" + tenantA.namespace},
		{name: "metrics route names tenant b", path: "/metrics", baggage: "namespace=" + tenantB.namespace},
		{name: "missing asset route names tenant a", path: "/public/build/app.js", baggage: "namespace=" + tenantA.namespace},
		{name: "boot error route names tenant a", path: "/-/fe-boot-error", baggage: "namespace=" + tenantA.namespace},
		{name: "post index names tenant a", method: http.MethodPost, path: "/", baggage: "namespace=" + tenantA.namespace},
		{name: "index without baggage", path: "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend.Reset()
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, tc.path, nil)
			req.Header.Del("Authorization")
			if tc.baggage != "" {
				req.Header.Set("baggage", tc.baggage)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			require.Less(t, rec.Code, 500, "handler failed before the disclosure check: %s", rec.Body.String())
			assertNoTenantDisclosure(t, rec, backend)
		})
	}
}

func TestUnauthenticatedBaggageDoesNotSelectFullFrontendSettings(t *testing.T) {
	enableReducedBootDataToggle(t)

	publicDir := setupTestWebAssets(t)
	backend := newTenantSettingsBackend(t, tenantA, tenantB)
	service := newFrontendServiceWithSettings(t, publicDir, backend.URL())
	mux := serveFrontend(service)

	cases := []struct {
		name    string
		path    string
		baggage string
	}{
		{name: "reduced boot data names tenant a", path: "/", baggage: "namespace=" + tenantA.namespace + ",org_id=" + tenantA.orgID},
		{name: "reduced boot data names tenant b", path: "/dashboards", baggage: "namespace=" + tenantB.namespace + ",org_id=" + tenantB.orgID},
		{name: "reduced boot data public dashboard names tenant a", path: "/public-dashboards/public-access-token-placeholder", baggage: "namespace=" + tenantA.namespace},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend.Reset()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Del("Authorization")
			req.Header.Set("baggage", tc.baggage)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			require.Less(t, rec.Code, 500, "handler failed before the disclosure check: %s", rec.Body.String())
			require.Contains(t, rec.Body.String(), "window.grafanaBootData")
			assertNoTenantDisclosure(t, rec, backend)
		})
	}
}

func assertNoTenantDisclosure(t *testing.T, rec *httptest.ResponseRecorder, backend *tenantSettingsBackend) {
	t.Helper()
	body := rec.Body.String()
	csp := rec.Header().Get("Content-Security-Policy")
	reportOnly := rec.Header().Get("Content-Security-Policy-Report-Only")
	combined := body + "\n" + csp + "\n" + reportOnly

	for _, tenant := range []tenantOverride{tenantA, tenantB} {
		for _, marker := range tenant.markers() {
			if marker != "" && strings.Contains(combined, marker) {
				t.Errorf("response disclosed %q from namespace %s\nCSP: %s\nCSP report-only: %s", marker, tenant.namespace, csp, reportOnly)
			}
		}
	}

	for _, call := range backend.calls() {
		if call.isExchange {
			continue
		}
		target := call.namespace + " " + call.path
		if strings.Contains(target, "stacks-victim") || strings.Contains(target, "tenant-a-") || strings.Contains(target, "tenant-b-") {
			t.Errorf("settings request followed a client-supplied namespace: path=%s namespace=%q usedExchangedCredential=%v",
				call.path, call.namespace, call.usedExchangedCredential)
		}
	}
	if t.Failed() {
		for _, call := range backend.calls() {
			if !call.isExchange {
				continue
			}
			t.Logf("token exchange namespace=%q audiences=%v presentedProcessCredential=%v",
				call.exchangeNamespace, call.exchangeAudiences, call.presentedProcessCredential)
		}
	}
}
