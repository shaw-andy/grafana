package ofrep

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	claims "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authnimpl"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
	"github.com/open-feature/go-sdk/openfeature"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	goffmodel "github.com/thomaspoignant/go-feature-flag/cmd/relayproxy/model"
	"go.opentelemetry.io/otel"
	k8smux "k8s.io/apiserver/pkg/server/mux"
)

// Flags whose static evaluation is false. Boot data only publishes flags that
// are on, so an unauthenticated OFREP response must not reveal these.
const offConfigFlag = "hiddenOffFlag"

var offFlags = []string{
	offConfigFlag,
	featuremgmt.FlagPublicDashboardsEmailSharing,
	featuremgmt.FlagFeaturesBulkFlagEvalFiltering,
	featuremgmt.FlagGrafanaOfrepRootUrl,
}

// signedInOnHeader is the test's stand-in for a completed login. Requests
// without the header go through the real authentication client queue.
const signedInOnHeader = "X-Test-Authenticated"

func TestUnauthenticatedStaticOFREPDoesNotDiscloseDisabledFlags(t *testing.T) {
	openfeatureTestMutex.Lock()
	t.Cleanup(func() {
		_ = openfeature.SetProviderAndWait(openfeature.NoopProvider{})
		openfeatureTestMutex.Unlock()
	})

	t.Run("default static provider", func(t *testing.T) {
		cfg := loadOFREPCfg(t, true)
		require.NoError(t, featuremgmt.InitOpenFeatureWithCfg(cfg))
		srv, builder := newOFREPServer(t, cfg)

		for _, path := range []string{
			"/ofrep/v1/evaluate/flags",
			"/apis/features.grafana.app/v0alpha1/namespaces/default/ofrep/v1/evaluate/flags",
		} {
			t.Run("bulk "+path, func(t *testing.T) {
				rec := postOFREP(t, srv, path, nil)
				assertBulkDoesNotDiscloseOffFlags(t, rec)
			})
			t.Run("bulk hostile origin "+path, func(t *testing.T) {
				rec := postOFREP(t, srv, path, map[string]string{"Origin": "https://evil.example"})
				assertBulkDoesNotDiscloseOffFlags(t, rec)
			})
		}

		for _, key := range offFlags {
			for _, path := range []string{
				"/ofrep/v1/evaluate/flags/" + key,
				"/apis/features.grafana.app/v0alpha1/namespaces/default/ofrep/v1/evaluate/flags/" + key,
			} {
				t.Run("one "+path, func(t *testing.T) {
					rec := postOFREP(t, srv, path, nil)
					assertOneFlagDoesNotDisclose(t, rec, key)
				})
			}
		}

		t.Run("standalone mux", func(t *testing.T) {
			mux := k8smux.NewPathRecorderMux("ofrep-disclosure")
			builder.Setup(mux)
			serve := func(path string) *httptest.ResponseRecorder {
				t.Helper()
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
				req.Header.Set("Content-Type", "application/json")
				mux.ServeHTTP(rec, req)
				return rec
			}
			for _, path := range []string{
				"/ofrep/v1/evaluate/flags",
				"/apis/features.grafana.app/v0alpha1/namespaces/default/ofrep/v1/evaluate/flags",
			} {
				t.Run("bulk "+path, func(t *testing.T) {
					assertBulkDoesNotDiscloseOffFlags(t, serve(path))
				})
			}
			for _, key := range offFlags {
				for _, path := range []string{
					"/ofrep/v1/evaluate/flags/" + key,
					"/apis/features.grafana.app/v0alpha1/namespaces/default/ofrep/v1/evaluate/flags/" + key,
				} {
					t.Run("one "+path, func(t *testing.T) {
						assertOneFlagDoesNotDisclose(t, serve(path), key)
					})
				}
			}
		})

		t.Run("signed in caller still receives static evaluation", func(t *testing.T) {
			rec := postOFREP(t, srv, "/ofrep/v1/evaluate/flags", map[string]string{signedInOnHeader: "true"})
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var result goffmodel.OFREPBulkEvaluateSuccessResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
			found := map[string]bool{}
			for _, flag := range result.Flags {
				if v, ok := flag.Value.(bool); ok {
					found[flag.Key] = v
				}
			}
			for _, key := range offFlags {
				value, ok := found[key]
				require.Truef(t, ok, "signed-in bulk evaluation omitted %q", key)
				require.Falsef(t, value, "signed-in evaluation of %q", key)
			}

			one := postOFREP(t, srv, "/ofrep/v1/evaluate/flags/"+offConfigFlag, map[string]string{signedInOnHeader: "true"})
			require.Equal(t, http.StatusOK, one.Code, one.Body.String())
			var single goffmodel.OFREPEvaluateSuccessResponse
			require.NoError(t, json.Unmarshal(one.Body.Bytes(), &single))
			require.Equal(t, offConfigFlag, single.Key)
			require.Equal(t, false, single.Value)
		})
	})

	t.Run("enable_api false does not serve evaluations", func(t *testing.T) {
		cfg := loadOFREPCfg(t, false)
		require.False(t, cfg.OpenFeature.APIEnabled)
		require.NoError(t, featuremgmt.InitOpenFeatureWithCfg(cfg))
		srv, builder := newOFREPServer(t, cfg)

		for _, path := range []string{
			"/ofrep/v1/evaluate/flags",
			"/ofrep/v1/evaluate/flags/" + offConfigFlag,
			"/apis/features.grafana.app/v0alpha1/namespaces/default/ofrep/v1/evaluate/flags",
			"/apis/features.grafana.app/v0alpha1/namespaces/default/ofrep/v1/evaluate/flags/" + offConfigFlag,
		} {
			t.Run(path, func(t *testing.T) {
				rec := postOFREP(t, srv, path, nil)
				assertAPIDisabled(t, rec)
				authed := postOFREP(t, srv, path, map[string]string{signedInOnHeader: "true"})
				assertAPIDisabled(t, authed)
			})
		}

		mux := k8smux.NewPathRecorderMux("ofrep-disabled")
		builder.Setup(mux)
		for _, path := range []string{
			"/ofrep/v1/evaluate/flags",
			"/ofrep/v1/evaluate/flags/" + offConfigFlag,
		} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
			req.Header.Set("Content-Type", "application/json")
			mux.ServeHTTP(rec, req)
			assertAPIDisabled(t, rec)
		}
	})
}

func loadOFREPCfg(t *testing.T, apiEnabled bool) *setting.Cfg {
	t.Helper()
	enabled := "false"
	if apiEnabled {
		enabled = "true"
	}
	// Defaults match conf/defaults.ini for the settings this request depends on:
	// static provider, anonymous access off, CSRF not forced, basic auth on,
	// auth proxy and JWT off, provisioning on, login cookie grafana_session.
	cfg, err := setting.NewCfgFromBytes([]byte(`
[feature_toggles]
hiddenOffFlag = false

[feature_toggles.openfeature]
enable_api = ` + enabled + `
provider = static

[auth.anonymous]
enabled = false

[security]
csrf_always_check = false

[auth.basic]
enabled = true

[auth.proxy]
enabled = false

[auth.jwt]
enabled = false

[provisioning]
enabled = true
`))
	require.NoError(t, err)
	require.Equal(t, setting.StaticProviderType, cfg.OpenFeature.ProviderType)
	require.Equal(t, apiEnabled, cfg.OpenFeature.APIEnabled)
	require.False(t, cfg.Anonymous.Enabled)
	require.Equal(t, "grafana_session", cfg.LoginCookieName)
	require.False(t, cfg.AuthProxy.Enabled)
	require.False(t, cfg.JWTAuth.Enabled)
	require.True(t, cfg.BasicAuthEnabled)
	require.True(t, cfg.ProvisioningEnabled)
	return cfg
}

func newOFREPServer(t *testing.T, cfg *setting.Cfg) (*web.Macaron, *APIBuilder) {
	t.Helper()
	tracer := tracing.InitializeTracerForTest()
	otelTracer := otel.Tracer("ofrep-disclosure-test")
	cfgProvider, err := configprovider.ProvideService(cfg)
	require.NoError(t, err)

	authnSvc := authnimpl.ProvideService(cfg, tracer, nil, &usagestats.UsageStatsMock{}, prometheus.NewRegistry(), nil)
	// Same clients ProvideRegistration registers for this configuration.
	// Anonymous is omitted because [auth.anonymous] enabled is false.
	authnSvc.RegisterClient(clients.ProvideRender(nil))
	authnSvc.RegisterClient(clients.ProvideAPIKey(nil, otelTracer))
	authnSvc.RegisterClient(clients.ProvideSession(cfgProvider, nil, nil, otelTracer))
	password := clients.ProvidePassword(nil, otelTracer, clients.ProvideGrafana(cfg, nil, otelTracer))
	authnSvc.RegisterClient(clients.ProvideBasic(password))
	authnSvc.RegisterClient(clients.ProvideProvisioning())

	handler := contexthandler.ProvideService(cfg, headerOrServiceAuth{next: authnSvc}, featuremgmt.WithFeatures())

	rr := routing.ProvideRegister()
	builder, err := ProvideService(cfg, rr)
	require.NoError(t, err)
	require.Equal(t, setting.StaticProviderType, builder.providerType)

	m := web.New()
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	m.Use(handler.Middleware)
	rr.Register(m)
	return m, builder
}

type headerOrServiceAuth struct {
	next authn.Authenticator
}

func (h headerOrServiceAuth) Authenticate(ctx context.Context, r *authn.Request) (*authn.Identity, error) {
	if r != nil && r.HTTPRequest != nil && r.HTTPRequest.Header.Get(signedInOnHeader) == "true" {
		return &authn.Identity{
			ID:    "1",
			Type:  claims.TypeUser,
			OrgID: 1,
			Login: "viewer",
		}, nil
	}
	return h.next.Authenticate(ctx, r)
}

func postOFREP(t *testing.T, srv http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// No grafana_session cookie: CSRF skips, and the session client does not match.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func assertBulkDoesNotDiscloseOffFlags(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	body := rec.Body.String()
	switch rec.Code {
	case http.StatusOK:
		var result goffmodel.OFREPBulkEvaluateSuccessResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result), body)
		for _, flag := range result.Flags {
			if v, ok := flag.Value.(bool); ok && !v {
				t.Fatalf("unauthenticated bulk evaluation disclosed disabled flag %q", flag.Key)
			}
		}
		for _, key := range offFlags {
			require.NotContains(t, body, `"`+key+`"`, "off flag listed in %s", body)
		}
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		for _, key := range offFlags {
			require.NotContains(t, body, `"`+key+`"`)
		}
	default:
		t.Fatalf("status %d body %s", rec.Code, body)
	}
}

func assertOneFlagDoesNotDisclose(t *testing.T, rec *httptest.ResponseRecorder, key string) {
	t.Helper()
	body := rec.Body.String()
	switch rec.Code {
	case http.StatusOK:
		t.Fatalf("unauthenticated evaluation of off flag %q returned 200: %s", key, body)
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		require.NotContains(t, body, `"value":false`)
		require.NotContains(t, body, `"value": false`)
	default:
		t.Fatalf("status %d for %q body %s", rec.Code, key, body)
	}
}

func assertAPIDisabled(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	body := rec.Body.String()
	switch rec.Code {
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		require.NotContains(t, body, `"`+offConfigFlag+`"`)
		require.NotContains(t, body, `"value":false`)
	default:
		t.Fatalf("enable_api=false still served status %d body %s", rec.Code, body)
	}
}
