package frontend

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	gokitlog "github.com/go-kit/log"
	"github.com/open-feature/go-sdk/openfeature"
	"github.com/stretchr/testify/assert"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware/loggermw"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

var testBaggageSigningKey = []byte("test-baggage-signing-key-placeholder")

// setSignedBaggage sets the baggage header the way the trusted ingress hop does,
// signed with testBaggageSigningKey.
func setSignedBaggage(req *http.Request, value string) {
	req.Header.Set("baggage", value)
	req.Header.Set(baggageSignatureHeader, hex.EncodeToString(signBaggage(testBaggageSigningKey, value)))
}

func TestContextMiddleware(t *testing.T) {
	t.Run("calls next handler with context", func(t *testing.T) {
		service := &frontendService{}
		nextCalled := false
		var capturedRequest *http.Request

		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			capturedRequest = r
		})

		middleware := service.contextMiddleware()
		handler := middleware(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		assert.True(t, nextCalled, "next handler should be called")
		assert.NotNil(t, capturedRequest, "request should be passed to next handler")
		assert.NotNil(t, capturedRequest.Context(), "request context should be set")
	})
}

func TestSetRequestContext(t *testing.T) {
	t.Run("parses namespace from baggage header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		setSignedBaggage(req, "namespace=stacks-123")
		rec := httptest.NewRecorder()

		ctx := setRequestContext(req.Context(), rec, req, nil, testBaggageSigningKey)

		namespace, ok := request.NamespaceFrom(ctx)
		assert.True(t, ok, "Namespace should be present in context")
		assert.Equal(t, "stacks-123", namespace, "Namespace should match baggage value")
	})

	t.Run("handles baggage header with multiple members", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		setSignedBaggage(req, "trace-id=abc123,namespace=tenant-456,user-id=xyz")
		rec := httptest.NewRecorder()

		ctx := setRequestContext(req.Context(), rec, req, nil, testBaggageSigningKey)

		namespace, ok := request.NamespaceFrom(ctx)
		assert.True(t, ok, "Namespace should be present in context")
		assert.Equal(t, "tenant-456", namespace, "Namespace should match baggage value")
	})

	t.Run("does not set a namespace when baggage header is missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		ctx := setRequestContext(req.Context(), rec, req, nil, testBaggageSigningKey)

		namespace, ok := request.NamespaceFrom(ctx)
		assert.False(t, ok, "Namespace should not be present in context")
		assert.Empty(t, namespace, "Namespace should be empty when not provided")
	})

	t.Run("handles invalid baggage header gracefully", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		setSignedBaggage(req, "invalid-baggage-format;;;")
		rec := httptest.NewRecorder()

		ctx := setRequestContext(req.Context(), rec, req, nil, testBaggageSigningKey)

		namespace, ok := request.NamespaceFrom(ctx)
		assert.False(t, ok, "Namespace should not be present in context")
		assert.Empty(t, namespace, "Namespace should be empty when baggage is invalid")
	})

	t.Run("handles baggage header without namespace member", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		setSignedBaggage(req, "other-key=other-value")
		rec := httptest.NewRecorder()

		ctx := setRequestContext(req.Context(), rec, req, nil, testBaggageSigningKey)

		namespace, ok := request.NamespaceFrom(ctx)
		assert.False(t, ok, "Namespace should not be present in context")
		assert.Empty(t, namespace, "Namespace should be empty when namespace member not in baggage")
	})
}

func TestSetRequestContextRejectsUntrustedBaggage(t *testing.T) {
	assertUntrusted := func(t *testing.T, ctx context.Context) {
		t.Helper()
		_, ok := request.NamespaceFrom(ctx)
		assert.False(t, ok, "untrusted baggage must not set a namespace")
		attrs := openfeature.TransactionContext(ctx).Attributes()
		assert.Equal(t, "default", attrs["namespace"])
		assert.NotContains(t, attrs, "org_id", "untrusted baggage must not reach the evaluation context")
	}

	t.Run("ignores unsigned baggage", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("baggage", "namespace=stacks-123,org_id=42")

		assertUntrusted(t, setRequestContext(req.Context(), httptest.NewRecorder(), req, []string{"org_id"}, testBaggageSigningKey))
	})

	t.Run("ignores baggage signed with a different key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		value := "namespace=stacks-123,org_id=42"
		req.Header.Set("baggage", value)
		req.Header.Set(baggageSignatureHeader, hex.EncodeToString(signBaggage([]byte("other-key-placeholder"), value)))

		assertUntrusted(t, setRequestContext(req.Context(), httptest.NewRecorder(), req, []string{"org_id"}, testBaggageSigningKey))
	})

	t.Run("ignores a signature for different baggage", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("baggage", "namespace=stacks-123,org_id=42")
		req.Header.Set(baggageSignatureHeader, hex.EncodeToString(signBaggage(testBaggageSigningKey, "namespace=stacks-own")))

		assertUntrusted(t, setRequestContext(req.Context(), httptest.NewRecorder(), req, []string{"org_id"}, testBaggageSigningKey))
	})

	t.Run("ignores a malformed signature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("baggage", "namespace=stacks-123,org_id=42")
		req.Header.Set(baggageSignatureHeader, "not-hex")

		assertUntrusted(t, setRequestContext(req.Context(), httptest.NewRecorder(), req, []string{"org_id"}, testBaggageSigningKey))
	})

	t.Run("ignores an extra baggage header next to a signed one", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		setSignedBaggage(req, "namespace=stacks-own")
		req.Header.Add("baggage", "namespace=stacks-123,org_id=42")

		assertUntrusted(t, setRequestContext(req.Context(), httptest.NewRecorder(), req, []string{"org_id"}, testBaggageSigningKey))
	})

	t.Run("ignores signed baggage when no signing key is configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		setSignedBaggage(req, "namespace=stacks-123,org_id=42")

		assertUntrusted(t, setRequestContext(req.Context(), httptest.NewRecorder(), req, []string{"org_id"}, nil))
	})
}

func TestSetRequestContextBaggageEvalContext(t *testing.T) {
	t.Run("copies configured baggage members into the evaluation context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		setSignedBaggage(req, "namespace=tenant-1,org_id=42,region=eu,ignored=nope")
		rec := httptest.NewRecorder()

		ctx := setRequestContext(req.Context(), rec, req, []string{"org_id", "region"}, testBaggageSigningKey)

		attrs := openfeature.TransactionContext(ctx).Attributes()
		assert.Equal(t, "tenant-1", attrs["namespace"])
		assert.Equal(t, "42", attrs["org_id"])
		assert.Equal(t, "eu", attrs["region"])
		assert.NotContains(t, attrs, "ignored", "members not in the configured list should not be copied")
	})

	t.Run("omits configured members that are absent from the baggage header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		setSignedBaggage(req, "namespace=tenant-1")
		rec := httptest.NewRecorder()

		ctx := setRequestContext(req.Context(), rec, req, []string{"org_id"}, testBaggageSigningKey)

		attrs := openfeature.TransactionContext(ctx).Attributes()
		assert.NotContains(t, attrs, "org_id", "absent baggage members should not be added")
	})

	t.Run("keeps default namespace and hostname when no keys are configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "example.com"
		rec := httptest.NewRecorder()

		ctx := setRequestContext(req.Context(), rec, req, nil, testBaggageSigningKey)

		attrs := openfeature.TransactionContext(ctx).Attributes()
		assert.Equal(t, "default", attrs["namespace"])
		assert.Equal(t, "example.com", attrs["hostname"])
	})
}

func TestReadBaggageEvalContextKeys(t *testing.T) {
	t.Run("returns configured keys", func(t *testing.T) {
		cfg := setting.NewCfg()
		sec, err := cfg.Raw.NewSection("frontend_service")
		assert.NoError(t, err)
		_, err = sec.NewKey("baggage_eval_context_keys", "org_id region")
		assert.NoError(t, err)

		assert.Equal(t, []string{"org_id", "region"}, readBaggageEvalContextKeys(cfg))
	})

	t.Run("returns empty list when not configured", func(t *testing.T) {
		cfg := setting.NewCfg()
		assert.Empty(t, readBaggageEvalContextKeys(cfg))
	})
}

func TestReadBaggageSigningKey(t *testing.T) {
	t.Run("returns configured key", func(t *testing.T) {
		cfg := setting.NewCfg()
		cfg.Raw.Section("frontend_service").Key("baggage_signing_key").SetValue("configured-key-placeholder")

		assert.Equal(t, []byte("configured-key-placeholder"), readBaggageSigningKey(cfg))
	})

	t.Run("returns empty key when not configured", func(t *testing.T) {
		cfg := setting.NewCfg()
		assert.Empty(t, readBaggageSigningKey(cfg))
	})
}

func TestRequestLogIncludesUserAgent(t *testing.T) {
	cfg := setting.NewCfg()
	cfg.RouterLogging = true
	features := featuremgmt.WithFeatures()

	service := &frontendService{cfg: cfg, features: features}

	// setRequestContext builds reqContext.Logger from log.New("context"). Swap the
	// cached instance's inner logger to capture the access log line emitted by
	// loggermw, while preserving the contextual fields added via .New(...).
	var buf bytes.Buffer
	contextLogger := log.New("context")
	contextLogger.Swap(gokitlog.NewLogfmtLogger(gokitlog.NewSyncWriter(&buf)))
	t.Cleanup(func() {
		contextLogger.Swap(gokitlog.NewLogfmtLogger(gokitlog.NewSyncWriter(io.Discard)))
	})

	loggerMW := loggermw.Provide(cfg, features)

	m := web.New()
	m.UseMiddleware(service.contextMiddleware())
	m.UseMiddleware(loggerMW.Middleware())
	m.Get("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("includes user_agent field when User-Agent header is set", func(t *testing.T) {
		buf.Reset()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "TestAgent/1.0")
		rec := httptest.NewRecorder()

		m.ServeHTTP(rec, req)

		assert.Contains(t, buf.String(), "Request Completed")
		assert.Contains(t, buf.String(), "user_agent=TestAgent/1.0")
	})

	t.Run("omits user_agent field when User-Agent header is not set", func(t *testing.T) {
		buf.Reset()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Del("User-Agent")
		rec := httptest.NewRecorder()

		m.ServeHTTP(rec, req)

		assert.Contains(t, buf.String(), "Request Completed")
		assert.NotContains(t, buf.String(), "user_agent")
	})
}
