package frontend

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/open-feature/go-sdk/openfeature"
	"k8s.io/apiserver/pkg/endpoints/request"

	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Minimal copy of contextHandler.Middleware for frontend-service
// frontend-service doesn't handle authentication or know what signed in users are
func (s *frontendService) contextMiddleware() web.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			span := trace.SpanFromContext(ctx)
			ctx = setRequestContext(ctx, w, r, s.baggageEvalContextKeys, s.baggageSigningKey)

			// Preserve the original span so the setRequestContext span doesn't get propagated as a parent of the rest of the request
			ctx = trace.ContextWithSpan(ctx, span)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func setRequestContext(ctx context.Context, w http.ResponseWriter, r *http.Request, baggageEvalContextKeys []string, baggageSigningKey []byte) context.Context {
	ctx, span := tracing.Start(ctx, "setRequestContext")
	defer span.End()

	webCtx := web.FromContext(ctx)
	reqContext := &contextmodel.ReqContext{
		Context:      webCtx,
		Logger:       log.New("context"),
		SignedInUser: &user.SignedInUser{},
	}

	// inject ReqContext in the context
	ctx = context.WithValue(ctx, ctxkey.Key{}, reqContext)

	// Set the context for the http.Request.Context
	// This modifies both r and reqContext.Req since they point to the same value
	if webCtx != nil {
		*reqContext.Req = *reqContext.Req.WithContext(ctx)
	}

	// add traceID to logger context
	traceID := tracing.TraceIDFromContext(ctx, false)
	if traceID != "" {
		reqContext.Logger = reqContext.Logger.New("traceID", traceID)
		// set trace ID in response headers as well
		w.Header().Set("Trace-ID", traceID)
	}

	// add hostname to logger context
	hostname := r.Host
	if hostname != "" {
		reqContext.Logger = reqContext.Logger.New("hostname", hostname)
	}

	// add user agent to logger context
	if userAgent := r.UserAgent(); userAgent != "" {
		reqContext.Logger = reqContext.Logger.New("user_agent", userAgent)
	}

	// The baggage header carries the namespace plus any additional members
	// configured for the evaluation context below. It is only trusted when the
	// ingress hop signed it, since the namespace selects tenant settings.
	bag := trustedBaggage(r, baggageSigningKey)

	namespace := bag.Member("namespace").Value()
	if namespace != "" {
		ctx = request.WithNamespace(ctx, namespace)
	}

	// Note: OpenFeature is already initialized by target.go before this service starts.
	// The frontend service only needs to set evaluation context per request
	openFeatureNamespace := "default"
	if namespace != "" {
		openFeatureNamespace = namespace
	}
	attributes := map[string]any{
		"namespace": openFeatureNamespace,
		"hostname":  hostname,
	}

	// Copy configured baggage members into the evaluation context. The members
	// can't be hardcoded here because they may be specific to a particular
	// deployment, so the set of keys is driven by configuration.
	for _, key := range baggageEvalContextKeys {
		if value := bag.Member(key).Value(); value != "" {
			attributes[key] = value
		}
	}

	evalCtx := openfeature.NewEvaluationContext(openFeatureNamespace, attributes)
	ctx = openfeature.MergeTransactionContext(ctx, evalCtx)

	return ctx
}

// readBaggageEvalContextKeys returns the list of W3C baggage member keys whose
// values are copied into the per-request OpenFeature evaluation context.
//
// [frontend_service]
// baggage_eval_context_keys = key1 key2
func readBaggageEvalContextKeys(cfg *setting.Cfg) []string {
	sec := cfg.SectionWithEnvOverrides("frontend_service")
	return sec.Key("baggage_eval_context_keys").Strings(" ")
}

// baggageSignatureHeader carries the hex-encoded HMAC-SHA256 of the raw
// baggage header value, computed by the ingress hop with the shared
// baggage_signing_key.
const baggageSignatureHeader = "X-Grafana-Baggage-Signature"

// readBaggageSigningKey returns the key used to authenticate the inbound
// baggage header. When it is empty, inbound baggage is ignored.
//
// [frontend_service]
// baggage_signing_key = <shared secret>
func readBaggageSigningKey(cfg *setting.Cfg) []byte {
	sec := cfg.SectionWithEnvOverrides("frontend_service")
	return []byte(sec.Key("baggage_signing_key").String())
}

// trustedBaggage returns the request's baggage only when it is a single header
// whose signature matches signingKey. The verified bytes are the ones parsed,
// so a caller can't pair a valid signature with different members.
func trustedBaggage(r *http.Request, signingKey []byte) baggage.Baggage {
	if len(signingKey) == 0 {
		return baggage.Baggage{}
	}

	values := r.Header.Values("baggage")
	if len(values) != 1 || values[0] == "" {
		return baggage.Baggage{}
	}
	raw := values[0]

	signature, err := hex.DecodeString(r.Header.Get(baggageSignatureHeader))
	if err != nil || len(signature) == 0 {
		return baggage.Baggage{}
	}
	if !hmac.Equal(signature, signBaggage(signingKey, raw)) {
		return baggage.Baggage{}
	}

	parsed, err := baggage.Parse(raw)
	if err != nil {
		return baggage.Baggage{}
	}
	return parsed
}

func signBaggage(signingKey []byte, raw string) []byte {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(raw))
	return mac.Sum(nil)
}
