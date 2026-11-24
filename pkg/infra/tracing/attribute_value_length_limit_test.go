package tracing

import (
	"bufio"
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/grafana/pkg/infra/log"
)

// attributeValueLengthLimit is the deployment limit under test. The tracer
// providers below do not pass WithSpanLimits, so the SDK reads this from the
// environment when the provider is created.
const attributeValueLengthLimit = 16

// replacementRunes is long enough that a value made of U+FFFD exceeds the
// limit in both characters and bytes.
const replacementRunes = 64

// TestInitTracerProviderCountsReplacementCharacter uses the OTLP and file
// tracer provider constructor. A request parsed by net/http carrying a path of
// U+FFFD must not be retained past the configured attribute value length limit.
func TestInitTracerProviderCountsReplacementCharacter(t *testing.T) {
	t.Setenv("OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT", strconv.Itoa(attributeValueLengthLimit))
	t.Setenv("OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", "")

	tp, exp := newInitTracer(t)
	req := readRequest(t, "GET /"+strings.Repeat("%EF%BF%BD", replacementRunes)+" HTTP/1.1\r\nHost: example.test\r\n\r\n")
	recordRequestAttributes(t, tp.Tracer("request"), req)
	require.NoError(t, tp.ForceFlush(context.Background()))
	spans := exp.GetSpans()

	// The raw request target is percent-encoded ASCII, so the counter sees it.
	// This fails if the constructor ignored the environment limit entirely.
	rawTarget := attributeContaining(t, spans, "http.url", "%EF%BF%BD")
	require.LessOrEqual(t, utf8.RuneCountInString(rawTarget), attributeValueLengthLimit)
	require.Less(t, utf8.RuneCountInString(rawTarget), len(req.RequestURI))

	decodedPath := attributeContaining(t, spans, "url.path", "\uFFFD")
	require.LessOrEqual(t, utf8.RuneCountInString(decodedPath), attributeValueLengthLimit,
		"initTracerProvider kept %d runes of a U+FFFD request path", utf8.RuneCountInString(decodedPath))

	flagKey := attributeContaining(t, spans, "flag_key", "k\uFFFD")
	require.LessOrEqual(t, utf8.RuneCountInString(flagKey), attributeValueLengthLimit,
		"initTracerProvider kept %d runes of a U+FFFD flag_key", utf8.RuneCountInString(flagKey))
}

// TestInitTracerProviderGenericAttributeLimit covers the fallback environment
// variable used when the span-specific one is unset.
func TestInitTracerProviderGenericAttributeLimit(t *testing.T) {
	t.Setenv("OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT", "")
	t.Setenv("OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", strconv.Itoa(attributeValueLengthLimit))

	tp, exp := newInitTracer(t)
	req := readRequest(t, "GET /"+strings.Repeat("%EF%BF%BD", replacementRunes)+" HTTP/1.1\r\nHost: example.test\r\n\r\n")
	recordRequestAttributes(t, tp.Tracer("request"), req)
	require.NoError(t, tp.ForceFlush(context.Background()))

	decodedPath := attributeContaining(t, exp.GetSpans(), "url.path", "\uFFFD")
	require.LessOrEqual(t, utf8.RuneCountInString(decodedPath), attributeValueLengthLimit,
		"OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT kept %d runes of a U+FFFD request path", utf8.RuneCountInString(decodedPath))
}

// TestJaegerProviderCountsReplacementCharacter covers the Jaeger constructor,
// which also calls NewTracerProvider without WithSpanLimits.
func TestJaegerProviderCountsReplacementCharacter(t *testing.T) {
	t.Setenv("OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT", strconv.Itoa(attributeValueLengthLimit))
	t.Setenv("OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", "")

	ots := &TracingService{
		cfg: &TracingConfig{
			Address:       "127.0.0.1:6831",
			Sampler:       "const",
			SamplerParam:  1,
			CustomAttribs: []attribute.KeyValue{},
		},
		log: log.NewNopLogger(),
	}
	tp, err := ots.initJaegerTracerProvider()
	require.NoError(t, err)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	req := readRequest(t, "GET /"+strings.Repeat("%EF%BF%BD", replacementRunes)+" HTTP/1.1\r\nHost: example.test\r\n\r\n")
	_, span := tp.Tracer("request").Start(context.Background(), "HTTP GET <unknown>", trace.WithAttributes(
		semconv.HTTPURLKey.String(req.RequestURI),
		attribute.String("url.path", req.URL.Path),
		attribute.String("flag_key", "k"+strings.Repeat("\uFFFD", replacementRunes)),
	))
	span.End()

	attrs := spanAttributeMap(t, span)
	require.LessOrEqual(t, utf8.RuneCountInString(attrs["url.path"]), attributeValueLengthLimit,
		"Jaeger provider kept %d runes of a U+FFFD request path", utf8.RuneCountInString(attrs["url.path"]))
	require.LessOrEqual(t, utf8.RuneCountInString(attrs["flag_key"]), attributeValueLengthLimit,
		"Jaeger provider kept %d runes of a U+FFFD flag_key", utf8.RuneCountInString(attrs["flag_key"]))
}

func newInitTracer(t *testing.T) (*tracesdk.TracerProvider, *tracetest.InMemoryExporter) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp, err := initTracerProvider(exp, "grafana", "test", tracesdk.AlwaysSample(), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return tp, exp
}

func readRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	require.NoError(t, err)
	return req
}

// recordRequestAttributes stores the same request fields RequestTracing puts on
// the server span, on a provider built by initTracerProvider.
func recordRequestAttributes(t *testing.T, tracer trace.Tracer, req *http.Request) {
	t.Helper()
	_, span := tracer.Start(context.Background(), "HTTP GET <unknown>", trace.WithAttributes(
		semconv.HTTPURLKey.String(req.RequestURI),
		attribute.String("url.path", req.URL.Path),
		semconv.HTTPMethodKey.String(req.Method),
	))
	span.SetAttributes(attribute.String("flag_key", "k"+strings.Repeat("\uFFFD", replacementRunes)))
	span.End()
}

func attributeContaining(t *testing.T, spans tracetest.SpanStubs, key, needle string) string {
	t.Helper()
	for _, span := range spans {
		for _, attr := range span.Attributes {
			if string(attr.Key) == key && strings.Contains(attr.Value.AsString(), needle) {
				return attr.Value.AsString()
			}
		}
	}
	t.Fatalf("no %s attribute containing %q", key, needle)
	return ""
}

type spanAttrReader interface {
	Attributes() []attribute.KeyValue
}

func spanAttributeMap(t *testing.T, span trace.Span) map[string]string {
	t.Helper()
	reader, ok := span.(spanAttrReader)
	require.True(t, ok, "span does not expose recorded attributes")
	out := map[string]string{}
	for _, attr := range reader.Attributes() {
		out[string(attr.Key)] = attr.Value.AsString()
	}
	return out
}
