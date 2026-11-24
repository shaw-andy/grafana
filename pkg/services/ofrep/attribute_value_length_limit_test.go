package ofrep

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	goffmodel "github.com/thomaspoignant/go-feature-flag/cmd/relayproxy/model"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// The tracer provider is built the way Grafana's tracing service builds it:
// NewTracerProvider with no WithSpanLimits, so the SDK applies
// OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT from the environment.
const fffdAttributeLimit = 16
const fffdReplacementRunes = 64

// TestRequestTracingAndOFREPCountReplacementCharacter sends unauthenticated
// requests whose path and flag key are dominated by U+FFFD and checks the
// recorded span attributes. Those characters are valid and must count toward
// the configured limit. The test fails while they are retained in full.
func TestRequestTracingAndOFREPCountReplacementCharacter(t *testing.T) {
	t.Setenv("OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT", strconv.Itoa(fffdAttributeLimit))
	t.Setenv("OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT", "")

	exp := tracetest.NewInMemoryExporter()
	tp := tracesdk.NewTracerProvider(
		tracesdk.WithSyncer(exp),
		tracesdk.WithSampler(tracesdk.AlwaysSample()),
	)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	srv := startFFFDServer(t, tp)
	client := srv.Client()

	asciiPath := "/" + strings.Repeat("a", fffdReplacementRunes)
	sendFFFD(t, client, srv, http.MethodGet, asciiPath, nil)

	replacementPath := "/" + strings.Repeat("\uFFFD", fffdReplacementRunes)
	sendFFFD(t, client, srv, http.MethodGet, replacementPath, nil)

	flagKey := "k" + strings.Repeat("\uFFFD", fffdReplacementRunes)
	resp := sendFFFD(t, client, srv, http.MethodPost, "/ofrep/v1/evaluate/flags/"+flagKey, strings.NewReader(`{}`))
	require.Equal(t, http.StatusOK, resp)

	rawStatus := sendRawFFFDTarget(t, srv, replacementPath)

	spans := exp.GetSpans()
	require.NotEmpty(t, spans)

	asciiURLPath := fffdAttrPrefix(t, spans, "url.path", "/aaa")
	require.LessOrEqual(t, utf8.RuneCountInString(asciiURLPath), fffdAttributeLimit)
	require.Less(t, utf8.RuneCountInString(asciiURLPath), utf8.RuneCountInString(asciiPath),
		"the length limit was not applied to an ordinary request path")

	encodedURL := fffdAttrContains(t, spans, "http.url", "%EF%BF%BD")
	require.LessOrEqual(t, utf8.RuneCountInString(encodedURL), fffdAttributeLimit,
		"percent-encoded request targets are ordinary text and must be truncated")

	decodedPath := fffdAttrContains(t, spans, "url.path", "\uFFFD")
	require.LessOrEqual(t, utf8.RuneCountInString(decodedPath), fffdAttributeLimit,
		"RequestTracing kept %d runes of a U+FFFD url.path", utf8.RuneCountInString(decodedPath))

	flag := fffdAttrContains(t, spans, "flag_key", "k\uFFFD")
	require.LessOrEqual(t, utf8.RuneCountInString(flag), fffdAttributeLimit,
		"ofrep kept %d runes of a U+FFFD flag_key", utf8.RuneCountInString(flag))

	if rawStatus > 0 {
		rawURL := fffdAttrContains(t, spans, "http.url", "\uFFFD")
		require.LessOrEqual(t, utf8.RuneCountInString(rawURL), fffdAttributeLimit,
			"RequestTracing kept %d runes of a raw U+FFFD request target", utf8.RuneCountInString(rawURL))
	}
}

func startFFFDServer(t *testing.T, tp *tracesdk.TracerProvider) *httptest.Server {
	t.Helper()
	builder, err := NewAPIBuilder(setting.StaticProviderType, nil, true, "", fffdFlagEvaluator{})
	require.NoError(t, err)

	m := web.New()
	m.Use(middleware.RequestTracing(tp.Tracer("request"), middleware.ShouldTraceWithExceptions))
	m.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := web.FromContext(r.Context())
			if c == nil {
				http.Error(w, "missing request context", http.StatusInternalServerError)
				return
			}
			reqCtx := &contextmodel.ReqContext{Context: c, Logger: log.NewNopLogger()}
			r = r.WithContext(ctxkey.Set(r.Context(), reqCtx))
			c.Req = r
			next.ServeHTTP(w, r)
		})
	})

	rr := routing.NewRouteRegister(middleware.ProvideRouteOperationName)
	builder.RegisterHTTPRoutes(rr)
	rr.Register(m)

	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return srv
}

func sendFFFD(t *testing.T, client *http.Client, srv *httptest.Server, method, path string, body io.Reader) int {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func sendRawFFFDTarget(t *testing.T, srv *httptest.Server, requestTarget string) int {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	_, err = io.WriteString(conn, "GET "+requestTarget+" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func fffdAttrContains(t *testing.T, spans tracetest.SpanStubs, key, needle string) string {
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

func fffdAttrPrefix(t *testing.T, spans tracetest.SpanStubs, key, prefix string) string {
	t.Helper()
	for _, span := range spans {
		for _, attr := range span.Attributes {
			if string(attr.Key) == key && strings.HasPrefix(attr.Value.AsString(), prefix) {
				return attr.Value.AsString()
			}
		}
	}
	t.Fatalf("no %s attribute with prefix %q", key, prefix)
	return ""
}

type fffdFlagEvaluator struct{}

func (fffdFlagEvaluator) EvalFlag(context.Context, string) (goffmodel.OFREPEvaluateSuccessResponse, error) {
	return goffmodel.OFREPEvaluateSuccessResponse{}, nil
}

func (fffdFlagEvaluator) EvalAllFlags(context.Context) (goffmodel.OFREPBulkEvaluateSuccessResponse, error) {
	return goffmodel.OFREPBulkEvaluateSuccessResponse{}, nil
}

var _ featuremgmt.StaticFlagEvaluator = fffdFlagEvaluator{}
