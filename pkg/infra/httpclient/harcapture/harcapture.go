// Package harcapture records datasource HTTP request/response pairs in memory and serializes them
// to HAR 1.2 for the on-demand diagnostics bundle.
//
// Entries are redacted as they are recorded, so the buffer never holds the credentials Grafana
// attaches to datasource requests: sensitive request/response headers (Authorization, Cookie,
// Proxy-Authorization, and any name containing token, secret, key, password, ...), all cookie
// values, URL userinfo, sensitive query parameters, sensitive form/JSON body fields, and credentials
// embedded in transport error text. See redact.go for the rules and for RedactHAREntry, which applies
// them to HAR produced outside this package. Redaction is name-based and cannot be exhaustive, so
// bundles should still be reviewed before they are shared.
package harcapture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chromedp/cdproto/har"
)

// encodeBody returns the HAR text representation of a body plus its encoding. Valid UTF-8 is stored
// as-is; binary payloads are base64-encoded (with encoding "base64") so they survive JSON marshaling
// intact instead of being corrupted by string() replacing invalid bytes with U+FFFD.
func encodeBody(body []byte) (text, encoding string) {
	if utf8.Valid(body) {
		return string(body), ""
	}
	return base64.StdEncoding.EncodeToString(body), "base64"
}

type contextKey struct{}

// Buffer collects HTTP request/response pairs as HAR 1.2 entries in memory.
type Buffer struct {
	mu      sync.Mutex
	entries []*har.Entry
	secrets SecretSet
}

// AddSecrets registers credential values, such as a datasource's decrypted secure settings, that are
// replaced wherever they appear in entries added afterwards. This covers credentials sent under a
// header or parameter name that name-based redaction does not recognize. Thread-safe.
func (b *Buffer) AddSecrets(values ...string) {
	b.mu.Lock()
	b.secrets = b.secrets.With(values...)
	b.mu.Unlock()
}

// WithCapture returns a child context carrying a new Buffer and the buffer itself.
func WithCapture(ctx context.Context) (context.Context, *Buffer) {
	buf := &Buffer{}
	return context.WithValue(ctx, contextKey{}, buf), buf
}

// FromContext returns the Buffer stored in ctx, or nil if absent.
func FromContext(ctx context.Context) *Buffer {
	v, _ := ctx.Value(contextKey{}).(*Buffer)
	return v
}

// AddEntry appends a captured request/response pair. rtErr is the RoundTrip error (nil on success);
// a transport-level failure (connection refused, DNS/TLS error, timeout) leaves resp nil and is
// recorded in the entry's comment. Thread-safe.
func (b *Buffer) AddEntry(req *http.Request, resp *http.Response, rtErr error, started time.Time, elapsed time.Duration) {
	e := buildEntry(req, resp, rtErr, started, elapsed)
	b.mu.Lock()
	b.secrets.scrubEntry(e)
	b.entries = append(b.entries, e)
	b.mu.Unlock()
}

// Len returns the number of captured entries. Thread-safe.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

// ToHAR serializes the captured entries to HAR 1.2 JSON. The entry types come from
// github.com/chromedp/cdproto/har -- the same library the plugin SDK's e2e HAR storage uses -- so
// the output stays replay-compatible with that fixture format.
func (b *Buffer) ToHAR() ([]byte, error) {
	b.mu.Lock()
	entries := make([]*har.Entry, len(b.entries))
	copy(entries, b.entries)
	b.mu.Unlock()

	doc := har.HAR{
		Log: &har.Log{
			Version: "1.2",
			Creator: &har.Creator{Name: "Grafana", Version: "1.0"},
			Entries: entries,
		},
	}
	return json.Marshal(doc)
}

// buildEntry builds a redacted HAR entry from a request/response pair (see the package doc).
func buildEntry(req *http.Request, resp *http.Response, rtErr error, started time.Time, elapsed time.Duration) *har.Entry {
	reqHeaders := toNameValues(req.Header)
	queryString := queryPairs(req.URL.Query())

	var pd *har.PostData
	var reqBodySize int64
	if req.Body != nil {
		body, readErr := io.ReadAll(req.Body)
		_ = req.Body.Close() // release the original body, as the RoundTripper contract requires
		if readErr != nil {
			// Restore the captured (partial) bytes followed by the error rather than leaving req.Body
			// consumed, so a caller of this shared helper can still read the body and observe the failure.
			req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), &errorReader{err: readErr}))
		} else {
			req.Body = io.NopCloser(bytes.NewReader(body))
			reqBodySize = int64(len(body))
			if len(body) > 0 {
				// HAR 1.2 PostData has no "encoding" field (only response Content does), so a
				// non-UTF-8 request body is base64-encoded into Text without a machine-readable
				// marker. base64 preserves the bytes (vs string() corrupting invalid UTF-8 to U+FFFD),
				// but a replay tool can't tell it's base64. Accepted: datasource request bodies are
				// text in practice, and body handling overall is a redaction/limits follow-up (#1281).
				text, encoding := encodeBody(body)
				if encoding == "" {
					text = redactBody(text, req.Header.Get("Content-Type"))
				}
				pd = &har.PostData{
					MimeType: req.Header.Get("Content-Type"),
					Text:     text,
				}
			}
		}
	}

	// Content is required by the HAR spec and dereferenced unconditionally by the SDK's replay, so
	// always attach a (possibly empty) Content, even for transport failures with no response body.
	harResp := &har.Response{HeadersSize: -1, Content: &har.Content{}}
	if resp != nil {
		harResp.Status = int64(resp.StatusCode)
		// HAR statusText is the reason phrase only ("OK"), but resp.Status is the full status line
		// ("200 OK"); strip the leading code (keeping the server's actual phrase).
		harResp.StatusText = strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
		harResp.HTTPVersion = resp.Proto
		harResp.Headers = toNameValues(resp.Header)
		harResp.Cookies = toCookies(resp.Cookies())
		harResp.RedirectURL = RedactURL(resp.Header.Get("Location"))
		if resp.Body != nil {
			// Drain then Close the original transport body so its connection is returned to the idle
			// pool (per the net/http contract), then hand the caller a fresh reader over the bytes.
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				// Preserve the original read failure for the caller: replay the captured bytes, then
				// surface the same error rather than silently substituting a truncated body.
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), &errorReader{err: readErr}))
			} else {
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
			harResp.BodySize = int64(len(body))
			text, encoding := encodeBody(body)
			if encoding == "" {
				text = redactBody(text, resp.Header.Get("Content-Type"))
			}
			harResp.Content = &har.Content{
				Size:     int64(len(body)),
				MimeType: resp.Header.Get("Content-Type"),
				Text:     text,
				Encoding: encoding,
			}
		}
	}

	var comment string
	if rtErr != nil {
		comment = "transport error: " + RedactText(rtErr.Error())
	}

	waitMs := float64(elapsed.Milliseconds())
	return &har.Entry{
		StartedDateTime: started.UTC().Format(time.RFC3339Nano),
		Time:            waitMs,
		Request: &har.Request{
			Method:      req.Method,
			URL:         RedactURL(req.URL.String()),
			HTTPVersion: req.Proto,
			Headers:     reqHeaders,
			QueryString: queryString,
			Cookies:     toCookies(req.Cookies()),
			PostData:    pd,
			BodySize:    reqBodySize,
			HeadersSize: -1,
		},
		Response: harResp,
		Cache:    &har.Cache{},
		Timings:  &har.Timings{Send: 0, Wait: waitMs, Receive: 0},
		Comment:  comment,
	}
}

// toNameValues flattens an http.Header into HAR name/value pairs, emitting one pair per value so
// repeated headers (e.g. multiple Set-Cookie) are preserved, in sorted order for deterministic output.
// Values are redacted by RedactHeaderValue.
func toNameValues(h http.Header) []*har.NameValuePair {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]*har.NameValuePair, 0, len(h))
	for _, name := range names {
		for _, v := range h[name] {
			result = append(result, &har.NameValuePair{Name: name, Value: RedactHeaderValue(name, v)})
		}
	}
	return result
}

// queryPairs flattens URL query values into HAR name/value pairs, sorted for deterministic output.
// Values of sensitive parameters are redacted.
func queryPairs(query map[string][]string) []*har.NameValuePair {
	names := make([]string, 0, len(query))
	for name := range query {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]*har.NameValuePair, 0, len(query))
	for _, name := range names {
		redact := IsSensitiveName(name)
		for _, v := range query[name] {
			if redact {
				v = RedactedValue
			} else {
				v = RedactText(v)
			}
			result = append(result, &har.NameValuePair{Name: name, Value: v})
		}
	}
	return result
}

// toCookies converts parsed HTTP cookies into HAR cookie entries (name/value), matching the SDK
// e2e HAR storage output so captured traffic stays replayable by the E2E fixture proxy. Values are
// always redacted: a cookie's name says little about whether its value is a session credential.
func toCookies(cookies []*http.Cookie) []*har.Cookie {
	result := make([]*har.Cookie, 0, len(cookies))
	for _, c := range cookies {
		result = append(result, &har.Cookie{Name: c.Name, Value: RedactedValue})
	}
	return result
}

// errorReader yields the wrapped error on Read. Used to re-surface a request/response body read
// failure to the caller after the captured (partial) bytes have been replayed.
type errorReader struct{ err error }

func (r *errorReader) Read([]byte) (int, error) { return 0, r.err }
