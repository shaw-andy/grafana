package web_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/web"
)

// multipartReserve is the extra in-memory budget mime/multipart.Reader.ReadForm
// adds on top of the maxMemory argument (go1.26.6 src/mime/multipart/formdata.go).
const multipartReserve = int64(10 << 20)

// headerLimitCliff is one byte under the 400-byte overhead readMIMEHeader
// subtracts before applying the per-line cap (go1.26.6 src/net/textproto/reader.go).
// A part that starts with a remaining budget below 400 makes that subtraction
// negative, and readLineSlice treats a negative limit as unlimited.
const headerLimitCliff = int64(399)

const mapEntryOverhead = 200

// oversizeHeader is large enough that a bounded read (one 4096-byte bufio fill
// in mime/multipart) stays under the slack below, and an unlimited read does not.
const oversizeHeader = 1 << 20

const readSlack = 64 << 10

func TestMultipartHeaderMemoryLimit(t *testing.T) {
	// A positive maxMemory still has a multi-megabyte budget. The bypass is not
	// the initial argument being tiny; it is the budget falling below 400 bytes
	// before a later part's headers are parsed.
	const maxMemory = int64(1024)
	orig := web.MaxMemory
	web.MaxMemory = maxMemory
	t.Cleanup(func() { web.MaxMemory = orig })

	// QueryBool, QueryInt, QueryInt64, QueryFloat64 and the WithDefault helpers
	// all call Query, which calls parseForm. Each case still sends its own body
	// so a regression in one wrapper is visible.
	cases := []struct {
		name    string
		method  string
		path    string
		handler func(*web.Context)
	}{
		{"post query", http.MethodPost, "/query", func(c *web.Context) { _ = c.Query("lang") }},
		{"post query strings", http.MethodPost, "/strings", func(c *web.Context) { _ = c.QueryStrings("lang") }},
		{"post query bool", http.MethodPost, "/bool", func(c *web.Context) { _ = c.QueryBool("on") }},
		{"put query int", http.MethodPut, "/int", func(c *web.Context) { _ = c.QueryInt("limit") }},
		{"put query int default", http.MethodPut, "/intd", func(c *web.Context) { _ = c.QueryIntWithDefault("limit", 1) }},
		{"post query int64", http.MethodPost, "/int64", func(c *web.Context) { _ = c.QueryInt64("n") }},
		{"post query int64 default", http.MethodPost, "/int64d", func(c *web.Context) { _ = c.QueryInt64WithDefault("n", 1) }},
		{"put query float64", http.MethodPut, "/float", func(c *web.Context) { _ = c.QueryFloat64("n") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := web.New()
			handler := tc.handler
			if tc.method == http.MethodPut {
				m.Put(tc.path, func(c *web.Context) {
					handler(c)
					c.Resp.WriteHeader(http.StatusNoContent)
				})
			} else {
				m.Post(tc.path, func(c *web.Context) {
					handler(c)
					c.Resp.WriteHeader(http.StatusNoContent)
				})
			}
			assertHeaderReadIsBounded(t, m, tc.method, tc.path, maxMemory)
		})
	}

	t.Run("post unmatched route", func(t *testing.T) {
		m := web.New()
		m.NotFound(func(c *web.Context) {
			// Same calls NotFoundHandler makes via getURLPrefs for a non-API path.
			_ = c.Query("lang")
			_ = c.Query("theme")
			c.Resp.WriteHeader(http.StatusNotFound)
		})
		assertHeaderReadIsBounded(t, m, http.MethodPost, "/no-such-page", maxMemory)
	})
}

func assertHeaderReadIsBounded(t *testing.T, m *web.Macaron, method, path string, maxMemory int64) {
	t.Helper()

	prefixLen, body := multipartBodyPastHeaderCliff(t, maxMemory, oversizeHeader)
	counter := &countReader{r: bytes.NewReader(body)}
	req := httptest.NewRequest(method, path, counter)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=bnd")
	rec := httptest.NewRecorder()

	m.ServeHTTP(rec, req)

	if counter.n > int64(prefixLen)+readSlack {
		t.Fatalf("parser read %d bytes of the part header that starts once the remaining memory budget is below 400 bytes (prefix %d, oversize %d); the line cap was not applied", counter.n-int64(prefixLen), prefixLen, oversizeHeader)
	}
}

// multipartBodyPastHeaderCliff returns a multipart body whose first part leaves
// fewer than 400 bytes of ReadForm budget, followed by a single header line of
// oversize bytes. prefixLen is the number of body bytes before that line's value.
func multipartBodyPastHeaderCliff(t *testing.T, maxMemory int64, oversize int) (prefixLen int, body []byte) {
	t.Helper()

	const name = "a"
	start := maxMemory + multipartReserve
	contentLen := start - int64(len(name)) - mapEntryOverhead - headerLimitCliff
	if contentLen <= 0 {
		t.Fatalf("content length %d is not positive", contentLen)
	}

	var buf bytes.Buffer
	buf.WriteString("--bnd\r\n")
	buf.WriteString("Content-Disposition: form-data; name=\"a\"\r\n\r\n")
	buf.Write(bytes.Repeat([]byte("A"), int(contentLen)))
	buf.WriteString("\r\n--bnd\r\n")
	buf.WriteString("X-Evil: ")
	prefixLen = buf.Len()
	buf.Write(bytes.Repeat([]byte("B"), oversize))
	buf.WriteString("\r\n\r\n--bnd--\r\n")
	return prefixLen, buf.Bytes()
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countReader) Close() error { return nil }
