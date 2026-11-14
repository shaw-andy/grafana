package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// multipartReserve is the extra in-memory budget mime/multipart.Reader.ReadForm
// adds on top of the maxMemory argument (go1.26.6 src/mime/multipart/formdata.go).
const multipartReserve = int64(10 << 20)

// headerLimitCliff is one byte under the 400-byte overhead readMIMEHeader
// subtracts before applying the per-line cap (go1.26.6 src/net/textproto/reader.go).
const headerLimitCliff = int64(399)

const mapEntryOverhead = 200

const oversizeHeader = 1 << 20

const readSlack = 64 << 10

// formValueMaxMemory is net/http.Request.FormValue's maxMemory argument
// (go1.26.6 src/net/http/request.go, defaultMaxMemory).
const formValueMaxMemory = int64(32 << 20)

func TestGetURLPrefsMultipartHeaderMemoryLimit(t *testing.T) {
	// NotFoundHandler calls setIndexViewData, which calls getURLPrefs, for any
	// unmatched POST or PUT whose path is not under /api. getURLPrefs is the
	// call that parses the body.
	const maxMemory = int64(1024)
	orig := web.MaxMemory
	web.MaxMemory = maxMemory
	t.Cleanup(func() { web.MaxMemory = orig })

	assertProductReadIsBounded(t, maxMemory, func(req *http.Request) {
		c := &contextmodel.ReqContext{Context: &web.Context{Req: req}}
		_ = getURLPrefs(c)
	})
}

func TestQueryBoolWithDefaultMultipartHeaderMemoryLimit(t *testing.T) {
	const maxMemory = int64(1024)
	orig := web.MaxMemory
	web.MaxMemory = maxMemory
	t.Cleanup(func() { web.MaxMemory = orig })

	assertProductReadIsBounded(t, maxMemory, func(req *http.Request) {
		c := &contextmodel.ReqContext{Context: &web.Context{Req: req}}
		_ = c.QueryBoolWithDefault("flag", false)
	})
}

func TestLoginRedirectMultipartHeaderMemoryLimit(t *testing.T) {
	// LoginView calls tryAutoLogin, which calls getRedirectToForAutoLogin when
	// an auto-login provider is configured. That reads the body via FormValue,
	// which parses multipart with net/http's own maxMemory, not web.MaxMemory.
	hs := &HTTPServer{Cfg: &setting.Cfg{}}
	assertProductReadIsBounded(t, formValueMaxMemory, func(req *http.Request) {
		req.Method = http.MethodGet
		req.URL.Path = "/login"
		c := &contextmodel.ReqContext{Context: &web.Context{Req: req}}
		_ = hs.getRedirectToForAutoLogin(c)
	})
}

func assertProductReadIsBounded(t *testing.T, maxMemory int64, invoke func(*http.Request)) {
	t.Helper()

	prefixLen, body := multipartBodyPastHeaderCliff(t, maxMemory, oversizeHeader)
	counter := &countReader{r: bytes.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/no-such-page", counter)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=bnd")

	invoke(req)

	if counter.n > int64(prefixLen)+readSlack {
		t.Fatalf("parser read %d bytes of the part header that starts once the remaining memory budget is below 400 bytes (prefix %d, oversize %d); the line cap was not applied", counter.n-int64(prefixLen), prefixLen, oversizeHeader)
	}
}

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
