package web

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

// multipartHeaderSlack is larger than the multipart bufio buffer (4096) and
// smaller than the oversized header line. A parser that enforces the remaining
// memory limit stops inside this window. A parser that bypasses the limit
// reads the whole line.
const multipartHeaderSlack = 32 << 10

func TestMultipartHeaderMemoryLimit(t *testing.T) {
	body, contentType, headerAt := multipartBodyUnderHeaderLimit(t)

	calls := []struct {
		name string
		call func(*Context)
	}{
		{name: "Query", call: func(ctx *Context) { ctx.Query("lang") }},
		{name: "QueryStrings", call: func(ctx *Context) { ctx.QueryStrings("lang") }},
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, call := range calls {
			t.Run(method+"/"+call.name, func(t *testing.T) {
				cr := &countingReader{r: bytes.NewReader(body)}
				req := httptest.NewRequest(method, "http://example.test/no-such-page", cr)
				req.Header.Set("Content-Type", contentType)
				req.ContentLength = int64(len(body))

				call.call(&Context{Req: req})

				if cr.n > int64(headerAt)+multipartHeaderSlack {
					t.Fatalf("read %d body bytes; oversized MIME header starts at %d. parseForm read that header past the remaining memory limit (slack %d)", cr.n, headerAt, multipartHeaderSlack)
				}
			})
		}
	}
}

// multipartBodyUnderHeaderLimit builds a multipart body that spends
// ParseMultipartForm's in-memory budget (MaxMemory plus the 10MiB mime/multipart
// reserves for non-file parts, then len(name)+200 for the first part) down to
// 100 bytes. The next part then starts with less than the 400 bytes
// net/textproto subtracts before reading a header line, and that line is much
// longer than the remaining budget.
func multipartBodyUnderHeaderLimit(t *testing.T) (body []byte, contentType string, headerAt int) {
	t.Helper()
	const (
		partName = "p"
		reserve  = int64(10 << 20)
		perPart  = int64(len(partName) + 200)
		remain   = int64(100)
		headerN  = 128 << 10
	)
	fillerN := MaxMemory + reserve - perPart - remain
	if fillerN <= 0 || remain >= 400 {
		t.Fatalf("cannot place the next part under the 400-byte header overhead: filler=%d remain=%d", fillerN, remain)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	field, err := w.CreateFormField(partName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := field.Write(bytes.Repeat([]byte("B"), int(fillerN))); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(&buf, "\r\n--%s\r\nX: ", w.Boundary()); err != nil {
		t.Fatal(err)
	}
	headerAt = buf.Len()
	if _, err := buf.Write(bytes.Repeat([]byte("A"), headerN)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(&buf, "\r\n\r\nv\r\n--%s--\r\n", w.Boundary()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), w.FormDataContentType(), headerAt
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
