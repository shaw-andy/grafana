package frontend

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gokitlog "github.com/go-kit/log"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/log/text"
	"github.com/grafana/grafana/pkg/setting"
)

// maxFrontendBootErrorBodyBytes is the most a boot-error request may cause the
// server to buffer. The shipped boot script calls this URL with an empty body,
// so a few kilobytes is the whole allowance. A fix that only inspects
// Content-Length, or that reads the body to completion and then rejects it,
// still fails the tests below: the chunked request has no Content-Length, and
// the server must answer before the client finishes the body.
const maxFrontendBootErrorBodyBytes = 8 << 10

func TestFrontendBootErrorBodyLimit(t *testing.T) {
	addr, logPath := startFrontendServer(t)

	t.Run("empty body without credentials is accepted", func(t *testing.T) {
		status, respBody := roundTripBootError(t, addr, bootErrorRequest("", nil))
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "OK", strings.TrimSpace(respBody))
	})

	// One byte past the allowance, and the client never ends the body. The
	// handler has to stop reading and respond; waiting for EOF is the bug.
	over := bytes.Repeat([]byte("A"), maxFrontendBootErrorBodyBytes+1)
	copy(over, []byte("BOOTERREARLYMARKER"))

	t.Run("chunked body is rejected before it ends", func(t *testing.T) {
		raw := bootErrorRequest("Transfer-Encoding: chunked\r\n", chunkedPayload(over, false))
		before := readLog(t, logPath)
		status, _ := roundTripBootError(t, addr, raw)
		require.Equal(t, http.StatusRequestEntityTooLarge, status)
		assertBodyNotLogged(t, before, readLog(t, logPath), "BOOTERREARLYMARKER")
	})

	t.Run("content-length body is rejected before it ends", func(t *testing.T) {
		// The declared length is far past what we actually send, so a check of
		// the header and a read of the stream are different. Either may reject,
		// but the handler must not block until the declared length arrives.
		header := fmt.Sprintf("Content-Length: %d\r\n", 1<<20)
		before := readLog(t, logPath)
		status, _ := roundTripBootError(t, addr, bootErrorRequest(header, over))
		require.Equal(t, http.StatusRequestEntityTooLarge, status)
		assertBodyNotLogged(t, before, readLog(t, logPath), "BOOTERREARLYMARKER")
	})

	t.Run("completed oversized bodies are rejected and not logged", func(t *testing.T) {
		payload := bytes.Repeat([]byte("B"), 64<<10)
		copy(payload, []byte("BOOTERROVERMARKER"))
		// A newline and a fake record must not be persisted either. The log
		// encoder may escape them; the payload bytes themselves must not land
		// in the file.
		copy(payload[len("BOOTERROVERMARKER"):], []byte("\nlevel=error msg=forged-boot-line\n"))

		before := readLog(t, logPath)
		chunked := bootErrorRequest("Transfer-Encoding: chunked\r\n", chunkedPayload(payload, true))
		chunkedStatus, _ := roundTripBootError(t, addr, chunked)

		withLength := bootErrorRequest(fmt.Sprintf("Content-Length: %d\r\n", len(payload)), payload)
		lengthStatus, _ := roundTripBootError(t, addr, withLength)

		assertBodyNotLogged(t, before, readLog(t, logPath), "BOOTERROVERMARKER")
		assertBodyNotLogged(t, before, readLog(t, logPath), "forged-boot-line")
		require.Equal(t, http.StatusRequestEntityTooLarge, chunkedStatus)
		require.Equal(t, http.StatusRequestEntityTooLarge, lengthStatus)
	})

	t.Run("a small body is not written to the error log", func(t *testing.T) {
		payload := bytes.Repeat([]byte("C"), 1024)
		copy(payload, []byte("BOOTERRSMALLMARKER"))
		raw := bootErrorRequest(fmt.Sprintf("Content-Length: %d\r\n", len(payload)), payload)
		before := readLog(t, logPath)
		status, _ := roundTripBootError(t, addr, raw)
		require.Contains(t, []int{http.StatusOK, http.StatusRequestEntityTooLarge}, status)
		assertBodyNotLogged(t, before, readLog(t, logPath), "BOOTERRSMALLMARKER")
	})
}

func startFrontendServer(t *testing.T) (string, string) {
	t.Helper()

	publicDir := setupTestWebAssets(t)
	cfg := &setting.Cfg{
		Raw:            ini.Empty(),
		HTTPPort:       "3000",
		StaticRootPath: publicDir,
	}
	service := createTestService(t, cfg)
	logPath := attachBootErrorLog(t, service)

	server := service.newFrontendServer(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		_ = server.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	return ln.Addr().String(), logPath
}

// attachBootErrorLog points the service logger at the same file writer and
// text encoding the default [log.file] format uses, so a body copied into
// s.log.Error shows up on disk.
func attachBootErrorLog(t *testing.T, service *frontendService) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "grafana.log")
	writer := log.NewFileWriter()
	writer.Filename = path
	writer.Rotate = false
	writer.Daily = false
	writer.Format = func(w io.Writer) gokitlog.Logger {
		return text.NewTextLogger(w)
	}
	require.NoError(t, writer.Init())
	t.Cleanup(func() { _ = writer.Close() })

	service.log.(*log.ConcreteLogger).Swap(writer)
	return path
}

func bootErrorRequest(extraHeaders string, body []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("GET /-/fe-boot-error?ts=1 HTTP/1.1\r\n")
	buf.WriteString("Host: 127.0.0.1\r\n")
	buf.WriteString(extraHeaders)
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func chunkedPayload(payload []byte, finished bool) []byte {
	var buf bytes.Buffer
	const size = 1024
	for len(payload) > 0 {
		n := size
		if n > len(payload) {
			n = len(payload)
		}
		fmt.Fprintf(&buf, "%x\r\n", n)
		buf.Write(payload[:n])
		buf.WriteString("\r\n")
		payload = payload[n:]
	}
	if finished {
		buf.WriteString("0\r\n\r\n")
	}
	return buf.Bytes()
}

func roundTripBootError(t *testing.T, addr string, raw []byte) (int, string) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write(raw)
		writeDone <- writeErr
	}()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	require.NoError(t, err, "frontend server kept reading the boot-error body instead of rejecting it")

	var proto string
	var status int
	_, err = fmt.Sscanf(statusLine, "%s %d", &proto, &status)
	require.NoError(t, err, "status line %q", statusLine)

	contentLength := -1
	for {
		line, readErr := reader.ReadString('\n')
		require.NoError(t, readErr)
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		const prefix = "Content-Length:"
		if len(line) >= len(prefix) && strings.EqualFold(line[:len(prefix)], prefix) {
			_, scanErr := fmt.Sscanf(strings.TrimSpace(line[len(prefix):]), "%d", &contentLength)
			require.NoError(t, scanErr)
		}
	}

	var respBody []byte
	if contentLength > 0 {
		respBody = make([]byte, contentLength)
		_, err = io.ReadFull(reader, respBody)
		require.NoError(t, err)
	}
	select {
	case <-writeDone:
	case <-time.After(200 * time.Millisecond):
	}
	return status, string(respBody)
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func assertBodyNotLogged(t *testing.T, before string, after string, marker string) {
	t.Helper()
	require.True(t, strings.HasPrefix(after, before), "error log was rewritten")
	growth := after[len(before):]
	if strings.Contains(growth, marker) || len(growth) >= maxFrontendBootErrorBodyBytes {
		t.Errorf("error log grew by %d bytes and retained the boot-error request body", len(growth))
	}
}
