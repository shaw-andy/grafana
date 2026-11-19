package github

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/git"
)

const gitHTTPBackend = "/usr/lib/git-core/git-http-backend"

// oversizedBlobBytes is larger than the cap the tests install and smaller than
// nanogit's unpacked-object ceiling, so a successful fetch returns the whole
// object to Read. The bytes are incompressible so the packfile on the wire
// stays about this large.
const oversizedBlobBytes = 512 * 1024

// readCapBytes is the provisioning file-size cap installed for these tests.
// It stands in for the 5 MiB default: Read applies whatever value was stored,
// and the production default is covered by TestProvisioningMaxFileSizeDefault.
const readCapBytes int64 = 32 * 1024

// protocolOverheadBytes bounds the info/refs, commit, and tree responses that
// a bounded read still has to transfer. It stays well under oversizedBlobBytes.
const protocolOverheadBytes int64 = 128 * 1024

func TestGitReadRejectsOversizedBlobBeforeBufferingIt(t *testing.T) {
	srv, repoURL := startGitHTTPServer(t, map[string][]byte{
		"dashboards/big.json": randomBytes(t, oversizedBlobBytes),
		"README.md":           randomBytes(t, oversizedBlobBytes),
		"ok.json":             []byte(`{"apiVersion":"v1","kind":"Config","metadata":{"name":"ok"}}`),
	})

	repo := newGitRepo(t, repoURL)
	repo.WithMaxFileSize(readCapBytes)

	t.Run("oversized resource", func(t *testing.T) {
		assertReadStopsAtCap(t, srv, repo, "dashboards/big.json")
	})
	t.Run("oversized raw file", func(t *testing.T) {
		assertReadStopsAtCap(t, srv, repo, "README.md")
	})
	t.Run("file under the cap is returned whole", func(t *testing.T) {
		info, err := repo.Read(context.Background(), "ok.json", "main")
		require.NoError(t, err)
		require.Equal(t, `{"apiVersion":"v1","kind":"Config","metadata":{"name":"ok"}}`, string(info.Data))
	})
	t.Run("disabled cap still returns the oversized blob", func(t *testing.T) {
		unlimited := newGitRepo(t, repoURL)
		info, err := unlimited.Read(context.Background(), "dashboards/big.json", "main")
		require.NoError(t, err)
		require.Len(t, info.Data, oversizedBlobBytes)
	})
}

func TestGitHubRepositoryReadRejectsOversizedBlobBeforeBufferingIt(t *testing.T) {
	payload := randomBytes(t, oversizedBlobBytes)
	srv, repoURL := startGitHTTPServer(t, map[string][]byte{
		"dashboards/big.json": payload,
	})

	gitRepo := newGitRepo(t, repoURL)
	gh, err := NewRepository(
		context.Background(),
		gitRepo.Config(),
		gitRepo,
		ProvideFactory(),
		"",
	)
	require.NoError(t, err)
	gh.WithMaxFileSize(readCapBytes)

	assertReadStopsAtCap(t, srv, gh, "dashboards/big.json")
}

func assertReadStopsAtCap(t *testing.T, srv *countingGitServer, reader repository.Reader, path string) {
	t.Helper()

	srv.ResetBytesWritten()
	info, err := reader.Read(context.Background(), path, "main")
	written := srv.BytesWritten()

	require.Error(t, err)
	require.Nil(t, info)
	require.Truef(t, apierrors.IsRequestEntityTooLargeError(err), "got %v", err)
	// The refusal has to happen before the blob body is on the wire. A check
	// that runs after GetBlobByPath has already pulled the object still
	// transfers about oversizedBlobBytes and fails here. Re-reading the same
	// path between the check and the use fails the same way.
	require.Lessf(t, written, readCapBytes+protocolOverheadBytes,
		"read of %s transferred %d bytes; cap is %d and the blob is %d",
		path, written, readCapBytes, oversizedBlobBytes)
}

func newGitRepo(t *testing.T, repoURL string) git.GitRepository {
	t.Helper()
	cfg := &provisioning.Repository{
		Spec: provisioning.RepositorySpec{
			Type: provisioning.GitRepositoryType,
			Git:  &provisioning.GitRepositoryConfig{URL: repoURL, Branch: "main"},
		},
	}
	repo, err := git.NewRepository(context.Background(), cfg, git.RepositoryConfig{
		URL:    repoURL,
		Branch: "main",
	}, nil, nil)
	require.NoError(t, err)
	return repo
}

type countingGitServer struct {
	url     string
	written atomic.Int64
	srv     *http.Server
	ln      net.Listener
}

func (s *countingGitServer) ResetBytesWritten()  { s.written.Store(0) }
func (s *countingGitServer) BytesWritten() int64 { return s.written.Load() }

func startGitHTTPServer(t *testing.T, files map[string][]byte) (*countingGitServer, string) {
	t.Helper()
	if _, err := os.Stat(gitHTTPBackend); err != nil {
		t.Fatalf("git http backend: %v", err)
	}

	root := t.TempDir()
	repoDir := filepath.Join(root, "owner", "repo.git")
	seedBareRepo(t, repoDir, files)

	out := &countingGitServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveGitCGI(t, root, w, r)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	out.ln = &countingListener{Listener: ln, written: &out.written}
	out.srv = &http.Server{Handler: handler}
	go func() { _ = out.srv.Serve(out.ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = out.srv.Shutdown(ctx)
	})

	out.url = "http://" + ln.Addr().String() + "/owner/repo.git"
	return out, out.url
}

type countingListener struct {
	net.Listener
	written *atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Keep the kernel from accepting the whole blob into the send buffer
	// before the client has read it. Otherwise a refused read still counts
	// as a full transfer.
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetWriteBuffer(1024)
	}
	return &countingConn{Conn: c, written: l.written}, nil
}

type countingConn struct {
	net.Conn
	written *atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

func seedBareRepo(t *testing.T, bareDir string, files map[string][]byte) {
	t.Helper()
	work := t.TempDir()
	runGit(t, work, "init", "-b", "main")
	runGit(t, work, "config", "user.email", "dev@example.com")
	runGit(t, work, "config", "user.name", "Dev")
	for name, body := range files {
		path := filepath.Join(work, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, body, 0o644))
	}
	runGit(t, work, "add", ".")
	runGit(t, work, "commit", "-m", "seed")
	require.NoError(t, os.MkdirAll(filepath.Dir(bareDir), 0o755))
	runGit(t, work, "clone", "--bare", work, bareDir)
	// nanogit asks upload-pack for a blobless commit fetch. Stock git hides
	// that command unless the filter capability is turned on.
	runGit(t, bareDir, "config", "http.receivepack", "true")
	runGit(t, bareDir, "config", "uploadpack.allowFilter", "true")
	runGit(t, bareDir, "config", "uploadpack.allowAnySHA1InWant", "true")
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %s: %s", strings.Join(args, " "), out)
}

func serveGitCGI(t *testing.T, projectRoot string, w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command(gitHTTPBackend)
	cmd.Env = append(os.Environ(),
		"GIT_PROJECT_ROOT="+projectRoot,
		"GIT_HTTP_EXPORT_ALL=1",
		"REQUEST_METHOD="+r.Method,
		"QUERY_STRING="+r.URL.RawQuery,
		"PATH_INFO="+r.URL.Path,
		"CONTENT_TYPE="+r.Header.Get("Content-Type"),
		"CONTENT_LENGTH="+strconv.FormatInt(r.ContentLength, 10),
		"HTTP_GIT_PROTOCOL="+r.Header.Get("Git-Protocol"),
		"HTTP_USER_AGENT="+r.Header.Get("User-Agent"),
		"REMOTE_ADDR="+r.RemoteAddr,
		"SERVER_PROTOCOL=HTTP/1.1",
	)
	cmd.Stdin = r.Body
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cmd.Start(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	br := bufio.NewReader(stdout)
	status := http.StatusOK
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			errOut, _ := io.ReadAll(stderr)
			_ = cmd.Wait()
			http.Error(w, fmt.Sprintf("cgi header: %v: %s", err, errOut), http.StatusBadGateway)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if strings.EqualFold(name, "Status") {
			if code, _, ok := strings.Cut(value, " "); ok {
				if n, err := strconv.Atoi(code); err == nil {
					status = n
				}
			}
			continue
		}
		w.Header().Add(name, value)
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, br)
	errOut, _ := io.ReadAll(stderr)
	if err := cmd.Wait(); err != nil {
		t.Logf("git-http-backend: %v: %s", err, errOut)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return buf
}
