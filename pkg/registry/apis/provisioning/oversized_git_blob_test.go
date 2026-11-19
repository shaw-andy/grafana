package provisioning

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana-app-sdk/logging"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/quotas"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/git"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/jobs/sync"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

const (
	gitHTTPBackend           = "/usr/lib/git-core/git-http-backend"
	oversizedBlobBytes       = 512 * 1024
	blobReadCapBytes   int64 = 32 * 1024
	// Room for info/refs, the commit, and the tree. Stays under the blob.
	blobProtocolOverhead int64 = 128 * 1024
)

func TestFilesAPIGetRejectsOversizedGitBlobBeforeBufferingIt(t *testing.T) {
	srv, repoURL := startBlobGitServer(t, map[string][]byte{
		"README.md":           randomBlob(t, oversizedBlobBytes),
		"dashboards/big.json": randomBlob(t, oversizedBlobBytes),
		"NOTE.md":             []byte("hello"),
	})
	repo := newBlobGitRepo(t, repoURL)
	connector := NewFilesConnector(
		&fakeRepoGetter{repo: repo},
		stubParserFactory{},
		stubClientFactory{},
		allowAllAccess{},
		false,
		blobReadCapBytes,
	)

	t.Run("raw file", func(t *testing.T) {
		assertFilesGetStopsAtCap(t, srv, connector, "README.md")
	})
	t.Run("resource file", func(t *testing.T) {
		assertFilesGetStopsAtCap(t, srv, connector, "dashboards/big.json")
	})
	t.Run("file under the cap is returned", func(t *testing.T) {
		responder := &fakeResponder{}
		req := httptest.NewRequest(http.MethodGet, "/repo/files/NOTE.md", nil)
		connector.handleRequest(context.Background(), "repo", req, responder, logging.FromContext(context.Background()))
		require.NoError(t, responder.err)
		require.Equal(t, http.StatusOK, responder.statusCode)
	})
}

func TestSyncApplyRejectsOversizedGitBlobBeforeBufferingIt(t *testing.T) {
	srv, repoURL := startBlobGitServer(t, map[string][]byte{
		"dashboards/big.json": randomBlob(t, oversizedBlobBytes),
	})
	repo := newBlobGitRepo(t, repoURL)
	repo.WithMaxFileSize(blobReadCapBytes)

	t.Run("write resource from file", func(t *testing.T) {
		mgr := resources.NewResourcesManager(repo, nil, nil, nil)
		srv.ResetBytesWritten()
		_, _, _, err := mgr.WriteResourceFromFile(context.Background(), "dashboards/big.json", "main")
		assertBlobTransferStopped(t, srv, err)
	})

	t.Run("dual writer read", func(t *testing.T) {
		writer := resources.NewDualReadWriter(repo, nil, nil, allowAuthorizer{}, false)
		srv.ResetBytesWritten()
		_, err := writer.Read(context.Background(), "dashboards/big.json", "main")
		assertBlobTransferStopped(t, srv, err)
	})
}

func TestSyncWorkerReadRejectsOversizedGitBlobBeforeBufferingIt(t *testing.T) {
	srv, repoURL := startBlobGitServer(t, map[string][]byte{
		"dashboards/big.json": randomBlob(t, oversizedBlobBytes),
	})
	repo := newBlobGitRepo(t, repoURL)
	reader := &recordingSyncer{}
	worker := sync.NewSyncWorker(
		stubClientFactory{},
		stubResourcesFactory{},
		func(context.Context, *provisioning.Repository, ...map[string]interface{}) error { return nil },
		reader,
		jobs.JobMetrics{},
		tracing.NewNoopTracerService(),
		1,
		blobReadCapBytes,
	)
	job := provisioning.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "pull"},
		Spec: provisioning.JobSpec{
			Action: provisioning.JobActionPull,
			Pull:   &provisioning.SyncJobOptions{},
		},
	}

	srv.ResetBytesWritten()
	err := worker.Process(context.Background(), repo, job, stubProgress{})
	require.Error(t, err)
	require.Truef(t, apierrors.IsRequestEntityTooLargeError(reader.err), "sync read returned %v", reader.err)
	require.Lessf(t, srv.BytesWritten(), blobReadCapBytes+blobProtocolOverhead,
		"sync transferred %d bytes; cap is %d and the blob is %d",
		srv.BytesWritten(), blobReadCapBytes, oversizedBlobBytes)
}

func assertFilesGetStopsAtCap(t *testing.T, srv *countingBlobServer, connector *filesConnector, path string) {
	t.Helper()
	srv.ResetBytesWritten()
	responder := &fakeResponder{}
	req := httptest.NewRequest(http.MethodGet, "/repo/files/"+path, nil)
	connector.handleRequest(context.Background(), "repo", req, responder, logging.FromContext(req.Context()))
	require.Error(t, responder.err)
	assertBlobTransferStopped(t, srv, responder.err)
}

func assertBlobTransferStopped(t *testing.T, srv *countingBlobServer, err error) {
	t.Helper()
	require.Truef(t, apierrors.IsRequestEntityTooLargeError(err), "got %v", err)
	require.Lessf(t, srv.BytesWritten(), blobReadCapBytes+blobProtocolOverhead,
		"transferred %d bytes; cap is %d and the blob is %d",
		srv.BytesWritten(), blobReadCapBytes, oversizedBlobBytes)
}

func newBlobGitRepo(t *testing.T, repoURL string) git.GitRepository {
	t.Helper()
	cfg := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "repo", Namespace: "default"},
		Spec: provisioning.RepositorySpec{
			Type: provisioning.GitRepositoryType,
			Git:  &provisioning.GitRepositoryConfig{URL: repoURL, Branch: "main"},
			Sync: provisioning.SyncOptions{Target: provisioning.SyncTargetTypeFolderless},
		},
	}
	repo, err := git.NewRepository(context.Background(), cfg, git.RepositoryConfig{
		URL:    repoURL,
		Branch: "main",
	}, nil, nil)
	require.NoError(t, err)
	return repo
}

type allowAllAccess struct{}

func (allowAllAccess) Check(context.Context, authlib.CheckRequest, string) error { return nil }
func (a allowAllAccess) WithFallbackRole(identity.RoleType) auth.AccessChecker   { return a }

type allowAuthorizer struct{}

func (allowAuthorizer) AuthorizeResource(context.Context, *resources.ParsedResource, string) error {
	return nil
}
func (allowAuthorizer) AuthorizeCreateFolder(context.Context, string) error { return nil }
func (allowAuthorizer) AuthorizeDeleteByPath(context.Context, string) error { return nil }
func (allowAuthorizer) AuthorizeMoveByPath(context.Context, string, string) error {
	return nil
}
func (allowAuthorizer) AuthorizeUpdateFolder(context.Context, string) error { return nil }
func (allowAuthorizer) AuthorizeReadRawFile(context.Context, string) error  { return nil }
func (allowAuthorizer) AuthorizeWrite(context.Context, string) error        { return nil }
func (allowAuthorizer) AuthorizeReadAllSupported(context.Context) error     { return nil }
func (allowAuthorizer) AuthorizeCreateAllSupported(context.Context) error   { return nil }
func (allowAuthorizer) AuthorizeDeleteAllSupported(context.Context) error   { return nil }

type stubParserFactory struct{}

func (stubParserFactory) GetParser(context.Context, repository.Reader) (resources.Parser, error) {
	return stubParser{}, nil
}

type stubParser struct{}

func (stubParser) Parse(context.Context, *repository.FileInfo) (*resources.ParsedResource, error) {
	return nil, fmt.Errorf("parser should not run once the read is refused")
}

type stubClientFactory struct{}

func (stubClientFactory) Clients(context.Context, string) (resources.ResourceClients, error) {
	return stubClients{}, nil
}

type stubClients struct{}

func (stubClients) ForKind(context.Context, schema.GroupVersionKind) (dynamic.ResourceInterface, schema.GroupVersionResource, error) {
	return nil, schema.GroupVersionResource{}, fmt.Errorf("not used")
}
func (stubClients) ForResource(context.Context, schema.GroupVersionResource) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	return nil, schema.GroupVersionKind{}, fmt.Errorf("not used")
}
func (stubClients) Folder(context.Context) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	return nil, schema.GroupVersionKind{Group: "folder.grafana.app", Version: "v1beta1", Kind: "Folder"}, nil
}
func (stubClients) User(context.Context) (dynamic.ResourceInterface, error) {
	return nil, fmt.Errorf("not used")
}
func (stubClients) SupportedResources() []resources.SupportedResource { return nil }

type stubResourcesFactory struct{}

func (stubResourcesFactory) Client(context.Context, repository.ReaderWriter, ...resources.RepositoryResourcesOption) (resources.RepositoryResources, error) {
	return stubResources{}, nil
}

type stubResources struct{}

func (stubResources) SetTree(resources.FolderTree) {}
func (stubResources) EnsureFolderPathExist(context.Context, string, string, ...resources.EnsurePathOption) (string, error) {
	return "", nil
}
func (stubResources) EnsureFolderExists(context.Context, resources.Folder, string) error { return nil }
func (stubResources) EnsureFolderTreeExists(context.Context, resources.FolderTree, resources.EnsureFolderTreeExistsOptions) error {
	return nil
}
func (stubResources) RemoveFolderFromTree(string)                {}
func (stubResources) RemoveFolder(context.Context, string) error { return nil }
func (stubResources) RenameFolderPath(context.Context, string, string, string, string, ...resources.EnsurePathOption) (string, error) {
	return "", nil
}
func (stubResources) WriteResourceFileFromObject(context.Context, *unstructured.Unstructured, resources.WriteOptions) (string, int, error) {
	return "", 0, nil
}
func (stubResources) WriteResourceFromFile(context.Context, string, string, ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	return "", schema.GroupVersionKind{}, 0, nil
}
func (stubResources) ReplaceResourceFromFile(context.Context, string, string, string, schema.GroupVersionResource, ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	return "", schema.GroupVersionKind{}, 0, nil
}
func (stubResources) ReplaceResourceFromFileByRef(context.Context, string, string, string, ...resources.WriteResourceOption) (string, schema.GroupVersionKind, int, error) {
	return "", schema.GroupVersionKind{}, 0, nil
}
func (stubResources) RemoveResourceFromFile(context.Context, string, string) (string, string, schema.GroupVersionKind, int, error) {
	return "", "", schema.GroupVersionKind{}, 0, nil
}
func (stubResources) FindResourcePath(context.Context, string, schema.GroupVersionKind) (string, error) {
	return "", nil
}
func (stubResources) RenameResourceFile(context.Context, string, string, string, string, ...resources.EnsurePathOption) (string, string, schema.GroupVersionKind, int, error) {
	return "", "", schema.GroupVersionKind{}, 0, nil
}
func (stubResources) Stats(context.Context) (*provisioning.ResourceStats, error) {
	return &provisioning.ResourceStats{}, nil
}
func (stubResources) List(context.Context) (*provisioning.ResourceList, error) {
	return &provisioning.ResourceList{}, nil
}

type recordingSyncer struct {
	err error
}

func (s *recordingSyncer) Sync(ctx context.Context, repo repository.ReaderWriter, _ provisioning.SyncJobOptions, _ resources.RepositoryResources, _ resources.ResourceClients, _ jobs.JobProgressRecorder, _ quotas.QuotaTracker) (string, error) {
	_, s.err = repo.Read(ctx, "dashboards/big.json", "main")
	return "main", s.err
}

type stubProgress struct{}

func (stubProgress) Started() time.Time                                       { return time.Now() }
func (stubProgress) Record(context.Context, jobs.JobResourceResult)           {}
func (stubProgress) RecordDryRun(context.Context, jobs.JobResourceResult)     {}
func (stubProgress) ResetResults(bool)                                        {}
func (stubProgress) SetFinalMessage(context.Context, string)                  {}
func (stubProgress) SetMessage(context.Context, string)                       {}
func (stubProgress) SetTotal(context.Context, int)                            {}
func (stubProgress) SetVariance(string)                                       {}
func (stubProgress) Variance() string                                         { return "" }
func (stubProgress) TooManyErrors() error                                     { return nil }
func (stubProgress) StrictMaxErrors(int)                                      {}
func (stubProgress) SetRefURLs(context.Context, *provisioning.RepositoryURLs) {}
func (stubProgress) Complete(context.Context, error) provisioning.JobStatus {
	return provisioning.JobStatus{State: provisioning.JobStateError}
}
func (stubProgress) ResultReasons() []string              { return nil }
func (stubProgress) HasDirPathFailedCreation(string) bool { return false }
func (stubProgress) HasDirPathFailedDeletion(string) bool { return false }
func (stubProgress) HasChildPathFailedCreation(string) bool {
	return false
}
func (stubProgress) HasChildPathFailedUpdate(string) bool { return false }

type countingBlobServer struct {
	written atomic.Int64
	srv     *http.Server
}

func (s *countingBlobServer) ResetBytesWritten()  { s.written.Store(0) }
func (s *countingBlobServer) BytesWritten() int64 { return s.written.Load() }

type countingBlobListener struct {
	net.Listener
	written *atomic.Int64
}

func (l *countingBlobListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetWriteBuffer(1024)
	}
	return &countingBlobConn{Conn: c, written: l.written}, nil
}

type countingBlobConn struct {
	net.Conn
	written *atomic.Int64
}

func (c *countingBlobConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

func startBlobGitServer(t *testing.T, files map[string][]byte) (*countingBlobServer, string) {
	t.Helper()
	if _, err := os.Stat(gitHTTPBackend); err != nil {
		t.Fatalf("git http backend: %v", err)
	}
	root := t.TempDir()
	bare := filepath.Join(root, "owner", "repo.git")
	seedBlobRepo(t, bare, files)

	out := &countingBlobServer{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	out.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveBlobGitCGI(t, root, w, r)
	})}
	go func() { _ = out.srv.Serve(&countingBlobListener{Listener: ln, written: &out.written}) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = out.srv.Shutdown(ctx)
	})
	return out, "http://" + ln.Addr().String() + "/owner/repo.git"
}

func seedBlobRepo(t *testing.T, bareDir string, files map[string][]byte) {
	t.Helper()
	work := t.TempDir()
	runBlobGit(t, work, "init", "-b", "main")
	runBlobGit(t, work, "config", "user.email", "dev@example.com")
	runBlobGit(t, work, "config", "user.name", "Dev")
	for name, body := range files {
		path := filepath.Join(work, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, body, 0o644))
	}
	runBlobGit(t, work, "add", ".")
	runBlobGit(t, work, "commit", "-m", "seed")
	require.NoError(t, os.MkdirAll(filepath.Dir(bareDir), 0o755))
	runBlobGit(t, work, "clone", "--bare", work, bareDir)
	runBlobGit(t, bareDir, "config", "uploadpack.allowFilter", "true")
	runBlobGit(t, bareDir, "config", "uploadpack.allowAnySHA1InWant", "true")
}

func runBlobGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %s: %s", strings.Join(args, " "), out)
}

func serveBlobGitCGI(t *testing.T, projectRoot string, w http.ResponseWriter, r *http.Request) {
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
				if n, convErr := strconv.Atoi(code); convErr == nil {
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

func randomBlob(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return buf
}
