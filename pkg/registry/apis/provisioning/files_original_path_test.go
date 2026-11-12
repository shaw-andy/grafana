package provisioning

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	authlib "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/client-go/dynamic"

	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioningapi "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/local"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

const outsideFileMarker = "outside-file-marker"

func TestFilesMoveOriginalPathDoesNotEscapeRepository(t *testing.T) {
	root := t.TempDir()
	repoDir := filepath.Join(root, "repo")
	outside := filepath.Join(root, "outside")
	require.NoError(t, os.Mkdir(repoDir, 0o700))
	require.NoError(t, os.Mkdir(outside, 0o700))

	cfg := &provisioningapi.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "local-repo", Namespace: "default"},
		Spec: provisioningapi.RepositorySpec{
			Type:      provisioningapi.LocalRepositoryType,
			Workflows: []provisioningapi.Workflow{provisioningapi.WriteWorkflow},
			Local:     &provisioningapi.LocalRepositoryConfig{Path: repoDir},
		},
	}
	repo := local.NewRepository(cfg, &local.LocalFolderResolver{
		PermittedPrefixes: []string{repoDir},
		HomePath:          repoDir,
	}, nil)
	connector := &filesConnector{
		getter:                stubRepoGetter{repo: repo},
		parsers:               resources.NewParserFactory(stubClientFactory{}, false),
		clients:               stubClientFactory{},
		access:                allowAccess{},
		folderMetadataEnabled: false,
		maxFileSize:           5 * 1024 * 1024,
	}

	t.Run("regular file outside the repository is not opened", func(t *testing.T) {
		secret := filepath.Join(outside, "secret.json")
		require.NoError(t, os.WriteFile(secret, []byte(outsideFileMarker), 0o600))
		watch := newOpenWatch(t, secret)

		responder := postOriginalPath(t, connector, repoDir, secret, time.Second)
		require.False(t, watch.opened(), "move read a file outside the repository before rejecting it")
		require.Error(t, responder.err)
		require.Nil(t, responder.obj)
		require.NotContains(t, responder.err.Error(), outsideFileMarker)
		_, err := os.Stat(filepath.Join(repoDir, "dummy.json"))
		require.ErrorIs(t, err, os.ErrNotExist)
		body, err := os.ReadFile(secret)
		require.NoError(t, err)
		require.Equal(t, outsideFileMarker, string(body))
	})

	t.Run("existing and missing paths return the same error", func(t *testing.T) {
		directory := filepath.Join(outside, "subdir")
		require.NoError(t, os.Mkdir(directory, 0o700))
		missing := filepath.Join(outside, "missing.json")

		found := postOriginalPath(t, connector, repoDir, directory, time.Second)
		absent := postOriginalPath(t, connector, repoDir, missing, time.Second)
		require.Error(t, found.err)
		require.Error(t, absent.err)
		require.Nil(t, found.obj)
		require.Nil(t, absent.obj)
		require.Equal(t, statusCode(absent.err), statusCode(found.err))
		require.Equal(t,
			redactPaths(statusMessage(absent.err), missing, relativePath(t, repoDir, missing)),
			redactPaths(statusMessage(found.err), directory, relativePath(t, repoDir, directory)))
		_, err := os.Stat(filepath.Join(repoDir, "dummy.json"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("zero size non regular file does not block the request", func(t *testing.T) {
		dev, err := os.Stat("/dev/zero")
		require.NoError(t, err)
		require.Zero(t, dev.Size())
		require.False(t, dev.Mode().IsRegular())

		fifo := filepath.Join(outside, "zero-fifo")
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))
		info, err := os.Stat(fifo)
		require.NoError(t, err)
		require.Zero(t, info.Size())
		require.False(t, info.Mode().IsRegular())

		watch := newOpenWatch(t, fifo)
		responder := postOriginalPath(t, connector, repoDir, fifo, 2*time.Second)
		require.False(t, watch.opened(), "move opened a zero-size non-regular file")
		require.Error(t, responder.err)
		require.Nil(t, responder.obj)
	})
}

func postOriginalPath(t *testing.T, connector *filesConnector, repoDir, target string, wait time.Duration) *recordingResponder {
	t.Helper()
	rel, err := filepath.Rel(repoDir, target)
	require.NoError(t, err)
	require.Contains(t, rel, "..")

	req := httptest.NewRequest(http.MethodPost, "/local-repo/files/dummy.json", nil)
	query := req.URL.Query()
	query.Set("originalPath", filepath.ToSlash(rel))
	req.URL.RawQuery = query.Encode()
	responder := &recordingResponder{}

	// The files route is wrapped with the connector timeout. The deadline is
	// short here so a read that ignores cancellation fails the test.
	timed := WithTimeout(connector, 100*time.Millisecond)
	connecter, ok := timed.(rest.Connecter)
	require.True(t, ok)
	handler, err := connecter.Connect(context.Background(), "local-repo", nil, responder)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}()
	select {
	case <-done:
		return responder
	case <-time.After(wait):
		t.Fatalf("files move did not return for originalPath %s", query.Get("originalPath"))
		return responder
	}
}

func redactPaths(message string, paths ...string) string {
	for _, p := range paths {
		message = strings.ReplaceAll(message, p, "PATH")
		message = strings.ReplaceAll(message, filepath.ToSlash(p), "PATH")
	}
	return message
}

func relativePath(t *testing.T, repoDir, target string) string {
	t.Helper()
	rel, err := filepath.Rel(repoDir, target)
	require.NoError(t, err)
	return filepath.ToSlash(rel)
}

func statusCode(err error) int32 {
	return statusOf(err).Code
}

func statusMessage(err error) string {
	return statusOf(err).Message
}

func statusOf(err error) metav1.Status {
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		return status.Status()
	}
	if err == nil {
		return metav1.Status{}
	}
	return metav1.Status{Message: err.Error()}
}

type stubRepoGetter struct{ repo repository.Repository }

func (s stubRepoGetter) GetRepository(context.Context, string) (repository.Repository, error) {
	return s.repo, nil
}

func (s stubRepoGetter) GetHealthyRepository(context.Context, string) (repository.Repository, error) {
	return s.repo, nil
}

type stubClientFactory struct{}

func (stubClientFactory) Clients(context.Context, string) (resources.ResourceClients, error) {
	return resourceClientsStub{}, nil
}

type resourceClientsStub struct{}

func (resourceClientsStub) ForKind(context.Context, schema.GroupVersionKind) (dynamic.ResourceInterface, schema.GroupVersionResource, error) {
	return nil, schema.GroupVersionResource{}, nil
}

func (resourceClientsStub) ForResource(context.Context, schema.GroupVersionResource) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	return nil, schema.GroupVersionKind{}, nil
}

func (resourceClientsStub) Folder(context.Context) (dynamic.ResourceInterface, schema.GroupVersionKind, error) {
	return nil, schema.GroupVersionKind{Group: "folder.grafana.app", Version: "v1beta1", Kind: "Folder"}, nil
}

func (resourceClientsStub) User(context.Context) (dynamic.ResourceInterface, error) {
	return nil, nil
}

func (resourceClientsStub) SupportedResources() []resources.SupportedResource { return nil }

type allowAccess struct{}

func (allowAccess) Check(context.Context, authlib.CheckRequest, string) error { return nil }

func (allowAccess) WithFallbackRole(identity.RoleType) auth.AccessChecker { return allowAccess{} }

type openWatch struct {
	t  *testing.T
	fd int
}

func newOpenWatch(t *testing.T, path string) *openWatch {
	t.Helper()
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(fd) })
	_, err = syscall.InotifyAddWatch(fd, path, syscall.IN_OPEN)
	require.NoError(t, err)
	return &openWatch{t: t, fd: fd}
}

func (w *openWatch) opened() bool {
	w.t.Helper()
	buf := make([]byte, 4096)
	opened := false
	for {
		n, err := syscall.Read(w.fd, buf)
		if n >= syscall.SizeofInotifyEvent && consumeOpenEvents(buf[:n]) {
			opened = true
		}
		if err != nil || n < syscall.SizeofInotifyEvent {
			return opened
		}
	}
}

func consumeOpenEvents(buf []byte) bool {
	opened := false
	for off := 0; off+syscall.SizeofInotifyEvent <= len(buf); {
		mask := uint32(buf[off+4]) | uint32(buf[off+5])<<8 | uint32(buf[off+6])<<16 | uint32(buf[off+7])<<24
		nameLen := int(uint32(buf[off+12]) | uint32(buf[off+13])<<8 | uint32(buf[off+14])<<16 | uint32(buf[off+15])<<24)
		if mask&syscall.IN_OPEN != 0 {
			opened = true
		}
		next := off + syscall.SizeofInotifyEvent + nameLen
		if next <= off || next > len(buf) {
			break
		}
		off = next
	}
	return opened
}
