package provisioning

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioningapi "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository/local"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

// outsideMarker is a stand-in for bytes stored outside the repository. It is not a credential.
const outsideMarker = "OUTSIDE-MARKER-f4504840"

type recordingAccess struct {
	mu    sync.Mutex
	calls []authlib.CheckRequest
	err   error
}

func (r *recordingAccess) Check(_ context.Context, req authlib.CheckRequest, _ string) error {
	r.mu.Lock()
	r.calls = append(r.calls, req)
	r.mu.Unlock()
	return r.err
}

func (r *recordingAccess) WithFallbackRole(identity.RoleType) auth.AccessChecker {
	return r
}

func TestHandleGetRawFile_SymlinkOutsideAuthorizedFolder(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "team"), 0o750))
	target := filepath.Join(outside, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte(outsideMarker), 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(root, "team", "notes.md")))

	cfg := &provisioningapi.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "my-repo"},
		Spec: provisioningapi.RepositorySpec{
			Type: provisioningapi.LocalRepositoryType,
			Sync: provisioningapi.SyncOptions{Target: provisioningapi.SyncTargetTypeFolder},
			Local: &provisioningapi.LocalRepositoryConfig{
				Path: root,
			},
		},
	}
	repo := local.NewRepository(cfg, &local.LocalFolderResolver{
		PermittedPrefixes: []string{root},
		HomePath:          root,
	}, repository.RegisterOperationMetrics(prometheus.NewRegistry()))
	repo.WithMaxFileSize(5 * 1024 * 1024)

	access := &recordingAccess{}
	authorizer := resources.NewAuthorizer(cfg, repo, access, resources.NewMockResourceClients(t), false)
	connector := &filesConnector{access: access}

	req := httptest.NewRequest(http.MethodGet, "/my-repo/files/team/notes.md", nil)
	opts, err := connector.parseRequestOptions(req, "my-repo", repo)
	require.NoError(t, err)
	require.Equal(t, "team/notes.md", opts.Path)

	result, err := connector.handleGetRawFile(context.Background(), opts, repo, authorizer)
	if result != nil {
		content, _ := result.Resource.File.Object["content"].(string)
		if strings.Contains(content, outsideMarker) {
			t.Fatalf("files API returned the symlink target after authorizing folder %q", resources.ParseFolder("team/", cfg.Name).ID)
		}
	}
	require.Error(t, err)

	require.NotEmpty(t, access.calls)
	require.Equal(t, resources.ParseFolder("team/", cfg.Name).ID, access.calls[0].Name)
	require.NotContains(t, access.calls[0].Name, outsideMarker)
}

func TestHandleGetRawFile_DeniedFolderDoesNotOpenSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "team"), 0o750))
	fifo := filepath.Join(outside, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	require.NoError(t, os.Symlink(fifo, filepath.Join(root, "team", "notes.md")))

	cfg := &provisioningapi.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "my-repo"},
		Spec: provisioningapi.RepositorySpec{
			Type: provisioningapi.LocalRepositoryType,
			Sync: provisioningapi.SyncOptions{Target: provisioningapi.SyncTargetTypeFolder},
			Local: &provisioningapi.LocalRepositoryConfig{
				Path: root,
			},
		},
	}
	repo := local.NewRepository(cfg, &local.LocalFolderResolver{
		PermittedPrefixes: []string{root},
		HomePath:          root,
	}, repository.RegisterOperationMetrics(prometheus.NewRegistry()))

	access := &recordingAccess{err: errDenied()}
	authorizer := resources.NewAuthorizer(cfg, repo, access, resources.NewMockResourceClients(t), false)
	connector := &filesConnector{access: access}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = connector.handleGetRawFile(context.Background(), resources.DualWriteOptions{Path: "team/notes.md"}, repo, authorizer)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err == nil {
			_ = writer.Close()
		}
		<-done
		t.Fatal("raw file read opened the symlink target before authorization failed")
	}
	require.NotEmpty(t, access.calls)
}

func TestListFolderFiles_SymlinkHash(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	payload := []byte(outsideMarker)
	target := filepath.Join(outside, "target.txt")
	require.NoError(t, os.WriteFile(target, payload, 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(root, "notes.md")))

	cfg := &provisioningapi.Repository{
		ObjectMeta: metav1.ObjectMeta{Name: "my-repo"},
		Spec: provisioningapi.RepositorySpec{
			Type: provisioningapi.LocalRepositoryType,
			Local: &provisioningapi.LocalRepositoryConfig{
				Path: root,
			},
		},
	}
	repo := local.NewRepository(cfg, &local.LocalFolderResolver{
		PermittedPrefixes: []string{root},
		HomePath:          root,
	}, repository.RegisterOperationMetrics(prometheus.NewRegistry()))

	sum := sha1.Sum(payload)
	outsideHash := hex.EncodeToString(sum[:])
	list, err := (&filesConnector{}).listFolderFiles(context.Background(), "", "", repo)
	if err != nil {
		return
	}
	for _, item := range list.Items {
		require.NotEqual(t, outsideHash, item.Hash, "file listing published the symlink target hash")
	}
}

func errDenied() error {
	return &deniedError{}
}

type deniedError struct{}

func (deniedError) Error() string { return "denied" }

func (deniedError) Status() metav1.Status {
	return metav1.Status{Status: metav1.StatusFailure, Reason: metav1.StatusReasonForbidden, Code: 403}
}
