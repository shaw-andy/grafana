package cloudmigrationimpl

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	snapshot "github.com/grafana/grafana-cloud-migration-snapshot/src"
	"github.com/grafana/grafana/pkg/services/cloudmigration"
	"github.com/grafana/grafana/pkg/services/cloudmigration/gmsclient"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util"
)

const (
	snapshotPathEscapeOrgID = int64(1)
	snapshotMarkerBody      = "snapshot-boundary-marker"
	outsideIndexSentinel    = "outside-index-sentinel"
	outsideDataSentinel     = "outside-data-sentinel"
	safeSnapshotID          = "11111111-1111-4111-8111-111111111111"
)

// TestCloudMigrationSnapshotPathEscape is the spec for the snapshot-id path
// traversal. It fails while a migration-service snapshot ID can be joined
// under the snapshot folder and that joined path is then removed, written, or
// opened outside the folder.
func TestCloudMigrationSnapshotPathEscape(t *testing.T) {
	s := setUpServiceTest(t).(*Service)

	t.Run("delete parent directory chosen by snapshot id", func(t *testing.T) {
		root := t.TempDir()
		dataDir := filepath.Join(root, "data")
		snapshotFolder := filepath.Join(dataDir, "cloud_migration")
		marker := filepath.Join(dataDir, "grafana.db")
		writeMarker(t, marker)
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeDb

		id := snapshotIDResolvingOutside(t, snapshotFolder, dataDir)
		sess := insertMigrationSession(t, s)
		created, createErr := createSnapshotWithID(t, s, sess.UID, id)
		if createErr == nil && created != nil {
			_, deleteErr := s.DeleteSession(context.Background(), snapshotPathEscapeOrgID, migrationUser(), sess.UID)
			createErr = joinErrors(createErr, deleteErr)
		}
		waitForBuilder(t, s)

		assertMarkerIntact(t, marker, created, createErr)
		require.Error(t, createErr)
	})

	t.Run("delete stored parent directory", func(t *testing.T) {
		root := t.TempDir()
		dataDir := filepath.Join(root, "data")
		snapshotFolder := filepath.Join(dataDir, "cloud_migration")
		marker := filepath.Join(dataDir, "grafana.db")
		writeMarker(t, marker)
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder

		// The directory persisted for this ID is the one delete reloads.
		localDir := filepath.Join(snapshotFolder, "grafana", "snapshots", snapshotIDResolvingOutside(t, snapshotFolder, dataDir))
		require.Equal(t, dataDir, filepath.Clean(localDir))
		sess := insertMigrationSession(t, s)
		insertSnapshot(t, s, sess.UID, localDir)
		requireStoredDirectory(t, s, sess.UID, localDir)

		_, deleteErr := s.DeleteSession(context.Background(), snapshotPathEscapeOrgID, migrationUser(), sess.UID)
		assertMarkerIntact(t, marker, &cloudmigration.CloudMigrationSnapshot{LocalDir: localDir}, deleteErr)
	})

	t.Run("delete sibling directory whose prefix matches the snapshot folder", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		sibling := filepath.Join(root, "data", "cloud_migration-extra")
		marker := filepath.Join(sibling, "secret.txt")
		writeMarker(t, marker)
		require.True(t, strings.HasPrefix(sibling, snapshotFolder), "fixture must defeat a boundary-blind prefix check")
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeDb

		id := snapshotIDResolvingOutside(t, snapshotFolder, sibling)
		sess := insertMigrationSession(t, s)
		created, createErr := createSnapshotWithID(t, s, sess.UID, id)
		if createErr == nil && created != nil {
			_, _ = s.DeleteSession(context.Background(), snapshotPathEscapeOrgID, migrationUser(), sess.UID)
		}
		waitForBuilder(t, s)

		assertMarkerIntact(t, marker, created, createErr)
		require.Error(t, createErr)
	})

	t.Run("delete stored sibling directory", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		sibling := filepath.Join(root, "data", "cloud_migration-extra")
		marker := filepath.Join(sibling, "secret.txt")
		writeMarker(t, marker)
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder

		sess := insertMigrationSession(t, s)
		insertSnapshot(t, s, sess.UID, sibling)
		requireStoredDirectory(t, s, sess.UID, sibling)

		_, deleteErr := s.DeleteSession(context.Background(), snapshotPathEscapeOrgID, migrationUser(), sess.UID)
		assertMarkerIntact(t, marker, &cloudmigration.CloudMigrationSnapshot{LocalDir: sibling}, deleteErr)
	})

	t.Run("delete file through a symlink stored under the snapshot folder", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		victimDir := filepath.Join(root, "victim")
		marker := filepath.Join(victimDir, "keep.txt")
		writeMarker(t, marker)
		link := filepath.Join(snapshotFolder, "grafana", "snapshots", "alias")
		require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
		require.NoError(t, os.Symlink(victimDir, link))
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeDb

		// The joined path is still lexically inside the snapshot folder.
		// Removal follows the symlink, so the check has to resolve the same path it deletes.
		id := filepath.Join("alias", "keep.txt")
		joined := filepath.Join(snapshotFolder, "grafana", "snapshots", id)
		rel, err := filepath.Rel(snapshotFolder, joined)
		require.NoError(t, err)
		require.False(t, rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)))

		sess := insertMigrationSession(t, s)
		created, createErr := createSnapshotWithID(t, s, sess.UID, id)
		if createErr == nil && created != nil {
			_, _ = s.DeleteSession(context.Background(), snapshotPathEscapeOrgID, migrationUser(), sess.UID)
		}
		waitForBuilder(t, s)

		assertMarkerIntact(t, marker, created, createErr)
		require.Error(t, createErr)
	})

	t.Run("delete stored symlink path", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		victimDir := filepath.Join(root, "victim")
		marker := filepath.Join(victimDir, "keep.txt")
		writeMarker(t, marker)
		link := filepath.Join(snapshotFolder, "grafana", "snapshots", "alias")
		require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
		require.NoError(t, os.Symlink(victimDir, link))
		localDir := filepath.Join(link, "keep.txt")
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder

		sess := insertMigrationSession(t, s)
		insertSnapshot(t, s, sess.UID, localDir)
		requireStoredDirectory(t, s, sess.UID, localDir)

		_, deleteErr := s.DeleteSession(context.Background(), snapshotPathEscapeOrgID, migrationUser(), sess.UID)
		assertMarkerIntact(t, marker, &cloudmigration.CloudMigrationSnapshot{LocalDir: localDir}, deleteErr)
	})

	t.Run("filesystem build writes outside the snapshot folder", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		escaped := filepath.Join(root, "escaped")
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeFs

		id := snapshotIDResolvingOutside(t, snapshotFolder, escaped)
		sess := insertMigrationSession(t, s)
		created, createErr := createSnapshotWithID(t, s, sess.UID, id)
		if createErr == nil && created != nil {
			waitForSnapshotBuild(t, s, sess.UID, created.UID, escaped)
		} else {
			waitForBuilder(t, s)
		}

		_, statErr := os.Stat(escaped)
		require.ErrorIs(t, statErr, os.ErrNotExist, "snapshot build created %s (createErr=%v localDir=%s)", escaped, createErr, localDirOf(created))
		require.Error(t, createErr)
	})

	t.Run("buildSnapshot refuses a stored directory outside the snapshot folder", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		escaped := filepath.Join(root, "escaped")
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeFs

		sess := insertMigrationSession(t, s)
		snap := insertSnapshot(t, s, sess.UID, escaped)
		err := s.buildSnapshot(context.Background(), migrationUser(), 10, []byte("{}"), snap, cloudmigration.ResourceTypes{}, string(cloudmigration.EncryptionAlgoNacl))

		_, statErr := os.Stat(escaped)
		require.ErrorIs(t, statErr, os.ErrNotExist, "buildSnapshot created %s", escaped)
		require.Error(t, err)
	})

	t.Run("filesystem build follows a symlink that is a single snapshot id segment", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		victimDir := filepath.Join(root, "victim")
		require.NoError(t, os.MkdirAll(victimDir, 0o750))
		link := filepath.Join(snapshotFolder, "grafana", "snapshots", "alias")
		require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
		require.NoError(t, os.Symlink(victimDir, link))
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeFs

		sess := insertMigrationSession(t, s)
		created, createErr := createSnapshotWithID(t, s, sess.UID, "alias")
		if createErr == nil && created != nil {
			waitForSnapshotBuild(t, s, sess.UID, created.UID, filepath.Join(victimDir, "index.json"))
		} else {
			waitForBuilder(t, s)
		}

		_, statErr := os.Stat(filepath.Join(victimDir, "index.json"))
		require.ErrorIs(t, statErr, os.ErrNotExist, "snapshot writer followed symlink into %s (createErr=%v)", victimDir, createErr)
		require.Error(t, createErr)
	})

	t.Run("buildSnapshot refuses a stored symlink directory", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		victimDir := filepath.Join(root, "victim")
		require.NoError(t, os.MkdirAll(victimDir, 0o750))
		link := filepath.Join(snapshotFolder, "grafana", "snapshots", "alias")
		require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
		require.NoError(t, os.Symlink(victimDir, link))
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeFs

		sess := insertMigrationSession(t, s)
		snap := insertSnapshot(t, s, sess.UID, link)
		err := s.buildSnapshot(context.Background(), migrationUser(), 10, []byte("{}"), snap, cloudmigration.ResourceTypes{}, string(cloudmigration.EncryptionAlgoNacl))

		_, statErr := os.Stat(filepath.Join(victimDir, "index.json"))
		require.ErrorIs(t, statErr, os.ErrNotExist, "buildSnapshot wrote through %s", link)
		require.Error(t, err)
	})

	t.Run("upload reads files from a stored directory outside the snapshot folder", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		escaped := filepath.Join(root, "escaped")
		writeSnapshotTree(t, escaped, map[string][]string{"DATASOURCE": {"part.bin"}}, map[string]string{"part.bin": outsideDataSentinel})
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeFs

		sess := insertMigrationSession(t, s)
		snap := insertSnapshot(t, s, sess.UID, escaped)
		capture := &captureUpload{}
		s.objectStorage = capture
		session := reloadSession(t, s, sess.UID)
		loaded := reloadSnapshot(t, s, sess.UID, snap.UID)
		err := s.uploadSnapshot(context.Background(), session, loaded, "http://127.0.0.1/upload")

		require.NotContains(t, capture.bodies(), outsideDataSentinel)
		require.NotContains(t, capture.bodies(), outsideIndexSentinel)
		require.Error(t, err)
		assertMarkerIntact(t, filepath.Join(escaped, "part.bin"), loaded, err)
	})

	t.Run("upload follows a symlink stored under the snapshot folder", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		victimDir := filepath.Join(root, "victim")
		writeSnapshotTree(t, victimDir, map[string][]string{"DATASOURCE": {"part.bin"}}, map[string]string{"part.bin": outsideDataSentinel})
		link := filepath.Join(snapshotFolder, "grafana", "snapshots", "alias")
		require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o750))
		require.NoError(t, os.Symlink(victimDir, link))
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeFs

		sess := insertMigrationSession(t, s)
		snap := insertSnapshot(t, s, sess.UID, link)
		capture := &captureUpload{}
		s.objectStorage = capture
		session := reloadSession(t, s, sess.UID)
		loaded := reloadSnapshot(t, s, sess.UID, snap.UID)
		err := s.uploadSnapshot(context.Background(), session, loaded, "http://127.0.0.1/upload")

		require.NotContains(t, capture.bodies(), outsideDataSentinel)
		require.Error(t, err)
	})

	t.Run("upload rejects an index file name that leaves the snapshot folder", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		localDir := filepath.Join(snapshotFolder, "grafana", "snapshots", safeSnapshotID)
		marker := filepath.Join(root, "outside.bin")
		writeMarker(t, marker)
		fileName, err := filepath.Rel(localDir, marker)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(fileName, ".."))
		require.Equal(t, marker, filepath.Clean(filepath.Join(localDir, fileName)))
		writeSnapshotTree(t, localDir, map[string][]string{"DATASOURCE": {fileName}}, nil)
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeFs

		sess := insertMigrationSession(t, s)
		snap := insertSnapshot(t, s, sess.UID, localDir)
		capture := &captureUpload{}
		s.objectStorage = capture
		session := reloadSession(t, s, sess.UID)
		loaded := reloadSnapshot(t, s, sess.UID, snap.UID)
		err = s.uploadSnapshot(context.Background(), session, loaded, "http://127.0.0.1/upload")

		require.NotContains(t, capture.bodies(), snapshotMarkerBody)
		require.Error(t, err)
		assertMarkerIntact(t, marker, loaded, err)
	})

	t.Run("a single safe snapshot id still builds and deletes only its own directory", func(t *testing.T) {
		root := t.TempDir()
		snapshotFolder := filepath.Join(root, "data", "cloud_migration")
		marker := filepath.Join(root, "untouched.txt")
		writeMarker(t, marker)
		s.cfg.CloudMigration.SnapshotFolder = snapshotFolder
		s.cfg.CloudMigration.ResourceStorageType = cloudmigration.ResourceStorageTypeDb

		sess := insertMigrationSession(t, s)
		created, err := createSnapshotWithID(t, s, sess.UID, safeSnapshotID)
		require.NoError(t, err)
		require.NotNil(t, created)
		waitForSnapshotBuild(t, s, sess.UID, created.UID, "")
		owned := filepath.Join(created.LocalDir, "owned.txt")
		require.NoError(t, os.MkdirAll(created.LocalDir, 0o750))
		require.NoError(t, os.WriteFile(owned, []byte(snapshotMarkerBody), 0o600))

		_, err = s.DeleteSession(context.Background(), snapshotPathEscapeOrgID, migrationUser(), sess.UID)
		require.NoError(t, err)
		assertMarkerIntact(t, marker, created, err)
		_, statErr := os.Stat(owned)
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})
}

func snapshotIDResolvingOutside(t *testing.T, snapshotFolder, target string) string {
	t.Helper()
	id, err := filepath.Rel(filepath.Join(snapshotFolder, "grafana", "snapshots"), target)
	require.NoError(t, err)
	joined := filepath.Join(snapshotFolder, "grafana", "snapshots", id)
	require.Equal(t, filepath.Clean(target), filepath.Clean(joined))
	rel, err := filepath.Rel(snapshotFolder, joined)
	require.NoError(t, err)
	require.True(t, rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)))
	return id
}

func migrationUser() *user.SignedInUser {
	return &user.SignedInUser{UserUID: "user-uid", OrgID: snapshotPathEscapeOrgID, Login: "admin"}
}

func insertMigrationSession(t *testing.T, s *Service) *cloudmigration.CloudMigrationSession {
	t.Helper()
	sess, err := s.store.CreateMigrationSession(context.Background(), cloudmigration.CloudMigrationSession{
		OrgID:       snapshotPathEscapeOrgID,
		AuthToken:   "placeholder-token",
		Slug:        "stack",
		StackID:     1,
		RegionSlug:  "region",
		ClusterSlug: "cluster",
	})
	require.NoError(t, err)
	return sess
}

func createSnapshotWithID(t *testing.T, s *Service, sessionUID, snapshotID string) (*cloudmigration.CloudMigrationSnapshot, error) {
	t.Helper()
	s.gmsClient = snapshotIDClient{id: snapshotID}
	return s.CreateSnapshot(context.Background(), migrationUser(), cloudmigration.CreateSnapshotCommand{
		SessionUID:    sessionUID,
		ResourceTypes: cloudmigration.ResourceTypes{},
	})
}

func insertSnapshot(t *testing.T, s *Service, sessionUID, localDir string) cloudmigration.CloudMigrationSnapshot {
	t.Helper()
	snap := cloudmigration.CloudMigrationSnapshot{
		UID:            util.GenerateShortUID(),
		SessionUID:     sessionUID,
		Status:         cloudmigration.SnapshotStatusPendingUpload,
		GMSSnapshotUID: "gms-snapshot",
		LocalDir:       localDir,
		GMSPublicKey:   []byte("placeholder-gms-public-key"),
		Metadata:       []byte("{}"),
		EncryptionAlgo: string(cloudmigration.EncryptionAlgoNacl),
	}
	require.NoError(t, s.store.CreateSnapshot(context.Background(), snap))
	return snap
}

func requireStoredDirectory(t *testing.T, s *Service, sessionUID, localDir string) {
	t.Helper()
	listed, err := s.GetSnapshotList(context.Background(), cloudmigration.ListSnapshotsQuery{
		SessionUID: sessionUID,
		OrgID:      snapshotPathEscapeOrgID,
		Page:       1,
		Limit:      50,
	})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.Equal(t, localDir, listed[0].LocalDir)
}

func reloadSession(t *testing.T, s *Service, sessionUID string) *cloudmigration.CloudMigrationSession {
	t.Helper()
	sess, err := s.store.GetMigrationSessionByUID(context.Background(), snapshotPathEscapeOrgID, sessionUID)
	require.NoError(t, err)
	return sess
}

func reloadSnapshot(t *testing.T, s *Service, sessionUID, snapshotUID string) *cloudmigration.CloudMigrationSnapshot {
	t.Helper()
	snap, err := s.store.GetSnapshotByUID(context.Background(), snapshotPathEscapeOrgID, sessionUID, snapshotUID, cloudmigration.SnapshotResultQueryParams{})
	require.NoError(t, err)
	return snap
}

func writeMarker(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(snapshotMarkerBody), 0o600))
}

func writeSnapshotTree(t *testing.T, dir string, items map[string][]string, files map[string]string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o750))
	encoded, err := snapshot.EncodeIndex(snapshot.Index{
		Version:        1,
		EncryptionAlgo: "nacl",
		PublicKey:      []byte("placeholder-gms-public-key"),
		Metadata:       []byte(outsideIndexSentinel),
		Items:          items,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), encoded, 0o600))
	for name, body := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	}
}

func assertMarkerIntact(t *testing.T, marker string, created *cloudmigration.CloudMigrationSnapshot, createErr error) {
	t.Helper()
	body, err := os.ReadFile(marker)
	require.NoError(t, err, "file %s was removed (createErr=%v localDir=%s)", marker, createErr, localDirOf(created))
	require.Equal(t, snapshotMarkerBody, string(body))
}

func localDirOf(created *cloudmigration.CloudMigrationSnapshot) string {
	if created == nil {
		return ""
	}
	return created.LocalDir
}

func joinErrors(primary, extra error) error {
	if primary != nil {
		return primary
	}
	return extra
}

func waitForSnapshotBuild(t *testing.T, s *Service, sessionUID, snapshotUID, appeared string) {
	t.Helper()
	require.Eventually(t, func() bool {
		if appeared != "" {
			if _, err := os.Stat(appeared); err == nil {
				return true
			}
		}
		snap, err := s.store.GetSnapshotByUID(context.Background(), snapshotPathEscapeOrgID, sessionUID, snapshotUID, cloudmigration.SnapshotResultQueryParams{})
		if err != nil || snap == nil {
			return false
		}
		return snap.Status == cloudmigration.SnapshotStatusPendingUpload || snap.Status == cloudmigration.SnapshotStatusError
	}, 30*time.Second, 20*time.Millisecond)
}

func waitForBuilder(t *testing.T, s *Service) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.buildSnapshotMutex.Lock()
		s.buildSnapshotMutex.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("snapshot builder did not release its lock")
	}
}

type snapshotIDClient struct {
	id string
}

func (c snapshotIDClient) ValidateKey(context.Context, cloudmigration.CloudMigrationSession) error {
	return nil
}

func (c snapshotIDClient) StartSnapshot(context.Context, cloudmigration.CloudMigrationSession, cloudmigration.EncryptionAlgo) (*cloudmigration.StartSnapshotResponse, error) {
	return &cloudmigration.StartSnapshotResponse{
		SnapshotID:           c.id,
		MaxItemsPerPartition: 10,
		Algo:                 string(cloudmigration.EncryptionAlgoNacl),
		GMSPublicKey:         []byte("placeholder-gms-public-key"),
		Metadata:             []byte("{}"),
	}, nil
}

func (c snapshotIDClient) GetSnapshotStatus(context.Context, cloudmigration.CloudMigrationSession, cloudmigration.CloudMigrationSnapshot, int) (*cloudmigration.GetSnapshotStatusResponse, error) {
	return &cloudmigration.GetSnapshotStatusResponse{State: cloudmigration.SnapshotStateUnknown}, nil
}

func (c snapshotIDClient) CreatePresignedUploadUrl(context.Context, cloudmigration.CloudMigrationSession, cloudmigration.CloudMigrationSnapshot) (string, error) {
	return "http://127.0.0.1/upload", nil
}

func (c snapshotIDClient) ReportEvent(context.Context, cloudmigration.CloudMigrationSession, gmsclient.EventRequestDTO) {
}

type captureUpload struct {
	mu      sync.Mutex
	payload []byte
}

func (c *captureUpload) PresignedURLUpload(_ context.Context, _, _ string, reader io.Reader) error {
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.payload = append(c.payload, body...)
	c.mu.Unlock()
	return nil
}

func (c *captureUpload) bodies() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.payload)
}
