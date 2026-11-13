package supportbundlesimpl

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/kvstore"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/supportbundles"
	"github.com/grafana/grafana/pkg/services/supportbundles/bundleregistry"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// configuredSecret is a credential the settings collector must not copy into a
// support bundle. The placeholder is an obvious fake value, not a real secret.
type configuredSecret struct {
	section     string
	key         string
	placeholder string
}

// TestSupportBundleSettingsDownloadOmitsConfiguredSecrets walks the create and
// download handlers with the settings collector selected. The create page
// pre-selects that collector because its Default flag is set, and the default
// support_bundles.public_keys value leaves the archive unencrypted.
func TestSupportBundleSettingsDownloadOmitsConfiguredSecrets(t *testing.T) {
	secrets := []configuredSecret{
		// Fields named by the report.
		{section: "security", key: "secret_key", placeholder: "placeholder-security-secret-key"},
		{section: "security", key: "admin_password", placeholder: "placeholder-security-admin-password"},
		{section: "grafana_com", key: "sso_api_token", placeholder: "placeholder-grafana-com-sso-api-token"},
		{section: "grafana_com", key: "proxy_token", placeholder: "placeholder-grafana-com-proxy-token"},
		{section: "snapshots", key: "external_snapshot_token", placeholder: "placeholder-external-snapshot-token"},
		{section: "rendering", key: "renderer_token", placeholder: "placeholder-renderer-token"},
		{section: "azure", key: "user_identity_client_secret", placeholder: "placeholder-azure-user-identity-client-secret"},
		{section: "auth.azuread", key: "client_secret", placeholder: "placeholder-azuread-client-secret"},
		// Same collector and the same redaction function. These keys also hold
		// credentials, so a fix that only covers the names above is incomplete.
		{section: "auth.github", key: "client_secret", placeholder: "placeholder-github-client-secret"},
		{section: "nats", key: "token", placeholder: "placeholder-nats-token"},
		{section: "analytics", key: "posthog_token", placeholder: "placeholder-posthog-token"},
		{section: "log.frontend", key: "api_key", placeholder: "placeholder-frontend-api-key"},
		{section: "auth.jwt", key: "key_value", placeholder: "placeholder-jwt-key-value"},
		{section: "auth.jwt", key: "jwk_set_value", placeholder: "placeholder-jwt-jwk-set-value"},
		{section: "database", key: "password", placeholder: "placeholder-database-password"},
		{section: "database", key: "url", placeholder: "mysql://placeholder-db-user:placeholder-database-url-password@db.example:3306/grafana"},
		{section: "remote_cache", key: "connstr", placeholder: "network=tcp,addr=127.0.0.1:6379,password=placeholder-redis-password,ssl=false"},
		{section: "smtp", key: "password", placeholder: "placeholder-smtp-password"},
		{section: "external_image_storage.s3", key: "secret_key", placeholder: "placeholder-s3-secret-key"},
		{section: "external_image_storage.s3", key: "access_key", placeholder: "placeholder-s3-access-key"},
		{section: "external_image_storage.webdav", key: "password", placeholder: "placeholder-webdav-password"},
		{section: "external_image_storage.azure_blob", key: "account_key", placeholder: "placeholder-azure-blob-account-key"},
		{section: "datasources", key: "secret_key", placeholder: "placeholder-datasources-secret-key"},
		{section: "secrets_manager.encryption.secret_key.v1", key: "secret_key", placeholder: "placeholder-envelope-secret-key"},
		{section: "metrics", key: "basic_auth_password", placeholder: "placeholder-metrics-basic-auth-password"},
		{section: "unified_alerting", key: "ha_redis_password", placeholder: "placeholder-ha-redis-password"},
		{section: "live", key: "ha_engine_password", placeholder: "placeholder-live-ha-password"},
	}

	raw := ini.Empty()
	supportBundles, err := raw.NewSection("support_bundles")
	require.NoError(t, err)
	_, err = supportBundles.NewKey("enabled", "true")
	require.NoError(t, err)
	_, err = supportBundles.NewKey("server_admin_only", "true")
	require.NoError(t, err)
	// Match conf/defaults.ini: the key is present and empty, so encryption stays off.
	_, err = supportBundles.NewKey("public_keys", "")
	require.NoError(t, err)

	for _, secret := range secrets {
		section, err := raw.NewSection(secret.section)
		require.NoError(t, err)
		_, err = section.NewKey(secret.key, secret.placeholder)
		require.NoError(t, err)
	}

	cfg := setting.NewCfg()
	cfg.Raw = raw

	// Same reads as ProvideService.
	section := cfg.SectionWithEnvOverrides("support_bundles")
	publicKeys := section.Key("public_keys").Strings(" ")
	require.Empty(t, publicKeys)

	kv := &mutexKV{KVStore: kvstore.NewFakeKVStore()}
	svc := &Service{
		log:                  log.New("test"),
		bundleRegistry:       bundleregistry.ProvideService(),
		cfg:                  cfg,
		enabled:              section.Key("enabled").MustBool(true),
		encryptionPublicKeys: publicKeys,
		serverAdminOnly:      section.Key("server_admin_only").MustBool(true),
		store:                newStore(kv),
		tracer:               tracing.InitializeTracerForTest(),
	}
	require.True(t, svc.enabled)
	require.True(t, svc.serverAdminOnly)
	svc.bundleRegistry.RegisterSupportItemCollector(settingsCollector(setting.ProvideProvider(cfg)))

	// The create page submits every collector whose default flag is set.
	// Requesting the settings collector directly is that submission, and it is
	// also what a caller sends when the box is checked by hand.
	settingsCollector := svc.bundleRegistry.Collectors()["settings"]
	require.Equal(t, "settings", settingsCollector.UID)
	require.False(t, settingsCollector.IncludedByDefault)

	body := `{"collectors":["settings"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/support-bundles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	createCtx := &contextmodel.ReqContext{
		Context: &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{
			UserID:         1,
			Login:          "server-admin",
			IsGrafanaAdmin: true,
		},
		IsSignedIn: true,
	}
	created := svc.handleCreate(createCtx)
	require.Equal(t, http.StatusCreated, created.Status())

	var pending supportbundles.Bundle
	require.NoError(t, json.Unmarshal(created.Body(), &pending))
	require.NotEmpty(t, pending.UID)

	var stored *supportbundles.Bundle
	require.Eventually(t, func() bool {
		got, err := svc.get(context.Background(), pending.UID)
		if err != nil {
			return false
		}
		stored = got
		return stored.State == supportbundles.StateComplete || stored.State == supportbundles.StateError
	}, 10*time.Second, 10*time.Millisecond)
	require.NotNil(t, stored)
	t.Logf("bundle state=%s archiveBytes=%d", stored.State, len(stored.TarBytes))

	downloadReq := httptest.NewRequest(http.MethodGet, "/api/support-bundles/"+pending.UID, nil)
	downloadReq = web.SetURLParams(downloadReq, map[string]string{":uid": pending.UID})
	recorder := httptest.NewRecorder()
	downloadCtx := &contextmodel.ReqContext{
		Context: &web.Context{
			Req:  downloadReq,
			Resp: web.NewResponseWriter(http.MethodGet, recorder),
		},
		SignedInUser: &user.SignedInUser{
			UserID:         1,
			Login:          "server-admin",
			IsGrafanaAdmin: true,
		},
		IsSignedIn: true,
	}
	downloaded := svc.handleDownload(downloadCtx)

	// The kv record is the archive a later download serves. Inspect both, and
	// do not treat a refusal that already persisted the secrets as success.
	payloads := [][]byte{stored.TarBytes}
	if downloaded.Status() == http.StatusOK {
		require.Equal(t, "application/tar+gzip", downloadCtx.Resp.Header().Get("Content-Type"))
		disposition := downloadCtx.Resp.Header().Get("Content-Disposition")
		require.NotContains(t, disposition, ".age")
		require.Equal(t, stored.TarBytes, downloaded.Body())
		payloads = append(payloads, downloaded.Body())
	}

	leakedSet := map[string]struct{}{}
	for _, payload := range payloads {
		for _, name := range credentialValuesInBundle(payload, secrets) {
			leakedSet[name] = struct{}{}
		}
	}
	leaked := make([]string, 0, len(leakedSet))
	for name := range leakedSet {
		leaked = append(leaked, name)
	}
	sort.Strings(leaked)

	require.Empty(t, leaked, "settings collector wrote configured secrets into the support bundle")
}

func credentialValuesInBundle(payload []byte, secrets []configuredSecret) []string {
	var found []string
	files, gzipErr := plaintextBundleFiles(payload)
	if gzipErr != nil {
		for _, secret := range secrets {
			for _, needle := range secret.needles() {
				if bytes.Contains(payload, []byte(needle)) {
					found = append(found, secret.section+"."+secret.key)
					break
				}
			}
		}
		return found
	}
	for _, secret := range secrets {
		for _, needle := range secret.needles() {
			for name, contents := range files {
				if bytes.Contains(contents, []byte(needle)) {
					found = append(found, name+":"+secret.section+"."+secret.key)
					break
				}
			}
		}
	}
	return found
}

func (s configuredSecret) needles() []string {
	switch s.key {
	case "url":
		return []string{"placeholder-database-url-password"}
	case "connstr":
		return []string{"placeholder-redis-password"}
	default:
		return []string{s.placeholder}
	}
}

func plaintextBundleFiles(payload []byte) (map[string][]byte, error) {
	if len(payload) == 0 {
		return map[string][]byte{}, nil
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	files := map[string][]byte{}
	tr := tar.NewReader(gzipReader)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		contents, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[hdr.Name] = contents
	}
	return files, nil
}

// mutexKV serializes the in-memory key-value stand-in. The SQL store writes the
// bundle JSON through without changing it; this wrapper only adds locking so
// the asynchronous collector and the test can share that stand-in.
type mutexKV struct {
	kvstore.KVStore
	mu sync.Mutex
}

func (m *mutexKV) Get(ctx context.Context, orgId int64, namespace string, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.KVStore.Get(ctx, orgId, namespace, key)
}

func (m *mutexKV) Set(ctx context.Context, orgId int64, namespace string, key string, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.KVStore.Set(ctx, orgId, namespace, key, value)
}

func (m *mutexKV) Del(ctx context.Context, orgId int64, namespace string, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.KVStore.Del(ctx, orgId, namespace, key)
}

func (m *mutexKV) Keys(ctx context.Context, orgId int64, namespace string, keyPrefix string) ([]kvstore.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.KVStore.Keys(ctx, orgId, namespace, keyPrefix)
}

func (m *mutexKV) GetAll(ctx context.Context, orgId int64, namespace string) (map[int64]map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.KVStore.GetAll(ctx, orgId, namespace)
}
