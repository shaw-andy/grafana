package shippedkey

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/registry/apis/secret/contracts"
	secretenc "github.com/grafana/grafana/pkg/registry/apis/secret/encryption"
	cipherservice "github.com/grafana/grafana/pkg/registry/apis/secret/encryption/cipher/service"
	gsmkms "github.com/grafana/grafana/pkg/registry/apis/secret/encryption/kmsproviders"
	encmanager "github.com/grafana/grafana/pkg/registry/apis/secret/encryption/manager"
	"github.com/grafana/grafana/pkg/registry/apis/secret/xkube"
	"github.com/grafana/grafana/pkg/services/encryption"
	encryptionprovider "github.com/grafana/grafana/pkg/services/encryption/provider"
	encryptionservice "github.com/grafana/grafana/pkg/services/encryption/service"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/kmsproviders/osskmsproviders"
	"github.com/grafana/grafana/pkg/services/secrets"
	secretsdb "github.com/grafana/grafana/pkg/services/secrets/database"
	secretsmanager "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/setting"
	secretdb "github.com/grafana/grafana/pkg/storage/secret/database"
	encryptionstorage "github.com/grafana/grafana/pkg/storage/secret/encryption"
	secretmigrator "github.com/grafana/grafana/pkg/storage/secret/migrator"
	"github.com/grafana/grafana/pkg/util"
)

// These tests are the spec for the shipped secret_key.
//
// A default installation must not write a secret that can be opened with the
// secret_key values published in conf/defaults.ini. Startup or the encrypt
// call may refuse that configuration, and then it must not have persisted a
// data key or returned ciphertext. Replacing only one of the two shipped keys
// must not leave the other provider writable under the key that remains in
// the file.
//
// The unwrap below follows the product's envelope layout and AES-CFB / AES-GCM
// steps. It does not call the product's Decrypt methods, so a refusal added
// only in front of those methods still fails while the stored bytes open with
// the published key.

const (
	placeholderSecret = "placeholder-datasource-credential"
	operatorChosen    = "operator-chosen-placeholder"

	algorithmDelimiter = '*'
	keyIDDelimiter     = '#'
	pbkdf2Iterations   = 10000
	derivedKeyLen      = 32
)

func TestShippedSecuritySecretKeyCannotOpenLegacyEnvelope(t *testing.T) {
	publishedSecurity, _ := publishedSecretKeys(t)
	assertLegacyEnvelopeRefusesPublishedKey(t, nil, publishedSecurity)
}

func TestShippedSecuritySecretKeyCannotOpenLegacyEnvelopeWhenSecretsManagerKeyIsReplaced(t *testing.T) {
	publishedSecurity, publishedManager := publishedSecretKeys(t)
	cfg := loadShippedConfig(t, "cfg:secrets_manager.encryption.secret_key.v1.secret_key="+operatorChosen)
	if cfg == nil {
		return
	}
	if configuredSecretsManagerKey(cfg) == publishedManager {
		t.Fatal("command line override did not replace secrets_manager.encryption.secret_key.v1")
	}
	assertLegacyEnvelopeRefusesPublishedKey(t, cfg, publishedSecurity)
}

func TestShippedSecretsManagerKeyCannotOpenEnvelope(t *testing.T) {
	_, publishedManager := publishedSecretKeys(t)
	assertSecretsManagerRefusesPublishedKey(t, nil, publishedManager)
}

func TestShippedSecretsManagerKeyCannotOpenEnvelopeWhenSecuritySecretKeyIsReplaced(t *testing.T) {
	publishedSecurity, publishedManager := publishedSecretKeys(t)
	cfg := loadShippedConfig(t, "cfg:security.secret_key="+operatorChosen)
	if cfg == nil {
		return
	}
	if configuredSecuritySecretKey(cfg) == publishedSecurity {
		t.Fatal("command line override did not replace security.secret_key")
	}
	assertSecretsManagerRefusesPublishedKey(t, cfg, publishedManager)
}

func TestShippedSecuritySecretKeyCannotOpenDirectEncryption(t *testing.T) {
	publishedSecurity, _ := publishedSecretKeys(t)
	cfg := loadShippedConfig(t)
	if cfg == nil {
		return
	}
	assertDirectEncryptionRefusesPublishedKey(t, cfg, publishedSecurity)
}

// SecretsService.Encrypt and EncryptJsonData are what datasource secure JSON,
// plugin settings, the secrets kv store, signing keys, alerting, service
// accounts, and provisioning call. The direct cipher is what secret rollback
// and the datasource-password migration write with security.secret_key.
func assertLegacyEnvelopeRefusesPublishedKey(t *testing.T, cfg *setting.Cfg, publishedSecurity string) {
	t.Helper()
	if cfg == nil {
		cfg = loadShippedConfig(t)
		if cfg == nil {
			return
		}
	}

	store := secretsdb.ProvideSecretsStore(sqlstore.NewTestStore(t))
	svc, _, err := newLegacyService(t, cfg, store)
	if err != nil {
		assertNoLegacyDataKeys(t, store)
		assertDirectEncryptionRefusesPublishedKey(t, cfg, publishedSecurity)
		return
	}

	ctx := context.Background()
	plaintext := []byte(placeholderSecret)
	raw, rawErr := svc.Encrypt(ctx, plaintext, secrets.WithoutScope())
	encryptedJSON, jsonErr := svc.EncryptJsonData(ctx, map[string]string{"password": placeholderSecret}, secrets.WithoutScope())
	keys := legacyDataKeys(t, store)

	blobs := make([][]byte, 0, 1+len(encryptedJSON))
	if len(raw) > 0 {
		blobs = append(blobs, raw)
	}
	for _, value := range encryptedJSON {
		if len(value) > 0 {
			blobs = append(blobs, value)
		}
	}
	if rawErr != nil || jsonErr != nil {
		if len(blobs) > 0 || len(keys) > 0 {
			t.Fatal("legacy envelope encryption refused only after writing a data key or ciphertext")
		}
	} else {
		assertBlobsAreNotPlaintext(t, plaintext, blobs...)
		if publishedKeyOpensLegacy(publishedSecurity, keys, plaintext, blobs...) {
			t.Fatal("published security.secret_key from conf/defaults.ini decrypted a secret written by the legacy envelope provider")
		}
		if configuredSecuritySecretKey(cfg) == publishedSecurity {
			t.Fatal("security.secret_key still has the value shipped in conf/defaults.ini after a secret was stored, but the unwrap did not recover it")
		}
	}
	assertDirectEncryptionRefusesPublishedKey(t, cfg, publishedSecurity)
}

func assertSecretsManagerRefusesPublishedKey(t *testing.T, cfg *setting.Cfg, publishedManager string) {
	t.Helper()
	if cfg == nil {
		cfg = loadShippedConfig(t)
		if cfg == nil {
			return
		}
	}

	ctx := context.Background()
	namespace := xkube.Namespace("default")
	mgr, store, err := newSecretsManager(t, cfg)
	if err != nil {
		assertNoSecretsManagerDataKeys(t, store, namespace)
		return
	}

	plaintext := []byte(placeholderSecret)
	payload, encErr := mgr.Encrypt(ctx, namespace, plaintext, contracts.EncryptionOption{SkipCache: true})
	keys := secretsManagerDataKeys(t, store, namespace)
	if encErr != nil {
		if len(payload.EncryptedData) > 0 || payload.DataKeyID != "" || len(keys) > 0 {
			t.Fatal("secrets-manager encryption refused only after writing a data key or ciphertext")
		}
		return
	}
	assertBlobsAreNotPlaintext(t, plaintext, payload.EncryptedData)
	opened := publishedKeyOpensSecretsManager(publishedManager, keys, payload, plaintext)
	if opened {
		t.Fatal("published secrets_manager.encryption.secret_key.v1 from conf/defaults.ini decrypted a secret written by secret_key.v1")
	}
	if configuredSecretsManagerKey(cfg) == publishedManager {
		t.Fatal("secrets_manager.encryption.secret_key.v1 still has the value shipped in conf/defaults.ini after a secret was stored, but the unwrap did not recover it")
	}
}

func assertDirectEncryptionRefusesPublishedKey(t *testing.T, cfg *setting.Cfg, publishedSecurity string) {
	t.Helper()
	enc, err := newEncryptionService(t, cfg)
	if err != nil {
		return
	}

	ctx := context.Background()
	fromSettings := setting.ProvideProvider(cfg).KeyValue("security", "secret_key").Value()
	jsonCipher, jsonErr := enc.EncryptJsonData(ctx, map[string]string{"password": placeholderSecret}, fromSettings)
	rawCipher, rawErr := util.Encrypt([]byte(placeholderSecret), cfg.SecretKey)

	blobs := make([][]byte, 0, 1+len(jsonCipher))
	if len(rawCipher) > 0 {
		blobs = append(blobs, rawCipher)
	}
	for _, value := range jsonCipher {
		if len(value) > 0 {
			blobs = append(blobs, value)
		}
	}
	if jsonErr != nil || rawErr != nil {
		if len(blobs) > 0 {
			t.Fatal("direct encryption refused only after returning ciphertext")
		}
		return
	}
	plaintext := []byte(placeholderSecret)
	assertBlobsAreNotPlaintext(t, plaintext, blobs...)
	if publishedKeyOpensDirect(publishedSecurity, plaintext, blobs...) {
		t.Fatal("published security.secret_key from conf/defaults.ini decrypted a secret written by the direct cipher")
	}
	if fromSettings == publishedSecurity || cfg.SecretKey == publishedSecurity {
		t.Fatal("security.secret_key still has the value shipped in conf/defaults.ini after direct encryption, but the unwrap did not recover it")
	}
}

func loadShippedConfig(t *testing.T, args ...string) *setting.Cfg {
	t.Helper()
	// Empty values do not override. Clear inherited overrides so the shipped file is what the process uses.
	t.Setenv("GF_SECURITY_SECRET_KEY", "")
	t.Setenv("GF_SECURITY_ENCRYPTION_PROVIDER", "")
	t.Setenv("GF_SECURITY_ENCRYPTION_ALGORITHM", "")
	t.Setenv("GF_SECRETS_MANAGER_ENCRYPTION_PROVIDER", "")
	t.Setenv("GF_SECRETS_MANAGER_ENCRYPTION_SECRET_KEY_V1_SECRET_KEY", "")

	root := repoRoot(t)
	defaults := filepath.Join(root, "conf", "defaults.ini")
	if _, err := os.Stat(defaults); err != nil {
		t.Fatalf("conf/defaults.ini is not available: %v", err)
	}

	cfg, err := setting.NewCfgFromArgs(setting.CommandLineArgs{
		HomePath: root,
		Args:     args,
	})
	if err != nil {
		// Refusing the shipped configuration at load time is a fix, provided no secret was stored.
		return nil
	}
	return cfg
}

func publishedSecretKeys(t *testing.T) (securityKey, secretsManagerKey string) {
	t.Helper()
	file, err := ini.Load(filepath.Join(repoRoot(t), "conf", "defaults.ini"))
	if err != nil {
		t.Fatalf("read conf/defaults.ini: %v", err)
	}
	securityKey = file.Section("security").Key("secret_key").Value()
	secretsManagerKey = file.Section("secrets_manager.encryption.secret_key.v1").Key("secret_key").Value()
	if securityKey == "" || secretsManagerKey == "" {
		t.Fatal("conf/defaults.ini has an empty secret_key; the attacker did not obtain a published key")
	}
	return securityKey, secretsManagerKey
}

func configuredSecuritySecretKey(cfg *setting.Cfg) string {
	return cfg.SectionWithEnvOverrides("security").Key("secret_key").Value()
}

func configuredSecretsManagerKey(cfg *setting.Cfg) string {
	providers := cfg.SecretsManagement.ConfiguredKMSProviders["secret_key.v1"]
	if providers == nil {
		return ""
	}
	return providers["secret_key"]
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "conf", "defaults.ini")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate the repository root from the working directory")
		}
		dir = parent
	}
}

func newEncryptionService(t *testing.T, cfg *setting.Cfg) (*encryptionservice.Service, error) {
	t.Helper()
	return encryptionservice.ProvideEncryptionService(
		tracing.InitializeTracerForTest(),
		encryptionprovider.Provider{},
		&usagestats.UsageStatsMock{T: t},
		cfg,
	)
}

func newLegacyService(t *testing.T, cfg *setting.Cfg, store secrets.Store) (*secretsmanager.SecretsService, *encryptionservice.Service, error) {
	t.Helper()
	enc, err := newEncryptionService(t, cfg)
	if err != nil {
		return nil, nil, err
	}
	features := featuremgmt.WithFeatures()
	svc, err := secretsmanager.ProvideSecretsService(
		tracing.InitializeTracerForTest(),
		store,
		osskmsproviders.ProvideService(enc, cfg, features),
		enc,
		cfg,
		features,
		&usagestats.UsageStatsMock{T: t},
	)
	if err != nil {
		return nil, enc, err
	}
	return svc, enc, nil
}

func newSecretsManager(t *testing.T, cfg *setting.Cfg) (contracts.EncryptionManager, contracts.DataKeyStorage, error) {
	t.Helper()
	testDB := sqlstore.NewTestStore(t, sqlstore.WithMigrator(secretmigrator.New()))
	tracer := noop.NewTracerProvider().Tracer("shipped-secret-key")
	db := secretdb.ProvideDatabase(testDB, tracer)
	store, err := encryptionstorage.ProvideDataKeyStorage(db, tracer, nil)
	if err != nil {
		return nil, nil, err
	}
	usage := &usagestats.UsageStatsMock{T: t}
	enc, err := cipherservice.ProvideAESGCMCipherService(tracer, usage)
	if err != nil {
		return nil, store, err
	}
	providers, err := gsmkms.ProvideOSSKMSProviders(cfg, enc)
	if err != nil {
		return nil, store, err
	}
	mgr, err := encmanager.ProvideEncryptionManager(tracer, store, usage, enc, providers, &noopDataKeyCache{}, cfg)
	if err != nil {
		return nil, store, err
	}
	return mgr, store, nil
}

func legacyDataKeys(t *testing.T, store secrets.Store) []*secrets.DataKey {
	t.Helper()
	keys, err := store.GetAllDataKeys(context.Background())
	if err != nil {
		t.Fatalf("list legacy data keys: %v", err)
	}
	return keys
}

func assertNoLegacyDataKeys(t *testing.T, store secrets.Store) {
	t.Helper()
	if keys := legacyDataKeys(t, store); len(keys) > 0 {
		t.Fatal("legacy encryption refused only after persisting a data key")
	}
}

func secretsManagerDataKeys(t *testing.T, store contracts.DataKeyStorage, namespace xkube.Namespace) []*contracts.SecretDataKey {
	t.Helper()
	if store == nil {
		return nil
	}
	keys, err := store.ListDataKeys(context.Background(), namespace.String())
	if err != nil {
		t.Fatalf("list secrets-manager data keys: %v", err)
	}
	return keys
}

func assertNoSecretsManagerDataKeys(t *testing.T, store contracts.DataKeyStorage, namespace xkube.Namespace) {
	t.Helper()
	if keys := secretsManagerDataKeys(t, store, namespace); len(keys) > 0 {
		t.Fatal("secrets-manager encryption refused only after persisting a data key")
	}
}

func assertBlobsAreNotPlaintext(t *testing.T, plaintext []byte, blobs ...[]byte) {
	t.Helper()
	for _, blob := range blobs {
		if bytes.Contains(blob, plaintext) {
			t.Fatal("ciphertext contains the plaintext")
		}
	}
}

func publishedKeyOpensLegacy(published string, keys []*secrets.DataKey, want []byte, blobs ...[]byte) bool {
	deks := make(map[string][]byte, len(keys))
	for _, key := range keys {
		raw, err := decryptProductCipher(key.EncryptedData, published)
		if err != nil || len(raw) == 0 {
			continue
		}
		deks[key.Id] = raw
	}
	for _, blob := range blobs {
		if opensEnvelope(deks, blob, want) || publishedKeyOpensDirect(published, want, blob) {
			return true
		}
	}
	return false
}

func opensEnvelope(deks map[string][]byte, blob, want []byte) bool {
	id, rest, ok := splitEnvelope(blob)
	if !ok {
		return false
	}
	if dek, exists := deks[id]; exists && dekOpens(dek, rest, want) {
		return true
	}
	for _, dek := range deks {
		if dekOpens(dek, rest, want) {
			return true
		}
	}
	return false
}

func dekOpens(dek, blob, want []byte) bool {
	plain, err := decryptProductCipher(blob, string(dek))
	return err == nil && bytes.Equal(plain, want)
}

func publishedKeyOpensSecretsManager(published string, keys []*contracts.SecretDataKey, payload contracts.EncryptedPayload, want []byte) bool {
	for _, key := range keys {
		raw, err := decryptProductCipher(key.EncryptedData, published)
		if err != nil || len(raw) == 0 {
			continue
		}
		if dekOpens(raw, payload.EncryptedData, want) {
			return true
		}
	}
	return false
}

func publishedKeyOpensDirect(published string, want []byte, blobs ...[]byte) bool {
	for _, blob := range blobs {
		plain, err := decryptProductCipher(blob, published)
		if err == nil && bytes.Equal(plain, want) {
			return true
		}
	}
	return false
}

// splitEnvelope mirrors SecretsService.Decrypt's key-id framing.
func splitEnvelope(payload []byte) (string, []byte, bool) {
	if len(payload) == 0 || payload[0] != keyIDDelimiter {
		return "", nil, false
	}
	payload = payload[1:]
	end := bytes.IndexByte(payload, keyIDDelimiter)
	if end < 0 {
		return "", nil, false
	}
	encoded := payload[:end]
	rest := payload[end+1:]
	id := make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded)))
	if _, err := base64.RawStdEncoding.Decode(id, encoded); err != nil {
		return "", nil, false
	}
	return string(id), rest, true
}

// decryptProductCipher repeats the AES steps in the encryption service and the
// secrets-manager cipher: algorithm prefix, PBKDF2 key, then AES-CFB or AES-GCM.
func decryptProductCipher(payload []byte, secret string) ([]byte, error) {
	algorithm, body, err := deriveAlgorithm(payload)
	if err != nil {
		return nil, err
	}
	if len(body) < encryption.SaltLength {
		return nil, errShortPayload
	}
	salt := body[:encryption.SaltLength]
	key, err := pbkdf2.Key(sha256.New, secret, salt, pbkdf2Iterations, derivedKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch algorithm {
	case encryption.AesGcm:
		return decryptGCM(block, body)
	default:
		return decryptCFB(block, body)
	}
}

func deriveAlgorithm(payload []byte) (string, []byte, error) {
	if len(payload) == 0 {
		return "", nil, errShortPayload
	}
	if payload[0] != algorithmDelimiter {
		return encryption.AesCfb, payload, nil
	}
	rest := payload[1:]
	end := bytes.IndexByte(rest, algorithmDelimiter)
	if end < 0 {
		return encryption.AesCfb, payload, nil
	}
	encoded := rest[:end]
	body := rest[end+1:]
	algorithm := make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded)))
	n, err := base64.RawStdEncoding.Decode(algorithm, encoded)
	if err != nil {
		return "", nil, err
	}
	name := string(algorithm[:n])
	if name == "" {
		return encryption.AesCfb, body, nil
	}
	return name, body, nil
}

func decryptCFB(block cipher.Block, payload []byte) ([]byte, error) {
	if len(payload) < encryption.SaltLength+aes.BlockSize {
		return nil, errShortPayload
	}
	iv := payload[encryption.SaltLength : encryption.SaltLength+aes.BlockSize]
	ciphertext := payload[encryption.SaltLength+aes.BlockSize:]
	plain := make([]byte, len(ciphertext))
	//nolint:staticcheck // AES-CFB is the cipher the product still writes.
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plain, ciphertext)
	return plain, nil
}

func decryptGCM(block cipher.Block, payload []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(payload) < encryption.SaltLength+gcm.NonceSize() {
		return nil, errShortPayload
	}
	nonce := payload[encryption.SaltLength : encryption.SaltLength+gcm.NonceSize()]
	ciphertext := payload[encryption.SaltLength+gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

var errShortPayload = errString("payload too short")

type errString string

func (e errString) Error() string { return string(e) }

type noopDataKeyCache struct{}

func (noopDataKeyCache) GetById(context.Context, string, string) (secretenc.DataKeyCacheEntry, bool, error) {
	return secretenc.DataKeyCacheEntry{}, false, nil
}

func (noopDataKeyCache) GetByLabel(context.Context, string, string) (secretenc.DataKeyCacheEntry, bool, error) {
	return secretenc.DataKeyCacheEntry{}, false, nil
}

func (noopDataKeyCache) Set(context.Context, string, secretenc.DataKeyCacheEntry) error {
	return nil
}

func (noopDataKeyCache) RemoveExpired(context.Context) {}

func (noopDataKeyCache) Flush(context.Context, string) {}
