package provisioning

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/notifier/legacy_storage"
	"github.com/grafana/grafana/pkg/services/ngalert/tests/fakes"
	"github.com/grafana/grafana/pkg/services/secrets"
	"github.com/grafana/grafana/pkg/services/secrets/database"
	"github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// These tests specify the cross-receiver contact point move. They fail while
// UpdateContactPoint copies stored secret settings onto a receiver the caller
// can decrypt without being allowed to read the source receiver's secrets.
const (
	victimReceiverName = "admin-owned"
	sinkReceiverName   = "editor-sink"
	decoyReceiverName  = "editor-decoy"
)

func TestIntegrationContactPointCrossReceiverSecretDisclosure(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	secretsService := manager.SetupTestService(t, database.ProvideSecretsStore(db.InitTestDB(t))) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore

	t.Run("slack last integration", func(t *testing.T) {
		runCrossReceiverSecretMove(t, secretsService, crossReceiverCase{
			integrationType: "slack",
			settings:        `{"recipient":"#alerts","token":"placeholder-victim"}`,
			secretField:     "token",
			secretValue:     "placeholder-victim",
		})
	})

	t.Run("slack one of two integrations", func(t *testing.T) {
		runCrossReceiverSecretMove(t, secretsService, crossReceiverCase{
			integrationType: "slack",
			settings:        `{"recipient":"#alerts","token":"placeholder-victim"}`,
			secretField:     "token",
			secretValue:     "placeholder-victim",
			siblingSettings: `{"recipient":"#other","token":"placeholder-sibling"}`,
		})
	})

	t.Run("webhook last integration", func(t *testing.T) {
		runCrossReceiverSecretMove(t, secretsService, crossReceiverCase{
			integrationType: "webhook",
			settings:        `{"url":"https://alerts.example/hook","authorization_credentials":"placeholder-victim"}`,
			secretField:     "authorization_credentials",
			secretValue:     "placeholder-victim",
		})
	})

	t.Run("last integration referenced by a route", func(t *testing.T) {
		runCrossReceiverSecretMove(t, secretsService, crossReceiverCase{
			integrationType:   "slack",
			settings:          `{"recipient":"#alerts","token":"placeholder-victim"}`,
			secretField:       "token",
			secretValue:       "placeholder-victim",
			referencedByRoute: true,
		})
	})

	t.Run("stored secret changes between the read that authorizes and the read that copies", func(t *testing.T) {
		runCrossReceiverSecretMove(t, secretsService, crossReceiverCase{
			integrationType:   "slack",
			settings:          `{"recipient":"#alerts","token":"placeholder-victim"}`,
			secretField:       "token",
			secretValue:       "placeholder-victim",
			replacementSecret: "placeholder-victim-replaced",
		})
	})

	t.Run("redacted update of the caller's own receiver keeps that receiver's secret", func(t *testing.T) {
		sut, _ := newContactPointService(t, secretsService)
		editor := editorWithAdminOn(sinkReceiverName, decoyReceiverName)
		sink := mustCreateContactPoint(t, sut, editor, sinkReceiverName, "slack", `{"recipient":"#sink","token":"placeholder-sink"}`)

		payload := sink
		payload.Settings = cloneSettings(t, sink.Settings)
		payload.Settings.Set("recipient", "#sink-renamed")

		require.NoError(t, sut.UpdateContactPoint(context.Background(), 1, editor, payload, models.ProvenanceNone))

		require.False(t, editorSees(t, sut, editor, "placeholder-victim"))
		require.True(t, editorSees(t, sut, editor, "placeholder-sink"))
		require.Equal(t, sinkReceiverName, receiverNameOf(t, sut, editor, sink.UID))
	})
}

type crossReceiverCase struct {
	integrationType   string
	settings          string
	secretField       string
	secretValue       string
	siblingSettings   string
	referencedByRoute bool
	// replacementSecret, when set, is written into the stored integration after
	// the first configuration read of the move and before the next one.
	replacementSecret string
}

func runCrossReceiverSecretMove(t *testing.T, secretsService secrets.Service, tc crossReceiverCase) {
	t.Helper()

	sut, store := newContactPointService(t, secretsService)
	admin := adminReceiverUser()
	// Permissions match a default Editor plus Admin on receivers that editor created.
	// Admin on a receiver includes secrets:read and protected:write for that receiver only.
	editor := editorWithAdminOn(sinkReceiverName, decoyReceiverName)

	victim := mustCreateContactPoint(t, sut, admin, victimReceiverName, tc.integrationType, tc.settings)
	var siblingUID string
	if tc.siblingSettings != "" {
		sibling := mustCreateContactPoint(t, sut, admin, victimReceiverName, tc.integrationType, tc.siblingSettings)
		siblingUID = sibling.UID
	}
	sink := mustCreateContactPoint(t, sut, editor, sinkReceiverName, tc.integrationType, sinkSettings(tc))
	_ = mustCreateContactPoint(t, sut, editor, decoyReceiverName, tc.integrationType, sinkSettings(tc))

	if tc.referencedByRoute {
		pointDefaultRouteAt(t, store, victimReceiverName)
		require.Equal(t, victimReceiverName, defaultRouteReceiver(t, store))
	}

	// The editor can list the integration, but not decrypt the source receiver.
	require.Equal(t, victimReceiverName, receiverNameOf(t, sut, editor, victim.UID))
	require.False(t, editorSees(t, sut, editor, tc.secretValue))

	// Arm after the reads above so the two configuration reads inside the move
	// itself observe different stored secrets.
	if tc.replacementSecret != "" {
		swapSecretAfterFirstRead(t, store, secretsService, victim.UID, tc.secretField, tc.replacementSecret)
	}

	// PUT the source integration with the redacted placeholder and the sink's name.
	payload := victim
	payload.Name = sinkReceiverName
	err := sut.UpdateContactPoint(context.Background(), 1, editor, payload, models.ProvenanceNone)

	forbidden := []string{tc.secretValue}
	if tc.replacementSecret != "" {
		forbidden = append(forbidden, tc.replacementSecret)
	}
	for _, value := range forbidden {
		require.Falsef(t, editorSees(t, sut, editor, value), "editor decrypted a secret carried off the source receiver")
	}
	require.Equalf(t, victimReceiverName, receiverNameOf(t, sut, editor, victim.UID), "source integration was moved")
	if siblingUID != "" {
		require.Equal(t, victimReceiverName, receiverNameOf(t, sut, editor, siblingUID))
	}
	require.Equal(t, sinkReceiverName, receiverNameOf(t, sut, editor, sink.UID))
	if tc.referencedByRoute {
		require.Equal(t, victimReceiverName, defaultRouteReceiver(t, store))
	}
	require.Error(t, err)
}

func sinkSettings(tc crossReceiverCase) string {
	if tc.integrationType == "webhook" {
		return `{"url":"https://sink.example/hook","authorization_credentials":"placeholder-sink"}`
	}
	return `{"recipient":"#sink","token":"placeholder-sink"}`
}

func newContactPointService(t *testing.T, secretsService secrets.Service) (*ContactPointService, *fakes.FakeAlertmanagerConfigStore) {
	t.Helper()
	store := fakes.NewFakeAlertmanagerConfigStore(createEncryptedConfig(t, secretsService))
	return createContactPointServiceSutWithConfigStore(t, secretsService, store), store
}

func mustCreateContactPoint(t *testing.T, sut *ContactPointService, user *user.SignedInUser, name, integrationType, settingsJSON string) definitions.EmbeddedContactPoint {
	t.Helper()
	settings, err := simplejson.NewJson([]byte(settingsJSON))
	require.NoError(t, err)
	created, err := sut.CreateContactPoint(context.Background(), 1, user, definitions.EmbeddedContactPoint{
		Name:     name,
		Type:     integrationType,
		Settings: settings,
	}, models.ProvenanceNone)
	require.NoError(t, err)
	require.NotEmpty(t, created.UID)
	return created
}

func cloneSettings(t *testing.T, settings *simplejson.Json) *simplejson.Json {
	t.Helper()
	raw, err := settings.MarshalJSON()
	require.NoError(t, err)
	cloned, err := simplejson.NewJson(raw)
	require.NoError(t, err)
	return cloned
}

func adminReceiverUser() *user.SignedInUser {
	return &user.SignedInUser{OrgID: 1, Permissions: map[int64]map[string][]string{
		1: {
			accesscontrol.ActionAlertingReceiversCreate:          nil,
			accesscontrol.ActionAlertingReceiversRead:            {models.ScopeReceiversAll},
			accesscontrol.ActionAlertingReceiversUpdate:          {models.ScopeReceiversAll},
			accesscontrol.ActionAlertingReceiversDelete:          {models.ScopeReceiversAll},
			accesscontrol.ActionAlertingReceiversReadSecrets:     {models.ScopeReceiversAll},
			accesscontrol.ActionAlertingReceiversUpdateProtected: {models.ScopeReceiversAll},
			accesscontrol.ActionAlertingProvisioningSetStatus:    nil,
		},
	}}
}

// editorWithAdminOn is a default Editor (create, read, update, and delete every
// receiver, and provenance write) who is also Admin of the named receivers.
// Admin is what creating a receiver grants its creator, and it is the only
// source of secrets:read and protected:write in this set.
func editorWithAdminOn(receiverNames ...string) *user.SignedInUser {
	adminScopes := make([]string, 0, len(receiverNames))
	for _, name := range receiverNames {
		adminScopes = append(adminScopes, models.ScopeReceiversProvider.GetResourceScopeUID(models.NameToUid(name)))
	}
	return &user.SignedInUser{OrgID: 1, Permissions: map[int64]map[string][]string{
		1: {
			accesscontrol.ActionAlertingReceiversCreate:          nil,
			accesscontrol.ActionAlertingReceiversRead:            {models.ScopeReceiversAll},
			accesscontrol.ActionAlertingReceiversUpdate:          {models.ScopeReceiversAll},
			accesscontrol.ActionAlertingReceiversDelete:          {models.ScopeReceiversAll},
			accesscontrol.ActionAlertingReceiversList:            nil,
			accesscontrol.ActionAlertingProvisioningSetStatus:    nil,
			accesscontrol.ActionAlertingReceiversReadSecrets:     adminScopes,
			accesscontrol.ActionAlertingReceiversUpdateProtected: adminScopes,
		},
	}}
}

func editorSees(t *testing.T, sut *ContactPointService, editor *user.SignedInUser, value string) bool {
	t.Helper()
	queries := []ContactPointQuery{
		{OrgID: 1, Decrypt: true},
		{OrgID: 1, Decrypt: true, Name: sinkReceiverName},
		{OrgID: 1, Decrypt: true, Name: decoyReceiverName},
	}
	for _, q := range queries {
		cps, err := sut.GetContactPoints(context.Background(), q, editor)
		require.NoError(t, err)
		for _, cp := range cps {
			raw, err := cp.Settings.MarshalJSON()
			require.NoError(t, err)
			if strings.Contains(string(raw), value) {
				return true
			}
		}
	}
	return false
}

func receiverNameOf(t *testing.T, sut *ContactPointService, user *user.SignedInUser, uid string) string {
	t.Helper()
	cps, err := sut.GetContactPoints(context.Background(), ContactPointQuery{OrgID: 1}, user)
	require.NoError(t, err)
	for _, cp := range cps {
		if cp.UID == uid {
			return cp.Name
		}
	}
	return ""
}

func pointDefaultRouteAt(t *testing.T, store *fakes.FakeAlertmanagerConfigStore, receiverName string) {
	t.Helper()
	cfg, err := legacy_storage.DeserializeAlertmanagerConfig([]byte(store.Config.AlertmanagerConfiguration))
	require.NoError(t, err)
	require.NotNil(t, cfg.AlertmanagerConfig.Route)
	cfg.AlertmanagerConfig.Route.Receiver = receiverName
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	store.Config.AlertmanagerConfiguration = string(raw)
}

func defaultRouteReceiver(t *testing.T, store *fakes.FakeAlertmanagerConfigStore) string {
	t.Helper()
	cfg, err := legacy_storage.DeserializeAlertmanagerConfig([]byte(store.Config.AlertmanagerConfiguration))
	require.NoError(t, err)
	require.NotNil(t, cfg.AlertmanagerConfig.Route)
	return cfg.AlertmanagerConfig.Route.Receiver
}

// swapSecretAfterFirstRead changes the stored ciphertext of one integration
// after the next configuration read returns. A move that authorizes one read
// and copies secrets from a later read must not disclose either value.
func swapSecretAfterFirstRead(t *testing.T, store *fakes.FakeAlertmanagerConfigStore, secretsService secrets.Service, integrationUID, field, replacement string) {
	t.Helper()
	encrypted, err := secretsService.Encrypt(context.Background(), []byte(replacement), secrets.WithoutScope())
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(encrypted)
	swapped := false
	store.GetFn = func(ctx context.Context, orgID int64) (*models.AlertConfiguration, error) {
		snapshot := store.Config
		snapshot.OrgID = orgID
		if !swapped {
			store.Config.AlertmanagerConfiguration = replaceSecureSetting(t, store.Config.AlertmanagerConfiguration, integrationUID, field, encoded)
			swapped = true
		}
		return &snapshot, nil
	}
}

func replaceSecureSetting(t *testing.T, config, integrationUID, field, encrypted string) string {
	t.Helper()
	var raw map[string]any
	require.NoError(t, json.Unmarshal([]byte(config), &raw))
	alertmanagerConfig, ok := raw["alertmanager_config"].(map[string]any)
	require.True(t, ok)
	receivers, ok := alertmanagerConfig["receivers"].([]any)
	require.True(t, ok)
	found := false
	for _, item := range receivers {
		receiver, ok := item.(map[string]any)
		require.True(t, ok)
		integrations, ok := receiver["grafana_managed_receiver_configs"].([]any)
		if !ok {
			continue
		}
		for _, item := range integrations {
			integration, ok := item.(map[string]any)
			require.True(t, ok)
			if integration["uid"] != integrationUID {
				continue
			}
			secure, _ := integration["secureSettings"].(map[string]any)
			if secure == nil {
				secure = map[string]any{}
				integration["secureSettings"] = secure
			}
			secure[field] = encrypted
			found = true
		}
	}
	require.Truef(t, found, "integration %s was not in the stored configuration", integrationUID)
	out, err := json.Marshal(raw)
	require.NoError(t, err)
	return string(out)
}
