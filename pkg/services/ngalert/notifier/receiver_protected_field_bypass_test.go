package notifier

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	kitlog "github.com/go-kit/log"
	alertingNotify "github.com/grafana/alerting/notify"
	"github.com/grafana/alerting/receivers"
	"github.com/grafana/alerting/receivers/schema"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	v1beta1 "github.com/grafana/grafana/apps/alerting/notifications/pkg/apis/alertingnotifications/v1beta1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	ac "github.com/grafana/grafana/pkg/services/ngalert/accesscontrol"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/user"

	alertingImages "github.com/grafana/alerting/images"
)

const (
	// Obvious placeholders. These are not credentials.
	placeholderClientID      = "placeholder-client-id"
	placeholderClientSecretA = "placeholder-client-secret-a"
	placeholderClientSecretB = "placeholder-client-secret-b"
	adminTokenURL            = "https://token.example.invalid/token"
	adminWebhookURL          = "https://hook.example.invalid/hook"
)

func TestEditorCannotExfiltrateOAuthClientSecretBySwitchingIntegrationVersion(t *testing.T) {
	ctx := context.Background()
	secretsSvc := fakes.NewFakeSecretsService()
	rs := createReceiverServiceSut(t, &secretsSvc)
	authz := ac.NewReceiverAccess[*models.Receiver](acimpl.ProvideAccessControl(featuremgmt.WithFeatures()), false)
	editor := editorUser()
	admin := adminUser()

	capture, tokenURL, hookURL := newCaptureServer(t)
	am := newTestAlertmanager(t, secretsSvc)

	target := createOAuthWebhookReceiver(t, ctx, rs, admin, "oauth-webhook-a", placeholderClientSecretA)
	other := createOAuthWebhookReceiver(t, ctx, rs, admin, "oauth-webhook-b", placeholderClientSecretB)

	require.NoError(t, authz.AuthorizeTestByUID(ctx, editor, target.UID))
	_, err := rs.GetReceiver(ctx, target.UID, true, editor)
	require.ErrorIs(t, err, ac.ErrAuthorizationBase)

	stored, err := rs.GetReceiver(ctx, target.UID, false, editor)
	require.NoError(t, err)
	require.Equal(t, schema.V1, stored.Integrations[0].Config.Version)

	body := attackTestBody(stored.Integrations[0].UID, string(schema.WebhookType), string(schema.V0mimir1), hookURL, tokenURL)
	integration, secureFields, err := integrationFromTestBody(body.Integration)
	require.NoError(t, err)

	testingSvc := &ReceiverTestingService{
		receiverSvc:       rs,
		amProvider:        staticAlertmanager{am: am},
		encryptionService: secretsSvc,
		authz:             authz,
		emailValidator:    &NoopOrgEmailValidator{},
	}
	_, err = testingSvc.PatchIntegrationAndTest(ctx, editor, testAlert(), target.UID, integration, secureFields)
	assertSecretStaysStored(t, err, capture, placeholderClientSecretA, placeholderClientSecretB)

	reloaded, err := rs.GetReceiver(ctx, target.UID, true, admin)
	require.NoError(t, err)
	require.Equal(t, schema.V1, reloaded.Integrations[0].Config.Version)
	require.Equal(t, adminTokenURL, nestedString(reloaded.Integrations[0].Settings, "http_config", "oauth2", "token_url"))
	require.NotContains(t, capture.urls(), other.UID)
}

func TestEditorCannotExfiltrateOAuthClientSecretBySwitchingIntegrationType(t *testing.T) {
	ctx := context.Background()
	secretsSvc := fakes.NewFakeSecretsService()
	rs := createReceiverServiceSut(t, &secretsSvc)
	authz := ac.NewReceiverAccess[*models.Receiver](acimpl.ProvideAccessControl(featuremgmt.WithFeatures()), false)
	editor := editorUser()
	admin := adminUser()
	capture, tokenURL, hookURL := newCaptureServer(t)
	am := newTestAlertmanager(t, secretsSvc)

	target := createOAuthWebhookReceiver(t, ctx, rs, admin, "oauth-webhook-type", placeholderClientSecretA)
	_ = createOAuthWebhookReceiver(t, ctx, rs, admin, "oauth-webhook-type-other", placeholderClientSecretB)

	require.NoError(t, authz.AuthorizeTestByUID(ctx, editor, target.UID))
	stored, err := rs.GetReceiver(ctx, target.UID, false, editor)
	require.NoError(t, err)

	body := attackTestBody(stored.Integrations[0].UID, string(schema.SlackType), string(schema.V0mimir1), hookURL, tokenURL)
	body.Integration.Settings["api_url"] = hookURL
	for _, key := range []string{"username", "title", "title_link", "pretext", "text", "fallback", "callback_id", "icon_emoji", "icon_url", "footer", "color", "channel"} {
		body.Integration.Settings[key] = "placeholder"
	}
	integration, secureFields, err := integrationFromTestBody(body.Integration)
	require.NoError(t, err)

	testingSvc := &ReceiverTestingService{
		receiverSvc:       rs,
		amProvider:        staticAlertmanager{am: am},
		encryptionService: secretsSvc,
		authz:             authz,
		emailValidator:    &NoopOrgEmailValidator{},
	}
	_, err = testingSvc.PatchIntegrationAndTest(ctx, editor, testAlert(), target.UID, integration, secureFields)
	assertSecretStaysStored(t, err, capture, placeholderClientSecretA, placeholderClientSecretB)
}

func TestEditorCannotRetargetOAuthTokenURLOnTheStoredSchema(t *testing.T) {
	ctx := context.Background()
	secretsSvc := fakes.NewFakeSecretsService()
	rs := createReceiverServiceSut(t, &secretsSvc)
	authz := ac.NewReceiverAccess[*models.Receiver](acimpl.ProvideAccessControl(featuremgmt.WithFeatures()), false)
	editor := editorUser()
	admin := adminUser()
	capture, tokenURL, hookURL := newCaptureServer(t)
	am := newTestAlertmanager(t, secretsSvc)

	target := createOAuthWebhookReceiver(t, ctx, rs, admin, "oauth-webhook-same-version", placeholderClientSecretA)
	stored, err := rs.GetReceiver(ctx, target.UID, false, editor)
	require.NoError(t, err)

	body := attackTestBody(stored.Integrations[0].UID, string(schema.WebhookType), string(schema.V1), hookURL, tokenURL)
	integration, secureFields, err := integrationFromTestBody(body.Integration)
	require.NoError(t, err)

	testingSvc := &ReceiverTestingService{
		receiverSvc:       rs,
		amProvider:        staticAlertmanager{am: am},
		encryptionService: secretsSvc,
		authz:             authz,
		emailValidator:    &NoopOrgEmailValidator{},
	}
	_, err = testingSvc.PatchIntegrationAndTest(ctx, editor, testAlert(), target.UID, integration, secureFields)
	assertSecretStaysStored(t, err, capture, placeholderClientSecretA, placeholderClientSecretB)
}

func TestEditorCannotPersistOAuthSecretOnASwitchedIntegrationVersion(t *testing.T) {
	ctx := context.Background()
	secretsSvc := fakes.NewFakeSecretsService()
	rs := createReceiverServiceSut(t, &secretsSvc)
	editor := editorUser()
	admin := adminUser()

	target := createOAuthWebhookReceiver(t, ctx, rs, admin, "oauth-webhook-update", placeholderClientSecretA)
	_ = createOAuthWebhookReceiver(t, ctx, rs, admin, "oauth-webhook-update-other", placeholderClientSecretB)
	stored, err := rs.GetReceiver(ctx, target.UID, false, editor)
	require.NoError(t, err)

	updated := stored.Clone()
	switched, ok := alertingNotify.GetSchemaVersionForIntegration(schema.WebhookType, schema.V0mimir1)
	require.True(t, ok)
	updated.Integrations[0].Config = switched
	updated.Integrations[0].Settings = attackSettings("https://attacker.example/hook", "https://attacker.example/token")
	updated.Integrations[0].SecureSettings = map[string]string{}

	_, err = rs.UpdateReceiver(ctx, &updated, map[string][]string{
		updated.Integrations[0].UID: {"http_config.oauth2.client_secret"},
	}, editor.GetOrgID(), editor)
	require.ErrorIs(t, err, ac.ErrAuthorizationBase)
	if err != nil {
		require.NotContains(t, err.Error(), placeholderClientSecretA)
		require.NotContains(t, err.Error(), placeholderClientSecretB)
	}

	reloaded, err := rs.GetReceiver(ctx, target.UID, true, admin)
	require.NoError(t, err)
	require.Equal(t, schema.V1, reloaded.Integrations[0].Config.Version)
	require.Equal(t, schema.WebhookType, reloaded.Integrations[0].Config.Type())
	require.Equal(t, adminTokenURL, nestedString(reloaded.Integrations[0].Settings, "http_config", "oauth2", "token_url"))
	require.NotContains(t, nestedString(reloaded.Integrations[0].Settings, "http_config", "oauth2", "token_url"), "attacker.example")
}

func TestEditorCannotPersistOAuthSecretOnASwitchedIntegrationType(t *testing.T) {
	ctx := context.Background()
	secretsSvc := fakes.NewFakeSecretsService()
	rs := createReceiverServiceSut(t, &secretsSvc)
	editor := editorUser()
	admin := adminUser()

	target := createOAuthWebhookReceiver(t, ctx, rs, admin, "oauth-webhook-update-type", placeholderClientSecretA)
	stored, err := rs.GetReceiver(ctx, target.UID, false, editor)
	require.NoError(t, err)

	updated := stored.Clone()
	switched, ok := alertingNotify.GetSchemaVersionForIntegration(schema.SlackType, schema.V0mimir1)
	require.True(t, ok)
	updated.Integrations[0].Config = switched
	settings := attackSettings("https://attacker.example/hook", "https://attacker.example/token")
	settings["api_url"] = "https://attacker.example/hook"
	for _, key := range []string{"username", "title", "title_link", "pretext", "text", "fallback", "callback_id", "icon_emoji", "icon_url", "footer", "color", "channel"} {
		settings[key] = "placeholder"
	}
	updated.Integrations[0].Settings = settings
	updated.Integrations[0].SecureSettings = map[string]string{}

	_, err = rs.UpdateReceiver(ctx, &updated, map[string][]string{
		updated.Integrations[0].UID: {"http_config.oauth2.client_secret"},
	}, editor.GetOrgID(), editor)
	require.ErrorIs(t, err, ac.ErrAuthorizationBase)

	reloaded, err := rs.GetReceiver(ctx, target.UID, true, admin)
	require.NoError(t, err)
	require.Equal(t, schema.V1, reloaded.Integrations[0].Config.Version)
	require.Equal(t, schema.WebhookType, reloaded.Integrations[0].Config.Type())
	require.Equal(t, adminTokenURL, nestedString(reloaded.Integrations[0].Settings, "http_config", "oauth2", "token_url"))
}

func assertSecretStaysStored(t *testing.T, err error, capture *captureServer, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if capture.contains(secret) {
			t.Fatalf("stored client secret was sent to the caller-controlled endpoint")
		}
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Fatalf("error result contains a stored client secret")
		}
	}
	require.ErrorIs(t, err, ac.ErrAuthorizationBase)
}

func createOAuthWebhookReceiver(t *testing.T, ctx context.Context, rs *ReceiverService, admin identity.Requester, name, clientSecret string) *models.Receiver {
	t.Helper()
	cfg, ok := alertingNotify.GetSchemaVersionForIntegration(schema.WebhookType, schema.V1)
	require.True(t, ok)
	receiver := &models.Receiver{
		Name:   name,
		Origin: models.ResourceOriginGrafana,
		Integrations: []*models.Integration{{
			Name:   name,
			Config: cfg,
			Settings: map[string]any{
				"url": adminWebhookURL,
				"http_config": map[string]any{
					"oauth2": map[string]any{
						"client_id":     placeholderClientID,
						"token_url":     adminTokenURL,
						"client_secret": clientSecret,
					},
				},
			},
			SecureSettings: map[string]string{},
		}},
	}
	created, err := rs.CreateReceiver(ctx, receiver, admin.GetOrgID(), admin)
	require.NoError(t, err)
	loaded, err := rs.GetReceiver(ctx, created.UID, true, admin)
	require.NoError(t, err)
	require.Equal(t, clientSecret, nestedString(loaded.Integrations[0].Settings, "http_config", "oauth2", "client_secret"))
	redacted, err := rs.GetReceiver(ctx, created.UID, false, admin)
	require.NoError(t, err)
	require.Empty(t, nestedString(redacted.Integrations[0].Settings, "http_config", "oauth2", "client_secret"))
	require.NotEmpty(t, redacted.Integrations[0].SecureSettings["http_config.oauth2.client_secret"])
	return redacted
}

func attackTestBody(integrationUID, integrationType, version, hookURL, tokenURL string) v1beta1.CreateReceiverIntegrationTestRequestBody {
	uid := integrationUID
	return v1beta1.CreateReceiverIntegrationTestRequestBody{
		Integration: v1beta1.CreateReceiverIntegrationTestRequestIntegration{
			Uid:     &uid,
			Type:    integrationType,
			Version: version,
			Settings: map[string]any{
				"url": hookURL,
				"http_config": map[string]any{
					"oauth2": map[string]any{
						"client_id": placeholderClientID,
						"token_url": tokenURL,
					},
				},
			},
			SecureFields: map[string]bool{
				"http_config.oauth2.client_secret": true,
			},
		},
		Alert: v1beta1.CreateReceiverIntegrationTestRequestAlert{
			Labels:      map[string]string{"alertname": "placeholder"},
			Annotations: map[string]string{"summary": "placeholder"},
		},
	}
}

func attackSettings(hookURL, tokenURL string) map[string]any {
	return map[string]any{
		"url": hookURL,
		"http_config": map[string]any{
			"oauth2": map[string]any{
				"client_id": placeholderClientID,
				"token_url": tokenURL,
			},
		},
	}
}

// integrationFromTestBody mirrors convertReceiverIntegrationToIntegration so the
// test request is the body the receiver test subresource accepts.
func integrationFromTestBody(integration v1beta1.CreateReceiverIntegrationTestRequestIntegration) (models.Integration, []string, error) {
	integrationType, err := alertingNotify.IntegrationTypeFromString(integration.Type)
	if err != nil {
		return models.Integration{}, nil, err
	}
	typeSchema, _ := alertingNotify.GetSchemaForIntegration(integrationType)
	var config schema.IntegrationSchemaVersion
	if integration.Version != "" {
		var ok bool
		config, ok = typeSchema.GetVersion(schema.Version(integration.Version))
		if !ok {
			return models.Integration{}, nil, models.ErrReceiverInvalid(errInvalidVersion(integration.Version, integration.Type))
		}
	} else {
		config = typeSchema.GetCurrentVersion()
	}
	out := models.Integration{
		Name:           "",
		Config:         config,
		Settings:       integration.Settings,
		SecureSettings: map[string]string{},
	}
	if integration.Uid != nil {
		out.UID = *integration.Uid
	}
	if integration.DisableResolveMessage != nil {
		out.DisableResolveMessage = *integration.DisableResolveMessage
	}
	var secureFields []string
	if out.UID != "" {
		for key, isSecure := range integration.SecureFields {
			if isSecure {
				secureFields = append(secureFields, key)
			}
		}
	}
	return out, secureFields, nil
}

type versionError string

func (e versionError) Error() string { return string(e) }

func errInvalidVersion(version, integrationType string) error {
	return versionError("invalid version " + version + " for integration type " + integrationType)
}

func editorUser() *user.SignedInUser {
	all := []string{models.ScopeReceiversAll}
	return &user.SignedInUser{
		OrgID:   1,
		OrgRole: org.RoleEditor,
		Permissions: map[int64]map[string][]string{
			1: {
				accesscontrol.ActionAlertingReceiversRead:       all,
				accesscontrol.ActionAlertingReceiversCreate:     nil,
				accesscontrol.ActionAlertingReceiversTest:       nil,
				accesscontrol.ActionAlertingReceiversTestCreate: {models.ScopeReceiversProvider.GetNewResourceScope(), models.ScopeReceiversAll},
				accesscontrol.ActionAlertingReceiversUpdate:     all,
				accesscontrol.ActionAlertingReceiversDelete:     all,
			},
		},
	}
}

func adminUser() *user.SignedInUser {
	all := []string{models.ScopeReceiversAll}
	return &user.SignedInUser{
		OrgID:   1,
		OrgRole: org.RoleAdmin,
		Permissions: map[int64]map[string][]string{
			1: {
				accesscontrol.ActionAlertingNotificationsWrite:       nil,
				accesscontrol.ActionAlertingNotificationsRead:        nil,
				accesscontrol.ActionAlertingReceiversCreate:          nil,
				accesscontrol.ActionAlertingReceiversRead:            all,
				accesscontrol.ActionAlertingReceiversUpdate:          all,
				accesscontrol.ActionAlertingReceiversReadSecrets:     all,
				accesscontrol.ActionAlertingReceiversUpdateProtected: all,
			},
		},
	}
}

func testAlert() Alert {
	return Alert{
		Labels:      map[string]string{"alertname": "placeholder"},
		Annotations: map[string]string{"summary": "placeholder"},
	}
}

type staticAlertmanager struct {
	am Alertmanager
}

func (s staticAlertmanager) AlertmanagerFor(int64) (Alertmanager, error) {
	return s.am, nil
}

func newTestAlertmanager(t *testing.T, secretsSvc fakes.FakeSecretsService) *alertmanager {
	t.Helper()
	logger := kitlog.NewNopLogger()
	maint := func(alertingNotify.State) (int64, error) { return 0, nil }
	gam, err := alertingNotify.NewGrafanaAlertmanager(alertingNotify.GrafanaAlertmanagerOpts{
		ExternalURL: "http://localhost",
		Silences: maintenanceOptions{
			retention:            time.Hour,
			maintenanceFrequency: time.Hour,
			maintenanceFunc:      maint,
		},
		Nflog: maintenanceOptions{
			retention:            time.Hour,
			maintenanceFrequency: time.Hour,
			maintenanceFunc:      maint,
		},
		EmailSender:   noopEmailSender{},
		ImageProvider: noopImageProvider{},
		Decrypter:     secretsSvc.GetDecryptedValue,
		TenantKey:     "orgID",
		TenantID:      1,
		Peer:          &NilPeer{},
		Logger:        logger,
		Metrics:       alertingNotify.NewGrafanaAlertmanagerMetrics(prometheus.NewRegistry(), logger),
	})
	require.NoError(t, err)
	t.Cleanup(gam.StopAndWait)
	return &alertmanager{Base: gam}
}

type noopEmailSender struct{}

func (noopEmailSender) SendEmail(context.Context, *receivers.SendEmailSettings) error { return nil }

type noopImageProvider struct{}

func (noopImageProvider) GetImage(context.Context, types.Alert) (*alertingImages.Image, error) {
	return nil, alertingImages.ErrImageNotFound
}

type captureServer struct {
	mu       sync.Mutex
	requests []capturedRequest
}

type capturedRequest struct {
	url         string
	body        string
	header      string
	basicUser   string
	basicSecret string
}

func newCaptureServer(t *testing.T) (*captureServer, string, string) {
	t.Helper()
	capture := &captureServer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := capturedRequest{
			url:    r.URL.String(),
			body:   string(body),
			header: r.Header.Get("Authorization"),
		}
		if user, pass, ok := r.BasicAuth(); ok {
			req.basicUser = user
			req.basicSecret = pass
		}
		capture.mu.Lock()
		capture.requests = append(capture.requests, req)
		capture.mu.Unlock()

		if strings.Contains(r.URL.Path, "/token") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"placeholder-token","token_type":"Bearer","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return capture, server.URL + "/token", server.URL + "/hook"
}

func (c *captureServer) contains(secret string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	for _, req := range c.requests {
		if strings.Contains(req.body, secret) || strings.Contains(req.header, secret) || strings.Contains(req.header, encoded) {
			return true
		}
		if req.basicSecret == secret || strings.Contains(req.basicUser, secret) || strings.Contains(req.basicSecret, secret) {
			return true
		}
	}
	return false
}

func (c *captureServer) urls() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, req := range c.requests {
		b.WriteString(req.url)
		b.WriteByte('\n')
	}
	return b.String()
}

func nestedString(settings map[string]any, path ...string) string {
	var current any = settings
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[key]
	}
	s, _ := current.(string)
	return s
}
