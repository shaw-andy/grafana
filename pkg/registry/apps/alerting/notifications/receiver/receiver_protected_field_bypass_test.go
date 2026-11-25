package receiver

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
	alertingImages "github.com/grafana/alerting/images"
	alertingModels "github.com/grafana/alerting/models"
	alertingNotify "github.com/grafana/alerting/notify"
	"github.com/grafana/alerting/receivers"
	"github.com/grafana/alerting/receivers/schema"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	v1beta1 "github.com/grafana/grafana/apps/alerting/notifications/pkg/apis/alertingnotifications/v1beta1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	ac "github.com/grafana/grafana/pkg/services/ngalert/accesscontrol"
	"github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/notifier"
	"github.com/grafana/grafana/pkg/services/ngalert/notifier/legacy_storage"
	"github.com/grafana/grafana/pkg/services/ngalert/notifier/routes"
	"github.com/grafana/grafana/pkg/services/ngalert/provisioning/validation"
	ngfakes "github.com/grafana/grafana/pkg/services/ngalert/tests/fakes"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	"github.com/grafana/grafana/pkg/services/user"
)

const (
	apiPlaceholderClientID     = "placeholder-client-id"
	apiPlaceholderClientSecret = "placeholder-client-secret-a"
	apiAdminTokenURL           = "https://token.example.invalid/token"
	apiAdminWebhookURL         = "https://hook.example.invalid/hook"
)

// TestEditorCannotExfiltrateOAuthClientSecretThroughReceiverTestAPI runs the
// attack through RequestHandler.TestReceiver: the request names the stored
// integration, switches it to the Mimir schema, and asks for the stored client
// secret. The secret must not leave the process.
func TestEditorCannotExfiltrateOAuthClientSecretThroughReceiverTestAPI(t *testing.T) {
	t.Parallel()

	capture := newAPICapture()
	defer capture.Close()

	secretsSvc := fakes.NewFakeSecretsService()
	authz := ac.NewReceiverAccess[*models.Receiver](acimpl.ProvideAccessControl(featuremgmt.WithFeatures()), true)
	admin := apiUser(1, org.RoleAdmin, apiAdminPermissions())
	editor := apiUser(2, org.RoleEditor, apiEditorPermissions())
	ctx := context.Background()

	receiverSvc := newAPIReceiverService(t, secretsSvc, authz)
	stored := createAPIOAuthReceiver(t, ctx, receiverSvc, admin, "oauth-api")
	require.NotEmpty(t, stored.Integrations[0].UID)

	base := newAPIGrafanaAlertmanager(t, secretsSvc)
	testingSvc := notifier.NewReceiverTestingService(receiverSvc, apiAlertmanagerProvider{base: base}, secretsSvc, authz, nil, &notifier.NoopOrgEmailValidator{})
	handler := New(testingSvc)

	authCtx := identity.WithRequester(ctx, editor)
	decision, _, err := Authorize(authCtx, authz, authorizer.AttributesRecord{
		User:            editor,
		Verb:            "create",
		APIGroup:        ResourceInfo.GroupResource().Group,
		Resource:        ResourceInfo.GroupResource().Resource,
		Subresource:     "test",
		Name:            stored.UID,
		ResourceRequest: true,
	})
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)

	uid := stored.Integrations[0].UID
	_, err = handler.TestReceiver(authCtx, editor, stored.UID, v1beta1.CreateReceiverIntegrationTestRequestBody{
		Integration: v1beta1.CreateReceiverIntegrationTestRequestIntegration{
			Uid:     &uid,
			Type:    "webhook",
			Version: "v0mimir1",
			Settings: map[string]any{
				"url": apiAdminWebhookURL,
				"http_config": map[string]any{
					"oauth2": map[string]any{
						"client_id": apiPlaceholderClientID,
						"token_url": capture.URL + "/token",
					},
				},
			},
			SecureFields: map[string]bool{
				"http_config.oauth2.client_secret": true,
			},
		},
	})
	if capture.contains(apiPlaceholderClientSecret) {
		t.Fatal("stored client secret was sent to the caller-controlled endpoint")
	}
	require.ErrorIs(t, err, ac.ErrAuthorizationBase)
	require.NotContains(t, err.Error(), apiPlaceholderClientSecret)
}

func newAPIReceiverService(t *testing.T, secretsSvc fakes.FakeSecretsService, authz *ac.ReceiverAccess[*models.Receiver]) *notifier.ReceiverService {
	t.Helper()
	cfgStore := legacy_storage.NewAlertmanagerConfigStore(
		newAPIConfigStore(),
		notifier.NewExtraConfigsCrypto(secretsSvc),
		featuremgmt.WithFeatures(),
	)
	return notifier.NewReceiverService(
		authz,
		cfgStore,
		ngfakes.NewFakeProvisioningStore(),
		noopRuleNotificationStore{},
		routes.NewFakeService(legacy_storage.ConfigRevision{}),
		secretsSvc,
		noopTransaction{},
		log.NewNopLogger(),
		ngfakes.NewFakeReceiverPermissionsService(),
		tracing.InitializeTracerForTest(),
		validation.ValidateProvenanceRelaxed,
		false,
		nil,
		&notifier.NoopOrgEmailValidator{},
		notifier.NoopReceiverStatusFetcher{},
	)
}

func createAPIOAuthReceiver(t *testing.T, ctx context.Context, svc *notifier.ReceiverService, admin identity.Requester, name string) *models.Receiver {
	t.Helper()
	cfg, ok := alertingNotify.GetSchemaVersionForIntegration(schema.WebhookType, schema.V1)
	require.True(t, ok)
	created, err := svc.CreateReceiver(ctx, &models.Receiver{
		Name:   name,
		Origin: models.ResourceOriginGrafana,
		Integrations: []*models.Integration{{
			Name:   name,
			Config: cfg,
			Settings: map[string]any{
				"url": apiAdminWebhookURL,
				"http_config": map[string]any{
					"oauth2": map[string]any{
						"client_id":     apiPlaceholderClientID,
						"token_url":     apiAdminTokenURL,
						"client_secret": apiPlaceholderClientSecret,
					},
				},
			},
			SecureSettings: map[string]string{},
		}},
	}, admin.GetOrgID(), admin)
	require.NoError(t, err)
	return created
}

type apiAlertmanagerProvider struct {
	base *alertingNotify.GrafanaAlertmanager
}

func (p apiAlertmanagerProvider) AlertmanagerFor(int64) (notifier.Alertmanager, error) {
	return apiAlertmanager{base: p.base}, nil
}

// apiAlertmanager.TestIntegration is the product wrapper: it converts the
// integration and calls the alertmanager implementation. The other methods are
// not on the test path.
type apiAlertmanager struct {
	base *alertingNotify.GrafanaAlertmanager
}

func (a apiAlertmanager) TestIntegration(ctx context.Context, receiverName string, integration models.Integration, alert alertingModels.TestReceiversConfigAlertParams) (alertingModels.IntegrationStatus, error) {
	cfg, err := notifier.IntegrationToIntegrationConfig(integration)
	if err != nil {
		return alertingModels.IntegrationStatus{}, err
	}
	return a.base.TestIntegration(ctx, receiverName, cfg, alert)
}

func (apiAlertmanager) ApplyConfig(context.Context, alertingNotify.NotificationsConfiguration) (bool, error) {
	return false, nil
}
func (apiAlertmanager) GetStatus(context.Context) (definitions.GettableStatus, error) {
	return definitions.GettableStatus{}, nil
}
func (apiAlertmanager) CreateSilence(context.Context, *definitions.PostableSilence) (string, error) {
	return "", nil
}
func (apiAlertmanager) DeleteSilence(context.Context, string) error { return nil }
func (apiAlertmanager) GetSilence(context.Context, string) (definitions.GettableSilence, error) {
	return definitions.GettableSilence{}, nil
}
func (apiAlertmanager) ListSilences(context.Context, []string) (definitions.GettableSilences, error) {
	return nil, nil
}
func (apiAlertmanager) SilenceState(context.Context) (alertingNotify.SilenceState, error) {
	return alertingNotify.SilenceState{}, nil
}
func (apiAlertmanager) GetAlerts(context.Context, bool, bool, bool, []string, string) (definitions.GettableAlerts, error) {
	return nil, nil
}
func (apiAlertmanager) GetAlertGroups(context.Context, bool, bool, bool, []string, string) (definitions.AlertGroups, error) {
	return nil, nil
}
func (apiAlertmanager) PutAlerts(context.Context, definitions.PostableAlerts) error { return nil }
func (apiAlertmanager) GetReceivers(context.Context) ([]alertingModels.ReceiverStatus, error) {
	return nil, nil
}
func (apiAlertmanager) TestTemplate(context.Context, definitions.TestTemplatesConfigBodyParams) (*notifier.TestTemplatesResults, error) {
	return nil, nil
}
func (apiAlertmanager) StopAndWait() {}
func (apiAlertmanager) Ready() bool  { return true }

func newAPIGrafanaAlertmanager(t *testing.T, secretsSvc fakes.FakeSecretsService) *alertingNotify.GrafanaAlertmanager {
	t.Helper()
	logger := kitlog.NewNopLogger()
	maint := func(alertingNotify.State) (int64, error) { return 0, nil }
	gam, err := alertingNotify.NewGrafanaAlertmanager(alertingNotify.GrafanaAlertmanagerOpts{
		Silences:      apiMaintenance{retention: time.Hour, frequency: time.Hour, maint: maint},
		Nflog:         apiMaintenance{retention: time.Hour, frequency: time.Hour, maint: maint},
		EmailSender:   apiNoopEmail{},
		ImageProvider: apiNoopImages{},
		Decrypter:     secretsSvc.GetDecryptedValue,
		TenantKey:     "orgID",
		TenantID:      1,
		Peer:          &notifier.NilPeer{},
		Logger:        logger,
		Metrics:       alertingNotify.NewGrafanaAlertmanagerMetrics(prometheus.NewRegistry(), logger),
	})
	require.NoError(t, err)
	t.Cleanup(gam.StopAndWait)
	return gam
}

type apiMaintenance struct {
	retention time.Duration
	frequency time.Duration
	maint     func(alertingNotify.State) (int64, error)
}

func (m apiMaintenance) InitialState() string                { return "" }
func (m apiMaintenance) Retention() time.Duration            { return m.retention }
func (m apiMaintenance) MaintenanceFrequency() time.Duration { return m.frequency }
func (m apiMaintenance) MaintenanceFunc(state alertingNotify.State) (int64, error) {
	return m.maint(state)
}

type apiNoopEmail struct{}

func (apiNoopEmail) SendEmail(context.Context, *receivers.SendEmailSettings) error { return nil }

type apiNoopImages struct{}

func (apiNoopImages) GetImage(context.Context, types.Alert) (*alertingImages.Image, error) {
	return nil, alertingImages.ErrImageNotFound
}

type noopRuleNotificationStore struct{}

func (noopRuleNotificationStore) RenameReceiverInNotificationSettings(context.Context, int64, string, string, func(models.Provenance) bool, bool) ([]models.AlertRuleKey, []models.AlertRuleKey, error) {
	return nil, nil, nil
}

func (noopRuleNotificationStore) ListContactPointRoutings(context.Context, models.ListContactPointRoutingsQuery) (map[models.AlertRuleKey]models.ContactPointRouting, error) {
	return nil, nil
}

type noopTransaction struct{}

func (noopTransaction) InTransaction(ctx context.Context, work func(context.Context) error) error {
	return work(ctx)
}

type apiConfigStore struct {
	mu  sync.Mutex
	cfg *models.AlertConfiguration
}

func newAPIConfigStore() *apiConfigStore {
	return &apiConfigStore{cfg: &models.AlertConfiguration{
		AlertmanagerConfiguration: `{
			"template_files": {},
			"alertmanager_config": {
				"route": {"receiver": "grafana-default-email"},
				"receivers": [{
					"name": "grafana-default-email",
					"grafana_managed_receiver_configs": [{
						"uid": "default-email",
						"name": "grafana-default-email",
						"type": "email",
						"settings": {"addresses": "example@example.com"}
					}]
				}]
			}
		}`,
		ConfigurationVersion: "v1",
		OrgID:                1,
	}}
}

func (s *apiConfigStore) GetLatestAlertmanagerConfiguration(context.Context, int64) (*models.AlertConfiguration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := *s.cfg
	return &copied, nil
}

func (s *apiConfigStore) UpdateAlertmanagerConfiguration(ctx context.Context, cmd *models.SaveAlertmanagerConfigurationCmd) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = &models.AlertConfiguration{
		AlertmanagerConfiguration: cmd.AlertmanagerConfiguration,
		ConfigurationVersion:      cmd.ConfigurationVersion,
		OrgID:                     cmd.OrgID,
		Default:                   cmd.Default,
	}
	return nil
}

type apiCapture struct {
	*httptest.Server
	mu       sync.Mutex
	requests []apiCapturedRequest
}

type apiCapturedRequest struct {
	body   string
	header string
	user   string
	pass   string
}

func newAPICapture() *apiCapture {
	capture := &apiCapture{}
	capture.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		user, pass, _ := r.BasicAuth()
		capture.mu.Lock()
		capture.requests = append(capture.requests, apiCapturedRequest{
			body:   string(body),
			header: r.Header.Get("Authorization"),
			user:   user,
			pass:   pass,
		})
		capture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"placeholder-token","token_type":"Bearer","expires_in":3600}`))
	}))
	return capture
}

func (c *apiCapture) contains(secret string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	for _, request := range c.requests {
		if strings.Contains(request.body, secret) || strings.Contains(request.header, secret) || strings.Contains(request.header, encoded) || strings.Contains(request.user, secret) || strings.Contains(request.pass, secret) {
			return true
		}
	}
	return false
}

func apiUser(id int64, role org.RoleType, permissions map[string][]string) identity.Requester {
	return &user.SignedInUser{
		UserID:      id,
		OrgID:       1,
		OrgRole:     role,
		Permissions: map[int64]map[string][]string{1: permissions},
	}
}

func apiEditorPermissions() map[string][]string {
	return map[string][]string{
		accesscontrol.ActionAlertingReceiversRead:       {models.ScopeReceiversAll},
		accesscontrol.ActionAlertingReceiversCreate:     nil,
		accesscontrol.ActionAlertingReceiversTest:       nil,
		accesscontrol.ActionAlertingReceiversTestCreate: {models.ScopeReceiversAll, models.ScopeReceiversProvider.GetNewResourceScope()},
		accesscontrol.ActionAlertingReceiversUpdate:     {models.ScopeReceiversAll},
		accesscontrol.ActionAlertingReceiversDelete:     {models.ScopeReceiversAll},
	}
}

func apiAdminPermissions() map[string][]string {
	return map[string][]string{
		accesscontrol.ActionAlertingNotificationsWrite:       {models.ScopeReceiversAll},
		accesscontrol.ActionAlertingNotificationsRead:        {models.ScopeReceiversAll},
		accesscontrol.ActionAlertingReceiversCreate:          nil,
		accesscontrol.ActionAlertingReceiversRead:            {models.ScopeReceiversAll},
		accesscontrol.ActionAlertingReceiversUpdate:          {models.ScopeReceiversAll},
		accesscontrol.ActionAlertingReceiversReadSecrets:     {models.ScopeReceiversAll},
		accesscontrol.ActionAlertingReceiversUpdateProtected: {models.ScopeReceiversAll},
	}
}
