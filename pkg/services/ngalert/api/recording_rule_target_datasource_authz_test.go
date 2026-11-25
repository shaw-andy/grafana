package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"

	alertingv0 "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/registry/apps/alerting/rules/recordingrule"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	dsfakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/datasources/guardian"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	"github.com/grafana/grafana/pkg/services/ngalert/accesscontrol"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/metrics"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/provisioning"
	"github.com/grafana/grafana/pkg/services/ngalert/tests/fakes"
	"github.com/grafana/grafana/pkg/services/ngalert/writer"
	"github.com/grafana/grafana/pkg/services/quota"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	targetHeaderName = "X-Recording-Target"
	forgedLabelKey   = "origin"
	forgedLabelValue = "forged"
)

// persistingRuleStore applies updates to the in-memory rules. The shared fake
// records update commands and leaves the previous rule in place, while the
// production store replaces the row with the submitted rule.
type persistingRuleStore struct {
	*fakes.RuleStore
}

func (s *persistingRuleStore) UpdateAlertRules(ctx context.Context, user *ngmodels.UserUID, updates []ngmodels.UpdateRule) error {
	if err := s.RuleStore.UpdateAlertRules(ctx, user, updates); err != nil {
		return err
	}
	for _, update := range updates {
		replaced := ngmodels.CopyRule(&update.New)
		rules := s.Rules[replaced.OrgID]
		found := false
		for i, existing := range rules {
			if existing.UID == replaced.UID && existing.OrgID == replaced.OrgID {
				rules[i] = replaced
				found = true
				break
			}
		}
		if !found {
			s.Rules[replaced.OrgID] = append(rules, replaced)
		}
	}
	return nil
}

// guardianCache resolves datasources the way CacheServiceImpl does in this
// build: load by uid and org, then ask the OSS datasource guardian. That
// guardian allows the query. It does not consult datasources:query scopes.
type guardianCache struct {
	byUID    map[string]*datasources.DataSource
	guardian guardian.DatasourceGuardianProvider
}

func (c *guardianCache) GetDatasource(_ context.Context, _ int64, _ identity.Requester, _ bool) (*datasources.DataSource, error) {
	return nil, datasources.ErrDataSourceNotFound
}

func (c *guardianCache) GetDatasourceByUID(_ context.Context, uid string, user identity.Requester, _ bool) (*datasources.DataSource, error) {
	if user == nil || user.GetOrgID() == 0 {
		return nil, datasources.ErrDataSourceNotFound
	}
	ds, ok := c.byUID[uid]
	if !ok || ds.OrgID != user.GetOrgID() {
		return nil, datasources.ErrDataSourceNotFound
	}
	can, err := c.guardian.New(user.GetOrgID(), user, *ds).CanQuery(ds.ID)
	if err != nil {
		return nil, err
	}
	if !can {
		return nil, datasources.ErrDataSourceAccessDenied
	}
	return ds, nil
}

// orgDataSources returns the datasource for the org in the query. After Swap,
// the protected datasource URL points at a second server so a write that looks
// the uid up again is observable separately from the URL seen at request time.
type orgDataSources struct {
	*dsfakes.FakeDataSourceService
	protectedUID string
	swapURL      string
	swapped      bool
	lookups      []datasources.GetDataSourceQuery
}

func (s *orgDataSources) GetDataSource(ctx context.Context, query *datasources.GetDataSourceQuery) (*datasources.DataSource, error) {
	s.lookups = append(s.lookups, *query)
	ds, err := s.FakeDataSourceService.GetDataSource(ctx, query)
	if err != nil {
		return nil, err
	}
	if query.OrgID != 0 && ds.OrgID != query.OrgID {
		return nil, datasources.ErrDataSourceNotFound
	}
	if s.swapped && ds.UID == s.protectedUID {
		copied := *ds
		copied.URL = s.swapURL
		return &copied, nil
	}
	return ds, nil
}

type recordingPluginContext struct {
	users []identity.Requester
}

func (p *recordingPluginContext) GetWithDataSource(_ context.Context, _ string, user identity.Requester, _ *datasources.DataSource) (backend.PluginContext, error) {
	p.users = append(p.users, user)
	return backend.PluginContext{}, nil
}

type openQuota struct{}

func (openQuota) GetQuotasByScope(context.Context, quota.Scope, int64) ([]quota.QuotaDTO, error) {
	return nil, nil
}
func (openQuota) Update(context.Context, *quota.UpdateQuotaCmd) error { return nil }
func (openQuota) QuotaReached(*contextmodel.ReqContext, quota.TargetSrv) (bool, error) {
	return false, nil
}
func (openQuota) CheckQuotaReached(context.Context, quota.TargetSrv, *quota.ScopeParameters) (bool, error) {
	return false, nil
}
func (openQuota) DeleteQuotaForUser(context.Context, int64) error { return nil }
func (openQuota) RegisterQuotaReporter(*quota.NewUsageReporter) error {
	return nil
}

type recordingRuleHarness struct {
	orgID        int64
	folderUID    string
	folderTitle  string
	allowedUID   string
	protectedUID string
	metric       string

	store     *persistingRuleStore
	folders   *foldertest.FakeService
	ds        *orgDataSources
	cache     *guardianCache
	plugin    *recordingPluginContext
	remote    *writer.DatasourceWriter
	protected *writer.TestRemoteWriteTarget
	allowed   *writer.TestRemoteWriteTarget
	swapped   *writer.TestRemoteWriteTarget
	authz     *accesscontrol.RuleService
}

func newRecordingRuleHarness(t *testing.T, metric string) *recordingRuleHarness {
	t.Helper()

	const (
		orgID        = int64(1)
		folderUID    = "team-folder"
		folderTitle  = "team-folder"
		allowedUID   = "allowed-ds"
		protectedUID = "protected-ds"
	)

	protected := writer.NewTestRemoteWriteTarget(t)
	allowed := writer.NewTestRemoteWriteTarget(t)
	swapped := writer.NewTestRemoteWriteTarget(t)
	t.Cleanup(protected.Close)
	t.Cleanup(allowed.Close)
	t.Cleanup(swapped.Close)
	protected.ExpectedPath = "/api/v1/write"
	allowed.ExpectedPath = "/api/v1/write"
	swapped.ExpectedPath = "/api/v1/write"

	jsonData := simplejson.New()
	jsonData.Set("prometheusType", "Prometheus")

	sources := &dsfakes.FakeDataSourceService{DataSourceHeaders: map[string]http.Header{}}
	add := func(uid, url, header string) {
		t.Helper()
		ds, err := sources.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:    orgID,
			UID:      uid,
			Name:     uid,
			Type:     datasources.DS_PROMETHEUS,
			JsonData: jsonData,
		})
		require.NoError(t, err)
		ds.URL = url
		sources.DataSourceHeaders[uid] = http.Header{targetHeaderName: []string{header}}
	}
	add(allowedUID, allowed.DatasourceURL(), "allowed")
	add(protectedUID, protected.DatasourceURL(), "protected")

	ds := &orgDataSources{
		FakeDataSourceService: sources,
		protectedUID:          protectedUID,
		swapURL:               swapped.DatasourceURL(),
	}
	cache := &guardianCache{
		byUID:    map[string]*datasources.DataSource{},
		guardian: guardian.ProvideGuardian(),
	}
	for _, source := range sources.DataSources {
		cache.byUID[source.UID] = source
	}

	ruleStore := fakes.NewRuleStore(t)
	ruleStore.Folders[orgID] = []*folder.Folder{{
		UID:       folderUID,
		Title:     folderTitle,
		OrgID:     orgID,
		ParentUID: folder.LegacyRootFolderUID, //nolint:staticcheck
	}}

	plugin := &recordingPluginContext{}
	remote := writer.NewDatasourceWriter(
		writer.DatasourceWriterConfig{Timeout: 5 * time.Second},
		ds,
		httpclient.NewProvider(),
		plugin,
		clock.New(),
		log.New("recording-rule-target-test"),
		metrics.NewRemoteWriterMetrics(prometheus.NewRegistry()),
	)

	folders := foldertest.NewFakeService()
	folders.AddFolder(&folder.Folder{UID: folderUID, Title: folderTitle, OrgID: orgID})

	return &recordingRuleHarness{
		orgID:        orgID,
		folderUID:    folderUID,
		folderTitle:  folderTitle,
		allowedUID:   allowedUID,
		protectedUID: protectedUID,
		metric:       metric,
		store:        &persistingRuleStore{RuleStore: ruleStore},
		folders:      folders,
		ds:           ds,
		cache:        cache,
		plugin:       plugin,
		remote:       remote,
		protected:    protected,
		allowed:      allowed,
		swapped:      swapped,
		authz:        accesscontrol.NewRuleService(acimpl.ProvideAccessControl(featuremgmt.WithFeatures())),
	}
}

func (h *recordingRuleHarness) editor(queryDatasources ...string) *user.SignedInUser {
	folderScope := folder.ScopeFoldersProvider.GetResourceScopeUID(h.folderUID)
	perms := map[string][]string{
		ac.ActionAlertingRuleCreate: {folderScope},
		ac.ActionAlertingRuleRead:   {folderScope},
		ac.ActionAlertingRuleUpdate: {folderScope},
		folder.ActionFoldersRead:    {folderScope},
	}
	for _, uid := range queryDatasources {
		perms[datasources.ActionQuery] = append(perms[datasources.ActionQuery], datasources.ScopeProvider.GetResourceScopeUID(uid))
	}
	return &user.SignedInUser{
		UserID:      7,
		OrgID:       h.orgID,
		Permissions: map[int64]map[string][]string{h.orgID: perms},
	}
}

func (h *recordingRuleHarness) ruler() *RulerSrv {
	return &RulerSrv{
		xactManager:     h.store,
		store:           h.store,
		QuotaService:    openQuota{},
		provenanceStore: fakes.NewFakeProvisioningStore(),
		log:             log.New("recording-rule-target-test"),
		cfg: &setting.UnifiedAlertingSettings{
			BaseInterval:                  10 * time.Second,
			DefaultRuleEvaluationInterval: 10 * time.Second,
		},
		authz:              h.authz,
		amConfigStore:      &fakeAMRefresher{},
		amRefresher:        &fakeAMRefresher{},
		conditionValidator: &recordingConditionValidator{},
	}
}

func (h *recordingRuleHarness) rules() *provisioning.AlertRuleService {
	return provisioning.NewAlertRuleService(
		h.store,
		fakes.NewFakeProvisioningStore(),
		h.folders,
		openQuota{},
		&provisioning.NopTransactionManager{},
		60,
		10,
		100,
		log.New("recording-rule-target-test"),
		&provisioning.NotificationSettingsValidatorProviderFake{},
		h.authz,
		provisioning.ProvideRuleMutationValidator(),
	)
}

func (h *recordingRuleHarness) query(datasourceUID string) apimodels.AlertQuery {
	return apimodels.AlertQuery{
		RefID:             "A",
		DatasourceUID:     datasourceUID,
		RelativeTimeRange: apimodels.RelativeTimeRange{From: apimodels.Duration(time.Minute), To: 0},
		Model:             []byte(`{"refId":"A"}`),
	}
}

func (h *recordingRuleHarness) rulerGroup(datasourceUID, targetUID, ruleUID string) apimodels.PostableRuleGroupConfig {
	return apimodels.PostableRuleGroupConfig{
		Name:     "rec-group",
		Interval: model.Duration(10 * time.Second),
		Rules: []apimodels.PostableExtendedRuleNode{{
			ApiRuleNode: &apimodels.ApiRuleNode{
				Labels: map[string]string{forgedLabelKey: forgedLabelValue},
			},
			GrafanaManagedAlert: &apimodels.PostableGrafanaRule{
				Title: "forged recording rule",
				UID:   ruleUID,
				Data:  []apimodels.AlertQuery{h.query(datasourceUID)},
				Record: &apimodels.Record{
					Metric:              h.metric,
					From:                "A",
					TargetDatasourceUID: targetUID,
				},
			},
		}},
	}
}

func (h *recordingRuleHarness) provisionedRule(datasourceUID, targetUID, ruleUID string) apimodels.ProvisionedAlertRule {
	target := targetUID
	return apimodels.ProvisionedAlertRule{
		UID:       ruleUID,
		OrgID:     h.orgID,
		FolderUID: h.folderUID,
		RuleGroup: "rec-group",
		Title:     "forged recording rule",
		Data:      []apimodels.AlertQuery{h.query(datasourceUID)},
		Labels:    map[string]string{forgedLabelKey: forgedLabelValue},
		Record: &apimodels.Record{
			Metric:              h.metric,
			From:                "A",
			TargetDatasourceUID: target,
		},
	}
}

func (h *recordingRuleHarness) seedRecordingRule(t *testing.T, datasourceUID, targetUID, ruleUID, metric string) {
	t.Helper()
	modelJSON := []byte(`{"refId":"A"}`)
	rule := &ngmodels.AlertRule{
		OrgID:           h.orgID,
		UID:             ruleUID,
		NamespaceUID:    h.folderUID,
		RuleGroup:       "rec-group",
		Title:           "existing recording rule",
		IntervalSeconds: 10,
		Data: []ngmodels.AlertQuery{{
			RefID:             "A",
			DatasourceUID:     datasourceUID,
			RelativeTimeRange: ngmodels.RelativeTimeRange{From: ngmodels.Duration(time.Minute)},
			Model:             modelJSON,
		}},
		Labels: map[string]string{forgedLabelKey: "existing"},
		Record: &ngmodels.Record{
			Metric:              metric,
			From:                "A",
			TargetDatasourceUID: targetUID,
		},
	}
	h.store.PutRule(context.Background(), rule)
}

func (h *recordingRuleHarness) replay(t *testing.T) {
	t.Helper()
	// Retarget the protected datasource before the scheduler write. A check that
	// passes and then loads the uid again writes to this second server.
	h.ds.swapped = true
	rules, err := h.store.ListAlertRules(context.Background(), &ngmodels.ListAlertRulesQuery{OrgID: h.orgID})
	require.NoError(t, err)
	frame := data.NewFrame("",
		data.NewField("time", nil, []time.Time{time.Unix(0, 0).UTC()}),
		data.NewField("value", data.Labels{"series": "one"}, []float64{1}),
	)
	frame.SetMeta(&data.FrameMeta{Type: data.FrameTypeNumericWide, TypeVersion: data.FrameTypeVersion{0, 1}})
	frames := data.Frames{frame}
	for _, rule := range rules {
		if rule.Record == nil {
			continue
		}
		err := h.remote.WriteDatasource(
			context.Background(),
			rule.Record.TargetDatasourceUID,
			rule.Record.Metric,
			time.Now(),
			frames,
			rule.OrgID,
			ngmodels.WithoutPrivateLabels(rule.Labels),
		)
		require.NoError(t, err)
	}
}

func (h *recordingRuleHarness) replayAuthorized(t *testing.T) {
	t.Helper()
	rules, err := h.store.ListAlertRules(context.Background(), &ngmodels.ListAlertRulesQuery{OrgID: h.orgID})
	require.NoError(t, err)
	frame := data.NewFrame("",
		data.NewField("time", nil, []time.Time{time.Unix(0, 0).UTC()}),
		data.NewField("value", data.Labels{"series": "one"}, []float64{1}),
	)
	frame.SetMeta(&data.FrameMeta{Type: data.FrameTypeNumericWide, TypeVersion: data.FrameTypeVersion{0, 1}})
	frames := data.Frames{frame}
	for _, rule := range rules {
		if rule.Record == nil {
			continue
		}
		err := h.remote.WriteDatasource(
			context.Background(),
			rule.Record.TargetDatasourceUID,
			rule.Record.Metric,
			time.Now(),
			frames,
			rule.OrgID,
			ngmodels.WithoutPrivateLabels(rule.Labels),
		)
		require.NoError(t, err)
	}
}

func (h *recordingRuleHarness) rulesTargeting(t *testing.T, uid string) int {
	t.Helper()
	rules, err := h.store.ListAlertRules(context.Background(), &ngmodels.ListAlertRulesQuery{OrgID: h.orgID})
	require.NoError(t, err)
	count := 0
	for _, rule := range rules {
		if rule.Record != nil && rule.Record.TargetDatasourceUID == uid {
			count++
		}
	}
	return count
}

func assertNoProtectedWrite(t *testing.T, h *recordingRuleHarness) {
	t.Helper()
	require.Zero(t, h.protected.RequestsCount, "remote write reached the protected datasource")
	require.Zero(t, h.swapped.RequestsCount, "remote write reached the protected datasource after it was resolved again")
	for _, body := range []string{h.protected.LastRequestBody, h.swapped.LastRequestBody} {
		if body == "" {
			continue
		}
		decoded, err := snappy.Decode(nil, []byte(body))
		require.NoError(t, err)
		require.NotContains(t, string(decoded), h.metric)
	}
}

func assertWriteUsesProtectedDatasource(t *testing.T, h *recordingRuleHarness) {
	t.Helper()
	require.Equal(t, 1, h.protected.RequestsCount)
	require.Zero(t, h.allowed.RequestsCount)
	require.Zero(t, h.swapped.RequestsCount)
	require.Equal(t, "protected", h.protected.LastHeaders.Get(targetHeaderName))
	decoded, err := snappy.Decode(nil, []byte(h.protected.LastRequestBody))
	require.NoError(t, err)
	require.Contains(t, string(decoded), h.metric)
	require.Contains(t, string(decoded), forgedLabelValue)
	require.NotEmpty(t, h.plugin.users)
	for _, user := range h.plugin.users {
		require.Nil(t, user)
	}
	require.NotEmpty(t, h.ds.lookups)
	for _, lookup := range h.ds.lookups {
		require.Equal(t, h.protectedUID, lookup.UID)
		require.Equal(t, h.orgID, lookup.OrgID)
	}
}

func TestRecordingRuleTargetDatasource_RulerCreateDenied(t *testing.T) {
	h := newRecordingRuleHarness(t, "forged_metric_ruler")
	editor := h.editor(h.allowedUID)
	ctx := createRequestContextWithPerms(h.orgID, editor.Permissions, nil)
	ctx.SignedInUser = editor

	resp := h.ruler().RoutePostNameRulesConfig(ctx, h.rulerGroup(h.allowedUID, h.protectedUID, "ruler-rule"), h.folderUID)
	h.replay(t)

	require.Equalf(t, http.StatusForbidden, resp.Status(), "body: %s", resp.Body())
	require.Zero(t, h.rulesTargeting(t, h.protectedUID))
	assertNoProtectedWrite(t, h)
	require.Zero(t, h.allowed.RequestsCount)
}

func TestRecordingRuleTargetDatasource_RulerExpressionOnlyDenied(t *testing.T) {
	h := newRecordingRuleHarness(t, "forged_metric_expr")
	editor := h.editor()
	ctx := createRequestContextWithPerms(h.orgID, editor.Permissions, nil)
	ctx.SignedInUser = editor

	resp := h.ruler().RoutePostNameRulesConfig(ctx, h.rulerGroup(expr.DatasourceUID, h.protectedUID, "expr-rule"), h.folderUID)
	h.replay(t)

	require.Equalf(t, http.StatusForbidden, resp.Status(), "body: %s", resp.Body())
	require.Zero(t, h.rulesTargeting(t, h.protectedUID))
	assertNoProtectedWrite(t, h)
}

func TestRecordingRuleTargetDatasource_RulerUpdateTargetOnlyDenied(t *testing.T) {
	h := newRecordingRuleHarness(t, "forged_metric_update")
	const ruleUID = "update-rule"
	h.seedRecordingRule(t, h.allowedUID, h.allowedUID, ruleUID, "existing_metric")
	editor := h.editor(h.allowedUID)
	ctx := createRequestContextWithPerms(h.orgID, editor.Permissions, nil)
	ctx.SignedInUser = editor

	resp := h.ruler().RoutePostNameRulesConfig(ctx, h.rulerGroup(h.allowedUID, h.protectedUID, ruleUID), h.folderUID)
	h.replay(t)

	require.Equalf(t, http.StatusForbidden, resp.Status(), "body: %s", resp.Body())
	require.Zero(t, h.rulesTargeting(t, h.protectedUID))
	require.Equal(t, 1, h.rulesTargeting(t, h.allowedUID))
	assertNoProtectedWrite(t, h)
	require.Equal(t, 1, h.allowed.RequestsCount)
	decoded, err := snappy.Decode(nil, []byte(h.allowed.LastRequestBody))
	require.NoError(t, err)
	require.Contains(t, string(decoded), "existing_metric")
	require.NotContains(t, string(decoded), h.metric)
}

func TestRecordingRuleTargetDatasource_ProvisioningCreateAndUpdateDenied(t *testing.T) {
	h := newRecordingRuleHarness(t, "forged_metric_prov")
	editor := h.editor(h.allowedUID)
	srv := &ProvisioningSrv{log: log.New("recording-rule-target-test"), alertRules: h.rules(), folderSvc: h.folders}
	ctx := createRequestContextWithPerms(h.orgID, editor.Permissions, nil)
	ctx.SignedInUser = editor
	ctx.Req.Header.Set(disableProvenanceHeaderName, "true")

	created := srv.RoutePostAlertRule(ctx, h.provisionedRule(h.allowedUID, h.protectedUID, "prov-rule"))
	require.Equalf(t, http.StatusForbidden, created.Status(), "create body: %s", created.Body())

	const ruleUID = "prov-update"
	h.seedRecordingRule(t, h.allowedUID, h.allowedUID, ruleUID, "existing_metric")
	updated := srv.RoutePutAlertRule(ctx, h.provisionedRule(h.allowedUID, h.protectedUID, ruleUID), ruleUID)
	h.replay(t)

	require.Equalf(t, http.StatusForbidden, updated.Status(), "update body: %s", updated.Body())
	require.Zero(t, h.rulesTargeting(t, h.protectedUID))
	assertNoProtectedWrite(t, h)
}

func TestRecordingRuleTargetDatasource_PrometheusConversionHeaderDenied(t *testing.T) {
	h := newRecordingRuleHarness(t, "forged_metric_convert")
	editor := h.editor(h.allowedUID)
	rules := h.rules()
	cfg := &setting.UnifiedAlertingSettings{
		DefaultRuleEvaluationInterval: time.Minute,
		BaseInterval:                  10 * time.Second,
		RecordingRules:                setting.RecordingRuleSettings{Enabled: true},
	}
	srv := NewConvertPrometheusSrv(cfg, log.NewNopLogger(), h.store, h.cache, rules, featuremgmt.WithFeatures(), nil, nil, fakeRulerSyncChecker{})
	ctx := createRequestContextWithPerms(h.orgID, editor.Permissions, nil)
	ctx.SignedInUser = editor
	ctx.Req.Header.Set(datasourceUIDHeader, h.allowedUID)
	ctx.Req.Header.Set(targetDatasourceUIDHeader, h.protectedUID)

	group := apimodels.PrometheusRuleGroup{
		Name:     "rec-group",
		Interval: model.Duration(time.Minute),
		Rules: []apimodels.PrometheusRule{{
			Record: h.metric,
			Expr:   "vector(1)",
			Labels: map[string]string{forgedLabelKey: forgedLabelValue},
		}},
	}
	resp := srv.RouteConvertPrometheusPostRuleGroup(ctx, h.folderTitle, group)
	h.replay(t)

	require.Equalf(t, http.StatusForbidden, resp.Status(), "body: %s", resp.Body())
	require.Zero(t, h.rulesTargeting(t, h.protectedUID))
	assertNoProtectedWrite(t, h)
	require.Zero(t, h.allowed.RequestsCount)
}

func TestRecordingRuleTargetDatasource_KubernetesCreateDenied(t *testing.T) {
	h := newRecordingRuleHarness(t, "forged_metric_k8s")
	editor := h.editor(h.allowedUID)
	storage := recordingrule.NewStorage(*h.rules(), request.GetNamespaceMapper(&setting.Cfg{}))
	ns := request.GetNamespaceMapper(&setting.Cfg{})(h.orgID)
	ctx := identity.WithRequester(k8srequest.WithNamespace(context.Background(), ns), editor)

	source := true
	allowed := alertingv0.RecordingRuleDatasourceUID(h.allowedUID)
	rule := &alertingv0.RecordingRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "k8s-rule",
		},
		Spec: alertingv0.RecordingRuleSpec{
			Title:               "forged recording rule",
			Metric:              alertingv0.RecordingRuleMetricName(h.metric),
			TargetDatasourceUID: alertingv0.RecordingRuleDatasourceUID(h.protectedUID),
			Trigger:             alertingv0.RecordingRuleIntervalTrigger{Interval: "1m"},
			Labels:              map[string]alertingv0.RecordingRuleTemplateString{forgedLabelKey: forgedLabelValue},
			Expressions: alertingv0.RecordingRuleExpressionMap{
				"A": {
					DatasourceUID: &allowed,
					Source:        &source,
					Model:         map[string]any{"refId": "A"},
				},
			},
		},
	}
	meta, err := utils.MetaAccessor(rule)
	require.NoError(t, err)
	meta.SetFolder(h.folderUID)

	_, err = storage.Create(ctx, rule, nil, &metav1.CreateOptions{})
	h.replay(t)

	require.ErrorIs(t, err, accesscontrol.ErrAuthorizationBase)
	require.Zero(t, h.rulesTargeting(t, h.protectedUID))
	assertNoProtectedWrite(t, h)
}

func TestRecordingRuleTargetDatasource_AuthorizedTargetIsWritten(t *testing.T) {
	h := newRecordingRuleHarness(t, "authorized_metric")
	editor := h.editor(h.allowedUID, h.protectedUID)
	ctx := createRequestContextWithPerms(h.orgID, editor.Permissions, nil)
	ctx.SignedInUser = editor

	resp := h.ruler().RoutePostNameRulesConfig(ctx, h.rulerGroup(h.allowedUID, h.protectedUID, "allowed-rule"), h.folderUID)
	require.Equalf(t, http.StatusAccepted, resp.Status(), "body: %s", resp.Body())
	require.Equal(t, 1, h.rulesTargeting(t, h.protectedUID))

	h.replayAuthorized(t)
	assertWriteUsesProtectedDatasource(t, h)
}

func TestRecordingRuleTargetDatasource_AuthorizedExpressionOnlyTargetIsWritten(t *testing.T) {
	h := newRecordingRuleHarness(t, "authorized_expr_metric")
	editor := h.editor(h.protectedUID)
	ctx := createRequestContextWithPerms(h.orgID, editor.Permissions, nil)
	ctx.SignedInUser = editor

	resp := h.ruler().RoutePostNameRulesConfig(ctx, h.rulerGroup(expr.DatasourceUID, h.protectedUID, "allowed-expr"), h.folderUID)
	require.Equalf(t, http.StatusAccepted, resp.Status(), "body: %s", resp.Body())
	h.replayAuthorized(t)
	assertWriteUsesProtectedDatasource(t, h)
}
