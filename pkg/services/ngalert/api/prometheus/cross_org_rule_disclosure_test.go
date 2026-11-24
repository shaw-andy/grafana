package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	ngaccesscontrol "github.com/grafana/grafana/pkg/services/ngalert/accesscontrol"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	tutil "github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

func promQuery(ref, expr, datasourceUID string) ngmodels.AlertQuery {
	query := ngmodels.CreatePrometheusQuery(ref, expr, 1000, 100, true, datasourceUID)
	query.RelativeTimeRange = ngmodels.RelativeTimeRange{
		From: ngmodels.Duration(10 * time.Minute),
	}
	return query
}

// Editor in org A, with a folder whose UID matches a folder in org B, must not
// receive org B's rule definition or live instances from
// GET /api/prometheus/grafana/api/v1/rules when rule_group mixes the victim
// group name with a no_group_for_rule_<uid> token.
func TestIntegrationRouteGetRuleStatuses_CrossOrgRuleGroup(t *testing.T) {
	tutil.SkipIntegrationTestInShortMode(t)

	const (
		attackerOrg        int64 = 1
		victimOrg          int64 = 2
		sharedFolder             = "sharedfolder01"
		victimUID                = "victimruleuid1"
		attackerUID              = "attackerrule01"
		victimGroup              = "victim-group"
		attackerGroup            = "attacker-group"
		victimQuery              = `count(victim_only_metric)`
		attackerQuery            = `count(attacker_metric)`
		victimReceiver           = "victim-pager"
		attackerReceiver         = "attacker-pager"
		victimLabel              = "victim-team"
		victimAnnotation         = "victim-secret-annotation"
		victimDatasource         = "victimdsuid"
		victimInstanceHost       = "victim-host"
		victimInstanceNote       = "victim-runbook"
	)

	cfg := setting.NewCfg()
	cfg.UnifiedAlerting.BaseInterval = 10 * time.Second
	sqlStore := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore

	folders := foldertest.NewFakeService()
	// Folder UIDs are unique per organization. The same UID in two orgs is how
	// the caller's allowed-folder map and the victim rule's namespace collide.
	folders.AddFolder(&folder.Folder{
		UID:          sharedFolder,
		Title:        "attacker folder",
		OrgID:        attackerOrg,
		Fullpath:     "attacker folder",
		FullpathUIDs: sharedFolder,
	})
	folders.AddFolder(&folder.Folder{
		UID:          sharedFolder,
		Title:        "victim folder",
		OrgID:        victimOrg,
		Fullpath:     "victim folder",
		FullpathUIDs: sharedFolder,
	})

	ruleStore := &store.DBstore{
		SQLStore:       sqlStore,
		FolderService:  folders,
		Logger:         log.New("ngalert.dbstore.test"),
		Cfg:            cfg.UnifiedAlerting,
		Bus:            bus.ProvideBus(tracing.InitializeTracerForTest()),
		FeatureToggles: featuremgmt.WithFeatures(),
	}

	gen := ngmodels.RuleGen.With(ngmodels.RuleMuts.WithIntervalMatching(cfg.UnifiedAlerting.BaseInterval))
	victim := gen.With(
		ngmodels.RuleMuts.WithOrgID(victimOrg),
		ngmodels.RuleMuts.WithNamespaceUID(sharedFolder),
		ngmodels.RuleMuts.WithUID(victimUID),
		ngmodels.RuleMuts.WithGroupName(victimGroup),
		ngmodels.RuleMuts.WithTitle("victim-rule"),
		ngmodels.RuleMuts.WithLabels(data.Labels{"team": victimLabel}),
		ngmodels.RuleMuts.WithAnnotations(data.Labels{"summary": victimAnnotation}),
		ngmodels.RuleMuts.WithNotificationSettings(ngmodels.NotificationSettings{
			ContactPointRouting: &ngmodels.ContactPointRouting{Receiver: victimReceiver},
		}),
		ngmodels.RuleMuts.WithQuery(promQuery("A", victimQuery, victimDatasource)),
	).Generate()
	attacker := gen.With(
		ngmodels.RuleMuts.WithOrgID(attackerOrg),
		ngmodels.RuleMuts.WithNamespaceUID(sharedFolder),
		ngmodels.RuleMuts.WithUID(attackerUID),
		ngmodels.RuleMuts.WithGroupName(attackerGroup),
		ngmodels.RuleMuts.WithTitle("attacker-rule"),
		ngmodels.RuleMuts.WithLabels(data.Labels{"team": "attacker-team"}),
		ngmodels.RuleMuts.WithAnnotations(data.Labels{"summary": "attacker-annotation"}),
		ngmodels.RuleMuts.WithNotificationSettings(ngmodels.NotificationSettings{
			ContactPointRouting: &ngmodels.ContactPointRouting{Receiver: attackerReceiver},
		}),
		ngmodels.RuleMuts.WithQuery(promQuery("A", attackerQuery, "attackerds")),
	).Generate()

	userUID := ngmodels.UserUID("user")
	_, err := ruleStore.InsertAlertRules(context.Background(), &userUID, []ngmodels.InsertRule{
		{AlertRule: victim},
		{AlertRule: attacker},
	})
	require.NoError(t, err)

	labels := ngmodels.InstanceLabels{"host": victimInstanceHost}
	_, labelsHash, err := labels.StringAndHash()
	require.NoError(t, err)
	now := time.Now().UTC()
	instance := ngmodels.AlertInstance{
		AlertInstanceKey: ngmodels.AlertInstanceKey{
			RuleOrgID:  victimOrg,
			RuleUID:    victim.UID,
			LabelsHash: labelsHash,
		},
		Labels:            labels,
		Annotations:       ngmodels.InstanceAnnotations{"runbook": victimInstanceNote},
		CurrentState:      ngmodels.InstanceStateFiring,
		CurrentStateSince: now,
		CurrentStateEnd:   now.Add(time.Hour),
		LastEvalTime:      now,
		LastResult:        ngmodels.LastResult{Values: map[string]float64{"A": 42}, Condition: "A"},
	}
	instances := store.ProtoInstanceDBStore{SQLStore: sqlStore, Logger: log.New("ngalert.instances.test"), FeatureToggles: featuremgmt.WithFeatures()}
	require.NoError(t, instances.SaveAlertInstancesForRule(context.Background(), ngmodels.AlertRuleKeyWithGroup{
		AlertRuleKey: ngmodels.AlertRuleKey{OrgID: victimOrg, UID: victim.UID},
		RuleGroup:    victim.RuleGroup,
	}, []ngmodels.AlertInstance{instance}))

	visible, err := ruleStore.GetUserVisibleNamespaces(context.Background(), attackerOrg, &user.SignedInUser{OrgID: attackerOrg})
	require.NoError(t, err)
	require.Contains(t, visible, sharedFolder)
	require.Equal(t, attackerOrg, visible[sharedFolder].OrgID)

	scope := folder.ScopeFoldersProvider.GetResourceScopeUID(sharedFolder)
	caller := &user.SignedInUser{
		OrgID: attackerOrg,
		Permissions: map[int64]map[string][]string{
			attackerOrg: {
				accesscontrol.ActionAlertingRuleRead: {scope},
				folder.ActionFoldersRead:             {scope},
			},
		},
	}
	// Fallback access-control evaluation denies. Folder access has to come from
	// the caller's permission on their own folder.
	authz := ngaccesscontrol.NewRuleService(&actest.FakeAccessControl{ExpectedEvaluate: false})

	noGroup, err := ngmodels.NewNoGroupRuleGroup(victim.UID)
	require.NoError(t, err)

	memory := state.NewManager(state.ManagerCfg{Log: log.New("ngalert.state.test"), Clock: clock.New()}, nil)
	memory.Put([]*state.State{{
		OrgID:        victimOrg,
		AlertRuleUID: victim.UID,
		CacheID:      data.Labels{"host": victimInstanceHost}.Fingerprint(),
		State:        eval.Alerting,
		Labels:       data.Labels{"host": victimInstanceHost},
		Annotations:  data.Labels{"runbook": victimInstanceNote},
		StartsAt:     now,
		EndsAt:       now.Add(time.Hour),
		LatestResult: &state.Evaluation{Condition: "A", Values: map[string]float64{"A": 42}},
	}})
	dbReader := state.NewStoreStateReader(instances, log.New("ngalert.state.reader.test"))

	newRequest := func(groups ...string) *contextmodel.ReqContext {
		t.Helper()
		values := url.Values{}
		for _, group := range groups {
			values.Add("rule_group", group)
		}
		req, err := http.NewRequest(http.MethodGet, "/api/prometheus/grafana/api/v1/rules?"+values.Encode(), nil)
		require.NoError(t, err)
		require.NoError(t, req.ParseForm())
		return &contextmodel.ReqContext{Context: &web.Context{Req: req}, SignedInUser: caller}
	}

	assertNoVictim := func(t *testing.T, body []byte) {
		t.Helper()
		var res apimodels.RuleResponse
		require.NoError(t, json.Unmarshal(body, &res))
		require.Equal(t, "success", res.Status)
		require.NotContains(t, string(body), victimQuery)
		require.NotContains(t, string(body), victimReceiver)
		require.NotContains(t, string(body), victimLabel)
		require.NotContains(t, string(body), victimAnnotation)
		require.NotContains(t, string(body), victimDatasource)
		require.NotContains(t, string(body), victim.UID)
		require.NotContains(t, string(body), victimInstanceHost)
		require.NotContains(t, string(body), victimInstanceNote)
		require.Contains(t, string(body), attacker.UID)
		require.Contains(t, string(body), attackerQuery)
		require.Contains(t, string(body), attackerReceiver)
	}

	t.Run("in-memory instances", func(t *testing.T) {
		api := NewPrometheusSrv(log.NewNopLogger(), memory, NewInMemoryRuleMutator(dbReader, memory), ruleStore, authz, nil)
		resp := api.RouteGetRuleStatuses(newRequest(victim.RuleGroup, attacker.RuleGroup, noGroup.String()))
		require.Equal(t, http.StatusOK, resp.Status())
		assertNoVictim(t, resp.Body())
	})

	t.Run("database instances", func(t *testing.T) {
		api := NewPrometheusSrv(log.NewNopLogger(), dbReader, NewDBRuleMutator(dbReader), ruleStore, authz, nil)
		resp := api.RouteGetRuleStatuses(newRequest(victim.RuleGroup, attacker.RuleGroup, noGroup.String()))
		require.Equal(t, http.StatusOK, resp.Status())
		assertNoVictim(t, resp.Body())
	})

	t.Run("legacy group statuses", func(t *testing.T) {
		req := newRequest(victim.RuleGroup, attacker.RuleGroup, noGroup.String())
		allowed := map[string]string{}
		for uid, f := range visible {
			allowed[uid] = f.Fullpath
		}
		res := PrepareRuleGroupStatuses(log.NewNopLogger(), ruleStore, RuleGroupStatusesOptions{
			Ctx:               context.Background(),
			OrgID:             attackerOrg,
			Query:             req.Req.Form,
			AllowedNamespaces: allowed,
		}, NewDBRuleMutator(dbReader), nil)
		require.Equal(t, "success", res.Status)
		raw, err := json.Marshal(res)
		require.NoError(t, err)
		assertNoVictim(t, raw)
	})

	t.Run("without the no-group token the other org stays hidden", func(t *testing.T) {
		api := NewPrometheusSrv(log.NewNopLogger(), dbReader, NewDBRuleMutator(dbReader), ruleStore, authz, nil)
		resp := api.RouteGetRuleStatuses(newRequest(victim.RuleGroup, attacker.RuleGroup))
		require.Equal(t, http.StatusOK, resp.Status())
		assertNoVictim(t, resp.Body())
	})
}
