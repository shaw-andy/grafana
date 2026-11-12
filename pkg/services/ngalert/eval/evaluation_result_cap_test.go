package eval_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
	datasourcesfakes "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/dsquerierclient"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	ngaccesscontrol "github.com/grafana/grafana/pkg/services/ngalert/accesscontrol"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	testdatasource "github.com/grafana/grafana/pkg/tsdb/grafana-testdata-datasource"
	"github.com/grafana/grafana/pkg/util"
)

// maxShippedEvaluationResultCap is the largest alerting_rule_evaluation_results
// value these tests accept. The cap has to be small enough that one rule cannot
// keep a state per series on every evaluation. 1024 is the spec for the shipped
// value: larger still lets a single rule retain one in-memory state per series.
const maxShippedEvaluationResultCap = 1024

// TestEditorFixedRoleGrantsAlertRuleCreate locks the precondition of the
// unbounded-evaluation path: the built-in Editor role is granted creation of
// alert rules in every folder.
func TestEditorFixedRoleGrantsAlertRuleCreate(t *testing.T) {
	t.Parallel()

	var writer *accesscontrol.RoleRegistration
	for _, registration := range ngaccesscontrol.FixedRoleRegistrations() {
		if registration.Role.Name == accesscontrol.FixedRolePrefix+"alerting.rules:writer" {
			registration := registration
			writer = &registration
			break
		}
	}
	require.NotNil(t, writer)
	require.Contains(t, writer.Grants, string(org.RoleEditor))

	var granted bool
	for _, permission := range writer.Role.Permissions {
		if permission.Action == accesscontrol.ActionAlertingRuleCreate && permission.Scope == folder.ScopeFoldersAll {
			granted = true
			break
		}
	}
	require.True(t, granted, "Editor rules writer role must grant alert.rules:create on all folders")
}

// TestEvaluationResultCap_ShippedDefaults exercises the scheduler path with the
// configuration shipped in conf/defaults.ini. Unified alerting is enabled when
// its setting is empty. The evaluator is built from that configuration, runs
// the real expression pipeline, and the state manager retains whatever Evaluate
// returns — the same two calls alertRule.evaluate makes. Recording rules and
// the query test API call EvaluateRaw on the same evaluator; backtesting calls
// Evaluate.
func TestEvaluationResultCap_ShippedDefaults(t *testing.T) {
	cfg := loadUnifiedAlertingSettings(t, nil)
	requireShippedAlertingEnabled(t, cfg)

	t.Run("testdata random walk reduced to one state per series", func(t *testing.T) {
		assertResultCap(t, cfg, testdataRandomWalkSource{})
	})
	t.Run("one numeric table expands to one state per row", func(t *testing.T) {
		assertResultCap(t, cfg, numericTableSource{})
	})
	t.Run("one wide frame expands to one state per series", func(t *testing.T) {
		assertResultCap(t, cfg, wideFrameSource{})
	})
}

// TestEvaluationResultCap_NonPositiveConfiguredValueIsStillCapped covers the
// same evaluation path when the quota is the shipped unlimited sentinel, zero,
// or absent. A missing or non-positive value has to behave as the shipped cap.
func TestEvaluationResultCap_NonPositiveConfiguredValueIsStillCapped(t *testing.T) {
	shipped := loadUnifiedAlertingSettings(t, nil)

	cases := []struct {
		name   string
		mutate func(*setting.Cfg)
	}{
		{
			name: "explicit -1",
			mutate: func(cfg *setting.Cfg) {
				cfg.Raw.Section("quota").Key("alerting_rule_evaluation_results").SetValue("-1")
			},
		},
		{
			name: "explicit 0",
			mutate: func(cfg *setting.Cfg) {
				cfg.Raw.Section("quota").Key("alerting_rule_evaluation_results").SetValue("0")
			},
		},
		{
			name: "key removed",
			mutate: func(cfg *setting.Cfg) {
				cfg.Raw.Section("quota").DeleteKey("alerting_rule_evaluation_results")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadUnifiedAlertingSettings(t, tc.mutate)
			assertResultCap(t, cfg, testdataRandomWalkSource{})
			require.Equal(t, shipped.UnifiedAlerting.EvaluationResultLimit, cfg.UnifiedAlerting.EvaluationResultLimit,
				"a missing or non-positive alerting_rule_evaluation_results must use the shipped cap")
		})
	}
}

type resultSource interface {
	// queries builds a rule whose condition yields one alert instance per series.
	queries(series int) (models.Condition, string)
	// handler is the datasource the expression pipeline queries.
	handler() backend.QueryDataHandler
	datasource() *datasources.DataSource
}

type testdataRandomWalkSource struct{}

func (testdataRandomWalkSource) handler() backend.QueryDataHandler {
	return testdatasource.ProvideService()
}

func (testdataRandomWalkSource) datasource() *datasources.DataSource {
	return &datasources.DataSource{UID: "testdata", Type: datasources.DS_TESTDATA, OrgID: 1}
}

func (testdataRandomWalkSource) queries(series int) (models.Condition, string) {
	// A one-hour interval across a one-hour range makes RandomWalk emit a
	// single point per series. The labels keep each reduced value distinct so
	// the state cache cannot collapse them.
	query := models.AlertQuery{
		RefID:         "A",
		DatasourceUID: "testdata",
		RelativeTimeRange: models.RelativeTimeRange{
			From: models.Duration(time.Hour),
			To:   0,
		},
		Model: json.RawMessage(fmt.Sprintf(`{
			"refId": "A",
			"scenarioId": "random_walk",
			"seriesCount": %d,
			"labels": "{series=\"$seriesIndex\"}",
			"intervalMs": 3600000,
			"maxDataPoints": 10
		}`, series)),
	}
	condition := models.Condition{
		Condition: "B",
		Data: []models.AlertQuery{
			query,
			models.CreateReduceExpression("B", "A", "last"),
		},
	}
	return condition, "B"
}

type numericTableSource struct{}

func (numericTableSource) handler() backend.QueryDataHandler {
	return backend.QueryDataHandlerFunc(func(_ context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
		resp := backend.NewQueryDataResponse()
		for _, q := range req.Queries {
			var model struct {
				SeriesCount int `json:"seriesCount"`
			}
			if err := json.Unmarshal(q.JSON, &model); err != nil {
				return nil, err
			}
			labels := make([]string, model.SeriesCount)
			values := make([]float64, model.SeriesCount)
			for i := 0; i < model.SeriesCount; i++ {
				labels[i] = fmt.Sprintf("series-%d", i)
				values[i] = 1
			}
			resp.Responses[q.RefID] = backend.DataResponse{
				Frames: data.Frames{data.NewFrame("",
					data.NewField("series", nil, labels),
					data.NewField("Value", nil, values),
				)},
			}
		}
		return resp, nil
	})
}

func (numericTableSource) datasource() *datasources.DataSource {
	return &datasources.DataSource{UID: "numeric-table", Type: "numeric-table", OrgID: 1}
}

func (numericTableSource) queries(series int) (models.Condition, string) {
	condition := models.Condition{
		Condition: "A",
		Data: []models.AlertQuery{{
			RefID:         "A",
			DatasourceUID: "numeric-table",
			RelativeTimeRange: models.RelativeTimeRange{
				From: models.Duration(time.Hour),
				To:   0,
			},
			Model: json.RawMessage(fmt.Sprintf(`{
				"refId": "A",
				"seriesCount": %d,
				"intervalMs": 3600000,
				"maxDataPoints": 10
			}`, series)),
		}},
	}
	return condition, "A"
}

type wideFrameSource struct{}

func (wideFrameSource) handler() backend.QueryDataHandler {
	return backend.QueryDataHandlerFunc(func(_ context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
		resp := backend.NewQueryDataResponse()
		for _, q := range req.Queries {
			var model struct {
				SeriesCount int `json:"seriesCount"`
			}
			if err := json.Unmarshal(q.JSON, &model); err != nil {
				return nil, err
			}
			fields := make([]*data.Field, 0, model.SeriesCount+1)
			fields = append(fields, data.NewField("time", nil, []time.Time{q.TimeRange.From}))
			for i := 0; i < model.SeriesCount; i++ {
				value := new(float64)
				*value = 1
				fields = append(fields, data.NewField(
					fmt.Sprintf("value-%d", i),
					data.Labels{"series": fmt.Sprintf("%d", i)},
					[]*float64{value},
				))
			}
			resp.Responses[q.RefID] = backend.DataResponse{
				Frames: data.Frames{data.NewFrame("wide", fields...)},
			}
		}
		return resp, nil
	})
}

func (wideFrameSource) datasource() *datasources.DataSource {
	return &datasources.DataSource{UID: "wide-frame", Type: "wide-frame", OrgID: 1}
}

func (wideFrameSource) queries(series int) (models.Condition, string) {
	query := models.AlertQuery{
		RefID:         "A",
		DatasourceUID: "wide-frame",
		RelativeTimeRange: models.RelativeTimeRange{
			From: models.Duration(time.Hour),
			To:   0,
		},
		Model: json.RawMessage(fmt.Sprintf(`{
			"refId": "A",
			"seriesCount": %d,
			"intervalMs": 3600000,
			"maxDataPoints": 10
		}`, series)),
	}
	condition := models.Condition{
		Condition: "B",
		Data: []models.AlertQuery{
			query,
			models.CreateReduceExpression("B", "A", "last"),
		},
	}
	return condition, "B"
}

// assertResultCap fails while evaluation of an oversized condition is accepted
// and each series is retained as alert state. A series count equal to the
// shipped cap must still be retained, so a fix that rejects every result does
// not pass.
func assertResultCap(t *testing.T, cfg *setting.Cfg, source resultSource) {
	t.Helper()

	limit := cfg.UnifiedAlerting.EvaluationResultLimit

	// A handful of series is enough to show that the real pipeline turns each
	// series into a cached alert state when nothing caps it.
	probe := 8
	if limit > 0 && limit < probe {
		probe = limit
	}
	probeStates, probeRaw, err := evaluateAndRetain(t, cfg, source, probe)
	require.NoError(t, err)
	require.NotNil(t, probeRaw)
	require.Len(t, probeStates, probe, "each series within the cap must be retained as alert state")

	require.Positive(t, limit, "alerting_rule_evaluation_results must ship as a positive cap, not unlimited")
	require.LessOrEqual(t, limit, maxShippedEvaluationResultCap,
		"the shipped cap must bound how many alert states one evaluation can retain")

	if probe != limit {
		atCapStates, atCapRaw, err := evaluateAndRetain(t, cfg, source, limit)
		require.NoError(t, err)
		require.NotNil(t, atCapRaw)
		require.Len(t, atCapStates, limit)
	}

	overStates, overRaw, err := evaluateAndRetain(t, cfg, source, limit+1)
	require.ErrorContains(t, err, "too many results")
	require.Nil(t, overRaw, "the oversized pipeline result must not be returned to the scheduler, recording rule, or test API")
	require.LessOrEqual(t, len(overStates), 1, "an oversized evaluation must not retain one alert state per series, got %d", len(overStates))
}

// evaluateAndRetain runs the evaluator the scheduler uses and then applies the
// result with the state manager, matching alertRule.evaluate: a pipeline error
// with no results becomes a single error state, and any results that were
// returned are cached.
func evaluateAndRetain(t *testing.T, cfg *setting.Cfg, source resultSource, series int) ([]*state.State, *backend.QueryDataResponse, error) {
	t.Helper()

	ds := source.datasource()
	cache := &datasourcesfakes.FakeCacheService{DataSources: []*datasources.DataSource{ds}}
	expressions := expr.ProvideService(
		cfg,
		queryDataPluginClient{handler: source.handler()},
		plugincontext.ProvideService(
			cfg,
			nil,
			&pluginstore.FakePluginStore{PluginList: []pluginstore.Plugin{{
				JSONData: plugins.JSONData{ID: ds.Type, Backend: true},
			}}},
			cache,
			&datasourcesfakes.FakeDataSourceService{},
			nil,
			pluginconfig.NewFakePluginRequestConfigProvider(),
		),
		featuremgmt.WithFeatures(),
		nil,
		tracing.InitializeTracerForTest(),
		dsquerierclient.NewNullQSDatasourceClientBuilder(),
	)

	factory := eval.NewEvaluatorFactory(cfg.UnifiedAlerting, cache, expressions)
	condition, conditionRef := source.queries(series)
	evaluator, err := factory.Create(eval.NewContext(context.Background(), &user.SignedInUser{OrgID: 1}), condition)
	require.NoError(t, err)

	now := time.Now()
	raw, rawErr := evaluator.EvaluateRaw(context.Background(), now)
	if rawErr == nil && raw != nil {
		frames := raw.Responses[conditionRef].Frames
		require.Lenf(t, frames, series, "condition %s returned %d frames for %d series", conditionRef, len(frames), series)
	}

	results, evalErr := evaluator.Evaluate(context.Background(), now)
	if evalErr != nil && results == nil {
		results = eval.Results{eval.NewResultFromError(evalErr, now, 0)}
	}

	mgr := state.NewManager(state.ManagerCfg{
		ExternalURL: nil,
		Images:      &state.NoopImageService{},
		Clock:       clock.New(),
		Tracer:      tracing.InitializeTracerForTest(),
		Log:         log.New("ngalert.state.manager"),
	}, state.NewNoopPersister())
	rule := &models.AlertRule{
		OrgID:           1,
		UID:             util.GenerateShortUID(),
		Title:           "oversized",
		Condition:       condition.Condition,
		Data:            condition.Data,
		NoDataState:     models.NoData,
		ExecErrState:    models.ErrorErrState,
		IntervalSeconds: 60,
	}
	_, err = mgr.ProcessEvalResults(context.Background(), now, rule, results, nil, nil)
	require.NoError(t, err)

	// EvaluateRaw and Evaluate share one cap. Prefer the raw error when the
	// response was refused, and surface the evaluation error otherwise.
	if rawErr != nil {
		return mgr.GetStatesForRuleUID(context.Background(), rule.OrgID, rule.UID), raw, rawErr
	}
	return mgr.GetStatesForRuleUID(context.Background(), rule.OrgID, rule.UID), raw, evalErr
}

// queryDataPluginClient forwards datasource queries to an in-process handler.
// The expression service only calls QueryData on this path.
type queryDataPluginClient struct {
	plugins.Client
	handler backend.QueryDataHandler
}

func (c queryDataPluginClient) QueryData(ctx context.Context, req *backend.QueryDataRequest) (*backend.QueryDataResponse, error) {
	return c.handler.QueryData(ctx, req)
}

func requireShippedAlertingEnabled(t *testing.T, cfg *setting.Cfg) {
	t.Helper()
	require.NotNil(t, cfg.UnifiedAlerting.Enabled, "an empty unified_alerting.enabled must enable alerting")
	require.True(t, *cfg.UnifiedAlerting.Enabled)
	require.Equal(t, 30*time.Second, cfg.UnifiedAlerting.EvaluationTimeout)
	require.True(t, cfg.ExpressionsEnabled)
}

func loadUnifiedAlertingSettings(t *testing.T, mutate func(*setting.Cfg)) *setting.Cfg {
	t.Helper()
	cfg := setting.NewCfg()
	err := cfg.Load(setting.CommandLineArgs{
		HomePath: "../../../../",
		Config:   "../../../../conf/defaults.ini",
		// Skip the args path so the test reads the shipped file rather than a
		// developer override.
		Args: nil,
	})
	require.NoError(t, err)
	if mutate != nil {
		mutate(cfg)
		require.NoError(t, cfg.ReadUnifiedAlertingSettings(cfg.Raw))
	}
	return cfg
}
