package search

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	k8srest "k8s.io/apiserver/pkg/registry/rest"

	"github.com/grafana/grafana-app-sdk/app"
	"github.com/grafana/grafana-app-sdk/resource"
	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	searchv0 "github.com/grafana/grafana/pkg/apis/search/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/registry/apps/alerting/rules/alertrule"
	"github.com/grafana/grafana/pkg/registry/apps/alerting/rules/recordingrule"
	grafanac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/apiserver/endpoints/request"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	ngac "github.com/grafana/grafana/pkg/services/ngalert/accesscontrol"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/provisioning"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tests/testsuite"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

const (
	visibleFolderUID = "fldvisible"
	secretFolderUID  = "fldsecret"
	missingFolderUID = "does-not-exist"

	visibleAlertTitle = "visible-alert-title"
	secretAlertTitle  = "secret-alert-title"
	visibleRecTitle   = "visible-recording-title"
	secretRecTitle    = "secret-recording-title"

	visibleAlertQuery = "VISIBLE_PROMQL"
	secretAlertQuery  = "SECRET_PROMQL_DO_NOT_LEAK"
	visibleRecQuery   = "VISIBLE_RECORD_PROMQL"
	secretRecQuery    = "SECRET_RECORD_PROMQL_DO_NOT_LEAK"
)

// TestRestrictedFolderFilterDoesNotReturnUnreadableRules is the spec for the
// folder-filter bypass in AlertRuleService.ListAlertRules. A caller who holds
// alert.rules:read but cannot read a folder must not receive that folder's
// alert or recording rules from list or search, including when the requested
// folder matches nothing they can read and when they can read no folder at all.
func TestRestrictedFolderFilterDoesNotReturnUnreadableRules(t *testing.T) {
	svc, ruleStore := newRuleService(t)
	insertFixtureRules(t, ruleStore)

	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	viewer := folderReader(1, visibleFolderUID)
	lockedOut := folderReader(1)
	ctx := requestContext(viewer)

	t.Run("coarse authorizer allows a viewer who can read rules in one folder", func(t *testing.T) {
		decision, _, err := alertrule.Authorize(ctx, ac, authorizer.AttributesRecord{
			Verb: "list", Resource: alertrule.ResourceInfo.GroupResource().Resource, ResourceRequest: true,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		decision, _, err = recordingrule.Authorize(ctx, ac, authorizer.AttributesRecord{
			Verb: "list", Resource: recordingrule.ResourceInfo.GroupResource().Resource, ResourceRequest: true,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		decision, _, err = Authorize(ctx, ac, authorizer.AttributesRecord{
			Verb: "create", Resource: RouteResource, ResourceRequest: true,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision)

		lockedCtx := requestContext(lockedOut)
		decision, _, err = alertrule.Authorize(lockedCtx, ac, authorizer.AttributesRecord{
			Verb: "list", Resource: alertrule.ResourceInfo.GroupResource().Resource, ResourceRequest: true,
		})
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision, "alert.rules:read on any scope is enough for the route authorizer")
	})

	namespacer := request.GetNamespaceMapper(&setting.Cfg{})
	alertStorage := alertrule.NewStorage(*svc, namespacer)
	recordingStorage := recordingrule.NewStorage(*svc, namespacer)
	handler := NewHandler(NewLegacyClient(*svc), NewLegacyClient(*svc))

	t.Run("list and search of a readable folder stay inside that folder", func(t *testing.T) {
		body := listBody(t, alertStorage, ctx, labelSelector(t, visibleFolderUID))
		require.Contains(t, body, visibleAlertTitle)
		require.Contains(t, body, visibleAlertQuery)
		require.NotContains(t, body, secretAlertTitle)
		require.NotContains(t, body, secretAlertQuery)
		require.NotContains(t, body, secretRecTitle)

		body = listBody(t, recordingStorage, ctx, labelSelector(t, visibleFolderUID))
		require.Contains(t, body, visibleRecTitle)
		require.Contains(t, body, visibleRecQuery)
		require.NotContains(t, body, secretRecTitle)
		require.NotContains(t, body, secretRecQuery)
		require.NotContains(t, body, secretAlertTitle)

		assertSearchHidesSecrets(t, handler, ctx, visibleFolderUID, visibleAlertTitle, visibleRecTitle)
	})

	t.Run("folder filter that names an unreadable folder returns no rules", func(t *testing.T) {
		for _, folderUID := range []string{secretFolderUID, missingFolderUID} {
			t.Run(folderUID, func(t *testing.T) {
				t.Run("alert list", func(t *testing.T) {
					requireNoFixtureRules(t, listBody(t, alertStorage, ctx, labelSelector(t, folderUID)))
				})
				t.Run("recording list", func(t *testing.T) {
					requireNoFixtureRules(t, listBody(t, recordingStorage, ctx, labelSelector(t, folderUID)))
				})
				t.Run("search", func(t *testing.T) {
					assertSearchHidesSecrets(t, handler, ctx, folderUID, "", "")
				})
			})
		}
	})

	t.Run("caller who can read no folder gets an empty list and an empty search", func(t *testing.T) {
		lockedCtx := requestContext(lockedOut)
		t.Run("alert list", func(t *testing.T) {
			requireNoFixtureRules(t, listBody(t, alertStorage, lockedCtx, &internalversion.ListOptions{}))
		})
		t.Run("recording list", func(t *testing.T) {
			requireNoFixtureRules(t, listBody(t, recordingStorage, lockedCtx, &internalversion.ListOptions{}))
		})
		t.Run("cross-kind search", func(t *testing.T) {
			rec := httptest.NewRecorder()
			require.NoError(t, handler.SearchRules(lockedCtx, rec, &app.CustomRouteRequest{
				ResourceIdentifier: resource.FullIdentifier{Namespace: "default"},
			}))
			requireNoFixtureRules(t, rec.Body.String())
		})
		t.Run("alert search", func(t *testing.T) {
			requireNoFixtureRules(t, perKindSearch(t, handler.SearchAlertRules, lockedCtx, nil))
		})
		t.Run("recording search", func(t *testing.T) {
			requireNoFixtureRules(t, perKindSearch(t, handler.SearchRecordingRules, lockedCtx, nil))
		})
	})
}

func newRuleService(t *testing.T) (*provisioning.AlertRuleService, store.DBstore) {
	t.Helper()
	sqlStore := db.InitTestDB(t)
	cfg := setting.UnifiedAlertingSettings{BaseInterval: 10 * time.Second}
	folders := foldertest.NewFakeService()
	folders.AddFolder(&folder.Folder{OrgID: 1, UID: visibleFolderUID, Title: "Visible"})
	folders.AddFolder(&folder.Folder{OrgID: 1, UID: secretFolderUID, Title: "Secret"})
	ruleStore := store.DBstore{
		SQLStore:       sqlStore,
		Cfg:            cfg,
		Logger:         log.NewNopLogger(),
		FolderService:  folders,
		FeatureToggles: featuremgmt.WithFeatures(),
	}
	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())
	svc := provisioning.NewAlertRuleService(
		ruleStore,
		ruleStore,
		folders,
		nil,
		sqlStore,
		60,
		10,
		100,
		log.NewNopLogger(),
		nil,
		ngac.NewRuleService(ac),
		nil,
	)
	return svc, ruleStore
}

func insertFixtureRules(t *testing.T, ruleStore store.DBstore) {
	t.Helper()
	rules := []ngmodels.AlertRule{
		alertRule("visalert1", visibleAlertTitle, visibleFolderUID, "visible-alerts", visibleAlertQuery),
		alertRule("secretalrt", secretAlertTitle, secretFolderUID, "secret-alerts", secretAlertQuery),
		recordingRule("visrecord", visibleRecTitle, visibleFolderUID, "visible-records", visibleRecQuery),
		recordingRule("secretrecd", secretRecTitle, secretFolderUID, "secret-records", secretRecQuery),
	}
	inserts := make([]ngmodels.InsertRule, len(rules))
	for i := range rules {
		inserts[i] = ngmodels.InsertRule{AlertRule: rules[i]}
	}
	_, err := ruleStore.InsertAlertRules(context.Background(), &ngmodels.AlertingUserUID, inserts)
	require.NoError(t, err)
}

func alertRule(uid, title, folderUID, group, query string) ngmodels.AlertRule {
	return ngmodels.AlertRule{
		UID:             uid,
		OrgID:           1,
		Title:           title,
		Condition:       "A",
		IntervalSeconds: 60,
		NamespaceUID:    folderUID,
		RuleGroup:       group,
		For:             time.Minute,
		NoDataState:     ngmodels.OK,
		ExecErrState:    ngmodels.OkErrState,
		Labels:          map[string]string{"marker": title},
		Annotations:     map[string]string{"summary": title},
		Data: []ngmodels.AlertQuery{{
			RefID:             "A",
			DatasourceUID:     "promds",
			Model:             json.RawMessage(fmt.Sprintf(`{"expr":%q,"refId":"A"}`, query)),
			RelativeTimeRange: ngmodels.RelativeTimeRange{From: ngmodels.Duration(time.Minute)},
		}},
	}
}

func recordingRule(uid, title, folderUID, group, query string) ngmodels.AlertRule {
	rule := alertRule(uid, title, folderUID, group, query)
	rule.Record = &ngmodels.Record{Metric: "metric_" + uid, From: "A", TargetDatasourceUID: "promds"}
	ngmodels.ClearRecordingRuleIgnoredFields(&rule)
	return rule
}

func folderReader(orgID int64, folderUIDs ...string) *user.SignedInUser {
	perms := map[string][]string{
		// Default Viewer fixed role fixed:alerting.rules:reader.
		grafanac.ActionAlertingRuleRead: {folder.ScopeFoldersAll},
	}
	if len(folderUIDs) > 0 {
		scopes := make([]string, 0, len(folderUIDs))
		for _, uid := range folderUIDs {
			scopes = append(scopes, folder.ScopeFoldersProvider.GetResourceScopeUID(uid))
		}
		perms[folder.ActionFoldersRead] = scopes
	}
	return &user.SignedInUser{
		UserID:      7,
		UserUID:     "viewer",
		OrgID:       orgID,
		OrgRole:     identity.RoleViewer,
		Permissions: map[int64]map[string][]string{orgID: perms},
	}
}

func requestContext(user identity.Requester) context.Context {
	ctx := identity.WithRequester(context.Background(), user)
	return genericapirequest.WithNamespace(ctx, "default")
}

func labelSelector(t *testing.T, folderUID string) *internalversion.ListOptions {
	t.Helper()
	selector, err := labels.Parse(model.FolderLabelKey + "=" + folderUID)
	require.NoError(t, err)
	return &internalversion.ListOptions{LabelSelector: selector}
}

func listBody(t *testing.T, storage k8srest.Lister, ctx context.Context, opts *internalversion.ListOptions) string {
	t.Helper()
	obj, err := storage.List(ctx, opts)
	require.NoError(t, err)
	raw, marshalErr := json.Marshal(obj)
	require.NoError(t, marshalErr)
	return string(raw)
}

func requireNoFixtureRules(t *testing.T, body string) {
	t.Helper()
	for _, marker := range []string{
		visibleAlertTitle, secretAlertTitle, visibleRecTitle, secretRecTitle,
		visibleAlertQuery, secretAlertQuery, visibleRecQuery, secretRecQuery,
	} {
		require.NotContains(t, body, marker)
	}
}

func assertSearchHidesSecrets(t *testing.T, handler *Handler, ctx context.Context, folderUID, wantAlert, wantRecording string) {
	t.Helper()
	where := &model.CreateSearchRulesRequestSearchWhereNode{
		Filter: &model.CreateSearchRulesRequestSearchFilterLeaf{
			Field:    fieldFolder,
			Operator: model.CreateSearchRulesRequestSearchFilterLeafOperatorIn,
			Values:   []string{folderUID},
		},
	}
	raw, err := json.Marshal(model.CreateSearchRulesRequestBody{Where: where})
	require.NoError(t, err)
	t.Run("cross-kind", func(t *testing.T) {
		rec := httptest.NewRecorder()
		require.NoError(t, handler.SearchRules(ctx, rec, &app.CustomRouteRequest{
			ResourceIdentifier: resource.FullIdentifier{Namespace: "default"},
			Body:               io.NopCloser(strings.NewReader(string(raw))),
		}))
		requireSearchBody(t, rec.Body.String(), wantAlert, wantRecording)
	})

	filter := &searchv0.WhereNode{Filter: &searchv0.FilterPredicate{
		Field: fieldFolder, Operator: perKindFilterOperatorIn, Values: []string{folderUID},
	}}
	t.Run("alert rules", func(t *testing.T) {
		requireSearchBody(t, perKindSearch(t, handler.SearchAlertRules, ctx, filter), wantAlert, "")
	})
	t.Run("recording rules", func(t *testing.T) {
		requireSearchBody(t, perKindSearch(t, handler.SearchRecordingRules, ctx, filter), "", wantRecording)
	})
}

func requireSearchBody(t *testing.T, body, wantAlert, wantRecording string) {
	t.Helper()
	if wantAlert != "" {
		require.Contains(t, body, wantAlert)
	} else {
		require.NotContains(t, body, visibleAlertTitle)
		require.NotContains(t, body, secretAlertTitle)
		require.NotContains(t, body, secretAlertQuery)
	}
	if wantRecording != "" {
		require.Contains(t, body, wantRecording)
	} else {
		require.NotContains(t, body, visibleRecTitle)
		require.NotContains(t, body, secretRecTitle)
		require.NotContains(t, body, secretRecQuery)
	}
	require.NotContains(t, body, secretAlertTitle)
	require.NotContains(t, body, secretAlertQuery)
	require.NotContains(t, body, secretRecTitle)
	require.NotContains(t, body, secretRecQuery)
}

func perKindSearch(t *testing.T, route func(context.Context, app.CustomRouteResponseWriter, *app.CustomRouteRequest) error, ctx context.Context, where *searchv0.WhereNode) string {
	t.Helper()
	query := searchv0.SearchQuery{
		TypeMeta: metav1.TypeMeta{APIVersion: searchv0.APIVERSION, Kind: searchv0.KindSearchQuery},
		Where:    where,
	}
	raw, err := json.Marshal(query)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	require.NoError(t, route(ctx, rec, &app.CustomRouteRequest{
		ResourceIdentifier: resource.FullIdentifier{Namespace: "default"},
		Body:               io.NopCloser(strings.NewReader(string(raw))),
	}))
	return rec.Body.String()
}
