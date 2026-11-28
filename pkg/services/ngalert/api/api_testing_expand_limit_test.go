package api

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	amv2 "github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alerting/models"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dsquerierclient"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	ngaccesscontrol "github.com/grafana/grafana/pkg/services/ngalert/accesscontrol"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// previewExpansionAllocBudget is the heap RouteTestGrafanaRuleConfig may use while
// expanding one annotation. It is several times the 4 MiB label cap and far below
// the 64 MiB full output of the doubling template.
const previewExpansionAllocBudget = 32 << 20

func TestRouteTestGrafanaRuleConfig_ExpressionRuleTemplateExpansionIsBounded(t *testing.T) {
	const (
		orgID         int64 = 1
		allowedFolder       = "folder-viewer-can-read"
		otherFolder         = "folder-viewer-cannot-read"
	)
	ac := acimpl.ProvideAccessControlTest()
	allowedScope := folder.ScopeFoldersProvider.GetResourceScopeUID(allowedFolder)
	viewer := &user.SignedInUser{
		OrgID:   orgID,
		OrgRole: "Viewer",
		Permissions: map[int64]map[string][]string{
			orgID: {
				// Fixed role fixed:alerting.rules:reader grants this action to Viewer.
				accesscontrol.ActionAlertingRuleRead: {allowedScope},
				// Top-level folder View grants folders:read. No datasources:query.
				folder.ActionFoldersRead: {allowedScope},
			},
		},
	}

	routeAllows, err := ac.Evaluate(context.Background(), viewer, accesscontrol.EvalPermission(accesscontrol.ActionAlertingRuleRead))
	require.NoError(t, err)
	require.True(t, routeAllows, "POST /api/v1/rule/test/grafana is authorized by alert.rules:read")

	rules := ngaccesscontrol.NewRuleService(ac)
	exprRule := &ngmodels.AlertRule{Data: []ngmodels.AlertQuery{{
		RefID:         "A",
		DatasourceUID: expr.DatasourceUID,
	}}}
	require.NoError(t, rules.AuthorizeDatasourceAccessForRule(context.Background(), viewer, exprRule))

	realRule := &ngmodels.AlertRule{Data: []ngmodels.AlertQuery{{
		RefID:         "A",
		DatasourceUID: "prom-ds",
	}}}
	require.Error(t, rules.AuthorizeDatasourceAccessForRule(context.Background(), viewer, realRule))

	srv := newPreviewSrv(t, ac, map[string]*folder.Folder{
		allowedFolder: {UID: allowedFolder, Title: "Allowed", Fullpath: "Allowed"},
		otherFolder:   {UID: otherFolder, Title: "Other", Fullpath: "Other"},
	})

	t.Run("refuses a folder the viewer cannot read before expanding", func(t *testing.T) {
		tmpl, fullLen := doublingTemplate(strings.Repeat("C", 1024), 16)
		require.Greater(t, fullLen, previewExpansionAllocBudget)
		rc := previewContext(viewer)
		var resp responseStatus
		alloc := heapAllocDuring(func() {
			resp = srv.RouteTestGrafanaRuleConfig(rc, previewRequest(otherFolder, tmpl))
		})
		require.Equal(t, http.StatusForbidden, resp.Status())
		require.LessOrEqualf(t, alloc, uint64(previewExpansionAllocBudget),
			"folder denial allocated %d bytes; the template must not be expanded", alloc)
	})

	t.Run("refuses a non-expression datasource before expanding", func(t *testing.T) {
		rc := previewContext(viewer)
		tmpl, _ := doublingTemplate(strings.Repeat("D", 1024), 16)
		body := previewRequest(allowedFolder, tmpl)
		body.Rule.GrafanaManagedAlert.Data[0].DatasourceUID = "prom-ds"
		body.Rule.GrafanaManagedAlert.Data[0].Model = []byte(`{"refId":"A"}`)
		var resp responseStatus
		alloc := heapAllocDuring(func() {
			resp = srv.RouteTestGrafanaRuleConfig(rc, body)
		})
		require.Equal(t, http.StatusForbidden, resp.Status())
		require.LessOrEqualf(t, alloc, uint64(previewExpansionAllocBudget),
			"datasource denial allocated %d bytes; the template must not be expanded", alloc)
	})

	t.Run("small template expands for a viewer", func(t *testing.T) {
		tmpl, fullLen := doublingTemplate("ping", 2)
		require.Equal(t, len("ping")*4, fullLen)
		rc := previewContext(viewer)
		resp := srv.RouteTestGrafanaRuleConfig(rc, previewRequest(allowedFolder, tmpl))
		require.Equalf(t, http.StatusOK, resp.Status(), "body: %s", resp.Body())
		alerts := decodeAlerts(t, resp.Body())
		require.NotEmpty(t, alerts)
		require.Equal(t, strings.Repeat("ping", 4), string(alerts[0].Annotations["summary"]))
		require.Equal(t, allowedFolder, string(alerts[0].Annotations[models.NamespaceUIDLabel]))
	})

	t.Run("doubling annotation does not materialize its full output", func(t *testing.T) {
		base := strings.Repeat("E", 1024)
		tmpl, fullLen := doublingTemplate(base, 16)
		require.Greater(t, fullLen, state.DefaultMaxLabelValueSize)
		require.Greater(t, fullLen, previewExpansionAllocBudget)
		require.Less(t, len(tmpl), 8<<10)

		rc := previewContext(viewer)
		var resp responseStatus
		alloc := heapAllocDuring(func() {
			resp = srv.RouteTestGrafanaRuleConfig(rc, previewRequest(allowedFolder, tmpl))
		})
		t.Logf("preview alloc=%d status=%d", alloc, resp.Status())
		require.LessOrEqualf(t, alloc, uint64(previewExpansionAllocBudget),
			"preview allocated %d bytes; full template output is %d bytes", alloc, fullLen)
		if resp.Status() == http.StatusOK {
			alerts := decodeAlerts(t, resp.Body())
			require.NotEmpty(t, alerts)
			require.Equal(t, allowedFolder, string(alerts[0].Annotations[models.NamespaceUIDLabel]))
			for name, value := range alerts[0].Annotations {
				require.LessOrEqualf(t, len(value), state.DefaultMaxLabelValueSize, "annotation %s", name)
			}
			for name, value := range alerts[0].Labels {
				require.LessOrEqualf(t, len(value), state.DefaultMaxLabelValueSize, "label %s", name)
			}
		} else {
			require.Equalf(t, http.StatusBadRequest, resp.Status(), "body: %s", resp.Body())
		}
	})
}

// responseStatus is the subset of response.Response used by these tests.
type responseStatus interface {
	Status() int
	Body() []byte
}

type permittingFolder struct {
	ac      accesscontrol.AccessControl
	folders map[string]*folder.Folder
}

func (p permittingFolder) GetNamespaceByUID(ctx context.Context, uid string, orgID int64, user identity.Requester) (*folder.Folder, error) {
	f, ok := p.folders[uid]
	if !ok || f.UID != uid {
		return nil, folder.ErrFolderNotFound
	}
	allowed, err := p.ac.Evaluate(ctx, user, accesscontrol.EvalPermission(folder.ActionFoldersRead, folder.ScopeFoldersProvider.GetResourceScopeUID(uid)))
	if err != nil || !allowed {
		return nil, folder.ErrAccessDenied
	}
	return f, nil
}

func newPreviewSrv(t *testing.T, ac accesscontrol.AccessControl, folders map[string]*folder.Folder) *TestingApiSrv {
	t.Helper()
	features := featuremgmt.WithFeatures()
	return &TestingApiSrv{
		authz: ngaccesscontrol.NewRuleService(ac),
		evaluator: eval.NewEvaluatorFactory(
			setting.UnifiedAlertingSettings{EvaluationTimeout: time.Minute},
			nil,
			expr.ProvideService(
				&setting.Cfg{ExpressionsEnabled: true},
				nil,
				nil,
				features,
				nil,
				tracing.InitializeTracerForTest(),
				dsquerierclient.NewNullQSDatasourceClientBuilder(),
			),
		),
		cfg: &setting.UnifiedAlertingSettings{
			BaseInterval:                  10 * time.Second,
			DefaultRuleEvaluationInterval: 10 * time.Second,
		},
		tracer:         tracing.InitializeTracerForTest(),
		featureManager: features,
		folderService:  permittingFolder{ac: ac, folders: folders},
		appUrl:         nil,
	}
}

func previewContext(usr *user.SignedInUser) *contextmodel.ReqContext {
	req, err := http.NewRequest(http.MethodPost, "/api/v1/rule/test/grafana", nil)
	if err != nil {
		panic(err)
	}
	return &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: usr,
		Logger:       log.New("ngalert.api.testing"),
	}
}

func previewRequest(folderUID, tmpl string) apimodels.PostableExtendedRuleNodeExtended {
	forDur := model.Duration(0)
	return apimodels.PostableExtendedRuleNodeExtended{
		Rule: apimodels.PostableExtendedRuleNode{
			ApiRuleNode: &apimodels.ApiRuleNode{
				For: &forDur,
				Annotations: map[string]string{
					"summary": tmpl,
				},
			},
			GrafanaManagedAlert: &apimodels.PostableGrafanaRule{
				Title:        "preview",
				Condition:    "A",
				NoDataState:  apimodels.OK,
				ExecErrState: apimodels.ErrorErrState,
				Data: []apimodels.AlertQuery{{
					RefID:             "A",
					DatasourceUID:     expr.DatasourceUID,
					RelativeTimeRange: apimodels.RelativeTimeRange{From: apimodels.Duration(10 * time.Minute), To: 0},
					Model:             []byte(`{"refId":"A","datasource":{"uid":"__expr__","type":"__expr__"},"type":"math","expression":"1"}`),
				}},
			},
		},
		NamespaceUID: folderUID,
		RuleGroup:    "group",
	}
}

func decodeAlerts(t *testing.T, body []byte) []amv2.PostableAlert {
	t.Helper()
	var alerts []amv2.PostableAlert
	require.NoError(t, json.Unmarshal(body, &alerts))
	return alerts
}

func doublingTemplate(base string, doublings int) (tmpl string, fullLen int) {
	var b strings.Builder
	b.WriteString(`{{define "d0"}}`)
	b.WriteString(base)
	b.WriteString(`{{end}}`)
	for i := 1; i <= doublings; i++ {
		b.WriteString(`{{define "d`)
		b.WriteString(itoa(i))
		b.WriteString(`"}}{{template "d`)
		b.WriteString(itoa(i - 1))
		b.WriteString(`"}}{{template "d`)
		b.WriteString(itoa(i - 1))
		b.WriteString(`"}}{{end}}`)
	}
	b.WriteString(`{{template "d`)
	b.WriteString(itoa(doublings))
	b.WriteString(`"}}`)
	return b.String(), len(base) << doublings
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [8]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}

func heapAllocDuring(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
