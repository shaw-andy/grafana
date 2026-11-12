package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboardsnapshots"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// Create persists the submitted dashboard, and GET /api/snapshots/{key} returns that
// dashboard with no session. The query text has to be gone before it is stored.
func TestCreateDashboardSnapshotStripsAnnotationQueriesBeforeAnonymousGet(t *testing.T) {
	editor := &user.SignedInUser{UserID: 1, OrgID: 1, Login: "editor"}
	body := []byte(`{
		"name": "Annotated dashboard",
		"dashboard": {
			"uid": "dashuid01",
			"title": "Annotated dashboard",
			"annotations": [{
				"kind": "AnnotationQuery",
				"spec": {
					"name": "Prom annotations",
					"enable": true,
					"hide": false,
					"iconColor": "red",
					"builtIn": false,
					"query": {
						"kind": "DataQuery",
						"group": "prometheus",
						"version": "v0",
						"datasource": {"name": "prom_ds_uid_annotation_7f3a"},
						"spec": {"expr": "sum(rate(payments_api_annotation_query[5m]))", "refId": "Anno"}
					}
				}
			}]
		}
	}`)

	var stored *simplejson.Json
	snapSvc := dashboardsnapshots.NewMockService(t)
	snapSvc.On("ValidateDashboardExists", mock.Anything, int64(1), "dashuid01").Return(nil)
	snapSvc.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			cmd := args.Get(1).(*dashboardsnapshots.CreateDashboardSnapshotCommand)
			raw, err := cmd.Dashboard.MarshalJSON()
			require.NoError(t, err)
			parsed, err := simplejson.NewJson(raw)
			require.NoError(t, err)
			stored = parsed
		}).
		Return(&dashboardsnapshots.DashboardSnapshot{Key: "public-key", DeleteKey: "delete-key"}, nil)

	hs := &HTTPServer{
		dashboardsnapshotsService: snapSvc,
		Cfg:                       &setting.Cfg{SnapshotEnabled: true},
		AccessControl:             actest.FakeAccessControl{ExpectedEvaluate: true},
	}

	postReq := httptest.NewRequest(http.MethodPost, "/api/snapshots/", bytes.NewReader(body))
	postReq.Header.Set("Content-Type", "application/json")
	postReq = postReq.WithContext(identity.WithRequester(postReq.Context(), editor))
	postRecorder := httptest.NewRecorder()
	hs.CreateDashboardSnapshot(&contextmodel.ReqContext{
		Context:      &web.Context{Req: postReq, Resp: web.NewResponseWriter(http.MethodPost, postRecorder)},
		SignedInUser: editor,
		IsSignedIn:   true,
		Logger:       log.NewNopLogger(),
	})
	require.Equal(t, http.StatusOK, postRecorder.Code, postRecorder.Body.String())
	require.NotNil(t, stored)

	snapSvc.On("GetDashboardSnapshot", mock.Anything, mock.MatchedBy(func(q *dashboardsnapshots.GetDashboardSnapshotQuery) bool {
		return q.Key == "public-key"
	})).Return(&dashboardsnapshots.DashboardSnapshot{
		Key:       "public-key",
		DeleteKey: "delete-key",
		Dashboard: stored,
		Expires:   time.Now().Add(time.Hour),
	}, nil)

	getReq := httptest.NewRequest(http.MethodGet, "/api/snapshots/public-key", nil)
	getReq = web.SetURLParams(getReq, map[string]string{":key": "public-key"})
	getRecorder := httptest.NewRecorder()
	resp := hs.GetDashboardSnapshot(&contextmodel.ReqContext{
		Context:      &web.Context{Req: getReq, Resp: web.NewResponseWriter(http.MethodGet, getRecorder)},
		SignedInUser: &user.SignedInUser{IsAnonymous: true},
		IsSignedIn:   false,
		Logger:       log.NewNopLogger(),
	})
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.Status())
	encoded := string(resp.Body())
	require.NotContains(t, encoded, "payments_api_annotation_query")
	require.NotContains(t, encoded, "sum(rate(payments_api_annotation_query[5m]))")
	require.NotContains(t, encoded, "prom_ds_uid_annotation_7f3a")
	require.Contains(t, encoded, "Prom annotations")

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(resp.Body(), &decoded))
	meta, ok := decoded["meta"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, meta["isSnapshot"])
}
