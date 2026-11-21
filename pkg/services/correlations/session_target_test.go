package correlations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/apiserver/client"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	fakedatasources "github.com/grafana/grafana/pkg/services/datasources/fakes"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
	"github.com/grafana/grafana/pkg/web"
)

const grafanaHost = "grafana.example"

func TestExternalCorrelationCreateRejectsSessionURL(t *testing.T) {
	t.Run("relative logout", func(t *testing.T) {
		rejectCreate(t, "/logout")
	})
	t.Run("logout with query", func(t *testing.T) {
		rejectCreate(t, "/logout?redirect=/login")
	})
	t.Run("organization switch", func(t *testing.T) {
		rejectCreate(t, "/profile/switch-org/2")
	})
	t.Run("protocol relative same host", func(t *testing.T) {
		rejectCreate(t, "//"+grafanaHost+"/logout")
	})
	t.Run("javascript url", func(t *testing.T) {
		rejectCreate(t, "javascript:alert(1)")
	})
	t.Run("absolute same host", func(t *testing.T) {
		rejectCreateOnHost(t, grafanaHost, "http://"+grafanaHost+"/logout")
	})
	t.Run("absolute same host and port", func(t *testing.T) {
		rejectCreateOnHost(t, grafanaHost+":3000", "http://"+grafanaHost+":3000/profile/switch-org/2")
	})
}

func TestExternalCorrelationCreateAllowsDifferentHost(t *testing.T) {
	for _, target := range []string{
		"https://docs.example.com/guide",
		"https://docs.example.com/logout",
		"http://docs.example.com/profile/switch-org/2",
	} {
		t.Run(target, func(t *testing.T) {
			svc, store, dsUID := newCorrelationService(t)
			resp := svc.createHandler(correlationRequest(t, grafanaHost, http.MethodPost, "/api/datasources/uid/"+dsUID+"/correlations", externalBody(target), map[string]string{
				":uid": dsUID,
			}))
			require.Equal(t, http.StatusOK, resp.Status(), string(resp.Body()))
			require.Equal(t, []string{target}, storedTargetURLs(t, store))
		})
	}
}

func TestExternalCorrelationUpdateRejectsSessionURL(t *testing.T) {
	for _, target := range []string{"/logout", "/profile/switch-org/2", "http://" + grafanaHost + "/logout"} {
		t.Run(target, func(t *testing.T) {
			svc, store, dsUID := newCorrelationService(t)
			created := createExternal(t, svc, dsUID, "https://docs.example.com/guide")

			resp := svc.updateHandler(correlationRequest(t, grafanaHost, http.MethodPatch, "/api/datasources/uid/"+dsUID+"/correlations/"+created.UID, externalBody(target), map[string]string{
				":uid":            dsUID,
				":correlationUID": created.UID,
			}))
			require.Equal(t, http.StatusBadRequest, resp.Status(), string(resp.Body()))
			require.Equal(t, []string{"https://docs.example.com/guide"}, storedTargetURLs(t, store))
		})
	}
}

func TestQueryCorrelationCreateStillStoresEmptyTarget(t *testing.T) {
	svc, store, dsUID := newCorrelationService(t)
	body := `{
		"targetUID": "` + dsUID + `",
		"type": "query",
		"label": "logs to metrics",
		"config": {"field": "message", "target": {}}
	}`
	resp := svc.createHandler(correlationRequest(t, grafanaHost, http.MethodPost, "/api/datasources/uid/"+dsUID+"/correlations", body, map[string]string{
		":uid": dsUID,
	}))
	require.Equal(t, http.StatusOK, resp.Status(), string(resp.Body()))
	require.Equal(t, []string{""}, storedTargetURLs(t, store))
}

func TestK8sCorrelationServiceRejectsSessionChangingExternalTarget(t *testing.T) {
	for _, target := range []string{"/logout", "/profile/switch-org/2", "http://" + grafanaHost + "/logout"} {
		t.Run("create "+target, func(t *testing.T) {
			fake := &recordingK8sHandler{}
			svc, dsUID := newK8sCorrelationService(fake)
			resp := svc.createHandler(correlationRequest(t, grafanaHost, http.MethodPost, "/api/datasources/uid/"+dsUID+"/correlations", externalBody(target), map[string]string{
				":uid": dsUID,
			}))
			require.Equal(t, http.StatusBadRequest, resp.Status(), string(resp.Body()))
			require.Empty(t, fake.createdURLs)
		})
		t.Run("update "+target, func(t *testing.T) {
			fake := &recordingK8sHandler{}
			svc, dsUID := newK8sCorrelationService(fake)
			resp := svc.updateHandler(correlationRequest(t, grafanaHost, http.MethodPatch, "/api/datasources/uid/"+dsUID+"/correlations/corr", externalBody(target), map[string]string{
				":uid":            dsUID,
				":correlationUID": "corr",
			}))
			require.Equal(t, http.StatusBadRequest, resp.Status(), string(resp.Body()))
			require.Empty(t, fake.updatedURLs)
		})
	}
}

func rejectCreate(t *testing.T, target string) {
	t.Helper()
	rejectCreateOnHost(t, grafanaHost, target)

	svc, store, dsUID := newCorrelationService(t)
	_, err := svc.CreateCorrelation(context.Background(), CreateCorrelationCommand{
		SourceUID: dsUID,
		OrgId:     1,
		Label:     "View documentation",
		Type:      external,
		Config: CorrelationConfig{
			Field:  "message",
			Target: map[string]any{"url": target},
		},
	})
	require.Error(t, err)
	require.Empty(t, storedTargetURLs(t, store))
}

func rejectCreateOnHost(t *testing.T, host, target string) {
	t.Helper()
	svc, store, dsUID := newCorrelationService(t)
	resp := svc.createHandler(correlationRequest(t, host, http.MethodPost, "/api/datasources/uid/"+dsUID+"/correlations", externalBody(target), map[string]string{
		":uid": dsUID,
	}))
	require.Equal(t, http.StatusBadRequest, resp.Status(), string(resp.Body()))
	require.Empty(t, storedTargetURLs(t, store))
}

func createExternal(t *testing.T, svc *CorrelationsService, dsUID, target string) Correlation {
	t.Helper()
	created, err := svc.CreateCorrelation(context.Background(), CreateCorrelationCommand{
		SourceUID: dsUID,
		OrgId:     1,
		Label:     "View documentation",
		Type:      external,
		Config: CorrelationConfig{
			Field:  "message",
			Target: map[string]any{"url": target},
		},
	})
	require.NoError(t, err)
	return created
}

func newCorrelationService(t *testing.T) (*CorrelationsService, db.DB, string) {
	t.Helper()
	store := db.NewTestStore(t)
	const dsUID = "loki-uid"
	svc := &CorrelationsService{
		SQLStore: store,
		DataSourceService: &fakedatasources.FakeDataSourceService{
			DataSources: []*datasources.DataSource{{
				UID:   dsUID,
				OrgID: 1,
				Name:  "Loki",
				Type:  "loki",
			}},
		},
		QuotaService: quotatest.New(false, nil),
	}
	return svc, store, dsUID
}

func newK8sCorrelationService(fake client.K8sHandler) (*CorrelationsK8sService, string) {
	const dsUID = "loki-uid"
	return &CorrelationsK8sService{
		DataSourceService: &fakedatasources.FakeDataSourceService{
			DataSources: []*datasources.DataSource{{
				UID:   dsUID,
				OrgID: 1,
				Name:  "Loki",
				Type:  "loki",
			}},
		},
		k8sClient: fake,
	}, dsUID
}

func correlationRequest(t *testing.T, host, method, path, body string, params map[string]string) *contextmodel.ReqContext {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req = web.SetURLParams(req, params)
	return &contextmodel.ReqContext{
		Context:      &web.Context{Req: req},
		SignedInUser: &user.SignedInUser{OrgID: 1},
	}
}

func externalBody(target string) string {
	payload := map[string]any{
		"label": "View documentation",
		"type":  "external",
		"config": map[string]any{
			"field": "message",
			"target": map[string]any{
				"url": target,
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func storedTargetURLs(t *testing.T, store db.DB) []string {
	t.Helper()
	type row struct {
		Config string `xorm:"config"`
	}
	var rows []row
	err := store.WithDbSession(context.Background(), func(session *db.Session) error {
		return session.Table("correlation").Cols("config").Find(&rows)
	})
	require.NoError(t, err)
	urls := make([]string, 0, len(rows))
	for _, row := range rows {
		var cfg CorrelationConfig
		require.NoError(t, json.Unmarshal([]byte(row.Config), &cfg))
		url, _ := cfg.Target["url"].(string)
		urls = append(urls, url)
	}
	return urls
}

type recordingK8sHandler struct {
	createdURLs []string
	updatedURLs []string
}

func (h *recordingK8sHandler) GetNamespace(orgID int64) string { return "org-1" }

func (h *recordingK8sHandler) Get(context.Context, string, int64, metav1.GetOptions, ...string) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (h *recordingK8sHandler) Create(_ context.Context, obj *unstructured.Unstructured, _ int64, _ metav1.CreateOptions) (*unstructured.Unstructured, error) {
	h.createdURLs = append(h.createdURLs, targetURL(obj))
	return obj, nil
}

func (h *recordingK8sHandler) Update(_ context.Context, obj *unstructured.Unstructured, _ int64, _ metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	h.updatedURLs = append(h.updatedURLs, targetURL(obj))
	return obj, nil
}

func (h *recordingK8sHandler) Patch(context.Context, string, types.PatchType, []byte, int64, metav1.PatchOptions) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{}, nil
}

func (h *recordingK8sHandler) Delete(context.Context, string, int64, metav1.DeleteOptions) error {
	return nil
}

func (h *recordingK8sHandler) DeleteCollection(context.Context, int64, metav1.ListOptions) error {
	return nil
}

func (h *recordingK8sHandler) List(context.Context, int64, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return &unstructured.UnstructuredList{}, nil
}

func (h *recordingK8sHandler) Search(context.Context, int64, *resourcepb.ResourceSearchRequest) (*resourcepb.ResourceSearchResponse, error) {
	return &resourcepb.ResourceSearchResponse{}, nil
}

func (h *recordingK8sHandler) GetStats(context.Context, int64) (*resourcepb.ResourceStatsResponse, error) {
	return &resourcepb.ResourceStatsResponse{}, nil
}

func (h *recordingK8sHandler) GetUsersFromMeta(context.Context, []string) (map[string]*user.User, error) {
	return map[string]*user.User{}, nil
}

func targetURL(obj *unstructured.Unstructured) string {
	if obj == nil {
		return ""
	}
	url, _, _ := unstructured.NestedString(obj.Object, "spec", "config", "target", "url")
	return url
}
