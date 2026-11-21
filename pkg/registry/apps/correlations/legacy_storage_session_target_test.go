package correlations

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	authlib "github.com/grafana/authlib/types"
	correlationsV0 "github.com/grafana/grafana/apps/correlations/pkg/apis/correlation/v0alpha1"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/correlations"
	"github.com/grafana/grafana/pkg/services/datasources"
	fakedatasources "github.com/grafana/grafana/pkg/services/datasources/fakes"
	datasourceservice "github.com/grafana/grafana/pkg/services/datasources/service"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
)

func TestLegacyStorageRejectsSessionChangingExternalTarget(t *testing.T) {
	for _, target := range []string{"/logout", "/profile/switch-org/2", "//grafana.example/logout", "javascript:alert(1)"} {
		t.Run("create "+target, func(t *testing.T) {
			store, svc, dsUID := newLegacyCorrelationService(t)
			storage := &legacyStorage{service: svc}
			ctx := k8srequest.WithNamespace(context.Background(), authlib.OrgNamespaceFormatter(1))
			_, err := storage.Create(ctx, externalCorrelationObject("corr", dsUID, target), allowAnyObject, &metav1.CreateOptions{})
			require.Empty(t, storedTargetURLs(t, store))
			require.Error(t, err)
		})

		t.Run("update "+target, func(t *testing.T) {
			store, svc, dsUID := newLegacyCorrelationService(t)
			created, err := svc.CreateCorrelation(context.Background(), correlations.CreateCorrelationCommand{
				SourceUID: dsUID,
				OrgId:     1,
				Label:     "View documentation",
				Type:      correlations.CorrelationType("external"),
				Config: correlations.CorrelationConfig{
					Field:  "message",
					Target: map[string]any{"url": "https://docs.example.com/guide"},
				},
			})
			require.NoError(t, err)

			storage := &legacyStorage{service: svc}
			ctx := k8srequest.WithNamespace(context.Background(), authlib.OrgNamespaceFormatter(1))
			_, _, err = storage.Update(
				ctx,
				created.UID,
				rest.DefaultUpdatedObjectInfo(externalCorrelationObject(created.UID, dsUID, target)),
				allowAnyObject,
				allowAnyUpdate,
				false,
				&metav1.UpdateOptions{},
			)
			require.Equal(t, []string{"https://docs.example.com/guide"}, storedTargetURLs(t, store))
			require.Error(t, err)
		})
	}
}

func allowAnyObject(context.Context, runtime.Object) error { return nil }

func allowAnyUpdate(context.Context, runtime.Object, runtime.Object) error { return nil }

func newLegacyCorrelationService(t *testing.T) (db.DB, *correlations.CorrelationsService, string) {
	t.Helper()
	sqlStore := db.NewTestStore(t)
	const (
		orgID = int64(1)
		dsUID = "loki-uid"
	)
	datasourceStore := datasourceservice.CreateStore(sqlStore, log.NewNopLogger())
	_, err := datasourceStore.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		OrgID: orgID,
		Name:  "Loki",
		UID:   dsUID,
		Type:  "loki",
	})
	require.NoError(t, err)
	svc := &correlations.CorrelationsService{
		SQLStore: sqlStore,
		DataSourceService: &fakedatasources.FakeDataSourceService{
			DataSources: []*datasources.DataSource{{
				UID:   dsUID,
				OrgID: orgID,
				Name:  "Loki",
				Type:  "loki",
			}},
		},
		QuotaService: quotatest.New(false, nil),
	}
	return sqlStore, svc, dsUID
}

func externalCorrelationObject(name, dsUID, target string) *correlationsV0.Correlation {
	return &correlationsV0.Correlation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: authlib.OrgNamespaceFormatter(1),
		},
		Spec: correlationsV0.CorrelationSpec{
			Label: "View documentation",
			Type:  correlationsV0.CorrelationCorrelationTypeExternal,
			Source: correlationsV0.CorrelationDataSourceRef{
				Group: "loki",
				Name:  dsUID,
			},
			Config: correlationsV0.CorrelationConfigSpec{
				Field:  "message",
				Target: correlationsV0.CorrelationTargetSpec{"url": target},
			},
		},
	}
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
		var cfg struct {
			Target map[string]any `json:"target"`
		}
		require.NoError(t, json.Unmarshal([]byte(row.Config), &cfg))
		url, _ := cfg.Target["url"].(string)
		urls = append(urls, url)
	}
	return urls
}
