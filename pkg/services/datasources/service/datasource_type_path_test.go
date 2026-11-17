package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/datasources"
)

// Datasource types are stored and later interpolated into a same-origin plugin
// URL. A type that is not an exact installed plugin id must be rejected before
// any row is written, including when the type only fails the plugin lookup.
func TestDataSourceTypeMustBeInstalledPluginID(t *testing.T) {
	payloads := []struct {
		name   string
		dsType string
	}{
		{name: "logout", dsType: "x/../../../logout#"},
		{name: "switch-org", dsType: "x/../../../profile/switch-org/2#"},
		{name: "plugin-prefix", dsType: "test/../../../logout#"},
	}

	for _, payload := range payloads {
		t.Run(payload.name, func(t *testing.T) {
			ctx := context.Background()
			dsService := initDSService(t)
			name := "path-type-" + payload.name
			dsType := payload.dsType

			created, err := dsService.AddDataSource(ctx, &datasources.AddDataSourceCommand{
				OrgID:  1,
				Name:   name,
				Type:   dsType,
				Access: datasources.DS_ACCESS_PROXY,
			})
			require.Error(t, err)
			require.Nil(t, created)

			_, getErr := dsService.GetDataSource(ctx, &datasources.GetDataSourceQuery{
				OrgID: 1,
				Name:  name,
			})
			require.ErrorIs(t, getErr, datasources.ErrDataSourceNotFound)

			all, listErr := dsService.GetAllDataSources(ctx, &datasources.GetAllDataSourcesQuery{})
			require.NoError(t, listErr)
			for _, ds := range all {
				require.NotEqual(t, dsType, ds.Type)
			}
		})
	}
}

func TestUpdateDataSourceRejectsTypeThatIsNotInstalledPluginID(t *testing.T) {
	ctx := context.Background()
	dsService := initDSService(t)

	created, err := dsService.AddDataSource(ctx, &datasources.AddDataSourceCommand{
		OrgID:  1,
		Name:   "kept-plugin",
		Type:   "test",
		Access: datasources.DS_ACCESS_PROXY,
	})
	require.NoError(t, err)
	require.Equal(t, "test", created.Type)

	updated, err := dsService.UpdateDataSource(ctx, &datasources.UpdateDataSourceCommand{
		ID:      created.ID,
		OrgID:   created.OrgID,
		UID:     created.UID,
		Name:    created.Name,
		Type:    "x/../../../logout#",
		Access:  datasources.DS_ACCESS_PROXY,
		Version: created.Version,
	})
	require.Error(t, err)
	require.Nil(t, updated)

	stored, getErr := dsService.GetDataSource(ctx, &datasources.GetDataSourceQuery{
		OrgID: created.OrgID,
		UID:   created.UID,
	})
	require.NoError(t, getErr)
	require.Equal(t, "test", stored.Type)
}
