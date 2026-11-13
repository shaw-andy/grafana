package service

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func storedBrowserAccessURLIsSafe(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() != "collector.example" {
		return false
	}
	// Compare the stored string, not parsed.Scheme. url.Parse lowercases the scheme
	// on the parsed value and does not rewrite the string that is inserted.
	return strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://")
}

func TestIntegrationDirectAccessUppercaseSchemeIsRejectedOrNormalized(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	const rawURL = "HTTPS://collector.example/graphite"

	t.Run("add", func(t *testing.T) {
		dsService := initDSService(t)
		ds, err := dsService.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:    1,
			Name:     "graphite-direct",
			Type:     datasources.DS_GRAPHITE,
			Access:   datasources.DS_ACCESS_DIRECT,
			URL:      rawURL,
			JsonData: simplejson.New(),
		})
		if err != nil {
			require.ErrorContains(t, err, "url")
			return
		}
		require.Truef(t, storedBrowserAccessURLIsSafe(ds.URL), "add returned %q", ds.URL)

		stored, err := dsService.GetDataSource(context.Background(), &datasources.GetDataSourceQuery{
			OrgID: 1,
			UID:   ds.UID,
		})
		require.NoError(t, err)
		require.Truef(t, storedBrowserAccessURLIsSafe(stored.URL), "add read back %q", stored.URL)
	})

	t.Run("update", func(t *testing.T) {
		dsService := initDSService(t)
		created, err := dsService.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
			OrgID:    1,
			Name:     "graphite-direct",
			Type:     datasources.DS_GRAPHITE,
			Access:   datasources.DS_ACCESS_DIRECT,
			URL:      "https://collector.example/graphite",
			JsonData: simplejson.New(),
		})
		require.NoError(t, err)

		updated, err := dsService.UpdateDataSource(context.Background(), &datasources.UpdateDataSourceCommand{
			ID:       created.ID,
			OrgID:    created.OrgID,
			UID:      created.UID,
			Name:     created.Name,
			Type:     created.Type,
			Access:   datasources.DS_ACCESS_DIRECT,
			URL:      rawURL,
			Version:  created.Version,
			JsonData: simplejson.New(),
		})
		if err != nil {
			require.ErrorContains(t, err, "url")
			return
		}
		require.Truef(t, storedBrowserAccessURLIsSafe(updated.URL), "update returned %q", updated.URL)

		stored, err := dsService.GetDataSource(context.Background(), &datasources.GetDataSourceQuery{
			OrgID: created.OrgID,
			UID:   created.UID,
		})
		require.NoError(t, err)
		require.Truef(t, storedBrowserAccessURLIsSafe(stored.URL), "update read back %q", stored.URL)
	})
}

func TestIntegrationDirectAccessLowercaseSchemeIsStored(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	const rawURL = "https://collector.example/graphite"
	dsService := initDSService(t)
	ds, err := dsService.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		OrgID:    1,
		Name:     "graphite-direct-lower",
		Type:     datasources.DS_GRAPHITE,
		Access:   datasources.DS_ACCESS_DIRECT,
		URL:      rawURL,
		JsonData: simplejson.New(),
	})
	require.NoError(t, err)

	stored, err := dsService.GetDataSource(context.Background(), &datasources.GetDataSourceQuery{
		OrgID: 1,
		UID:   ds.UID,
	})
	require.NoError(t, err)
	require.Equal(t, rawURL, stored.URL)
	require.Equal(t, datasources.DsAccess(datasources.DS_ACCESS_DIRECT), stored.Access)
}
