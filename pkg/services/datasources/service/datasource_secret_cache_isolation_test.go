package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/plugins/manager/pluginfakes"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	acmock "github.com/grafana/grafana/pkg/services/accesscontrol/mock"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/plugincontext"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/quota/quotatest"
	"github.com/grafana/grafana/pkg/services/secrets/fakes"
	secretskvs "github.com/grafana/grafana/pkg/services/secrets/kvstore"
	secretsmng "github.com/grafana/grafana/pkg/services/secrets/manager"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// Obvious placeholders. They exist so two organizations can be told apart.
const (
	attackerOrgID int64 = 1
	victimOrgID   int64 = 12
	otherOrgID    int64 = 3

	victimDatasourceName   = "prometheus"
	attackerDatasourceName = "2prometheus"
	otherDatasourceName    = "prometheus"

	victimDBName   = "mysql"
	attackerDBName = "2mysql"

	scopeHeader = "X-Scope-Token"

	placeholderVictimBasic    = "placeholder-victim-basic"
	placeholderAttackerBasic  = "placeholder-attacker-basic"
	placeholderVictimHeader   = "placeholder-victim-header"
	placeholderAttackerHeader = "placeholder-attacker-header"
	placeholderVictimDB       = "placeholder-victim-db"
	placeholderAttackerDB     = "placeholder-attacker-db"

	attackerBasicUser = "attacker-basic-user"
	victimBasicUser   = "victim-basic-user"
	attackerDBUser    = "attacker-db-user"
	victimDBUser      = "victim-db-user"
)

func TestIntegrationDatasourceSecretCacheOrgPrefixIsolation(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	t.Run("query sends the caller secret to the caller url", func(t *testing.T) {
		svc, store := newCachedDatasourceService(t)
		ctx := context.Background()

		var seenAuth, seenHeader string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenAuth = r.Header.Get("Authorization")
			seenHeader = r.Header.Get(scopeHeader)
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(server.Close)

		attacker := addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:         attackerOrgID,
			name:          attackerDatasourceName,
			dsType:        datasources.DS_PROMETHEUS,
			url:           server.URL,
			basicAuth:     true,
			basicAuthUser: attackerBasicUser,
			secrets: map[string]string{
				"basicAuthPassword":                 placeholderAttackerBasic,
				datasources.CustomHeaderValue + "1": placeholderAttackerHeader,
			},
		})
		victim := addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:         victimOrgID,
			name:          victimDatasourceName,
			dsType:        datasources.DS_PROMETHEUS,
			url:           "http://victim.example",
			basicAuth:     true,
			basicAuthUser: victimBasicUser,
			secrets: map[string]string{
				"basicAuthPassword":                 placeholderVictimBasic,
				datasources.CustomHeaderValue + "1": placeholderVictimHeader,
			},
		})

		// ProvideService keeps plaintext for five seconds. Wait that window out so the
		// next read is a cache miss filled by Get, which is the query path.
		time.Sleep(5*time.Second + 200*time.Millisecond)

		// A victim query loads that org's secret and caches it. The attacker request
		// below is the read that must stay on the attacker row.
		_, err := svc.DecryptedValues(ctx, victim)
		require.NoError(t, err)

		// The rows written at create stay the caller's own values. The shared read is the cache.
		require.Equal(t, placeholderAttackerBasic, storedDatasourceSecret(t, store, attackerOrgID, attackerDatasourceName)["basicAuthPassword"])
		require.Equal(t, placeholderVictimBasic, storedDatasourceSecret(t, store, victimOrgID, victimDatasourceName)["basicAuthPassword"])

		transport, err := svc.GetHTTPTransport(ctx, attacker, httpclient.NewProvider())
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/metrics", nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		user, pass, err := util.DecodeBasicAuthHeader(seenAuth)
		require.NoError(t, err)
		require.Equal(t, attackerBasicUser, user)
		require.Equal(t, placeholderAttackerBasic, pass)
		require.Equal(t, placeholderAttackerHeader, seenHeader)

		attackerValues, err := svc.DecryptedValues(ctx, attacker)
		require.NoError(t, err)
		require.Equal(t, placeholderAttackerBasic, attackerValues["basicAuthPassword"])
		require.Equal(t, placeholderAttackerHeader, attackerValues[datasources.CustomHeaderValue+"1"])

		password, err := svc.DecryptedBasicAuthPassword(ctx, attacker)
		require.NoError(t, err)
		require.Equal(t, placeholderAttackerBasic, password)

		settings, err := plugincontext.ProvideService(
			svc.cfg,
			nil,
			svc.pluginStore,
			nil,
			svc,
			nil,
			pluginconfig.NewFakePluginRequestConfigProvider(),
		).GetWithDataSource(ctx, attacker.Type, nil, attacker)
		require.NoError(t, err)
		require.Equal(t, attacker.URL, settings.DataSourceInstanceSettings.URL)
		require.Equal(t, placeholderAttackerBasic, settings.DataSourceInstanceSettings.DecryptedSecureJSONData["basicAuthPassword"])
		require.Equal(t, placeholderAttackerHeader, settings.DataSourceInstanceSettings.DecryptedSecureJSONData[datasources.CustomHeaderValue+"1"])
	})

	t.Run("save does not publish the other org secret", func(t *testing.T) {
		svc, store := newCachedDatasourceService(t)
		ctx := context.Background()

		attacker := addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:         attackerOrgID,
			name:          attackerDatasourceName,
			dsType:        datasources.DS_PROMETHEUS,
			url:           "http://attacker.example",
			basicAuth:     true,
			basicAuthUser: attackerBasicUser,
			secrets: map[string]string{
				"basicAuthPassword": placeholderAttackerBasic,
			},
		})
		_ = addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:         victimOrgID,
			name:          victimDatasourceName,
			dsType:        datasources.DS_PROMETHEUS,
			url:           "http://victim.example",
			basicAuth:     true,
			basicAuthUser: victimBasicUser,
			secrets: map[string]string{
				"basicAuthPassword": placeholderVictimBasic,
			},
		})
		other := addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:         otherOrgID,
			name:          otherDatasourceName,
			dsType:        datasources.DS_PROMETHEUS,
			url:           "http://other.example",
			basicAuth:     true,
			basicAuthUser: "other-basic-user",
			secrets: map[string]string{
				"basicAuthPassword": "placeholder-other-basic",
			},
		})

		otherValues, err := svc.DecryptedValues(ctx, other)
		require.NoError(t, err)
		require.Equal(t, "placeholder-other-basic", otherValues["basicAuthPassword"])

		require.Equal(t, placeholderAttackerBasic, storedDatasourceSecret(t, store, attackerOrgID, attackerDatasourceName)["basicAuthPassword"])
		require.Equal(t, placeholderVictimBasic, storedDatasourceSecret(t, store, victimOrgID, victimDatasourceName)["basicAuthPassword"])

		attackerValues, err := svc.DecryptedValues(ctx, attacker)
		require.NoError(t, err)
		require.Equal(t, placeholderAttackerBasic, attackerValues["basicAuthPassword"])
	})

	t.Run("update keeps the caller secret", func(t *testing.T) {
		svc, store := newCachedDatasourceService(t)
		ctx := context.Background()

		attacker := addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:         attackerOrgID,
			name:          attackerDatasourceName,
			dsType:        datasources.DS_PROMETHEUS,
			url:           "http://attacker.example",
			basicAuth:     true,
			basicAuthUser: attackerBasicUser,
			secrets: map[string]string{
				"basicAuthPassword":                 placeholderAttackerBasic,
				datasources.CustomHeaderValue + "1": placeholderAttackerHeader,
			},
		})
		_ = addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:         victimOrgID,
			name:          victimDatasourceName,
			dsType:        datasources.DS_PROMETHEUS,
			url:           "http://victim.example",
			basicAuth:     true,
			basicAuthUser: victimBasicUser,
			secrets: map[string]string{
				"basicAuthPassword":                 placeholderVictimBasic,
				datasources.CustomHeaderValue + "1": placeholderVictimHeader,
			},
		})

		updated, err := svc.UpdateDataSource(ctx, &datasources.UpdateDataSourceCommand{
			ID:            attacker.ID,
			UID:           attacker.UID,
			OrgID:         attacker.OrgID,
			Name:          "renamed-source",
			Type:          attacker.Type,
			Access:        datasources.DS_ACCESS_PROXY,
			URL:           attacker.URL,
			BasicAuth:     true,
			BasicAuthUser: attackerBasicUser,
			Version:       attacker.Version,
			JsonData:      headerJSON(),
		})
		require.NoError(t, err)
		require.Equal(t, "renamed-source", updated.Name)

		stored := storedDatasourceSecret(t, store, attackerOrgID, "renamed-source")
		require.Equal(t, placeholderAttackerBasic, stored["basicAuthPassword"])
		require.Equal(t, placeholderAttackerHeader, stored[datasources.CustomHeaderValue+"1"])
		require.Equal(t, placeholderVictimBasic, storedDatasourceSecret(t, store, victimOrgID, victimDatasourceName)["basicAuthPassword"])

		values, err := svc.DecryptedValues(ctx, updated)
		require.NoError(t, err)
		require.Equal(t, placeholderAttackerBasic, values["basicAuthPassword"])
	})

	t.Run("database password stays with the caller", func(t *testing.T) {
		svc, _ := newCachedDatasourceService(t)
		ctx := context.Background()

		attacker := addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:   attackerOrgID,
			name:    attackerDBName,
			dsType:  datasources.DS_MYSQL,
			url:     "attacker.example:3306",
			user:    attackerDBUser,
			secrets: map[string]string{"password": placeholderAttackerDB},
		})
		_ = addSecretDatasource(t, svc, secretDatasourceSpec{
			orgID:   victimOrgID,
			name:    victimDBName,
			dsType:  datasources.DS_MYSQL,
			url:     "victim.example:3306",
			user:    victimDBUser,
			secrets: map[string]string{"password": placeholderVictimDB},
		})

		password, err := svc.DecryptedPassword(ctx, attacker)
		require.NoError(t, err)
		require.Equal(t, placeholderAttackerDB, password)

		opts, err := svc.httpClientOptions(ctx, attacker)
		require.NoError(t, err)
		require.NotNil(t, opts.BasicAuth)
		require.Equal(t, attackerDBUser, opts.BasicAuth.User)
		require.Equal(t, placeholderAttackerDB, opts.BasicAuth.Password)
	})
}

type secretDatasourceSpec struct {
	orgID         int64
	name          string
	dsType        string
	url           string
	user          string
	basicAuth     bool
	basicAuthUser string
	secrets       map[string]string
}

func addSecretDatasource(t *testing.T, svc *Service, spec secretDatasourceSpec) *datasources.DataSource {
	t.Helper()
	ds, err := svc.AddDataSource(context.Background(), &datasources.AddDataSourceCommand{
		OrgID:          spec.orgID,
		Name:           spec.name,
		Type:           spec.dsType,
		Access:         datasources.DS_ACCESS_PROXY,
		URL:            spec.url,
		User:           spec.user,
		BasicAuth:      spec.basicAuth,
		BasicAuthUser:  spec.basicAuthUser,
		JsonData:       headerJSON(),
		SecureJsonData: spec.secrets,
	})
	require.NoError(t, err)
	require.Equal(t, spec.name, ds.Name)
	require.Equal(t, spec.orgID, ds.OrgID)
	return ds
}

func headerJSON() *simplejson.Json {
	data := simplejson.New()
	data.Set(datasources.CustomHeaderName+"1", scopeHeader)
	return data
}

func storedDatasourceSecret(t *testing.T, store secretskvs.SecretsKVStore, orgID int64, name string) map[string]string {
	t.Helper()
	raw, err := secretskvs.GetUnwrappedStoreFromCache(store)
	require.NoError(t, err)
	value, ok, err := raw.Get(context.Background(), orgID, name, secretskvs.DataSourceSecretType)
	require.NoError(t, err)
	require.True(t, ok)
	decoded := map[string]string{}
	require.NoError(t, json.Unmarshal([]byte(value), &decoded))
	return decoded
}

func newCachedDatasourceService(t *testing.T) (*Service, secretskvs.SecretsKVStore) {
	t.Helper()
	sqlStore := db.InitTestDB(t) //nolint:staticcheck // legacy shared-DB test setup; migrate to NewTestStore
	secretsService := secretsmng.SetupTestService(t, fakes.NewFakeSecretsStore())
	secretsStore, err := secretskvs.ProvideService(sqlStore, secretsService)
	require.NoError(t, err)

	permissions := acmock.NewMockedPermissionsService()
	permissions.On("SetPermissions", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]accesscontrol.ResourcePermission{}, nil)

	cfg := &setting.Cfg{BuildVersion: "11.0.0"}
	features := featuremgmt.WithFeatures()
	svc, err := ProvideService(
		sqlStore,
		secretsService,
		secretsStore,
		cfg,
		features,
		actest.FakeAccessControl{},
		permissions,
		quotatest.New(false, nil),
		&pluginstore.FakePluginStore{PluginList: []pluginstore.Plugin{
			{JSONData: plugins.JSONData{ID: datasources.DS_PROMETHEUS, Type: plugins.TypeDataSource, Name: "Prometheus"}},
			{JSONData: plugins.JSONData{ID: datasources.DS_MYSQL, Type: plugins.TypeDataSource, Name: "MySQL"}},
		}},
		&pluginfakes.FakePluginClient{},
		plugincontext.ProvideBaseService(cfg, pluginconfig.NewFakePluginRequestConfigProvider()),
		ProvideDataSourceRetriever(sqlStore, features),
	)
	require.NoError(t, err)
	return svc, secretsStore
}
