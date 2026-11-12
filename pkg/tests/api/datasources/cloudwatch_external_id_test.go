package datasources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/server"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// stackExternalIDPlaceholder is a stand-in for the instance AWS external ID
// (the [aws] external_id setting). It is not a real credential.
const stackExternalIDPlaceholder = "stack-external-id-placeholder"

// perDatasourceExternalIDPlaceholder is a stand-in stored on one CloudWatch
// datasource. It is not a real credential.
const perDatasourceExternalIDPlaceholder = "per-datasource-external-id-placeholder"

// TestIntegrationCloudWatchExternalIDResourceAuthorization exercises
// GET /api/datasources/uid/:uid/resources/external-id and the legacy numeric
// route. Callers who can query a datasource but cannot edit that datasource
// must not receive the instance external ID. Callers who can edit that
// datasource still receive the instance external ID, which the CloudWatch
// config editor treats as the stack ID (including when the datasource opts
// into a per-datasource ID).
func TestIntegrationCloudWatchExternalIDResourceAuthorization(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	dir, cfgPath := testinfra.CreateGrafDir(t, testinfra.GrafanaOpts{
		DisableAnonymous: true,
		// Registers /api/datasources/:id/resources/*, the same CallDatasourceResource
		// path as the UID route, behind this flag.
		EnableFeatureToggles: []string{"datasourceLegacyIdApi"},
	})
	setAWSExternalID(t, cfgPath, stackExternalIDPlaceholder)

	addr, env := testinfra.StartGrafanaEnv(t, dir, cfgPath)
	require.Equal(t, stackExternalIDPlaceholder, env.Cfg.AWSExternalId)

	ctx := context.Background()
	stackDS := addCloudWatchDatasource(t, ctx, env, "cwextstack", "CloudWatch stack external id", simplejson.NewFromAny(map[string]any{
		"authType": "grafana_assume_role",
	}))
	perDSDS := addCloudWatchDatasource(t, ctx, env, "cwextperds", "CloudWatch per datasource external id", simplejson.NewFromAny(map[string]any{
		"authType":                   "grafana_assume_role",
		"usePerDatasourceExternalId": true,
		"grafanaExternalId":          perDatasourceExternalIDPlaceholder,
	}))
	otherDS := addCloudWatchDatasource(t, ctx, env, "cwextother", "CloudWatch other datasource", simplejson.NewFromAny(map[string]any{
		"authType": "default",
	}))

	const password = "testpass"
	createOrgUser(t, env, "cw-viewer", password, org.RoleViewer)
	createOrgUser(t, env, "cw-editor", password, org.RoleEditor)

	// Query permission on a different datasource. The resource route evaluates
	// datasources:query with no UID, so this must not authorize the target.
	createUserWithPermissions(t, ctx, env.SQLStore, env.Cfg, addr, "cw-query-other", []resourcepermissions.SetResourcePermissionCommand{{
		Actions:           []string{datasources.ActionQuery},
		Resource:          "datasources",
		ResourceAttribute: "uid",
		ResourceID:        otherDS.UID,
	}})
	// Can edit a different datasource and query the target. Edit permission on
	// the other object must not authorize reading this datasource's external ID.
	createUserWithPermissions(t, ctx, env.SQLStore, env.Cfg, addr, "cw-write-other", []resourcepermissions.SetResourcePermissionCommand{
		{
			Actions:           []string{datasources.ActionWrite, datasources.ActionQuery},
			Resource:          "datasources",
			ResourceAttribute: "uid",
			ResourceID:        otherDS.UID,
		},
		{
			Actions:           []string{datasources.ActionQuery},
			Resource:          "datasources",
			ResourceAttribute: "uid",
			ResourceID:        stackDS.UID,
		},
	})
	// Can edit the target datasource. This is the caller the config screen uses.
	createUserWithPermissions(t, ctx, env.SQLStore, env.Cfg, addr, "cw-write-target", []resourcepermissions.SetResourcePermissionCommand{{
		Actions:           []string{datasources.ActionWrite, datasources.ActionQuery},
		Resource:          "datasources",
		ResourceAttribute: "uid",
		ResourceID:        stackDS.UID,
	}})
	createUserWithPermissions(t, ctx, env.SQLStore, env.Cfg, addr, "cw-write-perds", []resourcepermissions.SetResourcePermissionCommand{{
		Actions:           []string{datasources.ActionWrite, datasources.ActionQuery},
		Resource:          "datasources",
		ResourceAttribute: "uid",
		ResourceID:        perDSDS.UID,
	}})

	uidURL := func(uid string) string {
		return fmt.Sprintf("http://%s/api/datasources/uid/%s/resources/external-id", addr, uid)
	}
	idURL := fmt.Sprintf("http://%s/api/datasources/%d/resources/external-id", addr, stackDS.ID)

	t.Run("editor of the datasource receives the stack external id", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			user string
			url  string
		}{
			{name: "org admin uid route", user: "admin", url: uidURL(stackDS.UID)},
			{name: "write on that uid", user: "cw-write-target", url: uidURL(stackDS.UID)},
			{name: "org admin legacy id route", user: "admin", url: idURL},
		} {
			t.Run(tc.name, func(t *testing.T) {
				status, body := externalIDRequest(t, http.MethodGet, tc.url, tc.user, passwordFor(tc.user))
				require.Equal(t, http.StatusOK, status, body)
				require.Equal(t, stackExternalIDPlaceholder, externalIDFromBody(t, body))
			})
		}
	})

	t.Run("editor of a per-datasource cloudwatch datasource still receives the stack external id", func(t *testing.T) {
		for _, user := range []string{"admin", "cw-write-perds"} {
			t.Run(user, func(t *testing.T) {
				status, body := externalIDRequest(t, http.MethodGet, uidURL(perDSDS.UID), user, passwordFor(user))
				require.Equal(t, http.StatusOK, status, body)
				require.Equal(t, stackExternalIDPlaceholder, externalIDFromBody(t, body))
			})
		}
	})

	t.Run("query without edit on that datasource does not receive the external id", func(t *testing.T) {
		cases := []struct {
			name string
			user string
			url  string
		}{
			{name: "viewer uid route", user: "cw-viewer", url: uidURL(stackDS.UID)},
			{name: "viewer per-datasource uid route", user: "cw-viewer", url: uidURL(perDSDS.UID)},
			{name: "editor org role uid route", user: "cw-editor", url: uidURL(stackDS.UID)},
			{name: "query scoped to another datasource", user: "cw-query-other", url: uidURL(stackDS.UID)},
			{name: "write scoped to another datasource", user: "cw-write-other", url: uidURL(stackDS.UID)},
			{name: "viewer legacy id route", user: "cw-viewer", url: idURL},
			{name: "query scoped to another datasource legacy id route", user: "cw-query-other", url: idURL},
			{name: "write scoped to another datasource legacy id route", user: "cw-write-other", url: idURL},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				status, body := externalIDRequest(t, http.MethodGet, tc.url, tc.user, passwordFor(tc.user))
				require.Equalf(t, http.StatusForbidden, status, "body: %s", body)
				requireExternalIDAbsent(t, body)
			})
		}
	})

	t.Run("non-get and unauthenticated calls do not return the external id", func(t *testing.T) {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				status, body := externalIDRequest(t, method, uidURL(stackDS.UID), "cw-viewer", password)
				require.NotEqual(t, http.StatusOK, status, body)
				requireExternalIDAbsent(t, body)
			})
		}
		status, body := externalIDRequest(t, http.MethodGet, uidURL(stackDS.UID), "", "")
		require.NotEqual(t, http.StatusOK, status, body)
		requireExternalIDAbsent(t, body)
	})

	t.Run("plugin resource route without a datasource does not return the external id", func(t *testing.T) {
		pluginURL := fmt.Sprintf("http://%s/api/plugins/cloudwatch/resources/external-id", addr)
		for _, user := range []string{"admin", "cw-viewer"} {
			t.Run(user, func(t *testing.T) {
				status, body := externalIDRequest(t, http.MethodGet, pluginURL, user, passwordFor(user))
				require.NotEqual(t, http.StatusOK, status, body)
				requireExternalIDAbsent(t, body)
			})
		}
	})
}

func passwordFor(login string) string {
	if login == "admin" {
		return "admin"
	}
	return "testpass"
}

func setAWSExternalID(t *testing.T, cfgPath, externalID string) {
	t.Helper()
	file, err := ini.Load(cfgPath)
	require.NoError(t, err)
	_, err = file.Section("aws").NewKey("external_id", externalID)
	require.NoError(t, err)
	require.NoError(t, file.SaveTo(cfgPath))
}

func addCloudWatchDatasource(t *testing.T, ctx context.Context, env *server.TestEnv, uid, name string, jsonData *simplejson.Json) *datasources.DataSource {
	t.Helper()
	ds, err := env.Server.HTTPServer.DataSourcesService.AddDataSource(ctx, &datasources.AddDataSourceCommand{
		OrgID:    1,
		Access:   datasources.DS_ACCESS_PROXY,
		Name:     name,
		Type:     "cloudwatch",
		UID:      uid,
		URL:      "https://monitoring.us-east-1.amazonaws.com",
		JsonData: jsonData,
	})
	require.NoError(t, err)
	require.NotZero(t, ds.ID)
	return ds
}

func createOrgUser(t *testing.T, env *server.TestEnv, login, password string, role org.RoleType) {
	t.Helper()
	tests.CreateUser(t, env.SQLStore, env.Cfg, user.CreateUserCommand{
		DefaultOrgRole: string(role),
		Password:       user.Password(password),
		Login:          login,
		OrgID:          1,
	})
}

func externalIDRequest(t *testing.T, method, rawURL, login, password string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	require.NoError(t, err)
	if login != "" {
		req.SetBasicAuth(login, password)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec
	require.NoError(t, err)
	defer func() {
		require.NoError(t, resp.Body.Close())
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func externalIDFromBody(t *testing.T, body string) string {
	t.Helper()
	var payload struct {
		ExternalID string `json:"externalId"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &payload), body)
	return payload.ExternalID
}

func requireExternalIDAbsent(t *testing.T, body string) {
	t.Helper()
	require.NotContains(t, body, stackExternalIDPlaceholder)
	require.NotContains(t, body, perDatasourceExternalIDPlaceholder)
}
