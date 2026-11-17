package user

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/apiserver/options"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgimpl"
	"github.com/grafana/grafana/pkg/services/quota/quotaimpl"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/services/team/teamimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/userimpl"
	"github.com/grafana/grafana/pkg/storage/legacysql"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

const crossOrgStackID = "42"

type orgDetails struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// TestIntegrationStackNamespaceDoesNotCopyOrgRole proves that a member of
// organization 1 cannot carry that membership's builtin role into another
// organization when the Kubernetes user service is enabled and a stack id
// maps every organization onto one namespace.
//
// The assertions are the safe behavior. They fail while signed-in user
// resolution copies the organization 1 role onto the organization id taken
// from the request.
//
// POST /api/dashboards/db, POST /api/org/users, and PATCH /api/org/users/{id}
// are not asserted here. With a stack namespace those handlers make a second
// Kubernetes call as the rewritten identity, and the namespace authorizer
// rejects that call before it writes. POST /api/orgs/{orgId}/users does write,
// because the user lookup still runs as the caller's real organization.
func TestIntegrationStackNamespaceDoesNotCopyOrgRole(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := startStackUsersServer(t)
	require.Equal(t, crossOrgStackID, helper.GetEnv().Cfg.StackID)

	otherOrgID := helper.OrgB.OrgID
	require.NotEqual(t, int64(1), otherOrgID)
	require.Equal(t, int64(1), helper.Org1.OrgID)

	usersAPI := do(t, helper, helper.Org1.Admin, apis.RequestParams{
		Method: http.MethodGet,
		Path:   "/apis/iam.grafana.app/v0alpha1/namespaces/stacks-" + crossOrgStackID + "/users",
	})
	require.Equal(t, http.StatusOK, usersAPI.Response.StatusCode, "kubernetes user service is not serving the stack namespace: %s", usersAPI.Body)

	const otherOrgDatasource = "other-org-datasource"
	const stolenDatasource = "stolen-org-datasource"
	const stolenOrgName = "stolen-org-name"

	createDatasource(t, helper, helper.OrgB.Admin, otherOrgDatasource)
	orgAdminAuth := createOrgOneAdmin(t, helper)

	// Same-organization requests keep working, so a later denial is not a broken login.
	ownOrg := getOrg(t, helper, helper.Org1.Viewer, apis.RequestParams{Path: "/api/org"})
	require.Equal(t, http.StatusOK, ownOrg.Response.StatusCode, "body: %s", ownOrg.Body)
	require.Equal(t, helper.Org1.OrgID, ownOrg.Result.ID)

	t.Run("header query and target query do not select another organization", func(t *testing.T) {
		selectors := []apis.RequestParams{
			{
				Path: "/api/org",
				Headers: map[string]string{
					"X-Grafana-Org-Id": strconv.FormatInt(otherOrgID, 10),
				},
			},
			{Path: "/api/org?orgId=" + strconv.FormatInt(otherOrgID, 10)},
			{Path: "/api/org?targetOrgId=" + strconv.FormatInt(otherOrgID, 10)},
		}
		for _, sel := range selectors {
			t.Run(sel.Path, func(t *testing.T) {
				rsp := getOrg(t, helper, helper.Org1.Viewer, sel)
				if rsp.Result != nil {
					require.NotEqual(t, otherOrgID, rsp.Result.ID, "viewer of org 1 read another org: %s", rsp.Body)
				}
				require.NotContains(t, string(rsp.Body), `"name":"OrgB"`)
				require.NotContains(t, string(rsp.Body), fmt.Sprintf(`"id":%d`, otherOrgID))
			})
		}
	})

	t.Run("org 1 viewer cannot read another organization's datasources", func(t *testing.T) {
		rsp := do(t, helper, helper.Org1.Viewer, apis.RequestParams{
			Method: http.MethodGet,
			Path:   "/api/datasources",
			Headers: map[string]string{
				"X-Grafana-Org-Id": strconv.FormatInt(otherOrgID, 10),
			},
		})
		require.NotContains(t, string(rsp.Body), otherOrgDatasource, "status %d body %s", rsp.Response.StatusCode, rsp.Body)
	})

	t.Run("org 1 admin cannot create a datasource in another organization", func(t *testing.T) {
		rsp := doAuth(t, helper, orgAdminAuth, apis.RequestParams{
			Method: http.MethodPost,
			Path:   "/api/datasources",
			Headers: map[string]string{
				"X-Grafana-Org-Id": strconv.FormatInt(otherOrgID, 10),
			},
			Body: []byte(`{"name":"` + stolenDatasource + `","type":"prometheus","access":"proxy","url":"http://example.com"}`),
		})
		require.NotEqual(t, http.StatusOK, rsp.Response.StatusCode, "body: %s", rsp.Body)
		require.Equal(t, int64(0), countRows(t, helper, "SELECT COUNT(*) FROM data_source WHERE org_id = ? AND name = ?", otherOrgID, stolenDatasource))
	})

	t.Run("org 1 admin cannot rename another organization", func(t *testing.T) {
		rsp := doAuth(t, helper, orgAdminAuth, apis.RequestParams{
			Method: http.MethodPut,
			Path:   "/api/org",
			Headers: map[string]string{
				"X-Grafana-Org-Id": strconv.FormatInt(otherOrgID, 10),
			},
			Body: []byte(`{"name":"` + stolenOrgName + `"}`),
		})
		require.NotEqual(t, http.StatusOK, rsp.Response.StatusCode, "body: %s", rsp.Body)
		require.Equal(t, "OrgB", orgName(t, helper, otherOrgID))
	})

	t.Run("url org id does not grant the organization 1 role", func(t *testing.T) {
		// /api/orgs/{orgId} resolves the caller again for the organization in the path.
		t.Run("list users", func(t *testing.T) {
			rsp := doAuth(t, helper, orgAdminAuth, apis.RequestParams{
				Method: http.MethodGet,
				Path:   fmt.Sprintf("/api/orgs/%d/users", otherOrgID),
			})
			require.NotEqual(t, http.StatusOK, rsp.Response.StatusCode, "body: %s", rsp.Body)
			require.NotContains(t, string(rsp.Body), `"login":"admin2-org-2"`)
		})

		t.Run("add user", func(t *testing.T) {
			added := doAuth(t, helper, orgAdminAuth, apis.RequestParams{
				Method: http.MethodPost,
				Path:   fmt.Sprintf("/api/orgs/%d/users", otherOrgID),
				Body:   []byte(`{"loginOrEmail":"viewer","role":"Editor"}`),
			})
			require.NotEqual(t, http.StatusOK, added.Response.StatusCode, "body: %s", added.Body)
			require.Equal(t, int64(0), countRows(t, helper, `SELECT COUNT(*) FROM org_user WHERE org_id = ? AND user_id = (SELECT id FROM `+"`user`"+` WHERE login = ?)`, otherOrgID, "viewer"))
		})

		t.Run("rename", func(t *testing.T) {
			renamed := doAuth(t, helper, orgAdminAuth, apis.RequestParams{
				Method: http.MethodPut,
				Path:   fmt.Sprintf("/api/orgs/%d", otherOrgID),
				Body:   []byte(`{"name":"url-stolen-org-name"}`),
			})
			require.NotEqual(t, http.StatusOK, renamed.Response.StatusCode, "body: %s", renamed.Body)
			require.NotEqual(t, "url-stolen-org-name", orgName(t, helper, otherOrgID))
		})
	})
}

func startStackUsersServer(t *testing.T) *apis.K8sTestHelper {
	t.Helper()

	opts := testinfra.GrafanaOpts{
		AppModeProduction:      false,
		DisableAnonymous:       true,
		RBACSingleOrganization: true,
		APIServerStorageType:   options.StorageTypeUnified,
		EnableFeatureToggles: []string{
			featuremgmt.FlagGrafanaAPIServerWithExperimentalAPIs,
			featuremgmt.FlagKubernetesUsersApi,
			featuremgmt.FlagKubernetesUsersRedirect,
		},
	}
	grafDir, cfgPath := testinfra.CreateGrafDir(t, opts)
	// Every organization id is formatted as this one stack namespace.
	cfg, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	cfg = append(cfg, []byte("\n[environment]\nstack_id = "+crossOrgStackID+"\n")...)
	require.NoError(t, os.WriteFile(cfgPath, cfg, 0o600))

	opts.Dir = grafDir
	opts.DirPath = cfgPath
	return apis.NewK8sTestHelperWithOpts(t, apis.K8sTestHelperOpts{GrafanaOpts: opts})
}

func do(t *testing.T, helper *apis.K8sTestHelper, user apis.User, params apis.RequestParams) apis.K8sResponse[map[string]any] {
	t.Helper()
	params.User = user
	if params.Method == "" {
		params.Method = http.MethodGet
	}
	return apis.DoRequest(helper, params, &map[string]any{})
}

func doAuth(t *testing.T, helper *apis.K8sTestHelper, authorization string, params apis.RequestParams) apis.K8sResponse[map[string]any] {
	t.Helper()
	if params.Headers == nil {
		params.Headers = map[string]string{}
	}
	params.Headers["Authorization"] = authorization
	if params.Method == "" {
		params.Method = http.MethodGet
	}
	return apis.DoRequest(helper, params, &map[string]any{})
}

func getOrg(t *testing.T, helper *apis.K8sTestHelper, user apis.User, params apis.RequestParams) apis.K8sResponse[orgDetails] {
	t.Helper()
	params.User = user
	if params.Method == "" {
		params.Method = http.MethodGet
	}
	return apis.DoRequest(helper, params, &orgDetails{})
}

func createDatasource(t *testing.T, helper *apis.K8sTestHelper, user apis.User, name string) {
	t.Helper()
	rsp := do(t, helper, user, apis.RequestParams{
		Method: http.MethodPost,
		Path:   "/api/datasources",
		Body:   []byte(`{"name":"` + name + `","type":"prometheus","access":"proxy","url":"http://example.com"}`),
	})
	require.Equal(t, http.StatusOK, rsp.Response.StatusCode, "create datasource %s: %s", name, rsp.Body)
}

// createOrgOneAdmin creates an organization 1 admin who is not a server admin
// and is not a member of any other organization. The returned value is the
// Authorization header for that user. The user is inserted through the legacy
// store so the password basic auth reads is actually stored; the Kubernetes
// user create path does not persist passwords.
func createOrgOneAdmin(t *testing.T, helper *apis.K8sTestHelper) string {
	t.Helper()

	env := helper.GetEnv()
	cfgProvider, err := configprovider.ProvideService(env.Cfg)
	require.NoError(t, err)
	sql := legacysql.NewDatabaseProvider(env.SQLStore)
	quotaService := quotaimpl.ProvideService(context.Background(), sql, cfgProvider)
	orgSvc, err := orgimpl.ProvideService(sql, env.Cfg, quotaService)
	require.NoError(t, err)
	teamSvc, err := teamimpl.NewLegacyService(sql, tracing.NewNoopTracerService())
	require.NoError(t, err)
	userSvc, err := userimpl.NewLegacyService(
		sql, orgSvc, env.Cfg, teamSvc, localcache.ProvideService(), tracing.NewNoopTracerService(),
		quotaService, supportbundlestest.NewFakeBundleService(),
	)
	require.NoError(t, err)

	_, err = userSvc.Create(context.Background(), &user.CreateUserCommand{
		Login:          "org-one-admin",
		Email:          "org-one-admin@example.com",
		Name:           "Org One Admin",
		Password:       "placeholder",
		OrgID:          1,
		DefaultOrgRole: string(org.RoleAdmin),
	})
	require.NoError(t, err)

	authz := "Basic " + base64.StdEncoding.EncodeToString([]byte("org-one-admin:placeholder"))
	own := doAuth(t, helper, authz, apis.RequestParams{
		Method: http.MethodPost,
		Path:   "/api/datasources",
		Body:   []byte(`{"name":"org1-admin-datasource","type":"prometheus","access":"proxy","url":"http://example.com"}`),
	})
	require.Equal(t, http.StatusOK, own.Response.StatusCode, "org 1 admin cannot create a datasource in their own org: %s", own.Body)
	return authz
}

func countRows(t *testing.T, helper *apis.K8sTestHelper, query string, args ...any) int64 {
	t.Helper()
	var n int64
	err := helper.GetEnv().SQLStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL(query, args...).Get(&n)
		return err
	})
	require.NoError(t, err)
	return n
}

func orgName(t *testing.T, helper *apis.K8sTestHelper, orgID int64) string {
	t.Helper()
	var name string
	err := helper.GetEnv().SQLStore.WithDbSession(context.Background(), func(sess *db.Session) error {
		_, err := sess.SQL("SELECT name FROM org WHERE id = ?", orgID).Get(&name)
		return err
	})
	require.NoError(t, err)
	return name
}
