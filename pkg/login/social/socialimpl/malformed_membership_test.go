package socialimpl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/infra/usagestats"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/services/supportbundles/supportbundlestest"
	"github.com/grafana/grafana/pkg/setting"
)

func TestMalformedOAuthMembership_GetConnectorDoesNotAdmitOutsider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/userinfo":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"sub":   "outsider",
				"email": "outsider@example.com",
				"login": "outsider",
				"name":  "Outsider",
			}))
		case "/teams":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"teams": []string{"other-team"}}))
		case "/userinfo/orgs":
			require.NoError(t, json.NewEncoder(w).Encode([]map[string]string{{"login": "other-org"}}))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	settings := &models.SSOSettings{
		Provider: social.GenericOAuthProviderName,
		Settings: map[string]any{
			"enabled":                 true,
			"allow_sign_up":           true,
			"skip_org_role_sync":      true,
			"client_id":               "client-id",
			"auth_url":                "https://idp.example/authorize",
			"token_url":               "https://idp.example/token",
			"api_url":                 srv.URL + "/userinfo",
			"teams_url":               srv.URL + "/teams",
			"team_ids_attribute_path": "teams",
			"team_ids":                "[team-a, team-b]",
			"allowed_organizations":   "[org-a, org-b]",
		},
	}

	settingsSvc := ssosettingstests.NewFakeService()
	settingsSvc.ListFn = func(context.Context) ([]*models.SSOSettings, error) {
		return []*models.SSOSettings{settings}, nil
	}
	settingsSvc.GetForProviderFn = func(_ context.Context, provider string) (*models.SSOSettings, error) {
		require.Equal(t, social.GenericOAuthProviderName, provider)
		return settings, nil
	}

	cfg := setting.NewCfg()
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = "Viewer"
	svc := ProvideService(
		context.Background(),
		mustConfigProvider(t, cfg),
		featuremgmt.WithFeatures(),
		&usagestats.UsageStatsMock{},
		supportbundlestest.NewFakeBundleService(),
		remotecache.NewFakeStore(t),
		nil,
		settingsSvc,
	)

	connector, err := svc.GetConnector(context.Background(), social.GenericOAuthProviderName)
	if err != nil {
		return
	}
	require.True(t, connector.IsSignupAllowed())
	userInfo, err := connector.UserInfo(context.Background(), srv.Client(), &oauth2.Token{})
	if err == nil {
		t.Fatalf("GetConnector admitted an identity-provider user outside the configured teams and organizations: %+v", userInfo)
	}
}
