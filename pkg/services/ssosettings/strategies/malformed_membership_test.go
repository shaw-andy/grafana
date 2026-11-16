package strategies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	"github.com/grafana/grafana/pkg/services/ssosettings/ssosettingstests"
	"github.com/grafana/grafana/pkg/setting"
)

func TestMalformedOAuthMembership_IniTeamListDoesNotAdmitOutsider(t *testing.T) {
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

	raw, err := ini.Load([]byte(fmt.Sprintf(`
[auth.generic_oauth]
enabled = true
allow_sign_up = true
skip_org_role_sync = true
client_id = client-id
auth_url = https://idp.example/authorize
token_url = https://idp.example/token
api_url = %s/userinfo
teams_url = %s/teams
team_ids_attribute_path = teams
team_ids = [team-a, team-b]
allowed_organizations = [org-a, org-b]
`, srv.URL, srv.URL)))
	require.NoError(t, err)

	cfg := setting.NewCfg()
	cfg.Raw = raw
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = 1
	cfg.AutoAssignOrgRole = "Viewer"
	strategy := NewOAuthStrategy(staticConfigProvider(t, cfg))
	loaded, err := strategy.GetProviderConfig(context.Background(), "generic_oauth")
	require.NoError(t, err)
	require.Equal(t, "[team-a, team-b]", loaded["team_ids"])
	require.Equal(t, "[org-a, org-b]", loaded["allowed_organizations"])
	require.Equal(t, true, loaded["allow_sign_up"])

	info, err := connectors.CreateOAuthInfoFromKeyValues(loaded)
	if err != nil {
		return
	}
	provider, err := connectors.NewGenericOAuthProvider(
		context.Background(),
		info,
		staticConfigProvider(t, cfg),
		connectors.ProvideOrgRoleMapper(staticConfigProvider(t, cfg), &orgtest.FakeOrgService{}),
		ssosettingstests.NewFakeService(),
		featuremgmt.WithFeatures(),
		nil,
	)
	if err != nil {
		return
	}
	require.True(t, provider.IsSignupAllowed())
	userInfo, err := provider.UserInfo(context.Background(), srv.Client(), &oauth2.Token{})
	if err == nil {
		t.Fatalf("ini team_ids and allowed_organizations were treated as no restriction: %+v", userInfo)
	}
}
