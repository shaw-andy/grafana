package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	strictDefaultOrgID int64 = 1
	strictLimitedOrgID int64 = 5
)

// These tests describe the required behavior when role_attribute_strict is on and
// org_mapping contains any invalid entry: the provider must not grant the token role
// in the default organization. They fail while that assignment still happens.

func TestOrgMappingStrictValidGenericOAuthKeepsMappedOrg(t *testing.T) {
	info, err := genericOAuthUserInfo(t, []string{"contractors:5:Viewer"}, []string{"contractors"}, true)
	require.NoError(t, err)
	require.Equal(t, map[int64]org.RoleType{strictLimitedOrgID: org.RoleAdmin}, info.OrgRoles)
}

func TestOrgMappingStrictDisabledKeepsValidLines(t *testing.T) {
	info, err := genericOAuthUserInfo(t, []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"}, []string{"contractors"}, false)
	require.NoError(t, err)
	require.Equal(t, map[int64]org.RoleType{strictLimitedOrgID: org.RoleAdmin}, info.OrgRoles)
}

func TestOrgMappingStrictInvalidGenericOAuth(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		orgMapping   []string
		externalOrgs []string
	}{
		{
			name:         "malformed sibling drops the valid line",
			orgMapping:   []string{"contractors:5:Viewer", "not-a-mapping"},
			externalOrgs: []string{"contractors"},
		},
		{
			name:         "missing role drops the valid line",
			orgMapping:   []string{"contractors:5:Viewer", "staff:5"},
			externalOrgs: []string{"contractors"},
		},
		{
			name:         "invalid role drops the valid line",
			orgMapping:   []string{"contractors:5:Viewer", "staff:5:SuperUser"},
			externalOrgs: []string{"contractors"},
		},
		{
			name:         "unresolved organization drops the valid line",
			orgMapping:   []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"},
			externalOrgs: []string{"contractors"},
		},
		{
			name:         "unmatched external org still receives the token role after a discarded mapping",
			orgMapping:   []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"},
			externalOrgs: []string{"intruders"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			info, err := genericOAuthUserInfo(t, tc.orgMapping, tc.externalOrgs, true)
			requireDiscardedMappingDoesNotGrantDefaultOrg(t, err, orgRolesOf(info))
		})
	}
}

func TestOrgMappingStrictInvalidGenericOAuthReload(t *testing.T) {
	cfg := strictMappingCfg()
	mapper := mustProvideOrgRoleMapper(t, cfg, strictOrgService())
	provider, err := NewGenericOAuthProvider(context.Background(), strictGenericInfo([]string{"contractors:5:Viewer"}, true), testConfigProvider(t, cfg), mapper, nil, featuremgmt.WithFeatures(), nil)
	require.NoError(t, err)

	before, err := provider.UserInfo(context.Background(), http.DefaultClient, genericToken(t, []string{"contractors"}))
	require.NoError(t, err)
	require.Equal(t, map[int64]org.RoleType{strictLimitedOrgID: org.RoleAdmin}, before.OrgRoles)

	reloadErr := provider.Reload(context.Background(), ssoModels.SSOSettings{Settings: map[string]any{
		"role_attribute_strict": true,
		"role_attribute_path":   "role",
		"org_attribute_path":    "orgs",
		"org_mapping":           []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"},
		"allow_sign_up":         true,
	}})

	after, userErr := provider.UserInfo(context.Background(), http.DefaultClient, genericToken(t, []string{"contractors"}))
	if reloadErr != nil && userErr == nil && after != nil && after.OrgRoles[strictDefaultOrgID] == "" && after.OrgRoles[strictLimitedOrgID] == org.RoleAdmin {
		return
	}
	requireDiscardedMappingDoesNotGrantDefaultOrg(t, userErr, orgRolesOf(after))
}

func TestOrgMappingStrictInvalidGitHub(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user/teams":
			require.NoError(t, json.NewEncoder(w).Encode([]map[string]any{{
				"id":           7,
				"slug":         "contractors",
				"html_url":     serverURL + "/teams/contractors",
				"organization": map[string]string{"login": "acme"},
			}}))
		case "/user":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"id":    1,
				"login": "attacker",
				"email": "attacker@example.com",
				"name":  "Attacker",
				"role":  "Admin",
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	cfg := strictMappingCfg()
	mapper := mustProvideOrgRoleMapper(t, cfg, strictOrgService())
	info := &social.OAuthInfo{
		ApiUrl:              server.URL + "/user",
		RoleAttributePath:   "role",
		RoleAttributeStrict: true,
		OrgMapping:          []string{"@acme/contractors:5:Viewer", "staff:RenamedOrg:Editor"},
		AllowSignup:         true,
	}
	provider, err := NewGitHubProvider(context.Background(), info, testConfigProvider(t, cfg), mapper, nil, featuremgmt.WithFeatures())
	require.NoError(t, err)

	userInfo, userErr := provider.UserInfo(context.Background(), server.Client(), &oauth2.Token{})
	requireDiscardedMappingDoesNotGrantDefaultOrg(t, userErr, orgRolesOf(userInfo))
}

func TestOrgMappingStrictInvalidGitLab(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "userinfo unavailable", http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := strictMappingCfg()
	mapper := mustProvideOrgRoleMapper(t, cfg, strictOrgService())
	info := &social.OAuthInfo{
		AuthUrl:             server.URL + "/oauth/authorize",
		RoleAttributePath:   "role",
		RoleAttributeStrict: true,
		OrgMapping:          []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"},
		AllowSignup:         true,
	}
	provider, err := NewGitLabProvider(context.Background(), info, testConfigProvider(t, cfg), mapper, nil, featuremgmt.WithFeatures(), nil)
	require.NoError(t, err)

	key, keyID := createTestRSAKey(t)
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": signJWT(t, key, keyID, map[string]any{
		"sub":                "user-1",
		"preferred_username": "attacker",
		"email":              "attacker@example.com",
		"email_verified":     true,
		"name":               "Attacker",
		"role":               "Admin",
		"groups_direct":      []string{"contractors"},
	})})

	userInfo, userErr := provider.UserInfo(context.Background(), server.Client(), token)
	requireDiscardedMappingDoesNotGrantDefaultOrg(t, userErr, orgRolesOf(userInfo))
}

func TestOrgMappingStrictInvalidGoogle(t *testing.T) {
	cfg := strictMappingCfg()
	mapper := mustProvideOrgRoleMapper(t, cfg, strictOrgService())
	info := &social.OAuthInfo{
		RoleAttributePath:   "role",
		RoleAttributeStrict: true,
		OrgMapping:          []string{"*:5:Viewer", "staff:RenamedOrg:Editor"},
		AllowSignup:         true,
		Extra:               map[string]string{},
	}
	provider, err := NewGoogleProvider(context.Background(), info, testConfigProvider(t, cfg), mapper, nil, featuremgmt.WithFeatures(), nil)
	require.NoError(t, err)

	key, keyID := createTestRSAKey(t)
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": signJWT(t, key, keyID, map[string]any{
		"sub":            "user-1",
		"email":          "attacker@example.com",
		"email_verified": true,
		"name":           "Attacker",
		"role":           "Admin",
	})})

	userInfo, userErr := provider.UserInfo(context.Background(), http.DefaultClient, token)
	requireDiscardedMappingDoesNotGrantDefaultOrg(t, userErr, orgRolesOf(userInfo))
}

func TestOrgMappingStrictInvalidOkta(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"email": "attacker@example.com",
			"name":  "Attacker",
			"role":  "Admin",
			"orgs":  []string{"contractors"},
		}))
	}))
	defer server.Close()

	cfg := strictMappingCfg()
	mapper := mustProvideOrgRoleMapper(t, cfg, strictOrgService())
	info := &social.OAuthInfo{
		ApiUrl:              server.URL,
		AuthUrl:             "https://example.test/oauth/authorize",
		TokenUrl:            "https://example.test/oauth/token",
		RoleAttributePath:   "role",
		OrgAttributePath:    "orgs",
		RoleAttributeStrict: true,
		OrgMapping:          []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"},
		AllowSignup:         true,
	}
	provider, err := NewOktaProvider(context.Background(), info, testConfigProvider(t, cfg), mapper, nil, featuremgmt.WithFeatures(), nil)
	require.NoError(t, err)

	key, keyID := createTestRSAKey(t)
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": signJWT(t, key, keyID, map[string]any{
		"sub":   "user-1",
		"email": "attacker@example.com",
		"name":  "Attacker",
	})})

	userInfo, userErr := provider.UserInfo(context.Background(), server.Client(), token)
	requireDiscardedMappingDoesNotGrantDefaultOrg(t, userErr, orgRolesOf(userInfo))
}

func TestOrgMappingStrictInvalidAzureAD(t *testing.T) {
	key, keyID := createTestRSAKey(t)
	jwks := createJWKSResponse(t, key, keyID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/discovery/v2.0/keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(jwks)
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := strictMappingCfg()
	mapper := mustProvideOrgRoleMapper(t, cfg, strictOrgService())
	info := &social.OAuthInfo{
		AuthUrl:             server.URL + "/oauth2/v2.0/authorize",
		TokenUrl:            server.URL + "/oauth2/v2.0/token",
		ClientId:            "test-client",
		RoleAttributeStrict: true,
		OrgMapping:          []string{"contractors:5:Viewer", "staff:RenamedOrg:Editor"},
		AllowSignup:         true,
		Extra:               map[string]string{},
	}
	provider, err := NewAzureADProvider(context.Background(), info, testConfigProvider(t, cfg), mapper, nil, featuremgmt.WithFeatures(), nil)
	require.NoError(t, err)

	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": signJWT(t, key, keyID, map[string]any{
		"aud":    "test-client",
		"email":  "attacker@example.com",
		"name":   "Attacker",
		"oid":    "oid-1",
		"ver":    "2.0",
		"groups": []string{"contractors"},
		"roles":  []string{"Admin"},
	})})

	userInfo, userErr := provider.UserInfo(context.Background(), server.Client(), token)
	requireDiscardedMappingDoesNotGrantDefaultOrg(t, userErr, orgRolesOf(userInfo))
}

func strictMappingCfg() *setting.Cfg {
	cfg := setting.NewCfg()
	cfg.AutoAssignOrg = true
	cfg.AutoAssignOrgId = int(strictDefaultOrgID)
	cfg.AutoAssignOrgRole = string(org.RoleViewer)
	return cfg
}

func strictOrgService() *orgtest.FakeOrgService {
	return &orgtest.FakeOrgService{
		ExpectedOrgs:  []*org.OrgDTO{{ID: strictLimitedOrgID, Name: "Limited"}},
		ExpectedError: org.ErrOrgNotFound,
	}
}

func strictGenericInfo(orgMapping []string, strict bool) *social.OAuthInfo {
	return &social.OAuthInfo{
		RoleAttributePath:   "role",
		OrgAttributePath:    "orgs",
		RoleAttributeStrict: strict,
		OrgMapping:          orgMapping,
		AllowSignup:         true,
	}
}

func genericToken(t *testing.T, externalOrgs []string) *oauth2.Token {
	t.Helper()
	key, keyID := createTestRSAKey(t)
	return (&oauth2.Token{}).WithExtra(map[string]any{
		"id_token": signJWT(t, key, keyID, map[string]any{
			"sub":   "user-1",
			"email": "attacker@example.com",
			"role":  "Admin",
			"orgs":  externalOrgs,
		}),
	})
}

func genericOAuthUserInfo(t *testing.T, orgMapping []string, externalOrgs []string, strict bool) (*social.BasicUserInfo, error) {
	t.Helper()
	cfg := strictMappingCfg()
	mapper := mustProvideOrgRoleMapper(t, cfg, strictOrgService())
	provider, err := NewGenericOAuthProvider(context.Background(), strictGenericInfo(orgMapping, strict), testConfigProvider(t, cfg), mapper, nil, featuremgmt.WithFeatures(), nil)
	if err != nil {
		return nil, err
	}
	return provider.UserInfo(context.Background(), http.DefaultClient, genericToken(t, externalOrgs))
}

func orgRolesOf(info *social.BasicUserInfo) map[int64]org.RoleType {
	if info == nil {
		return nil
	}
	return info.OrgRoles
}

func requireDiscardedMappingDoesNotGrantDefaultOrg(t *testing.T, err error, roles map[int64]org.RoleType) {
	t.Helper()
	if role, ok := roles[strictDefaultOrgID]; ok {
		t.Fatalf("granted role %s in the default organization (%d): %v", role, strictDefaultOrgID, roles)
	}
	if err == nil {
		t.Fatalf("login succeeded after an invalid org_mapping with role_attribute_strict enabled; org roles=%v", roles)
	}
}
