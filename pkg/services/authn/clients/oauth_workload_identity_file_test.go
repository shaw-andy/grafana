package clients

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/login/social/connectors"
	"github.com/grafana/grafana/pkg/login/social/socialtest"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

// localFileMarker is the contents of a file the SSO settings writer must not be able to
// exfiltrate. It is a placeholder, not a credential.
const localFileMarker = "LOCAL_FILE_DISCLOSURE_MARKER"

func TestOAuthAuthenticateDoesNotPostLocalFileToWorkloadIdentityTokenURL(t *testing.T) {
	providers := []string{
		social.AzureADProviderName,
		social.GenericOAuthProviderName,
		social.OktaProviderName,
	}
	kinds := []string{
		"absolute_symlink",
		"parent_segment",
		"relative_symlink_after_check",
	}

	for _, provider := range providers {
		for _, kind := range kinds {
			t.Run(provider+"/"+kind, func(t *testing.T) {
				configuredPath, retarget := workloadIdentityDisclosurePaths(t, kind)
				bodies := &lockedBodies{}
				tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					bodies.add(string(body))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				}))
				t.Cleanup(tokenServer.Close)

				settings := workloadIdentitySettings(provider, configuredPath, tokenServer.URL)
				cfg := setting.NewCfg()
				cfg.SecretKey = "placeholder-signing-key"
				cfg.AppURL = "http://localhost:3000/"

				validator := newWorkloadIdentityConnector(t, provider, social.NewOAuthInfo(), cfg)
				validateErr := validator.Validate(context.Background(), ssoModels.SSOSettings{
					Provider: provider,
					Settings: settings,
				}, ssoModels.SSOSettings{Settings: map[string]any{}}, &user.SignedInUser{IsGrafanaAdmin: false})
				if validateErr != nil {
					require.Empty(t, bodies.snapshot(), "token endpoint was called before the settings were rejected")
					return
				}

				// The path is checked by validation above. Replacing it with a symlink to another
				// file before the login callback reads it must not disclose that file. A second
				// lookup of the same path string, including os.ReadFile following the link, still fails this test.
				retarget()

				info, err := connectors.CreateOAuthInfoFromKeyValues(settings)
				require.NoError(t, err)
				if info.Extra == nil {
					info.Extra = map[string]string{}
				}
				connector := newWorkloadIdentityConnector(t, provider, info, cfg)

				state := "placeholder-oauth-state"
				req, err := http.NewRequest(http.MethodGet, tokenServer.URL+"/login/"+provider+"?code=placeholder-code&state="+url.QueryEscape(state), nil)
				require.NoError(t, err)
				req.AddCookie(&http.Cookie{
					Name:  oauthStateCookieName,
					Value: hashOAuthState(state, cfg.SecretKey, info.ClientSecret),
				})

				client := ProvideOAuth(
					authn.ClientWithPrefix(provider),
					testConfigProvider(t, cfg),
					nil,
					&socialtest.FakeSocialService{
						ExpectedAuthInfoProvider: info,
						ExpectedConnector:        connector,
						ExpectedHttpClient:       tokenServer.Client(),
					},
					setting.ProvideProvider(setting.NewCfg()),
					featuremgmt.WithFeatures(),
					tracing.InitializeTracerForTest(),
				)

				_, authErr := client.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
				posted := strings.Join(bodies.snapshot(), "\n")
				require.NotContains(t, posted, localFileMarker)
				if len(bodies.snapshot()) == 0 {
					require.Error(t, authErr)
					require.NotErrorIs(t, authErr, errOAuthMissingState)
					require.NotErrorIs(t, authErr, errOAuthInvalidState)
					require.NotErrorIs(t, authErr, errOAuthMissingPKCE)
					require.NotErrorIs(t, authErr, errOAuthClientDisabled)
				}
			})
		}
	}
}

func newWorkloadIdentityConnector(t *testing.T, provider string, info *social.OAuthInfo, cfg *setting.Cfg) interface {
	social.SocialConnector
	Validate(ctx context.Context, newSettings ssoModels.SSOSettings, oldSettings ssoModels.SSOSettings, requester identity.Requester) error
} {
	t.Helper()
	cfgProvider := testConfigProvider(t, cfg)
	mapper := connectors.ProvideOrgRoleMapper(cfgProvider, orgtest.NewOrgServiceFake())
	features := featuremgmt.WithFeatures()
	ctx := context.Background()
	switch provider {
	case social.AzureADProviderName:
		connector, err := connectors.NewAzureADProvider(ctx, info, cfgProvider, mapper, nil, features, nil)
		require.NoError(t, err)
		return connector
	case social.GenericOAuthProviderName:
		connector, err := connectors.NewGenericOAuthProvider(ctx, info, cfgProvider, mapper, nil, features, nil)
		require.NoError(t, err)
		return connector
	case social.OktaProviderName:
		connector, err := connectors.NewOktaProvider(ctx, info, cfgProvider, mapper, nil, features, nil)
		require.NoError(t, err)
		return connector
	default:
		t.Fatalf("unsupported provider %s", provider)
		return nil
	}
}

func workloadIdentitySettings(provider, tokenFile, tokenServerURL string) map[string]any {
	settings := map[string]any{
		"enabled":                      true,
		"allow_sign_up":                true,
		"client_id":                    "client-id",
		"client_authentication":        social.WorkloadIdentity,
		"workload_identity_token_file": tokenFile,
		"auth_url":                     tokenServerURL + "/authorize",
		"token_url":                    tokenServerURL + "/token",
		"use_pkce":                     false,
		"scopes":                       "openid",
	}
	if provider == social.OktaProviderName {
		settings["api_url"] = tokenServerURL + "/userinfo"
	}
	return settings
}

func workloadIdentityDisclosurePaths(t *testing.T, kind string) (string, func()) {
	t.Helper()
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "private-file")
	require.NoError(t, os.WriteFile(secretPath, []byte(localFileMarker), 0o600))

	switch kind {
	case "absolute_symlink":
		dir := t.TempDir()
		configuredPath := filepath.Join(dir, "workload-token")
		require.NoError(t, os.Symlink(secretPath, configuredPath))
		return configuredPath, func() {}
	case "parent_segment":
		dir := t.TempDir()
		nested := filepath.Join(dir, "nested")
		require.NoError(t, os.Mkdir(nested, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "private-file"), []byte(localFileMarker), 0o600))
		// Keep the parent-directory segment in the configured string. filepath.Join would clean it.
		return nested + "/../private-file", func() {}
	case "relative_symlink_after_check":
		relDir, err := os.MkdirTemp(".", "wi-file-test-")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.RemoveAll(relDir) })
		configuredPath := filepath.Join(relDir, "workload-token")
		require.NoError(t, os.WriteFile(configuredPath, []byte("benign-workload-token-placeholder"), 0o600))
		return configuredPath, func() {
			require.NoError(t, os.Remove(configuredPath))
			require.NoError(t, os.Symlink(secretPath, configuredPath))
		}
	default:
		t.Fatalf("unknown path kind %s", kind)
		return "", func() {}
	}
}

type lockedBodies struct {
	mu    sync.Mutex
	items []string
}

func (b *lockedBodies) add(body string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(b.items, body)
}

func (b *lockedBodies) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.items))
	copy(out, b.items)
	return out
}
