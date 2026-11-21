package connectors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	ssoModels "github.com/grafana/grafana/pkg/services/ssosettings/models"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

func TestAzureADRefreshDoesNotPostLocalFileToWorkloadIdentityTokenURL(t *testing.T) {
	kinds := []string{
		"absolute_symlink",
		"parent_segment",
		"relative_symlink_after_check",
	}

	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			configuredPath, retarget := azureWorkloadIdentityDisclosurePaths(t, kind)
			bodies := &azureLockedBodies{}
			tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				bodies.add(string(body))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			}))
			t.Cleanup(tokenServer.Close)

			settings := map[string]any{
				"enabled":                      true,
				"allow_sign_up":                true,
				"client_id":                    "client-id",
				"client_authentication":        social.WorkloadIdentity,
				"workload_identity_token_file": configuredPath,
				"auth_url":                     tokenServer.URL + "/authorize",
				"token_url":                    tokenServer.URL + "/token",
				"use_refresh_token":            true,
				"scopes":                       "openid",
			}
			cfg := setting.NewCfg()
			cfg.AppURL = "http://localhost:3000/"
			validator := mustNewAzureADProvider(t, social.NewOAuthInfo(), cfg, mustProvideOrgRoleMapper(t, cfg, orgtest.NewOrgServiceFake()), nil, featuremgmt.WithFeatures(), nil)
			validateErr := validator.Validate(context.Background(), ssoModels.SSOSettings{
				Provider: social.AzureADProviderName,
				Settings: settings,
			}, ssoModels.SSOSettings{Settings: map[string]any{}}, &user.SignedInUser{IsGrafanaAdmin: false})
			if validateErr != nil {
				require.Empty(t, bodies.snapshot(), "token endpoint was called before the settings were rejected")
				return
			}

			// Validation has already accepted this path. Swapping it for a symlink before refresh
			// reads the path must not disclose the link target.
			retarget()

			info, err := CreateOAuthInfoFromKeyValues(settings)
			require.NoError(t, err)
			if info.Extra == nil {
				info.Extra = map[string]string{}
			}
			provider := mustNewAzureADProvider(t, info, cfg, mustProvideOrgRoleMapper(t, cfg, orgtest.NewOrgServiceFake()), nil, featuremgmt.WithFeatures(), nil)

			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, tokenServer.Client())
			_, refreshErr := provider.TokenSource(ctx, &oauth2.Token{
				AccessToken:  "placeholder-access-token",
				RefreshToken: "placeholder-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			}).Token()

			posted := strings.Join(bodies.snapshot(), "\n")
			require.NotContains(t, posted, azureLocalFileMarker)
			if len(bodies.snapshot()) == 0 {
				require.Error(t, refreshErr)
			}
		})
	}
}

const azureLocalFileMarker = "LOCAL_FILE_DISCLOSURE_MARKER"

func azureWorkloadIdentityDisclosurePaths(t *testing.T, kind string) (string, func()) {
	t.Helper()
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "private-file")
	require.NoError(t, os.WriteFile(secretPath, []byte(azureLocalFileMarker), 0o600))

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
		require.NoError(t, os.WriteFile(filepath.Join(dir, "private-file"), []byte(azureLocalFileMarker), 0o600))
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

type azureLockedBodies struct {
	mu    sync.Mutex
	items []string
}

func (b *azureLockedBodies) add(body string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(b.items, body)
}

func (b *azureLockedBodies) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.items))
	copy(out, b.items)
	return out
}
