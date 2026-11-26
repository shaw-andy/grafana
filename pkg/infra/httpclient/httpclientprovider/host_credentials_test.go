package httpclientprovider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-aws-sdk/pkg/awsds"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	sdkconfig "github.com/grafana/grafana-plugin-sdk-go/config"

	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsso"
	"github.com/grafana/grafana/pkg/services/validations"
	"github.com/grafana/grafana/pkg/setting"
)

const placeholderHostAccessKey = "placeholder-host-access-key"
const placeholderProfileAccessKey = "placeholder-profile-access-key"
const placeholderSecret = "placeholder-secret"

// TestShippedDefaultsDoNotSignSigV4WithHostCredentials covers proxied datasources
// (Prometheus, Elasticsearch, OpenSearch, and the other SigV4 types) that sign
// through the shared HTTP client. SigV4 itself is off in defaults.ini; the test
// turns on only that switch and leaves the shipped AWS auth-provider list in place.
func TestShippedDefaultsDoNotSignSigV4WithHostCredentials(t *testing.T) {
	cfg := loadShippedGrafanaConfig(t)
	cfg.SigV4AuthEnabled = true
	provider := New(cfg, &validations.OSSDataSourceRequestURLValidator{}, tracing.InitializeTracerForTest())
	injected := sigV4GrafanaConfig(t, cfg)

	cases := []struct {
		name       string
		jsonData   string
		profile    string
		marker     string
		assumeRole bool
	}{
		{
			name:     "sigV4AuthType default",
			jsonData: `{"sigV4Auth": true, "sigV4AuthType": "default", "sigV4Region": "us-east-1"}`,
			marker:   placeholderHostAccessKey,
		},
		{
			name:     "sigV4AuthType omitted",
			jsonData: `{"sigV4Auth": true, "sigV4Region": "us-east-1"}`,
			marker:   placeholderHostAccessKey,
		},
		{
			name:     "sigV4AuthType credentials",
			jsonData: `{"sigV4Auth": true, "sigV4AuthType": "credentials", "sigV4Profile": "tenant", "sigV4Region": "us-east-1"}`,
			profile:  "tenant",
			marker:   placeholderProfileAccessKey,
		},
		{
			name:       "sigV4 assume role from the default provider",
			jsonData:   `{"sigV4Auth": true, "sigV4AuthType": "default", "sigV4Region": "us-east-1", "sigV4AssumeRoleArn": "arn:aws:iam::123456789012:role/tenant"}`,
			marker:     placeholderHostAccessKey,
			assumeRole: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateHostCredentialEnv(t)
			if tc.profile != "" {
				t.Setenv("AWS_SHARED_CREDENTIALS_FILE", writeProfile(t, tc.profile, placeholderProfileAccessKey))
			} else {
				t.Setenv("AWS_ACCESS_KEY_ID", placeholderHostAccessKey)
				t.Setenv("AWS_SECRET_ACCESS_KEY", placeholderSecret)
			}

			var got []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = append(got, r.Header.Get("Authorization")+"\n"+readBody(t, r))
				w.WriteHeader(http.StatusForbidden)
			}))
			t.Cleanup(server.Close)

			if tc.assumeRole {
				// config@v1.33.3 env_config.go reads AWS_ENDPOINT_URL into BaseEndpoint,
				// which the assume-role STS client uses. The stand-in records that call.
				t.Setenv("AWS_ENDPOINT_URL", server.URL)
			}

			settings := &backend.DataSourceInstanceSettings{
				UID:      "proxied",
				Type:     "prometheus",
				Name:     "tenant-prom",
				JSONData: []byte(tc.jsonData),
			}

			// Data proxy requests do not carry Grafana config; the middleware falls back to the server cfg.
			signAndSend(t, provider, settings, server.URL, context.Background())
			// Callers that do inject plugin config must use the same shipped allow-list.
			signAndSend(t, provider, settings, server.URL, sdkconfig.WithGrafanaConfig(context.Background(), sdkconfig.NewGrafanaCfg(injected)))

			for _, header := range got {
				if strings.Contains(header, tc.marker) {
					t.Fatal("SigV4 signed a request with the host identity")
				}
			}
			if len(got) > 0 {
				t.Fatalf("SigV4 host auth reached the upstream (%d requests) under shipped AWS settings", len(got))
			}
		})
	}
}

func signAndSend(t *testing.T, provider *sdkhttpclient.Provider, settings *backend.DataSourceInstanceSettings, rawURL string, ctx context.Context) {
	t.Helper()
	opts, err := settings.HTTPClientOptions(ctx)
	require.NoError(t, err)
	transport, err := provider.GetTransport(opts)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL+"/api/v1/query", strings.NewReader(`{"q":"up"}`))
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	// A refusal from the signer returns an error and no response. A request that was signed reaches the server.
	_ = err
}

func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	return string(body)
}

type noopSSO struct{}

func (noopSSO) GetForProvider(context.Context, string) (*pluginsso.Settings, error) {
	return &pluginsso.Settings{Values: map[string]any{}}, nil
}

func loadShippedGrafanaConfig(t *testing.T) *setting.Cfg {
	t.Helper()
	restoreEnv(t,
		awsds.AllowedAuthProvidersEnvVarKeyName,
		awsds.AssumeRoleEnabledEnvVarKeyName,
		awsds.ListMetricsPageLimitKeyName,
		awsds.GrafanaAssumeRoleExternalIdKeyName,
		awsds.SessionDurationEnvVarKeyName,
	)
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: root,
		Config:   filepath.Join(root, "conf", "defaults.ini"),
	}))
	return cfg
}

func sigV4GrafanaConfig(t *testing.T, cfg *setting.Cfg) map[string]string {
	t.Helper()
	instanceCfg, err := pluginconfig.ProvidePluginInstanceConfig(cfg, setting.ProvideProvider(cfg), featuremgmt.WithFeatures())
	require.NoError(t, err)
	provider := pluginconfig.NewRequestConfigProvider(instanceCfg, noopSSO{})
	return provider.PluginRequestConfig(context.Background(), "prometheus", nil)
}

func isolateHostCredentialEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_ACCESS_KEY",
		"AWS_SECRET_KEY",
		"AWS_PROFILE",
		"AWS_DEFAULT_PROFILE",
		"AWS_SHARED_CREDENTIALS_FILE",
		"AWS_CONFIG_FILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_ROLE_ARN",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	empty := filepath.Join(t.TempDir(), "empty-aws")
	require.NoError(t, os.WriteFile(empty, []byte(""), 0o600))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", empty)
	t.Setenv("AWS_CONFIG_FILE", empty)
}

func writeProfile(t *testing.T, profile, accessKey string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials")
	contents := "[" + profile + "]\naws_access_key_id = " + accessKey + "\naws_secret_access_key = " + placeholderSecret + "\n"
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func restoreEnv(t *testing.T, keys ...string) {
	t.Helper()
	previous := make(map[string]*string, len(keys))
	for _, key := range keys {
		value, ok := os.LookupEnv(key)
		if ok {
			copied := value
			previous[key] = &copied
		} else {
			previous[key] = nil
		}
	}
	t.Cleanup(func() {
		for key, value := range previous {
			if value == nil {
				_ = os.Unsetenv(key)
				continue
			}
			_ = os.Setenv(key, *value)
		}
	})
}
