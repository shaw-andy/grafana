package cloudwatch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/grafana/grafana-aws-sdk/pkg/awsds"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	sdkconfig "github.com/grafana/grafana-plugin-sdk-go/config"

	"github.com/grafana/grafana/pkg/plugins/backendplugin/coreplugin"
	pluginlog "github.com/grafana/grafana/pkg/plugins/log"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginconfig"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsso"
	"github.com/grafana/grafana/pkg/setting"
)

// placeholderHostAccessKey is not a credential. It is a marker the AWS SDK
// writes into the SigV4 Authorization header when it uses the process environment.
const placeholderHostAccessKey = "placeholder-host-access-key"

// placeholderProfileAccessKey is the marker for a named profile in the host credentials file.
const placeholderProfileAccessKey = "placeholder-profile-access-key"

const placeholderSecret = "placeholder-secret"

// TestShippedDefaultsDoNotSignCloudWatchWithHostCredentials drives the core
// CloudWatch plugin the same way a query does: shipped Grafana config is placed
// on the plugin context, the core plugin copies it into the request context,
// and the real AWS SDK signs whatever newAWSConfig resolves.
//
// While host auth providers stay allowed, these calls reach the test server
// signed with the host identity. They must be refused before any AWS request.
func TestShippedDefaultsDoNotSignCloudWatchWithHostCredentials(t *testing.T) {
	cfg := loadShippedGrafanaConfig(t)
	grafanaCfg := cloudWatchGrafanaConfig(t, cfg)

	t.Run("default provider uses the host environment chain", func(t *testing.T) {
		isolateHostCredentialEnv(t)
		t.Setenv("AWS_ACCESS_KEY_ID", placeholderHostAccessKey)
		t.Setenv("AWS_SECRET_ACCESS_KEY", placeholderSecret)
		exerciseCloudWatch(t, grafanaCfg, authJSON("default", "", ""), placeholderHostAccessKey)
	})

	t.Run("omitted authType is the default provider", func(t *testing.T) {
		isolateHostCredentialEnv(t)
		t.Setenv("AWS_ACCESS_KEY_ID", placeholderHostAccessKey)
		t.Setenv("AWS_SECRET_ACCESS_KEY", placeholderSecret)
		exerciseCloudWatch(t, grafanaCfg, authJSON("", "", ""), placeholderHostAccessKey)
	})

	t.Run("legacy arn authType is the default provider", func(t *testing.T) {
		isolateHostCredentialEnv(t)
		t.Setenv("AWS_ACCESS_KEY_ID", placeholderHostAccessKey)
		t.Setenv("AWS_SECRET_ACCESS_KEY", placeholderSecret)
		exerciseCloudWatch(t, grafanaCfg, authJSON("arn", "", ""), placeholderHostAccessKey)
	})

	t.Run("credentials provider reads the host profile file", func(t *testing.T) {
		isolateHostCredentialEnv(t)
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", writeProfile(t, "tenant", placeholderProfileAccessKey))
		exerciseCloudWatch(t, grafanaCfg, authJSON("credentials", "tenant", ""), placeholderProfileAccessKey)
	})

	t.Run("default provider can assume a role with the host identity", func(t *testing.T) {
		isolateHostCredentialEnv(t)
		t.Setenv("AWS_ACCESS_KEY_ID", placeholderHostAccessKey)
		t.Setenv("AWS_SECRET_ACCESS_KEY", placeholderSecret)
		exerciseCloudWatch(t, grafanaCfg, authJSON("default", "", "arn:aws:iam::123456789012:role/tenant"), placeholderHostAccessKey)
	})

	t.Run("credentials provider can assume a role with the host profile", func(t *testing.T) {
		isolateHostCredentialEnv(t)
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", writeProfile(t, "tenant", placeholderProfileAccessKey))
		exerciseCloudWatch(t, grafanaCfg, authJSON("credentials", "tenant", "arn:aws:iam::123456789012:role/tenant"), placeholderProfileAccessKey)
	})

	t.Run("ec2 iam role is not a host provider an org admin can select", func(t *testing.T) {
		isolateHostCredentialEnv(t)
		t.Setenv("AWS_ACCESS_KEY_ID", placeholderHostAccessKey)
		t.Setenv("AWS_SECRET_ACCESS_KEY", placeholderSecret)
		exerciseCloudWatch(t, grafanaCfg, authJSON("ec2_iam_role", "", ""), placeholderHostAccessKey)
	})
}

func exerciseCloudWatch(t *testing.T, grafanaCfg map[string]string, jsonData string, forbiddenMarker string) {
	t.Helper()
	requests := &requestLog{}
	server := httptest.NewServer(requests.handler(t))
	t.Cleanup(server.Close)

	settings := strings.ReplaceAll(jsonData, "ENDPOINT", server.URL)
	plugin := newCloudWatchPlugin(t)
	pCtx := backend.PluginContext{
		PluginID:      "cloudwatch",
		OrgID:         2,
		GrafanaConfig: sdkconfig.NewGrafanaCfg(grafanaCfg),
		DataSourceInstanceSettings: &backend.DataSourceInstanceSettings{
			ID:       7,
			UID:      "tenant-cloudwatch",
			Type:     "cloudwatch",
			Name:     "tenant",
			JSONData: []byte(settings),
		},
		User: &backend.User{Login: "org-admin", Role: "Admin"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	// Metrics query, the /api/ds/query time series path.
	_, _ = plugin.QueryData(ctx, &backend.QueryDataRequest{
		PluginContext: pCtx,
		Queries: []backend.DataQuery{{
			RefID: "A",
			TimeRange: backend.TimeRange{
				From: time.Now().Add(-time.Hour),
				To:   time.Now(),
			},
			JSON: json.RawMessage(`{
				"type": "timeSeriesQuery",
				"namespace": "AWS/EC2",
				"metricName": "CPUUtilization",
				"dimensions": {"InstanceId": "i-tenant"},
				"region": "us-east-1",
				"id": "a",
				"statistics": ["Average"],
				"period": "300",
				"matchExact": true,
				"refId": "A"
			}`),
		}},
	})

	// Logs Insights, including the alert/backend execution path.
	_, _ = plugin.QueryData(ctx, &backend.QueryDataRequest{
		PluginContext: pCtx,
		Headers:       map[string]string{headerFromAlert: "true"},
		Queries: []backend.DataQuery{{
			RefID: "B",
			TimeRange: backend.TimeRange{
				From: time.Now().Add(-time.Hour),
				To:   time.Now(),
			},
			JSON: json.RawMessage(`{
				"queryMode": "Logs",
				"region": "us-east-1",
				"expression": "fields @timestamp, @message",
				"logGroupNames": ["/tenant/app"]
			}`),
		}},
	})

	// Health check hits both the metrics and logs APIs.
	_, _ = plugin.CheckHealth(ctx, &backend.CheckHealthRequest{PluginContext: pCtx})

	// Resource routes: EC2, tagging, logs, and OAM.
	sender := &discardResourceSender{}
	for _, path := range []string{
		"/regions",
		"/ec2-instance-attribute?region=us-east-1&attributeName=InstanceId&filters={}",
		"/ebs-volume-ids?region=us-east-1&instanceId=i-tenant",
		"/resource-arns?region=us-east-1&resourceType=ec2:instance&tags={}",
		"/log-groups?region=us-east-1",
		"/legacy-log-groups?region=us-east-1&limit=1",
		"/accounts?region=us-east-1",
		"/metrics?region=us-east-1&namespace=Custom/Tenant",
	} {
		parsed, err := url.Parse(path)
		require.NoError(t, err)
		_ = plugin.CallResource(ctx, &backend.CallResourceRequest{
			PluginContext: pCtx,
			Path:          parsed.Path,
			Method:        http.MethodGet,
			URL:           path,
		}, sender)
	}

	requests.mu.Lock()
	defer requests.mu.Unlock()
	for _, got := range requests.got {
		if strings.Contains(got.authorization, forbiddenMarker) || strings.Contains(got.body, forbiddenMarker) {
			t.Fatalf("CloudWatch signed an AWS request with the host identity at %s", got.url)
		}
	}
	if len(requests.got) > 0 {
		t.Fatalf("host auth reached AWS (%d requests) under shipped settings; the call must be refused first", len(requests.got))
	}
}

func authJSON(authType, profile, assumeRoleARN string) string {
	payload := map[string]string{
		"defaultRegion": "us-east-1",
		"endpoint":      "ENDPOINT",
	}
	if authType != "" {
		payload["authType"] = authType
	}
	if profile != "" {
		payload["profile"] = profile
	}
	if assumeRoleARN != "" {
		payload["assumeRoleArn"] = assumeRoleARN
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func newCloudWatchPlugin(t *testing.T) interface {
	backend.QueryDataHandler
	backend.CheckHealthHandler
	backend.CallResourceHandler
} {
	t.Helper()
	service := ProvideService()
	factory := coreplugin.New(backend.ServeOpts{
		QueryDataHandler:    service,
		CheckHealthHandler:  service,
		CallResourceHandler: service,
	})
	plugin, err := factory("cloudwatch", pluginlog.New("test"), noop.NewTracerProvider().Tracer("test"), func() []string { return nil })
	require.NoError(t, err)
	return plugin
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
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: root,
		Config:   filepath.Join(root, "conf", "defaults.ini"),
	}))
	return cfg
}

func cloudWatchGrafanaConfig(t *testing.T, cfg *setting.Cfg) map[string]string {
	t.Helper()
	instanceCfg, err := pluginconfig.ProvidePluginInstanceConfig(cfg, setting.ProvideProvider(cfg), featuremgmt.WithFeatures())
	require.NoError(t, err)
	provider := pluginconfig.NewRequestConfigProvider(instanceCfg, noopSSO{})
	return provider.PluginRequestConfig(context.Background(), "cloudwatch", nil)
}

type noopSSO struct{}

func (noopSSO) GetForProvider(context.Context, string) (*pluginsso.Settings, error) {
	return &pluginsso.Settings{Values: map[string]any{}}, nil
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
		"AWS_EC2_METADATA_DISABLED",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	// Point the SDK away from a real user profile in the home directory.
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

type capturedAWSRequest struct {
	url           string
	authorization string
	body          string
}

type requestLog struct {
	mu  sync.Mutex
	got []capturedAWSRequest
}

func (l *requestLog) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		l.mu.Lock()
		l.got = append(l.got, capturedAWSRequest{
			url:           r.URL.String(),
			authorization: r.Header.Get("Authorization"),
			body:          string(body),
		})
		l.mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)
	})
}

type discardResourceSender struct{}

func (discardResourceSender) Send(*backend.CallResourceResponse) error { return nil }
