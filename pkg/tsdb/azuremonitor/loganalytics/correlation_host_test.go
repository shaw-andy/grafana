package loganalytics

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-azure-sdk-go/v2/azcredentials"
	"github.com/grafana/grafana-azure-sdk-go/v2/azhttpclient"
	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
	"github.com/grafana/grafana-azure-sdk-go/v2/aztokenprovider"
	"github.com/grafana/grafana-azure-sdk-go/v2/azusercontext"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"

	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/kinds/dataquery"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// placeholderAzureAccessToken stands in for the datasource Azure access token.
// The Azure middleware attaches whatever token its provider returns. This test
// uses a placeholder so it does not contact Azure AD.
const placeholderAzureAccessToken = "placeholder-azure-access-token"

type placeholderTokenProvider struct{}

func (placeholderTokenProvider) GetAccessToken(context.Context, []string) (string, error) {
	return placeholderAzureAccessToken, nil
}

type observedRequest struct {
	host                string
	method              string
	sentDatasourceToken bool
}

// azureMonitorClient builds the Azure Monitor HTTP client the same way
// newHTTPClient does: route scopes, user identity, rate-limit session, and no
// endpoint allowlist. The token provider is the only stand-in. newHTTPClient
// would otherwise ask Azure AD for an access token before this request.
func azureMonitorClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()

	credentials := &azcredentials.AzureManagedIdentityCredentials{}
	azureSettings := &azsettings.AzureSettings{Cloud: azsettings.AzurePublic}
	authOpts := azhttpclient.NewAuthOptions(azureSettings)
	authOpts.AllowUserIdentity()
	authOpts.AddRateLimitSession(true)
	authOpts.Scopes([]string{"https://management.azure.com/.default"})
	authOpts.AddTokenProvider(credentials.AzureAuthType(), func(*azsettings.AzureSettings, azcredentials.AzureCredentials) (aztokenprovider.AzureTokenProvider, error) {
		return placeholderTokenProvider{}, nil
	})

	clientOpts := httpclient.Options{
		Header: http.Header{"X-Ms-App": []string{"Grafana"}},
		Timeouts: &httpclient.TimeoutOptions{
			Timeout:             5 * time.Second,
			DialTimeout:         2 * time.Second,
			TLSHandshakeTimeout: 2 * time.Second,
		},
		TLS: &httpclient.TLSOptions{
			CACertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})),
		},
	}
	azhttpclient.AddAzureAuthentication(&clientOpts, authOpts, credentials)

	// Append the SDK provider middlewares after the Azure middleware, matching
	// Provider.New. None of them allowlist the request host.
	provider := httpclient.NewProvider()
	client, err := provider.New(clientOpts)
	require.NoError(t, err)
	return client
}

func TestAzureTracesCorrelationDoesNotSendAccessTokenToCallerHost(t *testing.T) {
	var mu sync.Mutex
	var seen []observedRequest
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, observedRequest{
			host:                r.Host,
			method:              r.Method,
			sentDatasourceToken: r.Header.Get("Authorization") == "Bearer "+placeholderAzureAccessToken,
		})
		mu.Unlock()
		http.Error(w, "correlation rejected", http.StatusInternalServerError)
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)

	attackerHost := srv.Listener.Addr().String()
	client := azureMonitorClient(t, srv)

	settings := &azsettings.AzureSettings{Cloud: azsettings.AzurePublic}
	publicCloud, err := settings.GetCloud(azsettings.AzurePublic)
	require.NoError(t, err)
	chinaCloud, err := settings.GetCloud(azsettings.AzureChina)
	require.NoError(t, err)
	govCloud, err := settings.GetCloud(azsettings.AzureUSGovernment)
	require.NoError(t, err)

	cases := []struct {
		name         string
		resourceBase string
		resource     string
	}{
		{
			name:         "public cloud resource chooses the host",
			resourceBase: publicCloud.Properties["resourceManager"],
			resource:     "@" + attackerHost,
		},
		{
			name:         "public cloud resource with a path still chooses the host",
			resourceBase: publicCloud.Properties["resourceManager"],
			resource:     "@" + attackerHost + "/subscriptions/placeholder",
		},
		{
			name:         "china cloud resource chooses the host",
			resourceBase: chinaCloud.Properties["resourceManager"],
			resource:     "@" + attackerHost,
		},
		{
			name:         "us government cloud resource chooses the host",
			resourceBase: govCloud.Properties["resourceManager"],
			resource:     "@" + attackerHost,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			seen = nil
			mu.Unlock()

			body, err := json.Marshal(map[string]any{
				"azureTraces": map[string]any{
					"resources":    []string{tc.resource},
					"operationId":  "operation-1",
					"resultFormat": string(dataquery.ResultFormatTable),
				},
			})
			require.NoError(t, err)

			queryReq := &backend.QueryDataRequest{
				PluginContext: backend.PluginContext{
					User: &backend.User{Login: "placeholder-user"},
				},
			}
			ctx := azusercontext.WithUserFromQueryReq(context.Background(), queryReq)

			dsInfo := types.DatasourceInfo{
				Services: map[string]types.DatasourceService{
					"Azure Monitor": {
						URL:        tc.resourceBase,
						HTTPClient: client,
						Logger:     log.NewNullLogger(),
					},
				},
				Routes: map[string]types.AzRoute{
					"Azure Portal": {URL: publicCloud.Properties["portal"]},
				},
			}
			ds := &AzureLogAnalyticsDatasource{Logger: log.NewNullLogger()}
			// The traces query client must not be used to follow the correlation
			// call. A refusal has to happen before any authenticated request.
			tracesClient := &http.Client{Transport: httpclient.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
				t.Errorf("traces query client was called for host %s", r.URL.Host)
				return nil, http.ErrNotSupported
			})}

			resp, err := ds.ExecuteTimeSeriesQuery(ctx, []backend.DataQuery{{
				RefID:     "A",
				QueryType: string(dataquery.AzureQueryTypeAzureTraces),
				TimeRange: backend.TimeRange{From: time.Now().Add(-time.Hour), To: time.Now()},
				JSON:      body,
			}}, dsInfo, tracesClient, "https://api.loganalytics.io", false)
			require.NoError(t, err)
			require.Error(t, resp.Responses["A"].Error)

			mu.Lock()
			got := append([]observedRequest(nil), seen...)
			mu.Unlock()
			for _, req := range got {
				if req.sentDatasourceToken {
					t.Errorf("Azure Monitor client sent the datasource access token to %s with method %s", req.host, req.method)
				}
			}
			require.Empty(t, got, "correlation request reached a host chosen by azureTraces.resources")
		})
	}
}
