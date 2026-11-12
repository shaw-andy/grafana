package azuremonitor

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/grafana/grafana-azure-sdk-go/v2/azcredentials"
	"github.com/grafana/grafana-azure-sdk-go/v2/azsettings"
	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/types"
)

// placeholderDatasourceToken is the access token the local stand-in returns.
// It is not a credential; the datasource client secret below is also a placeholder.
const (
	placeholderDatasourceToken = "placeholder"
	placeholderClientSecret    = "placeholder"
	callerAuthorization        = "Bearer caller-supplied-placeholder"
)

// upstreamCall is a request the credentialed Azure client actually sent.
type upstreamCall struct {
	method        string
	path          string
	rawQuery      string
	body          string
	authorization string
}

// TestResourceProxyForwardsOnlyPickerReads checks that a caller who can hit the
// Azure Monitor resource routes cannot make the datasource identity call
// arbitrary Azure Resource Manager, Log Analytics, or Resource Graph operations.
//
// Allowed calls are the read-only resource-picker requests. Every other method
// or path must be rejected before the credentialed client is used. The
// assertion is on the request the client sends, so a check of a different
// path than the one that is forwarded still fails.
func TestResourceProxyForwardsOnlyPickerReads(t *testing.T) {
	var mu sync.Mutex
	var calls []upstreamCall

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			writeOpenIDConfiguration(w, r)
			return
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": placeholderDatasourceToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		mu.Lock()
		calls = append(calls, upstreamCall{
			method:        r.Method,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			body:          string(body),
			authorization: r.Header.Get("Authorization"),
		})
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(srv.Close)

	certFile := writeServerCert(t, srv.Certificate())
	t.Setenv("SSL_CERT_FILE", certFile)

	client := newCredentialedClient(t, srv.URL)
	service := newResourceService(client, srv.URL)

	allowed := []struct {
		name       string
		method     string
		path       string
		query      string
		body       string
		want       upstreamCall
		wantInBody string
	}{
		{
			name:   "list subscriptions",
			method: http.MethodGet,
			path:   "azuremonitor/subscriptions",
			query:  "api-version=2019-03-01",
			want: upstreamCall{
				method:        http.MethodGet,
				path:          "/subscriptions",
				rawQuery:      "api-version=2019-03-01",
				authorization: "Bearer " + placeholderDatasourceToken,
			},
			wantInBody: `"value"`,
		},
		{
			name:   "list metric definitions",
			method: http.MethodGet,
			path:   "azuremonitor/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/providers/microsoft.insights/metricdefinitions",
			query:  "api-version=2018-01-01",
			want: upstreamCall{
				method:        http.MethodGet,
				path:          "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/providers/microsoft.insights/metricdefinitions",
				rawQuery:      "api-version=2018-01-01",
				authorization: "Bearer " + placeholderDatasourceToken,
			},
			wantInBody: `"value"`,
		},
		{
			name:   "resource graph query",
			method: http.MethodPost,
			path:   "resourcegraph/providers/Microsoft.ResourceGraph/resources",
			query:  "api-version=2021-03-01",
			body:   `{"query":"Resources | project id"}`,
			want: upstreamCall{
				method:        http.MethodPost,
				path:          "/providers/Microsoft.ResourceGraph/resources",
				rawQuery:      "api-version=2021-03-01",
				body:          `{"query":"Resources | project id"}`,
				authorization: "Bearer " + placeholderDatasourceToken,
			},
			wantInBody: `"value"`,
		},
		{
			name:   "log analytics metadata",
			method: http.MethodGet,
			path:   "loganalytics/v1/workspaces/workspace-id/metadata",
			want: upstreamCall{
				method:        http.MethodGet,
				path:          "/v1/workspaces/workspace-id/metadata",
				authorization: "Bearer " + placeholderDatasourceToken,
			},
			wantInBody: `"tables"`,
		},
	}

	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			got, status, respBody := callResource(t, &mu, &calls, service, tt.method, tt.path, tt.query, tt.body)
			require.Len(t, got, 1, "credentialed client calls, status %d body %s", status, respBody)
			require.Equal(t, tt.want.method, got[0].method)
			require.Equal(t, tt.want.path, got[0].path)
			if tt.want.rawQuery != "" {
				require.Equal(t, tt.want.rawQuery, got[0].rawQuery)
			}
			require.Equal(t, tt.want.body, got[0].body)
			require.Equal(t, tt.want.authorization, got[0].authorization)
			require.NotEqual(t, callerAuthorization, got[0].authorization)
			require.Equal(t, http.StatusOK, status)
			require.Contains(t, respBody, tt.wantInBody)
		})
	}

	denied := []struct {
		name   string
		method string
		path   string
		query  string
		body   string
	}{
		{
			name:   "azure monitor put virtual machine",
			method: http.MethodPut,
			path:   "azuremonitor/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
			query:  "api-version=2021-07-01",
			body:   `{"location":"eastus"}`,
		},
		{
			name:   "azure monitor patch virtual machine",
			method: http.MethodPatch,
			path:   "azuremonitor/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
			query:  "api-version=2021-07-01",
			body:   `{"tags":{"env":"test"}}`,
		},
		{
			name:   "azure monitor delete virtual machine",
			method: http.MethodDelete,
			path:   "azuremonitor/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
			query:  "api-version=2021-07-01",
		},
		{
			name:   "azure monitor post deployment",
			method: http.MethodPost,
			path:   "azuremonitor/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Resources/deployments/example",
			query:  "api-version=2021-04-01",
			body:   `{"properties":{"mode":"Incremental","template":{}}}`,
		},
		{
			name:   "azure monitor get key vault secret",
			method: http.MethodGet,
			path:   "azuremonitor/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault/secrets/name",
			query:  "api-version=2022-07-01",
		},
		{
			name:   "azure monitor get role assignments",
			method: http.MethodGet,
			path:   "azuremonitor/subscriptions/sub-id/providers/Microsoft.Authorization/roleAssignments",
			query:  "api-version=2022-04-01",
		},
		{
			// The resource mux cleans ".." before the handler. A check of the
			// original path sees a metric-definitions read; the path that remains
			// is a role-assignment read. Neither form may be sent with the
			// datasource credential.
			name:   "azure monitor metric path that resolves to role assignments",
			method: http.MethodGet,
			path:   "azuremonitor/subscriptions/sub-id/providers/Microsoft.Insights/metricdefinitions/../../../../../../Microsoft.Authorization/roleAssignments",
			query:  "api-version=2022-04-01",
		},
		{
			name:   "log analytics arbitrary query",
			method: http.MethodPost,
			path:   "loganalytics/v1/workspaces/workspace-id/query",
			body:   `{"query":"union *"}`,
		},
		{
			name:   "log analytics delete metadata",
			method: http.MethodDelete,
			path:   "loganalytics/v1/workspaces/workspace-id/metadata",
		},
		{
			name:   "log analytics put workspace",
			method: http.MethodPut,
			path:   "loganalytics/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws",
			query:  "api-version=2022-10-01",
			body:   `{"location":"eastus"}`,
		},
		{
			name:   "resource graph put virtual machine",
			method: http.MethodPut,
			path:   "resourcegraph/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
			query:  "api-version=2021-07-01",
			body:   `{"location":"eastus"}`,
		},
		{
			name:   "resource graph post deployment",
			method: http.MethodPost,
			path:   "resourcegraph/subscriptions/sub-id/providers/Microsoft.Resources/deployments/example",
			query:  "api-version=2021-04-01",
			body:   `{"properties":{"mode":"Incremental","template":{}}}`,
		},
		{
			name:   "resource graph delete resource group",
			method: http.MethodDelete,
			path:   "resourcegraph/subscriptions/sub-id/resourceGroups/rg",
			query:  "api-version=2021-04-01",
		},
	}

	for _, tt := range denied {
		t.Run(tt.name, func(t *testing.T) {
			got, status, respBody := callResource(t, &mu, &calls, service, tt.method, tt.path, tt.query, tt.body)
			require.Empty(t, got, "credentialed client forwarded %+v for %s %s query %q body %q status %d response %s", got, tt.method, tt.path, tt.query, tt.body, status, respBody)
			if status >= 300 && status < 400 {
				require.NotContains(t, respBody, `"value"`)
				return
			}
			require.GreaterOrEqual(t, status, 400)
			require.Less(t, status, 500)
			require.NotContains(t, respBody, `"value"`)
		})
	}
}

func newCredentialedClient(t *testing.T, serverURL string) *http.Client {
	t.Helper()
	scopes, err := audienceToScopes(serverURL)
	require.NoError(t, err)

	jsonData, err := json.Marshal(map[string]any{
		"tlsSkipVerify": true,
	})
	require.NoError(t, err)

	settings := &backend.DataSourceInstanceSettings{
		JSONData:                jsonData,
		DecryptedSecureJSONData: map[string]string{},
	}
	model := types.DatasourceInfo{
		Credentials: &azcredentials.AzureClientSecretCredentials{
			AzureCloud:   azsettings.AzurePublic,
			Authority:    serverURL,
			TenantId:     "adfs",
			ClientId:     "placeholder-client-id",
			ClientSecret: placeholderClientSecret,
		},
	}
	route := types.AzRoute{
		URL:     serverURL,
		Scopes:  scopes,
		Headers: map[string]string{"x-ms-app": "Grafana"},
	}
	client, err := newHTTPClient(context.Background(), route, model, settings, &azsettings.AzureSettings{
		Cloud: azsettings.AzurePublic,
	}, httpclient.NewProvider())
	require.NoError(t, err)
	require.NotNil(t, client)
	return client
}

func newResourceService(client *http.Client, serverURL string) *Service {
	service := types.DatasourceService{URL: serverURL, HTTPClient: client}
	s := ProvideService(httpclient.NewProvider())
	s.im = &fakeInstance{
		services: map[string]types.DatasourceService{
			azureMonitor:       service,
			azureLogAnalytics:  service,
			azureResourceGraph: service,
		},
	}
	return s
}

type bodySender struct {
	status int
	body   []byte
}

func (s *bodySender) Send(resp *backend.CallResourceResponse) error {
	if resp == nil {
		return nil
	}
	if resp.Status != 0 {
		s.status = resp.Status
	}
	s.body = append(s.body, resp.Body...)
	return nil
}

func callResource(t *testing.T, mu *sync.Mutex, calls *[]upstreamCall, service *Service, method, path, rawQuery, body string) ([]upstreamCall, int, string) {
	t.Helper()
	mu.Lock()
	*calls = nil
	mu.Unlock()

	resourceURL := path
	if rawQuery != "" {
		resourceURL += "?" + rawQuery
	}
	sender := &bodySender{}
	err := service.CallResource(context.Background(), &backend.CallResourceRequest{
		PluginContext: backend.PluginContext{
			User: &backend.User{Login: "viewer", Role: "Viewer"},
		},
		Path:   path,
		URL:    resourceURL,
		Method: method,
		Headers: map[string][]string{
			"Authorization": {callerAuthorization},
			"Content-Type":  {"application/json"},
		},
		Body: []byte(body),
	}, sender)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	out := append([]upstreamCall(nil), *calls...)
	return out, sender.status, string(sender.body)
}

func writeOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	authority := "https://" + r.Host + "/adfs"
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"authorization_endpoint": authority + "/oauth2/v2.0/authorize",
		"token_endpoint":         authority + "/oauth2/v2.0/token",
		"issuer":                 authority + "/v2.0",
	})
}

func writeServerCert(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	require.NotNil(t, cert)
	f, err := os.CreateTemp(t.TempDir(), "stand-in.pem")
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	require.NoError(t, f.Close())
	return f.Name()
}
