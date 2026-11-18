package dashboardsnapshots

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	snapshot "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

// External snapshot publishing stores deleteUrl from the snapshot server and later
// requests that URL from the Grafana process. These tests pin the safe behavior:
// the delete URL's scheme and host must be the configured snapshot server, literal
// internal addresses must not be dialed, and a redirect must not be followed to a
// different host. They fail while that request is still made.

func TestExternalSnapshotCreateRejectsDeleteURLWhoseHostIsNotConfigured(t *testing.T) {
	withoutSnapshotProxy(t)

	internal := newCountingServer(t, http.StatusOK)
	configured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key":       "k",
			"deleteKey": "d",
			"url":       "http://" + r.Host + "/dashboard/snapshot/k",
			"deleteUrl": "http://" + r.Host + "@" + hostport(internal.url) + "/latest/meta-data?x=/api/snapshots-delete/d",
		})
	}))
	t.Cleanup(configured.Close)

	resp, err := createExternalDashboardSnapshot(externalSnapshotCmd(t), configured.URL, "")
	require.Error(t, err)
	requireNoUntrustedDeleteURL(t, resp, configured.URL)
	require.Zero(t, internal.hits(), "create requested the delete URL host before refusing it")
}

func TestExternalSnapshotCreateRejectsDeleteURLBypasses(t *testing.T) {
	withoutSnapshotProxy(t)

	cases := []struct {
		name   string
		delete func(configuredHost string) string
	}{
		{
			name: "link-local metadata address kept by query text",
			delete: func(string) string {
				return "http://169.254.169.254/latest/meta-data/iam/security-credentials/?x=/api/snapshots-delete/d"
			},
		},
		{
			name: "private address",
			delete: func(string) string {
				return "http://10.13.13.13/api/snapshots-delete/d"
			},
		},
		{
			name: "different port on the configured IP",
			delete: func(string) string {
				return "http://127.0.0.1:1/api/snapshots-delete/d"
			},
		},
		{
			name: "https on the configured host",
			delete: func(configuredHost string) string {
				return "https://" + configuredHost + "/api/snapshots-delete/d"
			},
		},
		{
			name: "configured host is only a prefix of the delete host",
			delete: func(configuredHost string) string {
				return "http://" + configuredHost + ".evil.invalid/api/snapshots-delete/d"
			},
		},
		{
			name: "configured origin is only a query parameter",
			delete: func(configuredHost string) string {
				return "http://192.168.13.13/api/snapshots-delete/d?next=http://" + configuredHost
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"key":       "k",
					"deleteKey": "d",
					"url":       "http://" + r.Host + "/dashboard/snapshot/k",
					"deleteUrl": tc.delete(r.Host),
				})
			}))
			t.Cleanup(configured.Close)

			resp, err := createExternalDashboardSnapshot(externalSnapshotCmd(t), configured.URL, "")
			require.Error(t, err)
			requireNoUntrustedDeleteURL(t, resp, configured.URL)
		})
	}
}

func TestExternalSnapshotCreateAcceptsDeleteURLOnConfiguredHost(t *testing.T) {
	withoutSnapshotProxy(t)

	configured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key":       "k",
			"deleteKey": "d",
			"url":       "http://" + r.Host + "/dashboard/snapshot/k",
			"deleteUrl": "http://" + r.Host + "/api/snapshots-delete/d",
		})
	}))
	t.Cleanup(configured.Close)

	resp, err := createExternalDashboardSnapshot(externalSnapshotCmd(t), configured.URL, "")
	require.NoError(t, err)
	require.NotNil(t, resp)
	requireSameOrigin(t, configured.URL, resp.DeleteUrl)
	requireSameOrigin(t, configured.URL, resp.Url)
}

func TestExternalSnapshotCreateDoesNotFollowRedirectToAnotherHost(t *testing.T) {
	withoutSnapshotProxy(t)

	var internal countingServer
	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internal.add(r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"key":"k","deleteKey":"d","url":"http://127.0.0.1/x","deleteUrl":"http://127.0.0.1/api/snapshots-delete/d"}`))
	}))
	t.Cleanup(internalServer.Close)

	var posts int
	configured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		http.Redirect(w, r, internalServer.URL+"/latest/meta-data", http.StatusFound)
	}))
	t.Cleanup(configured.Close)

	_, err := createExternalDashboardSnapshot(externalSnapshotCmd(t), configured.URL, "")
	require.Error(t, err)
	require.Equal(t, 1, posts, "configured snapshot server should still receive the create POST")
	require.Zero(t, internal.hits(), "create followed a redirect from the configured snapshot server")
}

func TestCreateDashboardSnapshotDoesNotStoreMismatchedDeleteURL(t *testing.T) {
	withoutSnapshotProxy(t)

	configured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key":       "k",
			"deleteKey": "d",
			"url":       "http://169.254.169.254/latest/meta-data",
			"deleteUrl": "http://169.254.169.254/latest/meta-data?x=/api/snapshots-delete/d",
		})
	}))
	t.Cleanup(configured.Close)

	mockService := NewMockService(t)
	mockService.On("ValidateDashboardExists", mock.Anything, int64(1), "test-dashboard-uid").Return(nil)
	mockService.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { t.Errorf("snapshot with an untrusted delete URL was stored") }).
		Return(&DashboardSnapshot{}, nil).Maybe()

	testUser := createTestUser()
	req, err := http.NewRequest(http.MethodPost, "/api/snapshots", nil)
	require.NoError(t, err)
	req = req.WithContext(identity.WithRequester(req.Context(), testUser))
	ctx, recorder := createReqContext(t, req, testUser)

	CreateDashboardSnapshot(ctx, snapshot.SnapshotSharingOptions{
		SnapshotsEnabled:    true,
		ExternalEnabled:     true,
		ExternalSnapshotURL: configured.URL,
	}, CreateDashboardSnapshotCommand{
		DashboardCreateCommand: snapshot.DashboardCreateCommand{
			Dashboard: createTestDashboard(t),
			Name:      "external",
			External:  true,
		},
	}, mockService)

	require.NotEqual(t, http.StatusOK, recorder.Code)
	mockService.AssertNotCalled(t, "CreateDashboardSnapshot", mock.Anything, mock.Anything)
}

func TestDeleteExternalDashboardSnapshotDoesNotRequestInternalURLs(t *testing.T) {
	withoutSnapshotProxy(t)

	loopback := newCountingServer(t, http.StatusOK)
	v6 := newIPv6LoopbackServer(t)
	literal := []string{
		loopback.url + "/latest/meta-data/iam/security-credentials/?x=/api/snapshots-delete/d",
		loopback.url + "/api/snapshots-delete/d",
		loopback.url + "/latest/meta-data/iam",
		"http://localhost" + portSuffix(loopback.url) + "/api/snapshots-delete/d",
		"http://0.0.0.0" + portSuffix(loopback.url) + "/api/snapshots-delete/d",
		v6 + "/api/snapshots-delete/d",
		"http://user:placeholder@" + hostport(loopback.url) + "/api/snapshots-delete/d",
	}

	for _, target := range literal {
		t.Run(target, func(t *testing.T) {
			err := DeleteExternalDashboardSnapshot(target)
			require.Error(t, err)
			requireNotDialed(t, err)
		})
	}
	require.Zero(t, loopback.hits())

	// Link-local and private addresses have no local listener. A dial is visible
	// because the shared client waits until its timeout and returns a URL error.
	unroutable := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/?x=/api/snapshots-delete/d",
		"http://10.13.13.13/api/snapshots-delete/d",
		"http://192.168.13.13/latest/meta-data",
		"http://172.16.13.13/api/snapshots-delete/d",
	}
	var wg sync.WaitGroup
	for _, target := range unroutable {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			err := DeleteExternalDashboardSnapshot(target)
			if err == nil {
				t.Errorf("%s: delete succeeded", target)
				return
			}
			var ue *url.Error
			if errors.As(err, &ue) {
				t.Errorf("%s: dialed untrusted host", target)
			}
		}(target)
	}
	wg.Wait()
}

func TestDeleteWithKeyDoesNotRequestStoredInternalURL(t *testing.T) {
	withoutSnapshotProxy(t)

	internal := newCountingServer(t, http.StatusOK)
	stored := internal.url + "/latest/meta-data?x=/api/snapshots-delete/d"

	mockService := NewMockService(t)
	mockService.On("GetDashboardSnapshot", mock.Anything, mock.Anything).Return(&DashboardSnapshot{
		Key:               "k",
		DeleteKey:         "d",
		OrgID:             1,
		External:          true,
		ExternalDeleteURL: stored,
	}, nil)
	mockService.On("DeleteDashboardSnapshot", mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { t.Errorf("local snapshot deleted while requesting an untrusted delete URL") }).
		Return(nil).Maybe()

	err := DeleteWithKey(context.Background(), "d", mockService)
	require.Error(t, err)
	require.Zero(t, internal.hits())
	mockService.AssertNotCalled(t, "DeleteDashboardSnapshot", mock.Anything, mock.Anything)
}

type countingServer struct {
	url   string
	mu    sync.Mutex
	count int
	auth  bool
}

func (c *countingServer) add(r *http.Request) {
	c.mu.Lock()
	c.count++
	if r.Header.Get("Authorization") != "" {
		c.auth = true
	}
	c.mu.Unlock()
}

func (c *countingServer) hits() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func newCountingServer(t *testing.T, status int) *countingServer {
	t.Helper()
	cs := &countingServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.add(r)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	cs.url = srv.URL
	return cs
}

func newIPv6LoopbackServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return fmt.Sprintf("http://[::1]:%d", ln.Addr().(*net.TCPAddr).Port)
}

func externalSnapshotCmd(t *testing.T) CreateDashboardSnapshotCommand {
	t.Helper()
	return CreateDashboardSnapshotCommand{
		DashboardCreateCommand: snapshot.DashboardCreateCommand{
			Dashboard: createTestDashboard(t),
			Name:      "external",
		},
	}
}

func requireNoUntrustedDeleteURL(t *testing.T, resp *CreateExternalSnapshotResponse, configured string) {
	t.Helper()
	if resp == nil {
		return
	}
	if resp.DeleteUrl != "" {
		parsed, err := url.Parse(resp.DeleteUrl)
		require.NoError(t, err)
		want, err := url.Parse(configured)
		require.NoError(t, err)
		require.Equal(t, want.Scheme, parsed.Scheme)
		require.Equal(t, want.Host, parsed.Host)
	}
}

func requireSameOrigin(t *testing.T, configured, raw string) {
	t.Helper()
	got, err := url.Parse(raw)
	require.NoError(t, err)
	want, err := url.Parse(configured)
	require.NoError(t, err)
	require.Equal(t, want.Scheme, got.Scheme)
	require.Equal(t, want.Host, got.Host)
}

func requireNotDialed(t *testing.T, err error) {
	t.Helper()
	var ue *url.Error
	if errors.As(err, &ue) {
		t.Fatalf("dialed untrusted host: %v", err)
	}
}

func hostport(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

func portSuffix(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return ":" + u.Port()
}

func withoutSnapshotProxy(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		t.Setenv(key, "")
	}
}
