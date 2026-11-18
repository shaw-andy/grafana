package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	dashv0 "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	commonv0 "github.com/grafana/grafana/pkg/apimachinery/apis/common/v0alpha1"
	"github.com/grafana/grafana/pkg/services/dashboardsnapshots"
)

// These tests cover the Kubernetes snapshot client, which publishes and deletes
// external snapshots on a different HTTP client from the legacy service. The
// delete URL returned by the snapshot server is stored and later requested, and
// with externalSnapshotsK8SAPIPush enabled that request is rebuilt from the
// stored host and carries the configured bearer token.

const placeholderExternalSnapshotToken = "placeholder-external-snapshot-token"

func TestK8sExternalSnapshotCreateRejectsMismatchedDeleteURL(t *testing.T) {
	internal := newCountingServer(t, http.StatusOK)

	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			configured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" && legacy {
					t.Errorf("legacy create sent an Authorization header to the snapshot server")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"key":       "k",
					"deleteKey": "d",
					"url":       "http://" + r.Host + "/dashboard/snapshot/k",
					"deleteUrl": "http://" + r.Host + "@" + hostport(internal.url) + "/latest/meta-data?x=/api/snapshots-delete/d",
				})
			}))
			t.Cleanup(configured.Close)

			resp, err := pushExternalSnapshot(t, legacy, configured.URL)
			require.Error(t, err)
			if resp != nil && resp.DeleteURL != "" {
				got, perr := url.Parse(resp.DeleteURL)
				require.NoError(t, perr)
				want, perr := url.Parse(configured.URL)
				require.NoError(t, perr)
				require.Equal(t, want.Scheme, got.Scheme)
				require.Equal(t, want.Host, got.Host)
			}
			require.Zero(t, internal.hits())
		})
	}
}

func TestK8sExternalSnapshotCreateRejectsUnrelatedDeleteHosts(t *testing.T) {
	cases := map[string]string{
		"link-local": "http://169.254.169.254/latest/meta-data?x=/api/snapshots-delete/d",
		"private":    "http://10.13.13.13/api/snapshots-delete/d",
		"suffix":     "",
	}
	for name, deleteURL := range cases {
		t.Run(name, func(t *testing.T) {
			for _, legacy := range []bool{false, true} {
				configured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw := deleteURL
					if name == "suffix" {
						raw = "http://" + r.Host + ".evil.invalid/api/snapshots-delete/d"
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{
						"key": "k", "deleteKey": "d",
						"url": "http://" + r.Host + "/dashboard/snapshot/k", "deleteUrl": raw,
					})
				}))
				t.Cleanup(configured.Close)
				_, err := pushExternalSnapshot(t, legacy, configured.URL)
				require.Error(t, err)
			}
		})
	}
}

func TestK8sExternalSnapshotCreateDoesNotFollowRedirect(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			internal := newCountingServer(t, http.StatusOK)
			var posts int
			configured := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				http.Redirect(w, r, internal.url+"/latest/meta-data", http.StatusFound)
			}))
			t.Cleanup(configured.Close)

			_, err := pushExternalSnapshot(t, legacy, configured.URL)
			require.Error(t, err)
			require.Equal(t, 1, posts)
			require.Zero(t, internal.hits())
			require.False(t, internal.sawAuth(), "redirect target received an Authorization header")
		})
	}
}

func TestDeleteExternalSnapshotLegacyDoesNotRequestInternalURL(t *testing.T) {
	loopback := newCountingServer(t, http.StatusOK)
	targets := []string{
		loopback.url + "/latest/meta-data/iam/security-credentials/?x=/api/snapshots-delete/d",
		loopback.url + "/api/snapshots-delete/d",
		loopback.url + "/latest/meta-data/iam",
		"http://localhost" + portSuffix(loopback.url) + "/api/snapshots-delete/d",
		"http://0.0.0.0" + portSuffix(loopback.url) + "/api/snapshots-delete/d",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			err := deleteExternalSnapshotLegacy(target)
			require.Error(t, err)
			requireNotDialed(t, err)
		})
	}
	require.Zero(t, loopback.hits())

	unroutable := []string{
		"http://169.254.169.254/latest/meta-data?x=/api/snapshots-delete/d",
		"http://10.13.13.13/api/snapshots-delete/d",
		"http://192.168.13.13/latest/meta-data",
	}
	var wg sync.WaitGroup
	for _, target := range unroutable {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			err := deleteExternalSnapshotLegacy(target)
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

func TestDeleteExternalSnapshotDoesNotSendTokenToInternalHost(t *testing.T) {
	loopback := newCountingServer(t, http.StatusOK)
	err := deleteExternalSnapshot(loopback.url+"/apis/dashboard.grafana.app/v0alpha1/namespaces/default/snapshots/delete/d", placeholderExternalSnapshotToken)
	require.Error(t, err)
	require.Zero(t, loopback.hits())
	require.False(t, loopback.sawAuth(), "Authorization header was sent to the untrusted host")
}

func TestSnapshotLegacyStoreDeleteDoesNotRequestStoredInternalURL(t *testing.T) {
	loopback := newCountingServer(t, http.StatusOK)
	stored := []struct {
		name string
		flag bool
		url  string
	}{
		{name: "legacy query trick", flag: false, url: loopback.url + "/latest/meta-data?x=/api/snapshots-delete/abc123"},
		{name: "legacy rebuilt path", flag: false, url: loopback.url + "/latest/meta-data/iam"},
		{name: "k8s rebuilt host", flag: true, url: loopback.url + "/api/snapshots-delete/abc123"},
	}

	for _, tc := range stored {
		t.Run(tc.name, func(t *testing.T) {
			setExternalSnapshotsK8SAPIPushToggle(t, tc.flag)
			before := loopback.hits()
			mockService := dashboardsnapshots.NewMockService(t)
			mockService.On("GetDashboardSnapshot", mock.Anything, mock.Anything).Return(&dashboardsnapshots.DashboardSnapshot{
				Key:               "snap-1",
				DeleteKey:         "abc123",
				OrgID:             1,
				External:          true,
				ExternalDeleteURL: tc.url,
			}, nil)
			mockService.On("DeleteDashboardSnapshot", mock.Anything, mock.Anything).
				Run(func(mock.Arguments) { t.Errorf("local snapshot deleted") }).
				Return(nil).Maybe()

			store := &SnapshotLegacyStore{
				ResourceInfo:          dashv0.SnapshotResourceInfo,
				Service:               mockService,
				ExternalSnapshotToken: placeholderExternalSnapshotToken,
			}
			_, _, err := store.Delete(ctxForOrg(1), "snap-1", nil, &metav1.DeleteOptions{})
			require.Error(t, err)
			require.Equal(t, before, loopback.hits())
			require.False(t, loopback.sawAuth(), "Authorization header was sent to the untrusted host")
			mockService.AssertNotCalled(t, "DeleteDashboardSnapshot", mock.Anything, mock.Anything)
		})
	}
}

func pushExternalSnapshot(t *testing.T, legacy bool, configured string) (*dashv0.DashboardCreateResponse, error) {
	t.Helper()
	cmd := &dashboardsnapshots.CreateDashboardSnapshotCommand{
		DashboardCreateCommand: dashv0.DashboardCreateCommand{
			Name: "external",
			Dashboard: &commonv0.Unstructured{Object: map[string]any{
				"uid": "dash-1",
			}},
		},
	}
	options := dashv0.SnapshotSharingOptions{
		ExternalSnapshotURL:   configured,
		ExternalSnapshotToken: placeholderExternalSnapshotToken,
	}
	if legacy {
		return createExternalSnapshotLegacy(cmd, options)
	}
	return createExternalSnapshot(cmd, options)
}

type countingServer struct {
	url  string
	mu   sync.Mutex
	n    int
	auth bool
}

func (c *countingServer) add(r *http.Request) {
	c.mu.Lock()
	c.n++
	if r.Header.Get("Authorization") != "" {
		c.auth = true
	}
	c.mu.Unlock()
}

func (c *countingServer) hits() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *countingServer) sawAuth() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.auth
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
