package dashboardsnapshots

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	snapshot "github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// browserPath is the path a browser assigns to an anchor href.
// Chrome treats "\" as "/" and removes "." / ".." segments, including the
// %2e encodings of those segments, before it requests the URL.
func browserPath(raw string) string {
	raw = strings.ReplaceAll(raw, "\\", "/")
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	var out []string
	for _, seg := range strings.Split(parsed.EscapedPath(), "/") {
		switch strings.ToLower(seg) {
		case "", ".", "%2e":
			if seg == "" && len(out) == 0 {
				out = append(out, "")
			}
		case "..", "%2e%2e", ".%2e", "%2e.":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	path := strings.Join(out, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func TestBrowserPathMatchesObservedResolution(t *testing.T) {
	// Resolutions checked with Chrome 157 and Node's WHATWG URL parser.
	cases := map[string]string{
		"http://127.0.0.1:3000/dashboard/snapshot/../../logout":         "/logout",
		"http://127.0.0.1:3000/dashboard/snapshot/..\\..\\logout":       "/logout",
		"http://127.0.0.1:3000/dashboard/snapshot/%2e%2e/%2e%2e/logout": "/logout",
		"http://127.0.0.1:3000/dashboard/snapshot/.%2e/.%2e/logout":     "/logout",
		"http://127.0.0.1:3000/api/snapshots-delete/../../logout":       "/logout",
		"http://127.0.0.1:3000/grafana/dashboard/snapshot/../../logout": "/grafana/logout",
		"http://127.0.0.1:3000/dashboard/snapshot/..%2F..%2Flogout":     "/dashboard/snapshot/..%2F..%2Flogout",
		"http://127.0.0.1:3000/dashboard/snapshot/abcDEF0123456789":     "/dashboard/snapshot/abcDEF0123456789",
	}
	for raw, want := range cases {
		require.Equal(t, want, browserPath(raw), raw)
	}
}

func TestCallerSuppliedSnapshotKeyCannotLogOutViewer(t *testing.T) {
	origAppURL := setting.AppUrl
	setting.AppUrl = "http://localhost:3000/"
	t.Cleanup(func() { setting.AppUrl = origAppURL })

	const appURL = "http://localhost:3000/"
	payloads := []struct {
		name string
		body string
	}{
		{
			name: "slash segments",
			body: `{"name":"Quarterly review","dashboard":{"uid":"test-dashboard-uid"},"key":"../../logout","deleteKey":"../../logout"}`,
		},
		{
			name: "backslashes",
			body: `{"name":"Quarterly review","dashboard":{"uid":"test-dashboard-uid"},"key":"..\\..\\logout","deleteKey":"..\\..\\logout"}`,
		},
		{
			name: "percent encoded dot segments",
			body: `{"name":"Quarterly review","dashboard":{"uid":"test-dashboard-uid"},"key":"%2e%2e/%2e%2e/logout","deleteKey":"%2e%2e/%2e%2e/logout"}`,
		},
		{
			name: "delete key only",
			body: `{"name":"Quarterly review","dashboard":{"uid":"test-dashboard-uid"},"key":"abcDEF0123456789","deleteKey":"../../logout"}`,
		},
	}

	for _, tc := range payloads {
		t.Run("local/"+tc.name, func(t *testing.T) {
			assertSnapshotCreateDoesNotPublishLogoutLink(t, appURL, tc.body, false)
		})
		t.Run("public/"+tc.name, func(t *testing.T) {
			assertSnapshotCreateDoesNotPublishLogoutLink(t, appURL, tc.body, true)
		})
	}

	t.Run("omitted key is generated", func(t *testing.T) {
		body := `{"name":"Quarterly review","dashboard":{"uid":"test-dashboard-uid"}}`
		code, stored, response := createSnapshotFromJSON(t, body, false)
		require.Equal(t, http.StatusOK, code)
		require.Len(t, stored, 1)
		require.Regexp(t, `^[0-9A-Za-z]+$`, stored[0].Key)
		require.Regexp(t, `^[0-9A-Za-z]+$`, stored[0].DeleteKey)
		require.Equal(t, "/dashboard/snapshot/"+stored[0].Key, browserPath(appURL+"dashboard/snapshot/"+stored[0].Key))
		require.Equal(t, "/dashboard/snapshot/"+stored[0].Key, browserPath(response["url"].(string)))
		require.Equal(t, "/api/snapshots-delete/"+stored[0].DeleteKey, browserPath(response["deleteUrl"].(string)))
	})

	t.Run("alphanumeric key is preserved", func(t *testing.T) {
		body := `{"name":"Quarterly review","dashboard":{"uid":"test-dashboard-uid"},"key":"abcDEF0123456789","deleteKey":"zzzYYY000111"}`
		code, stored, response := createSnapshotFromJSON(t, body, false)
		require.Equal(t, http.StatusOK, code)
		require.Len(t, stored, 1)
		require.Equal(t, "abcDEF0123456789", stored[0].Key)
		require.Equal(t, "zzzYYY000111", stored[0].DeleteKey)
		require.Equal(t, "Quarterly review", stored[0].Name)
		require.Equal(t, "/dashboard/snapshot/abcDEF0123456789", browserPath(response["url"].(string)))
		require.Equal(t, "/api/snapshots-delete/zzzYYY000111", browserPath(response["deleteUrl"].(string)))
	})
}

func assertSnapshotCreateDoesNotPublishLogoutLink(t *testing.T, appURL, body string, public bool) {
	t.Helper()
	code, stored, response := createSnapshotFromJSON(t, body, public)

	if len(stored) > 0 && code != http.StatusOK {
		t.Fatalf("snapshot was stored before the request was refused, status %d", code)
	}

	for _, cmd := range stored {
		require.NotEqual(t, "/logout", browserPath(appURL+"dashboard/snapshot/"+cmd.Key), "stored key %q", cmd.Key)
		require.NotEqual(t, "/logout", browserPath(appURL+"api/snapshots-delete/"+cmd.DeleteKey), "stored delete key %q", cmd.DeleteKey)
		require.Equal(t, "Quarterly review", cmd.Name)
	}

	if code == http.StatusOK {
		require.NotEqual(t, "/logout", browserPath(response["url"].(string)))
		require.NotEqual(t, "/logout", browserPath(response["deleteUrl"].(string)))
	}
}

func createSnapshotFromJSON(t *testing.T, body string, public bool) (int, []*CreateDashboardSnapshotCommand, map[string]any) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/snapshots", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testUser := createTestUser()
	req = req.WithContext(identity.WithRequester(req.Context(), testUser))

	var cmd CreateDashboardSnapshotCommand
	require.NoError(t, web.Bind(req, &cmd))

	mockService := NewMockService(t)
	var stored []*CreateDashboardSnapshotCommand
	if !public {
		mockService.On("ValidateDashboardExists", mock.Anything, int64(1), "test-dashboard-uid").Return(nil).Maybe()
	}
	mockService.On("CreateDashboardSnapshot", mock.Anything, mock.Anything).
		Return(func(_ context.Context, got *CreateDashboardSnapshotCommand) *DashboardSnapshot {
			copied := *got
			stored = append(stored, &copied)
			return &DashboardSnapshot{Key: got.Key, DeleteKey: got.DeleteKey}
		}, nil).Maybe()

	ctx, recorder := createReqContext(t, req, testUser)
	cfg := snapshot.SnapshotSharingOptions{SnapshotsEnabled: true}
	if public {
		CreateDashboardSnapshotPublic(ctx, cfg, cmd, mockService)
	} else {
		CreateDashboardSnapshot(ctx, cfg, cmd, mockService)
	}

	var response map[string]any
	if recorder.Body.Len() > 0 {
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	}
	return recorder.Code, stored, response
}
