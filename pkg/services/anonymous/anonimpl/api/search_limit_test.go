package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/anonymous/anonimpl/anonstore"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/util/xorm"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// These tests are the spec for anonymous device search. They fail while a request can
// make the store read every anon_device row into memory, or can pass an uncapped page
// size through to the database. A fixed handler caps the page, and the store counts
// matching rows without materializing them.

const (
	maxAnonymousDevicePageSize = 100
	// One returned page, including a single wide user agent, stays under this.
	// Reading every seeded wide row does not.
	maxAnonymousSearchAlloc = 512 * 1024
	wideDeviceRows          = 120
	wideUserAgentBytes      = 8 * 1024
)

func TestIntegrationAnonymousDeviceSearchDoesNotLoadEveryRow(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	sqlStore := db.NewTestStore(t)
	store := anonstore.ProvideAnonDBStore(sqlStore, 0)
	seedAnonymousDevices(t, store)

	cfg := setting.NewCfg()
	cfg.Anonymous.Enabled = true
	routeRegister := routing.NewRouteRegister()
	NewAnonDeviceServiceAPI(cfg, store, acimpl.ProvideAccessControlTest(), routeRegister).RegisterAPIEndpoints()
	server := webtest.NewServer(t, routeRegister)

	capture := &sqlCapture{}
	sqlStore.GetEngine().SetLogger(capture)
	sqlStore.GetEngine().ShowSQL(true)

	h := &deviceSearchHarness{t: t, server: server, capture: capture}
	reader := userWithPermissions(t, 1, map[string][]string{
		accesscontrol.ActionUsersRead: {"global.users:id:4"},
	})
	orgReader := userWithPermissions(t, 1, map[string][]string{
		accesscontrol.ActionOrgUsersRead: {accesscontrol.ScopeUsersAll},
	})

	t.Run("users read on one user is enough and a different action is not", func(t *testing.T) {
		capture.reset()
		status, _ := h.get("/api/anonymous/search?perpage=1", orgReader)
		require.Equal(t, http.StatusForbidden, status)
		require.Empty(t, deviceQueries(capture.lines()), "a refused search must not read anon_device: %v", capture.lines())

		capture.reset()
		status, body := h.get("/api/anonymous/search?perpage=1&sort=updatedAt-desc", reader)
		require.Equal(t, http.StatusOK, status, string(body))
	})

	t.Run("page size one still counts every match without loading them", func(t *testing.T) {
		// The first call pays for driver and session setup. The next call is the one that must stay small.
		_, _ = h.get("/api/anonymous/search?perpage=1", reader)

		var result searchResponse
		alloc := allocDuring(func() {
			capture.reset()
			status, body := h.get("/api/anonymous/search?perpage=1&page=2&sort=updatedAt-desc", reader)
			require.Equal(t, http.StatusOK, status, string(body))
			require.NoError(t, json.Unmarshal(body, &result))
		})
		require.Equal(t, int64(wideDeviceRows+1), result.TotalCount)
		require.Len(t, result.Devices, 1)
		require.LessOrEqual(t, result.PerPage, maxAnonymousDevicePageSize)
		require.Lessf(t, alloc, uint64(maxAnonymousSearchAlloc),
			"search allocated %d bytes for one page; queries: %v", alloc, capture.lines())
		assertDeviceSelectsBounded(t, capture.lines(), maxAnonymousDevicePageSize)
	})

	t.Run("requested page size is capped before the database reads rows", func(t *testing.T) {
		for _, perPage := range []string{"0", "-3", "1000000", "999999999"} {
			t.Run(perPage, func(t *testing.T) {
				capture.reset()
				status, body := h.get("/api/anonymous/search?perpage="+perPage, reader)
				require.Equal(t, http.StatusOK, status, string(body))
				var result searchResponse
				require.NoError(t, json.Unmarshal(body, &result))
				require.Equal(t, int64(wideDeviceRows+1), result.TotalCount)
				require.LessOrEqual(t, result.PerPage, maxAnonymousDevicePageSize)
				require.LessOrEqual(t, len(result.Devices), maxAnonymousDevicePageSize)
				require.NotEmpty(t, result.Devices)
				assertDeviceSelectsBounded(t, capture.lines(), maxAnonymousDevicePageSize)
			})
		}
	})

	t.Run("a filtered search does not load rows that do not match", func(t *testing.T) {
		_, _ = h.get("/api/anonymous/search?perpage=1&query=203.0.113.50", reader)

		var result searchResponse
		alloc := allocDuring(func() {
			capture.reset()
			status, body := h.get("/api/anonymous/search?perpage=1000000&query=203.0.113.50", reader)
			require.Equal(t, http.StatusOK, status, string(body))
			require.NoError(t, json.Unmarshal(body, &result))
		})
		require.Lessf(t, alloc, uint64(maxAnonymousSearchAlloc),
			"filtered search allocated %d bytes; queries: %v", alloc, capture.lines())
		require.Equal(t, int64(1), result.TotalCount)
		require.Len(t, result.Devices, 1)
		require.Equal(t, "device-match", result.Devices[0].DeviceID)
		require.LessOrEqual(t, result.PerPage, maxAnonymousDevicePageSize)
		assertDeviceSelectsBounded(t, capture.lines(), maxAnonymousDevicePageSize)
	})

	t.Run("device list does not materialize every row", func(t *testing.T) {
		capture.reset()
		status, body := h.get("/api/anonymous/devices", reader)
		require.Equal(t, http.StatusOK, status, string(body))
		require.LessOrEqual(t, countDeviceIDs(t, body), maxAnonymousDevicePageSize)
		assertDeviceSelectsBounded(t, capture.lines(), maxAnonymousDevicePageSize)
	})
}

func seedAnonymousDevices(t *testing.T, store *anonstore.AnonDBStore) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, store.CreateOrUpdateDevice(t.Context(), &anonstore.Device{
		DeviceID:  "device-match",
		ClientIP:  "203.0.113.50",
		UserAgent: "match",
		CreatedAt: now,
		UpdatedAt: now,
	}))
	require.NoError(t, store.CreateOrUpdateDevice(t.Context(), &anonstore.Device{
		DeviceID:  "device-old",
		ClientIP:  "198.51.100.8",
		UserAgent: "old",
		CreatedAt: now.Add(-90 * 24 * time.Hour),
		UpdatedAt: now.Add(-90 * 24 * time.Hour),
	}))

	agent := make([]byte, wideUserAgentBytes)
	for i := range agent {
		agent[i] = 'A'
	}
	for i := 0; i < wideDeviceRows; i++ {
		agent[0] = byte('A' + (i % 26))
		require.NoError(t, store.CreateOrUpdateDevice(t.Context(), &anonstore.Device{
			DeviceID:  fmt.Sprintf("device-%03d", i),
			ClientIP:  "10.0.0.1",
			UserAgent: string(agent),
			CreatedAt: now,
			UpdatedAt: now,
		}))
	}
}

func userWithPermissions(t *testing.T, orgID int64, permissions map[string][]string) *user.SignedInUser {
	t.Helper()
	return &user.SignedInUser{
		UserID: 4,
		OrgID:  orgID,
		Login:  "reader",
		Permissions: map[int64]map[string][]string{
			orgID: permissions,
		},
	}
}

type searchResponse struct {
	TotalCount int64 `json:"totalCount"`
	Devices    []struct {
		DeviceID string `json:"deviceId"`
	} `json:"devices"`
	Page    int `json:"page"`
	PerPage int `json:"perPage"`
}

type deviceSearchHarness struct {
	t       *testing.T
	server  *webtest.Server
	capture *sqlCapture
}

func (h *deviceSearchHarness) get(target string, usr *user.SignedInUser) (int, []byte) {
	h.t.Helper()
	req := webtest.RequestWithSignedInUser(h.server.NewGetRequest(target), usr)
	resp, err := h.server.Send(req)
	require.NoError(h.t, err)
	defer func() {
		require.NoError(h.t, resp.Body.Close())
	}()
	body, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	return resp.StatusCode, body
}

type sqlCapture struct {
	xorm.DiscardLogger
	mu    sync.Mutex
	saved []string
}

func (s *sqlCapture) Infof(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = append(s.saved, fmt.Sprintf(format, args...))
}

func (s *sqlCapture) IsShowSQL() bool { return true }

func (s *sqlCapture) ShowSQL(show ...bool) {}

func (s *sqlCapture) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = nil
}

func (s *sqlCapture) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.saved))
	copy(out, s.saved)
	return out
}

func allocDuring(fn func()) uint64 {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

var (
	countSelectRe = regexp.MustCompile(`(?i)\bselect\s+count\s*\(`)
	limitRe       = regexp.MustCompile(`(?i)\blimit\s+(\d+)`)
)

func deviceQueries(queries []string) []string {
	var matched []string
	for _, query := range queries {
		if strings.Contains(strings.ToLower(query), "anon_device") {
			matched = append(matched, query)
		}
	}
	return matched
}

func assertDeviceSelectsBounded(t *testing.T, queries []string, maxRows int) {
	t.Helper()
	matched := deviceQueries(queries)
	require.NotEmpty(t, matched, "expected SQL against anon_device, got %v", queries)
	for _, query := range matched {
		lower := strings.ToLower(query)
		if !strings.Contains(lower, "select") || countSelectRe.MatchString(query) {
			continue
		}
		found := limitRe.FindStringSubmatch(query)
		require.NotEmptyf(t, found, "anon_device select has no LIMIT:\n%s", query)
		var limit int
		_, err := fmt.Sscan(found[1], &limit)
		require.NoError(t, err)
		require.LessOrEqualf(t, limit, maxRows, "anon_device select LIMIT %d exceeds %d:\n%s", limit, maxRows, query)
	}
}

func countDeviceIDs(t *testing.T, body []byte) int {
	t.Helper()
	var raw any
	require.NoError(t, json.Unmarshal(body, &raw))
	return countDeviceIDValues(raw)
}

func countDeviceIDValues(v any) int {
	switch node := v.(type) {
	case map[string]any:
		total := 0
		if _, ok := node["deviceId"]; ok {
			total++
		}
		for _, child := range node {
			total += countDeviceIDValues(child)
		}
		return total
	case []any:
		total := 0
		for _, child := range node {
			total += countDeviceIDValues(child)
		}
		return total
	default:
		return 0
	}
}
