package acimpl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/accesscontrol/api"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/contexthandler/ctxkey"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

const (
	reloadBasicAction  = "test.basic:read"
	reloadDirectAction = "test.direct:read"
	reloadTeamAction   = "test.team:read"
	reloadTeamID       = int64(11)
)

// countingStore records how many times the permission service asks the
// database for basic-role, team, and direct permissions.
type countingStore struct {
	actest.FakeStore
	basic  atomic.Int64
	teams  atomic.Int64
	direct atomic.Int64
	delay  time.Duration
}

func (s *countingStore) GetBasicRolesPermissions(ctx context.Context, query accesscontrol.GetUserPermissionsQuery) ([]accesscontrol.Permission, error) {
	s.basic.Add(1)
	s.wait()
	return []accesscontrol.Permission{{Action: reloadBasicAction, Scope: "basic"}}, nil
}

func (s *countingStore) GetTeamsPermissions(ctx context.Context, query accesscontrol.GetUserPermissionsQuery) (map[int64][]accesscontrol.Permission, error) {
	s.teams.Add(1)
	s.wait()
	return map[int64][]accesscontrol.Permission{
		reloadTeamID: {{Action: reloadTeamAction, Scope: "teams:id:11"}},
	}, nil
}

func (s *countingStore) GetUserPermissions(ctx context.Context, query accesscontrol.GetUserPermissionsQuery) ([]accesscontrol.Permission, error) {
	s.direct.Add(1)
	s.wait()
	return []accesscontrol.Permission{{Action: reloadDirectAction, Scope: "direct"}}, nil
}

func (s *countingStore) wait() {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
}

func (s *countingStore) snapshot() (basic, teams, direct int64) {
	return s.basic.Load(), s.teams.Load(), s.direct.Load()
}

type reloadHarness struct {
	store   *countingStore
	httpSrv *httptest.Server
	client  *http.Client
	users   sync.Map
	seq     atomic.Int64
}

func newReloadHarness(t *testing.T, delay time.Duration) *reloadHarness {
	t.Helper()

	cfg := setting.NewCfg()
	// Production default: permission_cache is on unless the operator turns it off.
	cfg.RBAC.PermissionCache = true
	require.True(t, cfg.RBAC.PermissionCache)

	store := &countingStore{delay: delay}
	svc := &Service{
		actionResolver: resourcepermissions.NewActionSetService(),
		cache:          localcache.ProvideService(),
		cfg:            cfg,
		features:       featuremgmt.WithFeatures(),
		log:            log.New("accesscontrol-reloadcache-test"),
		roles:          accesscontrol.BuildBasicRoleDefinitions(),
		store:          store,
	}

	acAPI := api.NewAccessControlAPI(routing.NewRouteRegister(), actest.FakeAccessControl{}, svc, nil)
	acAPI.RegisterAPIEndpoints()

	h := &reloadHarness{
		store:  store,
		client: &http.Client{},
	}
	// One request context per call. A shared context would mix concurrent writes.
	m := web.New()
	m.Use(func(c *web.Context) {
		reqCtx := &contextmodel.ReqContext{Context: c, Logger: log.New("reloadcache-test")}
		if id := c.Req.Header.Get("X-Test-User"); id != "" {
			if signedIn, ok := h.users.Load(id); ok {
				reqCtx.SignedInUser = signedIn.(*user.SignedInUser)
				reqCtx.IsSignedIn = true
			}
		}
		c.Req = c.Req.WithContext(ctxkey.Set(c.Req.Context(), reqCtx))
	})
	acAPI.RouteRegister.Register(m.Router)
	h.httpSrv = httptest.NewServer(m)
	t.Cleanup(h.httpSrv.Close)
	return h
}

func viewerUser(id int64) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  id,
		OrgID:   1,
		OrgRole: "Viewer",
		Login:   "viewer",
		TeamIDs: []int64{reloadTeamID},
	}
}

func orgAdminUser() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:  8,
		OrgID:   1,
		OrgRole: "Admin",
		Login:   "org-admin",
		TeamIDs: []int64{reloadTeamID},
	}
}

func serviceAccountUser() *user.SignedInUser {
	return &user.SignedInUser{
		UserID:           9,
		OrgID:            1,
		OrgRole:          "Viewer",
		Login:            "sa",
		IsServiceAccount: true,
		TeamIDs:          []int64{reloadTeamID},
	}
}

func (h *reloadHarness) newGet(usr *user.SignedInUser, target string) (*http.Request, error) {
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	req, err := http.NewRequest(http.MethodGet, h.httpSrv.URL+target, nil)
	if err != nil {
		return nil, err
	}
	id := strconv.FormatInt(h.seq.Add(1), 10)
	h.users.Store(id, usr)
	req.Header.Set("X-Test-User", id)
	return req, nil
}

func (h *reloadHarness) get(t *testing.T, usr *user.SignedInUser, target string) (int, []byte) {
	t.Helper()
	req, err := h.newGet(usr, target)
	require.NoError(t, err)
	status, body, err := sendReloadRequest(h.client, req)
	require.NoError(t, err)
	return status, body
}

func sendReloadRequest(client *http.Client, req *http.Request) (int, []byte, error) {
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, nil, err
	}
	return res.StatusCode, body, nil
}

func requireActions(t *testing.T, endpoint string, body []byte) {
	t.Helper()
	actions := []string{reloadBasicAction, reloadDirectAction, reloadTeamAction}
	path := endpoint
	if before, _, ok := strings.Cut(endpoint, "?"); ok {
		path = before
	}
	if strings.HasSuffix(path, "/actions") {
		var out map[string]bool
		require.NoError(t, json.Unmarshal(body, &out), string(body))
		for _, action := range actions {
			require.Truef(t, out[action], "actions response missing %s: %s", action, body)
		}
		return
	}
	var out map[string][]string
	require.NoError(t, json.Unmarshal(body, &out), string(body))
	for _, action := range actions {
		_, ok := out[action]
		require.Truef(t, ok, "permissions response missing %s: %s", action, body)
	}
}

// TestSignedInUserReloadCacheDoesNotRequeryPermissions is the spec for the
// access-control list endpoints. A signed-in caller who is not a server
// administrator must not be able to force fresh basic-role, team, or direct
// permission queries by passing reloadcache.
func TestSignedInUserReloadCacheDoesNotRequeryPermissions(t *testing.T) {
	endpoints := []string{
		"/api/access-control/user/actions",
		"/api/access-control/user/permissions",
	}
	callers := []struct {
		name string
		user *user.SignedInUser
	}{
		{name: "viewer", user: viewerUser(3)},
		{name: "org admin", user: orgAdminUser()},
		{name: "service account", user: serviceAccountUser()},
	}
	flags := []string{"true", "1", "TRUE"}

	for _, endpoint := range endpoints {
		for _, caller := range callers {
			for _, flag := range flags {
				t.Run(endpoint+"/"+caller.name+"/"+flag, func(t *testing.T) {
					h := newReloadHarness(t, 0)
					// A second user shares the org role and the team, so those
					// cache keys are already populated by the first lookup.
					other := viewerUser(4)
					other.OrgRole = caller.user.OrgRole
					if caller.user.UserID == other.UserID {
						other.UserID = 5
					}

					status, body := h.get(t, caller.user, endpoint)
					require.Equal(t, http.StatusOK, status, string(body))
					requireActions(t, endpoint, body)
					basic, teams, direct := h.store.snapshot()
					require.Equal(t, int64(1), basic, "warm-up should load basic-role permissions once")
					require.Equal(t, int64(1), teams, "warm-up should load team permissions once")
					require.Equal(t, int64(1), direct, "warm-up should load direct permissions once")

					status, body = h.get(t, caller.user, endpoint)
					require.Equal(t, http.StatusOK, status, string(body))
					requireActions(t, endpoint, body)
					basicAfter, teamsAfter, directAfter := h.store.snapshot()
					require.Equal(t, basic, basicAfter, "cached lookup without reloadcache still queried basic roles")
					require.Equal(t, teams, teamsAfter, "cached lookup without reloadcache still queried teams")
					require.Equal(t, direct, directAfter, "cached lookup without reloadcache still queried direct permissions")

					target := endpoint + "?reloadcache=" + flag
					const extra = 8
					for range extra {
						status, body = h.get(t, caller.user, target)
						require.Equal(t, http.StatusOK, status, string(body))
						requireActions(t, endpoint, body)
					}
					// The other caller has no direct-permission entry yet. One
					// direct load is the ordinary miss. Role and team entries
					// are already cached and must stay cached.
					status, body = h.get(t, other, target)
					require.Equal(t, http.StatusOK, status, string(body))
					requireActions(t, endpoint, body)

					gotBasic, gotTeams, gotDirect := h.store.snapshot()
					require.Equal(t, basic, gotBasic, "reloadcache issued new basic-role queries")
					require.Equal(t, teams, gotTeams, "reloadcache issued new team queries")
					require.Equal(t, direct+1, gotDirect, "reloadcache issued extra direct permission queries")
				})
			}
		}
	}
}

// TestParallelReloadCacheCoalescesPermissionLookups covers a cold cache and a
// warm cache. Parallel requests that pass reloadcache must not each run their
// own basic-role, team, and direct permission queries.
func TestParallelReloadCacheCoalescesPermissionLookups(t *testing.T) {
	endpoints := []string{
		"/api/access-control/user/actions",
		"/api/access-control/user/permissions",
	}
	flags := []string{"true", "1"}

	for _, endpoint := range endpoints {
		for _, flag := range flags {
			t.Run("cold/"+endpoint+"/"+flag, func(t *testing.T) {
				h := newReloadHarness(t, 30*time.Millisecond)
				usr := viewerUser(3)
				target := endpoint + "?reloadcache=" + flag
				statuses, bodies := h.parallelGets(t, usr, target, 12)
				for i := range statuses {
					require.Equal(t, http.StatusOK, statuses[i], string(bodies[i]))
					requireActions(t, endpoint, bodies[i])
				}
				basic, teams, direct := h.store.snapshot()
				require.Equal(t, int64(1), basic, "parallel reloadcache ran %d basic-role queries", basic)
				require.Equal(t, int64(1), teams, "parallel reloadcache ran %d team queries", teams)
				require.Equal(t, int64(1), direct, "parallel reloadcache ran %d direct permission queries", direct)
			})

			t.Run("warm/"+endpoint+"/"+flag, func(t *testing.T) {
				h := newReloadHarness(t, 30*time.Millisecond)
				usr := viewerUser(3)
				status, body := h.get(t, usr, endpoint)
				require.Equal(t, http.StatusOK, status, string(body))
				requireActions(t, endpoint, body)
				basic, teams, direct := h.store.snapshot()
				require.Equal(t, int64(1), basic)
				require.Equal(t, int64(1), teams)
				require.Equal(t, int64(1), direct)

				target := endpoint + "?reloadcache=" + flag
				statuses, bodies := h.parallelGets(t, usr, target, 12)
				for i := range statuses {
					require.Equal(t, http.StatusOK, statuses[i], string(bodies[i]))
					requireActions(t, endpoint, bodies[i])
				}
				gotBasic, gotTeams, gotDirect := h.store.snapshot()
				require.Equal(t, basic, gotBasic, "parallel reloadcache on a warm cache ran basic-role queries")
				require.Equal(t, teams, gotTeams, "parallel reloadcache on a warm cache ran team queries")
				require.Equal(t, direct, gotDirect, "parallel reloadcache on a warm cache ran direct permission queries")
			})
		}
	}
}

func (h *reloadHarness) parallelGets(t *testing.T, usr *user.SignedInUser, target string, n int) ([]int, [][]byte) {
	t.Helper()
	reqs := make([]*http.Request, n)
	for i := range n {
		req, err := h.newGet(usr, target)
		require.NoError(t, err)
		reqs[i] = req
	}

	statuses := make([]int, n)
	bodies := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], bodies[i], errs[i] = sendReloadRequest(h.client, reqs[i])
		}()
	}
	wg.Wait()
	for i := range errs {
		require.NoErrorf(t, errs[i], "parallel request %d failed", i)
	}
	return statuses, bodies
}
