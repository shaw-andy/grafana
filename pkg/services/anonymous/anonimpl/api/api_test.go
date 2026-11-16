package api_test

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/database"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/anonymous/anonimpl/anonstore"
	"github.com/grafana/grafana/pkg/services/anonymous/anonimpl/api"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	orgID          int64 = 1
	targetUserID   int64 = 7
	scopedUserID   int64 = 42
	wildcardUserID int64 = 43
	globalUserID   int64 = 44
	unprivilegedID int64 = 45
	deviceAlpha          = "anon-device-alpha"
	deviceBeta           = "anon-device-beta"
	ipAlpha              = "203.0.113.10"
	ipBeta               = "203.0.113.20"
	agentAlpha           = "AnonDeviceAgentAlpha"
	agentBeta            = "AnonDeviceAgentBeta"
)

// TestIntegrationAnonymousDeviceRoutes checks the HTTP handlers that list anonymous devices.
// A caller whose users:read grant covers one user, or every user id but not the global users
// scope, must not receive stored device ids, client IPs, or user agents. The same rows must
// stay unread after anonymous access is turned off. A caller holding users:read on the global
// users scope still receives them while anonymous access is enabled.
func TestIntegrationAnonymousDeviceRoutes(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	sqlStore := db.NewTestStore(t)
	ctx := context.Background()
	cfg := &setting.Cfg{}
	cfg.Anonymous.Enabled = true

	grantManagedUsersRead(t, ctx, sqlStore, cfg, scopedUserID, strconv.FormatInt(targetUserID, 10))
	grantManagedUsersRead(t, ctx, sqlStore, cfg, wildcardUserID, "*")
	grantGlobalUsersRead(t, ctx, sqlStore, globalUserID)

	scopedUser := viewerWithDBPermissions(t, ctx, sqlStore, scopedUserID)
	wildcardUser := viewerWithDBPermissions(t, ctx, sqlStore, wildcardUserID)
	globalUser := viewerWithDBPermissions(t, ctx, sqlStore, globalUserID)
	unprivileged := &user.SignedInUser{UserID: unprivilegedID, OrgID: orgID, OrgRole: org.RoleViewer}

	require.Equal(t, []string{"global.users:id:" + strconv.FormatInt(targetUserID, 10)}, scopedUser.GetPermissions()[accesscontrol.ActionUsersRead])
	require.Equal(t, []string{"global.users:id:*"}, wildcardUser.GetPermissions()[accesscontrol.ActionUsersRead])
	require.Equal(t, []string{accesscontrol.ScopeGlobalUsersAll}, globalUser.GetPermissions()[accesscontrol.ActionUsersRead])
	require.Empty(t, unprivileged.GetPermissions()[accesscontrol.ActionUsersRead])

	store := anonstore.ProvideAnonDBStore(sqlStore, 0)
	now := time.Now()
	require.NoError(t, store.CreateOrUpdateDevice(ctx, &anonstore.Device{
		DeviceID: deviceAlpha, ClientIP: ipAlpha, UserAgent: agentAlpha, CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, store.CreateOrUpdateDevice(ctx, &anonstore.Device{
		DeviceID: deviceBeta, ClientIP: ipBeta, UserAgent: agentBeta, CreatedAt: now, UpdatedAt: now,
	}))

	routeRegister := routing.NewRouteRegister()
	deviceAPI := api.NewAnonDeviceServiceAPI(cfg, store, acimpl.ProvideAccessControlTest(), routeRegister)
	deviceAPI.RegisterAPIEndpoints()
	server := webtest.NewServer(t, routeRegister)

	paths := []string{
		"/api/anonymous/devices",
		"/api/anonymous/search?perpage=50&page=1",
		"/api/anonymous/search?perpage=50&page=1&query=" + ipBeta,
	}

	t.Run("single user scope does not reveal every device", func(t *testing.T) {
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				status, body := getAnonymous(t, server, scopedUser, path)
				requireNoStoredDevices(t, status, body)
			})
		}
	})

	t.Run("per-user wildcard scope does not reveal every device", func(t *testing.T) {
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				status, body := getAnonymous(t, server, wildcardUser, path)
				requireNoStoredDevices(t, status, body)
			})
		}
	})

	t.Run("missing users read does not reveal devices", func(t *testing.T) {
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				status, body := getAnonymous(t, server, unprivileged, path)
				require.Equal(t, http.StatusForbidden, status)
				requireNoStoredDevices(t, status, body)
			})
		}
	})

	t.Run("global users scope lists and searches devices while anonymous access is enabled", func(t *testing.T) {
		status, body := getAnonymous(t, server, globalUser, paths[0])
		require.Equal(t, http.StatusOK, status)
		requireAllStoredDevices(t, body)

		status, body = getAnonymous(t, server, globalUser, paths[1])
		require.Equal(t, http.StatusOK, status)
		requireAllStoredDevices(t, body)

		status, body = getAnonymous(t, server, globalUser, paths[2])
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, deviceBeta)
		require.Contains(t, body, ipBeta)
		require.Contains(t, body, agentBeta)
	})

	t.Run("stored devices stay hidden after anonymous access is turned off", func(t *testing.T) {
		cfg.Anonymous.Enabled = false
		t.Cleanup(func() { cfg.Anonymous.Enabled = true })
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				status, body := getAnonymous(t, server, globalUser, path)
				requireNoStoredDevices(t, status, body)
			})
		}
	})
}

func grantManagedUsersRead(t *testing.T, ctx context.Context, sqlStore db.DB, cfg *setting.Cfg, userID int64, resourceID string) {
	t.Helper()
	permissionsStore := resourcepermissions.NewStore(cfg, sqlStore, featuremgmt.WithFeatures())
	_, err := permissionsStore.SetUserResourcePermission(ctx, orgID, accesscontrol.User{ID: userID}, resourcepermissions.SetResourcePermissionCommand{
		Actions:           []string{accesscontrol.ActionUsersRead},
		Resource:          "global.users",
		ResourceAttribute: "id",
		ResourceID:        resourceID,
	}, nil)
	require.NoError(t, err)
}

func grantGlobalUsersRead(t *testing.T, ctx context.Context, sqlStore db.DB, userID int64) {
	t.Helper()
	acStore := database.ProvideService(sqlStore)
	roleName := accesscontrol.ManagedUserRoleName(userID)
	require.NoError(t, acStore.CreateRole(ctx, accesscontrol.RoleDTO{
		UID:  "test-global-users-reader",
		Name: roleName,
		Permissions: []accesscontrol.Permission{{
			Action: accesscontrol.ActionUsersRead,
			Scope:  accesscontrol.ScopeGlobalUsersAll,
		}},
	}))

	require.NoError(t, sqlStore.WithDbSession(ctx, func(sess *db.Session) error {
		role := accesscontrol.Role{}
		has, err := sess.Where("name = ?", roleName).Get(&role)
		if err != nil {
			return err
		}
		if !has {
			t.Fatal("global users reader role was not stored")
		}
		_, err = sess.Insert(&accesscontrol.UserRole{
			OrgID:   orgID,
			UserID:  userID,
			RoleID:  role.ID,
			Created: time.Now(),
		})
		return err
	}))
}

func viewerWithDBPermissions(t *testing.T, ctx context.Context, sqlStore db.DB, userID int64) *user.SignedInUser {
	t.Helper()
	usr := &user.SignedInUser{UserID: userID, OrgID: orgID, OrgRole: org.RoleViewer}
	permissions, err := database.ProvideService(sqlStore).GetUserPermissions(ctx, accesscontrol.GetUserPermissionsQuery{
		OrgID:        usr.GetOrgID(),
		UserID:       userID,
		Roles:        accesscontrol.GetOrgRoles(usr),
		TeamIDs:      usr.GetTeams(),
		RolePrefixes: acimpl.OSSRolesPrefixes,
	})
	require.NoError(t, err)
	usr.Permissions = map[int64]map[string][]string{
		usr.GetOrgID(): accesscontrol.GroupScopesByActionContext(ctx, permissions),
	}
	return usr
}

func getAnonymous(t *testing.T, server *webtest.Server, usr *user.SignedInUser, path string) (int, string) {
	t.Helper()
	req := server.NewGetRequest(path)
	webtest.RequestWithSignedInUser(req, usr)
	res, err := server.Send(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(body)
}

func requireNoStoredDevices(t *testing.T, status int, body string) {
	t.Helper()
	for _, marker := range []string{deviceAlpha, deviceBeta, ipAlpha, ipBeta, agentAlpha, agentBeta} {
		require.NotContains(t, body, marker, "status %d", status)
	}
}

func requireAllStoredDevices(t *testing.T, body string) {
	t.Helper()
	for _, marker := range []string{deviceAlpha, deviceBeta, ipAlpha, ipBeta, agentAlpha, agentBeta} {
		require.Contains(t, body, marker)
	}
}
