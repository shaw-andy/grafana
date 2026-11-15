package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/auth/authtest"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/org/orgtest"
	tempuser "github.com/grafana/grafana/pkg/services/temp_user"
	"github.com/grafana/grafana/pkg/services/temp_user/tempusertest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/services/user/usertest"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web/webtest"
)

// pendingAdminInviteCode is the invite secret seeded for these tests.
// It is a placeholder, not a captured credential.
const pendingAdminInviteCode = "placeholder-invite-code"

const pendingAdminInviteEmail = "admin-invite@example.com"

// inviteMemory mirrors tempuserimpl store filtering: pending invites for an org
// are returned with their code, and status updates apply to the invite with that code.
type inviteMemory struct {
	mu      sync.Mutex
	invites []*tempuser.TempUserDTO
}

func (s *inviteMemory) list(_ context.Context, query *tempuser.GetTempUsersQuery) ([]*tempuser.TempUserDTO, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*tempuser.TempUserDTO, 0)
	for _, invite := range s.invites {
		if query.OrgID > 0 && invite.OrgID != query.OrgID {
			continue
		}
		if query.Status != "" && invite.Status != query.Status {
			continue
		}
		if query.Email != "" && !strings.EqualFold(invite.Email, query.Email) {
			continue
		}
		copied := *invite
		out = append(out, &copied)
	}
	return out, nil
}

func (s *inviteMemory) byCode(_ context.Context, query *tempuser.GetTempUserByCodeQuery) (*tempuser.TempUserDTO, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, invite := range s.invites {
		if invite.Code == query.Code {
			copied := *invite
			return &copied, nil
		}
	}
	return nil, tempuser.ErrTempUserNotFound
}

func (s *inviteMemory) updateStatus(_ context.Context, cmd *tempuser.UpdateTempUserStatusCommand) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, invite := range s.invites {
		if invite.Code == cmd.Code {
			invite.Status = cmd.Status
			return nil
		}
	}
	return tempuser.ErrTempUserNotFound
}

func (s *inviteMemory) status(code string) tempuser.TempUserStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, invite := range s.invites {
		if invite.Code == code {
			return invite.Status
		}
	}
	return ""
}

type recordingOrgService struct {
	*orgtest.FakeOrgService
	added []org.AddOrgUserCommand
}

func (r *recordingOrgService) AddOrgUser(_ context.Context, cmd *org.AddOrgUserCommand) error {
	r.added = append(r.added, *cmd)
	return nil
}

func TestOrgInviteListAndRevokeBindOrgUsersAddScope(t *testing.T) {
	tests := []struct {
		name        string
		permissions []accesscontrol.Permission
		allow       bool
	}{
		{
			name: "single user id scope",
			permissions: []accesscontrol.Permission{{
				Action: accesscontrol.ActionOrgUsersAdd,
				Scope:  "users:id:7",
			}},
		},
		{
			name: "every user id scope",
			permissions: []accesscontrol.Permission{{
				Action: accesscontrol.ActionOrgUsersAdd,
				Scope:  "users:id:*",
			}},
		},
		{
			name: "missing org users add",
			permissions: []accesscontrol.Permission{{
				Action: accesscontrol.ActionOrgUsersRead,
				Scope:  accesscontrol.ScopeUsersAll,
			}},
		},
		{
			name:        "no permissions",
			permissions: nil,
		},
		{
			name: "users wildcard",
			permissions: []accesscontrol.Permission{{
				Action: accesscontrol.ActionOrgUsersAdd,
				Scope:  accesscontrol.ScopeUsersAll,
			}},
			allow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &inviteMemory{invites: []*tempuser.TempUserDTO{{
				ID:     1,
				OrgID:  1,
				Email:  pendingAdminInviteEmail,
				Name:   "Pending Admin",
				Role:   org.RoleAdmin,
				Code:   pendingAdminInviteCode,
				Status: tempuser.TmpUserInvitePending,
			}}}
			tempUsers := &tempusertest.FakeTempUserService{
				GetTempUsersQueryFN:    store.list,
				GetTempUserByCodeFN:    store.byCode,
				UpdateTempUserStatusFN: store.updateStatus,
			}
			orgSvc := &recordingOrgService{FakeOrgService: orgtest.NewOrgServiceFake()}
			userSvc := &usertest.FakeUserService{}
			userSvc.CreateFn = func(_ context.Context, cmd *user.CreateUserCommand) (*user.User, error) {
				return &user.User{
					ID:    100,
					Email: cmd.Email,
					Login: cmd.Login,
					Name:  cmd.Name,
				}, nil
			}
			userSvc.UpdateFn = func(_ context.Context, _ *user.UpdateUserCommand) error {
				return nil
			}

			server := SetupAPITestServer(t, func(hs *HTTPServer) {
				hs.Cfg = setting.NewCfg()
				hs.log = log.New("org-invite-scope-test")
				hs.bus = bus.ProvideBus(tracing.InitializeTracerForTest())
				hs.tempUserService = tempUsers
				hs.orgService = orgSvc
				hs.userService = userSvc
				hs.AuthTokenService = authtest.NewFakeUserAuthTokenService()
			})

			caller := authedUserWithPermissions(42, 1, tt.permissions)
			listResp, err := server.Send(webtest.RequestWithSignedInUser(
				server.NewGetRequest("/api/org/invites"),
				caller,
			))
			require.NoError(t, err)
			listBody, err := io.ReadAll(listResp.Body)
			require.NoError(t, err)
			require.NoError(t, listResp.Body.Close())

			disclosed := inviteCodes(t, listResp.StatusCode, listBody)
			if !tt.allow {
				for _, code := range disclosed {
					completeInvite(t, server, code)
				}
			}

			revokeResp, err := server.SendJSON(webtest.RequestWithSignedInUser(
				server.NewRequest(http.MethodPatch, "/api/org/invites/"+pendingAdminInviteCode+"/revoke", nil),
				caller,
			))
			require.NoError(t, err)
			revokeBody, err := io.ReadAll(revokeResp.Body)
			require.NoError(t, err)
			require.NoError(t, revokeResp.Body.Close())

			if tt.allow {
				require.Equal(t, http.StatusOK, listResp.StatusCode, "users:* may list pending invites: %s", listBody)
				require.Contains(t, disclosed, pendingAdminInviteCode)
				require.Equal(t, http.StatusOK, revokeResp.StatusCode, "users:* may revoke the listed invite: %s", revokeBody)
				require.Equal(t, tempuser.TmpUserRevoked, store.status(pendingAdminInviteCode))
				require.Empty(t, orgSvc.added)
				return
			}

			require.Emptyf(t, orgSvc.added, "disclosed invite codes must not create an org admin, list status %d, revoke status %d, invite status %s", listResp.StatusCode, revokeResp.StatusCode, store.status(pendingAdminInviteCode))
			require.Equalf(t, http.StatusForbidden, listResp.StatusCode, "list body: %s", listBody)
			require.NotContains(t, string(listBody), pendingAdminInviteCode)
			require.NotContains(t, disclosed, pendingAdminInviteCode)
			require.Equalf(t, http.StatusForbidden, revokeResp.StatusCode, "revoke body: %s", revokeBody)
			require.Equal(t, tempuser.TmpUserInvitePending, store.status(pendingAdminInviteCode))
		})
	}
}

func inviteCodes(t *testing.T, status int, body []byte) []string {
	t.Helper()
	if status != http.StatusOK {
		return nil
	}
	var invites []*tempuser.TempUserDTO
	require.NoError(t, json.Unmarshal(body, &invites))
	codes := make([]string, 0, len(invites))
	for _, invite := range invites {
		if invite.Code != "" {
			codes = append(codes, invite.Code)
		}
		require.Equal(t, org.RoleAdmin, invite.Role)
	}
	return codes
}

func completeInvite(t *testing.T, server *webtest.Server, code string) {
	t.Helper()
	body := `{"inviteCode":"` + code + `","email":"` + pendingAdminInviteEmail + `","name":"Pending Admin","username":"invited-admin","password":"placeholder","confirmPassword":"placeholder"}`
	resp, err := server.SendJSON(server.NewPostRequest("/api/user/invite/complete", strings.NewReader(body)))
	require.NoError(t, err)
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, "completing a disclosed invite code: %s", responseBody)
}
