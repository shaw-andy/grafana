package user

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	authlib "github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	iam "github.com/grafana/grafana/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/tests/apis"
	"github.com/grafana/grafana/pkg/tests/testinfra"
	"github.com/grafana/grafana/pkg/util/testutil"
)

// TestIntegrationDisplayMemberEnumeration locks the IAM display API to the same
// audience as GET /api/org/users/lookup.
//
// A caller who is forbidden from that lookup, and a caller for whom lookup
// omits a hidden member, must not learn the member's display name (including
// the login or email fallback), UID, internal id, identity type, or avatar
// URL. The check has to apply to the organization the handler resolves: a
// grant in another organization must not reveal this organization's members,
// and a key for a member of another organization must not be returned.
//
// The same GET is the only display operation that resolves caller-supplied
// keys. It is parsed as a namespaced list. Verb get on display is marked the
// same way in the authorizer but has no handler that resolves keys; this test
// still requests a named path so a response there cannot carry member data.
// searchTeams is a different unchecked resource and is not covered here.
func TestIntegrationDisplayMemberEnumeration(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)

	helper := apis.NewK8sTestHelper(t, testinfra.GrafanaOpts{
		AppModeProduction: false,
		DisableAnonymous:  true,
		EnableFeatureToggles: []string{
			featuremgmt.FlagGrafanaAPIServerWithExperimentalAPIs,
		},
	})
	t.Cleanup(func() {
		helper.Shutdown()
	})

	org1NS := helper.Namespacer(helper.Org1.Admin.Identity.GetOrgID())
	orgBNS := helper.Namespacer(helper.OrgB.Admin.Identity.GetOrgID())
	require.NotEqual(t, org1NS, orgBNS)

	named := createOrgMember(t, helper, helper.Org1.Admin, memberSpec{
		name:  "Directory Member Alpha",
		login: "directory-member-alpha",
		email: "directory-member-alpha@example.com",
		orgID: helper.Org1.Admin.Identity.GetOrgID(),
	})
	// No name: the display fallback is the login, then the email. Login is
	// distinct from the email so either value showing up is a disclosure.
	nameless := createOrgMember(t, helper, helper.Org1.Admin, memberSpec{
		name:  "",
		login: "nameless-display-login",
		email: "nameless-display@example.com",
		orgID: helper.Org1.Admin.Identity.GetOrgID(),
	})
	hidden := createOrgMember(t, helper, helper.Org1.Admin, memberSpec{
		name:  "Hidden Org Member",
		login: "hidden-org-member",
		email: "hidden-org-member@example.com",
		orgID: helper.OrgB.Admin.Identity.GetOrgID(),
	})
	helper.GetEnv().Cfg.HiddenUsers[hidden.login] = struct{}{}
	t.Cleanup(func() {
		delete(helper.GetEnv().Cfg.HiddenUsers, hidden.login)
	})

	editor := memberFromIdentity(t, helper.Org1.Editor)
	serviceAccount := member{
		id:    helper.Org1.ViewerServiceAccount.Id,
		uid:   helper.Org1.ViewerServiceAccount.UID,
		login: helper.Org1.ViewerServiceAccount.Login,
		email: "",
		name:  helper.Org1.ViewerServiceAccount.Name,
	}
	otherOrg := memberFromIdentity(t, helper.OrgB.Editor)

	org1Victims := []member{named, nameless, editor, serviceAccount, otherOrg}

	// Grant this caller org-admin in the other organization. A check that is
	// not bound to the organization being queried would treat that grant as
	// permission to read this organization's members.
	helper.AddUserToOrg(helper.Org1.Viewer, "OrgB", helper.OrgB.Admin.Identity.GetOrgRole())

	t.Run("lookup is forbidden for a viewer", func(t *testing.T) {
		status, body := getLookup(t, helper, helper.Org1.Viewer)
		require.Equal(t, http.StatusForbidden, status, "viewer must not be allowed to call org user lookup, body: %s", body)
	})

	t.Run("viewer cannot enumerate members by id or uid", func(t *testing.T) {
		keys := keysFor(org1Victims...)
		keys = append(keys, "user:"+named.uid, "user:"+strconv.FormatInt(named.id, 10))
		rsp := getDisplay(t, helper, helper.Org1.Viewer, org1NS, keys)
		assertMembersAbsent(t, rsp, org1Victims)
	})

	t.Run("single key lookup is not exempt", func(t *testing.T) {
		rsp := getDisplay(t, helper, helper.Org1.Viewer, org1NS, []string{nameless.uid})
		assertMembersAbsent(t, rsp, []member{nameless})
	})

	t.Run("editor and org role none cannot enumerate members", func(t *testing.T) {
		for _, caller := range []apis.User{helper.Org1.Editor, helper.Org1.None} {
			t.Run(string(caller.Identity.GetOrgRole()), func(t *testing.T) {
				status, body := getLookup(t, helper, caller)
				require.Equal(t, http.StatusForbidden, status, "body: %s", body)
				rsp := getDisplay(t, helper, caller, org1NS, keysFor(named, nameless, serviceAccount))
				assertMembersAbsent(t, rsp, []member{named, nameless, serviceAccount})
			})
		}
	})

	t.Run("viewer service account cannot enumerate members", func(t *testing.T) {
		rsp := getDisplayWithToken(t, helper, helper.Org1.ViewerServiceAccountToken, org1NS, keysFor(named, nameless))
		assertMembersAbsent(t, rsp, []member{named, nameless})
	})

	t.Run("anonymous request is rejected", func(t *testing.T) {
		path := displayPath(org1NS, []string{named.uid})
		rsp := apis.DoRequest(helper, apis.RequestParams{Method: http.MethodGet, Path: path}, &iam.DisplayList{})
		require.Equal(t, http.StatusUnauthorized, rsp.Response.StatusCode)
		assertMembersAbsent(t, rsp, []member{named})
	})

	t.Run("named display path does not return members", func(t *testing.T) {
		path := fmt.Sprintf("/apis/iam.grafana.app/v0alpha1/namespaces/%s/display/%s", org1NS, url.PathEscape(named.uid))
		rsp := apis.DoRequest(helper, apis.RequestParams{
			User:   helper.Org1.Viewer,
			Method: http.MethodGet,
			Path:   path,
		}, &iam.DisplayList{})
		assertMembersAbsent(t, rsp, org1Victims)
	})

	t.Run("keys for another organization are not resolved in this namespace", func(t *testing.T) {
		rsp := getDisplay(t, helper, helper.Org1.Viewer, org1NS, keysFor(otherOrg))
		assertMembersAbsent(t, rsp, []member{otherOrg})
	})

	t.Run("caller who is not a member cannot read another organization namespace", func(t *testing.T) {
		// Org1 editor and none are not members of org B. Org1 viewer is, so that
		// identity is not used here: membership in the target org is a separate case.
		for _, caller := range []apis.User{helper.Org1.Editor, helper.Org1.None} {
			t.Run(string(caller.Identity.GetOrgRole()), func(t *testing.T) {
				rsp := getDisplay(t, helper, caller, orgBNS, keysFor(otherOrg, hidden))
				require.Contains(t, []int{http.StatusForbidden, http.StatusUnauthorized}, rsp.Response.StatusCode, "body: %s", rsp.Body)
				assertMembersAbsent(t, rsp, []member{otherOrg, hidden})
			})
		}
	})

	t.Run("hidden member omitted by lookup is omitted by display", func(t *testing.T) {
		status, body := getLookup(t, helper, helper.OrgB.Admin)
		require.Equal(t, http.StatusOK, status, "org admin should be able to call lookup, body: %s", body)
		var listed []dtos.UserLookupDTO
		require.NoError(t, json.Unmarshal(body, &listed))
		for _, u := range listed {
			require.NotEqual(t, hidden.login, u.Login)
			require.NotEqual(t, hidden.uid, u.UID)
		}

		rsp := getDisplay(t, helper, helper.OrgB.Admin, orgBNS, keysFor(hidden))
		assertMembersAbsent(t, rsp, []member{hidden})
	})

	t.Run("org admin can still resolve a member lookup would return", func(t *testing.T) {
		status, body := getLookup(t, helper, helper.Org1.Admin)
		require.Equal(t, http.StatusOK, status, "body: %s", body)
		rsp := getDisplay(t, helper, helper.Org1.Admin, org1NS, []string{named.uid, strconv.FormatInt(named.id, 10)})
		require.Equal(t, http.StatusOK, rsp.Response.StatusCode, "body: %s", rsp.Body)
		require.NotNil(t, rsp.Result)
		require.True(t, memberReturned(rsp.Result, named), "admin lookup of a visible member should still succeed")
	})
}

type memberSpec struct {
	name  string
	login string
	email string
	orgID int64
}

type member struct {
	id    int64
	uid   string
	login string
	email string
	name  string
}

func createOrgMember(t *testing.T, helper *apis.K8sTestHelper, admin apis.User, spec memberSpec) member {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"name":     spec.name,
		"email":    spec.email,
		"login":    spec.login,
		"password": "placeholder",
		"orgId":    spec.orgID,
	})
	require.NoError(t, err)

	var created user.AdminCreateUserResponse
	rsp := apis.DoRequest(helper, apis.RequestParams{
		User:   admin,
		Method: http.MethodPost,
		Path:   "/api/admin/users",
		Body:   payload,
	}, &created)
	require.Equal(t, http.StatusOK, rsp.Response.StatusCode, "body: %s", rsp.Body)
	require.NotZero(t, created.ID)
	require.NotEmpty(t, created.UID)
	t.Cleanup(func() {
		apis.DoRequest(helper, apis.RequestParams{
			User:   admin,
			Method: http.MethodDelete,
			Path:   fmt.Sprintf("/api/admin/users/%d", created.ID),
		}, &map[string]any{})
	})
	return member{id: created.ID, uid: created.UID, login: spec.login, email: spec.email, name: spec.name}
}

func memberFromIdentity(t *testing.T, u apis.User) member {
	t.Helper()
	id, err := identity.UserIdentifier(u.Identity.GetID())
	require.NoError(t, err)
	uid := u.Identity.GetRawIdentifier()
	if uid == "" {
		uid = u.Identity.GetUID()
	}
	return member{
		id:    id,
		uid:   uid,
		login: u.Identity.GetLogin(),
		email: u.Identity.GetEmail(),
		name:  u.Identity.GetName(),
	}
}

func keysFor(members ...member) []string {
	keys := make([]string, 0, len(members)*2)
	for _, m := range members {
		if m.uid != "" {
			keys = append(keys, m.uid)
		}
		if m.id != 0 {
			keys = append(keys, strconv.FormatInt(m.id, 10))
		}
	}
	return keys
}

func displayPath(namespace string, keys []string) string {
	q := url.Values{}
	for _, key := range keys {
		q.Add("key", key)
	}
	return fmt.Sprintf("/apis/iam.grafana.app/v0alpha1/namespaces/%s/display?%s", namespace, q.Encode())
}

func getDisplay(t *testing.T, helper *apis.K8sTestHelper, caller apis.User, namespace string, keys []string) apis.K8sResponse[iam.DisplayList] {
	t.Helper()
	return apis.DoRequest(helper, apis.RequestParams{
		User:   caller,
		Method: http.MethodGet,
		Path:   displayPath(namespace, keys),
	}, &iam.DisplayList{})
}

func getDisplayWithToken(t *testing.T, helper *apis.K8sTestHelper, token string, namespace string, keys []string) apis.K8sResponse[iam.DisplayList] {
	t.Helper()
	return apis.DoRequest(helper, apis.RequestParams{
		Method:  http.MethodGet,
		Path:    displayPath(namespace, keys),
		Headers: map[string]string{"Authorization": "Bearer " + token},
	}, &iam.DisplayList{})
}

func getLookup(t *testing.T, helper *apis.K8sTestHelper, caller apis.User) (int, []byte) {
	t.Helper()
	rsp := apis.DoRequest(helper, apis.RequestParams{
		User:   caller,
		Method: http.MethodGet,
		Path:   "/api/org/users/lookup",
	}, &[]dtos.UserLookupDTO{})
	return rsp.Response.StatusCode, rsp.Body
}

func assertMembersAbsent(t *testing.T, rsp apis.K8sResponse[iam.DisplayList], victims []member) {
	t.Helper()
	body := string(rsp.Body)
	if rsp.Result != nil {
		var leaks []string
		for _, victim := range victims {
			item, ok := returnedMember(rsp.Result, victim)
			if !ok {
				continue
			}
			leaks = append(leaks, fmt.Sprintf("uid %s id %d name %q login %q as identity %s/%s displayName %q avatar %q",
				victim.uid, victim.id, victim.name, victim.login,
				item.Identity.Type, item.Identity.Name, item.DisplayName, item.AvatarURL))
		}
		require.Empty(t, leaks)
	}
	// The request keys are echoed in a successful display document. Those keys
	// are values the caller already supplied. Login, email, display name, and
	// the avatar hash are not, and must not come back for a member the caller
	// is not allowed to read.
	for _, victim := range victims {
		if victim.login != "" {
			require.NotContains(t, body, victim.login)
		}
		if victim.email != "" {
			require.NotContains(t, body, victim.email)
			require.NotContains(t, body, emailAvatarHash(victim.email))
		}
		if strings.Contains(victim.name, " ") {
			require.NotContains(t, body, victim.name)
		}
	}
}

func memberReturned(list *iam.DisplayList, victim member) bool {
	_, ok := returnedMember(list, victim)
	return ok
}

func returnedMember(list *iam.DisplayList, victim member) (iam.Display, bool) {
	for _, item := range list.Items {
		if victim.id != 0 && item.InternalID == victim.id {
			return item, true
		}
		if victim.uid != "" && item.Identity.Name == victim.uid {
			return item, true
		}
		if item.Identity.Type == authlib.TypeServiceAccount && victim.login != "" && item.DisplayName == victim.name && victim.name != "" {
			return item, true
		}
	}
	return iam.Display{}, false
}

func emailAvatarHash(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return fmt.Sprintf("%x", sum)
}
