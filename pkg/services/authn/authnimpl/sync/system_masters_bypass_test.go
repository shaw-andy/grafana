package sync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	claims "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/apiserver/auth/authenticator"
	gfauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

// systemMasters is the Kubernetes group the built-in authorizer treats as
// privileged. These tests use the literal because that is the value a team UID
// or an external group has to match.
const systemMasters = "system:masters"

// TestTeamUIDSystemMastersDoesNotAuthorizeAnotherOrg starts from the user-sync
// hook that copies team UIDs into the identity groups, hands that identity to
// the API authenticator, and requires the built-in authorizer to deny a
// request aimed at a different organization.
func TestTeamUIDSystemMastersDoesNotAuthorizeAnotherOrg(t *testing.T) {
	identityTypes := []claims.IdentityType{claims.TypeUser, claims.TypeServiceAccount}
	verbs := []string{"list", "get", "create", "update", "patch", "delete", "watch", "deletecollection"}
	apiGroups := []string{
		"prometheus.datasource.grafana.app",
		"dashboard.grafana.app",
	}

	for _, identityType := range identityTypes {
		for _, verb := range verbs {
			for _, group := range apiGroups {
				t.Run(string(identityType)+" "+verb+" "+group, func(t *testing.T) {
					id := identityFromTeamUIDs(t, identityType, []string{systemMasters, "engineering"})
					decision, _ := authorize(t, id, verb, group, "datasources", "default")
					require.Equal(t, authorizer.DecisionDeny, decision)
				})
			}
		}
	}
}

// TestOrdinaryTeamUIDStillCannotCrossOrgs is the same path with a team UID
// that is not a Kubernetes system group. Cross-organization requests stay denied.
func TestOrdinaryTeamUIDStillCannotCrossOrgs(t *testing.T) {
	id := identityFromTeamUIDs(t, claims.TypeUser, []string{"engineering"})
	decision, _ := authorize(t, id, "list", "prometheus.datasource.grafana.app", "datasources", "default")
	require.Equal(t, authorizer.DecisionDeny, decision)
}

// TestExternalGroupSystemMastersDoesNotAuthorizeAnotherOrg runs the groups-claim
// hook (the path used when id_use_external_groups_for_groups_claim is on) and
// then the same authenticator and authorizer.
func TestExternalGroupSystemMastersDoesNotAuthorizeAnotherOrg(t *testing.T) {
	hook := ProvideGroupsClaimSync(&setting.Cfg{IDUseExternalGroupsForGroupsClaim: true})
	id := &authn.Identity{
		ID:             "7",
		UID:            "user-7",
		Type:           claims.TypeUser,
		OrgID:          2,
		Namespace:      "org-2",
		Login:          "org-two-admin",
		Name:           "Org Two Admin",
		OrgRoles:       map[int64]org.RoleType{2: org.RoleAdmin},
		ExternalGroups: []string{systemMasters, "engineering"},
		Groups:         []string{"engineering"},
	}
	require.NoError(t, hook.SyncGroupsClaimHook(context.Background(), id, &authn.Request{}))
	require.Contains(t, id.GetGroups(), "engineering")

	for _, verb := range []string{"list", "create"} {
		decision, _ := authorize(t, id, verb, "prometheus.datasource.grafana.app", "datasources", "default")
		require.Equal(t, authorizer.DecisionDeny, decision, verb)
	}
	// The hook must not publish a Kubernetes system group as this user's groups.
	require.NotContains(t, id.GetGroups(), systemMasters)
}

// TestAPIKeyAndAnonymousSystemMastersDoNotAuthorize covers identities that do
// not go through user sync but are still returned by the API authenticator.
func TestAPIKeyAndAnonymousSystemMastersDoNotAuthorize(t *testing.T) {
	cases := []struct {
		name string
		id   *authn.Identity
	}{
		{
			name: "api-key",
			id: &authn.Identity{
				ID:        "9",
				Type:      claims.TypeAPIKey,
				OrgID:     2,
				Namespace: "org-2",
				Name:      "org-two-key",
				OrgRoles:  map[int64]org.RoleType{2: org.RoleAdmin},
				Groups:    []string{systemMasters},
			},
		},
		{
			name: "anonymous",
			id: &authn.Identity{
				ID:        "0",
				Type:      claims.TypeAnonymous,
				OrgID:     2,
				Namespace: "org-2",
				Name:      "anonymous",
				OrgRoles:  map[int64]org.RoleType{2: org.RoleNone},
				Groups:    []string{systemMasters},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, _ := authorize(t, tc.id, "list", "prometheus.datasource.grafana.app", "datasources", "default")
			require.Equal(t, authorizer.DecisionDeny, decision)
		})
	}
}

func identityFromTeamUIDs(t *testing.T, identityType claims.IdentityType, teamUIDs []string) *authn.Identity {
	t.Helper()
	signedIn := &user.SignedInUser{
		UserID:    7,
		UserUID:   "user-7",
		OrgID:     2,
		OrgRole:   identity.RoleAdmin,
		Namespace: "org-2",
		Login:     "org-two-admin",
		Name:      "Org Two Admin",
		TeamUIDs:  teamUIDs,
	}
	if identityType == claims.TypeServiceAccount {
		signedIn.IsServiceAccount = true
	}
	id := &authn.Identity{ID: "7", Type: identityType}
	syncSignedInUserToIdentity(signedIn, id)
	return id
}

func authorize(t *testing.T, id *authn.Identity, verb, group, resource, namespace string) (authorizer.Decision, string) {
	t.Helper()
	ctx := identity.WithRequester(context.Background(), id)
	req := httptest.NewRequest(http.MethodGet, "/apis/"+group+"/v0alpha1/namespaces/"+namespace+"/"+resource, nil)
	req = req.WithContext(ctx)

	// The API authenticator is what turns the Grafana requester into the
	// Kubernetes user the authorizer reads groups from.
	res, ok, err := authenticator.NewAuthenticator().AuthenticateRequest(req)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, res.User)

	decision, reason, err := gfauthorizer.NewGrafanaBuiltInSTAuthorizer().Authorize(ctx, authorizer.AttributesRecord{
		User:            res.User,
		Verb:            verb,
		APIGroup:        group,
		APIVersion:      "v0alpha1",
		Resource:        resource,
		Namespace:       namespace,
		ResourceRequest: true,
	})
	require.NoError(t, err)
	return decision, reason
}
