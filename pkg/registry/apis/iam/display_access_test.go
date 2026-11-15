package iam

import (
	"context"
	"testing"

	authlib "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/iam/display"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing/licensingtest"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

func TestDisplayAccessPolicy(t *testing.T) {
	const orgID = int64(1)
	ns := authlib.NamespaceInfo{Value: "default", OrgID: orgID}
	ac := acimpl.ProvideAccessControl(featuremgmt.WithFeatures())

	license := func(enforce bool) *licensingtest.FakeLicensing {
		l := licensingtest.NewFakeLicensing()
		l.On("FeatureEnabled", "accesscontrol.enforcement").Return(enforce)
		return l
	}
	cfg := &setting.Cfg{HiddenUsers: map[string]struct{}{"hidden": {}}}

	member := display.Member{Type: authlib.TypeUser, UID: "u5", ID: 5, Login: "member"}
	otherMember := display.Member{Type: authlib.TypeUser, UID: "u6", ID: 6, Login: "other"}
	hiddenMember := display.Member{Type: authlib.TypeUser, UID: "u7", ID: 7, Login: "hidden"}
	serviceAccount := display.Member{Type: authlib.TypeServiceAccount, UID: "sa8", ID: 8, Login: "sa-1-svc"}
	otherServiceAccount := display.Member{Type: authlib.TypeServiceAccount, UID: "sa9", ID: 9, Login: "sa-1-other"}

	requester := func(perms map[string][]string) *user.SignedInUser {
		return &user.SignedInUser{
			UserID:      1,
			UserUID:     "caller",
			OrgID:       orgID,
			Login:       "caller",
			Permissions: map[int64]map[string][]string{orgID: perms},
		}
	}

	filterFor := func(t *testing.T, enforce bool, u identity.Requester, ns authlib.NamespaceInfo) display.MemberFilter {
		t.Helper()
		policy := newDisplayAccessPolicy(ac, license(enforce), cfg)
		allow, err := policy(identity.WithRequester(context.Background(), u), ns)
		require.NoError(t, err)
		if allow == nil {
			return func(display.Member) bool { return false }
		}
		return allow
	}

	t.Run("caller without lookup permissions resolves no one", func(t *testing.T) {
		allow := filterFor(t, false, requester(nil), ns)
		require.False(t, allow(member))
		require.False(t, allow(serviceAccount))
	})

	t.Run("org.users:read resolves users but not hidden users or service accounts", func(t *testing.T) {
		allow := filterFor(t, false, requester(map[string][]string{"org.users:read": {"users:*"}}), ns)
		require.True(t, allow(member))
		require.True(t, allow(otherMember))
		require.False(t, allow(hiddenMember))
		require.False(t, allow(serviceAccount))
	})

	t.Run("grafana admin resolves hidden users", func(t *testing.T) {
		u := requester(map[string][]string{"org.users:read": {"users:*"}})
		u.IsGrafanaAdmin = true
		allow := filterFor(t, false, u, ns)
		require.True(t, allow(hiddenMember))
	})

	t.Run("permission write grants lookup only without access control enforcement", func(t *testing.T) {
		perms := map[string][]string{"folders.permissions:write": {"folders:uid:f1"}}
		require.True(t, filterFor(t, false, requester(perms), ns)(member))
		require.False(t, filterFor(t, true, requester(perms), ns)(member))
	})

	t.Run("access control enforcement scopes users by id", func(t *testing.T) {
		allow := filterFor(t, true, requester(map[string][]string{"org.users:read": {"users:id:5"}}), ns)
		require.True(t, allow(member))
		require.False(t, allow(otherMember))
	})

	t.Run("service accounts require serviceaccounts:read on that account", func(t *testing.T) {
		allow := filterFor(t, false, requester(map[string][]string{"serviceaccounts:read": {"serviceaccounts:id:8"}}), ns)
		require.True(t, allow(serviceAccount))
		require.False(t, allow(otherServiceAccount))
		require.False(t, allow(member))
	})

	t.Run("permissions do not apply to another organization", func(t *testing.T) {
		u := requester(map[string][]string{"org.users:read": {"users:*"}})
		other := authlib.NamespaceInfo{Value: "org-2", OrgID: 2}
		require.False(t, filterFor(t, false, u, other)(member))
	})
}

func TestDisplayAuthorizer(t *testing.T) {
	ctx := identity.WithRequester(context.Background(), &user.SignedInUser{UserID: 1, OrgID: 1})

	attrs := func(verb, name string) authorizer.AttributesRecord {
		return authorizer.AttributesRecord{
			ResourceRequest: true,
			Verb:            verb,
			Resource:        "display",
			Namespace:       "default",
			Name:            name,
		}
	}

	decision, _, err := displayAuthorizer.Authorize(ctx, attrs("list", ""))
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)

	decision, _, err = displayAuthorizer.Authorize(ctx, attrs("get", "u1"))
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionDeny, decision)

	decision, _, err = displayAuthorizer.Authorize(context.Background(), attrs("list", ""))
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionDeny, decision)
}
