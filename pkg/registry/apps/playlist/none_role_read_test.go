package playlist

import (
	"context"
	"testing"

	claims "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	grafanaauthorizer "github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer"
)

// TestNoneRoleCannotReadPlaylistsWhenRBACDisabled runs the playlist authorizer
// inside the same Grafana authorizer chain the API server installs
// (impersonation, privileged groups, namespace, per-group authorizer, org role).
// With playlistsRBAC off, a requester whose organization role is None must not
// be allowed to get, list, or watch playlists. Viewer reads stay allowed by the
// org-role authorizer, which is the path every role other than None already uses.
func TestNoneRoleCannotReadPlaylistsWhenRBACDisabled(t *testing.T) {
	chain := grafanaauthorizer.NewGrafanaBuiltInSTAuthorizer()
	// Registered once. Each subtest rebinds the OpenFeature test provider to
	// that subtest before calling Authorize, which is what the provider requires.
	var playlistAuth authorizer.Authorizer
	for _, version := range []string{"v0alpha1", "v1"} {
		chain.Register(schema.GroupVersion{Group: "playlist.grafana.app", Version: version}, authorizer.AuthorizerFunc(
			func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
				return playlistAuth.Authorize(ctx, attr)
			},
		))
	}

	readVerbs := []string{"get", "list", "watch"}
	versions := []string{"v0alpha1", "v1"}
	cases := []struct {
		resource    string
		subresource string
	}{
		{resource: "playlists"},
		{resource: "playlists", subresource: "status"},
	}

	for _, idType := range []claims.IdentityType{claims.TypeUser, claims.TypeServiceAccount} {
		t.Run(string(idType), func(t *testing.T) {
			playlistAuth = installerWithToggle(t, false, &mockAccessControl{}).GetAuthorizer()
			requester := &identity.StaticRequester{
				Type:      idType,
				UserID:    42,
				UserUID:   "none-reader",
				Login:     "none-reader",
				Name:      "none-reader",
				OrgID:     1,
				Namespace: "default",
				OrgRole:   identity.RoleNone,
			}
			ctx := identity.WithRequester(context.Background(), requester)

			for _, version := range versions {
				for _, verb := range readVerbs {
					for _, tc := range cases {
						name := "collected-dashboards"
						if verb != "get" {
							name = ""
						}
						attrs := authorizer.AttributesRecord{
							User:            requester,
							Verb:            verb,
							Namespace:       "default",
							APIGroup:        "playlist.grafana.app",
							APIVersion:      version,
							Resource:        tc.resource,
							Subresource:     tc.subresource,
							Name:            name,
							ResourceRequest: true,
						}
						decision, _, err := chain.Authorize(ctx, attrs)
						require.NoError(t, err)
						require.Equal(t, authorizer.DecisionDeny, decision,
							"%s %s %s/%s subresource=%q", idType, verb, version, tc.resource, tc.subresource)
					}
				}
			}

			for _, verb := range []string{"create", "update", "patch", "delete", "deletecollection"} {
				attrs := authorizer.AttributesRecord{
					User:            requester,
					Verb:            verb,
					Namespace:       "default",
					APIGroup:        "playlist.grafana.app",
					APIVersion:      "v1",
					Resource:        "playlists",
					Name:            "collected-dashboards",
					ResourceRequest: true,
				}
				decision, _, err := chain.Authorize(ctx, attrs)
				require.NoError(t, err)
				require.Equal(t, authorizer.DecisionDeny, decision, "write verb %s", verb)
			}
		})
	}

	t.Run("viewer reads remain allowed", func(t *testing.T) {
		playlistAuth = installerWithToggle(t, false, &mockAccessControl{}).GetAuthorizer()
		requester := &identity.StaticRequester{
			Type:      claims.TypeUser,
			UserID:    7,
			UserUID:   "viewer",
			Login:     "viewer",
			Name:      "viewer",
			OrgID:     1,
			Namespace: "default",
			OrgRole:   identity.RoleViewer,
		}
		ctx := identity.WithRequester(context.Background(), requester)
		for _, verb := range readVerbs {
			attrs := authorizer.AttributesRecord{
				User:            requester,
				Verb:            verb,
				Namespace:       "default",
				APIGroup:        "playlist.grafana.app",
				APIVersion:      "v1",
				Resource:        "playlists",
				Name:            "collected-dashboards",
				ResourceRequest: true,
			}
			decision, _, err := chain.Authorize(ctx, attrs)
			require.NoError(t, err)
			require.Equal(t, authorizer.DecisionAllow, decision, "viewer %s", verb)
		}
	})
}
