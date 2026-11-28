package team

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/grafana/authlib/types"
	iamv0alpha1 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/registry/apis/iam/legacy"
	"github.com/grafana/grafana/pkg/services/team"
)

func TestLegacyStoreCreateRejectsSystemPrefixName(t *testing.T) {
	for _, name := range []string{"system:masters", "system:authenticated", "system:"} {
		t.Run(name, func(t *testing.T) {
			store := &recordingTeamStore{}
			created, err := createTeam(t, store, name)
			require.Error(t, err)
			require.Nil(t, created)
			require.Nil(t, store.created, "the team row must not be written when the name is rejected")
		})
	}
}

func TestLegacyStoreCreateKeepsNonSystemColonName(t *testing.T) {
	store := &recordingTeamStore{}
	created, err := createTeam(t, store, "my:team")
	require.NoError(t, err)
	require.NotNil(t, created)
	require.NotNil(t, store.created)
	require.Equal(t, "my:team", store.created.UID)
	require.Equal(t, "my:team", created.GetName())
	require.Equal(t, "user-7", store.created.MemberCreates[0].UserUID)
}

func createTeam(t *testing.T, store *recordingTeamStore, name string) (*iamv0alpha1.Team, error) {
	t.Helper()
	legacyStore := NewLegacyStore(store, nil, noop.NewTracerProvider().Tracer("test"), legacy.NoopExternalGroupReconciler{})
	obj := &iamv0alpha1.Team{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "org-2"},
		Spec: iamv0alpha1.TeamSpec{
			Title: "Innocent title",
			Members: []iamv0alpha1.TeamTeamMember{{
				Kind:       "User",
				Name:       "user-7",
				Permission: iamv0alpha1.TeamTeamPermissionMember,
			}},
		},
	}
	ctx := identity.WithRequester(context.Background(), &identity.StaticRequester{
		Type:      types.TypeUser,
		UserID:    7,
		UserUID:   "user-7",
		OrgID:     2,
		Namespace: "org-2",
		OrgRole:   identity.RoleAdmin,
	})
	ctx = genericapirequest.WithNamespace(ctx, "org-2")

	// Same validation the IAM admission hook passes into storage Create.
	validate := rest.ValidateObjectFunc(func(ctx context.Context, obj runtime.Object) error {
		teamObj, ok := obj.(*iamv0alpha1.Team)
		if !ok {
			return errNotATeam
		}
		return ValidateOnCreate(ctx, &fakeTeamSearchClient{}, teamObj, legacy.NoopExternalGroupReconciler{})
	})
	out, err := legacyStore.Create(ctx, obj, validate, nil)
	if err != nil {
		return nil, err
	}
	created, ok := out.(*iamv0alpha1.Team)
	require.True(t, ok)
	return created, nil
}

type errString string

func (e errString) Error() string { return string(e) }

var errNotATeam = errString("expected team")

type recordingTeamStore struct {
	legacy.LegacyIdentityStore
	created *legacy.CreateTeamCommand
}

func (s *recordingTeamStore) GetUserInternalID(_ context.Context, _ types.NamespaceInfo, q legacy.GetUserInternalIDQuery) (*legacy.GetUserInternalIDResult, error) {
	if q.UID != "user-7" {
		return nil, errString("unknown user")
	}
	return &legacy.GetUserInternalIDResult{ID: 7}, nil
}

func (s *recordingTeamStore) CreateTeam(_ context.Context, _ types.NamespaceInfo, cmd legacy.CreateTeamCommand) (*legacy.CreateTeamResult, error) {
	copied := cmd
	s.created = &copied
	return &legacy.CreateTeamResult{Team: team.Team{
		ID:    1,
		UID:   cmd.UID,
		Name:  cmd.Name,
		OrgID: cmd.OrgID,
	}}, nil
}

func (s *recordingTeamStore) ListTeamBindings(context.Context, types.NamespaceInfo, legacy.ListTeamBindingsQuery) (*legacy.ListTeamBindingsResult, error) {
	return &legacy.ListTeamBindingsResult{}, nil
}
