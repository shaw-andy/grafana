package rulesequence

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/user"
)

// folderEditorCtx can write rules in folder-a, only read them in folder-b, and
// has no access to folder-c.
func folderEditorCtx() context.Context {
	a := folder.ScopeFoldersProvider.GetResourceScopeUID("folder-a")
	b := folder.ScopeFoldersProvider.GetResourceScopeUID("folder-b")
	return identity.WithRequester(context.Background(), &user.SignedInUser{
		UserID: 2,
		OrgID:  1,
		Permissions: map[int64]map[string][]string{1: {
			folder.ActionFoldersRead:               {a, b},
			accesscontrol.ActionAlertingRuleRead:   {a, b},
			accesscontrol.ActionAlertingRuleCreate: {a},
			accesscontrol.ActionAlertingRuleUpdate: {a},
			accesscontrol.ActionAlertingRuleDelete: {a},
		}},
	})
}

func adminCtx() context.Context {
	all := folder.ScopeFoldersProvider.GetResourceAllScope()
	return identity.WithRequester(context.Background(), &user.SignedInUser{
		UserID: 1,
		OrgID:  1,
		Permissions: map[int64]map[string][]string{1: {
			folder.ActionFoldersRead:               {all},
			accesscontrol.ActionAlertingRuleRead:   {all},
			accesscontrol.ActionAlertingRuleCreate: {all},
			accesscontrol.ActionAlertingRuleUpdate: {all},
			accesscontrol.ActionAlertingRuleDelete: {all},
		}},
	})
}

func sequenceIn(name, folderUID string) *model.RuleSequence {
	return &model.RuleSequence{ObjectMeta: metav1.ObjectMeta{
		Name:            name,
		ResourceVersion: "1",
		Annotations:     map[string]string{model.FolderAnnotationKey: folderUID},
	}}
}

func requireForbidden(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	require.True(t, apierrors.IsForbidden(err), "expected forbidden, got %v", err)
}

func TestStorageAuthorizer(t *testing.T) {
	authz := NewStorageAuthorizer(acimpl.ProvideAccessControlTest())
	ctx := folderEditorCtx()

	t.Run("create requires rule write in the sequence folder", func(t *testing.T) {
		require.NoError(t, authz.BeforeCreate(ctx, sequenceIn("s", "folder-a")))
		requireForbidden(t, authz.BeforeCreate(ctx, sequenceIn("s", "folder-b")))
		requireForbidden(t, authz.BeforeCreate(ctx, sequenceIn("s", "folder-c")))
		requireForbidden(t, authz.BeforeCreate(ctx, sequenceIn("s", "")))
	})

	t.Run("update is authorized against the stored folder and the new folder", func(t *testing.T) {
		require.NoError(t, authz.BeforeUpdate(ctx, sequenceIn("s", "folder-a"), sequenceIn("s", "folder-a")))
		requireForbidden(t, authz.BeforeUpdate(ctx, sequenceIn("s", "folder-b"), sequenceIn("s", "folder-b")))
		requireForbidden(t, authz.BeforeUpdate(ctx, sequenceIn("s", "folder-c"), sequenceIn("s", "folder-a")))
		requireForbidden(t, authz.BeforeUpdate(ctx, sequenceIn("s", "folder-a"), sequenceIn("s", "folder-b")))
	})

	t.Run("an update that creates the sequence is authorized as a create", func(t *testing.T) {
		require.NoError(t, authz.BeforeUpdate(ctx, &model.RuleSequence{}, sequenceIn("s", "folder-a")))
		requireForbidden(t, authz.BeforeUpdate(ctx, &model.RuleSequence{}, sequenceIn("s", "folder-b")))
	})

	t.Run("delete requires rule delete in the stored folder", func(t *testing.T) {
		require.NoError(t, authz.BeforeDelete(ctx, sequenceIn("s", "folder-a")))
		requireForbidden(t, authz.BeforeDelete(ctx, sequenceIn("s", "folder-b")))
		requireForbidden(t, authz.BeforeDelete(ctx, sequenceIn("s", "folder-c")))
	})

	t.Run("get requires rule read in the stored folder", func(t *testing.T) {
		require.NoError(t, authz.AfterGet(ctx, sequenceIn("s", "folder-a")))
		require.NoError(t, authz.AfterGet(ctx, sequenceIn("s", "folder-b")))
		requireForbidden(t, authz.AfterGet(ctx, sequenceIn("s", "folder-c")))
	})

	t.Run("list keeps only sequences in readable folders", func(t *testing.T) {
		list := &model.RuleSequenceList{Items: []model.RuleSequence{
			*sequenceIn("seq-a", "folder-a"),
			*sequenceIn("seq-c", "folder-c"),
			*sequenceIn("seq-b", "folder-b"),
			*sequenceIn("seq-none", ""),
		}}
		got, err := authz.FilterList(ctx, list)
		require.NoError(t, err)
		names := []string{}
		for _, item := range got.(*model.RuleSequenceList).Items {
			names = append(names, item.Name)
		}
		require.Equal(t, []string{"seq-a", "seq-b"}, names)
	})

	t.Run("watch forwards only events for readable folders", func(t *testing.T) {
		filter, err := authz.WatchFilter(ctx)
		require.NoError(t, err)
		allowed, err := filter([]watch.Event{
			{Type: watch.Added, Object: sequenceIn("seq-a", "folder-a")},
			{Type: watch.Modified, Object: sequenceIn("seq-c", "folder-c")},
			{Type: watch.Deleted, Object: sequenceIn("seq-b", "folder-b")},
		})
		require.NoError(t, err)
		require.Equal(t, []bool{true, false, true}, allowed)
	})

	t.Run("org-wide rule access is allowed everywhere", func(t *testing.T) {
		admin := adminCtx()
		require.NoError(t, authz.BeforeCreate(admin, sequenceIn("s", "folder-c")))
		require.NoError(t, authz.BeforeUpdate(admin, sequenceIn("s", "folder-c"), sequenceIn("s", "folder-b")))
		require.NoError(t, authz.BeforeDelete(admin, sequenceIn("s", "folder-c")))
		require.NoError(t, authz.AfterGet(admin, sequenceIn("s", "folder-c")))
	})

	t.Run("Grafana's service identity is not filtered", func(t *testing.T) {
		svc, _ := identity.WithServiceIdentity(context.Background(), 1)
		require.NoError(t, authz.BeforeCreate(svc, sequenceIn("s", "folder-c")))
		require.NoError(t, authz.AfterGet(svc, sequenceIn("s", "folder-c")))
		got, err := authz.FilterList(svc, &model.RuleSequenceList{Items: []model.RuleSequence{*sequenceIn("seq-c", "folder-c")}})
		require.NoError(t, err)
		require.Len(t, got.(*model.RuleSequenceList).Items, 1)
	})
}

func TestAuthorizeSubresourceRequiresAllFolders(t *testing.T) {
	ac := acimpl.ProvideAccessControlTest()
	statusRequest := func(verb string) authorizer.AttributesRecord {
		return authorizer.AttributesRecord{
			Verb:            verb,
			Resource:        ResourceInfo.GroupResource().Resource,
			Subresource:     "status",
			Name:            "seq-c",
			ResourceRequest: true,
		}
	}

	for _, verb := range []string{"get", "update", "patch"} {
		decision, _, _ := Authorize(folderEditorCtx(), ac, statusRequest(verb))
		require.Equal(t, authorizer.DecisionDeny, decision, verb)

		decision, _, err := Authorize(adminCtx(), ac, statusRequest(verb))
		require.NoError(t, err)
		require.Equal(t, authorizer.DecisionAllow, decision, verb)
	}

	decision, _, err := Authorize(folderEditorCtx(), ac, authorizer.AttributesRecord{
		Verb:            "get",
		Resource:        ResourceInfo.GroupResource().Resource,
		Name:            "seq-a",
		ResourceRequest: true,
	})
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision, "the folder scope of a resource request is left to the storage authorizer")
}
