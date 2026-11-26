package resource

import (
	"context"
	"slices"
	"strconv"
	"strings"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// TrashAuthorizer decides who may see a deleted object: whoever deleted it, or an
// admin of the folder it was in.
//
// Not the read check live search applies. Read access to a folder is common, so
// reusing it would disclose other people's deleted objects.
//
// One authorizer per request, because of the cache below.
type TrashAuthorizer struct {
	access claims.AccessClient
	user   claims.AuthInfo

	// Trash never federates, so one group and resource covers every candidate.
	key *resourcepb.ResourceKey

	// A UID only identifies someone within their own namespace.
	namespaceMatches bool

	rootFolder string

	// Cached because the check is a network call and a page of results usually
	// spans far fewer folders than items. Must not outlive the request, or a
	// permission change would never take effect.
	folderAdmin map[string]bool

	// The failure is swallowed, so report it or it is invisible.
	onCheckError func(err error)
}

func NewTrashAuthorizer(
	access claims.AccessClient,
	user claims.AuthInfo,
	key *resourcepb.ResourceKey,
	onCheckError func(err error),
) *TrashAuthorizer {
	return &TrashAuthorizer{
		access:           access,
		user:             user,
		key:              key,
		namespaceMatches: claims.NamespaceMatches(user.GetNamespace(), key.Namespace),
		rootFolder:       rootFolderFor(key.Group),
		folderAdmin:      map[string]bool{},
		onCheckError:     onCheckError,
	}
}

// k6FolderUID is hidden from anyone but a service account. The single check in
// authlib denies it outright, and BatchCheck has no such rule, so batching a
// decision for it would answer differently from every other path.
//
// Spelled here rather than imported from pkg/services/accesscontrol, which unified
// storage does not depend on.
const k6FolderUID = "k6-app"

// generalFolderUID is the root folder. Spelled here for the same reason as
// k6FolderUID.
const generalFolderUID = "general"

// rootFolderFor is the folder the admin check names for an object with no folder.
//
// A check with no folder and no name is read by authz as "may the caller do this
// anywhere", which administering a single object satisfies. So the root is named
// instead, and only an admin of the general folder, or of every folder, passes.
// Authz ignores the folder for the kinds it maps without folder support.
//
// Plugin kinds keep the empty folder: storage refuses the root for those that
// live in folders, so no folder means the kind has none, and authz then asks for
// the namespace-wide role the plugin grants, which is the question meant here.
func rootFolderFor(group string) string {
	if strings.HasSuffix(group, ".ext.grafana.app") {
		return ""
	}
	return generalFolderUID
}

func (a *TrashAuthorizer) checkedFolder(folder string) string {
	if folder == "" {
		return a.rootFolder
	}
	return folder
}

// TrashItem is one object Prepare may need a folder check for.
type TrashItem struct {
	Folder    string
	DeletedBy string
}

// Prepare resolves the folder checks items will need in one call per batch, so the
// Allowed calls that follow read the cache instead of waiting for a round trip each.
//
// Only a hint: a folder left undecided is checked on its own by FolderAdmin.
func (a *TrashAuthorizer) Prepare(ctx context.Context, items []TrashItem) {
	var pending []string
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		folder := a.checkedFolder(item.Folder)
		if a.deletedByCaller(item.DeletedBy) || seen[folder] || folder == k6FolderUID {
			continue
		}
		if _, decided := a.folderAdmin[folder]; decided {
			continue
		}
		seen[folder] = true
		pending = append(pending, folder)
	}

	for batch := range slices.Chunk(pending, claims.MaxBatchCheckItems) {
		a.prepareBatch(ctx, batch)
	}
}

func (a *TrashAuthorizer) prepareBatch(ctx context.Context, folders []string) {
	checks := make([]claims.BatchCheckItem, 0, len(folders))
	for i, folder := range folders {
		checks = append(checks, claims.BatchCheckItem{
			CorrelationID: strconv.Itoa(i),
			Verb:          utils.VerbSetPermissions,
			Group:         a.key.Group,
			Resource:      a.key.Resource,
			Folder:        folder,
		})
	}

	resp, err := a.access.BatchCheck(ctx, a.user, claims.BatchCheckRequest{
		Namespace: a.key.Namespace,
		Checks:    checks,
	})
	if err != nil {
		if a.onCheckError != nil {
			a.onCheckError(err)
		}
		return
	}

	for i, folder := range folders {
		// A folder left undecided here is checked on its own by FolderAdmin, which
		// reports its own failure. Reporting again here would double every log line
		// of an authz outage, once per item.
		result, ok := resp.Results[strconv.Itoa(i)]
		if !ok || result.Error != nil {
			continue
		}
		a.folderAdmin[folder] = result.Allowed
	}
}

// Allowed reports whether the caller may see an object in folder deleted by
// deletedBy.
//
// deletedBy is compared first because it needs no authorization call. The two
// conditions are ORed, so the order affects only cost, not the answer.
func (a *TrashAuthorizer) Allowed(ctx context.Context, folder, deletedBy string) bool {
	if a.deletedByCaller(deletedBy) {
		return true
	}
	return a.FolderAdmin(ctx, folder)
}

func (a *TrashAuthorizer) deletedByCaller(deletedBy string) bool {
	return a.namespaceMatches && deletedBy != "" && deletedBy == a.user.GetUID()
}

// FolderAdmin reports whether the caller administers folder. An empty folder is
// the root; see rootFolderFor.
func (a *TrashAuthorizer) FolderAdmin(ctx context.Context, folder string) bool {
	folder = a.checkedFolder(folder)
	if isAdmin, ok := a.folderAdmin[folder]; ok {
		return isAdmin
	}
	resp, err := a.access.Check(ctx, a.user, claims.CheckRequest{
		Verb:      utils.VerbSetPermissions,
		Group:     a.key.Group,
		Resource:  a.key.Resource,
		Namespace: a.key.Namespace,
	}, folder)
	if err != nil && a.onCheckError != nil {
		a.onCheckError(err)
	}
	isAdmin := err == nil && resp.Allowed
	a.folderAdmin[folder] = isAdmin
	return isAdmin
}
