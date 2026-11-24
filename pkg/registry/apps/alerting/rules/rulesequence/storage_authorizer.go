package rulesequence

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/apiserver/auth/authorizer/storewrapper"
	"github.com/grafana/grafana/pkg/services/folder"
)

var _ storewrapper.ResourceStorageAuthorizer = (*StorageAuthorizer)(nil)

// StorageAuthorizer scopes every RuleSequence operation to the folder stored on
// the object. Unified storage does not enforce RBAC for this resource, and the
// request-level Authorize only checks that the caller holds the action on some
// folder, so this is where the folder scope is applied. Grafana's own service
// identity (the scheduler and the membership index informer) is authorized by
// its token at the request level and holds no alert.rules RBAC actions, so it
// is not filtered here.
type StorageAuthorizer struct {
	ac accesscontrol.AccessControl
}

func NewStorageAuthorizer(ac accesscontrol.AccessControl) *StorageAuthorizer {
	return &StorageAuthorizer{ac: ac}
}

// A sequence overrides the interval of the rules it lists and blocks moving or
// deleting them, so creating one, or moving one into a folder, changes rules in
// that folder and needs rule update as well as create there.
func (a *StorageAuthorizer) BeforeCreate(ctx context.Context, obj runtime.Object) error {
	folderUID, name, err := folderOf(obj)
	if err != nil {
		return err
	}
	return a.authorize(ctx, name, folderUID, accesscontrol.ActionAlertingRuleCreate, accesscontrol.ActionAlertingRuleUpdate)
}

func (a *StorageAuthorizer) BeforeUpdate(ctx context.Context, oldObj, obj runtime.Object) error {
	oldMeta, err := utils.MetaAccessor(oldObj)
	if err != nil {
		return storewrapper.ErrUnexpectedType
	}
	// The store passes an empty object when an update or apply creates the
	// sequence; anything it read from storage has a resource version.
	if oldMeta.GetResourceVersion() == "" {
		return a.BeforeCreate(ctx, obj)
	}
	oldFolderUID, name, err := folderOf(oldObj)
	if err != nil {
		return err
	}
	newFolderUID, _, err := folderOf(obj)
	if err != nil {
		return err
	}
	if oldFolderUID == newFolderUID {
		return a.authorize(ctx, name, oldFolderUID, accesscontrol.ActionAlertingRuleUpdate)
	}
	if err := a.authorize(ctx, name, oldFolderUID, accesscontrol.ActionAlertingRuleUpdate, accesscontrol.ActionAlertingRuleDelete); err != nil {
		return err
	}
	return a.authorize(ctx, name, newFolderUID, accesscontrol.ActionAlertingRuleCreate, accesscontrol.ActionAlertingRuleUpdate)
}

func (a *StorageAuthorizer) BeforeDelete(ctx context.Context, obj runtime.Object) error {
	folderUID, name, err := folderOf(obj)
	if err != nil {
		return err
	}
	return a.authorize(ctx, name, folderUID, accesscontrol.ActionAlertingRuleDelete)
}

func (a *StorageAuthorizer) AfterGet(ctx context.Context, obj runtime.Object) error {
	folderUID, name, err := folderOf(obj)
	if err != nil {
		return err
	}
	return a.authorize(ctx, name, folderUID)
}

func (a *StorageAuthorizer) FilterList(ctx context.Context, list runtime.Object) (runtime.Object, error) {
	l, ok := list.(*model.RuleSequenceList)
	if !ok {
		return nil, storewrapper.ErrUnexpectedType
	}
	user, err := identity.GetRequester(ctx)
	if err != nil {
		return nil, storewrapper.ErrUnauthenticated
	}
	canRead := a.folderReadChecker(ctx, user)
	items := make([]model.RuleSequence, 0, len(l.Items))
	for i := range l.Items {
		folderUID, _, err := folderOf(&l.Items[i])
		if err != nil {
			return nil, err
		}
		ok, err := canRead(folderUID)
		if err != nil {
			return nil, err
		}
		if ok {
			items = append(items, l.Items[i])
		}
	}
	l.Items = items
	return l, nil
}

func (a *StorageAuthorizer) WatchFilter(ctx context.Context) (storewrapper.WatchEventFilter, error) {
	user, err := identity.GetRequester(ctx)
	if err != nil {
		return nil, storewrapper.ErrUnauthenticated
	}
	canRead := a.folderReadChecker(ctx, user)
	return func(events []watch.Event) ([]bool, error) {
		allowed := make([]bool, len(events))
		for i, ev := range events {
			folderUID, _, err := folderOf(ev.Object)
			if err != nil {
				continue
			}
			ok, err := canRead(folderUID)
			if err != nil {
				return nil, err
			}
			allowed[i] = ok
		}
		return allowed, nil
	}, nil
}

// folderReadChecker memoizes read decisions per folder for one list or watch.
func (a *StorageAuthorizer) folderReadChecker(ctx context.Context, user identity.Requester) func(folderUID string) (bool, error) {
	if identity.IsServiceIdentity(ctx) {
		return func(string) (bool, error) { return true, nil }
	}
	decisions := map[string]bool{}
	return func(folderUID string) (bool, error) {
		if ok, seen := decisions[folderUID]; seen {
			return ok, nil
		}
		ok, err := a.ac.Evaluate(ctx, user, folderEvaluator(folderUID))
		if err != nil {
			return false, err
		}
		decisions[folderUID] = ok
		return ok, nil
	}
}

func (a *StorageAuthorizer) authorize(ctx context.Context, name, folderUID string, actions ...string) error {
	if identity.IsServiceIdentity(ctx) {
		return nil
	}
	user, err := identity.GetRequester(ctx)
	if err != nil {
		return storewrapper.ErrUnauthenticated
	}
	ok, err := a.ac.Evaluate(ctx, user, folderEvaluator(folderUID, actions...))
	if err != nil {
		return err
	}
	if !ok {
		return apierrors.NewForbidden(ResourceInfo.GroupResource(), name,
			fmt.Errorf("missing alert rule permissions in folder %q", folderUID))
	}
	return nil
}

// folderEvaluator requires reading the folder and its rules, plus the given rule
// actions, all on the folder itself. A sequence without a folder requires them
// on every folder.
func folderEvaluator(folderUID string, actions ...string) accesscontrol.Evaluator {
	scope := folder.ScopeFoldersProvider.GetResourceAllScope()
	if folderUID != "" {
		scope = folder.ScopeFoldersProvider.GetResourceScopeUID(folderUID)
	}
	evals := []accesscontrol.Evaluator{
		accesscontrol.EvalPermission(folder.ActionFoldersRead, scope),
		accesscontrol.EvalPermission(accesscontrol.ActionAlertingRuleRead, scope),
	}
	for _, action := range actions {
		evals = append(evals, accesscontrol.EvalPermission(action, scope))
	}
	return accesscontrol.EvalAll(evals...)
}

func folderOf(obj runtime.Object) (folderUID string, name string, err error) {
	meta, err := utils.MetaAccessor(obj)
	if err != nil {
		return "", "", storewrapper.ErrUnexpectedType
	}
	return meta.GetFolder(), meta.GetName(), nil
}
