package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"slices"
	"strconv"

	claims "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/storage/unified/resourcepb"
)

// An older version of an object records the folder it was saved in, not where
// the object is now. Since then the object may have moved, been deleted, or been
// replaced by a new object with the same name, so that folder must not decide
// who sees the version.
//
// olderVersionAuthorizer decides against the object as it is now. A version of a
// live object needs read access where the object lives. A version of a deleted
// object follows the trash rule: its deleter, or an admin of the folder it was
// deleted from. A version whose UID is not the UID of the object now holding its
// name belongs to an object that is gone, and is denied.
//
// One authorizer per request: decisions are cached and must not outlive it.
type olderVersionAuthorizer struct {
	s        *server
	user     claims.AuthInfo
	group    string
	resource string

	current map[objectRef]*currentObject
	trash   map[string]*TrashAuthorizer
}

type objectRef struct {
	namespace string
	name      string
}

// olderVersion is one version to authorize. Without matchUID it is matched to
// the current object by name alone, for callers that have no body to read the
// UID from.
type olderVersion struct {
	objectRef
	uid      string
	matchUID bool
}

type currentState int

const (
	// Neither live nor in the trash. Nobody may see its older versions.
	objectGone currentState = iota
	objectLive
	objectDeleted
)

type currentObject struct {
	state           currentState
	folder          string
	uid             string
	resourceVersion int64
	deletedBy       string
	canRead         bool
}

func (s *server) newOlderVersionAuthorizer(user claims.AuthInfo, group, resource string) *olderVersionAuthorizer {
	return &olderVersionAuthorizer{
		s:        s,
		user:     user,
		group:    group,
		resource: resource,
		current:  map[objectRef]*currentObject{},
		trash:    map[string]*TrashAuthorizer{},
	}
}

func versionWithBody(namespace, name string, value []byte) olderVersion {
	return olderVersion{
		objectRef: objectRef{namespace: namespace, name: name},
		uid:       objectUID(value),
		matchUID:  true,
	}
}

// objectUID returns "" for a body it cannot read, which matches only a current
// object that has no UID either.
func objectUID(value []byte) string {
	var obj struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(value, &obj); err != nil {
		return ""
	}
	return obj.Metadata.UID
}

// authorize reports, for each version, whether the caller may see it.
func (a *olderVersionAuthorizer) authorize(ctx context.Context, versions []olderVersion) ([]bool, error) {
	refs := make([]objectRef, len(versions))
	for i, v := range versions {
		refs[i] = v.objectRef
	}
	if err := a.resolve(ctx, refs); err != nil {
		return nil, err
	}

	allowed := make([]bool, len(versions))
	for i, v := range versions {
		obj := a.current[v.objectRef]
		if v.matchUID && v.uid != obj.uid {
			continue
		}
		switch obj.state {
		case objectLive:
			allowed[i] = obj.canRead
		case objectDeleted:
			allowed[i] = a.trashAuthorizer(v.namespace).Allowed(ctx, obj.folder, obj.deletedBy)
		case objectGone:
		}
	}
	return allowed, nil
}

// resolve looks up the current state of every object not looked up yet, and
// decides read access to the live ones.
func (a *olderVersionAuthorizer) resolve(ctx context.Context, refs []objectRef) error {
	var pending []objectRef
	seen := make(map[objectRef]bool, len(refs))
	for _, ref := range refs {
		if _, ok := a.current[ref]; ok || seen[ref] {
			continue
		}
		seen[ref] = true
		pending = append(pending, ref)
	}
	if len(pending) == 0 {
		return nil
	}

	requests := make([]*resourcepb.ReadRequest, len(pending))
	for i, ref := range pending {
		requests[i] = &resourcepb.ReadRequest{Key: a.key(ref)}
	}
	resolved := make(map[objectRef]*currentObject, len(pending))
	i := 0
	for rsp := range a.s.readResources(ctx, requests) {
		if i >= len(pending) {
			return fmt.Errorf("resource reader returned more responses than requested")
		}
		ref := pending[i]
		i++
		switch {
		case rsp.Error == nil:
			resolved[ref] = &currentObject{
				state:           objectLive,
				folder:          rsp.Folder,
				uid:             objectUID(rsp.Value),
				resourceVersion: rsp.ResourceVersion,
			}
		case rsp.Error.Code == http.StatusNotFound:
			obj, err := a.lookupDeleted(ctx, ref)
			if err != nil {
				return err
			}
			resolved[ref] = obj
		default:
			return ErrorFromResponse(rsp.Error, nil)
		}
	}
	if i != len(pending) {
		return fmt.Errorf("resource reader returned %d responses for %d requests", i, len(pending))
	}

	if err := a.checkRead(ctx, resolved); err != nil {
		return err
	}
	for ref, obj := range resolved {
		a.current[ref] = obj
	}
	return nil
}

// lookupDeleted finds the deletion marker for a name that is not live. The
// marker records the deleter as the last updater.
func (a *olderVersionAuthorizer) lookupDeleted(ctx context.Context, ref objectRef) (*currentObject, error) {
	obj := &currentObject{state: objectGone}
	_, err := a.s.backend.ListHistory(ctx, &resourcepb.ListRequest{
		Source:  resourcepb.ListRequest_TRASH,
		Options: &resourcepb.ListOptions{Key: a.key(ref)},
	}, func(iter ListIterator) error {
		if !iter.Next() {
			return iter.Error()
		}
		if err := iter.Error(); err != nil {
			return err
		}
		marker, err := parseTrashItem(iter.Value())
		if err != nil {
			return err
		}
		// Provisioned objects are never retrievable from trash.
		if marker.GetAnnotation(utils.AnnoKeyManagerKind) != "" {
			return nil
		}
		obj = &currentObject{
			state:     objectDeleted,
			folder:    iter.Folder(),
			uid:       string(marker.GetUID()),
			deletedBy: marker.GetUpdatedBy(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return obj, nil
}

// checkRead decides get access to each live object in the folder it lives in now.
func (a *olderVersionAuthorizer) checkRead(ctx context.Context, objects map[objectRef]*currentObject) error {
	byNamespace := map[string][]objectRef{}
	for ref, obj := range objects {
		if obj.state == objectLive {
			byNamespace[ref.namespace] = append(byNamespace[ref.namespace], ref)
		}
	}
	for namespace, refs := range byNamespace {
		for batch := range slices.Chunk(refs, claims.MaxBatchCheckItems) {
			checks := make([]claims.BatchCheckItem, len(batch))
			for i, ref := range batch {
				obj := objects[ref]
				checks[i] = claims.BatchCheckItem{
					CorrelationID:      strconv.Itoa(i),
					Verb:               utils.VerbGet,
					Group:              a.group,
					Resource:           a.resource,
					Name:               ref.name,
					Folder:             obj.folder,
					FreshnessTimestamp: ResourceVersionTime(obj.resourceVersion),
				}
			}
			rsp, err := a.s.access.BatchCheck(ctx, a.user, claims.BatchCheckRequest{
				Namespace: namespace,
				Checks:    checks,
			})
			if err != nil {
				return err
			}
			for i, ref := range batch {
				result, ok := rsp.Results[strconv.Itoa(i)]
				objects[ref].canRead = ok && result.Error == nil && result.Allowed
			}
		}
	}
	return nil
}

func (a *olderVersionAuthorizer) trashAuthorizer(namespace string) *TrashAuthorizer {
	if t, ok := a.trash[namespace]; ok {
		return t
	}
	key := &resourcepb.ResourceKey{Group: a.group, Resource: a.resource, Namespace: namespace}
	t := NewTrashAuthorizer(a.s.access, a.user, key, func(err error) {
		a.s.log.Warn("Failed to check folder admin for an older version of a deleted object", "group", a.group, "resource", a.resource, "namespace", namespace, "error", err)
	})
	a.trash[namespace] = t
	return t
}

func (a *olderVersionAuthorizer) key(ref objectRef) *resourcepb.ResourceKey {
	return &resourcepb.ResourceKey{
		Group:     a.group,
		Resource:  a.resource,
		Namespace: ref.namespace,
		Name:      ref.name,
	}
}

// filterOlderVersions yields the items the caller may see, in order, authorizing
// up to batchSize items at a time.
func filterOlderVersions[T any](ctx context.Context, a *olderVersionAuthorizer, items iter.Seq[T], batchSize int, versionOf func(T) olderVersion) iter.Seq2[T, error] {
	batchSize = max(1, min(batchSize, claims.MaxBatchCheckItems))
	return func(yield func(T, error) bool) {
		batch := make([]T, 0, batchSize)
		versions := make([]olderVersion, 0, batchSize)
		flush := func() bool {
			if len(batch) == 0 {
				return true
			}
			allowed, err := a.authorize(ctx, versions)
			if err != nil {
				var zero T
				yield(zero, err)
				return false
			}
			for i, item := range batch {
				if allowed[i] && !yield(item, nil) {
					return false
				}
			}
			batch = batch[:0]
			versions = versions[:0]
			return true
		}

		for item := range items {
			batch = append(batch, item)
			versions = append(versions, versionOf(item))
			if len(batch) == batchSize && !flush() {
				return
			}
		}
		flush()
	}
}

// replayedEventVisible reports whether the caller may see an event replayed from
// before its watch began, which is an older version like any other.
func (s *server) replayedEventVisible(ctx context.Context, user claims.AuthInfo, event *WrittenEvent) (bool, error) {
	allowed, err := s.newOlderVersionAuthorizer(user, event.Key.Group, event.Key.Resource).authorize(ctx, []olderVersion{
		versionWithBody(event.Key.Namespace, event.Key.Name, event.Value),
	})
	if err != nil {
		return false, err
	}
	return allowed[0], nil
}

// authorizeOlderVersion is authorizeRead for a read at an explicit resource
// version.
func (s *server) authorizeOlderVersion(ctx context.Context, user claims.AuthInfo, key *resourcepb.ResourceKey, rsp *BackendReadResponse) *resourcepb.ErrorResult {
	if rsp.Error != nil && rsp.Error.Code == http.StatusNotFound {
		return rsp.Error
	}
	version := olderVersion{objectRef: objectRef{namespace: key.Namespace, name: key.Name}}
	if rsp.Error == nil {
		version = versionWithBody(key.Namespace, key.Name, rsp.Value)
	}
	allowed, err := s.newOlderVersionAuthorizer(user, key.Group, key.Resource).authorize(ctx, []olderVersion{version})
	if err != nil {
		return AsErrorResult(err)
	}
	if !allowed[0] {
		return &resourcepb.ErrorResult{Code: http.StatusForbidden}
	}
	return nil
}
