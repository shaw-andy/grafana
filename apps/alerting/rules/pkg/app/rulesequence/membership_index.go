package rulesequence

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/grafana/grafana-app-sdk/resource"
	"k8s.io/apiserver/pkg/endpoints/request"

	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/config"
)

var errNamespaceRequired = errors.New("rule sequence membership lookup requires a request namespace")

// MembershipIndex maintains a watch-backed, in-memory index that maps rule UIDs
// to the RuleSequence that owns them. It implements operator.ResourceWatcher so
// the app-sdk informer infrastructure keeps it in sync via Add/Update/Delete
// events.
//
// Admission validators call Resolve to perform O(1) membership lookups instead
// of listing all RuleSequences on every request.
//
// The informer may watch every namespace (on-prem, all orgs), and rule UIDs and
// sequence names are only unique within a namespace, so every entry is keyed by
// namespace. Lookups never cross namespaces.
//
// Before the informer's initial list has been processed the index is empty, so
// Resolve returns "not found" for every UID. This is permissive by design:
// the app-sdk starts serving admission webhooks before informers sync, so every
// app faces the same startup window. Invalid states that slip through (e.g., a
// rule claimed by two sequences) should be detected and surfaced by a
// reconciler.
//
// TODO: This membership index will not scale in MT since this code will be handling
// ALL tenant's rules/sequences rather than a single tenant's, causing memory overhead
// to grow unbounded.
//
// TODO: Add a RuleSequence reconciler that verifies membership invariants after
// the fact and writes status conditions (e.g., MembershipValid=False) when a
// rule is claimed by multiple sequences, references a nonexistent rule, or has
// a folder mismatch. This closes the gap left by the permissive startup window
// and any residual TOCTOU race in the watch-backed index.
type MembershipIndex struct {
	// mu protects index and sequences.
	mu sync.RWMutex
	// index maps (namespace, ruleUID) -> owning sequence.
	index map[ruleKey]sequenceKey
	// sequences stores the full set of rule refs per sequence so Update and
	// Delete can remove stale entries without re-scanning.
	sequences map[sequenceKey][]string
}

type ruleKey struct {
	namespace string
	uid       string
}

type sequenceKey struct {
	namespace string
	name      string
}

// NewMembershipIndex creates an empty index. The caller must register it as a
// Watcher on the RuleSequence AppManagedKind so the app-sdk informer populates
// it.
func NewMembershipIndex() *MembershipIndex {
	return &MembershipIndex{
		index:     make(map[ruleKey]sequenceKey),
		sequences: make(map[sequenceKey][]string),
	}
}

// Resolve returns membership information for the requested rule UIDs within
// the namespace of the request carried by ctx. Each UID is looked up in O(1)
// time against the in-memory index.
//
// The returned map always contains an entry for every requested UID. If a UID
// is not owned by any sequence in that namespace, its entry has Found=false.
func (m *MembershipIndex) Resolve(ctx context.Context, uids []string) (map[string]config.RuleSequenceMembership, error) {
	namespace, ok := request.NamespaceFrom(ctx)
	if !ok || namespace == "" {
		return nil, errNamespaceRequired
	}

	result := make(map[string]config.RuleSequenceMembership, len(uids))
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, uid := range uids {
		if owner, ok := m.index[ruleKey{namespace: namespace, uid: uid}]; ok {
			result[uid] = config.RuleSequenceMembership{SequenceUID: owner.name, Found: true}
		} else {
			result[uid] = config.RuleSequenceMembership{}
		}
	}
	return result, nil
}

// Add is called by the informer when a new RuleSequence is created or observed
// during the initial list.
func (m *MembershipIndex) Add(_ context.Context, obj resource.Object) error {
	seq, ok := obj.(*model.RuleSequence)
	if !ok {
		return fmt.Errorf("membership index received non-RuleSequence object: %T", obj)
	}

	key := keyOf(seq)
	refs := collectRuleUIDs(seq)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(key)
	m.addLocked(key, refs)
	return nil
}

// Update is called by the informer when a RuleSequence is modified. The old
// object's refs are removed before the new refs are indexed.
func (m *MembershipIndex) Update(_ context.Context, old, new resource.Object) error {
	oldSeq, ok := old.(*model.RuleSequence)
	if !ok {
		return fmt.Errorf("membership index received non-RuleSequence old object: %T", old)
	}
	newSeq, ok := new.(*model.RuleSequence)
	if !ok {
		return fmt.Errorf("membership index received non-RuleSequence new object: %T", new)
	}

	newKey := keyOf(newSeq)
	newRefs := collectRuleUIDs(newSeq)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(keyOf(oldSeq))
	m.removeLocked(newKey)
	m.addLocked(newKey, newRefs)
	return nil
}

// Delete is called by the informer when a RuleSequence is removed.
func (m *MembershipIndex) Delete(_ context.Context, obj resource.Object) error {
	seq, ok := obj.(*model.RuleSequence)
	if !ok {
		return fmt.Errorf("membership index received non-RuleSequence object: %T", obj)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(keyOf(seq))
	return nil
}

func (m *MembershipIndex) addLocked(key sequenceKey, refs []string) {
	m.sequences[key] = refs
	for _, uid := range refs {
		m.index[ruleKey{namespace: key.namespace, uid: uid}] = key
	}
}

// removeLocked drops the entries recorded for key. An index entry is only
// removed while it is still owned by key, so another sequence that has since
// claimed the UID keeps it.
func (m *MembershipIndex) removeLocked(key sequenceKey) {
	refs, exists := m.sequences[key]
	if !exists {
		return
	}
	for _, uid := range refs {
		rk := ruleKey{namespace: key.namespace, uid: uid}
		if m.index[rk] == key {
			delete(m.index, rk)
		}
	}
	delete(m.sequences, key)
}

func keyOf(seq *model.RuleSequence) sequenceKey {
	return sequenceKey{namespace: seq.Namespace, name: seq.Name}
}

// collectRuleUIDs extracts all referenced rule UIDs from a RuleSequence spec,
// recording rules first, then alerting rules.
func collectRuleUIDs(seq *model.RuleSequence) []string {
	refs := make([]string, 0, len(seq.Spec.RecordingRules)+len(seq.Spec.AlertingRules))
	for _, ref := range seq.Spec.RecordingRules {
		if uid := string(ref.Name); uid != "" {
			refs = append(refs, uid)
		}
	}
	for _, ref := range seq.Spec.AlertingRules {
		if uid := string(ref.Name); uid != "" {
			refs = append(refs, uid)
		}
	}
	return refs
}
