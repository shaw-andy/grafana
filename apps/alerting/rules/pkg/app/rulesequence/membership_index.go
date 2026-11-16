package rulesequence

import (
	"context"
	"fmt"
	"sync"

	"github.com/grafana/grafana-app-sdk/resource"

	model "github.com/grafana/grafana/apps/alerting/rules/pkg/apis/alerting/v0alpha1"
	"github.com/grafana/grafana/apps/alerting/rules/pkg/app/config"
)

// MembershipIndex maintains a watch-backed, in-memory index that maps rule UIDs
// to the RuleSequence that owns them. It implements operator.ResourceWatcher so
// the app-sdk informer infrastructure keeps it in sync via Add/Update/Delete
// events.
//
// Admission validators call Resolve to perform O(1) membership lookups instead
// of listing all RuleSequences on every request.
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
	// index maps (namespace, ruleUID) -> sequenceUID (the Name field on the
	// RuleSequence object). Rule and sequence UIDs are only unique within a
	// namespace, so every key carries the namespace.
	index map[namespacedName]string
	// sequences stores the full set of rule refs per sequence so Update and
	// Delete can remove stale entries without re-scanning.
	sequences map[namespacedName][]string
}

type namespacedName struct {
	namespace string
	name      string
}

// NewMembershipIndex creates an empty index. The caller must register it as a
// Watcher on the RuleSequence AppManagedKind so the app-sdk informer populates
// it.
func NewMembershipIndex() *MembershipIndex {
	return &MembershipIndex{
		index:     make(map[namespacedName]string),
		sequences: make(map[namespacedName][]string),
	}
}

// Resolve returns membership information for the requested rule UIDs within
// namespace. Each UID is looked up in O(1) time against the in-memory index.
//
// The returned map always contains an entry for every requested UID. If a UID
// is not owned by any sequence, its entry has Found=false.
func (m *MembershipIndex) Resolve(_ context.Context, namespace string, uids []string) (map[string]config.RuleSequenceMembership, error) {
	result := make(map[string]config.RuleSequenceMembership, len(uids))
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, uid := range uids {
		if seqUID, ok := m.index[namespacedName{namespace, uid}]; ok {
			result[uid] = config.RuleSequenceMembership{SequenceUID: seqUID, Found: true}
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

	refs := collectRuleUIDs(seq)
	seqKey := namespacedName{seq.Namespace, seq.Name}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sequences[seqKey] = refs
	for _, uid := range refs {
		m.index[namespacedName{seq.Namespace, uid}] = seq.Name
	}
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

	oldKey := namespacedName{oldSeq.Namespace, oldSeq.Name}
	newKey := namespacedName{newSeq.Namespace, newSeq.Name}
	newRefs := collectRuleUIDs(newSeq)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove old entries. Only delete from index if the mapping still points to
	// this sequence (another sequence could theoretically have claimed the UID
	// in between, though admission should prevent this).
	if oldRefs, exists := m.sequences[oldKey]; exists {
		for _, uid := range oldRefs {
			ruleKey := namespacedName{oldKey.namespace, uid}
			if m.index[ruleKey] == oldKey.name {
				delete(m.index, ruleKey)
			}
		}
		delete(m.sequences, oldKey)
	}

	// Index new entries.
	m.sequences[newKey] = newRefs
	for _, uid := range newRefs {
		m.index[namespacedName{newKey.namespace, uid}] = newKey.name
	}
	return nil
}

// Delete is called by the informer when a RuleSequence is removed.
func (m *MembershipIndex) Delete(_ context.Context, obj resource.Object) error {
	seq, ok := obj.(*model.RuleSequence)
	if !ok {
		return fmt.Errorf("membership index received non-RuleSequence object: %T", obj)
	}

	seqKey := namespacedName{seq.Namespace, seq.Name}

	m.mu.Lock()
	defer m.mu.Unlock()

	if refs, exists := m.sequences[seqKey]; exists {
		for _, uid := range refs {
			ruleKey := namespacedName{seq.Namespace, uid}
			if m.index[ruleKey] == seq.Name {
				delete(m.index, ruleKey)
			}
		}
		delete(m.sequences, seqKey)
	}
	return nil
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
