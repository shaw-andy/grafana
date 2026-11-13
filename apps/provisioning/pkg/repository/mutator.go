package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apiserver/pkg/admission"

	provisioningadmission "github.com/grafana/grafana/apps/provisioning/pkg/apis/admission"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
)

// AdmissionMutator handles mutation for Repository resources
type AdmissionMutator struct {
	factory         Factory
	minSyncInterval time.Duration
}

// NewAdmissionMutator creates a new repository mutator
func NewAdmissionMutator(
	factory Factory,
	minSyncInterval time.Duration,
) *AdmissionMutator {
	return &AdmissionMutator{
		factory:         factory,
		minSyncInterval: minSyncInterval,
	}
}

// Mutate applies mutations to Repository resources
func (m *AdmissionMutator) Mutate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	obj := a.GetObject()
	if obj == nil {
		return nil
	}

	if a.GetSubresource() != "" && !provisioningadmission.SpecAndSecureChanged(a) {
		return nil // pure status patch: spec/secure untouched, nothing to (re)mutate
	}

	r, ok := obj.(*provisioning.Repository)
	if !ok {
		return fmt.Errorf("expected repository configuration, got %T", obj)
	}

	// Enforcing the presence of finalizers in resources not marked for deletion.
	if r.DeletionTimestamp == nil || r.DeletionTimestamp.IsZero() {
		if len(r.Finalizers) == 0 {
			r.Finalizers = []string{
				RemoveOrphanResourcesFinalizer,
				RemovePendingJobsFinalizer,
				CleanFinalizer,
			}
		}
	}

	if r.Spec.Sync.IntervalSeconds == 0 || r.Spec.Sync.IntervalSeconds < int64(m.minSyncInterval.Seconds()) {
		r.Spec.Sync.IntervalSeconds = int64(m.minSyncInterval.Seconds())
	}

	if r.Spec.Workflows == nil {
		r.Spec.Workflows = []provisioning.Workflow{}
	}

	if r.Spec.Webhook != nil && r.Spec.Webhook.BaseURL != "" {
		r.Spec.Webhook.BaseURL = strings.TrimRight(r.Spec.Webhook.BaseURL, "/")
	}

	// Extra mutators from factory
	if err := m.factory.Mutate(ctx, r, a.GetOldObject()); err != nil {
		return fmt.Errorf("failed to mutate repository: %w", err)
	}

	return nil
}

// CopySecureValues copies secure values from old to new repository if they are zero in the new one.
// This preserves existing secrets during updates when they are not provided in the new object.
func CopySecureValues(new, old *provisioning.Repository) {
	if old == nil || old.Secure.IsZero() {
		return
	}
	if new.Secure.Token.IsZero() {
		new.Secure.Token = old.Secure.Token
	}
	if new.Secure.WebhookSecret.IsZero() {
		new.Secure.WebhookSecret = old.Secure.WebhookSecret
	}
	if new.Secure.CommitSigningKey.IsZero() {
		new.Secure.CommitSigningKey = old.Secure.CommitSigningKey
	}
}

func RequiresNewTokenForURLChange(new, old *provisioning.Repository) bool {
	return old != nil && new.URL() != old.URL() && new.Secure.Token.IsZero()
}

// RequiresNewTokenForConnectionRemoval reports whether an update drops the
// connection while keeping the stored token that connection issued. Without the
// connection, that token would be treated as a user token and presented to
// whatever host the repository URL names.
// ReferencesForeignSecureValues reports whether new names a stored secure value
// that old does not already hold in the same field. Storage checks such references
// on write; callers that build a repository from an unsaved configuration must
// refuse them instead, or they would decrypt another object's secret.
func ReferencesForeignSecureValues(new, old *provisioning.Repository) bool {
	var held provisioning.SecureValues
	if old != nil {
		held = old.Secure
	}
	foreign := func(name, heldName string) bool {
		return name != "" && name != heldName
	}
	return foreign(new.Secure.Token.Name, held.Token.Name) ||
		foreign(new.Secure.WebhookSecret.Name, held.WebhookSecret.Name) ||
		foreign(new.Secure.CommitSigningKey.Name, held.CommitSigningKey.Name)
}

func RequiresNewTokenForConnectionRemoval(new, old *provisioning.Repository) bool {
	return old != nil && old.HasConnection() && !new.HasConnection() &&
		new.Secure.Token.Create.IsZero() && !new.Secure.Token.Remove
}
