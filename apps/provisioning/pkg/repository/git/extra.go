package git

import (
	"context"
	"fmt"
	"net"

	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/apps/provisioning/pkg/repository"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type extra struct {
	decrypter repository.Decrypter
	// allowInsecure permits http:// URLs together with a token (cleartext credentials); local/dev only.
	allowInsecure bool
	metrics       *repository.OperationMetrics
	clientMetrics *ClientMetrics
	urlValidator  *repository.URLValidator
}

type ExtraOption func(*extra)

// WithURLValidator sets the validator every connection to the repository host must pass.
// Without it, connections to loopback, private, link-local and unspecified addresses are refused.
func WithURLValidator(urlValidator *repository.URLValidator) ExtraOption {
	return func(e *extra) {
		e.urlValidator = urlValidator
	}
}

func Extra(decrypter repository.Decrypter, allowInsecure bool, metrics *repository.OperationMetrics, clientMetrics *ClientMetrics, opts ...ExtraOption) repository.Extra {
	e := &extra{
		decrypter:     decrypter,
		allowInsecure: allowInsecure,
		metrics:       metrics,
		clientMetrics: clientMetrics,
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.urlValidator == nil {
		e.urlValidator = repository.NewURLValidator(repository.Allowlist{}, net.DefaultResolver.LookupIPAddr)
	}
	return e
}

func (e *extra) Type() provisioning.RepositoryType {
	return provisioning.GitRepositoryType
}

func (e *extra) Build(ctx context.Context, r *provisioning.Repository) (repository.Repository, error) {
	secure := e.decrypter(r)
	cfg := r.Spec.Git
	if cfg == nil {
		return nil, fmt.Errorf("git configuration is required")
	}

	token, err := secure.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt token: %w", err)
	}

	signingKey, err := secure.CommitSigningKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt signing key: %w", err)
	}

	return NewRepository(ctx, r, RepositoryConfig{
		URL:              cfg.URL,
		Branch:           cfg.Branch,
		Path:             cfg.Path,
		TokenUser:        cfg.TokenUser,
		Token:            token,
		CommitSigningKey: signingKey,
		SigningMethod:    SigningMethodFromSpec(r),
		SMIMECertificate: SMIMECertificateFromSpec(r),
		SkipGitSuffix:    true,
		Transport:        e.urlValidator.Transport(),
	}, e.metrics, e.clientMetrics)
}

func (e *extra) Mutate(ctx context.Context, obj runtime.Object, oldObj runtime.Object) error {
	return Mutate(ctx, obj)
}

func (e *extra) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return Validate(ctx, obj, e.allowInsecure)
}
