package git

import (
	"context"
	"fmt"
	"net/http"

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
	httpTransport http.RoundTripper
}

type ExtraOption func(*extra)

// WithHTTPTransport sets the transport used to reach repository URLs, typically
// one built by repository.NewHTTPTransport with the configured allowlist.
func WithHTTPTransport(transport http.RoundTripper) ExtraOption {
	return func(e *extra) {
		e.httpTransport = transport
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
		HTTPTransport:    e.httpTransport,
	}, e.metrics, e.clientMetrics)
}

func (e *extra) Mutate(ctx context.Context, obj runtime.Object, oldObj runtime.Object) error {
	return Mutate(ctx, obj)
}

func (e *extra) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return Validate(ctx, obj, e.allowInsecure)
}
