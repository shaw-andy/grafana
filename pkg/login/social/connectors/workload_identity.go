package connectors

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/configprovider"
	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/services/ssosettings"
)

// serverWorkloadIdentityTokenFile returns the workload identity token file set for the provider in the
// server configuration. The token file contents are sent to the provider's token URL, which SSO settings
// writers can change, so the file itself must only be chosen by whoever controls the server configuration.
func serverWorkloadIdentityTokenFile(ctx context.Context, cfgProvider configprovider.ConfigProvider, provider string) (string, error) {
	section := "auth." + provider
	sections, err := cfgProvider.GetSections(ctx, section)
	if err != nil {
		return "", fmt.Errorf("get configuration for OAuth provider %q: %w", provider, err)
	}
	return sections.Section(section).Key("workload_identity_token_file").String(), nil
}

// ReadWorkloadIdentityToken reads the workload identity token for the provider. tokenFile comes from the
// provider's SSO settings and must match the token file set in the server configuration; only the server
// configured file is read.
func ReadWorkloadIdentityToken(ctx context.Context, cfgProvider configprovider.ConfigProvider, provider string, tokenFile string) (string, error) {
	allowed, err := serverWorkloadIdentityTokenFile(ctx, cfgProvider, provider)
	if err != nil {
		return "", err
	}
	if allowed == "" || tokenFile != allowed {
		return "", fmt.Errorf("workload identity token file must match workload_identity_token_file in the [auth.%s] section of the server configuration", provider)
	}

	federatedToken, err := os.ReadFile(allowed)
	if err != nil {
		return "", fmt.Errorf("failed to read workload identity token file: %w", err)
	}
	return strings.TrimSpace(string(federatedToken)), nil
}

func (s *SocialBase) workloadIdentityTokenFileValidator(ctx context.Context) ssosettings.ValidateFunc[social.OAuthInfo] {
	return func(info *social.OAuthInfo, requester identity.Requester) error {
		if info.ClientAuthentication != social.WorkloadIdentity {
			return nil
		}
		allowed, err := serverWorkloadIdentityTokenFile(ctx, s.cfgProvider, s.providerName)
		if err != nil {
			return err
		}
		if allowed == "" || info.WorkloadIdentityTokenFile != allowed {
			return ssosettings.ErrInvalidOAuthConfig("Workload identity token file must match workload_identity_token_file in the server configuration.")
		}
		return nil
	}
}
