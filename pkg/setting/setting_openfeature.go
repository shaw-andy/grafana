package setting

import (
	"fmt"
	"net/url"
	"time"

	"github.com/grafana/grafana/pkg/infra/features"
)

// OpenFeatureProviderType is an alias for features.OpenFeatureProviderType
type OpenFeatureProviderType = features.OpenFeatureProviderType

const (
	// StaticProviderType is for internal Grafana use with static flags
	StaticProviderType OpenFeatureProviderType = "static"

	// Re-export features package constants for convenience
	FeaturesServiceProviderType = features.FeaturesServiceProviderType
	OFREPProviderType           = features.OFREPProviderType
)

type OpenFeatureSettings struct {
	APIEnabled   bool
	ProviderType features.OpenFeatureProviderType
	URL          *url.URL
	TargetingKey string
	ContextAttrs map[string]string
	CacheTTL     time.Duration
	// TLSCACertPath is a PEM bundle used to verify the remote provider's certificate.
	// When empty, the system roots are used.
	TLSCACertPath string
	// TLSInsecureSkipVerify disables verification of the remote provider's certificate.
	// For testing only; never enable in production.
	TLSInsecureSkipVerify bool
}

func (cfg *Cfg) readOpenFeatureSettings() error {
	cfg.OpenFeature = OpenFeatureSettings{}

	config := cfg.Raw.Section("feature_toggles.openfeature")
	cfg.OpenFeature.APIEnabled = config.Key("enable_api").MustBool(true)

	providerType := config.Key("provider").Validate(func(in string) string {
		if in == "" {
			return string(StaticProviderType)
		}

		switch in {
		case string(StaticProviderType):
			return string(StaticProviderType)
		case string(features.FeaturesServiceProviderType):
			return string(features.FeaturesServiceProviderType)
		case string(features.OFREPProviderType):
			return string(features.OFREPProviderType)
		default:
			cfg.Logger.Warn("invalid provider type", "provider", in)
			cfg.Logger.Info("using static provider for openfeature")
			return string(StaticProviderType)
		}
	})

	cfg.OpenFeature.ProviderType = features.OpenFeatureProviderType(providerType)
	strURL := config.Key("url").MustString("")

	defaultTargetingKey := "default"
	if cfg.StackID != "" {
		defaultTargetingKey = fmt.Sprintf("stacks-%s", cfg.StackID)
	}

	cfg.OpenFeature.TargetingKey = config.Key("targetingKey").MustString(defaultTargetingKey)

	if strURL != "" && (cfg.OpenFeature.ProviderType == features.FeaturesServiceProviderType || cfg.OpenFeature.ProviderType == features.OFREPProviderType) {
		u, err := url.Parse(strURL)
		if err != nil {
			return fmt.Errorf("invalid feature provider url: %w", err)
		}
		cfg.OpenFeature.URL = u
	}

	// build the eval context attributes using [feature_toggles.openfeature.context] section
	ctxConf := cfg.Raw.Section("feature_toggles.openfeature.context")
	attrs := map[string]string{}
	for _, key := range ctxConf.KeyStrings() {
		attrs[key] = ctxConf.Key(key).String()
	}

	// Some default attributes
	if _, ok := attrs["grafana_version"]; !ok {
		attrs["grafana_version"] = BuildVersion
	}

	if _, ok := attrs["namespace"]; !ok {
		attrs["namespace"] = defaultTargetingKey
	}

	cfg.OpenFeature.ContextAttrs = attrs

	cfg.OpenFeature.CacheTTL = config.Key("cache_ttl").MustDuration(time.Minute)
	cfg.OpenFeature.TLSCACertPath = config.Key("tls_ca_cert_path").MustString("")
	cfg.OpenFeature.TLSInsecureSkipVerify = config.Key("tls_insecure_skip_verify").MustBool(false)
	return nil
}
