package ssosettings

import (
	"fmt"
	"strings"
)

// IsEndpointField reports whether a provider setting names a remote endpoint
// that Grafana contacts on behalf of the provider.
func IsEndpointField(key string) bool {
	return strings.HasSuffix(strings.ToLower(key), "_url")
}

// IsPresentedCredentialField reports whether a secret setting is sent to the
// provider's endpoints. Other secret settings, such as TLS keys and
// certificates, are used by Grafana without being disclosed to the peer.
func IsPresentedCredentialField(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "secret") || strings.Contains(lower, "password")
}

// EndpointsChanged reports whether settings sets any endpoint field to a value
// other than the stored one. An absent or empty endpoint is not a change: it
// resolves to the server-side default, which settings writers do not control.
func EndpointsChanged(settings, stored map[string]any) bool {
	for key, value := range settings {
		if !IsEndpointField(key) || value == nil || value == "" {
			continue
		}
		if storedValue, ok := stored[key]; !ok || fmt.Sprint(storedValue) != fmt.Sprint(value) {
			return true
		}
	}
	return false
}
