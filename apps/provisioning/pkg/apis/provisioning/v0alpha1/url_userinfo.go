package v0alpha1

import (
	"encoding/json"
	"net/url"
	"strings"
)

// HasURLUserinfo reports whether rawURL embeds a username or password before its host.
func HasURLUserinfo(rawURL string) bool {
	_, found := stripURLUserinfo(rawURL)
	return found
}

// RemoveURLUserinfo returns rawURL without any username or password embedded before its host.
// URLs without userinfo are returned unchanged.
func RemoveURLUserinfo(rawURL string) string {
	clean, _ := stripURLUserinfo(rawURL)
	return clean
}

func stripURLUserinfo(rawURL string) (string, bool) {
	// Userinfo is always delimited by a literal '@'.
	if !strings.Contains(rawURL, "@") {
		return rawURL, false
	}

	if parsed, err := url.Parse(rawURL); err == nil && parsed.Host != "" {
		if parsed.User == nil {
			return rawURL, false
		}
		parsed.User = nil
		return parsed.String(), true
	}

	// Values that do not parse to a host cannot be trusted to be credential-free:
	// drop everything up to the last '@' after the scheme.
	prefix, rest := "", rawURL
	if i := strings.Index(rawURL, "://"); i >= 0 {
		prefix, rest = rawURL[:i+3], rawURL[i+3:]
	}
	return prefix + rest[strings.LastIndex(rest, "@")+1:], true
}

// urlFields returns every repository and server URL in the spec, whatever the repository type.
func (r *Repository) urlFields() []*string {
	var fields []*string
	if r.Spec.GitHub != nil {
		fields = append(fields, &r.Spec.GitHub.URL)
	}
	if r.Spec.GitHubEnterprise != nil {
		fields = append(fields, &r.Spec.GitHubEnterprise.URL, &r.Spec.GitHubEnterprise.ServerURL)
	}
	if r.Spec.Git != nil {
		fields = append(fields, &r.Spec.Git.URL)
	}
	if r.Spec.Bitbucket != nil {
		fields = append(fields, &r.Spec.Bitbucket.URL)
	}
	if r.Spec.GitLab != nil {
		fields = append(fields, &r.Spec.GitLab.URL)
	}
	return fields
}

// HasURLUserinfo reports whether any repository or server URL in the spec embeds userinfo.
func (r *Repository) HasURLUserinfo() bool {
	for _, u := range r.urlFields() {
		if HasURLUserinfo(*u) {
			return true
		}
	}
	return false
}

// RemoveURLUserinfo removes userinfo from every repository and server URL in the spec.
func (r *Repository) RemoveURLUserinfo() {
	for _, u := range r.urlFields() {
		*u = RemoveURLUserinfo(*u)
	}
}

// The MarshalJSON methods below keep userinfo out of every serialized repository:
// API responses (get, list, watch) and objects written back to storage.

func (c GitHubRepositoryConfig) MarshalJSON() ([]byte, error) {
	type plain GitHubRepositoryConfig
	c.URL = RemoveURLUserinfo(c.URL)
	return json.Marshal(plain(c))
}

func (c GitHubEnterpriseRepositoryConfig) MarshalJSON() ([]byte, error) {
	type plain GitHubEnterpriseRepositoryConfig
	c.URL = RemoveURLUserinfo(c.URL)
	c.ServerURL = RemoveURLUserinfo(c.ServerURL)
	return json.Marshal(plain(c))
}

func (c GitRepositoryConfig) MarshalJSON() ([]byte, error) {
	type plain GitRepositoryConfig
	c.URL = RemoveURLUserinfo(c.URL)
	return json.Marshal(plain(c))
}

func (c BitbucketRepositoryConfig) MarshalJSON() ([]byte, error) {
	type plain BitbucketRepositoryConfig
	c.URL = RemoveURLUserinfo(c.URL)
	return json.Marshal(plain(c))
}

func (c GitLabRepositoryConfig) MarshalJSON() ([]byte, error) {
	type plain GitLabRepositoryConfig
	c.URL = RemoveURLUserinfo(c.URL)
	return json.Marshal(plain(c))
}
