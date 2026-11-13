package github

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrServerMismatch reports a repository URL that is not on the GitHub server a
// connection belongs to.
var ErrServerMismatch = errors.New("repository URL is not on the connection's GitHub server")

// RepositoryOrigin returns the origin ("scheme://host") of repoURL when repoURL is
// a repository on the GitHub server at serverURL. An empty serverURL is github.com,
// which only serves https://github.com and https://www.github.com.
func RepositoryOrigin(repoURL, serverURL string) (string, error) {
	scheme, host, err := urlOrigin(repoURL)
	if err != nil {
		return "", fmt.Errorf("parse repository URL: %w", err)
	}

	if serverURL == "" {
		if scheme == "https" && (host == "github.com" || host == "www.github.com") {
			return scheme + "://" + host, nil
		}
		return "", fmt.Errorf("%w: %s://%s is not github.com", ErrServerMismatch, scheme, host)
	}

	serverScheme, serverHost, err := urlOrigin(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	if scheme != serverScheme || host != serverHost {
		return "", fmt.Errorf("%w: %s://%s is not %s://%s", ErrServerMismatch, scheme, host, serverScheme, serverHost)
	}
	return scheme + "://" + host, nil
}

// urlOrigin returns the lowercased scheme and host (including any port) of raw.
func urlOrigin(raw string) (scheme, host string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	if u.Host == "" {
		return "", "", errors.New("missing host")
	}
	return strings.ToLower(u.Scheme), strings.ToLower(u.Host), nil
}
