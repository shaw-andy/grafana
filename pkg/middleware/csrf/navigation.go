package csrf

import (
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// IsUserNavigation reports whether r is the browser opening a page for the user, as
// opposed to an image, script, fetch or automatically loaded frame that page content
// can request with the user's session cookie. Same-origin GET subresource requests
// carry no Origin header, so the CSRF check lets them through; GET handlers that
// change session state must refuse anything that is not a user navigation.
func IsUserNavigation(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document":
		return true
	case "iframe", "frame":
		return r.Header.Get("Sec-Fetch-User") == "?1"
	case "":
		// Browsers only send Fetch Metadata to secure origins. Subresource requests
		// (images, fetch, XHR) never ask for HTML, while navigations always do.
		return acceptsHTML(r.Header.Values("Accept"))
	default:
		return false
	}
}

func acceptsHTML(accept []string) bool {
	for _, header := range accept {
		for _, mediaRange := range strings.Split(header, ",") {
			mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(mediaRange))
			if err != nil || mediaType != "text/html" {
				continue
			}
			if q, err := strconv.ParseFloat(params["q"], 64); err == nil && q <= 0 {
				continue
			}
			return true
		}
	}
	return false
}
