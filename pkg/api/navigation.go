package api

import (
	"net/http"
	"strings"
)

// isDocumentNavigation reports whether a GET request is a browser navigation to a
// page rather than a load triggered by page content, such as an image, stylesheet,
// media element, fetch or a frame. Those loads carry the session cookie on
// same-site requests, so handlers that change session state must ignore them.
func isDocumentNavigation(r *http.Request) bool {
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		if mode != "navigate" {
			return false
		}
		// Frames loaded by page content navigate without user activation; a user
		// clicking a link inside an embedded Grafana frame sets Sec-Fetch-User.
		return r.Header.Get("Sec-Fetch-Dest") == "document" || r.Header.Get("Sec-Fetch-User") == "?1"
	}

	// Browsers only send fetch metadata to secure origins. Without it, navigations
	// are the only loads that ask for HTML.
	for _, accept := range r.Header.Values("Accept") {
		for _, mediaRange := range strings.Split(accept, ",") {
			mediaType, _, _ := strings.Cut(mediaRange, ";")
			if strings.EqualFold(strings.TrimSpace(mediaType), "text/html") {
				return true
			}
		}
	}
	return false
}
