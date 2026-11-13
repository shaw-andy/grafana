package api

import "net/http"

// isEmbeddedResourceRequest reports whether the browser issued the request to
// load part of a page (an image, media, script, style, or a fetch/XHR call)
// rather than to navigate to it. Browsers attach the session cookie to those
// loads, so GET handlers that change the caller's session must refuse them.
// Requests without Fetch Metadata headers (older browsers, non-browser clients)
// are treated as navigations so existing links and redirects keep working.
func isEmbeddedResourceRequest(r *http.Request) bool {
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return true
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "", "document", "iframe", "frame":
		return false
	default:
		return true
	}
}
