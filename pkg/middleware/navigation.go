package middleware

import "net/http"

// GET routes that change session state must not act on subresource loads. An img, audio, video,
// object or CSS url() request carries the session cookie and sends no Origin header, so the CSRF
// filter lets it through. Browsers report what a request is for in the Fetch Metadata headers,
// which page script cannot set. Every browser Grafana's frontend targets sends them, so a request
// without them is refused rather than trusted.

// IsUserNavigation reports whether r loads a top-level page, or a frame page the user clicked
// through to. A frame that loads by itself does not count, because markup that can add an iframe
// gets the same cookies as markup that can add an img.
func IsUserNavigation(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Mode") != "navigate" {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document":
		return true
	case "iframe", "frame":
		return r.Header.Get("Sec-Fetch-User") == "?1"
	default:
		return false
	}
}

// IsNavigation reports whether r loads a page, at the top level or in a frame. Use it only where
// a frame loading by itself must still work, such as Grafana embedded in another application.
func IsNavigation(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Mode") != "navigate" {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document", "iframe", "frame":
		return true
	default:
		return false
	}
}
