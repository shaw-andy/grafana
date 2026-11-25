package api

import "net/http"

// isUnattendedRequest reports whether the browser marked the request as a subresource load
// (image, media, script, fetch) or as a frame navigation the user did not start. Markup that
// dashboard editors or query results control can trigger both without a click, so GET routes
// that change the viewer's session must refuse them. Browsers that send no fetch metadata
// headers are not identified.
func isUnattendedRequest(r *http.Request) bool {
	dest := r.Header.Get("Sec-Fetch-Dest")
	if dest == "" || dest == "document" {
		return false
	}
	userNavigation := r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-User") == "?1"
	return !userNavigation
}
