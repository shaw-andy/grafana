package middleware

import (
	"net/http"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
)

// isSameSiteEmbeddedRequest reports whether the browser sent the request to load something into a page
// on this site, such as an image, a stylesheet or a frame, rather than to navigate the window to it.
// Content that users author, like a text panel, can make every viewer's browser send such a request
// with their session cookie, so it must not change that session.
func isSameSiteEmbeddedRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site":
	default:
		return false
	}
	dest := r.Header.Get("Sec-Fetch-Dest")
	return dest != "" && dest != "document"
}

// ReqNavigation refuses requests that a page on this site embedded instead of navigating to. Use it on
// GET routes that change the session, such as logging out or switching the active organization.
func ReqNavigation(c *contextmodel.ReqContext) {
	if isSameSiteEmbeddedRequest(c.Req) {
		c.Resp.Header().Set("Cache-Control", "no-store")
		http.Error(c.Resp, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}
