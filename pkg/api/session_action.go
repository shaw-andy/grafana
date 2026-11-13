package api

import (
	"embed"
	"html/template"
	"net/http"

	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
)

var (
	//go:embed session_action_confirm.html
	sessionActionTemplateFS embed.FS

	// Parsed with the default {{ }} delimiters; kept separate from the view
	// templates which use [[ ]].
	sessionActionConfirmTemplate = template.Must(template.ParseFS(sessionActionTemplateFS, "session_action_confirm.html"))
)

// sessionActionPage describes a confirmation page for an action that changes
// the signed-in session. Following a link only shows the page; the action runs
// when the user submits its form, which the CSRF filter checks like any other
// state-changing request.
type sessionActionPage struct {
	Title     string
	Message   string
	Confirm   string
	Action    string
	CancelURL string
}

func (hs *HTTPServer) renderSessionActionPage(c *contextmodel.ReqContext, page sessionActionPage) {
	h := c.Resp.Header()
	h.Set("Content-Type", "text/html; charset=UTF-8")
	h.Set("Cache-Control", "no-store")
	// A framed confirmation page could be used to trick the user into submitting it.
	h.Set("X-Frame-Options", "deny")
	c.Resp.WriteHeader(http.StatusOK)

	if err := sessionActionConfirmTemplate.Execute(c.Resp, page); err != nil {
		hs.log.Error("Failed to render session action confirmation page", "error", err)
	}
}
