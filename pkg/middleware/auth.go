package middleware

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/middleware/cookies"
	"github.com/grafana/grafana/pkg/plugins"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/auth"
	"github.com/grafana/grafana/pkg/services/authn"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

type AuthOptions struct {
	ReqGrafanaAdmin bool
	ReqNoAnonynmous bool
	ReqSignedIn     bool
}

func accessForbidden(c *contextmodel.ReqContext) {
	if c.IsApiRequest() {
		c.JsonApiErr(403, "Permission denied", nil)
		return
	}

	c.Redirect(setting.AppSubUrl + "/")
}

func notAuthorized(c *contextmodel.ReqContext) {
	if c.IsApiRequest() {
		c.WriteErrOrFallback(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), c.LookupTokenErr)
		return
	}

	if !c.UseSessionStorageRedirect {
		writeRedirectCookie(c)
	}

	if _, ok := errors.AsType[authn.TokenNeedsRotationError](c.LookupTokenErr); ok {
		if !c.UseSessionStorageRedirect {
			c.Redirect(setting.AppSubUrl + "/user/auth-tokens/rotate")
			return
		}

		c.Redirect(setting.AppSubUrl + "/user/auth-tokens/rotate" + getRedirectToQueryParam(c))
		return
	}

	if !c.UseSessionStorageRedirect {
		c.Redirect(setting.AppSubUrl + "/login")
		return
	}

	c.Redirect(setting.AppSubUrl + "/login" + getRedirectToQueryParam(c))
}

func tokenRevoked(c *contextmodel.ReqContext, err *auth.TokenRevokedError) {
	if c.IsApiRequest() {
		c.JSON(http.StatusUnauthorized, map[string]any{
			"message": "Token revoked",
			"error": map[string]any{
				"id":                    "ERR_TOKEN_REVOKED",
				"maxConcurrentSessions": err.MaxConcurrentSessions,
			},
		})
		return
	}

	if !c.UseSessionStorageRedirect {
		writeRedirectCookie(c)
		c.Redirect(setting.AppSubUrl + "/login")
		return
	}

	c.Redirect(setting.AppSubUrl + "/login" + getRedirectToQueryParam(c))
}

func writeRedirectCookie(c *contextmodel.ReqContext) {
	redirectTo := c.Req.RequestURI
	if setting.AppSubUrl != "" && !strings.HasPrefix(redirectTo, setting.AppSubUrl) {
		redirectTo = setting.AppSubUrl + c.Req.RequestURI
	}

	if redirectTo == "/" {
		return
	}

	// remove any forceLogin=true params
	redirectTo = RemoveForceLoginParams(redirectTo)
	cookies.WriteCookie(c.Resp, "redirect_to", url.QueryEscape(redirectTo), 0, nil)
}

func getRedirectToQueryParam(c *contextmodel.ReqContext) string {
	redirectTo := c.Req.RequestURI
	if setting.AppSubUrl != "" && strings.HasPrefix(redirectTo, setting.AppSubUrl) {
		redirectTo = strings.TrimPrefix(redirectTo, setting.AppSubUrl)
	}

	if redirectTo == "/" {
		return ""
	}

	// remove any forceLogin=true params
	redirectTo = RemoveForceLoginParams(redirectTo)
	return "?redirectTo=" + url.QueryEscape(redirectTo)
}

var forceLoginParamsRegexp = regexp.MustCompile(`&?forceLogin=true`)

func RemoveForceLoginParams(str string) string {
	return forceLoginParamsRegexp.ReplaceAllString(str, "")
}

func CanAdminPlugins(cfg *setting.Cfg, accessControl ac.AccessControl) func(c *contextmodel.ReqContext) {
	return func(c *contextmodel.ReqContext) {
		hasAccess := ac.HasAccess(accessControl, c)
		if !pluginaccesscontrol.ReqCanAdminPlugins(cfg)(c) && !hasAccess(pluginaccesscontrol.AdminAccessEvaluator) {
			accessForbidden(c)
			return
		}
		if c.AllowAnonymous && !c.IsSignedIn && shouldForceLogin(c) {
			notAuthorized(c)
			return
		}
	}
}

func RoleAppPluginAuth(accessControl ac.AccessControl, ps pluginstore.Store, logger log.Logger) func(c *contextmodel.ReqContext) {
	return func(c *contextmodel.ReqContext) {
		pluginID := web.Params(c.Req)[":id"]
		requestPaths := appRequestPathVariants(c.Req.URL)
		appRoot := normalizeIncludePath("/a/" + pluginID)
		for _, reqPath := range requestPaths {
			if !isUnderIncludePath(reqPath, appRoot) {
				accessForbidden(c)
				return
			}
		}

		p, exists := ps.Plugin(c.Req.Context(), pluginID)
		if !exists {
			// The frontend will handle app not found appropriately
			return
		}

		pages := pageIncludesUnder(p.Includes, appRoot)
		// Apps without page includes under their app URL declare no per-page restrictions there;
		// plugins.app:access already gates them.
		if len(pages) == 0 {
			return
		}

		hasAccess := ac.HasAccess(accessControl, c)
		canOpen := func(i *plugins.Includes) bool {
			if i.RequiresRBACAction() {
				return hasAccess(pluginaccesscontrol.GetPluginRouteEvaluator(pluginID, i.Action))
			}
			return c.HasUserRole(i.Role)
		}

		// The plugin's client router decides what renders under any URL, so every reading of the
		// path must fall under an include the caller may open, and the most specific include wins.
		for _, reqPath := range requestPaths {
			matched := longestMatchingIncludes(pages, reqPath)
			if len(matched) == 0 {
				logger.Debug("Plugin path is not covered by any page include", "plugin", pluginID)
				accessForbidden(c)
				return
			}
			for _, i := range matched {
				if !canOpen(i.include) {
					logger.Debug("User doesn't have access to plugin include", "plugin", pluginID, "include", i.include.Name)
					accessForbidden(c)
					return
				}
			}
		}
	}
}

type pageInclude struct {
	path    string
	include *plugins.Includes
}

func pageIncludesUnder(includes []*plugins.Includes, root string) []pageInclude {
	pages := make([]pageInclude, 0, len(includes))
	for _, i := range includes {
		if i.Type != "page" || i.Path == "" {
			continue
		}
		p := i.Path
		if idx := strings.IndexAny(p, "?#"); idx >= 0 {
			p = p[:idx]
		}
		p = normalizeIncludePath(cleanURLPath(p))
		if !isUnderIncludePath(p, root) {
			continue
		}
		pages = append(pages, pageInclude{path: p, include: i})
	}
	return pages
}

func longestMatchingIncludes(pages []pageInclude, path string) []pageInclude {
	var matched []pageInclude
	for _, page := range pages {
		if !isUnderIncludePath(path, page.path) {
			continue
		}
		if len(matched) > 0 && len(page.path) < len(matched[0].path) {
			continue
		}
		if len(matched) > 0 && len(page.path) > len(matched[0].path) {
			matched = matched[:0]
		}
		matched = append(matched, page)
	}
	return matched
}

// appRequestPathVariants returns the decoded and escaped request path, each as sent and with
// dot segments resolved, so that no reading of the URL can land outside the include it is checked against.
func appRequestPathVariants(u *url.URL) []string {
	raw := []string{u.Path, u.EscapedPath()}
	variants := make([]string, 0, len(raw)*2)
	for _, p := range raw {
		for _, v := range []string{normalizeIncludePath(p), normalizeIncludePath(cleanURLPath(p))} {
			if !slices.Contains(variants, v) {
				variants = append(variants, v)
			}
		}
	}
	return variants
}

func cleanURLPath(p string) string {
	return path.Clean("/" + p)
}

// normalizeIncludePath is case-insensitive because client-side routers match routes case-insensitively by default.
func normalizeIncludePath(p string) string {
	return strings.ToLower(strings.Trim(p, "/"))
}

func isUnderIncludePath(requestPath, includePath string) bool {
	if includePath == "" {
		return true
	}
	return requestPath == includePath || strings.HasPrefix(requestPath, includePath+"/")
}

func RoleAuth(roles ...org.RoleType) web.Handler {
	return func(c *contextmodel.ReqContext) {
		ok := slices.Contains(roles, c.OrgRole)
		if !ok {
			accessForbidden(c)
		}
	}
}

func Auth(options *AuthOptions) web.Handler {
	return func(c *contextmodel.ReqContext) {
		forceLogin := false
		if c.AllowAnonymous {
			forceLogin = shouldForceLogin(c)
			if !forceLogin {
				orgIDValue := c.Req.URL.Query().Get("orgId")
				orgID, err := strconv.ParseInt(orgIDValue, 10, 64)
				if err == nil && orgID > 0 && orgID != c.GetOrgID() {
					forceLogin = true
				}
			}
		}

		requireLogin := !c.AllowAnonymous || forceLogin || options.ReqNoAnonynmous

		if !c.IsSignedIn && options.ReqSignedIn && requireLogin {
			if revokedErr, ok := errors.AsType[*auth.TokenRevokedError](c.LookupTokenErr); ok {
				tokenRevoked(c, revokedErr)
				return
			}

			notAuthorized(c)
			return
		}

		if !c.IsGrafanaAdmin && options.ReqGrafanaAdmin {
			accessForbidden(c)
			return
		}
	}
}

// snapshotPublicModeOrPermission allows access when snapshot public mode is enabled,
// otherwise requires the user to be signed in and have the given permission.
func snapshotPublicModeOrPermission(cfg *setting.Cfg, ac2 ac.AccessControl, action string) web.Handler {
	evaluator := ac.EvalPermission(action)
	return func(c *contextmodel.ReqContext) {
		if cfg.SnapshotPublicMode {
			return
		}

		if !c.IsSignedIn {
			notAuthorized(c)
			return
		}

		hasAccess, err := ac2.Evaluate(c.Req.Context(), c.SignedInUser, evaluator)
		if err != nil {
			c.JsonApiErr(http.StatusInternalServerError, "Internal server error", err)
			return
		}
		if !hasAccess {
			c.JsonApiErr(http.StatusForbidden, "forbidden", nil)
			return
		}
	}
}

// SnapshotPublicModeOrCreate creates a middleware that allows access
// if snapshot public mode is enabled or if user has creation permission.
func SnapshotPublicModeOrCreate(cfg *setting.Cfg, ac2 ac.AccessControl) web.Handler {
	return snapshotPublicModeOrPermission(cfg, ac2, dashboards.ActionSnapshotsCreate)
}

// SnapshotPublicModeOrDelete creates a middleware that allows access
// if snapshot public mode is enabled or if user has delete permission.
func SnapshotPublicModeOrDelete(cfg *setting.Cfg, ac2 ac.AccessControl) web.Handler {
	return snapshotPublicModeOrPermission(cfg, ac2, dashboards.ActionSnapshotsDelete)
}

func ReqNotSignedIn(c *contextmodel.ReqContext) {
	if c.IsSignedIn {
		c.Redirect(setting.AppSubUrl + "/")
	}
}

// NoAuth creates a middleware that doesn't require any authentication.
// If forceLogin param is set it will redirect the user to the login page.
func NoAuth() web.Handler {
	return func(c *contextmodel.ReqContext) {
		if shouldForceLogin(c) {
			notAuthorized(c)
			return
		}
	}
}

// shouldForceLogin checks if user should be enforced to login.
// Returns true if forceLogin parameter is set.
func shouldForceLogin(c *contextmodel.ReqContext) bool {
	forceLogin := false
	forceLoginParam, err := strconv.ParseBool(c.Req.URL.Query().Get("forceLogin"))
	if err == nil {
		forceLogin = forceLoginParam
	}

	return forceLogin
}
