package router

import (
	"context"
	"strings"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginaccesscontrol"
)

// Remote deployments have no local RBAC store to load permissions from, so only
// the permissions carried by the authenticated requester can grant access. Only
// app access is decided here, and only for the scopes the requester holds; every
// other action, and an unscoped app access check, is denied.
type pluginManifestAccessControl struct{}

var _ accesscontrol.AccessControl = pluginManifestAccessControl{}

func (pluginManifestAccessControl) Evaluate(_ context.Context, user identity.Requester, evaluator accesscontrol.Evaluator) (bool, error) {
	if user == nil || evaluator == nil {
		return false, nil
	}
	granted := user.GetPermissions()[pluginaccesscontrol.ActionAppAccess]
	return evaluator.EvaluateCustom(func(action string, scopes ...string) (bool, error) {
		if action != pluginaccesscontrol.ActionAppAccess {
			return false, nil
		}
		for _, target := range scopes {
			for _, scope := range granted {
				if pluginScopeMatches(scope, target) {
					return true, nil
				}
			}
		}
		return false, nil
	})
}

// pluginScopeMatches treats a single trailing '*' as a prefix grant, so
// plugins:id:alpha-* covers every plugin id starting with alpha-.
func pluginScopeMatches(scope, target string) bool {
	if scope == "" || target == "" {
		return false
	}
	if prefix, ok := strings.CutSuffix(scope, "*"); ok {
		return !strings.ContainsAny(prefix, "*?") && strings.HasPrefix(target, prefix)
	}
	return scope == target
}

func (pluginManifestAccessControl) RegisterScopeAttributeResolver(string, accesscontrol.ScopeAttributeResolver) {
}

func (a pluginManifestAccessControl) WithoutResolvers() accesscontrol.AccessControl {
	return a
}

func (pluginManifestAccessControl) InvalidateResolverCache(int64, string) {}
