package accesscontrol

import (
	"context"
	"errors"
	"slices"

	"github.com/grafana/grafana/pkg/apimachinery/errutil"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/db"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/annotations"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/search/model"
	"github.com/grafana/grafana/pkg/setting"
)

var (
	ErrReadForbidden = errutil.NewBase(
		errutil.StatusForbidden,
		"annotations.accesscontrol.read",
		errutil.WithPublicMessage("User missing permissions"),
	)
	ErrAccessControlInternal = errutil.NewBase(
		errutil.StatusInternal,
		"annotations.accesscontrol.internal",
		errutil.WithPublicMessage("Internal error while checking permissions"),
	)
)

type Authorizer interface {
	Authorize(ctx context.Context, query annotations.ItemQuery) (*AccessResources, error)
}

var _ Authorizer = (*AuthService)(nil)

type AuthService struct {
	db                        db.DB
	features                  featuremgmt.FeatureToggles
	dashSvc                   dashboards.DashboardService
	folderSvc                 folder.Service
	searchDashboardsPageLimit int64
	maxDepth                  int
}

func NewAuthService(db db.DB, features featuremgmt.FeatureToggles, dashSvc dashboards.DashboardService, cfg *setting.Cfg) *AuthService {
	section := cfg.Raw.Section("annotations")
	searchDashboardsPageLimit := section.Key("search_dashboards_page_limit").MustInt64(1000)

	return &AuthService{
		db:                        db,
		features:                  features,
		dashSvc:                   dashSvc,
		searchDashboardsPageLimit: searchDashboardsPageLimit,
		maxDepth:                  cfg.MaxNestedFolderDepth,
	}
}

// WithFolderService makes folder ancestors resolve through the folder service, the same source
// the annotation id scope resolver uses. Without it, ancestors are read from the legacy folder table.
func (authz *AuthService) WithFolderService(folderSvc folder.Service) *AuthService {
	authz.folderSvc = folderSvc
	return authz
}

// Authorize checks if the user has permission to read annotations, then returns a struct containing dashboards and scope types that the user has access to.
func (authz *AuthService) Authorize(ctx context.Context, query annotations.ItemQuery) (*AccessResources, error) {
	user := query.SignedInUser
	if user == nil || user.IsNil() {
		return nil, ErrReadForbidden.Errorf("missing user")
	}

	scopes, has := user.GetPermissions()[ac.ActionAnnotationsRead]
	if !has {
		return nil, ErrReadForbidden.Errorf("user does not have permission to read annotations")
	}
	scopeTypes := annotationScopeTypes(scopes)
	_, canAccessOrgAnnotations := scopeTypes[annotations.Organization.String()]
	if query.AnnotationID != 0 {
		annotationDashboardUID, err := authz.getAnnotationDashboard(ctx, query)
		if err != nil {
			return nil, ErrAccessControlInternal.Errorf("failed to fetch annotations: %w", err)
		}
		query.DashboardUID = annotationDashboardUID
	}

	visibleDashboards, hasMoreDashboards, err := authz.dashboardsWithVisibleAnnotations(ctx, query)
	if err != nil {
		if errors.Is(err, ErrReadForbidden) {
			return nil, err
		}
		return nil, ErrAccessControlInternal.Errorf("failed to fetch dashboards: %w", err)
	}

	return &AccessResources{
		Dashboards:              visibleDashboards,
		HasMoreDashboards:       hasMoreDashboards,
		CanAccessOrgAnnotations: canAccessOrgAnnotations,
	}, nil
}

func (authz *AuthService) getAnnotationDashboard(ctx context.Context, query annotations.ItemQuery) (string, error) {
	var items []annotations.Item
	params := make([]any, 0)
	err := authz.db.WithDbSession(ctx, func(sess *db.Session) error {
		sql := `
			SELECT
				a.id,
				a.org_id,
				a.dashboard_uid
			FROM annotation as a
			WHERE a.org_id = ? AND a.id = ?
			`
		params = append(params, query.OrgID, query.AnnotationID)

		return sess.SQL(sql, params...).Find(&items)
	})
	if err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "", ErrAccessControlInternal.Errorf("annotation not found")
	}

	return items[0].DashboardUID, nil
}

// dashboardsWithVisibleAnnotations returns the dashboards on the requested search page whose annotations
// the user can read, and whether the search page was full.
// Dashboard search only checks dashboard read access, so each hit is also checked against the user's
// annotations read scopes, the same scopes the annotation id scope resolver produces.
func (authz *AuthService) dashboardsWithVisibleAnnotations(ctx context.Context, query annotations.ItemQuery) (map[string]int64, bool, error) {
	var dashboardUIDs []string
	if query.DashboardUID != "" {
		dashboardUIDs = []string{query.DashboardUID}
	}

	dashs, err := authz.dashSvc.SearchDashboards(ctx, &dashboards.FindPersistedDashboardsQuery{
		DashboardUIDs: dashboardUIDs,
		OrgId:         query.SignedInUser.GetOrgID(),
		SignedInUser:  query.SignedInUser,
		Page:          query.Page,
		Type:          model.TypeAnnotation,
		Limit:         authz.searchDashboardsPageLimit,
	})
	if err != nil {
		return nil, false, err
	}

	checker := newAnnotationScopeChecker(authz, query.SignedInUser)
	visibleDashboards := make(map[string]int64)
	for _, d := range dashs {
		if query.DashboardUID != "" && d.UID != query.DashboardUID {
			continue
		}
		canRead, err := checker.canReadDashboardAnnotations(ctx, d.UID, d.FolderUID)
		if err != nil {
			return nil, false, err
		}
		if canRead {
			visibleDashboards[d.UID] = d.ID
			continue
		}
		// A dashboard the caller asked for by UID is denied outright. For a lookup by annotation id the
		// UID comes from the annotation itself, so leaving it out reports the annotation as not found.
		if query.DashboardUID != "" && query.AnnotationID == 0 {
			return nil, false, ErrReadForbidden.Errorf("user cannot read annotations of dashboard %s", d.UID)
		}
	}

	return visibleDashboards, int64(len(dashs)) >= authz.searchDashboardsPageLimit, nil
}

type annotationScopeChecker struct {
	authz          *AuthService
	user           identity.Requester
	allAnnotations bool
	ancestorScopes map[string][]string
}

func newAnnotationScopeChecker(authz *AuthService, user identity.Requester) *annotationScopeChecker {
	wildcards := ac.WildcardsFromPrefix(ac.ScopeAnnotationsProvider.GetResourceScope(""))
	allAnnotations := slices.ContainsFunc(user.GetPermissions()[ac.ActionAnnotationsRead], wildcards.Contains)
	return &annotationScopeChecker{
		authz:          authz,
		user:           user,
		allAnnotations: allAnnotations,
		ancestorScopes: map[string][]string{},
	}
}

// canReadDashboardAnnotations reports whether annotations:read covers the dashboard, its folder, or any
// of the folder's ancestors (or the general folder for dashboards at the root).
func (c *annotationScopeChecker) canReadDashboardAnnotations(ctx context.Context, dashboardUID, folderUID string) (bool, error) {
	if c.allAnnotations {
		return true, nil
	}
	if folderUID == "" {
		folderUID = folder.GeneralFolderUID
	}
	scopes := []string{
		dashboards.ScopeDashboardsProvider.GetResourceScopeUID(dashboardUID),
		folder.ScopeFoldersProvider.GetResourceScopeUID(folderUID),
	}
	permissions := c.user.GetPermissions()
	if ac.EvalPermission(ac.ActionAnnotationsRead, scopes...).Evaluate(permissions) {
		return true, nil
	}
	if folderUID == folder.GeneralFolderUID {
		return false, nil
	}

	inherited, err := c.inheritedScopes(ctx, folderUID)
	if err != nil {
		return false, err
	}
	if len(inherited) == 0 {
		return false, nil
	}
	return ac.EvalPermission(ac.ActionAnnotationsRead, inherited...).Evaluate(permissions), nil
}

func (c *annotationScopeChecker) inheritedScopes(ctx context.Context, folderUID string) ([]string, error) {
	if scopes, ok := c.ancestorScopes[folderUID]; ok {
		return scopes, nil
	}

	orgID := c.user.GetOrgID()
	var scopes []string
	var err error
	if c.authz.folderSvc != nil {
		scopes, err = identity.WithServiceIdentityFn(ctx, orgID, func(ctx context.Context) ([]string, error) {
			return folder.GetInheritedScopes(ctx, orgID, folderUID, c.authz.folderSvc)
		})
		if errors.Is(err, folder.ErrFolderNotFound) {
			scopes, err = nil, nil
		}
	} else {
		scopes, err = c.authz.legacyFolderAncestorScopes(ctx, orgID, folderUID)
	}
	if err != nil {
		return nil, err
	}

	c.ancestorScopes[folderUID] = scopes
	return scopes, nil
}

func (authz *AuthService) legacyFolderAncestorScopes(ctx context.Context, orgID int64, folderUID string) ([]string, error) {
	maxDepth := authz.maxDepth
	if maxDepth <= 0 {
		maxDepth = setting.DefaultMaxNestedFolderDepth
	}

	var scopes []string
	visited := map[string]bool{folderUID: true}
	err := authz.db.WithDbSession(ctx, func(sess *db.Session) error {
		current := folderUID
		for range maxDepth {
			var parents []string
			if err := sess.SQL("SELECT COALESCE(parent_uid, '') FROM folder WHERE org_id = ? AND uid = ?", orgID, current).Find(&parents); err != nil {
				return err
			}
			if len(parents) == 0 || parents[0] == "" || visited[parents[0]] {
				return nil
			}
			current = parents[0]
			visited[current] = true
			scopes = append(scopes, folder.ScopeFoldersProvider.GetResourceScopeUID(current))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return scopes, nil
}

func annotationScopeTypes(scopes []string) map[any]struct{} {
	allScopeTypes := map[any]struct{}{
		annotations.Dashboard.String():    {},
		annotations.Organization.String(): {},
	}

	types, hasWildcardScope := ac.ParseScopes(ac.ScopeAnnotationsProvider.GetResourceScopeType(""), scopes)
	if hasWildcardScope {
		types = allScopeTypes
	}

	return types
}
