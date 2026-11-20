package accesscontrol

import (
	"context"
	"errors"
	"strings"

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

func NewAuthService(db db.DB, features featuremgmt.FeatureToggles, dashSvc dashboards.DashboardService, folderSvc folder.Service, cfg *setting.Cfg) *AuthService {
	section := cfg.Raw.Section("annotations")
	searchDashboardsPageLimit := section.Key("search_dashboards_page_limit").MustInt64(1000)

	return &AuthService{
		db:                        db,
		features:                  features,
		dashSvc:                   dashSvc,
		folderSvc:                 folderSvc,
		searchDashboardsPageLimit: searchDashboardsPageLimit,
		maxDepth:                  cfg.MaxNestedFolderDepth,
	}
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
		return nil, ErrAccessControlInternal.Errorf("failed to fetch dashboards: %w", err)
	}

	return &AccessResources{
		Dashboards:              visibleDashboards,
		CanAccessOrgAnnotations: canAccessOrgAnnotations,
		HasMoreDashboards:       hasMoreDashboards,
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

// dashboardsWithVisibleAnnotations returns the dashboards the user can read whose annotations the user can also read,
// and whether the dashboard search page was full.
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

	// The dashboard search only checks dashboard read access, so the annotation read scopes have to be applied here.
	checker := newAnnotationScopeChecker(authz.folderSvc, query.SignedInUser)
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
		}
	}

	hasMoreDashboards := len(dashs) > 0 && int64(len(dashs)) >= authz.searchDashboardsPageLimit
	return visibleDashboards, hasMoreDashboards, nil
}

// annotationScopeChecker evaluates annotations:read against the same dashboard and folder scopes
// that the annotation ID scope resolver produces for a dashboard annotation.
type annotationScopeChecker struct {
	folderSvc       folder.Service
	orgID           int64
	permissions     map[string][]string
	hasFolderScopes bool
	inherited       map[string][]string
}

func newAnnotationScopeChecker(folderSvc folder.Service, user identity.Requester) *annotationScopeChecker {
	scopes := user.GetPermissions()[ac.ActionAnnotationsRead]
	hasFolderScopes := false
	for _, scope := range scopes {
		if strings.HasPrefix(scope, folder.ScopeFoldersPrefix) {
			hasFolderScopes = true
			break
		}
	}

	return &annotationScopeChecker{
		folderSvc:       folderSvc,
		orgID:           user.GetOrgID(),
		permissions:     map[string][]string{ac.ActionAnnotationsRead: scopes},
		hasFolderScopes: hasFolderScopes,
		inherited:       make(map[string][]string),
	}
}

func (c *annotationScopeChecker) canReadDashboardAnnotations(ctx context.Context, dashboardUID, folderUID string) (bool, error) {
	if dashboardUID == "" {
		return false, nil
	}

	scopes := []string{dashboards.ScopeDashboardsProvider.GetResourceScopeUID(dashboardUID)}
	if folderUID == "" || folderUID == folder.GeneralFolderUID {
		scopes = append(scopes, folder.ScopeFoldersProvider.GetResourceScopeUID(folder.GeneralFolderUID))
		return c.evaluate(scopes), nil
	}

	scopes = append(scopes, folder.ScopeFoldersProvider.GetResourceScopeUID(folderUID))
	if c.evaluate(scopes) {
		return true, nil
	}
	if !c.hasFolderScopes {
		return false, nil
	}

	inherited, err := c.inheritedFolderScopes(ctx, folderUID)
	if err != nil {
		return false, err
	}
	return c.evaluate(inherited), nil
}

func (c *annotationScopeChecker) evaluate(scopes []string) bool {
	if len(scopes) == 0 {
		return false
	}
	return ac.EvalPermission(ac.ActionAnnotationsRead, scopes...).Evaluate(c.permissions)
}

func (c *annotationScopeChecker) inheritedFolderScopes(ctx context.Context, folderUID string) ([]string, error) {
	if scopes, ok := c.inherited[folderUID]; ok {
		return scopes, nil
	}
	if c.folderSvc == nil {
		return nil, nil
	}

	// The user may be able to read the dashboard without being able to read its ancestor folders.
	scopes, err := identity.WithServiceIdentityFn(ctx, c.orgID, func(ctx context.Context) ([]string, error) {
		return folder.GetInheritedScopes(ctx, c.orgID, folderUID, c.folderSvc)
	})
	if err != nil {
		if !errors.Is(err, folder.ErrFolderNotFound) {
			return nil, err
		}
		scopes = nil
	}

	c.inherited[folderUID] = scopes
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
