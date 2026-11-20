package annotationsimpl

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/types"
	"github.com/grafana/grafana/pkg/api"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/annotations"
	annotationac "github.com/grafana/grafana/pkg/services/annotations/accesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/folder"
	"github.com/grafana/grafana/pkg/services/folder/foldertest"
	"github.com/grafana/grafana/pkg/services/search/model"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/services/tag/tagimpl"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	allowedDashboardUID = "dash-allowed"
	secretDashboardUID  = "dash-secret"
	generalDashboardUID = "dash-general"
	allowedFolderUID    = "allowed-folder"
	parentFolderUID     = "parent-folder"
	secretFolderUID     = "secret-folder"

	allowedNote = "allowed-dashboard note"
	secretNote  = "secret incident timeline"
	generalNote = "general folder note"
	orgNote     = "organization note"

	allowedTag = "allowed-tag"
	secretTag  = "secret-incident"
	generalTag = "general-tag"
	orgTag     = "org-tag"

	authorLogin = "incident-author"
	authorEmail = "incident-author@example.com"
)

// annotationDashboardSearch is the dashboard search the annotation list calls.
// A hit is returned when the caller can get the dashboard, which the resource
// authorizer maps to dashboards:read on the dashboard UID, or on the dashboard
// folder and its parents. It does not consult annotations:read.
type annotationDashboardSearch struct {
	*dashboards.FakeDashboardService
	ac        ac.AccessControl
	reader    types.AccessClient
	dashes    []*dashboards.Dashboard
	ancestors map[string][]string
}

func (s *annotationDashboardSearch) SearchDashboards(ctx context.Context, query *dashboards.FindPersistedDashboardsQuery) (model.HitList, error) {
	hits := make(model.HitList, 0, len(s.dashes))
	for _, dash := range s.dashes {
		if query.OrgId != 0 && dash.OrgID != query.OrgId {
			continue
		}
		if len(query.DashboardUIDs) > 0 && !contains(query.DashboardUIDs, dash.UID) {
			continue
		}
		allowed, err := s.canRead(ctx, query.SignedInUser, dash)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		hits = append(hits, &model.Hit{
			ID:        dash.ID,
			UID:       dash.UID,
			OrgID:     dash.OrgID,
			FolderUID: dash.FolderUID,
			Type:      model.DashHitDB,
		})
	}
	return hits, nil
}

func (s *annotationDashboardSearch) GetDashboard(_ context.Context, query *dashboards.GetDashboardQuery) (*dashboards.Dashboard, error) {
	for _, dash := range s.dashes {
		if query.OrgID != 0 && dash.OrgID != query.OrgID {
			continue
		}
		if query.UID != "" && dash.UID == query.UID {
			return dash, nil
		}
		if query.ID != 0 && dash.ID == query.ID {
			return dash, nil
		}
	}
	return nil, dashboards.ErrDashboardNotFound
}

func (s *annotationDashboardSearch) canRead(ctx context.Context, requester identity.Requester, dash *dashboards.Dashboard) (bool, error) {
	if requester == nil || requester.IsNil() {
		return false, nil
	}
	// Search authorizes each hit with verb get on the dashboard resource.
	// LegacyAccessClient maps that verb to dashboards:read and the dashboard UID scope.
	resp, err := s.reader.Check(ctx, requester, types.CheckRequest{
		Verb:      utils.VerbGet,
		Group:     "dashboard.grafana.app",
		Resource:  "dashboards",
		Namespace: "default",
		Name:      dash.UID,
	}, dash.FolderUID)
	if err != nil {
		return false, err
	}
	if resp.Allowed {
		return true, nil
	}
	if dash.FolderUID == "" {
		return false, nil
	}
	scopes := []string{folder.ScopeFoldersProvider.GetResourceScopeUID(dash.FolderUID)}
	for _, ancestor := range s.ancestors[dash.FolderUID] {
		scopes = append(scopes, folder.ScopeFoldersProvider.GetResourceScopeUID(ancestor))
	}
	return s.ac.Evaluate(ctx, requester, ac.EvalPermission(dashboards.ActionDashboardsRead, scopes...))
}

// parentFolders resolves the parent chain the annotation id scope resolver reads.
type parentFolders struct {
	*foldertest.FakeService
	parents map[string][]*folder.Folder
}

func (p *parentFolders) GetParents(_ context.Context, q folder.GetParentsQuery) ([]*folder.Folder, error) {
	return p.parents[q.UID], nil
}

func TestAnnotationListHonorsAnnotationReadScopes(t *testing.T) {
	sql := sqlstore.NewTestStore(t)
	ctx := context.Background()
	authorID := insertAuthor(t, sql)

	dashes := &annotationDashboardSearch{
		FakeDashboardService: dashboards.NewFakeDashboardService(t),
		ac:                   acimpl.ProvideAccessControlTest(),
		dashes: []*dashboards.Dashboard{
			{ID: 11, UID: allowedDashboardUID, OrgID: 1, FolderUID: allowedFolderUID},
			{ID: 22, UID: secretDashboardUID, OrgID: 1, FolderUID: secretFolderUID},
			{ID: 33, UID: generalDashboardUID, OrgID: 1, FolderUID: ""},
		},
		ancestors: map[string][]string{
			allowedFolderUID: {parentFolderUID},
		},
	}
	dashes.reader = ac.NewLegacyAccessClient(dashes.ac, ac.ResourceAuthorizerOptions{
		Resource: "dashboards",
		Attr:     "uid",
	})

	folders := &parentFolders{
		FakeService: foldertest.NewFakeService(),
		parents: map[string][]*folder.Folder{
			allowedFolderUID: {{UID: parentFolderUID, OrgID: 1}},
		},
	}
	insertFolder(t, sql, parentFolderUID, "")
	insertFolder(t, sql, allowedFolderUID, parentFolderUID)
	insertFolder(t, sql, secretFolderUID, "")

	cfg := setting.NewCfg()
	cfg.AnnotationMaximumTagsLength = 150
	features := featuremgmt.WithFeatures()
	xormStore := NewXormStore(cfg, log.New("annotation.test"), sql, tagimpl.ProvideService(sql), prometheus.NewRegistry())
	// folders (and folder.parent_uid) is the parent chain the annotation id resolver
	// uses. The list must allow a parent folder scope to cover child dashboards.
	authz := annotationac.NewAuthService(sql, features, dashes, cfg)
	repo := NewRepositoryImpl(authz, features, xormStore, xormStore)

	saveAnnotation(t, xormStore, authorID, 11, allowedDashboardUID, allowedNote, []string{allowedTag}, "Pending", "OK")
	secret := saveAnnotation(t, xormStore, authorID, 22, secretDashboardUID, secretNote, []string{secretTag}, "Normal", "Alerting")
	saveAnnotation(t, xormStore, authorID, 33, generalDashboardUID, generalNote, []string{generalTag}, "Normal", "Normal")
	saveAnnotation(t, xormStore, authorID, 0, "", orgNote, []string{orgTag}, "", "")

	// Every caller below can open all three dashboards. Annotation read is narrower.
	dashboardRead := []string{
		dashboards.ScopeDashboardsProvider.GetResourceScopeUID(allowedDashboardUID),
		dashboards.ScopeDashboardsProvider.GetResourceScopeUID(secretDashboardUID),
		dashboards.ScopeDashboardsProvider.GetResourceScopeUID(generalDashboardUID),
	}

	scopedReader := signedInUser(ac.ActionAnnotationsRead, []string{
		dashboards.ScopeDashboardsProvider.GetResourceScopeUID(allowedDashboardUID),
	}, dashboardRead)
	folderReader := signedInUser(ac.ActionAnnotationsRead, []string{
		folder.ScopeFoldersProvider.GetResourceScopeUID(allowedFolderUID),
	}, dashboardRead)
	ancestorReader := signedInUser(ac.ActionAnnotationsRead, []string{
		folder.ScopeFoldersProvider.GetResourceScopeUID(parentFolderUID),
	}, dashboardRead)
	generalReader := signedInUser(ac.ActionAnnotationsRead, []string{
		folder.ScopeFoldersProvider.GetResourceScopeUID(ac.GeneralFolderUID),
	}, dashboardRead)
	secretFolderReader := signedInUser(ac.ActionAnnotationsRead, []string{
		folder.ScopeFoldersProvider.GetResourceScopeUID(secretFolderUID),
	}, dashboardRead)

	t.Run("list route accepts any annotations read scope", func(t *testing.T) {
		require.True(t, ac.EvalPermission(ac.ActionAnnotationsRead).Evaluate(scopedReader.GetPermissions()))
	})

	t.Run("list omits dashboards outside the annotation read scope", func(t *testing.T) {
		resources, err := authz.Authorize(ctx, annotations.ItemQuery{OrgID: 1, SignedInUser: scopedReader, Limit: 100})
		require.NoError(t, err)
		require.Contains(t, resources.Dashboards, allowedDashboardUID)
		require.NotContains(t, resources.Dashboards, secretDashboardUID)
		require.NotContains(t, resources.Dashboards, generalDashboardUID)
		require.False(t, resources.CanAccessOrgAnnotations)

		items := findAnnotations(t, repo, annotations.ItemQuery{OrgID: 1, SignedInUser: scopedReader, Limit: 100})
		requireNote(t, items, allowedNote, allowedTag, "Pending", "OK")
		requireNoNote(t, items, secretNote, secretTag, "Alerting")
		requireNoNote(t, items, generalNote, generalTag, "")
		requireNoNote(t, items, orgNote, orgTag, "")
	})

	t.Run("list filtered by the secret tag still omits that annotation", func(t *testing.T) {
		items := findAnnotations(t, repo, annotations.ItemQuery{
			OrgID: 1, SignedInUser: scopedReader, Limit: 100, Tags: []string{secretTag},
		})
		requireNoNote(t, items, secretNote, secretTag, "Alerting")
	})

	t.Run("dashboard uid outside annotation read scopes is forbidden", func(t *testing.T) {
		items, err := repo.Find(ctx, &annotations.ItemQuery{
			OrgID: 1, SignedInUser: scopedReader, Limit: 100, DashboardUID: secretDashboardUID,
		})
		require.ErrorIs(t, err, annotationac.ErrReadForbidden)
		requireNoNote(t, items, secretNote, secretTag, "Alerting")
	})

	t.Run("dashboard uid inside annotation read scopes returns that annotation", func(t *testing.T) {
		items := findAnnotations(t, repo, annotations.ItemQuery{
			OrgID: 1, SignedInUser: scopedReader, Limit: 100, DashboardUID: allowedDashboardUID,
		})
		require.Len(t, items, 1)
		requireNote(t, items, allowedNote, allowedTag, "Pending", "OK")
	})

	t.Run("folder scope includes only dashboards in that folder", func(t *testing.T) {
		resources, err := authz.Authorize(ctx, annotations.ItemQuery{OrgID: 1, SignedInUser: folderReader, Limit: 100})
		require.NoError(t, err)
		require.Contains(t, resources.Dashboards, allowedDashboardUID)
		require.NotContains(t, resources.Dashboards, secretDashboardUID)
		require.NotContains(t, resources.Dashboards, generalDashboardUID)

		items := findAnnotations(t, repo, annotations.ItemQuery{OrgID: 1, SignedInUser: folderReader, Limit: 100})
		requireNote(t, items, allowedNote, allowedTag, "Pending", "OK")
		requireNoNote(t, items, secretNote, secretTag, "Alerting")
		requireNoNote(t, items, generalNote, generalTag, "")
		requireNoNote(t, items, orgNote, orgTag, "")
	})

	t.Run("inherited folder scope includes dashboards in child folders", func(t *testing.T) {
		resources, err := authz.Authorize(ctx, annotations.ItemQuery{OrgID: 1, SignedInUser: ancestorReader, Limit: 100})
		require.NoError(t, err)
		require.Contains(t, resources.Dashboards, allowedDashboardUID)
		require.NotContains(t, resources.Dashboards, secretDashboardUID)
		require.NotContains(t, resources.Dashboards, generalDashboardUID)

		items := findAnnotations(t, repo, annotations.ItemQuery{OrgID: 1, SignedInUser: ancestorReader, Limit: 100})
		requireNote(t, items, allowedNote, allowedTag, "Pending", "OK")
		requireNoNote(t, items, secretNote, secretTag, "Alerting")
	})

	t.Run("general folder scope includes only root dashboards", func(t *testing.T) {
		resources, err := authz.Authorize(ctx, annotations.ItemQuery{OrgID: 1, SignedInUser: generalReader, Limit: 100})
		require.NoError(t, err)
		require.Contains(t, resources.Dashboards, generalDashboardUID)
		require.NotContains(t, resources.Dashboards, allowedDashboardUID)
		require.NotContains(t, resources.Dashboards, secretDashboardUID)

		items := findAnnotations(t, repo, annotations.ItemQuery{OrgID: 1, SignedInUser: generalReader, Limit: 100})
		requireNote(t, items, generalNote, generalTag, "Normal", "Normal")
		requireNoNote(t, items, allowedNote, allowedTag, "")
		requireNoNote(t, items, secretNote, secretTag, "")
		requireNoNote(t, items, orgNote, orgTag, "")
	})

	t.Run("secret folder scope does not include the other dashboards", func(t *testing.T) {
		items := findAnnotations(t, repo, annotations.ItemQuery{OrgID: 1, SignedInUser: secretFolderReader, Limit: 100})
		requireNote(t, items, secretNote, secretTag, "Normal", "Alerting")
		requireNoNote(t, items, allowedNote, allowedTag, "")
		requireNoNote(t, items, generalNote, generalTag, "")
	})

	t.Run("dashboard uid wildcard reads every dashboard annotation and not organization annotations", func(t *testing.T) {
		allDashboards := dashboards.ScopeDashboardsProvider.GetResourceScopeUID("*")
		reader := signedInUser(ac.ActionAnnotationsRead, []string{allDashboards}, []string{allDashboards})
		items := findAnnotations(t, repo, annotations.ItemQuery{OrgID: 1, SignedInUser: reader, Limit: 100})
		requireNote(t, items, allowedNote, allowedTag, "Pending", "OK")
		requireNote(t, items, secretNote, secretTag, "Normal", "Alerting")
		requireNote(t, items, generalNote, generalTag, "Normal", "Normal")
		requireNoNote(t, items, orgNote, orgTag, "")
	})

	t.Run("annotation wildcard reads dashboard and organization annotations", func(t *testing.T) {
		reader := signedInUser(ac.ActionAnnotationsRead, []string{ac.ScopeAnnotationsAll}, []string{dashboards.ScopeDashboardsAll})
		items := findAnnotations(t, repo, annotations.ItemQuery{OrgID: 1, SignedInUser: reader, Limit: 100})
		requireNote(t, items, secretNote, secretTag, "Normal", "Alerting")
		requireNote(t, items, orgNote, orgTag, "", "")
	})

	t.Run("missing annotations read is forbidden", func(t *testing.T) {
		reader := signedInUser(dashboards.ActionDashboardsRead, dashboardRead, nil)
		require.False(t, ac.EvalPermission(ac.ActionAnnotationsRead).Evaluate(reader.GetPermissions()))
		_, err := repo.Find(ctx, &annotations.ItemQuery{OrgID: 1, SignedInUser: reader, Limit: 100})
		require.ErrorIs(t, err, annotationac.ErrReadForbidden)
	})

	t.Run("annotation id read resolves scopes and denies the secret annotation", func(t *testing.T) {
		checker := acimpl.ProvideAccessControlTest()
		checker.RegisterScopeAttributeResolver(api.AnnotationTypeScopeResolver(repo, features, dashes, folders))

		allowed, err := checker.Evaluate(ctx, scopedReader, ac.EvalPermission(
			ac.ActionAnnotationsRead,
			ac.Scope(ac.ScopeAnnotationsRoot, "id", strconv.FormatInt(secret.ID, 10)),
		))
		require.NoError(t, err)
		require.False(t, allowed)

		savedAllowed := findAnnotations(t, repo, annotations.ItemQuery{
			OrgID: 1, SignedInUser: scopedReader, Limit: 100, DashboardUID: allowedDashboardUID,
		})
		require.Len(t, savedAllowed, 1)
		allowedByID, err := checker.Evaluate(ctx, scopedReader, ac.EvalPermission(
			ac.ActionAnnotationsRead,
			ac.Scope(ac.ScopeAnnotationsRoot, "id", strconv.FormatInt(savedAllowed[0].ID, 10)),
		))
		require.NoError(t, err)
		require.True(t, allowedByID)

		ancestorAllowed, err := checker.Evaluate(ctx, ancestorReader, ac.EvalPermission(
			ac.ActionAnnotationsRead,
			ac.Scope(ac.ScopeAnnotationsRoot, "id", strconv.FormatInt(savedAllowed[0].ID, 10)),
		))
		require.NoError(t, err)
		require.True(t, ancestorAllowed)
	})
}

func signedInUser(annotationAction string, annotationScopes, dashboardScopes []string) *user.SignedInUser {
	permissions := map[string][]string{}
	if annotationScopes != nil {
		permissions[annotationAction] = annotationScopes
	}
	if dashboardScopes != nil {
		permissions[dashboards.ActionDashboardsRead] = dashboardScopes
	}
	return &user.SignedInUser{
		OrgID: 1,
		Permissions: map[int64]map[string][]string{
			1: permissions,
		},
	}
}

func findAnnotations(t *testing.T, repo *RepositoryImpl, query annotations.ItemQuery) []*annotations.ItemDTO {
	t.Helper()
	items, err := repo.Find(context.Background(), &query)
	require.NoError(t, err)
	return items
}

func requireNote(t *testing.T, items []*annotations.ItemDTO, text, tag, prevState, newState string) {
	t.Helper()
	for _, item := range items {
		if item.Text != text {
			continue
		}
		require.Contains(t, item.Tags, tag)
		require.Equal(t, authorLogin, item.Login)
		require.Equal(t, authorEmail, item.Email)
		require.Equal(t, prevState, item.PrevState)
		require.Equal(t, newState, item.NewState)
		return
	}
	require.Failf(t, "missing annotation", "annotation %q was not returned", text)
}

func requireNoNote(t *testing.T, items []*annotations.ItemDTO, text, tag, newState string) {
	t.Helper()
	for _, item := range items {
		require.NotEqual(t, text, item.Text)
		require.NotContains(t, item.Tags, tag)
		if newState != "" {
			require.NotEqual(t, newState, item.NewState)
		}
	}
}

func saveAnnotation(t *testing.T, store *xormRepositoryImpl, userID, dashboardID int64, dashboardUID, text string, tags []string, prevState, newState string) *annotations.Item {
	t.Helper()
	item := &annotations.Item{
		OrgID:        1,
		UserID:       userID,
		DashboardID:  dashboardID,
		DashboardUID: dashboardUID,
		Text:         text,
		Tags:         tags,
		PrevState:    prevState,
		NewState:     newState,
		Epoch:        time.Now().UnixMilli(),
	}
	require.NoError(t, store.Add(context.Background(), item))
	return item
}

func insertAuthor(t *testing.T, sql *sqlstore.SQLStore) int64 {
	t.Helper()
	var id int64
	err := sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		now := time.Now()
		_, err := sess.Exec(`INSERT INTO `+sql.GetDialect().Quote("user")+
			` (version, uid, login, email, name, org_id, is_admin, is_disabled, help_flags1, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			0, "author-uid", authorLogin, authorEmail, "Incident Author", 1, false, false, 0, now, now)
		if err != nil {
			return err
		}
		_, err = sess.SQL(`SELECT id FROM `+sql.GetDialect().Quote("user")+` WHERE uid = ?`, "author-uid").Get(&id)
		return err
	})
	require.NoError(t, err)
	require.NotZero(t, id)
	return id
}

func insertFolder(t *testing.T, sql *sqlstore.SQLStore, uid, parentUID string) {
	t.Helper()
	err := sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		now := time.Now()
		_, err := sess.Exec(`INSERT INTO folder (uid, org_id, title, parent_uid, created, updated) VALUES (?, ?, ?, ?, ?, ?)`,
			uid, 1, uid, parentUID, now, now)
		return err
	})
	require.NoError(t, err)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
