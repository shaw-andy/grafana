package notifier

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	alertingModels "github.com/grafana/alerting/models"
	alertingNotify "github.com/grafana/alerting/notify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/grafana/authlib/authn"
	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/types"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	grafanaauthn "github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/authz/rbac"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	ngimage "github.com/grafana/grafana/pkg/services/ngalert/image"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/rendering"
	"github.com/grafana/grafana/pkg/services/screenshot"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	screenshotOrgID       = int64(12)
	screenshotOrgNS       = "org-12"
	screenshotAuthorID    = "42"
	screenshotOwnDS       = "own-ds"
	screenshotSecretDS    = "secret-ds"
	screenshotAllowedDash = "allowed-dash"
	screenshotSecretDash  = "secret-dash"
	ownPanelResult        = "panel-result:" + screenshotOwnDS
	secretPanelResult     = "panel-result:" + screenshotSecretDS
)

// The firing path stores a panel screenshot and the notifier reads those bytes
// back for the contact point. The author is the rule's UpdatedBy. The tick
// context is not that user. A dashboard the author cannot read, and a
// datasource the author cannot query, must not be rendered or delivered.
func TestAlertScreenshotDoesNotDiscloseUnreadableDashboard(t *testing.T) {
	author := screenshotAuthor()

	t.Run("dashboard the author cannot read is not captured or delivered", func(t *testing.T) {
		env := newScreenshotEnv(t, "")
		img, err := env.capture(author, screenshotSecretDash, 7)
		delivered := env.delivered(t)
		require.NotContains(t, delivered, secretPanelResult)
		require.Zero(t, env.hits.Load(), "renderer was called for a dashboard the author cannot read")
		require.False(t, env.sawFile.Load(), "a screenshot file was created before the capture was refused")
		require.Error(t, err)
		require.Nil(t, img)
	})

	t.Run("readable dashboard is rendered as the author and omits datasources they cannot query", func(t *testing.T) {
		env := newScreenshotEnv(t, "")
		img, err := env.capture(author, screenshotAllowedDash, 3)
		require.NoError(t, err)
		require.NotNil(t, img)
		require.NoError(t, env.checkErr)

		delivered := env.delivered(t)
		require.Contains(t, delivered, ownPanelResult)
		require.NotContains(t, delivered, secretPanelResult)
		require.Equal(t, screenshotAllowedDash, env.renderedDashboard)
		require.NotEqual(t, screenshotSecretDash, env.renderedDashboard)
		require.Equal(t, types.TypeUser, env.identityType)
		require.Equal(t, screenshotAuthorID, env.identityID)
		require.True(t, env.allowedDashRead)
		require.True(t, env.ownQuery)
		require.False(t, env.secretDashRead)
		require.False(t, env.secretQuery)
	})

	t.Run("a later dashboard lookup cannot replace the dashboard that was authorized", func(t *testing.T) {
		env := newScreenshotEnv(t, screenshotSecretDash)
		img, err := env.capture(author, screenshotAllowedDash, 3)
		require.NoError(t, err)
		require.NotNil(t, img)
		require.NoError(t, env.checkErr)

		delivered := env.delivered(t)
		require.Contains(t, delivered, ownPanelResult)
		require.NotContains(t, delivered, secretPanelResult)
		require.Equal(t, screenshotAllowedDash, env.renderedDashboard)
		require.Equal(t, types.TypeUser, env.identityType)
		require.Equal(t, screenshotAuthorID, env.identityID)
		require.False(t, env.secretDashRead)
		require.False(t, env.secretQuery)
	})
}

type screenshotEnv struct {
	images  ngimage.ImageService
	saved   *recordingImages
	hits    atomic.Int32
	sawFile atomic.Bool

	mu                sync.Mutex
	renderedDashboard string
	identityType      types.IdentityType
	identityID        string
	ownQuery          bool
	secretQuery       bool
	allowedDashRead   bool
	secretDashRead    bool
	checkErr          error
	stopWatch         chan struct{}
}

func newScreenshotEnv(t *testing.T, swapTo string) *screenshotEnv {
	t.Helper()
	env := &screenshotEnv{stopWatch: make(chan struct{})}
	authz := rbac.NewTestService(screenshotAuthorID, authorPermissions(), nil)
	caller := authn.NewAccessTokenAuthInfo(authn.Claims[authn.AccessTokenClaims]{
		Claims: jwt.Claims{
			Subject:  types.NewTypeID(types.TypeAccessPolicy, "authz-caller"),
			Audience: []string{"authzservice"},
		},
		Rest: authn.AccessTokenClaims{Namespace: screenshotOrgNS},
	})
	checkCtx := types.WithAuthInfo(context.Background(), caller)

	var rs *rendering.RenderingService
	versionSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/version") {
			select {
			case versionSeen <- struct{}{}:
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"version":"3.12.0"}`)
			return
		}
		env.hits.Add(1)
		env.servePanel(authz, checkCtx, rs, w, r)
	}))
	t.Cleanup(server.Close)

	imgDir := t.TempDir()
	cfg := setting.NewCfg()
	cfg.ImagesDir = filepath.Join(imgDir, "png")
	cfg.CSVsDir = filepath.Join(imgDir, "csv")
	cfg.PDFsDir = filepath.Join(imgDir, "pdf")
	cfg.RendererServerUrl = server.URL
	cfg.RendererCallbackUrl = "http://127.0.0.1:3000/"
	cfg.RendererRenderKeyLifeTime = time.Minute
	require.NoError(t, os.MkdirAll(cfg.ImagesDir, 0o750))
	require.NoError(t, os.MkdirAll(cfg.CSVsDir, 0o750))
	require.NoError(t, os.MkdirAll(cfg.PDFsDir, 0o750))

	var err error
	rs, err = rendering.ProvideService(cfg, featuremgmt.WithFeatures(), remotecache.NewFakeStore(t))
	require.NoError(t, err)
	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = rs.Run(runCtx) }()
	select {
	case <-versionSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("image renderer was not asked for its version")
	}

	env.saved = &recordingImages{FakeImageStore: store.NewFakeImageStore(t)}
	shots := screenshot.NewHeadlessScreenshotService(cfg, &swappingDashboards{swapTo: swapTo}, rs, prometheus.NewRegistry())
	env.images = ngimage.NewScreenshotImageService(&ngimage.NoOpCacheService{}, &screenshot.NoOpRateLimiter{}, log.NewNopLogger(), shots, 5*time.Second, env.saved, nil)

	go env.watch(cfg.ImagesDir)
	t.Cleanup(func() { close(env.stopWatch) })
	return env
}

func (env *screenshotEnv) capture(author *user.SignedInUser, dashboardUID string, panelID int64) (*models.Image, error) {
	panel := panelID
	rule := &models.AlertRule{
		OrgID:        screenshotOrgID,
		UID:          "rule-1",
		Title:        "editor rule",
		DashboardUID: &dashboardUID,
		PanelID:      &panel,
		UpdatedBy:    models.NewUserUID(author),
	}
	// Evaluation calls NewImage with the tick context, not the rule author.
	return env.images.NewImage(context.Background(), rule)
}

func (env *screenshotEnv) delivered(t *testing.T) string {
	t.Helper()
	provider := newImageProvider(env.saved, log.NewNopLogger())
	var chunks []string
	env.saved.mu.Lock()
	saved := append([]*models.Image(nil), env.saved.saved...)
	env.saved.mu.Unlock()
	for _, image := range saved {
		alert := alertingNotify.Alert{
			Alert: model.Alert{
				Annotations: model.LabelSet{alertingModels.ImageTokenAnnotation: model.LabelValue(image.Token)},
			},
		}
		got, err := provider.GetImage(context.Background(), alert)
		if err != nil || got == nil || got.RawData == nil {
			continue
		}
		content, err := got.RawData(context.Background())
		if err != nil {
			continue
		}
		chunks = append(chunks, string(content.Content))
	}
	return strings.Join(chunks, "\n")
}

func (env *screenshotEnv) servePanel(authz *rbac.Service, checkCtx context.Context, rs *rendering.RenderingService, w http.ResponseWriter, r *http.Request) {
	// grafana-image-renderer pkg/api/render.go reads these query params and, when
	// both are set, adds a renderKey cookie before the browser opens the callback URL.
	target := r.URL.Query().Get("url")
	renderKey := r.URL.Query().Get("renderKey")
	domain := r.URL.Query().Get("domain")
	callback, err := url.Parse(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// grafana-image-renderer pkg/service/browser.go sets the cookie, then navigates
	// to the callback URL. The cookie is sent when the callback host is that domain.
	if renderKey != "" && domain != "" && cookieDomainMatches(callback.Hostname(), domain) {
		req.AddCookie(&http.Cookie{Name: "renderKey", Value: renderKey})
	}
	ident, err := clients.ProvideRender(rs).Authenticate(r.Context(), &grafanaauthn.Request{HTTPRequest: req})
	if err != nil {
		env.mu.Lock()
		env.checkErr = err
		env.mu.Unlock()
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(callback.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "d-solo" {
		http.Error(w, "unexpected callback path "+callback.Path, http.StatusBadRequest)
		return
	}
	dashUID := parts[1]
	subject := string(ident.Type) + ":" + ident.ID
	ownQuery, err := allow(authz, checkCtx, subject, "query.grafana.app", "query", "create", screenshotOwnDS)
	if err != nil {
		env.noteErr(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	secretQuery, err := allow(authz, checkCtx, subject, "query.grafana.app", "query", "create", screenshotSecretDS)
	if err != nil {
		env.noteErr(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allowedDash, err := allow(authz, checkCtx, subject, "dashboard.grafana.app", "dashboards", "get", screenshotAllowedDash)
	if err != nil {
		env.noteErr(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	secretDash, err := allow(authz, checkCtx, subject, "dashboard.grafana.app", "dashboards", "get", screenshotSecretDash)
	if err != nil {
		env.noteErr(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	env.mu.Lock()
	env.renderedDashboard = dashUID
	env.identityType = ident.Type
	env.identityID = ident.ID
	env.ownQuery = ownQuery
	env.secretQuery = secretQuery
	env.allowedDashRead = allowedDash
	env.secretDashRead = secretDash
	env.mu.Unlock()

	datasource := screenshotSecretDS
	canQuery := secretQuery
	if dashUID == screenshotAllowedDash {
		datasource = screenshotOwnDS
		canQuery = ownQuery
	}
	if !canQuery {
		_, _ = io.WriteString(w, "panel-denied")
		return
	}
	_, _ = io.WriteString(w, "panel-result:"+datasource)
}

func (env *screenshotEnv) noteErr(err error) {
	env.mu.Lock()
	env.checkErr = err
	env.mu.Unlock()
}

func (env *screenshotEnv) watch(dir string) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-env.stopWatch:
			return
		case <-ticker.C:
			entries, err := os.ReadDir(dir)
			if err == nil && len(entries) > 0 {
				env.sawFile.Store(true)
			}
		}
	}
}

func cookieDomainMatches(host, domain string) bool {
	if host == "" || domain == "" {
		return false
	}
	if strings.Contains(domain, ":") && !strings.Contains(domain, "[") && !strings.Contains(domain, "]") {
		domain = "[" + domain + "]"
		host = "[" + host + "]"
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func allow(authz *rbac.Service, ctx context.Context, subject, group, resource, verb, name string) (bool, error) {
	resp, err := authz.Check(ctx, &authzv1.CheckRequest{
		Namespace: screenshotOrgNS,
		Subject:   subject,
		Group:     group,
		Resource:  resource,
		Verb:      verb,
		Name:      name,
	})
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}

func screenshotAuthor() *user.SignedInUser {
	return &user.SignedInUser{UserID: 42, OrgID: screenshotOrgID, OrgRole: identity.RoleEditor}
}

func authorPermissions() []accesscontrol.Permission {
	return []accesscontrol.Permission{
		{Action: datasources.ActionQuery, Scope: datasources.ScopeProvider.GetResourceScopeUID(screenshotOwnDS)},
		{Action: dashboards.ActionDashboardsRead, Scope: dashboards.ScopeDashboardsProvider.GetResourceScopeUID(screenshotAllowedDash)},
	}
}

type recordingImages struct {
	*store.FakeImageStore
	mu    sync.Mutex
	saved []*models.Image
}

func (r *recordingImages) SaveImage(ctx context.Context, img *models.Image) error {
	if err := r.FakeImageStore.SaveImage(ctx, img); err != nil {
		return err
	}
	r.mu.Lock()
	cp := *img
	r.saved = append(r.saved, &cp)
	r.mu.Unlock()
	return nil
}

type swappingDashboards struct {
	dashboards.FakeDashboardService
	mu     sync.Mutex
	calls  int
	swapTo string
}

func (d *swappingDashboards) GetDashboard(_ context.Context, query *dashboards.GetDashboardQuery) (*dashboards.Dashboard, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	uid := query.UID
	if call > 1 && d.swapTo != "" {
		uid = d.swapTo
	}
	return &dashboards.Dashboard{UID: uid, Slug: uid, OrgID: query.OrgID}, nil
}
