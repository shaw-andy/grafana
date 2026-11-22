package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	alertingImages "github.com/grafana/alerting/images"
	alertingModels "github.com/grafana/alerting/models"
	"github.com/grafana/alerting/receivers"
	alertingEmail "github.com/grafana/alerting/receivers/email/v1"
	alertingTemplates "github.com/grafana/alerting/templates"
	sdkdata "github.com/grafana/grafana-plugin-sdk-go/data"
	ammodels "github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/alertmanager/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/components/imguploader"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/log/logtest"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/middleware/loggermw"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	"github.com/grafana/grafana/pkg/services/ngalert/image"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/notifications"
	"github.com/grafana/grafana/pkg/services/rendering"
	"github.com/grafana/grafana/pkg/services/screenshot"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// TestLocalImageStorageScreenshotsAreNotAnonymous checks the screenshot path
// used when external image storage is local: the renderer writes a PNG under
// the images directory, the local uploader publishes an attachments URL, that
// URL is copied onto the alert and into the notification, and the HTTP server
// is asked for the file with no session.
//
// The assertions are the behavior the server must have. They fail while the
// images directory is mounted on an unauthenticated route.
func TestLocalImageStorageScreenshotsAreNotAnonymous(t *testing.T) {
	markerA := []byte("screenshot-marker-private-dashboard-a-7f3c1e")
	markerB := []byte("screenshot-marker-private-dashboard-b-91ab40")

	cfg, renderSrv := startRenderingService(t, map[string][]byte{
		"panelId=1": markerA,
		"panelId=2": markerB,
	})
	require.Equal(t, setting.Prod, cfg.Env)
	require.Equal(t, "local", cfg.ImageUploadProvider)
	require.True(t, cfg.UnifiedAlerting.Screenshots.Capture)
	require.True(t, cfg.UnifiedAlerting.Screenshots.UploadExternalImageStorage)
	require.False(t, cfg.Anonymous.Enabled)

	images := store.NewFakeImageStore(t)
	reg := prometheus.NewRegistry()
	uploader, err := imguploader.NewImageUploader(cfg)
	require.NoError(t, err)
	ds := dashboards.NewFakeDashboardService(t)
	ds.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{
		UID:   "private-dash",
		Slug:  "private-dash",
		OrgID: 1,
		Title: "Private",
	}, nil).Twice()

	svc := image.NewScreenshotImageService(
		&image.NoOpCacheService{},
		&screenshot.NoOpRateLimiter{},
		log.New("ngalert.image"),
		screenshot.NewHeadlessScreenshotService(cfg, ds, renderSrv, reg),
		cfg.UnifiedAlerting.Screenshots.CaptureTimeout,
		images,
		image.NewUploadingService(uploader, reg),
	)

	imageA := takeScreenshot(t, svc, 1)
	imageB := takeScreenshot(t, svc, 2)
	require.Equal(t, markerA, mustRead(t, imageA.Path))
	require.Equal(t, markerB, mustRead(t, imageB.Path))
	require.True(t, strings.HasPrefix(filepath.Clean(imageA.Path), filepath.Clean(cfg.ImagesDir)+string(os.PathSeparator)))

	appURL, err := url.Parse(cfg.AppURL)
	require.NoError(t, err)
	postable := state.StateToPostableAlert(state.StateTransition{
		State: &state.State{
			State:       eval.Alerting,
			Labels:      sdkdata.Labels{"alertname": "PrivatePanel"},
			Annotations: map[string]string{},
			Image:       imageA,
			StartsAt:    time.Now(),
			EndsAt:      time.Now().Add(time.Hour),
		},
		PreviousState: eval.Normal,
	}, appURL)

	html := notificationHTML(t, cfg, images, notifyAlert(postable))
	published := []string{}
	if urlFromAlert := postable.Annotations[alertingModels.ImageURLAnnotation]; urlFromAlert != "" {
		published = append(published, urlFromAlert)
	}
	published = append(published, urlsIn(html)...)
	if imageA.URL != "" {
		published = append(published, imageA.URL)
	}

	server := newAttachmentServer(t, cfg)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// The stable path has no session and no query credential. Both rendered
	// files live in the mounted directory, including one the caller addresses
	// only by filename.
	assertAnonymousDoesNotReceive(t, client, server.URL, stableAttachmentPath(imageA), markerA)
	assertAnonymousDoesNotReceive(t, client, server.URL, stableAttachmentPath(imageB), markerB)

	// A credential carried by A's published address must not authorize B.
	// Today the address has no credential, so this is B's stable path.
	swapped := swapPublishedCredential(imageA.URL, imageB)
	assertAnonymousDoesNotReceive(t, client, server.URL, swapped, markerB)

	for _, address := range published {
		assertPublishedAddressIsNotPublic(t, client, server.URL, address, markerA)
	}
}

// TestImagesDirectoryStaysPrivateForOtherProviders checks the same files are
// not mounted when the provider is not local. This is the configuration gate
// around the mount.
func TestImagesDirectoryStaysPrivateForOtherProviders(t *testing.T) {
	marker := []byte("screenshot-marker-not-mounted-c4e8aa")
	cfg, _ := startRenderingService(t, map[string][]byte{"panelId=1": marker})
	cfg.ImageUploadProvider = "s3"

	path, err := filepath.Abs(filepath.Join(cfg.ImagesDir, "not-published.png"))
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(cfg.ImagesDir, 0o750))
	require.NoError(t, os.WriteFile(path, marker, 0o600))

	server := newAttachmentServer(t, cfg)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	assertAnonymousDoesNotReceive(t, client, server.URL, "/public/img/attachments/not-published.png", marker)
}

func startRenderingService(t *testing.T, panels map[string][]byte) (*setting.Cfg, *rendering.RenderingService) {
	t.Helper()

	renderer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/version") {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"version":"3.12.0"}`))
			require.NoError(t, err)
			return
		}
		callback := r.URL.Query().Get("url")
		var body []byte
		for panel, marker := range panels {
			if strings.Contains(callback, panel) {
				body = marker
				break
			}
		}
		if body == nil {
			http.Error(w, "unknown panel", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(body)
		require.NoError(t, err)
	}))
	t.Cleanup(renderer.Close)

	dataDir := t.TempDir()
	custom := filepath.Join(t.TempDir(), "custom.ini")
	ini := fmt.Sprintf(`
app_mode = production

[paths]
data = %s

[server]
root_url = http://grafana.example:3000/

[external_image_storage]
provider = local

[unified_alerting.screenshots]
capture = true
upload_external_image_storage = true

[rendering]
renderer_token = placeholder-renderer-token

[smtp]
enabled = true

[auth.anonymous]
enabled = false
`, dataDir)
	require.NoError(t, os.WriteFile(custom, []byte(ini), 0o600))

	cfg := setting.NewCfg()
	require.NoError(t, cfg.Load(setting.CommandLineArgs{
		HomePath: repoRoot(t),
		Config:   custom,
	}))
	cfg.RendererServerUrl = renderer.URL + "/render"

	features := featuremgmt.WithFeatures(featuremgmt.FlagRenderAuthJWT)
	rs, err := rendering.ProvideService(cfg, features, nil)
	require.NoError(t, err)

	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = rs.Run(runCtx)
	}()
	require.Eventually(t, func() bool {
		return rs.Version() == "3.12.0"
	}, 5*time.Second, 20*time.Millisecond)

	return cfg, rs
}

func takeScreenshot(t *testing.T, svc image.ImageService, panelID int64) *ngmodels.Image {
	t.Helper()
	dash := "private-dash"
	panel := panelID
	got, err := svc.NewImage(context.Background(), &ngmodels.AlertRule{
		OrgID:        1,
		UID:          "rule",
		DashboardUID: &dash,
		PanelID:      &panel,
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	return got
}

func newAttachmentServer(t *testing.T, cfg *setting.Cfg) *httptest.Server {
	t.Helper()
	features := featuremgmt.WithFeatures()
	hs := &HTTPServer{
		log:              log.New("test"),
		Cfg:              cfg,
		Features:         features,
		promRegister:     prometheus.NewRegistry(),
		LoggerMiddleware: loggermw.Provide(cfg, features),
		Csrf:             csrf.ProvideCSRFFilter(cfg),
		ContextHandler: contexthandler.ProvideService(cfg, &authntest.FakeService{
			ExpectedErr: fmt.Errorf("no session"),
		}, features),
	}
	hs.web = web.New()
	hs.addMiddlewaresAndStaticRoutes()
	hs.web.NotFound(middleware.ProvideRouteOperationName("notfound"), middleware.ReqSignedIn, hs.NotFoundHandler)

	server := httptest.NewServer(hs.web)
	t.Cleanup(server.Close)
	return server
}

func notificationHTML(t *testing.T, cfg *setting.Cfg, images store.ImageStore, alert *types.Alert) string {
	t.Helper()
	mailer := notifications.NewFakeMailer()
	ns, err := notifications.ProvideService(bus.ProvideBus(tracing.InitializeTracerForTest()), cfg, mailer, nil)
	require.NoError(t, err)

	notifier := alertingEmail.New(alertingEmail.Config{
		SingleEmail: true,
		Addresses:   []string{"ops@example.com"},
		// An empty message selects the default alert body, which renders ImageURL.
		Subject: "alert",
	}, receivers.Metadata{}, alertingTemplates.ForTests(t), notificationEmailSender{ns: ns},
		alertingImages.NewTokenProvider(&notificationTokenStore{store: images, logger: log.NewNopLogger()}, &logtest.Fake{}),
		&logtest.Fake{})

	ok, err := notifier.Notify(context.Background(), alert)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, mailer.Sent, 1)
	body := mailer.Sent[0].Body["text/html"]
	require.NotEmpty(t, body)
	return body
}

func notifyAlert(postable *ammodels.PostableAlert) *types.Alert {
	annotations := model.LabelSet{}
	for k, v := range postable.Annotations {
		annotations[model.LabelName(k)] = model.LabelValue(v)
	}
	labels := model.LabelSet{}
	for k, v := range postable.Labels {
		labels[model.LabelName(k)] = model.LabelValue(v)
	}
	return &types.Alert{
		Alert: model.Alert{
			Labels:      labels,
			Annotations: annotations,
			StartsAt:    time.Time(postable.StartsAt),
			EndsAt:      time.Time(postable.EndsAt),
		},
	}
}

func stableAttachmentPath(img *ngmodels.Image) string {
	return "/public/img/attachments/" + filepath.Base(img.Path)
}

func swapPublishedCredential(published string, other *ngmodels.Image) string {
	u, err := url.Parse(published)
	if err != nil {
		return stableAttachmentPath(other)
	}
	swapped := url.URL{Path: stableAttachmentPath(other), RawQuery: u.RawQuery}
	return swapped.String()
}

func urlsIn(html string) []string {
	var out []string
	seen := map[string]struct{}{}
	rest := html
	for {
		i := strings.Index(rest, "http://")
		j := strings.Index(rest, "https://")
		start := -1
		switch {
		case i >= 0 && (j < 0 || i < j):
			start = i
		case j >= 0:
			start = j
		default:
			return out
		}
		rest = rest[start:]
		end := strings.IndexAny(rest, "\"' <>")
		if end < 0 {
			end = len(rest)
		}
		raw := rest[:end]
		rest = rest[end:]
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
}

func assertAnonymousDoesNotReceive(t *testing.T, client *http.Client, serverURL, target string, secret []byte) {
	t.Helper()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		resp, body := anonymousRequest(t, client, serverURL, method, target, false)
		if bytes.Contains(body, secret) || resp.ContentLength == int64(len(secret)) && resp.StatusCode == http.StatusOK {
			t.Fatalf("anonymous %s %s returned the screenshot (status %d, cache %q)", method, target, resp.StatusCode, resp.Header.Get("Cache-Control"))
		}
		if strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "public") &&
			(bytes.Contains(body, secret) || resp.ContentLength == int64(len(secret))) {
			t.Fatalf("anonymous %s %s is publicly cacheable (status %d, cache %q)", method, target, resp.StatusCode, resp.Header.Get("Cache-Control"))
		}
	}

	resp, body := anonymousRequest(t, client, serverURL, http.MethodGet, target, true)
	if bytes.Contains(body, secret) {
		t.Fatalf("anonymous GET %s with gzip returned the screenshot (status %d, cache %q)", target, resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
}

func assertPublishedAddressIsNotPublic(t *testing.T, client *http.Client, serverURL, published string, secret []byte) {
	t.Helper()
	u, err := url.Parse(published)
	require.NoError(t, err)
	if u.Host != "" && u.Host != "grafana.example:3000" && !strings.HasPrefix(published, serverURL) {
		return
	}
	// Drop any query before requesting. A later signed URL may keep working
	// while it is presented in full; the stable path must not.
	pathOnly := u.Path
	if pathOnly == "" {
		pathOnly = published
	}
	assertAnonymousDoesNotReceive(t, client, serverURL, pathOnly, secret)

	resp, body := anonymousRequest(t, client, serverURL, http.MethodGet, published, false)
	if bytes.Contains(body, secret) && strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "public") {
		t.Fatalf("published address %s returned the screenshot with Cache-Control %q", published, resp.Header.Get("Cache-Control"))
	}
}

func anonymousRequest(t *testing.T, client *http.Client, serverURL, method, target string, gzipAccept bool) (*http.Response, []byte) {
	t.Helper()
	requestURL := target
	if parsed, err := url.Parse(target); err == nil && parsed.IsAbs() {
		requestURL = serverURL + parsed.RequestURI()
	} else if strings.HasPrefix(target, "/") {
		requestURL = serverURL + target
	}
	req, err := http.NewRequest(method, requestURL, nil)
	require.NoError(t, err)
	if gzipAccept {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	body := decodeBody(t, resp)
	return resp, body
}

func decodeBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" && resp.Body != nil {
		zr, err := gzip.NewReader(resp.Body)
		require.NoError(t, err)
		defer zr.Close()
		reader = zr
	}
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	return body
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(wd, "conf", "defaults.ini")); err == nil {
			return wd
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			t.Fatal("could not find conf/defaults.ini from the working directory")
		}
		wd = parent
	}
}

// notificationEmailSender matches notifier.emailSender. SendEmail copies the
// alerting command onto the Grafana notification service.
type notificationEmailSender struct {
	ns notifications.Service
}

func (s notificationEmailSender) SendEmail(ctx context.Context, cmd *receivers.SendEmailSettings) error {
	send := notifications.SendEmailCommand{
		To:            cmd.To,
		SingleEmail:   cmd.SingleEmail,
		Template:      cmd.Template,
		Subject:       cmd.Subject,
		Data:          cmd.Data,
		ReplyTo:       cmd.ReplyTo,
		EmbeddedFiles: cmd.EmbeddedFiles,
	}
	if len(cmd.EmbeddedContents) > 0 {
		send.EmbeddedContents = make([]notifications.EmbeddedContent, len(cmd.EmbeddedContents))
		for i, ec := range cmd.EmbeddedContents {
			send.EmbeddedContents[i] = notifications.EmbeddedContent{Name: ec.Name, Content: ec.Content}
		}
	}
	return s.ns.SendEmailCommandHandlerSync(ctx, &notifications.SendEmailCommandSync{SendEmailCommand: send})
}

// notificationTokenStore matches notifier.tokenStore. GetImage loads the stored
// screenshot and returns its URL to the notifier.
type notificationTokenStore struct {
	store  store.ImageStore
	logger log.Logger
}

func (t *notificationTokenStore) GetImage(ctx context.Context, token string) (*alertingImages.Image, error) {
	image, err := t.store.GetImage(ctx, token)
	if err != nil {
		if errors.Is(err, ngmodels.ErrImageNotFound) {
			return nil, alertingImages.ErrImageNotFound
		}
		return nil, err
	}
	return &alertingImages.Image{
		ID:  token,
		URL: image.URL,
		RawData: func(context.Context) (alertingImages.ImageContent, error) {
			if image.Path == "" {
				return alertingImages.ImageContent{}, ngmodels.ErrImageDataUnavailable
			}
			b, err := os.ReadFile(image.Path)
			if err != nil {
				return alertingImages.ImageContent{}, err
			}
			return alertingImages.ImageContent{Name: filepath.Base(image.Path), Content: b}, nil
		},
	}, nil
}
