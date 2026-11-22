package state_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	gokitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana-plugin-sdk-go/data"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/log/text"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/clients"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	"github.com/grafana/grafana/pkg/services/ngalert/image"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/rendering"
	"github.com/grafana/grafana/pkg/services/screenshot"
	"github.com/grafana/grafana/pkg/setting"
)

// placeholderRendererToken is a test signing key, not a deployed credential.
const placeholderRendererToken = "placeholder-renderer-token"

func TestAlertScreenshotFailureDoesNotDiscloseRenderCredential(t *testing.T) {
	rs, renderLog := newRemoteRenderingService(t, closedTCPURL(t))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = rs.Run(ctx) }()
	waitUntilRenderWired(t, rs, renderLog)

	stateLog := &bytes.Buffer{}
	stateLogger := log.New(t.Name())
	stateLogger.Swap(level.NewFilter(text.NewTextLogger(stateLog), level.AllowInfo()))

	dashboardsService := &dashboards.FakeDashboardService{}
	dashboardsService.On("GetDashboard", mock.Anything, mock.Anything).Return(&dashboards.Dashboard{
		UID:   "dashuid",
		Slug:  "dash-slug",
		OrgID: 1,
	}, nil)

	screenshots := screenshot.NewHeadlessScreenshotService(rs.Cfg, dashboardsService, rs, prometheus.NewRegistry())
	images := image.NewScreenshotImageService(
		&image.NoOpCacheService{},
		&screenshot.NoOpRateLimiter{},
		log.NewNopLogger(),
		screenshots,
		5*time.Second,
		store.NewFakeImageStore(t),
		nil,
	)

	externalURL, err := url.Parse("http://127.0.0.1:3000/")
	require.NoError(t, err)
	mgr := state.NewManager(state.ManagerCfg{
		Log:         stateLogger,
		Images:      images,
		Clock:       clock.New(),
		Tracer:      tracing.InitializeTracerForTest(),
		ExternalURL: externalURL,
	}, state.NewNoopPersister())

	dashboardUID := "dashuid"
	panelID := int64(2)
	rule := &ngmodels.AlertRule{
		OrgID:           1,
		UID:             "ruleuid",
		Title:           "screenshot rule",
		IntervalSeconds: 60,
		NamespaceUID:    "ns",
		DashboardUID:    &dashboardUID,
		PanelID:         &panelID,
		NoDataState:     ngmodels.NoData,
		ExecErrState:    ngmodels.ErrorErrState,
		Labels:          map[string]string{},
		Annotations:     map[string]string{},
	}
	_, evalErr := mgr.ProcessEvalResults(context.Background(), time.Now(), rule, eval.Results{{
		State:       eval.Alerting,
		Instance:    data.Labels{"instance": "a"},
		EvaluatedAt: time.Now(),
	}}, nil, state.NoopSender)
	if evalErr != nil {
		t.Fatal("alert evaluation returned an error before screenshot capture could be checked")
	}

	logged := renderLog.String() + "\n" + stateLog.String()
	if !strings.Contains(logged, "Failed to send request to remote rendering service") {
		t.Fatal("alert screenshot did not reach the remote renderer")
	}
	if !strings.Contains(stateLog.String(), "Failed to take an image") {
		t.Fatal("alert state manager did not log the screenshot failure")
	}
	assertLogsDoNotAuthenticate(t, rs, logged)
}

func newRemoteRenderingService(t *testing.T, serverURL string) (*rendering.RenderingService, *bytes.Buffer) {
	t.Helper()
	cfg := setting.NewCfg()
	cfg.Env = setting.Prod
	cfg.AppURL = "http://127.0.0.1:3000/"
	cfg.RendererCallbackUrl = "http://127.0.0.1:3000/"
	cfg.RendererServerUrl = serverURL
	cfg.RendererAuthToken = placeholderRendererToken
	cfg.RendererRenderKeyLifeTime = 5 * time.Minute
	dir := t.TempDir()
	cfg.ImagesDir = filepath.Join(dir, "png")
	cfg.CSVsDir = filepath.Join(dir, "csv")
	cfg.PDFsDir = filepath.Join(dir, "pdf")

	buf := &bytes.Buffer{}
	logger := log.New("rendering")
	logger.Swap(level.NewFilter(text.NewTextLogger(buf), level.AllowInfo()))
	t.Cleanup(func() {
		logger.Swap(gokitlog.NewNopLogger())
	})

	rs, err := rendering.ProvideService(cfg, featuremgmt.WithFeatures(featuremgmt.FlagRenderAuthJWT), nil)
	require.NoError(t, err)
	return rs, buf
}

func waitUntilRenderWired(t *testing.T, rs *rendering.RenderingService, renderLog *bytes.Buffer) {
	t.Helper()
	require.Eventually(t, func() bool {
		defer func() { _ = recover() }()
		_, err := rs.Render(context.Background(), rendering.RenderPNG, rendering.Opts{
			CommonOpts: rendering.CommonOpts{
				TimeoutOpts: rendering.TimeoutOpts{Timeout: time.Second},
				Path:        "d-solo/probe/probe?orgId=1",
				AuthOpts: rendering.AuthOpts{
					OrgID:   1,
					UserID:  7,
					OrgRole: "Viewer",
				},
			},
		})
		return err != nil
	}, 2*time.Second, 10*time.Millisecond)
	renderLog.Reset()
}

func assertLogsDoNotAuthenticate(t *testing.T, rs rendering.Service, logged string) {
	t.Helper()
	client := clients.ProvideRender(rs)
	for _, candidate := range credentialCandidates(logged) {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:3000/d-solo/dash/slug", nil)
		req.Header.Set("Cookie", "renderKey="+candidate)
		identity, err := client.Authenticate(context.Background(), &authn.Request{HTTPRequest: req})
		if err == nil && identity != nil {
			t.Fatalf("alert screenshot log contained a render cookie that authenticated as type %s org %d id %s", identity.Type, identity.OrgID, identity.ID)
		}
	}
}

var (
	jwtCandidate       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+=*\.[A-Za-z0-9_-]+=*\.[A-Za-z0-9_-]+=*`)
	renderKeyCandidate = regexp.MustCompile(`renderKey=([^&\s"\\]+)`)
)

func credentialCandidates(blob string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(value string) {
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = decoded
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, match := range jwtCandidate.FindAllString(blob, -1) {
		add(match)
	}
	for _, match := range renderKeyCandidate.FindAllStringSubmatch(blob, -1) {
		add(match[1])
	}
	return out
}

func closedTCPURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return "http://" + addr + "/render"
}
