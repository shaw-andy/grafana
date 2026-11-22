package rendering

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log/level"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/log/text"
	"github.com/grafana/grafana/pkg/infra/remotecache"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tests/testsuite"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

// placeholderRendererToken is a test signing key, not a deployed credential.
const placeholderRendererToken = "placeholder-renderer-token"

func TestRenderAuthJWTEnabledByDefault(t *testing.T) {
	cfg := setting.NewCfg()
	fm, err := featuremgmt.ProvideManagerService(cfg)
	require.NoError(t, err)
	require.True(t, fm.IsEnabledGlobally(featuremgmt.FlagRenderAuthJWT), "renderAuthJWT is the production default")
}

func TestRemoteRendererFailureDoesNotDiscloseRenderCredential(t *testing.T) {
	t.Run("connection refused png as signed-in user", func(t *testing.T) {
		assertTransportFailureDoesNotDisclose(t, transportCase{
			serverURL: closedTCPURL(t),
			render:    renderPNGAsUser,
			debug:     false,
		})
	})

	t.Run("connection refused png as render service", func(t *testing.T) {
		assertTransportFailureDoesNotDisclose(t, transportCase{
			serverURL: closedTCPURL(t),
			render:    renderPNGAsRenderService,
			debug:     false,
		})
	})

	t.Run("connection refused pdf", func(t *testing.T) {
		assertTransportFailureDoesNotDisclose(t, transportCase{
			serverURL: closedTCPURL(t),
			render:    renderPDF,
			debug:     false,
		})
	})

	t.Run("connection refused csv", func(t *testing.T) {
		assertTransportFailureDoesNotDisclose(t, transportCase{
			serverURL: closedTCPURL(t),
			render:    renderCSV,
			debug:     false,
		})
	})

	t.Run("tls verification failure", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(server.Close)
		assertTransportFailureDoesNotDisclose(t, transportCase{
			serverURL: server.URL + "/render",
			render:    renderPNGAsUser,
			debug:     false,
		})
	})

	t.Run("client timeout", func(t *testing.T) {
		assertTransportFailureDoesNotDisclose(t, transportCase{
			serverURL: hangingTCPURL(t),
			render:    renderPNGAsUser,
			debug:     false,
			timeout:   200 * time.Millisecond,
		})
	})

	t.Run("debug log of the outbound url", func(t *testing.T) {
		assertTransportFailureDoesNotDisclose(t, transportCase{
			serverURL: closedTCPURL(t),
			render:    renderPNGAsUser,
			debug:     true,
		})
	})
}

func TestRemoteRendererFailureWithCacheKeyDoesNotStayValid(t *testing.T) {
	// The non-default provider stores a one-time key. A failed render must not
	// leave that key usable, including when the failure is written to the log.
	rs, buf := newTestRenderingService(t, closedTCPURL(t), false, false)
	err := renderPNGAsUser(t, rs, time.Second)
	requireTransportFailure(t, err)
	requireRendererAttemptLogged(t, buf.String())
	assertNoAcceptedRenderCredential(t, rs, buf.String(), err.Error())
}

type transportCase struct {
	serverURL string
	render    func(t *testing.T, rs *RenderingService, timeout time.Duration) error
	debug     bool
	timeout   time.Duration
}

func assertTransportFailureDoesNotDisclose(t *testing.T, tc transportCase) {
	t.Helper()
	timeout := tc.timeout
	if timeout == 0 {
		timeout = time.Second
	}
	rs, buf := newTestRenderingService(t, tc.serverURL, true, tc.debug)
	err := tc.render(t, rs, timeout)
	requireTransportFailure(t, err)
	logged := buf.String()
	requireRendererAttemptLogged(t, logged)
	assertNoAcceptedRenderCredential(t, rs, logged, err.Error())
}

func newTestRenderingService(t *testing.T, serverURL string, jwt bool, debug bool) (*RenderingService, *bytes.Buffer) {
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

	var cache *remotecache.RemoteCache
	features := featuremgmt.WithFeatures(featuremgmt.FlagRenderAuthJWT)
	if !jwt {
		features = featuremgmt.WithFeatures()
		cache = remotecache.NewFakeStore(t)
	}

	rs, err := ProvideService(cfg, features, cache)
	require.NoError(t, err)
	// Run assigns these when a remote renderer URL is configured.
	rs.renderAction = rs.renderViaHTTP
	rs.renderCSVAction = rs.renderCSVViaHTTP
	rs.version = "4.0.0"

	buf := &bytes.Buffer{}
	opt := level.AllowInfo()
	if debug {
		opt = level.AllowDebug()
	}
	logger := log.New(t.Name())
	logger.Swap(level.NewFilter(text.NewTextLogger(buf), opt))
	rs.log = logger
	return rs, buf
}

func renderPNGAsUser(t *testing.T, rs *RenderingService, timeout time.Duration) error {
	t.Helper()
	_, err := rs.Render(context.Background(), RenderPNG, Opts{
		CommonOpts: userRenderOpts(timeout),
		Width:      100,
		Height:     100,
	})
	return err
}

func renderPNGAsRenderService(t *testing.T, rs *RenderingService, timeout time.Duration) error {
	t.Helper()
	opts := userRenderOpts(timeout)
	opts.AuthOpts = renderingServiceAuth()
	_, err := rs.Render(context.Background(), RenderPNG, Opts{
		CommonOpts: opts,
		Width:      100,
		Height:     100,
	})
	return err
}

func renderPDF(t *testing.T, rs *RenderingService, timeout time.Duration) error {
	t.Helper()
	_, err := rs.Render(context.Background(), RenderPDF, Opts{
		CommonOpts: userRenderOpts(timeout),
	})
	return err
}

func renderCSV(t *testing.T, rs *RenderingService, timeout time.Duration) error {
	t.Helper()
	_, err := rs.RenderCSV(context.Background(), CSVOpts{CommonOpts: userRenderOpts(timeout)})
	return err
}

func userRenderOpts(timeout time.Duration) CommonOpts {
	return CommonOpts{
		AuthOpts: AuthOpts{
			OrgID:   1,
			UserID:  42,
			OrgRole: org.RoleViewer,
		},
		TimeoutOpts: TimeoutOpts{Timeout: timeout},
		Path:        "d-solo/dash/slug?orgId=1&panelId=2",
	}
}

func renderingServiceAuth() AuthOpts {
	return AuthOpts{OrgID: 1, UserID: 0, OrgRole: org.RoleAdmin}
}

func requireTransportFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the remote renderer call to fail")
	}
	if errors.Is(err, ErrRenderUnavailable) || errors.Is(err, ErrConcurrentLimitReached) {
		t.Fatal("renderer call did not reach the remote client")
	}
}

func requireRendererAttemptLogged(t *testing.T, logged string) {
	t.Helper()
	if strings.Contains(logged, "Failed to send request to remote rendering service") ||
		strings.Contains(logged, "Failed to render image") {
		return
	}
	t.Fatal("renderer failure was not written to the log")
}

var (
	jwtCandidate       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+=*\.[A-Za-z0-9_-]+=*\.[A-Za-z0-9_-]+=*`)
	renderKeyCandidate = regexp.MustCompile(`renderKey=([^&\s"\\]+)`)
)

func assertNoAcceptedRenderCredential(t *testing.T, rs *RenderingService, blobs ...string) {
	t.Helper()
	for _, blob := range blobs {
		for _, candidate := range credentialCandidates(blob) {
			user, ok := rs.GetRenderUser(context.Background(), candidate)
			if ok && user != nil {
				t.Fatalf("renderer output contained a render credential that still authenticates as org %d user %d role %s", user.OrgID, user.UserID, user.OrgRole)
			}
		}
	}
}

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

func hangingTCPURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection until the listener closes so the client times out.
			time.Sleep(5 * time.Second)
			_ = conn.Close()
		}
	}()
	return "http://" + ln.Addr().String() + "/render"
}
