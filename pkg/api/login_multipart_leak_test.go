package api

import (
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

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/login/social"
	"github.com/grafana/grafana/pkg/middleware/csrf"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/authn/authntest"
	"github.com/grafana/grafana/pkg/services/contexthandler"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// defaultMaxMemory in net/http (go1.26.6 request.go) is the budget FormValue
// passes to ParseMultipartForm. File parts larger than this are written to disk.
const formValueMaxMemory = 32 << 20

// TestAutoLoginMultipartTempFilesAreRemoved fails while GET/HEAD /login parses a
// multipart body on a copied request and leaves the temp file behind. It passes
// once that body is no longer parsed, or once every temp file it creates is removed
// before the request finishes.
func TestAutoLoginMultipartTempFilesAreRemoved(t *testing.T) {
	fakeSetIndexViewData(t)

	cases := []struct {
		name           string
		method         string
		oauthAutoLogin bool
		providerAuto   bool
		samlAutoLogin  bool
		wantRedirect   string
	}{
		{
			name:         "oauth provider auto login",
			method:       http.MethodGet,
			providerAuto: true,
			wantRedirect: "/login/github",
		},
		{
			name:           "legacy oauth auto login",
			method:         http.MethodGet,
			oauthAutoLogin: true,
			wantRedirect:   "/login/github",
		},
		{
			name:          "saml auto login",
			method:        http.MethodGet,
			samlAutoLogin: true,
			wantRedirect:  "/login/saml",
		},
		{
			name:         "head oauth provider auto login",
			method:       http.MethodHead,
			providerAuto: true,
			wantRedirect: "/login/github",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := fmt.Sprintf("leak-%d-%s", time.Now().UnixNano(), strings.ReplaceAll(t.Name(), "/", "-"))
			redirectTo := "/d/abc"
			hs, m := newAutoLoginLeakServer(t, tc.oauthAutoLogin, tc.providerAuto, tc.samlAutoLogin)
			var sawDuring []string
			m.Get("/login", func(c *contextmodel.ReqContext) {
				hs.LoginView(c)
				sawDuring = multipartTempFilesContaining(t, marker)
			})

			srv := httptest.NewServer(m)
			t.Cleanup(srv.Close)

			status, location := doMultipartLogin(t, srv.Client(), srv.URL, tc.method, redirectTo, marker)
			require.Equal(t, http.StatusTemporaryRedirect, status)
			require.Contains(t, location, tc.wantRedirect)
			require.Contains(t, location, "redirectTo="+url.QueryEscape(redirectTo))

			// The keep-alive follow-up is served only after net/http finishes the upload,
			// including its own MultipartForm cleanup. Give that cleanup a moment when
			// the connection is closed instead of reused. A file that is still here
			// after that is leaked, not merely waiting on the server.
			followStatus, followErr := doPlainLogin(t, srv.Client(), srv.URL+"/login?disableAutoLogin=true")
			if followErr == nil {
				require.Equal(t, http.StatusOK, followStatus)
			}

			deadline := time.Now().Add(500 * time.Millisecond)
			var left []string
			for {
				left = multipartTempFilesContaining(t, marker)
				if len(left) == 0 || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			for _, name := range append(append([]string{}, sawDuring...), left...) {
				name := name
				t.Cleanup(func() { _ = os.Remove(name) })
			}
			t.Logf("temp files during handler: %s; after request finished: %s", formatTempFiles(t, sawDuring), formatTempFiles(t, left))
			require.Empty(t, left, "multipart temp files must not remain after GET/HEAD /login finishes")
		})
	}
}

func newAutoLoginLeakServer(t *testing.T, oauthAutoLogin, providerAuto, samlAuto bool) (*HTTPServer, *web.Macaron) {
	t.Helper()

	cfg := setting.NewCfg()
	cfg.LoginCookieName = "grafana_session"
	cfg.OAuthAutoLogin = oauthAutoLogin

	features, err := featuremgmt.ProvideManagerService(cfg)
	require.NoError(t, err)
	require.True(t, features.IsEnabledGlobally(featuremgmt.FlagUseSessionStorageForRedirection),
		"useSessionStorageForRedirection is on by default; this test follows that configuration")

	provider := &social.OAuthInfo{Enabled: true, Name: "GitHub"}
	if providerAuto {
		provider.AutoLogin = true
	}
	var providers map[string]*social.OAuthInfo
	if !samlAuto {
		providers = map[string]*social.OAuthInfo{"github": provider}
	}

	authnService := &authntest.FakeService{
		// No session cookie: authentication fails and the request stays signed out.
		ExpectedErr: errors.New("no session"),
	}
	if samlAuto {
		authnService.EnabledClients = []string{authn.ClientSAML}
		authnService.ExpectedClientConfig = &authntest.FakeSSOClientConfig{ExpectedIsAutoLoginEnabled: true}
	} else {
		authnService.EnabledClients = []string{}
	}

	_, htmlHandlerRequestsDuration := setupHTMLHandlerMetrics()
	hs := &HTTPServer{
		Cfg:                         cfg,
		License:                     &licensing.OSSLicensingService{},
		Features:                    features,
		SocialService:               &mockSocialService{oAuthInfos: providers},
		authnService:                authnService,
		htmlHandlerRequestsDuration: htmlHandlerRequestsDuration,
	}

	// No session: authentication fails and IsSignedIn stays false, which is the
	// default when anonymous access is disabled.
	ctxHdlr := contexthandler.ProvideService(cfg, &authntest.FakeService{ExpectedErr: errors.New("no session")}, features)
	m := web.New()
	// CSRF runs before /login in production and skips requests with no login cookie.
	m.UseMiddleware(csrf.ProvideCSRFFilter(cfg).Middleware())
	m.Use(ctxHdlr.Middleware)
	return hs, m
}

func doMultipartLogin(t *testing.T, client *http.Client, baseURL, method, redirectTo, marker string) (int, string) {
	t.Helper()

	body, length, boundary := oversizedMultipartFile(marker)
	req, err := http.NewRequest(method, baseURL+"/login?redirectTo="+url.QueryEscape(redirectTo), body)
	require.NoError(t, err)
	req.ContentLength = length
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	// httptest's client follows redirects. The attack stops at the 307.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	return resp.StatusCode, resp.Header.Get("Location")
}

func doPlainLogin(t *testing.T, client *http.Client, rawURL string) (int, error) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func oversizedMultipartFile(marker string) (io.Reader, int64, string) {
	const boundary = "leakboundary"
	header := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"blob.bin\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n"
	// One byte past the in-memory budget forces a temporary file.
	fileBytes := int64(formValueMaxMemory + 1)
	pad := fileBytes - int64(len(marker))
	footer := "\r\n--" + boundary + "--\r\n"
	reader := io.MultiReader(
		strings.NewReader(header),
		strings.NewReader(marker),
		io.LimitReader(repeatByteReader{b: 'x'}, pad),
		strings.NewReader(footer),
	)
	return reader, int64(len(header)+len(footer)) + fileBytes, boundary
}

type repeatByteReader struct{ b byte }

func (r repeatByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

func formatTempFiles(t *testing.T, names []string) string {
	t.Helper()
	parts := make([]string, 0, len(names))
	for _, name := range names {
		info, err := os.Stat(name)
		if err != nil {
			parts = append(parts, name+":missing")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d", name, info.Size()))
	}
	return strings.Join(parts, ", ")
}

func multipartTempFilesContaining(t *testing.T, marker string) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "multipart-*"))
	require.NoError(t, err)

	var found []string
	buf := make([]byte, len(marker))
	for _, name := range matches {
		f, err := os.Open(name)
		if err != nil {
			continue
		}
		n, _ := io.ReadFull(f, buf)
		_ = f.Close()
		if n == len(marker) && string(buf) == marker {
			found = append(found, name)
		}
	}
	return found
}
