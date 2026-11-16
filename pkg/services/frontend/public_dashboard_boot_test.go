package frontend

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/web"
)

// TestPublicDashboardBootRequestDoesNotLeaveBootData is the spec for the
// public-dashboard boot URL. A single percent-encoded path segment is handed to
// the page as the access token, and public/boot/index.ts appends that token to
// /bootdata. These cases fail while that request's path can be /logout or
// /profile/switch-org/{id}, and pass once the page refuses the segment or the
// boot URL can no longer resolve onto those routes.
func TestPublicDashboardBootRequestDoesNotLeaveBootData(t *testing.T) {
	publicDir := setupTestWebAssets(t)
	cfg := &setting.Cfg{
		Raw:            ini.Empty(),
		HTTPPort:       "3000",
		StaticRootPath: publicDir,
	}
	service := createTestService(t, cfg)

	mux := web.New()
	service.addMiddlewares(mux)
	service.registerRoutes(mux)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	bootSource := stripTypeOnlyImports(t, filepath.Join(repoRoot(t), "public", "boot", "index.ts"))

	// A real access token is a UUID. This one is a fixed test value.
	const validToken = "11111111-1111-4111-8111-111111111111"

	cases := []struct {
		name            string
		requestTarget   string
		forbiddenPaths  []string
		wantPath        string
		requireRendered bool
	}{
		{
			name:          "parent directory segment resolves the boot request onto logout",
			requestTarget: "/public-dashboards/%2e%2e%2f%2e%2e%2flogout",
			forbiddenPaths: []string{
				"/logout",
			},
		},
		{
			name:          "single parent directory segment resolves the boot request onto logout",
			requestTarget: "/public-dashboards/%2e%2e%2flogout",
			forbiddenPaths: []string{
				"/logout",
			},
		},
		{
			name:          "parent directory segment resolves the boot request onto organization switch",
			requestTarget: "/public-dashboards/%2e%2e%2f%2e%2e%2fprofile%2fswitch-org%2f2",
			forbiddenPaths: []string{
				"/profile/switch-org/2",
			},
		},
		{
			name:            "a uuid token still requests that token under bootdata",
			requestTarget:   "/public-dashboards/" + validToken,
			wantPath:        "/bootdata/" + validToken,
			requireRendered: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := rawGET(t, server.Listener.Addr().String(), tc.requestTarget)
			fetches := bootFetches(t, bootSource, body)

			for _, fetch := range fetches {
				for _, forbidden := range tc.forbiddenPaths {
					if fetch.Pathname == forbidden {
						t.Fatalf("boot fetch %s %s landed on %s (page status %d)", fetch.Method, fetch.URL, forbidden, status)
					}
				}
				if fetch.Credentials == "omit" && fetch.Pathname != "" {
					t.Fatalf("boot fetch dropped credentials: %+v", fetch)
				}
			}

			if tc.requireRendered {
				require.Equal(t, http.StatusOK, status)
				require.NotEmpty(t, fetches)
				require.Equal(t, tc.wantPath, fetches[0].Pathname)
				require.Equal(t, http.MethodGet, fetches[0].Method)
			}
		})
	}
}

type bootFetch struct {
	URL         string `json:"url"`
	Pathname    string `json:"pathname"`
	Method      string `json:"method"`
	Credentials string `json:"credentials"`
}

func bootFetches(t *testing.T, bootSource string, html string) []bootFetch {
	t.Helper()

	htmlPath := filepath.Join(t.TempDir(), "index.html")
	require.NoError(t, os.WriteFile(htmlPath, []byte(html), 0o600))

	runner := filepath.Join(t.TempDir(), "run-boot.mjs")
	require.NoError(t, os.WriteFile(runner, []byte(bootRunnerSource), 0o600))

	cmd := exec.Command("node", "--experimental-strip-types", runner, htmlPath, bootSource, "https://grafana.example")
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = exitErr.Stderr
		}
		require.NoError(t, err, "boot runner failed: %s\n%s", stderr, out)
	}

	var fetched []bootFetch
	require.NoError(t, json.Unmarshal(out, &fetched), "runner output: %s", out)
	return fetched
}

func rawGET(t *testing.T, addr, requestTarget string) (int, string) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = io.WriteString(conn, "GET "+requestTarget+" HTTP/1.1\r\nHost: grafana.example\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// stripTypeOnlyImports copies the boot entry and drops import declarations whose
// specifiers are all type-only. The webpack entry (scripts/webpack/webpack.common.ts)
// erases those the same way; the declarations have no runtime effect. Node's
// type stripper still tries to resolve them, so the copy executed below does not
// contain them. Every other line is unchanged.
func stripTypeOnlyImports(t *testing.T, src string) string {
	t.Helper()

	raw, err := os.ReadFile(src)
	require.NoError(t, err)

	var b strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if isTypeOnlyImport(line) {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}

	dst := filepath.Join(t.TempDir(), "boot.ts")
	require.NoError(t, os.WriteFile(dst, []byte(b.String()), 0o600))
	return dst
}

func isTypeOnlyImport(line string) bool {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "import ") || !strings.HasSuffix(trimmed, ";") {
		return false
	}
	open := strings.Index(trimmed, "{")
	close := strings.Index(trimmed, "}")
	if open < 0 || close < open {
		return false
	}
	parts := strings.Split(trimmed[open+1:close], ",")
	saw := false
	for _, part := range parts {
		spec := strings.TrimSpace(part)
		if spec == "" {
			continue
		}
		saw = true
		if !strings.HasPrefix(spec, "type ") {
			return false
		}
	}
	return saw
}

func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "public", "boot", "index.ts")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find public/boot/index.ts from the test working directory")
		}
		dir = parent
	}
}

// bootRunnerSource loads the rendered page's token assignment, then imports the
// boot entry so its module-scope read of window.__grafanaPublicDashboardAccessToken
// and its fetch() are the ones from public/boot/index.ts.
const bootRunnerSource = `import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const html = readFileSync(process.argv[2], 'utf8');
const bootURL = pathToFileURL(process.argv[3]).href;
const origin = process.argv[4];

const match = html.match(/window\.__grafanaPublicDashboardAccessToken\s*=\s*([\s\S]*?);/);
let token = undefined;
if (match) {
  token = Function('"use strict"; return (' + match[1] + ');')();
}

const fetches = [];
globalThis.window = {
  location: {
    origin,
    search: '',
    pathname: '/public-dashboards/token',
    href: origin + '/public-dashboards/token',
    hostname: 'grafana.example',
  },
  __grafanaPublicDashboardAccessToken: token,
  grafanaBootData: { settings: {}, user: {}, assets: { light: '/light.css', dark: '/dark.css' } },
  onload: null,
};
globalThis.document = {
  cookie: '',
  querySelector() { return null; },
  documentElement: {},
  body: { classList: { add() {} } },
  head: { appendChild() {} },
  createElement() { return {}; },
};
globalThis.fetch = async (input, init) => {
  const url = input instanceof URL ? new URL(input.href) : new URL(String(input), origin);
  fetches.push({
    url: url.href,
    pathname: url.pathname,
    method: (init && init.method) || 'GET',
    credentials: (init && init.credentials) || 'same-origin',
  });
  return {
    status: 500,
    ok: false,
    headers: { get() { return null; } },
    async text() { return 'not-json'; },
  };
};

try {
  await import(bootURL);
} catch (err) {
  console.error(err);
  process.exit(1);
}
await new Promise((resolve) => setTimeout(resolve, 50));
process.stdout.write(JSON.stringify(fetches));
`
