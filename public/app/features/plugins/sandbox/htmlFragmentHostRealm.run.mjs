import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import http from 'node:http';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const esbuild = require('esbuild');
const { chromium } = require('playwright-core');

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../..');
const harnessEntry = path.join(repoRoot, 'public/app/features/plugins/sandbox/htmlFragmentHostRealm.harness.ts');
const publicDir = path.join(repoRoot, 'public');

const HOST_REALM_MARKER = 'IFRAME';
const SANDBOX_IFRAME_NODE_NAME = '#document-fragment';

function resolveWithExtension(basePath) {
  const fs = require('node:fs');
  const candidates = [
    `${basePath}.ts`,
    `${basePath}.tsx`,
    `${basePath}.js`,
    path.join(basePath, 'index.ts'),
    path.join(basePath, 'index.tsx'),
    path.join(basePath, 'index.js'),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
}

async function bundleHarness() {
  const result = await esbuild.build({
    absWorkingDir: repoRoot,
    entryPoints: [harnessEntry],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    write: false,
    target: 'es2022',
    conditions: ['@grafana-app/source', 'browser', 'import', 'module', 'default'],
    define: {
      'process.env.NODE_ENV': '"production"',
    },
    loader: {
      '.css': 'empty',
      '.svg': 'empty',
      '.png': 'empty',
      '.gif': 'empty',
      '.jpg': 'empty',
      '.woff': 'empty',
      '.woff2': 'empty',
      '.ttf': 'empty',
      '.eot': 'empty',
    },
    plugins: [
      {
        name: 'grafana-public-paths',
        setup(build) {
          build.onResolve({ filter: /^systemjs\/dist\// }, (args) => {
            const withExtension = args.path.endsWith('.js') ? args.path : `${args.path}.js`;
            return { path: require.resolve(withExtension, { paths: [repoRoot] }) };
          });
          build.onResolve({ filter: /.*/ }, (args) => {
            if (args.path.startsWith('.') || args.path.startsWith('@') || args.path.startsWith('\0') || path.isAbsolute(args.path)) {
              return null;
            }
            const resolved = resolveWithExtension(path.join(publicDir, args.path));
            if (resolved) {
              return { path: resolved };
            }
            return null;
          });
        },
      },
    ],
  });
  return result.outputFiles[0].text;
}

function pageHtml() {
  return `<!doctype html>
<html>
  <head><meta charset="utf-8"><title>sandbox probe</title></head>
  <body>
    <script>
      window.grafanaBootData = {
        settings: {
          buildInfo: { version: '1.0.0', commit: 'probe', env: 'production' },
          datasources: {},
          featureToggles: {},
          enableFrontendSandboxForPlugins: []
        },
        user: { isSignedIn: true, theme: 'dark', login: 'probe' },
        navTree: []
      };
    </script>
    <script src="/harness.js"></script>
  </body>
</html>`;
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

async function runPage(script, search) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/harness.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript' });
      res.end(script);
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(pageHtml());
  });
  const port = await listen(server);
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage();
  const logs = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      logs.push(`${msg.type()}: ${msg.text()}`);
    }
  });
  page.on('pageerror', (error) => logs.push(`pageerror: ${error.message}`));
  try {
    await page.goto(`http://127.0.0.1:${port}/${search}`, { waitUntil: 'load', timeout: 60000 });
    await page.waitForFunction(() => Array.isArray(window.__htmlFragmentResults), null, { timeout: 60000 });
    const results = await page.evaluate(() => window.__htmlFragmentResults);
    return { results, logs };
  } finally {
    await browser.close();
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

test('sandboxed plugin HTML sinks do not run event handlers in the host page', { timeout: 180000 }, async () => {
  const script = await bundleHarness();
  const { results, logs } = await runPage(script, '');
  assert.ok(results.length > 0, `probe produced no results\n${logs.join('\n')}`);

  const failures = [];
  for (const result of results) {
    assert.equal(
      result.sandboxSelected,
      true,
      `${result.id} was not loaded through the frontend sandbox gate\n${JSON.stringify(result)}\n${logs.join('\n')}`
    );
    assert.equal(
      result.directIframeNodeName,
      SANDBOX_IFRAME_NODE_NAME,
      `${result.id} did not run inside the sandbox distortion\n${JSON.stringify(result)}`
    );
    assert.equal(result.benign, 'benign', `${result.id} did not finish plugin execution\n${JSON.stringify(result)}`);
    if (result.skipped) {
      continue;
    }
    if (result.probe === HOST_REALM_MARKER) {
      failures.push(result.id);
    }
  }

  assert.deepEqual(
    failures,
    [],
    `host-realm handlers ran for: ${failures.join(', ')}\n${JSON.stringify(results, null, 2)}\n${logs.join('\n')}`
  );
});

test('document.write from a sandboxed plugin does not run a host-page handler', { timeout: 180000 }, async () => {
  const script = await bundleHarness();
  const { results } = await runPage(script, '?sink=document-write');
  assert.equal(results.length, 1);
  const result = results[0];
  assert.equal(result.sandboxSelected, true, JSON.stringify(result));
  assert.equal(result.directIframeNodeName, SANDBOX_IFRAME_NODE_NAME, JSON.stringify(result));
  assert.equal(result.benign, 'benign', JSON.stringify(result));
  assert.notEqual(result.probe, HOST_REALM_MARKER, JSON.stringify(result));
});

test('document.writeln from a sandboxed plugin does not run a host-page handler', { timeout: 180000 }, async () => {
  const script = await bundleHarness();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/harness.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript' });
      res.end(script);
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(pageHtml());
  });
  const port = await listen(server);
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await browser.newPage();
  try {
    await page.goto(`http://127.0.0.1:${port}/?sink=document-writeln`, { waitUntil: 'commit', timeout: 30000 });
    await page
      .waitForFunction(
        () => sessionStorage.getItem('probe-document-writeln') || Array.isArray(window.__htmlFragmentResults),
        null,
        { timeout: 8000 }
      )
      .catch(() => undefined);
    const observed = await page.evaluate(() => ({
      marker: sessionStorage.getItem('probe-document-writeln'),
      results: window.__htmlFragmentResults || null,
    }));
    assert.ok(observed.marker || observed.results, `writeln probe did not run: ${JSON.stringify(observed)}`);
    assert.notEqual(observed.marker, HOST_REALM_MARKER, `writeln ran in the host page (${observed.marker})`);
    if (observed.results) {
      assert.notEqual(observed.results[0].probe, HOST_REALM_MARKER, JSON.stringify(observed.results[0]));
    }
  } finally {
    await browser.close();
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
});
