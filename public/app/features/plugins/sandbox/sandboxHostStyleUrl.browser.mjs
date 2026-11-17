/**
 * Sandboxed plugins must not be able to make the browser request a same-origin
 * URL by writing CSS. These tests fail while that is still possible.
 *
 * Run from the repository root:
 *   node public/app/features/plugins/sandbox/sandboxHostStyleUrl.browser.mjs
 */
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import http from 'node:http';
import test from 'node:test';

import esbuild from 'esbuild';
import { chromium } from 'playwright';

const CHROME = [process.env.CHROME_PATH, '/opt/google/chrome/chrome', '/usr/bin/google-chrome', '/usr/bin/chromium']
  .find((candidate) => candidate && existsSync(candidate));
const SESSION_COOKIE = 'grafana_session';
const SESSION_VALUE = 'session-placeholder';

const probes = [
  {
    id: 'probe-body-assign',
    source: `document.body.style.backgroundImage = 'url(/logout?op=body-assign)';`,
  },
  {
    id: 'probe-body-setproperty',
    source: `document.body.style.setProperty('background-image', 'url(/logout?op=body-setProperty)');`,
  },
  {
    id: 'probe-body-csstext',
    source: `document.body.style.cssText = 'background-image:url(/logout?op=body-cssText)';`,
  },
  {
    id: 'probe-body-setattribute',
    source: `document.body.setAttribute('style', 'background-image:url(/logout?op=body-setAttribute)');`,
  },
  {
    id: 'probe-body-shorthand',
    source: `document.body.style.background = 'url(/logout?op=body-shorthand)';`,
  },
  {
    id: 'probe-body-list-style',
    source: `document.body.style.listStyleImage = 'url(/logout?op=body-list-style)';`,
  },
  {
    id: 'probe-head-assign',
    source: `document.head.style.backgroundImage = 'url(/logout?op=head-assign)';`,
  },
  {
    id: 'probe-html-assign',
    source: `document.documentElement.style.backgroundImage = 'url(/profile/switch-org/2?op=html-assign)';`,
  },
  {
    id: 'probe-html-setproperty',
    source: `document.documentElement.style.setProperty('background-image', 'url(/profile/switch-org/2?op=html-setProperty)');`,
  },
  {
    id: 'probe-created',
    source: `const el = document.createElement('div');
el.style.backgroundImage = 'url(/logout?op=created)';
document.body.appendChild(el);`,
  },
  {
    id: 'probe-outside-root',
    source: `const el = document.getElementById('host-outside');
el.style.backgroundImage = 'url(/logout?op=outside-root)';`,
  },
  {
    id: 'probe-sandbox-root',
    source: `const root = document.getElementById('sandbox-slot');
const el = document.createElement('div');
root.appendChild(el);
el.style.backgroundImage = 'url(/profile/switch-org/2?op=sandbox-root)';`,
  },
  {
    id: 'probe-innerhtml',
    source: `const el = document.getElementById('host-outside');
el.innerHTML = '<div style="background-image:url(/logout?op=innerHTML)"></div>';`,
  },
  {
    id: 'probe-insert-adjacent',
    source: `document.body.insertAdjacentHTML('beforeend', '<div style="background-image:url(/logout?op=insertAdjacentHTML)"></div>');`,
  },
  {
    id: 'probe-cursor',
    source: `document.body.style.cursor = 'url(/logout?op=cursor), auto';`,
  },
];

function pluginModule(id, source) {
  return `define([], function () {
  try {
${source}
  } catch (error) {}
  return { ran: ${JSON.stringify(id)} };
});
`;
}

function pageHtml() {
  return `<!doctype html>
<html>
  <head><meta charset="utf-8"><title>sandbox style probe</title></head>
  <body>
    <div id="host-outside"></div>
    <div id="reactRoot"><div id="host-inside"></div></div>
    <div id="sandbox-slot" data-plugin-sandbox="probe-sandbox-root"></div>
    <script src="/harness.js"></script>
  </body>
</html>`;
}

async function bundleHarness() {
  const result = await esbuild.build({
    absWorkingDir: new URL('../../../../../', import.meta.url).pathname,
    entryPoints: ['public/app/features/plugins/sandbox/sandboxHostStyleUrl.harness.ts'],
    bundle: true,
    write: false,
    format: 'iife',
    platform: 'browser',
    target: 'chrome120',
    conditions: ['@grafana-app/source', 'browser', 'import', 'default'],
    alias: {
      'systemjs/dist/system': './node_modules/systemjs/dist/system.js',
      'systemjs/dist/extras/amd': './node_modules/systemjs/dist/extras/amd.js',
    },
    define: {
      'process.env.NODE_ENV': '"production"',
    },
    tsconfigRaw: {
      compilerOptions: {
        jsx: 'react',
        paths: {
          'app/*': ['./public/app/*'],
          '*': ['./public/*'],
        },
      },
    },
    logLevel: 'silent',
    loader: {
      '.css': 'empty',
      '.ttf': 'empty',
      '.svg': 'empty',
      '.png': 'empty',
      '.gif': 'empty',
      '.woff': 'empty',
      '.woff2': 'empty',
    },
  });
  return result.outputFiles[0].text;
}

function startServer(harnessJs) {
  const modules = new Map(
    probes.map((probe) => [`/public/plugins/${probe.id}/module.js`, pluginModule(probe.id, probe.source)])
  );
  const hits = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const record = {
      path: url.pathname,
      search: url.search,
      cookie: req.headers.cookie ?? null,
      origin: req.headers.origin ?? null,
      dest: req.headers['sec-fetch-dest'] ?? null,
      mode: req.headers['sec-fetch-mode'] ?? null,
    };
    if (url.pathname !== '/' && url.pathname !== '/harness.js' && !modules.has(url.pathname)) {
      hits.push(record);
    }
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(pageHtml());
      return;
    }
    if (url.pathname === '/harness.js') {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      res.end(harnessJs);
      return;
    }
    const source = modules.get(url.pathname);
    if (source) {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      res.end(source);
      return;
    }
    res.writeHead(204);
    res.end();
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ server, hits, port: address.port });
    });
  });
}

test('a sandboxed plugin cannot make the browser request same-origin URLs through CSS', async () => {
  const harnessJs = await bundleHarness();
  const { server, hits, port } = await startServer(harnessJs);
  assert.ok(CHROME, 'Chrome is required to run this test');
  const browser = await chromium.launch({ executablePath: CHROME, headless: true });
  try {
    const context = await browser.newContext();
    await context.addCookies([
      {
        name: SESSION_COOKIE,
        value: SESSION_VALUE,
        url: `http://127.0.0.1:${port}/`,
        httpOnly: true,
        sameSite: 'Lax',
        secure: false,
      },
    ]);
    const page = await context.newPage();
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(String(error)));
    await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'load' });
    if (pageErrors.length) {
      assert.fail(`page failed before plugins ran: ${pageErrors.join('\n')}`);
    }
    await page.evaluate((plugins) => {
      window.__installPlugins(plugins);
    }, probes.map((probe) => ({ id: probe.id, module: `/public/plugins/${probe.id}/module.js` })));

    const results = [];
    for (const probe of probes) {
      try {
        const exported = await page.evaluate((pluginId) => window.__loadPlugin(pluginId), probe.id);
        results.push({ id: probe.id, ran: exported?.ran ?? null, error: null });
      } catch (error) {
        results.push({ id: probe.id, ran: null, error: String(error) });
      }
    }
    await page.waitForTimeout(500);

    const dom = await page.evaluate(() => document.documentElement.outerHTML);
    const sensitive = hits.filter((hit) => hit.path === '/logout' || hit.path.startsWith('/profile/switch-org/'));
    const leakedInDom = dom.includes('/logout') || dom.includes('/profile/switch-org');
    assert.deepEqual(
      results.map((result) => ({ id: result.id, ran: result.ran, error: result.error })),
      probes.map((probe) => ({ id: probe.id, ran: probe.id, error: null }))
    );
    assert.deepEqual(sensitive, []);
    assert.equal(leakedInDom, false, `host document contains a plugin-supplied URL:\n${dom}`);
  } finally {
    await browser.close();
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
});
