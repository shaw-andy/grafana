/**
 * Spec for the frontend plugin sandbox: plugin code must not insert a script
 * that runs in the Grafana page.
 *
 * These tests fail while that is still possible. They are expected to pass
 * once every insertion path below refuses the script instead of handing the
 * node to the browser's native method.
 *
 * Run from the repository root:
 *   node --test public/app/features/plugins/sandbox/pluginSandboxScriptInsertion.browser.test.mjs
 *
 * Playwright's Chromium is used when it is installed (`yarn playwright install chromium`).
 * Otherwise set CHROME_PATH to a Chrome or Chromium binary.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const require = createRequire(import.meta.url);
const esbuild = require('esbuild');
const { chromium } = require('playwright-core');

const repoRoot = path.resolve(import.meta.dirname, '../../../../..');
const harnessEntry = path.join(repoRoot, 'public/app/features/plugins/sandbox/pluginSandboxScriptInsertion.harness.ts');

function parentScriptSource(marker) {
  return `window.__parentRealmScript=${JSON.stringify(marker)};alert(${JSON.stringify(marker)})`;
}

function direct(marker, statement) {
  return `
    const script = document.createElement('script');
    script.text = ${JSON.stringify(parentScriptSource(marker))};
    const anchor = document.createElement('span');
    document.body.appendChild(anchor);
    ${statement}
  `;
}

function nested(marker, statement) {
  return `
    const script = document.createElement('script');
    script.text = ${JSON.stringify(parentScriptSource(marker))};
    const anchor = document.createElement('span');
    document.body.appendChild(anchor);
    const holder = document.createElement('div');
    holder.append(script);
    ${statement}
  `;
}

// Each entry is plugin code. The marker is alerted only if the browser runs
// the script as a classic script of the parent page. The sandbox's own alert
// is distorted and does not open a dialog.
const attacks = [
  ['body.replaceChildren(script)', (marker) => direct(marker, 'document.body.replaceChildren(script);')],
  [
    'connected div.replaceChildren(script)',
    (marker) =>
      direct(
        marker,
        `const host = document.createElement('div');
         document.body.appendChild(host);
         host.replaceChildren(script);`
      ),
  ],
  [
    'body.replaceChildren(other, script)',
    (marker) =>
      direct(
        marker,
        `const other = document.createElement('div');
         document.body.replaceChildren(other, script);`
      ),
  ],
  [
    'script.textContent then body.replaceChildren(script)',
    (marker) => `
      const script = document.createElement('script');
      script.textContent = ${JSON.stringify(parentScriptSource(marker))};
      document.body.replaceChildren(script);
    `,
  ],
  [
    'createElementNS(script) then body.replaceChildren(script)',
    (marker) => `
      const script = document.createElementNS('http://www.w3.org/1999/xhtml', 'script');
      script.text = ${JSON.stringify(parentScriptSource(marker))};
      document.body.replaceChildren(script);
    `,
  ],
  ['body.append(script)', (marker) => direct(marker, 'document.body.append(script);')],
  ['body.prepend(script)', (marker) => direct(marker, 'document.body.prepend(script);')],
  ['anchor.before(script)', (marker) => direct(marker, 'anchor.before(script);')],
  ['anchor.after(script)', (marker) => direct(marker, 'anchor.after(script);')],
  ['body.insertBefore(script, anchor)', (marker) => direct(marker, 'document.body.insertBefore(script, anchor);')],
  ['body.replaceChild(script, anchor)', (marker) => direct(marker, 'document.body.replaceChild(script, anchor);')],
  ['anchor.replaceWith(script)', (marker) => direct(marker, 'anchor.replaceWith(script);')],
  [
    "body.insertAdjacentElement('beforeend', script)",
    (marker) => direct(marker, "document.body.insertAdjacentElement('beforeend', script);"),
  ],
  [
    'Range.insertNode(script)',
    (marker) =>
      direct(
        marker,
        `const range = document.createRange();
         range.selectNodeContents(document.body);
         range.collapse(false);
         range.insertNode(script);`
      ),
  ],
  [
    'body.replaceChildren(fragment containing script)',
    (marker) =>
      direct(
        marker,
        `const fragment = document.createDocumentFragment();
         fragment.append(script);
         document.body.replaceChildren(fragment);`
      ),
  ],
  [
    'body.append(fragment containing script)',
    (marker) =>
      direct(
        marker,
        `const fragment = document.createDocumentFragment();
         fragment.append(script);
         document.body.append(fragment);`
      ),
  ],
  [
    'body.append(createContextualFragment with script)',
    (marker) => `
      const html = ${JSON.stringify(`<script>${parentScriptSource(marker)}</script>`)};
      const fragment = document.createRange().createContextualFragment(html);
      document.body.append(fragment);
    `,
  ],
  [
    'body.replaceChildren(holder containing script)',
    (marker) => nested(marker, 'document.body.replaceChildren(holder);'),
  ],
  ['body.append(holder containing script)', (marker) => nested(marker, 'document.body.append(holder);')],
  ['body.prepend(holder containing script)', (marker) => nested(marker, 'document.body.prepend(holder);')],
  ['anchor.before(holder containing script)', (marker) => nested(marker, 'anchor.before(holder);')],
  ['anchor.after(holder containing script)', (marker) => nested(marker, 'anchor.after(holder);')],
  [
    'body.insertBefore(holder containing script, anchor)',
    (marker) => nested(marker, 'document.body.insertBefore(holder, anchor);'),
  ],
  [
    'body.replaceChild(holder containing script, anchor)',
    (marker) => nested(marker, 'document.body.replaceChild(holder, anchor);'),
  ],
  ['anchor.replaceWith(holder containing script)', (marker) => nested(marker, 'anchor.replaceWith(holder);')],
  [
    "body.insertAdjacentElement('beforeend', holder containing script)",
    (marker) => nested(marker, "document.body.insertAdjacentElement('beforeend', holder);"),
  ],
  ['body.appendChild(holder containing script)', (marker) => nested(marker, 'document.body.appendChild(holder);')],
  [
    'Range.insertNode(holder containing script)',
    (marker) =>
      nested(
        marker,
        `const range = document.createRange();
         range.selectNodeContents(document.body);
         range.collapse(false);
         range.insertNode(holder);`
      ),
  ],
  ['document.replaceChildren(script)', (marker) => direct(marker, 'document.replaceChildren(script);')],
  ['document.prepend(script)', (marker) => direct(marker, 'document.prepend(script);')],
  ['body.moveBefore(script, null)', (marker) => direct(marker, 'document.body.moveBefore(script, null);')],
];

async function bundleHarness() {
  const outfile = path.join(os.tmpdir(), `plugin-sandbox-script-insertion-${process.pid}.js`);
  await esbuild.build({
    absWorkingDir: repoRoot,
    entryPoints: [harnessEntry],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    outfile,
    conditions: ['@grafana-app/source'],
    define: { 'process.env.NODE_ENV': '"production"' },
    loader: {
      '.css': 'empty',
      '.svg': 'empty',
      '.png': 'empty',
      '.gif': 'empty',
      '.woff': 'empty',
      '.woff2': 'empty',
    },
    alias: {
      '@locker/near-membrane-dom': path.join(repoRoot, 'node_modules/@locker/near-membrane-dom/dist/index.mjs.js'),
      '@locker/near-membrane-base': path.join(repoRoot, 'node_modules/@locker/near-membrane-base/dist/index.mjs.js'),
      '@locker/near-membrane-shared': path.join(
        repoRoot,
        'node_modules/@locker/near-membrane-shared/dist/index.mjs.js'
      ),
      '@locker/near-membrane-shared-dom': path.join(
        repoRoot,
        'node_modules/@locker/near-membrane-shared-dom/dist/index.mjs.js'
      ),
    },
    plugins: [
      {
        name: 'stub-systemjs',
        setup(build) {
          build.onResolve({ filter: /^systemjs(\/|$)/ }, () => ({
            path: path.join(os.tmpdir(), `plugin-sandbox-systemjs-stub-${process.pid}.js`),
          }));
        },
      },
    ],
  });
  return outfile;
}

function startServer(harnessFile) {
  const server = http.createServer((req, res) => {
    if (req.url === '/harness.js') {
      res.setHeader('content-type', 'text/javascript');
      fs.createReadStream(harnessFile).pipe(res);
      return;
    }
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end(
      '<!doctype html><html><head><title>sandbox</title></head><body><div id="app"></div><script src="/harness.js"></script></body></html>'
    );
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

async function launchBrowser() {
  const args = ['--no-sandbox', '--disable-dev-shm-usage'];
  if (process.env.CHROME_PATH) {
    return chromium.launch({ executablePath: process.env.CHROME_PATH, headless: true, args });
  }
  try {
    return await chromium.launch({ headless: true, args });
  } catch {
    return chromium.launch({ channel: 'chrome', headless: true, args });
  }
}

test('sandboxed plugin script insertion does not run in the parent page', async (t) => {
  const stub = path.join(os.tmpdir(), `plugin-sandbox-systemjs-stub-${process.pid}.js`);
  fs.writeFileSync(stub, 'export default {};\nexport const SystemJS = {};\n');
  const harnessFile = await bundleHarness();
  const server = await startServer(harnessFile);
  const browser = await launchBrowser();
  t.after(async () => {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(harnessFile, { force: true });
    fs.rmSync(stub, { force: true });
  });

  const page = await browser.newPage();
  const dialogs = [];
  page.on('dialog', async (dialog) => {
    dialogs.push(dialog.message());
    await dialog.dismiss();
  });
  const { port } = server.address();
  await page.goto(`http://127.0.0.1:${port}/`);
  await page.waitForFunction(() => typeof window.__runInPluginSandbox === 'function');

  async function runPlugin(code) {
    dialogs.length = 0;
    return page.evaluate((pluginCode) => {
      delete window.__parentRealmScript;
      document.body.innerHTML = '<div id="app"></div>';
      let thrown = null;
      try {
        window.__runInPluginSandbox(pluginCode);
      } catch (error) {
        thrown = error instanceof Error ? error.message : String(error);
      }
      const scripts = Array.from(document.scripts).map((script) => script.text);
      return {
        thrown,
        parentRealmScript: window.__parentRealmScript ?? null,
        connectedScriptText: scripts.filter((text) => text.includes('__parentRealmScript')),
      };
    }, code);
  }

  await t.test('plugin javascript cannot call the parent alert or set a parent window property', async () => {
    const result = await runPlugin(`
      alert('sandbox-direct');
      window.__parentRealmScript = 'sandbox-direct';
    `);
    assert.deepEqual(dialogs, []);
    assert.equal(result.parentRealmScript, null);
    assert.deepEqual(result.connectedScriptText, []);
  });

  await t.test('appendChild of a script element does not run it in the parent page', async () => {
    const marker = 'appendChild-direct-script';
    const result = await runPlugin(direct(marker, 'document.body.appendChild(script);'));
    assert.equal(result.parentRealmScript, null, result.thrown ?? '');
    assert.equal(dialogs.includes(marker), false);
    assert.deepEqual(result.connectedScriptText, []);
  });

  await t.test('append of a plain element still inserts that element', async () => {
    const result = await runPlugin(`
      const div = document.createElement('div');
      div.id = 'plain-div';
      document.body.append(div);
    `);
    const inserted = await page.evaluate(() => document.getElementById('plain-div') !== null);
    assert.equal(result.thrown, null);
    assert.equal(inserted, true);
  });

  for (const [name, build] of attacks) {
    await t.test(`${name} does not run a parent-page script`, async () => {
      const marker = name;
      const result = await runPlugin(build(marker));
      assert.equal(
        result.parentRealmScript,
        null,
        `parent page ran the plugin script (${result.parentRealmScript}); throw=${result.thrown}`
      );
      assert.equal(dialogs.includes(marker), false, `parent page alerted ${marker}`);
      assert.deepEqual(
        result.connectedScriptText,
        [],
        `parent document contains the plugin script: ${result.connectedScriptText.join('\n')}`
      );
    });
  }
});
