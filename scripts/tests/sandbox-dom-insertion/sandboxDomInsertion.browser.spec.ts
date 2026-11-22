/**
 * Sandbox DOM insertion spec.
 *
 * Run from the repository root:
 *   yarn playwright test --config scripts/tests/sandbox-dom-insertion/playwright.config.ts
 *
 * Jest replaces @locker/near-membrane-dom with a stub, so these tests load the
 * production sandbox loader in Chrome. They fail while a sandboxed plugin can
 * put a classic script into the live page. appendChild of a script element is
 * the contained path and is expected to pass.
 *
 * Not asserted, because Chrome refuses the insertion before a script can run:
 * Document.append, Document.prepend, and DocumentType before/after/replaceWith.
 * insertAdjacentText cannot insert an element. Element.setHTML was not run
 * through the sandbox.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';

import { expect, test, type Page } from '@playwright/test';
import esbuild from 'esbuild';

const repoRoot = path.resolve(__dirname, '../../..');
const harnessEntry = path.join(__dirname, 'sandboxDomInsertion.harness.ts');

type ProbeResult = {
  hostRan: string | null;
  iframeNode: string | null;
  connected: string | null;
  threw: string | null;
  error: string | null;
  textError: string | null;
  loadError: string | null;
  payloadScripts: string[];
  logs: string[];
};

/**
 * Each entry is one sandboxed plugin. `create` builds the node the plugin
 * tries to insert. `invoke` is the insertion the plugin performs after that.
 * The host page fails the test when that insertion runs a classic script in
 * the Grafana page or leaves the script in the live document.
 */
const insertions: Record<string, { create?: string; invoke: string }> = {
  'insert-adjacent-beforeend': {
    invoke: `document.body.insertAdjacentElement('beforeend', script);`,
  },
  'insert-adjacent-afterbegin': {
    invoke: `document.body.insertAdjacentElement('afterbegin', script);`,
  },
  'insert-adjacent-beforebegin': {
    invoke: `document.body.insertAdjacentElement('beforebegin', script);`,
  },
  'insert-adjacent-afterend': {
    invoke: `document.body.insertAdjacentElement('afterend', script);`,
  },
  'insert-adjacent-detached-then-connect': {
    invoke: `var parent = document.createElement('div'); parent.insertAdjacentElement('beforeend', script); document.body.appendChild(parent);`,
  },
  'insert-before': {
    invoke: `document.body.insertBefore(script, anchor);`,
  },
  'replace-child': {
    invoke: `document.body.replaceChild(script, anchor);`,
  },
  'element-append': {
    invoke: `document.body.append(script);`,
  },
  'element-prepend': {
    invoke: `document.body.prepend(script);`,
  },
  'element-after': {
    invoke: `anchor.after(script);`,
  },
  'element-before': {
    invoke: `anchor.before(script);`,
  },
  'element-replace-with': {
    invoke: `anchor.replaceWith(script);`,
  },
  'character-data-before': {
    invoke: `var text = document.createTextNode('t'); anchor.appendChild(text); text.before(script);`,
  },
  'character-data-after': {
    invoke: `var text = document.createTextNode('t'); anchor.appendChild(text); text.after(script);`,
  },
  'character-data-replace-with': {
    invoke: `var text = document.createTextNode('t'); anchor.appendChild(text); text.replaceWith(script);`,
  },
  'fragment-append-then-connect': {
    invoke: `var frag = document.createDocumentFragment(); frag.append(script); document.body.appendChild(frag);`,
  },
  'fragment-prepend-then-connect': {
    invoke: `var frag = document.createDocumentFragment(); var spacer = document.createElement('span'); frag.appendChild(spacer); frag.prepend(script); document.body.appendChild(frag);`,
  },
  'fragment-replace-children-then-connect': {
    invoke: `var frag = document.createDocumentFragment(); var spacer = document.createElement('span'); frag.appendChild(spacer); frag.replaceChildren(script); document.body.appendChild(frag);`,
  },
  'element-replace-children': {
    invoke: `var parent = document.createElement('div'); document.body.appendChild(parent); parent.replaceChildren(script);`,
  },
  'create-element-upper': {
    create: `document.createElement('SCRIPT')`,
    invoke: `document.body.insertAdjacentElement('beforeend', script);`,
  },
  'create-element-ns': {
    create: `document.createElementNS('http://www.w3.org/1999/xhtml', 'script')`,
    invoke: `document.body.insertAdjacentElement('beforeend', script);`,
  },
  'append-child': {
    invoke: `document.body.appendChild(script);`,
  },
  'range-insert-node': {
    invoke: `var range = document.createRange(); range.selectNode(anchor); range.insertNode(script);`,
  },
  'range-fragment-append-child': {
    invoke: `var parent = document.createElement('div'); document.body.appendChild(parent); var range = document.createRange(); range.selectNodeContents(parent); var frag = range.createContextualFragment('<script>' + payload + '<\\/script>'); parent.appendChild(frag);`,
  },
  'range-fragment-append': {
    invoke: `var parent = document.createElement('div'); document.body.appendChild(parent); var range = document.createRange(); range.selectNodeContents(parent); var frag = range.createContextualFragment('<script>' + payload + '<\\/script>'); parent.append(frag);`,
  },
  'domparser-move': {
    invoke: `var parsed = new DOMParser().parseFromString('<script>' + payload + '<\\/script>', 'text/html'); var moved = parsed.querySelector('script'); document.body.insertAdjacentElement('beforeend', moved);`,
  },
  'inner-html-move': {
    invoke: `var holder = document.createElement('div'); holder.innerHTML = '<script>' + payload + '<\\/script>'; var moved = holder.querySelector('script'); document.body.insertAdjacentElement('beforeend', moved);`,
  },
  'insert-adjacent-html': {
    invoke: `document.body.insertAdjacentHTML('beforeend', '<script>' + payload + '<\\/script>');`,
  },
};

function pluginSource(pluginId: string): string {
  const insertion = insertions[pluginId];
  if (!insertion) {
    throw new Error(`unknown insertion ${pluginId}`);
  }
  const payload = `window.__hostRan=${JSON.stringify(pluginId)};`;
  const create = insertion.create ?? `document.createElement('script')`;
  return `define([], function () {
    var payload = ${JSON.stringify(payload)};
    var iframe = document.createElement('iframe');
    document.documentElement.setAttribute('data-iframe-node', String(iframe && iframe.nodeName));
    var anchor = document.createElement('div');
    anchor.id = 'anchor';
    document.body.appendChild(anchor);
    var script = ${create};
    try {
      script.text = payload;
    } catch (e) {
      document.documentElement.setAttribute('data-text-error', String(e && e.message || e));
    }
    var threw = 'false';
    var error = '';
    try {
      ${insertion.invoke}
      document.documentElement.setAttribute('data-connected', String(!!script && document.contains(script)));
    } catch (e) {
      threw = 'true';
      error = String(e && e.message || e);
    }
    document.documentElement.setAttribute('data-threw', threw);
    document.documentElement.setAttribute('data-error', error);
    return { plugin: {} };
  });
`;
}

function pageHtml(): string {
  return `<!doctype html>
<html>
<head><meta charset="utf-8"></head>
<body>
<script>
window.grafanaBootData = {
  assets: { dark: '', light: '' },
  navTree: [],
  user: {
    id: 1,
    uid: 'viewer',
    login: 'viewer',
    email: 'viewer@example.test',
    name: 'Viewer',
    isSignedIn: true,
    isGrafanaAdmin: false,
    orgCount: 1,
    orgId: 1,
    orgName: 'Main',
    orgRole: 'Viewer',
    theme: 'dark',
    lightTheme: false,
    timezone: 'browser',
    locale: 'en-US',
    helpFlags1: 0,
    hasEditPermissionInFolders: false,
    permissions: {}
  },
  settings: {
    featureToggles: {},
    datasources: {},
    panels: {},
    apps: {}
  }
};
</script>
<script src="/bundle.js"></script>
</body>
</html>`;
}

let server: http.Server;
let baseURL: string;
let bundleJs = '';

async function loadProbe(page: Page, pluginId: string): Promise<ProbeResult> {
  const logs: string[] = [];
  page.on('pageerror', (error) => {
    logs.push(`pageerror: ${error.message}`);
  });
  page.on('console', (message) => {
    if (message.type() === 'error') {
      logs.push(`console: ${message.text()}`);
    }
  });
  await page.goto(`${baseURL}/?pluginId=${encodeURIComponent(pluginId)}`);
  await page.waitForFunction(() => window.__sandboxProbeDone === true);
  const observed = await page.evaluate(() => {
    const view = window;
    return {
      hostRan: view.__hostRan ?? null,
      iframeNode: document.documentElement.getAttribute('data-iframe-node'),
      connected: document.documentElement.getAttribute('data-connected'),
      threw: document.documentElement.getAttribute('data-threw'),
      error: document.documentElement.getAttribute('data-error'),
      textError: document.documentElement.getAttribute('data-text-error'),
      loadError: document.documentElement.getAttribute('data-load-error'),
      payloadScripts: Array.from(document.scripts)
        .filter((script) => script.text.includes('__hostRan'))
        .map((script) => script.text),
    };
  });
  return { ...observed, logs };
}

function expectHostUnchanged(result: ProbeResult): void {
  const detail = JSON.stringify(result);
  expect(result.loadError, detail).toBeNull();
  expect(result.iframeNode, detail).toBe('#document-fragment');
  expect(result.hostRan, detail).toBeNull();
  expect(result.payloadScripts, detail).toEqual([]);
}

test.beforeAll(async () => {
  const built = await esbuild.build({
    absWorkingDir: repoRoot,
    entryPoints: [harnessEntry],
    bundle: true,
    write: false,
    format: 'iife',
    platform: 'browser',
    target: 'chrome120',
    jsx: 'automatic',
    conditions: ['@grafana-app/source', 'browser', 'import', 'module', 'default'],
    alias: {
      app: path.join(repoRoot, 'public/app'),
      'systemjs/dist/system': path.join(repoRoot, 'node_modules/systemjs/dist/system.js'),
      'systemjs/dist/extras/amd': path.join(repoRoot, 'node_modules/systemjs/dist/extras/amd.js'),
    },
    define: {
      'process.env.NODE_ENV': '"production"',
    },
    loader: {
      '.css': 'empty',
      '.scss': 'empty',
      '.sass': 'empty',
      '.svg': 'empty',
      '.png': 'empty',
      '.jpg': 'empty',
      '.jpeg': 'empty',
      '.gif': 'empty',
      '.webp': 'empty',
      '.woff': 'empty',
      '.woff2': 'empty',
      '.ttf': 'empty',
      '.eot': 'empty',
    },
    logLevel: 'warning',
  });
  bundleJs = built.outputFiles[0].text;

  server = http.createServer((req, res) => {
    const url = req.url ?? '/';
    if (url.startsWith('/bundle.js')) {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      res.end(bundleJs);
      return;
    }
    const pluginMatch = url.match(/^\/public\/plugins\/([^/]+)\/module\.js/);
    if (pluginMatch) {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      res.end(pluginSource(decodeURIComponent(pluginMatch[1])));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(pageHtml());
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address() as AddressInfo;
  baseURL = `http://127.0.0.1:${address.port}`;
});

test.afterAll(async () => {
  if (!server) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

test('appendChild keeps an inline script out of the host page', async ({ page }) => {
  expectHostUnchanged(await loadProbe(page, 'append-child'));
});

for (const pluginId of Object.keys(insertions)) {
  if (pluginId === 'append-child') {
    continue;
  }
  test(`${pluginId} does not run or leave a script in the host page`, async ({ page }) => {
    expectHostUnchanged(await loadProbe(page, pluginId));
  });
}

declare global {
  interface Window {
    __sandboxProbeDone?: boolean;
    __hostRan?: string;
  }
}
