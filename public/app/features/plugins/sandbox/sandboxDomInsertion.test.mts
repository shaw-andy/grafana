import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import type { Browser, Page } from 'playwright';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

const PLUGIN_ID = 'sandbox-escape';
const PAYLOAD = 'globalThis.__sandboxEscape = "executed";';

/**
 * Each snippet runs inside a plugin module loaded by the real frontend sandbox
 * (shouldLoadPluginInFrontendSandbox, then importPluginModuleInSandbox).
 * `script` is an HTMLScriptElement whose text is the payload. `marker` is a div
 * already appended to the host document body.
 *
 * The assertion is that the payload does not run in the host page or in the
 * sandbox iframe, and that no connected script element carries it. These cases
 * fail while Element.replaceWith and the other unfiltered insertion paths call
 * the browser's native method.
 *
 * Ran in Chrome and not asserted here, because the payload did not run:
 * Document.append, Document.prepend, Document.replaceChildren, and
 * DocumentType.replaceWith throw HierarchyRequestError before the script is
 * connected. Element.innerHTML inserts a script element but Chrome does not
 * run it. Node.appendChild of a script element is covered below; today it is
 * diverted to the sandbox script loader and does not run the inline payload.
 *
 * Not covered: Element.setAttribute event handlers, ShadowRoot insertion, and
 * Element.setHTML / setHTMLUnsafe.
 */
const insertions: Array<[string, string]> = [
  ['Element.replaceWith', 'marker.replaceWith(script);'],
  ['Element.replaceWith with a preceding sibling', 'marker.replaceWith(document.createElement("span"), script);'],
  [
    'Text.replaceWith',
    'const text = document.createTextNode("t"); document.body.appendChild(text); text.replaceWith(script);',
  ],
  [
    'Comment.replaceWith',
    'const comment = document.createComment("c"); document.body.appendChild(comment); comment.replaceWith(script);',
  ],
  ['Element.replaceChildren', 'marker.replaceChildren(script);'],
  ['Node.replaceChild', 'marker.parentNode.replaceChild(script, marker);'],
  ['Node.insertBefore', 'marker.parentNode.insertBefore(script, marker);'],
  ['Element.insertAdjacentElement', 'marker.insertAdjacentElement("beforeend", script);'],
  ['Range.insertNode', 'const range = document.createRange(); range.selectNode(marker); range.insertNode(script);'],
  [
    'Range.surroundContents',
    `marker.textContent = ${JSON.stringify(PAYLOAD)}; const range = document.createRange(); range.selectNodeContents(marker); range.surroundContents(document.createElement("script"));`,
  ],
  ['Element.append', 'marker.append(script);'],
  ['Element.append with a preceding sibling', 'marker.append(document.createElement("span"), script);'],
  ['Element.prepend', 'marker.prepend(script);'],
  ['Element.before', 'marker.before(script);'],
  ['Element.after', 'marker.after(script);'],
  ['Text.before', 'const text = document.createTextNode("t"); document.body.appendChild(text); text.before(script);'],
  ['Text.after', 'const text = document.createTextNode("t"); document.body.appendChild(text); text.after(script);'],
  [
    'createElementNS script then Element.replaceWith',
    `const nsScript = document.createElementNS("http://www.w3.org/1999/xhtml", "script"); nsScript.text = ${JSON.stringify(PAYLOAD)}; marker.replaceWith(nsScript);`,
  ],
  [
    'Range.createContextualFragment script then Node.appendChild',
    `const range = document.createRange(); range.selectNode(marker); const frag = range.createContextualFragment(${JSON.stringify(`<script>${PAYLOAD}</script>`)}); marker.appendChild(frag);`,
  ],
  [
    'Range.createContextualFragment nested script then Node.appendChild',
    `const range = document.createRange(); range.selectNode(marker); const frag = range.createContextualFragment(${JSON.stringify(`<div><script>${PAYLOAD}</script></div>`)}); marker.appendChild(frag);`,
  ],
  [
    'Range.createContextualFragment script then Element.append',
    `const range = document.createRange(); range.selectNode(marker); const frag = range.createContextualFragment(${JSON.stringify(`<script>${PAYLOAD}</script>`)}); marker.append(frag);`,
  ],
  [
    'Element.append of a script into a detached div, then Node.appendChild of that div',
    `const wrap = document.createElement("div"); const nested = document.createElement("script"); nested.text = ${JSON.stringify(PAYLOAD)}; wrap.append(nested); marker.appendChild(wrap);`,
  ],
  [
    'Element.replaceWith of a script inside a detached div, then Node.appendChild of that div',
    `const wrap = document.createElement("div"); const placeholder = document.createElement("span"); wrap.appendChild(placeholder); const nested = document.createElement("script"); nested.text = ${JSON.stringify(PAYLOAD)}; placeholder.replaceWith(nested); marker.appendChild(wrap);`,
  ],
  ['Node.appendChild of a script element', 'marker.appendChild(script);'],
];

type Observation = {
  sandboxed: boolean;
  title: string;
  hostEscape: string | null;
  iframeEscape: Array<string | null>;
  payloadConnected: boolean;
  error?: string;
  pageErrors: string[];
};

describe('frontend sandbox DOM insertion', () => {
  let browser: Browser;
  let server: http.Server;
  let origin: string;

  before(async () => {
    const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-dom-insertion-'));
    const bundlePath = path.join(workdir, 'harness.js');
    bundleHarness(bundlePath);
    const pageHtml = sandboxPageHtml();
    server = http.createServer((req, res) => {
      const url = (req.url ?? '/').split('?')[0];
      if (url === '/' || url === '/index.html') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(pageHtml);
        return;
      }
      if (url === '/harness.js') {
        res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
        fs.createReadStream(bundlePath).pipe(res);
        return;
      }
      res.writeHead(404);
      res.end('missing');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (address == null || typeof address === 'string') {
      throw new Error('sandbox test server did not bind a TCP port');
    }
    origin = `http://127.0.0.1:${address.port}`;

    const { chromium } = require('playwright') as typeof import('playwright');
    browser = await chromium.launch({
      headless: true,
      executablePath: chromeExecutable(),
    });
  });

  after(async () => {
    await browser?.close();
    if (server) {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });

  for (const [name, insertion] of insertions) {
    it(`${name} does not run a script in the Grafana page`, async () => {
      const observed = await runPlugin(browser, origin, pluginModuleSource(insertion));
      const detail = `${observed.pageErrors.join('\n')}\n${observed.error ?? ''}`;
      assert.equal(observed.sandboxed, true, detail);
      assert.equal(observed.title, 'sandbox-plugin-ran', detail);
      assert.equal(observed.hostEscape, null, detail);
      assert.deepEqual(
        observed.iframeEscape.filter((value) => value != null),
        [],
        detail
      );
      assert.equal(observed.payloadConnected, false, detail);
    });
  }
});

function pluginModuleSource(insertion: string): string {
  return `define([], function () {
    document.title = 'sandbox-plugin-ran';
    const marker = document.createElement('div');
    marker.id = 'host-marker';
    document.body.appendChild(marker);
    const script = document.createElement('script');
    script.id = 'xss-script';
    script.text = ${JSON.stringify(PAYLOAD)};
    ${insertion}
    return { plugin: {} };
  });`;
}

async function runPlugin(browser: Browser, origin: string, source: string): Promise<Observation> {
  const page: Page = await browser.newPage();
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  try {
    await page.goto(origin, { waitUntil: 'load' });
    // This callback is serialized into the browser. Keep it free of TypeScript syntax.
    const observed = await page.evaluate(async (pluginSource) => {
      const load = Reflect.get(window, '__loadListedSandboxPlugin');
      if (!load) {
        return {
          sandboxed: false,
          title: document.title,
          hostEscape: null,
          iframeEscape: [],
          payloadConnected: false,
          error: 'sandbox harness did not install its loader',
        };
      }
      const loaded = await load('sandbox-escape', pluginSource);
      const payloadIn = (root) =>
        [...root.querySelectorAll('script')].some(
          (element) => element.isConnected && (element.textContent ?? '').includes('__sandboxEscape')
        );
      const iframeEscape = [];
      let payloadConnected = payloadIn(document);
      for (const frame of document.querySelectorAll('iframe')) {
        try {
          const view = frame.contentWindow;
          iframeEscape.push(view && view.__sandboxEscape ? view.__sandboxEscape : null);
          if (frame.contentDocument && payloadIn(frame.contentDocument)) {
            payloadConnected = true;
          }
        } catch (error) {
          iframeEscape.push(error instanceof Error ? error.message : String(error));
        }
      }
      return {
        sandboxed: loaded.sandboxed,
        title: document.title,
        hostEscape: globalThis.__sandboxEscape ?? null,
        iframeEscape,
        payloadConnected,
        error: loaded.error,
      };
    }, source);
    return { ...observed, pageErrors };
  } finally {
    await page.close();
  }
}

function sandboxPageHtml(): string {
  const boot = {
    assets: { dark: '', light: '' },
    user: { isSignedIn: true, id: 1, theme: 'dark' },
    navTree: [],
    settings: {
      enableFrontendSandboxForPlugins: [PLUGIN_ID],
      appSubUrl: '',
      buildInfo: { env: 'production', version: '1.0', commit: '1' },
      featureToggles: {},
      datasources: {
        [PLUGIN_ID]: {
          type: PLUGIN_ID,
          name: 'Sandbox escape',
          meta: {
            id: PLUGIN_ID,
            name: 'Sandbox escape',
            type: 'datasource',
            module: `/public/plugins/${PLUGIN_ID}/module.js`,
          },
        },
      },
    },
  };
  return `<!doctype html>
<html>
  <head><meta charset="utf-8"></head>
  <body>
    <script>window.grafanaBootData = ${JSON.stringify(boot)};</script>
    <script src="/harness.js"></script>
  </body>
</html>`;
}

function bundleHarness(outfile: string): void {
  const result = spawnSync(process.execPath, [path.join(here, 'sandboxDomInsertion.bundle.mjs'), outfile], {
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `esbuild exited ${result.status}`);
  }
}

function chromeExecutable(): string {
  if (process.env.CHROME_BIN && fs.existsSync(process.env.CHROME_BIN)) {
    return process.env.CHROME_BIN;
  }
  const candidates = ['/opt/google/chrome/chrome', '/usr/bin/google-chrome', '/usr/bin/chromium-browser'];
  const found = candidates.find((candidate) => fs.existsSync(candidate));
  if (!found) {
    throw new Error('Chrome is required to run the sandbox DOM insertion tests');
  }
  return found;
}
