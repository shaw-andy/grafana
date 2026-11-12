import http from 'node:http';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const nodeRequire = createRequire(__filename);

import { chromium, type Browser, type Page } from '@playwright/test';
import * as esbuild from 'esbuild';

/**
 * Plugins listed in enable_frontend_sandbox_for_plugins are evaluated by
 * importPluginModuleInSandbox. These tests load a probe through that function
 * and fail if the probe's markup runs in the host page.
 *
 * The assertions are expected to fail until the sandbox rejects host-page
 * script sinks. Run:
 *
 * yarn jest --watchAll=false --config public/app/features/plugins/sandbox/jest.sandbox-escape.config.js
 */

const MARKER = '__hostRealmMarker';
const REPO_ROOT = path.resolve(__dirname, '../../../../..');
const HARNESS = path.join(__dirname, 'pluginSandboxHostEscape.harness.ts');
const CHROME = process.env.CHROME_PATH ?? '/usr/bin/google-chrome-stable';

type ProbeResult = { fetched: boolean; error: string | null };

declare global {
  interface Window {
    __probeSource?: string;
    __hostRealmMarker?: string;
    __runSandboxProbe?: () => Promise<ProbeResult>;
  }
}

const bootData = {
  assets: { dark: '', light: '' },
  navTree: [],
  user: { theme: 'dark', locale: 'en-US', lightTheme: false },
  settings: {
    datasources: {
      'escape-probe-instance': {
        type: 'escape-probe',
        meta: {
          id: 'escape-probe',
          name: 'Escape probe',
          type: 'datasource',
          module: '/public/plugins/escape-probe/module.js',
        },
      },
    },
  },
};

function plugin(body: string): string {
  return `define([], function () {\n${body}\nreturn { plugin: {} };\n});\n`;
}

const fixedBox = 'position:fixed;top:0;left:0;width:160px;height:160px';

function onerrorImage(marker: string, insert: string): string {
  return plugin(`
    var img = document.createElement('img');
    img.setAttribute('onerror', 'window.${MARKER}=${JSON.stringify(marker)}');
    img.setAttribute('src', '/not-an-image.png');
    ${insert}
  `);
}

describe('sandboxed plugin script in the host page', () => {
  let browser: Browser;
  let server: http.Server;
  let origin: string;
  let bundlePath: string;

  beforeAll(async () => {
    bundlePath = path.join(os.tmpdir(), `plugin-sandbox-host-escape-${process.pid}.js`);
    await esbuild.build({
      absWorkingDir: REPO_ROOT,
      entryPoints: [HARNESS],
      outfile: bundlePath,
      bundle: true,
      format: 'iife',
      platform: 'browser',
      target: 'es2022',
      conditions: ['@grafana-app/source', 'browser'],
      nodePaths: [path.join(REPO_ROOT, 'public')],
      define: {
        'process.env.NODE_ENV': '"production"',
      },
      banner: {
        js: 'var process = globalThis.process || { env: { NODE_ENV: "production" }, browser: true };',
      },
      loader: {
        '.css': 'empty',
        '.svg': 'dataurl',
        '.png': 'dataurl',
        '.jpg': 'dataurl',
        '.gif': 'dataurl',
        '.woff': 'empty',
        '.woff2': 'empty',
        '.ttf': 'empty',
        '.eot': 'empty',
      },
      plugins: [
        {
          name: 'systemjs-extensionless',
          setup(build) {
            build.onResolve({ filter: /^systemjs\/dist\// }, (args) => {
              const file = args.path.endsWith('.js') ? args.path : `${args.path}.js`;
              return { path: nodeRequire.resolve(file) };
            });
          },
        },
      ],
      logLevel: 'silent',
    });

    server = http.createServer((_req, res) => {
      const html = `<!doctype html><html><head><title>sandbox-probe</title></head><body><script>window.grafanaBootData = ${JSON.stringify(
        bootData
      )};</script></body></html>`;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') {
      throw new Error('probe server did not bind');
    }
    origin = `http://127.0.0.1:${address.port}`;

    browser = await chromium.launch({
      executablePath: CHROME,
      headless: true,
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    });
  }, 180000);

  afterAll(async () => {
    await browser?.close();
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  });

  async function openProbePage(): Promise<Page> {
    const page = await browser.newPage();
    await page.goto(origin, { waitUntil: 'load' });
    await page.addScriptTag({ path: bundlePath });
    return page;
  }

  async function runProbe(source: string, interaction?: { hover?: string; click?: string }) {
    const page = await openProbePage();
    try {
      await page.evaluate((probeSource) => {
        window.__probeSource = probeSource;
      }, source);
      let result: ProbeResult;
      try {
        result = await page.evaluate(async () => {
          if (!window.__runSandboxProbe) {
            return { fetched: false, error: 'probe harness was not installed' };
          }
          return window.__runSandboxProbe();
        });
      } catch (error) {
        throw new Error(`host page context failed while the sandboxed plugin ran: ${String(error)}`);
      }

      if (interaction?.hover) {
        await page
          .locator(interaction.hover)
          .hover({ timeout: 1000, force: true })
          .catch(() => undefined);
      }
      if (interaction?.click) {
        await page
          .locator(interaction.click)
          .click({ timeout: 1000, force: true })
          .catch(() => undefined);
      }

      await page
        .waitForFunction((marker) => window[marker] !== undefined, MARKER, { timeout: 1000 })
        .catch(() => undefined);

      const marker = await page.evaluate((name) => window[name] ?? null, MARKER);
      return { ...result, marker };
    } finally {
      await page.close();
    }
  }

  it('keeps a direct global assignment inside the sandbox', async () => {
    const result = await runProbe(plugin(`window.${MARKER} = 'direct-assignment';`));
    expect(result.fetched).toBe(true);
    expect(result.marker).toBeNull();
  });

  it('still lets a sandboxed plugin append a plain element', async () => {
    const page = await openProbePage();
    try {
      await page.evaluate(
        (probeSource) => {
          window.__probeSource = probeSource;
        },
        plugin(`
        var div = document.createElement('div');
        div.id = 'benign-node';
        div.textContent = 'ok';
        document.body.appendChild(div);
      `)
      );
      const result = await page.evaluate(async () => window.__runSandboxProbe!());
      const text = await page.locator('#benign-node').textContent();
      expect(result.fetched).toBe(true);
      expect(result.error).toBeNull();
      expect(text).toBe('ok');
    } finally {
      await page.close();
    }
  });

  it('does not run an inline script appended to the host body', async () => {
    const result = await runProbe(
      plugin(`
      var script = document.createElement('script');
      script.textContent = 'window.${MARKER}="inline-script"';
      document.body.appendChild(script);
    `)
    );
    expect(result.fetched).toBe(true);
    expect(result.marker).toBeNull();
  });

  it('does not insert an iframe created with createElement("iframe")', async () => {
    const page = await openProbePage();
    try {
      await page.evaluate(
        (probeSource) => {
          window.__probeSource = probeSource;
        },
        plugin(`
        var iframe = document.createElement('iframe');
        iframe.setAttribute('srcdoc', '<script>parent.${MARKER}="lower-iframe"<\\/script>');
        document.body.appendChild(iframe);
      `)
      );
      await page.evaluate(async () => window.__runSandboxProbe!());
      await page.waitForTimeout(300);
      expect(await page.locator('iframe[srcdoc]').count()).toBe(0);
      expect(await page.evaluate((name) => window[name] ?? null, MARKER)).toBeNull();
    } finally {
      await page.close();
    }
  });

  it('does not leave a javascript URL on a host anchor', async () => {
    const page = await openProbePage();
    try {
      await page.evaluate(
        (probeSource) => {
          window.__probeSource = probeSource;
        },
        plugin(`
        var link = document.createElement('a');
        link.id = 'js-url';
        link.textContent = 'open';
        link.setAttribute('href', 'javascript:window.${MARKER}="javascript-url"');
        document.body.appendChild(link);
      `)
      );
      const result = await page.evaluate(async () => window.__runSandboxProbe!());
      const href = (await page.locator('#js-url').getAttribute('href')) ?? '';
      expect(result.fetched).toBe(true);
      expect(href).not.toMatch(/^javascript:/i);
    } finally {
      await page.close();
    }
  });

  it('does not run onerror assigned through innerHTML', async () => {
    const result = await runProbe(
      plugin(`
      document.body.insertAdjacentHTML('beforeend', '<img alt="sanitized" src="/not-an-image.png" onerror="window.${MARKER}=\\'innerHTML-onerror\\'">');
    `)
    );
    expect(result.fetched).toBe(true);
    expect(result.marker).toBeNull();
  });

  it.each([
    {
      name: 'setAttribute onerror and appendChild',
      source: onerrorImage('setAttribute-onerror', 'document.body.appendChild(img);'),
    },
    {
      name: 'setAttributeNS onerror and appendChild',
      source: plugin(`
        var img = document.createElement('img');
        img.setAttributeNS(null, 'onerror', 'window.${MARKER}="setAttributeNS-onerror"');
        img.setAttributeNS(null, 'src', '/not-an-image.png');
        document.body.appendChild(img);
      `),
    },
    {
      name: 'Element.append of an onerror image',
      source: onerrorImage('append', 'document.body.append(img);'),
    },
    {
      name: 'Element.prepend of an onerror image',
      source: onerrorImage('prepend', 'document.body.prepend(img);'),
    },
    {
      name: 'Element.after of an onerror image',
      source: onerrorImage(
        'after',
        `var anchor = document.createElement('div');
         document.body.appendChild(anchor);
         anchor.after(img);`
      ),
    },
    {
      name: 'Element.before of an onerror image',
      source: onerrorImage(
        'before',
        `var anchor = document.createElement('div');
         document.body.appendChild(anchor);
         anchor.before(img);`
      ),
    },
    {
      name: 'Node.insertBefore of an onerror image',
      source: onerrorImage('insertBefore', 'document.body.insertBefore(img, null);'),
    },
    {
      name: 'Node.replaceChild of an onerror image',
      source: onerrorImage(
        'replaceChild',
        `var anchor = document.createElement('div');
         document.body.appendChild(anchor);
         document.body.replaceChild(img, anchor);`
      ),
    },
    {
      name: 'Element.insertAdjacentElement of an onerror image',
      source: onerrorImage(
        'insertAdjacentElement',
        `var anchor = document.createElement('div');
         document.body.appendChild(anchor);
         anchor.insertAdjacentElement('afterend', img);`
      ),
    },
    {
      name: 'Document.append of an onerror image',
      source: onerrorImage('document-append', 'document.append(img);'),
    },
    {
      name: 'innerHTML onpointerenter',
      hover: '#inner-target',
      source: plugin(`
        document.body.innerHTML = '<div id="inner-target" style="${fixedBox}" onpointerenter="window.${MARKER}=\\'innerHTML-onpointerenter\\'">x</div>';
      `),
    },
    {
      name: 'outerHTML onpointerenter',
      hover: '#outer-target',
      source: plugin(`
        var holder = document.createElement('div');
        document.body.appendChild(holder);
        holder.outerHTML = '<div id="outer-target" style="${fixedBox}" onpointerenter="window.${MARKER}=\\'outerHTML\\'">x</div>';
      `),
    },
    {
      name: 'insertAdjacentHTML onpointerenter',
      hover: '#adjacent-target',
      source: plugin(`
        document.body.insertAdjacentHTML('beforeend', '<div id="adjacent-target" style="${fixedBox}" onpointerenter="window.${MARKER}=\\'insertAdjacentHTML\\'">x</div>');
      `),
    },
    {
      name: 'DOMParser onpointerenter adopted into the host document',
      hover: '#parser-target',
      source: plugin(`
        var parsed = new DOMParser().parseFromString('<div id="parser-target" style="${fixedBox}" onpointerenter="window.${MARKER}=\\'domparser\\'">x</div>', 'text/html');
        document.body.appendChild(parsed.getElementById('parser-target'));
      `),
    },
    {
      name: 'Range.createContextualFragment onerror image',
      source: plugin(`
        var range = document.createRange();
        range.selectNode(document.body);
        var fragment = range.createContextualFragment('<img alt="fragment" src="/not-an-image.png" onerror="window.${MARKER}=\\'createContextualFragment\\'">');
        document.body.appendChild(fragment);
      `),
    },
    {
      name: 'document.writeln onerror image',
      source: plugin(`
        document.writeln('<img alt="writeln" src="/not-an-image.png" onerror="window.${MARKER}=\\'writeln\\'">');
      `),
    },
    {
      name: 'createElement("IFRAME") srcdoc inserted with insertBefore',
      source: plugin(`
        var iframe = document.createElement('IFRAME');
        iframe.setAttribute('srcdoc', '<script>parent.${MARKER}="iframe-createElement-case"<\\/script>');
        document.body.insertBefore(iframe, null);
      `),
    },
    {
      name: 'createElementNS iframe srcdoc inserted with insertBefore',
      source: plugin(`
        var iframe = document.createElementNS('http://www.w3.org/1999/xhtml', 'iframe');
        iframe.setAttribute('srcdoc', '<script>parent.${MARKER}="iframe-createElementNS"<\\/script>');
        document.body.insertBefore(iframe, null);
      `),
    },
    {
      name: 'createElementNS iframe srcdoc inserted with replaceChild',
      source: plugin(`
        var anchor = document.createElement('div');
        document.body.appendChild(anchor);
        var iframe = document.createElementNS('http://www.w3.org/1999/xhtml', 'iframe');
        iframe.setAttribute('srcdoc', '<script>parent.${MARKER}="iframe-replaceChild"<\\/script>');
        document.body.replaceChild(iframe, anchor);
      `),
    },
    {
      name: 'createElementNS iframe srcdoc inserted with insertAdjacentElement',
      source: plugin(`
        var anchor = document.createElement('div');
        document.body.appendChild(anchor);
        var iframe = document.createElementNS('http://www.w3.org/1999/xhtml', 'iframe');
        iframe.setAttribute('srcdoc', '<script>parent.${MARKER}="iframe-insertAdjacentElement"<\\/script>');
        anchor.insertAdjacentElement('afterend', iframe);
      `),
    },
    {
      name: 'setAttributeNode onerror and appendChild',
      source: plugin(`
        var img = document.createElement('img');
        var attr = document.createAttribute('onerror');
        attr.value = 'window.${MARKER}="setAttributeNode"';
        img.setAttributeNode(attr);
        img.setAttribute('src', '/not-an-image.png');
        document.body.appendChild(img);
      `),
    },
    {
      name: 'iframe src javascript URL',
      source: plugin(`
        var iframe = document.createElement('IFRAME');
        iframe.setAttribute('src', 'javascript:parent.${MARKER}="iframe-javascript-src"');
        document.body.insertBefore(iframe, null);
      `),
    },
  ])('$name does not run in the host page', async ({ source, hover, click }) => {
    const result = await runProbe(source, { hover, click });
    expect(result.fetched).toBe(true);
    expect(result.marker).toBeNull();
  });
});
