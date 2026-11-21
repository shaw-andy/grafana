/**
 * Spec for host-document event handlers installed from sandboxed plugin HTML.
 *
 * importPluginModuleInSandbox evaluates the plugin inside the near-membrane
 * sandbox. These tests load that function in a browser and expect plugin markup
 * not to install handlers on the host document. They fail while the gap is present.
 *
 * Left untested, because they are not HTML parser sinks:
 * - script elements produced by the HTML parser (the browser does not run them)
 * - an event property assigned a function that was created inside the sandbox
 * - window.top, a separate host-window reference
 */
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { TextEncoder } from 'node:util';

import { chromium, type Browser, type Page } from 'playwright-core';

// Jest's jsdom realm makes Node's TextEncoder fail esbuild's Uint8Array check.
// esbuild is loaded only after both come from the same realm.
const encodedProbe = new TextEncoder().encode('');
if (!(encodedProbe instanceof Uint8Array)) {
  global.Uint8Array = encodedProbe.constructor as typeof Uint8Array;
  global.TextEncoder = TextEncoder as typeof global.TextEncoder;
}

if (typeof global.setImmediate !== 'function') {
  global.setImmediate = ((fn: (...args: unknown[]) => void, ...args: unknown[]) =>
    setTimeout(fn, 0, ...args)) as typeof setImmediate;
}

const repoRoot = path.resolve(__dirname, '../../../../..');
const harnessEntry = path.join(__dirname, 'sandboxHtmlFragmentXss.harness.ts');

const HOST_TOKEN = 'HOSTONLY';

const fragmentPayload = `
define([], function () {
  function click(id) {
    var el = document.getElementById(id);
    if (el && el.click) el.click();
    if (el && el.focus) el.focus();
  }
  try {
    var iframe = document.createElement('iframe');
    iframe.id = 'control-iframe';
    document.body.appendChild(iframe);
  } catch (e) {}

  function frag(html) { return document.createRange().createContextualFragment(html); }
  var anchor = document.createElement('span');
  anchor.id = 'anchor';
  document.body.appendChild(anchor);

  try {
    document.body.appendChild(frag('<img id="ccf-onerror" src="/no-such-ccf-onerror.png" onerror="window.__xss.push(\\'ccf-appendChild-onerror:\\'+window.__hostToken)">'));
  } catch (e) {}
  try {
    document.body.appendChild(frag('<button id="ccf-onclick" onclick="window.__xss.push(\\'ccf-appendChild-onclick\\')">x</button>'));
    click('ccf-onclick');
  } catch (e) {}
  try {
    document.body.appendChild(frag('<details id="ccf-toggle" open ontoggle="window.__xss.push(\\'ccf-ontoggle\\')"></details>'));
  } catch (e) {}
  try {
    document.body.appendChild(frag('<input id="ccf-focus" onfocus="window.__xss.push(\\'ccf-onfocus\\')">'));
    click('ccf-focus');
  } catch (e) {}
  try { document.body.append(frag('<img id="ccf-append" src="/no-such-append.png" onerror="window.__xss.push(\\'ccf-append\\')">')); } catch (e) {}
  try { document.body.prepend(frag('<img id="ccf-prepend" src="/no-such-prepend.png" onerror="window.__xss.push(\\'ccf-prepend\\')">')); } catch (e) {}
  try { anchor.before(frag('<img id="ccf-before" src="/no-such-before.png" onerror="window.__xss.push(\\'ccf-before\\')">')); } catch (e) {}
  try { anchor.after(frag('<img id="ccf-after" src="/no-such-after.png" onerror="window.__xss.push(\\'ccf-after\\')">')); } catch (e) {}
  try {
    document.body.insertBefore(frag('<img id="ccf-insertbefore" src="/no-such-ib.png" onerror="window.__xss.push(\\'ccf-insertBefore\\')">'), anchor);
  } catch (e) {}
  try {
    var repl = document.createElement('span');
    document.body.appendChild(repl);
    document.body.replaceChild(frag('<img id="ccf-replace" src="/no-such-replace.png" onerror="window.__xss.push(\\'ccf-replaceChild\\')">'), repl);
  } catch (e) {}
  try {
    var node = frag('<img id="ccf-adj" src="/no-such-adj.png" onerror="window.__xss.push(\\'ccf-insertAdjacentElement\\')">').firstChild;
    anchor.insertAdjacentElement('afterend', node);
  } catch (e) {}
  try {
    var range = new Range();
    range.selectNode(document.body);
    document.body.appendChild(range.createContextualFragment('<img id="new-range" src="/no-such-new-range.png" onerror="window.__xss.push(\\'new-Range-onerror\\')">'));
  } catch (e) {}

  try {
    var innerClick = document.createElement('div');
    document.body.appendChild(innerClick);
    innerClick.innerHTML = '<button id="inner-click" onclick="window.__xss.push(\\'innerHTML-onclick\\')">x</button>';
    click('inner-click');
  } catch (e) {}
  try {
    var innerError = document.createElement('div');
    document.body.appendChild(innerError);
    innerError.innerHTML = '<img id="inner-onerror" src="/no-such-inner-onerror.png" onerror="window.__xss.push(\\'innerHTML-onerror\\')">';
  } catch (e) {}
  try {
    var outer = document.createElement('div');
    document.body.appendChild(outer);
    outer.outerHTML = '<button id="outer-click" onclick="window.__xss.push(\\'outerHTML-onclick\\')">x</button>';
    click('outer-click');
  } catch (e) {}
  try {
    document.body.insertAdjacentHTML('beforeend', '<button id="adjhtml-click" onclick="window.__xss.push(\\'insertAdjacentHTML-onclick\\')">x</button>');
    click('adjhtml-click');
    document.body.insertAdjacentHTML('beforeend', '<img id="adjhtml-onerror" src="/no-such-adjhtml.png" onerror="window.__xss.push(\\'insertAdjacentHTML-onerror\\')">');
  } catch (e) {}
  try {
    var parsedClick = new DOMParser().parseFromString('<button id="parser-click" onclick="window.__xss.push(\\'parseFromString-onclick\\')">x</button>', 'text/html');
    document.body.appendChild(parsedClick.body.firstChild);
    click('parser-click');
  } catch (e) {}
  try {
    var parsedError = new DOMParser().parseFromString('<img id="parser-onerror" src="/no-such-parser.png" onerror="window.__xss.push(\\'parseFromString-onerror\\')">', 'text/html');
    document.body.appendChild(parsedError.body.firstChild);
  } catch (e) {}
  try {
    var unsafe = document.createElement('div');
    document.body.appendChild(unsafe);
    if (unsafe.setHTMLUnsafe) {
      unsafe.setHTMLUnsafe('<button id="unsafe-click" onclick="window.__xss.push(\\'setHTMLUnsafe-onclick\\')">x</button>');
      click('unsafe-click');
    }
    if (unsafe.setHTML) {
      unsafe.setHTML('<button id="sethtml-click" onclick="window.__xss.push(\\'setHTML-onclick\\')">x</button>');
      click('sethtml-click');
    }
  } catch (e) {}
  try {
    var host = document.createElement('div');
    host.id = 'shadow-host';
    document.body.appendChild(host);
    var root = host.attachShadow({ mode: 'open' });
    root.innerHTML = '<button id="shadow-click" onclick="window.__xss.push(\\'shadow-innerHTML-onclick\\')">x</button>';
    var shadowButton = root.getElementById('shadow-click');
    if (shadowButton) shadowButton.click();
  } catch (e) {}
  try {
    if (Document.parseHTMLUnsafe) {
      var parsedUnsafe = Document.parseHTMLUnsafe('<button id="parseunsafe-click" onclick="window.__xss.push(\\'parseHTMLUnsafe-onclick\\')">x</button>');
      document.body.appendChild(parsedUnsafe.body.firstChild);
      click('parseunsafe-click');
    }
  } catch (e) {}
  try {
    var other = document.implementation.createHTMLDocument('t');
    other.body.innerHTML = '<button id="impl-click" onclick="window.__xss.push(\\'createHTMLDocument-onclick\\')">x</button>';
    document.body.appendChild(document.importNode(other.body.firstChild, true));
    click('impl-click');
  } catch (e) {}
  try {
    var img = document.createElement('img');
    img.id = 'setattr-img';
    img.setAttribute('onerror', 'window.__xss.push("setAttribute-onerror")');
    img.src = '/no-such-setattr.png';
    document.body.appendChild(img);
  } catch (e) {}
  return {};
});
`;

const documentWritePayload = `
define([], function () {
  try {
    document.open();
    document.write('<button id="write-click" onclick="window.__xss.push(\\'document-write-onclick\\')">x</button>');
    document.close();
    var written = document.getElementById('write-click');
    if (written && written.click) written.click();
  } catch (e) {}
  try {
    document.writeln('<button id="writeln-click" onclick="window.__xss.push(\\'document-writeln-onclick\\')">x</button>');
    var writtenLine = document.getElementById('writeln-click');
    if (writtenLine && writtenLine.click) writtenLine.click();
  } catch (e) {}
  return {};
});
`;

type RunResult = {
  error: string;
  xss: string[];
  iframePresent: boolean;
  reactRootPresent: boolean;
  onAttributes: string[];
};

async function bundleHarness(outfile: string) {
  const esbuild = await import('esbuild');
  await esbuild.build({
    entryPoints: [harnessEntry],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    outfile,
    define: { 'process.env.NODE_ENV': '"production"' },
    conditions: ['@grafana-app/source'],
    loader: {
      '.css': 'empty',
      '.svg': 'text',
      '.png': 'empty',
      '.gif': 'empty',
      '.woff': 'empty',
      '.woff2': 'empty',
      '.ttf': 'empty',
      '.eot': 'empty',
    },
    alias: {
      'systemjs/dist/system': path.join(repoRoot, 'node_modules/systemjs/dist/system.js'),
      'systemjs/dist/extras/amd': path.join(repoRoot, 'node_modules/systemjs/dist/extras/amd.js'),
    },
    logLevel: 'silent',
  });
}

function startServer(rootDir: string): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    let file = '';
    if (url.pathname === '/' || url.pathname === '/index.html') {
      file = path.join(rootDir, 'index.html');
    } else if (url.pathname === '/harness.js') {
      file = path.join(rootDir, 'harness.js');
    } else if (url.pathname.startsWith('/public/plugins/xss-plugin/')) {
      file = path.join(rootDir, 'module.js');
    } else {
      res.writeHead(404);
      res.end('missing');
      return;
    }
    res.end(fs.readFileSync(file));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        throw new Error('test server did not bind a TCP port');
      }
      resolve({
        url: `http://127.0.0.1:${address.port}/`,
        close: () =>
          new Promise((done, reject) => {
            server.close((err) => (err ? reject(err) : done()));
          }),
      });
    });
  });
}

async function launchBrowser(): Promise<Browser> {
  const executablePath = [
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].find((candidate) => fs.existsSync(candidate));
  if (executablePath) {
    return chromium.launch({ executablePath, headless: true, args: ['--no-sandbox', '--disable-gpu'] });
  }
  return chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-gpu'] });
}

async function runPayload(browser: Browser, harnessJs: string, pluginSource: string): Promise<RunResult> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-xss-'));
  fs.writeFileSync(path.join(dir, 'harness.js'), harnessJs);
  fs.writeFileSync(path.join(dir, 'module.js'), pluginSource);
  fs.writeFileSync(
    path.join(dir, 'index.html'),
    `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="reactRoot"></div><script>
window.grafanaBootData = { settings: {}, user: { locale: 'en-US' }, navTree: [] };
window.__xss = [];
window.__hostToken = ${JSON.stringify(HOST_TOKEN)};
</script><script src="/harness.js"></script></body></html>`
  );
  const server = await startServer(dir);
  const page: Page = await browser.newPage();
  try {
    await page.goto(server.url, { waitUntil: 'load', timeout: 30000 });
    await page.waitForFunction(() => (window as unknown as { __done?: boolean }).__done === true, null, {
      timeout: 20000,
    });
    await page.waitForTimeout(400);
    return await page.evaluate(() => {
      const onAttributes: string[] = [];
      const walk = (node: Node) => {
        if (node instanceof Element) {
          for (const attr of node.getAttributeNames()) {
            if (attr.toLowerCase().startsWith('on')) {
              onAttributes.push(`${node.id || node.nodeName}:${attr}`);
            }
          }
          if (node.shadowRoot) {
            walk(node.shadowRoot);
          }
        }
        for (const child of node.childNodes) {
          walk(child);
        }
      };
      walk(document);
      const hostWindow = window as unknown as { __xss?: string[]; __error?: string };
      return {
        error: hostWindow.__error ?? '',
        xss: hostWindow.__xss ?? [],
        iframePresent: document.getElementById('control-iframe') !== null,
        reactRootPresent: document.getElementById('reactRoot') !== null,
        onAttributes,
      };
    });
  } finally {
    await page.close();
    await server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('sandboxed plugin HTML sinks', () => {
  let browser: Browser;
  let harnessJs: string;

  beforeAll(async () => {
    const outfile = path.join(os.tmpdir(), `sandbox-xss-harness-${process.pid}.js`);
    await bundleHarness(outfile);
    harnessJs = fs.readFileSync(outfile, 'utf8');
    fs.rmSync(outfile, { force: true });
    browser = await launchBrowser();
  }, 60000);

  afterAll(async () => {
    await browser?.close();
  });

  it('does not let fragment, parser, or attribute sinks install host event handlers', async () => {
    const result = await runPayload(browser, harnessJs, fragmentPayload);

    expect(result.error).toBe('');
    // The iframe distortion is the control that the sandbox, not the raw page, ran.
    expect(result.iframePresent).toBe(false);
    expect(result.reactRootPresent).toBe(true);
    expect(result.xss).toEqual([]);
    expect(result.onAttributes).toEqual([]);
  }, 30000);

  it('does not let document.open, document.write, or document.writeln rewrite the host page', async () => {
    const result = await runPayload(browser, harnessJs, documentWritePayload);

    expect(result.error).toBe('');
    expect(result.reactRootPresent).toBe(true);
    expect(result.xss).toEqual([]);
    expect(result.onAttributes).toEqual([]);
  }, 30000);
});
