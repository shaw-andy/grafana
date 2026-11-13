/**
 * @jest-environment jsdom
 */
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';

/**
 * The saved MapLibre style URL is loaded with the page's real fetch.
 * Node's fetch does not attach a cookie jar (undici leaves that step unimplemented),
 * so this drives the bundled basemap in Chrome, which does.
 *
 * The session cookie value below is a placeholder, not a real session.
 */
const SESSION_COOKIE_NAME = 'grafana_session';
const SESSION_COOKIE_VALUE = 'session-placeholder';

const HARNESS = path.join(__dirname, 'maplibre.styleUrlCredentials.harness.ts');
const ESBUILD = path.join(process.cwd(), 'node_modules/esbuild/bin/esbuild');
const CHROME = process.env.CHROME_PATH || '/usr/local/bin/google-chrome';

interface Hit {
  path: string;
  sentSessionCookie: boolean;
}

describe('MapLibre style URL credentials', () => {
  jest.setTimeout(60000);

  it('does not send the viewer session cookie for a same-origin style URL', async () => {
    const hits = await loadStylesInBrowser();
    const credentialed = hits.filter((hit) => hit.sentSessionCookie);
    expect(credentialed).toEqual([]);
  });
});

async function loadStylesInBrowser(): Promise<Hit[]> {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'maplibre-style-credentials-'));
  const bundlePath = path.join(work, 'harness.js');
  const cert = await makeCertificate(work);
  const hits: Hit[] = [];
  let pageResult = '';

  const server = https.createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
    const url = new URL(req.url || '/', 'https://127.0.0.1');
    const requestPath = url.pathname + url.search;
    // The document and the harness are not style loads. A favicon request is the browser, not the basemap.
    if (requestPath !== '/' && requestPath !== '/harness.js' && url.pathname !== '/favicon.ico') {
      hits.push({
        path: requestPath,
        sentSessionCookie: sessionCookieSent(req.headers.cookie),
      });
    }
    respond(requestPath, res, fs.readFileSync(bundlePath));
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address == null || typeof address === 'string') {
    throw new Error('test server did not bind a port');
  }
  const origin = `https://127.0.0.1:${address.port}`;

  const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'maplibre-style-chrome-'));
  let chrome: ChildProcess | undefined;
  try {
    await bundleHarness(bundlePath);
    chrome = spawn(
      CHROME,
      [
        '--headless=new',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-background-networking',
        '--no-first-run',
        '--ignore-certificate-errors',
        `--user-data-dir=${userData}`,
        '--virtual-time-budget=20000',
        '--dump-dom',
        `${origin}/`,
      ],
      { stdio: ['ignore', 'pipe', 'ignore'] }
    );
    chrome.stdout?.on('data', (chunk: Buffer) => {
      pageResult += chunk.toString();
    });
    const killer = setTimeout(() => chrome?.kill('SIGKILL'), 25000);
    await new Promise<void>((resolve) => chrome?.on('close', () => resolve()));
    clearTimeout(killer);
  } finally {
    server.close();
    chrome?.kill('SIGKILL');
    fs.rmSync(work, { recursive: true, force: true });
    fs.rmSync(userData, { recursive: true, force: true });
  }

  if (!pageResult.includes('>done<')) {
    throw new Error(`browser did not finish loading styles: ${pageResult.slice(0, 500)}`);
  }
  return hits;
}

function sessionCookieSent(header: string | undefined): boolean {
  return (header || '')
    .split(';')
    .some((part) => part.trim().startsWith(`${SESSION_COOKIE_NAME}=`));
}

function respond(requestPath: string, res: import('node:http').ServerResponse, bundle: Buffer): void {
  if (requestPath === '/') {
    res.setHeader(
      'Set-Cookie',
      `${SESSION_COOKIE_NAME}=${SESSION_COOKIE_VALUE}; HttpOnly; Path=/; SameSite=Lax`
    );
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(pageHtml());
    return;
  }
  if (requestPath === '/harness.js') {
    res.setHeader('Content-Type', 'text/javascript');
    res.end(bundle);
    return;
  }
  // Logout is a redirect to a document that is not style JSON, matching the route's response shape.
  if (requestPath === '/logout') {
    res.statusCode = 302;
    res.setHeader('Location', '/login');
    res.end();
    return;
  }
  if (requestPath === '/login') {
    res.setHeader('Content-Type', 'text/html');
    res.end('<html>signed out</html>');
    return;
  }
  if (requestPath === '/profile/switch-org/2') {
    res.setHeader('Content-Type', 'text/html');
    res.end('<html>not json</html>');
    return;
  }
  if (requestPath === '/user/auth-tokens/rotate') {
    res.statusCode = 503;
    res.setHeader('Content-Type', 'text/plain');
    res.end('unavailable');
    return;
  }
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ version: 8, sources: {}, layers: [] }));
}

function pageHtml(): string {
  return `<!doctype html><body><pre id="out">pending</pre>
<script src="/harness.js"></script>
<script>
  const originalFetch = window.fetch.bind(window);
  let pending = 0;
  window.fetch = function (input, init) {
    pending += 1;
    return Promise.resolve(originalFetch(input, init)).finally(() => {
      pending -= 1;
    });
  };
  async function settle() {
    for (let i = 0; i < 40; i++) {
      if (pending === 0) {
        await new Promise((resolve) => setTimeout(resolve, 30));
        if (pending === 0) {
          return;
        }
      } else {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    }
  }
  (async () => {
    const origin = location.origin;
    const urls = [
      '/logout',
      '/profile/switch-org/2',
      '/user/auth-tokens/rotate',
      origin + '/logout?abs=1',
      '//' + location.host + '/logout?proto=1',
    ];
    for (const url of urls) {
      await window.initMaplibreStyle(url);
      await settle();
    }
    document.getElementById('out').textContent = 'done';
  })().catch((error) => {
    document.getElementById('out').textContent = 'failed ' + error;
  });
</script></body>`;
}

function bundleHarness(outfile: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(ESBUILD, [HARNESS, '--bundle', '--format=iife', '--platform=browser', `--outfile=${outfile}`], {
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`esbuild failed: ${stderr}`));
      }
    });
  });
}

function makeCertificate(dir: string): Promise<{ key: string; cert: string }> {
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  return new Promise((resolve, reject) => {
    const child = spawn(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', keyPath, '-out', certPath, '-days', '1', '-nodes', '-subj', '/CN=127.0.0.1'],
      { stdio: 'ignore' }
    );
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error('openssl failed to create the test certificate'));
        return;
      }
      resolve({ key: fs.readFileSync(keyPath, 'utf8'), cert: fs.readFileSync(certPath, 'utf8') });
    });
  });
}
