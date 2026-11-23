import { existsSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { join } from 'node:path';

import * as esbuild from 'esbuild';
import { chromium, type Browser, type Page } from '@playwright/test';

// Jest's module filename is this source file, so __dirname is the sandbox directory.
// A bundled probe can override it when the compiled file lives somewhere else.
const here = process.env.SANDBOX_TEST_DIR || __dirname;
const repoRoot = join(here, '../../../../../');
const shimDir = join(here, 'workerSandboxEscape.shims');

const SESSION_COOKIE = 'grafana_session=placeholder-session';

export type WorkerCanary = {
  kind: string;
  scope: string;
  origin: string;
  cookie: string | null;
};

export type SandboxObservation = {
  kind: string;
  eligible: boolean | null;
  reached: boolean;
  rejected: boolean;
  error: string | null;
  pageOrigin: string;
  documentWriteThrew: boolean | null;
  canaries: WorkerCanary[];
};

const KINDS = [
  'control-shared-worker-blob',
  'document-write',
  'shared-worker-blob',
  'shared-worker-data',
  'shared-worker-same-origin',
  'shared-worker-default-view',
  'shared-worker-flipping',
  'worker-blob',
  'worker-data',
  'worker-same-origin',
  'worker-default-view',
  'worker-flipping',
  'service-worker-blob',
  'service-worker-same-origin',
  'audio-worklet-blob',
  'paint-worklet-blob',
] as const;

export type SandboxWorkerKind = (typeof KINDS)[number];

// Entry points the sandbox must reject. The page-owned control and the document.write
// distortion check are separate observations.
export const blockedWorkerKinds = KINDS.filter(
  (kind) => kind !== 'control-shared-worker-blob' && kind !== 'document-write'
);

function json(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'set-cookie': `${SESSION_COOKIE}; Path=/; SameSite=Lax`,
  });
  res.end(JSON.stringify(body));
}

function workerBeacon(kind: string, canaryUrl: string): string {
  return `fetch(${JSON.stringify(canaryUrl)},{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({kind:${JSON.stringify(
    kind
  )},scope:self.constructor&&self.constructor.name,origin:location.origin})});`;
}

function pluginSource(kind: SandboxWorkerKind, pluginId: string, canaryUrl: string): string {
  const sameOrigin = `/public/plugins/${pluginId}/worker.js`;
  const lines: string[] = [
    'define([], function () {',
    '  fetch("/reached", { method: "POST" });',
  ];

  if (kind === 'document-write') {
    lines.push(
      '  var documentWriteThrew = false;',
      '  try { document.write("x"); } catch (e) { documentWriteThrew = true; }',
      `  if (!documentWriteThrew) { fetch(${JSON.stringify(canaryUrl)}, { method: "POST", headers: {"content-type":"application/json"}, body: JSON.stringify({kind:"document-write",scope:"document",origin:location.origin}) }); }`,
      '  return { plugin: { documentWriteThrew: documentWriteThrew } };',
      '});'
    );
    return lines.join('\n');
  }

  const blob = `URL.createObjectURL(new Blob([${JSON.stringify(workerBeacon(kind, canaryUrl))}], { type: "text/javascript" }))`;
  if (kind === 'shared-worker-blob') {
    lines.push(`  var worker = new SharedWorker(${blob});`, '  worker.port.start();');
  } else if (kind === 'shared-worker-data') {
    lines.push(
      `  var worker = new SharedWorker("data:text/javascript," + encodeURIComponent(${JSON.stringify(workerBeacon(kind, canaryUrl))}));`,
      '  worker.port.start();'
    );
  } else if (kind === 'shared-worker-same-origin') {
    lines.push(`  var worker = new SharedWorker(${JSON.stringify(sameOrigin + '?kind=' + kind)});`, '  worker.port.start();');
  } else if (kind === 'shared-worker-default-view') {
    lines.push(
      `  var Ctor = document.defaultView.SharedWorker;`,
      `  var worker = new Ctor(${blob});`,
      '  worker.port.start();'
    );
  } else if (kind === 'shared-worker-flipping') {
    lines.push(
      `  var blobUrl = ${blob};`,
      '  var reads = 0;',
      '  var flipping = {',
      `    toString: function () { reads += 1; return reads === 1 ? ${JSON.stringify(sameOrigin + '?kind=shared-worker-flipping-checked')} : blobUrl; }`,
      '  };',
      '  var worker = new SharedWorker(flipping);',
      '  worker.port.start();'
    );
  } else if (kind === 'worker-blob') {
    lines.push(`  new Worker(${blob});`);
  } else if (kind === 'worker-data') {
    lines.push(`  new Worker("data:text/javascript," + encodeURIComponent(${JSON.stringify(workerBeacon(kind, canaryUrl))}));`);
  } else if (kind === 'worker-same-origin') {
    lines.push(`  new Worker(${JSON.stringify(sameOrigin + '?kind=' + kind)});`);
  } else if (kind === 'worker-default-view') {
    lines.push(`  var Ctor = document.defaultView.Worker;`, `  new Ctor(${blob});`);
  } else if (kind === 'worker-flipping') {
    lines.push(
      `  var blobUrl = ${blob};`,
      '  var reads = 0;',
      '  var flipping = {',
      `    toString: function () { reads += 1; return reads === 1 ? ${JSON.stringify(sameOrigin + '?kind=worker-flipping-checked')} : blobUrl; }`,
      '  };',
      '  new Worker(flipping);'
    );
  } else if (kind === 'service-worker-blob') {
    lines.push(`  navigator.serviceWorker.register(${blob});`);
  } else if (kind === 'service-worker-same-origin') {
    lines.push(`  navigator.serviceWorker.register(${JSON.stringify(sameOrigin + '?kind=' + kind)});`);
  } else if (kind === 'audio-worklet-blob') {
    lines.push(`  var ctx = new AudioContext();`, `  ctx.audioWorklet.addModule(${blob});`);
  } else if (kind === 'paint-worklet-blob') {
    lines.push(`  CSS.paintWorklet.addModule(${blob});`);
  }

  lines.push('  return { plugin: {} };', '});');
  return lines.join('\n');
}

async function bundleHarness(): Promise<string> {
  const aliased = (name: string) => join(shimDir, name);
  const result = await esbuild.build({
    absWorkingDir: repoRoot,
    entryPoints: [join(here, 'workerSandboxEscape.harness.ts')],
    bundle: true,
    write: false,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    jsx: 'transform',
    define: {
      // isPluginFrontendSandboxEligible returns false when NODE_ENV is "test".
      // The browser bundle has to match a production page load, where that check is not taken.
      'process.env.NODE_ENV': '"production"',
    },
    alias: {
      '@grafana/data': aliased('grafanaData.ts'),
      '@grafana/runtime': aliased('grafanaRuntime.ts'),
      '@grafana/runtime/internal': aliased('grafanaRuntimeInternal.ts'),
      '@grafana/runtime/unstable': aliased('grafanaRuntimeUnstable.ts'),
      '@grafana/i18n': aliased('i18n.ts'),
      '@grafana/i18n/internal': aliased('i18n.ts'),
      '@grafana/ui': aliased('empty.ts'),
      '@grafana/faro-web-sdk': aliased('empty.ts'),
      'app/core/services/context_srv': aliased('contextSrv.ts'),
    },
    nodePaths: (process.env.SANDBOX_NODE_PATHS ?? `${join(repoRoot, 'node_modules')}:/tmp/sbdeps/node_modules`)
      .split(':')
      .filter((entry) => entry.length > 0 && existsSync(entry)),
    plugins: [
      {
        name: 'sandbox-test-resolve',
        setup(build) {
          const nodeModules = (process.env.SANDBOX_NODE_PATHS ?? `${join(repoRoot, 'node_modules')}:/tmp/sbdeps/node_modules`)
            .split(':')
            .filter((entry) => entry.length > 0 && existsSync(entry));
          build.onResolve({ filter: /^systemjs\/dist\// }, (args) => {
            for (const root of nodeModules) {
              const withJs = join(root, `${args.path}.js`);
              const asIs = join(root, args.path);
              if (existsSync(withJs)) {
                return { path: withJs };
              }
              if (existsSync(asIs)) {
                return { path: asIs };
              }
            }
            return undefined;
          });
          build.onResolve({ filter: /admin\/api$/ }, () => ({
            path: aliased('pluginDetailsApi.ts'),
          }));
          build.onResolve({ filter: /^app\// }, (args) => {
            if (args.path === 'app/core/services/context_srv') {
              return { path: aliased('contextSrv.ts') };
            }
            if (args.path.startsWith('app/plugins/')) {
              return { path: aliased('empty.ts') };
            }
            const base = join(repoRoot, 'public', args.path);
            for (const ext of ['.ts', '.tsx', '.js']) {
              if (existsSync(base + ext)) {
                return { path: base + ext };
              }
            }
            return { path: base + '.ts' };
          });
        },
      },
    ],
  });
  return result.outputFiles[0].text;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export async function observeSandboxWorkers(): Promise<SandboxObservation[]> {
  const harness = await bundleHarness();
  const canaries: WorkerCanary[] = [];
  let reached = false;
  let activeKind: SandboxWorkerKind = 'document-write';
  let activePluginId = '';
  let canaryUrl = '';

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    if (req.method === 'POST' && url.pathname === '/canary') {
      const raw = await readBody(req);
      const parsed = JSON.parse(raw) as { kind?: string; scope?: string; origin?: string };
      canaries.push({
        kind: String(parsed.kind),
        scope: String(parsed.scope),
        origin: String(parsed.origin),
        cookie: req.headers.cookie ?? null,
      });
      json(res, 204, {});
      return;
    }
    if (req.method === 'POST' && url.pathname === '/reached') {
      reached = true;
      json(res, 204, {});
      return;
    }
    if (url.pathname === '/harness.js') {
      res.writeHead(200, {
        'content-type': 'text/javascript',
        'set-cookie': `${SESSION_COOKIE}; Path=/; SameSite=Lax`,
      });
      res.end(harness);
      return;
    }
    if (url.pathname.endsWith('/worker.js')) {
      const kind = url.searchParams.get('kind') ?? activeKind;
      res.writeHead(200, {
        'content-type': 'text/javascript',
        'set-cookie': `${SESSION_COOKIE}; Path=/; SameSite=Lax`,
      });
      res.end(workerBeacon(kind, canaryUrl));
      return;
    }
    if (url.pathname.endsWith('/module.js')) {
      res.writeHead(200, {
        'content-type': 'text/javascript',
        'set-cookie': `${SESSION_COOKIE}; Path=/; SameSite=Lax`,
      });
      res.end(pluginSource(activeKind, activePluginId, canaryUrl));
      return;
    }
    if (url.pathname === '/') {
      const pluginId = url.searchParams.get('pluginId') ?? '';
      const modulePath = `/public/plugins/${pluginId}/module.js`;
      const control = url.searchParams.get('control') === '1';
      const page = `<!doctype html><meta charset="utf-8"><script>window.__SANDBOX_CASE__=${JSON.stringify({
        pluginId,
        modulePath,
        control,
      })};</script><script src="/harness.js"></script>`;
      res.writeHead(200, {
        'content-type': 'text/html',
        'set-cookie': `${SESSION_COOKIE}; Path=/; SameSite=Lax`,
      });
      res.end(page);
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('test server did not bind');
  }
  const origin = `http://127.0.0.1:${address.port}`;
  canaryUrl = `${origin}/canary`;

  let browser: Browser | undefined;
  const observations: SandboxObservation[] = [];
  try {
    browser = await chromium.launch({ channel: 'chrome', headless: true });
    for (const kind of KINDS) {
      canaries.length = 0;
      reached = false;
      activeKind = kind;
      activePluginId = `escape-${kind}`;
      const page: Page = await browser.newPage();
      const control = kind === 'control-shared-worker-blob';
      await page.goto(
        `${origin}/?pluginId=${encodeURIComponent(activePluginId)}&control=${control ? '1' : '0'}`,
        { waitUntil: 'domcontentloaded' }
      );
      await page.waitForFunction(() => window.__SANDBOX_RESULT__ !== undefined, undefined, { timeout: 20000 });
      const deadline = Date.now() + 1500;
      while (Date.now() < deadline) {
        if (canaries.length > 0 && (control || reached)) {
          break;
        }
        await page.waitForTimeout(50);
      }
      // Give a worker started after the constructor returned one more beat.
      await page.waitForTimeout(200);
      const result = await page.evaluate(() => window.__SANDBOX_RESULT__);
      observations.push({
        kind,
        eligible: result?.eligible ?? null,
        reached: control ? true : reached,
        rejected: Boolean(result?.rejected),
        error: result?.error ?? null,
        pageOrigin: result?.pageOrigin ?? origin,
        documentWriteThrew: result?.documentWriteThrew ?? null,
        canaries: canaries.slice(),
      });
      await page.close();
    }
  } finally {
    await browser?.close();
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
  return observations;
}
