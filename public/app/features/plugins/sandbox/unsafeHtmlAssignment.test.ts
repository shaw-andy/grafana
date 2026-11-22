/**
 * Spec for the plugin-sandbox HTML sinks. These assertions describe the secure
 * behavior and fail while the native unsafe HTML parsers are returned to sandboxed
 * plugins. Run:
 *   node --experimental-strip-types public/app/features/plugins/sandbox/unsafeHtmlAssignment.test.ts
 */
import { spawn } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import esbuild from 'esbuild';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../../..');
const harnessPath = path.join(here, 'unsafeHtmlAssignment.harness.ts');

const EXECUTED_MARKERS = [
  'element-setHTMLUnsafe',
  'shadow-setHTMLUnsafe',
  'shadow-innerHTML',
  'parseHTMLUnsafe',
  'createContextualFragment',
  'createElement-insertBefore',
  'body-setHTMLUnsafe',
];

type LogEntry = { name: string; status: string; detail: string };
type XssMessage = { kind?: string; marker?: string; saw?: string };
type HarnessResult = {
  coverage: Record<string, boolean>;
  elementsError: string;
  bodyError: string;
  elementsLog: string | null;
  bodyLog: string | null;
  messages: XssMessage[];
  srcdocIframeCount: number;
  parentCookieSeenFromFrame: string;
};

function writeStubs(dir: string): Record<string, string> {
  const files: Record<string, string> = {
    'grafana-data.js': `
      export const PluginType = { app: 'app', panel: 'panel', datasource: 'datasource' };
      export function patchArrayVectorProrotypeMethods() {}
      export class DataSourceApi {}
      export class CustomVariableSupport {}
      export const textUtil = { sanitizeUrl: (url) => url };
    `,
    'grafana-runtime.js': `
      export const config = {
        buildInfo: { env: 'production' },
        trustedTypesDefaultPolicyEnabled: false,
        cspReportOnlyEnabled: false,
        featureToggles: {},
        pluginsCDNBaseURL: '',
        appSubUrl: '',
      };
    `,
    'grafana-runtime-unstable.js': `
      export function getLogger() {
        return { logWarning() {}, logError() {}, logInfo() {} };
      }
    `,
    'grafana-runtime-internal.js': `
      export async function getDatasourcePluginMeta(pluginId) {
        if (pluginId === 'sandbox-xss-elements' || pluginId === 'sandbox-xss-body') {
          return { id: pluginId, type: 'datasource', module: '/public/plugins/' + pluginId + '/module.js' };
        }
        return null;
      }
      export async function getPanelPluginMetas() { return []; }
      export async function getAppPluginMetas() { return []; }
      export function invalidatePluginSettingsCache() {}
    `,
    'grafana-ui.js': 'export {};',
    'faro.js': 'export {};',
    'lodash.js': `
      export { default as isFunction } from ${JSON.stringify(path.join(repoRoot, 'node_modules/lodash/isFunction.js'))};
      export { default as cloneDeep } from ${JSON.stringify(path.join(repoRoot, 'node_modules/lodash/cloneDeep.js'))};
    `,
  };
  const aliases: Record<string, string> = {};
  for (const [name, contents] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    writeFileSync(filePath, contents);
    aliases[name] = filePath;
  }
  return aliases;
}

async function runInChrome(): Promise<HarnessResult> {
  const stubDir = mkdtempSync(path.join(tmpdir(), 'sandbox-xss-'));
  const stubs = writeStubs(stubDir);
  const outfile = path.join(stubDir, 'harness.js');
  const nm = path.join(repoRoot, 'node_modules');
  await esbuild.build({
    absWorkingDir: repoRoot,
    entryPoints: [harnessPath],
    bundle: true,
    format: 'iife',
    outfile,
    define: { 'process.env.NODE_ENV': '"production"' },
    alias: {
      '@grafana/data': stubs['grafana-data.js'],
      '@grafana/runtime': stubs['grafana-runtime.js'],
      '@grafana/runtime/unstable': stubs['grafana-runtime-unstable.js'],
      '@grafana/runtime/internal': stubs['grafana-runtime-internal.js'],
      '@grafana/ui': stubs['grafana-ui.js'],
      '@grafana/faro-web-sdk': stubs['faro.js'],
      lodash: stubs['lodash.js'],
      'systemjs/dist/extras/amd': path.join(nm, 'systemjs/dist/extras/amd.js'),
      'systemjs/dist/system': path.join(nm, 'systemjs/dist/system.js'),
    },
  });

  const html = '<!doctype html><body><div id="root"></div><script src="/harness.js"></script></body>';
  const server = createServer((req, res: ServerResponse) => {
    if (req.url?.startsWith('/harness.js')) {
      res.writeHead(200, { 'Content-Type': 'text/javascript' });
      res.end(readFileSync(outfile));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('test server failed to bind');
  }
  const url = `http://127.0.0.1:${address.port}/`;
  const chrome = process.env.CHROME_PATH || 'google-chrome';
  try {
    const dom = await new Promise<string>((resolve, reject) => {
      const child = spawn(
        chrome,
        ['--headless=new', '--no-sandbox', '--disable-gpu', '--virtual-time-budget=8000', '--dump-dom', url],
        { stdio: ['ignore', 'pipe', 'pipe'] }
      );
      let stdout = '';
      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString();
      });
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
      }, 20000);
      child.on('exit', () => {
        clearTimeout(timer);
        resolve(stdout);
      });
      child.on('error', reject);
    });
    const start = dom.indexOf('<pre id="out">');
    const end = dom.indexOf('</pre>', start);
    if (start < 0 || end < 0) {
      throw new Error('harness produced no result: ' + dom.slice(0, 500));
    }
    return JSON.parse(dom.slice(start + '<pre id="out">'.length, end).replaceAll('&quot;', '"').replaceAll('&amp;', '&').replaceAll('&lt;', '<').replaceAll('&gt;', '>')) as HarnessResult;
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function parseLog(raw: string | null): LogEntry[] {
  if (!raw) {
    return [];
  }
  return JSON.parse(raw) as LogEntry[];
}

export async function verifySandboxRejectsUnsafeHtml(): Promise<void> {
  const result = await runInChrome();
  const failures: string[] = [];
  const elements = parseLog(result.elementsLog);
  const body = parseLog(result.bodyLog);
  const byName = new Map([...elements, ...body].map((entry) => [entry.name, entry]));

  for (const control of ['innerHTML', 'domparser']) {
    const entry = byName.get(control);
    if (!entry || entry.status !== 'threw' || !entry.detail.includes('<iframe> is not allowed')) {
      failures.push(`${control} was not rejected by the existing sandbox distortion: ${JSON.stringify(entry)}`);
    }
  }

  const executed = (result.messages || []).filter((message) => message.kind === 'xss').map((message) => message.marker);
  for (const marker of EXECUTED_MARKERS) {
    if (executed.includes(marker)) {
      failures.push(`${marker} ran a same-origin iframe script inside the sandbox (saw parent marker: ${result.messages.find((message) => message.marker === marker)?.saw})`);
    }
    const entry = byName.get(marker);
    if (entry?.detail === 'iframe-present') {
      failures.push(`${marker} inserted an iframe into the live document`);
    }
  }

  if (result.srcdocIframeCount > 0) {
    failures.push(`live document still contains ${result.srcdocIframeCount} srcdoc iframe(s)`);
  }
  if (result.parentCookieSeenFromFrame.includes('session_probe=probe-placeholder')) {
    failures.push('iframe script could read the parent document cookie jar');
  }
  if (!result.coverage.elementInnerHTML || !result.coverage.domParser) {
    failures.push(`sandbox distortion map did not include the existing HTML sinks: ${JSON.stringify(result.coverage)}`);
  }
  if (result.elementsError) {
    failures.push(`elements plugin failed to load: ${result.elementsError}`);
  }

  if (failures.length > 0) {
    throw new Error(failures.join('\n'));
  }
}

const isJest = typeof describe === 'function';
if (isJest) {
  describe('plugin sandbox unsafe HTML assignment', () => {
    it('does not run iframe scripts from unwrapped HTML parsers', async () => {
      await verifySandboxRejectsUnsafeHtml();
    }, 60000);
  });
} else if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  verifySandboxRejectsUnsafeHtml()
    .then(() => {
      console.log('sandbox unsafe HTML sinks rejected iframe script');
    })
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : error);
      process.exit(1);
    });
}
