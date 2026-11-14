'use strict';

const http = require('http');
const path = require('path');

const esbuild = require('esbuild');
const { chromium } = require('playwright');

async function main() {
  const sandboxDir = __dirname;
  const repoRoot = path.resolve(sandboxDir, '../../../../../');
  const harnessPath = path.join(sandboxDir, 'scriptInsertionEscape.harness.ts');
  const codeLoaderStubPath = path.join(sandboxDir, 'scriptInsertionEscape.codeLoaderStub.ts');

  const bundled = await esbuild.build({
    absWorkingDir: repoRoot,
    entryPoints: [harnessPath],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    write: false,
    jsx: 'automatic',
    tsconfig: path.join(repoRoot, 'tsconfig.json'),
    define: {
      'process.env.NODE_ENV': '"production"',
    },
    alias: {
      '@grafana/data': path.join(sandboxDir, 'scriptInsertionEscape.grafanaDataShim.ts'),
      '@grafana/runtime': path.join(sandboxDir, 'scriptInsertionEscape.grafanaRuntimeShim.ts'),
      '@grafana/runtime/unstable': path.join(sandboxDir, 'scriptInsertionEscape.loggerShim.ts'),
    },
    plugins: [
      {
        name: 'stub-plugin-source-fetch',
        setup(build) {
          build.onResolve({ filter: /\/codeLoader$/ }, () => {
            return { path: codeLoaderStubPath };
          });
        },
      },
    ],
  });

  const source = bundled.outputFiles[0] && bundled.outputFiles[0].text;
  if (!source) {
    throw new Error('esbuild produced no sandbox insertion bundle');
  }

  const html = `<!DOCTYPE html>
<html>
  <head><meta charset="utf-8" /></head>
  <body>
    <script>
      window.grafanaBootData = {
        assets: { dark: '', light: '' },
        settings: { buildInfo: { env: 'production' } },
        user: { theme: 'dark', locale: 'en-US' },
        navTree: [],
      };
    </script>
    <script src="/bundle.js"></script>
  </body>
</html>`;

  const server = http.createServer((req, res) => {
    if (req.url === '/bundle.js') {
      res.setHeader('content-type', 'text/javascript; charset=utf-8');
      res.end(source);
      return;
    }
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end(html);
  });

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('could not bind the sandbox insertion page');
  }

  const pageErrors = [];
  const browser = await chromium.launch({
    executablePath: '/usr/bin/google-chrome',
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });

  try {
    const page = await browser.newPage();
    page.on('pageerror', (error) => {
      pageErrors.push(error instanceof Error ? error.stack || error.message : String(error));
    });
    await page.goto(`http://127.0.0.1:${address.port}/`, { waitUntil: 'load' });
    const started = await page.evaluate(() => typeof window.__runScriptInsertionCases === 'function');
    if (!started) {
      throw new Error(`sandbox harness did not start:\n${pageErrors.join('\n')}`);
    }
    const results = await page.evaluate(async () => window.__runScriptInsertionCases());
    process.stdout.write(JSON.stringify({ results, errors: pageErrors }));
  } finally {
    await browser.close();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  process.stdout.write(JSON.stringify({ error: message }));
  process.exitCode = 1;
});
