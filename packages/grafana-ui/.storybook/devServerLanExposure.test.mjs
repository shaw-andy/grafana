/**
 * Spec for the Storybook development server started by the package scripts.
 *
 * A client that can open the dev server on a non-loopback address must not be
 * able to learn the WebSocket credential from the HTML page and use it to
 * create or rewrite story files. These assertions fail while storybook 10.3.6
 * is in use, because that server listens on every interface, embeds the
 * credential in the manager HTML, and accepts story writes from that client.
 *
 * The same `storybook dev` entrypoint backs both package scripts:
 * - packages/grafana-ui: `storybook dev -p 9001 -c .storybook --no-open`
 * - packages/grafana-flamegraph: `storybook dev -p 6006`
 * The flamegraph script omits `--no-open` and uses another port. Neither flag
 * changes the listen address or the story-write channel, so one server covers
 * both. Not exercised here, because they are separate channel operations:
 * open-in-editor (starts an external editor), whats-new cache and notification
 * toggles (write the Storybook cache or main config), and file search (read).
 * No Vitest addon is installed, so this does not cover command execution.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');
const marker = 'exposure-marker';

async function loadPackage(relativePath) {
  return JSON.parse(await readFile(path.join(repoRoot, relativePath), 'utf8'));
}

function externalIpv4Addresses() {
  const addresses = [];
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) {
        addresses.push(entry.address);
      }
    }
  }
  return addresses;
}

function scriptArgs(script, port) {
  const args = script.split(/\s+/);
  const portFlag = args.indexOf('-p');
  assert.notEqual(portFlag, -1, `storybook script must select a port: ${script}`);
  args[portFlag + 1] = String(port);
  assert.equal(args.includes('--host'), false, `script must not choose a listen host: ${script}`);
  return args.slice(1);
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function installStorybook(directory, version) {
  await mkdir(path.join(directory, '.storybook'), { recursive: true });
  await mkdir(path.join(directory, 'stories'), { recursive: true });
  await mkdir(path.join(directory, 'src'), { recursive: true });
  await writeFile(
    path.join(directory, 'package.json'),
    JSON.stringify(
      {
        name: 'storybook-exposure-fixture',
        private: true,
        type: 'module',
        dependencies: {
          '@storybook/react-vite': version,
          react: '19.2.0',
          'react-dom': '19.2.0',
          storybook: version,
          vite: '6.4.1',
        },
      },
      null,
      2
    )
  );
  await writeFile(
    path.join(directory, '.storybook', 'main.js'),
    [
      'export default {',
      "  stories: ['../stories/**/*.stories.js', '../src/**/*.stories.jsx'],",
      "  framework: '@storybook/react-vite',",
      '};',
      '',
    ].join('\n')
  );
  await writeFile(
    path.join(directory, 'stories', 'Button.stories.js'),
    ["const meta = { title: 'Button' };", 'export default meta;', "export const Primary = { args: { label: 'safe' } };", ''].join(
      '\n'
    )
  );
  await writeFile(path.join(directory, 'src', 'Widget.js'), 'export function Widget() { return null; }\n');
  await new Promise((resolve, reject) => {
    const child = spawn('npm', ['install', '--no-audit', '--no-fund', '--loglevel=error', '--legacy-peer-deps'], {
      cwd: directory,
      stdio: 'inherit',
    });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`npm install exited ${code}`))));
  });
}

async function waitForLoopback(port, child) {
  const started = Date.now();
  let exitCode = null;
  child.once('exit', (code) => {
    exitCode = code;
  });
  while (Date.now() - started < 90_000) {
    if (exitCode !== null) {
      throw new Error(`storybook exited ${exitCode} before serving pages`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(2000) });
      if (response.ok) {
        await response.arrayBuffer();
        return;
      }
    } catch {
      // The server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error('storybook did not serve the manager page on loopback');
}

function credentialFromManagerHtml(html) {
  const match = html.match(/window\['CHANNEL_OPTIONS'\]\s*=\s*(\{[\s\S]*?\});/);
  if (!match) {
    return null;
  }
  const parsed = JSON.parse(match[1]);
  return typeof parsed.wsToken === 'string' && parsed.wsToken.length > 0 ? parsed.wsToken : null;
}

async function fetchManager(address, port) {
  try {
    const response = await fetch(`http://${address}:${port}/`, { signal: AbortSignal.timeout(5000) });
    return { reachable: true, status: response.status, body: await response.text() };
  } catch {
    return { reachable: false, status: 0, body: '' };
  }
}

function sendChannelRequest(WebSocket, address, port, credential, event) {
  const responseType = event.type.replace('Request', 'Response');
  const socket = new WebSocket(
    `ws://${address}:${port}/storybook-server-channel?token=${encodeURIComponent(credential)}`,
    { origin: `http://${address}:${port}` }
  );
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.close();
      resolve(false);
    }, 8000);
    const finish = () => {
      clearTimeout(timer);
      socket.close();
      resolve(true);
    };
    socket.on('open', () => socket.send(JSON.stringify(event)));
    socket.on('message', (data) => {
      if (data.toString().includes(responseType)) {
        finish();
      }
    });
    socket.on('unexpected-response', () => {
      clearTimeout(timer);
      socket.close();
      resolve(false);
    });
    socket.on('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

test('a non-loopback client cannot use the dev server page to write story files', async () => {
  const uiPackage = await loadPackage('packages/grafana-ui/package.json');
  const flamegraphPackage = await loadPackage('packages/grafana-flamegraph/package.json');
  const version = uiPackage.devDependencies.storybook;
  assert.equal(flamegraphPackage.devDependencies.storybook, version);
  assert.equal(uiPackage.scripts.storybook.includes('--host'), false);
  assert.equal(flamegraphPackage.scripts.storybook.includes('--host'), false);

  const patchPath = path.join(repoRoot, '.yarn/patches/storybook-npm-10.3.6-8a0644ac0b.patch');
  if (existsSync(patchPath)) {
    const patch = await readFile(patchPath, 'utf8');
    assert.equal(patch.includes('wsToken'), false);
    assert.equal(patch.includes('getListenHost'), false);
  }

  const addresses = externalIpv4Addresses();
  assert.ok(addresses.length > 0, 'this check needs a non-loopback IPv4 address');

  const directory = await mkdtemp(path.join(os.tmpdir(), 'storybook-exposure-'));
  const port = await freePort();
  let child;
  try {
    await installStorybook(directory, version);
    const env = { ...process.env, CI: '1', BROWSER: 'none', STORYBOOK_DISABLE_TELEMETRY: '1' };
    delete env.STORYBOOK_WEBSOCKET_TOKEN;
    child = spawn(
      path.join(directory, 'node_modules', '.bin', 'storybook'),
      [...scriptArgs(uiPackage.scripts.storybook, port), '--ci', '--exact-port', '--disable-telemetry', '--quiet'],
      { cwd: directory, env, stdio: 'ignore' }
    );
    await waitForLoopback(port, child);

    const storyPath = path.join(directory, 'stories', 'Button.stories.js');
    const createdStoryPath = path.join(directory, 'src', 'Widget.stories.jsx');
    const before = await readFile(storyPath, 'utf8');
    const WebSocket = createRequire(path.join(directory, 'package.json'))('ws');

    for (const address of addresses) {
      const page = await fetchManager(address, port);
      if (!page.reachable || page.status !== 200) {
        continue;
      }
      const credential = credentialFromManagerHtml(page.body);
      if (!credential) {
        continue;
      }
      await sendChannelRequest(WebSocket, address, port, credential, {
        type: 'saveStoryRequest',
        args: [
          {
            id: 'exposure-save',
            payload: {
              csfId: 'button--primary',
              importPath: 'stories/Button.stories.js',
              args: JSON.stringify({ label: marker }),
            },
          },
        ],
      });
      await sendChannelRequest(WebSocket, address, port, credential, {
        type: 'createNewStoryfileRequest',
        args: [
          {
            id: 'exposure-create',
            payload: {
              componentFilePath: 'src/Widget.js',
              componentExportName: 'Widget',
              componentIsDefaultExport: false,
              componentExportCount: 1,
            },
          },
        ],
      });
      break;
    }

    const after = await readFile(storyPath, 'utf8');
    assert.deepEqual(
      {
        storyRewritten: after !== before,
        storyFileCreated: existsSync(createdStoryPath),
      },
      {
        storyRewritten: false,
        storyFileCreated: false,
      }
    );
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolve) => {
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 5000);
        child.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    await rm(directory, { recursive: true, force: true });
  }
});
