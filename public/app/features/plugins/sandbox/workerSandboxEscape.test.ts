import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

type WorkerCanary = {
  kind: string;
  scope: string;
  origin: string;
  cookie: string | null;
};

type SandboxObservation = {
  kind: string;
  eligible: boolean | null;
  reached: boolean;
  rejected: boolean;
  error: string | null;
  pageOrigin: string;
  documentWriteThrew: boolean | null;
  canaries: WorkerCanary[];
};

// Jest replaces @locker/near-membrane-dom and its jsdom environment breaks esbuild's Uint8Array check.
// The runner is a plain Node process so the real near-membrane bundle and Chrome SharedWorker run.
const blockedWorkerKinds = [
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

describe('sandboxed plugins cannot start workers on the Grafana origin', () => {
  let observations: SandboxObservation[] = [];

  beforeAll(() => {
    const runner = join(__dirname, 'workerSandboxEscape.runner.cjs');
    const result = spawnSync(process.execPath, [runner], {
      encoding: 'utf8',
      cwd: join(__dirname, '../../../../../'),
      env: {
        ...process.env,
        NODE_PATH: join(__dirname, '../../../../../node_modules'),
      },
      maxBuffer: 16 * 1024 * 1024,
    });
    if (result.status !== 0) {
      throw new Error(`worker sandbox runner failed\n${result.stdout}\n${result.stderr}`);
    }
    observations = JSON.parse(result.stdout) as SandboxObservation[];
  }, 120000);

  function observation(kind: string): SandboxObservation {
    const found = observations.find((row) => row.kind === kind);
    if (!found) {
      throw new Error(`missing observation for ${kind}`);
    }
    return found;
  }

  test('a page-owned SharedWorker blob runs on the page origin and sends the session cookie', () => {
    const row = observation('control-shared-worker-blob');
    expect(row.canaries).toEqual([
      {
        kind: 'control-shared-worker-blob',
        scope: 'SharedWorkerGlobalScope',
        origin: row.pageOrigin,
        cookie: 'grafana_session=placeholder-session',
      },
    ]);
  });

  test('the sandbox still rejects document.write for a listed community plugin', () => {
    const row = observation('document-write');
    expect(row.eligible).toBe(true);
    expect(row.reached).toBe(true);
    expect(row.documentWriteThrew).toBe(true);
    expect(row.rejected).toBe(false);
    expect(row.canaries).toEqual([]);
  });

  test.each(blockedWorkerKinds)('%s is rejected before any worker script runs', (kind) => {
    const row = observation(kind);
    expect(row.eligible).toBe(true);
    expect(row.reached).toBe(true);
    expect(row.canaries).toEqual([]);
    expect(row.rejected).toBe(true);
  });
});
