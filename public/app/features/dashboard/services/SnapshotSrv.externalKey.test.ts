import { http, HttpResponse } from 'msw';

import { config, setBackendSrv } from '@grafana/runtime';
import { FlagKeys } from '@grafana/runtime/internal';
import { SceneTimeRange } from '@grafana/scenes';
import server, { setupMockServer } from '@grafana/test-utils/server';
import { setTestFlags } from '@grafana/test-utils/unstable';
import { backendSrv } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';
import { ShareSnapshot as LegacyShareSnapshot } from 'app/features/dashboard/components/ShareModal/ShareSnapshot';
import { type DashboardModel } from 'app/features/dashboard/state/DashboardModel';
import { DashboardScene } from 'app/features/dashboard-scene/scene/DashboardScene';
import { DefaultGridLayoutManager } from 'app/features/dashboard-scene/scene/layout-default/DefaultGridLayoutManager';
import { ShareSnapshotTab } from 'app/features/dashboard-scene/sharing/ShareSnapshotTab';
import { configureStore } from 'app/store/configureStore';

import { getDashboardSnapshotSrv } from './SnapshotSrv';

setBackendSrv(backendSrv);
setupMockServer();

const safeKey = 'abcdefghijklmnopqrstuvwxyz012345';

const victims = [
  { label: 'data source', path: 'api/datasources/uid/victim-ds' },
  { label: 'dashboard', path: 'api/dashboards/uid/victim-dash' },
  { label: 'user', path: 'api/admin/users/7' },
];

function traversalKey(path: string, encoded: boolean): string {
  const segment = encoded ? '%2e%2e/' : '../';
  return segment.repeat(12) + path;
}

function installCatchAll(): string[] {
  const seen: string[] = [];
  server.use(
    http.all('*', ({ request }) => {
      const url = new URL(request.url);
      seen.push(`${request.method} ${url.pathname}`);
      return HttpResponse.json({ meta: {} });
    })
  );
  return seen;
}

async function attempt(run: () => Promise<unknown>): Promise<void> {
  try {
    await run();
  } catch {
    // Refusing before the request is the safe outcome. A request that still
    // leaves /api/snapshots is recorded by the catch-all and fails below.
  }
}

function resolvedLine(line: string): string {
  const space = line.indexOf(' ');
  const method = line.slice(0, space);
  const path = line.slice(space + 1);
  // Same URL resolution XMLHttpRequest performs before the request is sent.
  const resolved = new URL(path, window.location.href);
  return `${method} ${resolved.pathname}`;
}

function snapshotPath(path: string): boolean {
  return (
    path.startsWith('/api/snapshots/') ||
    path.startsWith('/api/snapshots-delete/') ||
    path.startsWith(`/apis/dashboard.grafana.app/v0alpha1/namespaces/${config.namespace}/snapshots/`)
  );
}

function assertSnapshotRequests(seen: string[], victimPath: string) {
  const resolved = seen.map(resolvedLine);
  expect(resolved.filter((line) => line.endsWith(`/${victimPath}`))).toEqual([]);
  expect(resolved.filter((line) => !snapshotPath(line.slice(line.indexOf(' ') + 1)))).toEqual([]);
}

describe('snapshot key delete URL', () => {
  beforeAll(() => {
    configureStore();
  });

  beforeEach(() => {
    contextSrv.user.orgId = 1;
    contextSrv.user.isSignedIn = true;
    // index.html sets <base href="{{AppSubUrl}}/">. With the default empty subpath that is
    // "/". The test runtime resolves relative URLs against the document URL, so the
    // document URL is the base URL the browser uses for these requests.
    document.head.querySelectorAll('base').forEach((el) => el.remove());
    const base = document.createElement('base');
    base.href = '/';
    document.head.appendChild(base);
    window.history.pushState({}, '', '/');
    document.cookie = 'grafana_session=placeholder';
    setTestFlags({ [FlagKeys.SnapshotsKubernetesSnapshots]: false });
  });

  afterEach(() => {
    setTestFlags({});
  });

  describe('legacy snapshot client', () => {
    it('deletes an alphanumeric key under /api/snapshots', async () => {
      const seen = installCatchAll();

      await getDashboardSnapshotSrv().deleteSnapshot(safeKey);

      expect(seen).toEqual([`DELETE /api/snapshots/${safeKey}`]);
    });

    it.each(victims)('does not DELETE a $label when the key climbs out of /api/snapshots', async ({ path }) => {
      const seen = installCatchAll();

      await attempt(() => getDashboardSnapshotSrv().deleteSnapshot(traversalKey(path, false)));

      assertSnapshotRequests(seen, path);
    });

    it.each(victims)('does not DELETE a $label when the key uses encoded parent segments', async ({ path }) => {
      const seen = installCatchAll();

      await attempt(() => getDashboardSnapshotSrv().deleteSnapshot(traversalKey(path, true)));

      assertSnapshotRequests(seen, path);
    });

    it.each(victims)('does not GET a $label when loading a snapshot by a climbing key', async ({ path }) => {
      const seen = installCatchAll();

      await attempt(() => getDashboardSnapshotSrv().getSnapshot(traversalKey(path, false)));

      assertSnapshotRequests(seen, path);
    });
  });

  describe('kubernetes snapshot client', () => {
    beforeEach(() => {
      setTestFlags({ [FlagKeys.SnapshotsKubernetesSnapshots]: true });
    });

    it('deletes an alphanumeric name on the snapshot resource', async () => {
      const seen = installCatchAll();

      await getDashboardSnapshotSrv().deleteSnapshot(safeKey);

      expect(seen).toEqual([
        `DELETE /apis/dashboard.grafana.app/v0alpha1/namespaces/${config.namespace}/snapshots/${safeKey}`,
      ]);
    });

    it.each(victims)(
      'does not DELETE a $label when the snapshot name climbs out of the snapshots resource',
      async ({ path }) => {
        const seen = installCatchAll();

        await attempt(() => getDashboardSnapshotSrv().deleteSnapshot(traversalKey(path, false)));

        assertSnapshotRequests(seen, path);
      }
    );

    it.each(victims)(
      'does not DELETE a $label when the snapshot name uses encoded parent segments',
      async ({ path }) => {
        const seen = installCatchAll();

        await attempt(() => getDashboardSnapshotSrv().deleteSnapshot(traversalKey(path, true)));

        assertSnapshotRequests(seen, path);
      }
    );
  });

  describe('share drawer', () => {
    function buildTab(): ShareSnapshotTab {
      const scene = new DashboardScene({
        title: 'my dashboard',
        uid: 'dash-1',
        meta: { canEdit: true },
        $timeRange: new SceneTimeRange({}),
        body: DefaultGridLayoutManager.fromVizPanels([]),
      });
      const tab = new ShareSnapshotTab({ dashboardRef: scene.getRef() });
      scene.setState({ overlay: tab });
      return tab;
    }

    it.each(victims)('passes the create response key through to delete without reaching a $label', async ({ path }) => {
      const seen = installCatchAll();
      const tab = buildTab();

      await attempt(() => tab.onSnapshotDelete(traversalKey(path, false)));

      assertSnapshotRequests(seen, path);
    });
  });

  describe('legacy share modal delete URL', () => {
    beforeEach(() => {
      jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    it.each(victims)('does not request a $label when deleteUrl climbs out of snapshots-delete', async ({ path }) => {
      const seen = installCatchAll();
      const modal = new LegacyShareSnapshot({
        dashboard: { title: 'board' } as DashboardModel,
      });
      modal.state = {
        ...modal.state,
        deleteUrl: `${window.location.origin}/api/snapshots-delete/${traversalKey(path, false)}`,
      };

      await attempt(() => modal.deleteSnapshot());

      assertSnapshotRequests(seen, path);
    });
  });
});
