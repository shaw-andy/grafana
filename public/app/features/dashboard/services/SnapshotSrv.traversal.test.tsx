import { render, waitFor } from '@testing-library/react';
import { createMemoryHistory } from 'history';
import { useEffect } from 'react';
// eslint-disable-next-line no-restricted-imports
import { Router } from 'react-router-dom';
import { CompatRouter, Route, Routes, useParams } from 'react-router-dom-v5-compat';

import { config, setBackendSrv } from '@grafana/runtime';
import { backendSrv } from 'app/core/services/backend_srv';

import { getDashboardScenePageStateManager } from '../../dashboard-scene/pages/DashboardScenePageStateManager';

import { DashboardLoaderSrvV2, dashboardLoaderSrv } from './DashboardLoaderSrv';
import { getDashboardSnapshotSrv } from './SnapshotSrv';

const TRAVERSAL_LOGOUT = '../../../logout';
const TRAVERSAL_SWITCH_ORG = '../../../profile/switch-org/2';
const TRAVERSAL_ENCODED_DOTS = '%2e%2e/%2e%2e/%2e%2e/logout';
const TRAVERSAL_BACKSLASH = '..\\..\\..\\logout';
const SAFE_KEY = 'key-a';

interface CapturedRequest {
  raw: string;
  pathname: string;
  method: string;
  credentials: RequestCredentials;
}

function installBaseHref() {
  document.head.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.href = '/';
  document.head.appendChild(base);
}

function installFetchRecorder() {
  const calls: CapturedRequest[] = [];
  const spy = jest.spyOn(window, 'fetch').mockImplementation(async (input, init) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const resolved = new URL(raw, document.baseURI);
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const credentials = init?.credentials ?? (input instanceof Request ? input.credentials : 'same-origin');
    calls.push({ raw, pathname: resolved.pathname, method, credentials });
    return new Response(
      JSON.stringify({
        dashboard: { uid: 'snap', title: 'Snapshot', schemaVersion: 39, panels: [] },
        meta: { isSnapshot: true },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  });

  return {
    calls,
    restore() {
      spy.mockRestore();
    },
  };
}

const UNSAFE_KEYS = [TRAVERSAL_LOGOUT, TRAVERSAL_SWITCH_ORG, TRAVERSAL_ENCODED_DOTS, TRAVERSAL_BACKSLASH];

function snapshotRequests(calls: CapturedRequest[]) {
  return calls.filter(
    (call) =>
      call.raw.includes('snapshot') ||
      call.pathname === '/logout' ||
      call.pathname.startsWith('/profile/') ||
      call.raw.includes('logout') ||
      call.raw.includes('switch-org')
  );
}

describe('snapshot key path traversal', () => {
  beforeEach(() => {
    installBaseHref();
    setBackendSrv(backendSrv);
  });

  describe('legacy snapshot client', () => {
    it.each(UNSAFE_KEYS)('rejects %j before a credentialed request leaves /api/snapshots', async (key) => {
      const recorder = installFetchRecorder();
      try {
        const snapshotSrv = getDashboardSnapshotSrv();
        const getResult = snapshotSrv.getSnapshot(key).then(
          () => 'resolved',
          () => 'rejected'
        );
        const deleteResult = snapshotSrv.deleteSnapshot(key).then(
          () => 'resolved',
          () => 'rejected'
        );
        await Promise.allSettled([getResult, deleteResult]);
        expect(snapshotRequests(recorder.calls)).toEqual([]);
        expect(await getResult).toBe('rejected');
        expect(await deleteResult).toBe('rejected');
      } finally {
        recorder.restore();
      }
    });

    it('still loads a single-segment snapshot key with the session credential', async () => {
      const recorder = installFetchRecorder();

      const dto = await getDashboardSnapshotSrv().getSnapshot(SAFE_KEY);

      expect(dto.meta.canShare).toBe(false);
      expect(snapshotRequests(recorder.calls)).toEqual([
        {
          raw: 'api/snapshots/key-a',
          pathname: '/api/snapshots/key-a',
          method: 'GET',
          credentials: 'same-origin',
        },
      ]);
      recorder.restore();
    });

    it('still deletes a single-segment snapshot key with the session credential', async () => {
      const recorder = installFetchRecorder();

      await getDashboardSnapshotSrv().deleteSnapshot(SAFE_KEY);

      expect(snapshotRequests(recorder.calls)).toEqual([
        {
          raw: 'api/snapshots/key-a',
          pathname: '/api/snapshots/key-a',
          method: 'DELETE',
          credentials: 'same-origin',
        },
      ]);
      recorder.restore();
    });
  });

  describe('dashboard loaders', () => {
    it('does not let the v1 snapshot loader request /logout', async () => {
      const recorder = installFetchRecorder();

      const loaded = dashboardLoaderSrv.loadDashboard('snapshot', TRAVERSAL_LOGOUT, undefined).then(
        () => 'resolved',
        () => 'rejected'
      );
      const snapshotted = dashboardLoaderSrv.loadSnapshot(TRAVERSAL_SWITCH_ORG).then(
        () => 'resolved',
        () => 'rejected'
      );
      await Promise.allSettled([loaded, snapshotted]);
      expect(snapshotRequests(recorder.calls)).toEqual([]);
      expect(await loaded).toBe('rejected');
      expect(await snapshotted).toBe('rejected');
      recorder.restore();
    });

    it('does not let the v2 snapshot loader request /profile/switch-org', async () => {
      const recorder = installFetchRecorder();
      const loader = new DashboardLoaderSrvV2();

      const snapshotted = loader.loadSnapshot(TRAVERSAL_SWITCH_ORG).then(
        () => 'resolved',
        () => 'rejected'
      );
      await snapshotted.catch(() => undefined);
      expect(snapshotRequests(recorder.calls)).toEqual([]);
      expect(await snapshotted).toBe('rejected');
      recorder.restore();
    });

    it('does not request /logout when the v2 dashboard loader is given a snapshot slug and no uid', async () => {
      const recorder = installFetchRecorder();
      const loader = new DashboardLoaderSrvV2();
      try {
        await expect(
          Promise.resolve().then(() => loader.loadDashboard('snapshot', TRAVERSAL_LOGOUT, ''))
        ).rejects.toBeTruthy();
        expect(snapshotRequests(recorder.calls)).toEqual([]);
      } finally {
        recorder.restore();
      }
    });
  });

  describe('public snapshot route', () => {
    it('does not follow a snapshot link whose key decodes to a parent-directory path', async () => {
      config.featureToggles.dashboardNewLayouts = true;
      const recorder = installFetchRecorder();
      const seen: { slug?: string; settled?: Promise<unknown> } = {};

      function SnapshotPageProbe() {
        const { type, slug } = useParams();

        useEffect(() => {
          seen.slug = slug;
          if (type === 'snapshot' && slug) {
            seen.settled = getDashboardScenePageStateManager().loadSnapshot(slug);
          }
        }, [type, slug]);

        return null;
      }

      const history = createMemoryHistory({
        initialEntries: ['/dashboard/snapshot/..%2F..%2F..%2Flogout'],
      });

      const { unmount } = render(
        <Router history={history}>
          <CompatRouter>
            <Routes>
              <Route path="/dashboard/:type/:slug" element={<SnapshotPageProbe />} />
            </Routes>
          </CompatRouter>
        </Router>
      );

      try {
        await waitFor(() => {
          expect(seen.slug).toBe(TRAVERSAL_LOGOUT);
        });
        await seen.settled;
        expect(snapshotRequests(recorder.calls)).toEqual([]);
      } finally {
        unmount();
        recorder.restore();
      }
    });

    it('does not follow a dashboard-solo snapshot link through the v1 loader', async () => {
      config.featureToggles.dashboardNewLayouts = false;
      const recorder = installFetchRecorder();
      const seen: { slug?: string; settled?: Promise<unknown> } = {};

      function SoloSnapshotProbe() {
        const { type, slug } = useParams();

        useEffect(() => {
          seen.slug = slug;
          if (type === 'snapshot' && slug) {
            seen.settled = dashboardLoaderSrv.loadDashboard(type, slug, undefined);
          }
        }, [type, slug]);

        return null;
      }

      const history = createMemoryHistory({
        initialEntries: ['/dashboard-solo/snapshot/..%2F..%2F..%2Flogout'],
      });

      const { unmount } = render(
        <Router history={history}>
          <CompatRouter>
            <Routes>
              <Route path="/dashboard-solo/:type/:slug" element={<SoloSnapshotProbe />} />
            </Routes>
          </CompatRouter>
        </Router>
      );

      try {
        await waitFor(() => {
          expect(seen.slug).toBe(TRAVERSAL_LOGOUT);
        });
        await seen.settled;
        expect(snapshotRequests(recorder.calls)).toEqual([]);
        await expect(seen.settled).rejects.toBeTruthy();
      } finally {
        unmount();
        recorder.restore();
      }
    });
  });
});
