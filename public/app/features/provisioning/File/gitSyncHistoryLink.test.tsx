import { waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom-v5-compat';
import { render } from 'test/test-utils';

import { config, setBackendSrv } from '@grafana/runtime';
import { getRouteComponentProps } from 'app/core/navigation/mocks/routeProps';
import { BackendSrv } from 'app/core/services/backend_srv';
import { DashboardScenePage } from 'app/features/dashboard-scene/pages/DashboardScenePage';
import { DashboardRoutes } from 'app/types/dashboard';

import { PROVISIONING_PREVIEW_URL, PROVISIONING_URL } from '../constants';

import FileHistoryPage from './FileHistoryPage';
import FileStatusPage from './FileStatusPage';

/**
 * Segments the generated provisioning client places before the caller-supplied
 * repository path: apis, group, version, namespaces, namespace, repositories,
 * name, and the resource (history or files). A single-segment namespace is the
 * value GrafanaConfig ships with.
 */
const API_SEGMENTS_BEFORE_FILE_PATH = 8;

interface CapturedRequest {
  rawUrl: string;
  method: string;
  credentials: RequestCredentials | undefined;
  resolvedPath: string;
}

/**
 * The address bar keeps `%252e%252e` as its own path segments. A single
 * `%2e%2e` is removed by the URL parser before the document loads, so that
 * form never reaches the page.
 */
function browserEntry(absolutePathAndQuery: string): string {
  const url = new URL(absolutePathAndQuery, 'http://grafana.example');
  return `${url.pathname}${url.search}`;
}

function doubleEncodedParents(count: number): string {
  return Array.from({ length: count }, () => '%252e%252e').join('/');
}

function historyLink(tail: string, repoType: string): string {
  return browserEntry(
    `${PROVISIONING_URL}/repo/history/${doubleEncodedParents(API_SEGMENTS_BEFORE_FILE_PATH)}/${tail}?repo_type=${repoType}`
  );
}

function fileLink(tail: string): string {
  return browserEntry(
    `${PROVISIONING_URL}/repo/file/${doubleEncodedParents(API_SEGMENTS_BEFORE_FILE_PATH)}/${tail}`
  );
}

function previewLink(tail: string): string {
  return browserEntry(
    `${PROVISIONING_PREVIEW_URL}/repo/preview/${doubleEncodedParents(API_SEGMENTS_BEFORE_FILE_PATH)}/${tail}`
  );
}

describe('Git Sync links that copy the address into a provisioning path', () => {
  let captured: CapturedRequest[];
  const originalFetch = window.fetch;

  beforeEach(() => {
    config.provisioningEnabled = true;
    config.namespace = 'default';
    document.head.querySelectorAll('base').forEach((node) => node.remove());
    const base = document.createElement('base');
    base.setAttribute('href', '/');
    document.head.appendChild(base);

    captured = [];
    // Startup is what normally publishes the backend client. Tests have to do
    // that explicitly; the client itself is the production BackendSrv.
    setBackendSrv(new BackendSrv());
    window.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      captured.push({
        rawUrl,
        method: (init?.method ?? 'GET').toUpperCase(),
        credentials: init?.credentials,
        resolvedPath: new URL(rawUrl, document.baseURI).pathname,
      });
      return new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
  });

  afterEach(() => {
    window.fetch = originalFetch;
  });

  async function settleRequests() {
    await waitFor(() => {
      expect(captured.length).toBeGreaterThan(0);
    });
    await waitFor(async () => {
      const seen = captured.length;
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(captured.length).toBe(seen);
    });
  }

  function resolvedPaths(): string[] {
    return captured.map((call) => call.resolvedPath);
  }

  it.each(['github', 'githubEnterprise', 'gitlab', 'bitbucket'])(
    'does not let a %s history link request logout',
    async (repoType) => {
      render(
        <Routes>
          <Route path={`${PROVISIONING_URL}/:name/history/*`} element={<FileHistoryPage />} />
        </Routes>,
        { historyOptions: { initialEntries: [historyLink('logout', repoType)] } }
      );

      await settleRequests();

      expect(resolvedPaths()).not.toContain('/logout');
    }
  );

  it.each(['github', 'gitlab'])(
    'does not let a %s history link request the organization switch page',
    async (repoType) => {
      render(
        <Routes>
          <Route path={`${PROVISIONING_URL}/:name/history/*`} element={<FileHistoryPage />} />
        </Routes>,
        { historyOptions: { initialEntries: [historyLink('profile/switch-org/2', repoType)] } }
      );

      await settleRequests();

      expect(resolvedPaths().some((path) => path.startsWith('/profile/switch-org/'))).toBe(false);
    }
  );

  it('keeps a normal file path inside the history API', async () => {
    render(
      <Routes>
        <Route path={`${PROVISIONING_URL}/:name/history/*`} element={<FileHistoryPage />} />
      </Routes>,
      {
        historyOptions: {
          initialEntries: [browserEntry(`${PROVISIONING_URL}/repo/history/folder/file.json?repo_type=github`)],
        },
      }
    );

    await settleRequests();

    expect(resolvedPaths()).toContain(
      '/apis/provisioning.grafana.app/v0alpha1/namespaces/default/repositories/repo/history/folder/file.json'
    );
    const historyCall = captured.find((call) => call.resolvedPath.endsWith('/history/folder/file.json'));
    expect(historyCall?.method).toBe('GET');
    expect(historyCall?.credentials).toBe('same-origin');
  });

  it('does not let a file link request logout', async () => {
    render(
      <Routes>
        <Route path={`${PROVISIONING_URL}/:name/file/*`} element={<FileStatusPage />} />
      </Routes>,
      { historyOptions: { initialEntries: [fileLink('logout')] } }
    );

    await settleRequests();

    expect(resolvedPaths()).not.toContain('/logout');
  });

  it('does not let a file link request the organization switch page', async () => {
    render(
      <Routes>
        <Route path={`${PROVISIONING_URL}/:name/file/*`} element={<FileStatusPage />} />
      </Routes>,
      { historyOptions: { initialEntries: [fileLink('profile/switch-org/2')] } }
    );

    await settleRequests();

    expect(resolvedPaths().some((path) => path.startsWith('/profile/switch-org/'))).toBe(false);
  });

  it('keeps a normal file path inside the files API', async () => {
    render(
      <Routes>
        <Route path={`${PROVISIONING_URL}/:name/file/*`} element={<FileStatusPage />} />
      </Routes>,
      { historyOptions: { initialEntries: [browserEntry(`${PROVISIONING_URL}/repo/file/folder/file.json`)] } }
    );

    await settleRequests();

    expect(resolvedPaths()).toContain(
      '/apis/provisioning.grafana.app/v0alpha1/namespaces/default/repositories/repo/files/folder/file.json'
    );
  });

  it('does not let a provisioning preview link request logout', async () => {
    const routeProps = getRouteComponentProps({
      route: {
        path: `${PROVISIONING_PREVIEW_URL}/:slug/preview/*`,
        component: () => null,
        routeName: DashboardRoutes.Provisioning,
      },
      queryParams: {},
    });

    render(
      <Routes>
        <Route path={`${PROVISIONING_PREVIEW_URL}/:slug/preview/*`} element={<DashboardScenePage {...routeProps} />} />
      </Routes>,
      { historyOptions: { initialEntries: [previewLink('logout')] } }
    );

    await settleRequests();

    expect(resolvedPaths()).not.toContain('/logout');
  });
});
