import { configureStore } from '@reduxjs/toolkit';
import { render, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { fromFetch } from 'rxjs/fetch';

import { setBackendSrv } from '@grafana/runtime';
import { BackendSrv } from 'app/core/services/backend_srv';
import { fetchProvisionedDashboards } from 'app/features/dashboard/dashgrid/DashboardLibrary/api/dashboardLibraryApi';
import { loadPluginDashboards } from 'app/features/plugins/admin/state/actions';
import { reducer as pluginsReducer } from 'app/features/plugins/admin/state/reducer';
import { RequestStatus } from 'app/features/plugins/admin/types';

import { DataSourceDashboards } from './components/DataSourceDashboards';
import dataSourcesReducers from './state/reducers';

const LOGOUT_TYPE = 'x/../../../logout#';
const SWITCH_ORG_TYPE = 'x/../../../profile/switch-org/2#';

interface RecordedRequest {
  pathname: string;
  credentials: RequestCredentials | undefined;
}

function installBaseHref() {
  document.head.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.href = '/';
  document.head.appendChild(base);
}

function requestTarget(input: RequestInfo | URL): RecordedRequest & { raw: string } {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
  return {
    raw,
    pathname: new URL(raw, document.baseURI).pathname,
    credentials: undefined,
  };
}

function installFetchRecorder() {
  const recorded: RecordedRequest[] = [];
  const fetchMock = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const target = requestTarget(input);
    recorded.push({ pathname: target.pathname, credentials: init?.credentials });
    const body = '[]';
    return new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  window.fetch = fetchMock as typeof window.fetch;
  return recorded;
}

function useBackend() {
  setBackendSrv(
    new BackendSrv({
      fromFetch,
      appEvents: { publish: () => undefined, emit: () => undefined } as never,
      contextSrv: { user: { orgId: 1, isSignedIn: true } } as never,
      logout: () => undefined,
    })
  );
}

function outsideApi(recorded: RecordedRequest[]) {
  return recorded.filter((call) => !call.pathname.startsWith('/api/'));
}

describe('datasource type plugin dashboard requests', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  beforeEach(() => {
    installBaseHref();
    useBackend();
    // Same resolution Chrome applies to a relative fetch against <base href="/">.
    expect(document.baseURI).toBe('http://localhost/');
    expect(new URL(`api/plugins/${LOGOUT_TYPE}/dashboards`, document.baseURI).pathname).toBe('/logout');
    expect(new URL(`api/plugins/${SWITCH_ORG_TYPE}/dashboards`, document.baseURI).pathname).toBe(
      '/profile/switch-org/2'
    );
  });

  it('resolves a normal plugin id under /api/plugins with the session credentials', async () => {
    const recorded = installFetchRecorder();

    const store = configureStore({
      reducer: (state = { dataSources: { dataSource: { id: 7, type: 'prometheus' } } }) => state,
    });
    await store.dispatch(loadPluginDashboards());

    expect(recorded).toEqual([{ pathname: '/api/plugins/prometheus/dashboards', credentials: 'same-origin' }]);
  });

  it.each([
    ['logout', LOGOUT_TYPE],
    ['organization switch', SWITCH_ORG_TYPE],
  ])('loadPluginDashboards does not request %s for a stored datasource type', async (_label, dsType) => {
    const recorded = installFetchRecorder();
    const store = configureStore({
      reducer: (state = { dataSources: { dataSource: { id: 7, type: dsType } } }) => state,
    });

    await store.dispatch(loadPluginDashboards());

    expect(outsideApi(recorded)).toEqual([]);
  });

  it.each([
    ['logout', LOGOUT_TYPE],
    ['organization switch', SWITCH_ORG_TYPE],
  ])('fetchProvisionedDashboards does not request %s for a datasource type', async (_label, dsType) => {
    const recorded = installFetchRecorder();

    await fetchProvisionedDashboards(dsType);

    expect(outsideApi(recorded)).toEqual([]);
  });

  it.each([
    ['logout', LOGOUT_TYPE, '/logout'],
    ['organization switch', SWITCH_ORG_TYPE, '/profile/switch-org/2'],
  ])('opening the datasource dashboards tab does not request %s', async (_label, dsType, forbiddenPath) => {
    const recorded: RecordedRequest[] = [];
    window.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const target = requestTarget(input);
      recorded.push({ pathname: target.pathname, credentials: init?.credentials });
      const body = target.pathname.startsWith('/api/datasources/uid/')
        ? JSON.stringify({ id: 7, uid: 'dsuid', name: 'opened-by-viewer', type: dsType, access: 'proxy' })
        : '[]';
      return new Response(body, {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof window.fetch;

    const store = configureStore({
      reducer: {
        ...dataSourcesReducers,
        plugins: pluginsReducer,
      },
      middleware: (getDefaultMiddleware) => getDefaultMiddleware({ serializableCheck: false, immutableCheck: false }),
    });
    // Plugin settings already rejects this type via validatePath and logs that rejection.
    // The dashboards request under test does not.
    jest.spyOn(console, 'error').mockImplementation(() => undefined);

    render(
      <Provider store={store}>
        <DataSourceDashboards uid="dsuid" />
      </Provider>
    );

    await waitFor(() => {
      const status = store.getState().plugins.requests['plugins/loadPluginDashboards']?.status;
      expect(status === RequestStatus.Fulfilled || status === RequestStatus.Rejected).toBe(true);
    });

    expect(recorded.map((call) => call.pathname)).not.toContain(forbiddenPath);
    expect(outsideApi(recorded)).toEqual([]);
  });
});
