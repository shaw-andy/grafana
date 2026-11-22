import { renderHook, waitFor } from '@testing-library/react';
import { type PropsWithChildren } from 'react';
import { Provider } from 'react-redux';
import { fromFetch } from 'rxjs/fetch';

import { type DataSourceInstanceSettings } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';
import { BackendSrv } from 'app/core/services/backend_srv';
import { type ContextSrv } from 'app/core/services/context_srv';
import { AlertManagerDatasource } from 'app/plugins/datasource/alertmanager/DataSource';
import { type AlertManagerDataSourceJsonData } from 'app/plugins/datasource/alertmanager/types';
import { configureStore } from 'app/store/configureStore';
import { AccessControlAction } from 'app/types/accessControl';

import { useRulesSourcesWithRuler } from '../hooks/useRuleSourcesWithRuler';
import { grantUserPermissions, mockDataSource } from '../mocks';
import { setupDataSources } from '../testSetup/datasources';

import { discoverAlertmanagerFeatures, discoverFeaturesByUid } from './buildInfo';
import { featureDiscoveryApi } from './featureDiscoveryApi';

const LOGOUT_PATH = '/user/auth-tokens/rotate?redirectTo=/logout#';
const ORG_SWITCH_PATH = '/user/auth-tokens/rotate?redirectTo=/profile/switch-org/2#';

interface SeenRequest {
  pathname: string;
  redirectTo: string | null;
  redirectMode: RequestRedirect | undefined;
  credentials: RequestCredentials | undefined;
}

const seen: SeenRequest[] = [];

function installFetchRecorder() {
  const fetchImpl: typeof fetch = async (input, init) => {
    let rawUrl = '';
    if (typeof input === 'string') {
      rawUrl = input;
    } else if (input instanceof URL) {
      rawUrl = input.toString();
    } else {
      rawUrl = input.url;
    }
    const resolved = new URL(rawUrl, document.baseURI);
    seen.push({
      pathname: resolved.pathname,
      redirectTo: resolved.searchParams.get('redirectTo'),
      redirectMode: init?.redirect,
      credentials: init?.credentials,
    });
    return new Response(JSON.stringify({ status: 'success', data: { version: '2.45.0' } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  window.fetch = fetchImpl;
  globalThis.fetch = fetchImpl;
}

function useRealBackend() {
  const backendSrv = new BackendSrv({
    fromFetch,
    contextSrv: { user: { orgId: 1, isSignedIn: true } } as ContextSrv,
    logout: () => undefined,
  });
  setBackendSrv(backendSrv);
}

function sessionRoutes(requests: SeenRequest[]) {
  return requests.filter(
    (request) =>
      request.pathname.includes('/user/auth-tokens/rotate') ||
      request.pathname === '/logout' ||
      request.pathname.startsWith('/profile/switch-org/') ||
      request.redirectTo === '/logout' ||
      (request.redirectTo ?? '').startsWith('/profile/switch-org/')
  );
}

function expectNoSessionRoute(requests: SeenRequest[]) {
  expect(sessionRoutes(requests)).toEqual([]);
}

function expectBuildInfoStaysOnProxyAndDoesNotFollowRedirects(requests: SeenRequest[]) {
  const buildInfo = requests.filter((request) => request.pathname.endsWith('/api/v1/status/buildinfo'));
  for (const request of buildInfo) {
    expect(request.pathname.startsWith('/api/datasources/proxy/')).toBe(true);
    expect(request.redirectMode === 'manual' || request.redirectMode === 'error').toBe(true);
  }
}

function directSource(
  partial: Partial<DataSourceInstanceSettings<AlertManagerDataSourceJsonData>>
): DataSourceInstanceSettings<AlertManagerDataSourceJsonData> {
  return mockDataSource<AlertManagerDataSourceJsonData>({
    access: 'direct',
    jsonData: {},
    ...partial,
  });
}

function StoreProvider({ children }: PropsWithChildren) {
  return <Provider store={configureStore()}>{children}</Provider>;
}

beforeEach(() => {
  seen.length = 0;
  // document.baseURI is what the browser resolves the stored path against; Testing Library has no setter for it.
  // eslint-disable-next-line testing-library/no-node-access
  for (const node of Array.from(document.getElementsByTagName('base'))) {
    node.remove();
  }
  const base = document.createElement('base');
  base.href = '/';
  document.head.appendChild(base);
  config.appSubUrl = '';
  config.defaultDatasourceManageAlertsUiToggle = true;
  grantUserPermissions([AccessControlAction.AlertingRuleExternalRead]);
  installFetchRecorder();
  useRealBackend();
});

describe('alert feature discovery session redirect', () => {
  it.each([
    ['path', 'prometheus', 'prom-direct', LOGOUT_PATH, false],
    ['path', 'grafana-amazonprometheus-datasource', 'amazon-direct', LOGOUT_PATH, false],
    ['path', 'grafana-azureprometheus-datasource', 'azure-direct', LOGOUT_PATH, false],
    ['path', 'prometheus', 'prom-org', ORG_SWITCH_PATH, false],
    ['same-origin absolute', 'prometheus', 'prom-abs', LOGOUT_PATH, true],
    ['same-origin absolute', 'alertmanager', 'am-abs', ORG_SWITCH_PATH, true],
  ])(
    'does not request session rotation for a %s browser-access %s data source',
    async (_shape, type, uid, storedUrl, absolute) => {
      const url = absolute ? `${new URL(document.baseURI).origin}${storedUrl}` : storedUrl;
      setupDataSources(directSource({ uid, name: uid, type, url }));

      if (type === 'alertmanager') {
        await discoverAlertmanagerFeatures(uid).catch(() => undefined);
      } else {
        await discoverFeaturesByUid(uid).catch(() => undefined);
      }

      expectNoSessionRoute(seen);
      expectBuildInfoStaysOnProxyAndDoesNotFollowRedirects(seen);
    }
  );

  it('does not request the stored browser URL while discovering Loki rules', async () => {
    setupDataSources(directSource({ uid: 'loki-direct', name: 'loki-direct', type: 'loki', url: LOGOUT_PATH }));

    await discoverFeaturesByUid('loki-direct').catch(() => undefined);

    expectNoSessionRoute(seen);
  });

  it('does not request session rotation while discovering an external Alertmanager', async () => {
    setupDataSources(
      directSource({
        uid: 'am-direct',
        name: 'External AM',
        type: 'alertmanager',
        url: LOGOUT_PATH,
      })
    );

    await discoverAlertmanagerFeatures('External AM');

    expectNoSessionRoute(seen);
    expectBuildInfoStaysOnProxyAndDoesNotFollowRedirects(seen);
  });

  it('does not request session rotation from the Alertmanager data source health check', async () => {
    const settings = directSource({
      uid: 'am-health',
      name: 'External AM health',
      type: 'alertmanager',
      url: ORG_SWITCH_PATH,
    });
    setupDataSources(settings);

    await new AlertManagerDatasource(settings).testDatasource();

    expectNoSessionRoute(seen);
    expectBuildInfoStaysOnProxyAndDoesNotFollowRedirects(seen);
  });

  it('does not follow redirects for proxy buildinfo', async () => {
    setupDataSources(
      mockDataSource({
        uid: 'prom-proxy',
        name: 'prom-proxy',
        type: 'prometheus',
        access: 'proxy',
        url: '/api/datasources/proxy/uid/prom-proxy',
        jsonData: { manageAlerts: true },
      })
    );

    await discoverFeaturesByUid('prom-proxy');

    expectNoSessionRoute(seen);
    expect(seen.some((request) => request.pathname === '/api/datasources/proxy/uid/prom-proxy/api/v1/status/buildinfo')).toBe(
      true
    );
    expectBuildInfoStaysOnProxyAndDoesNotFollowRedirects(seen);
  });

  it('does not request session rotation when a viewer opens alert rules', async () => {
    setupDataSources(
      directSource({
        uid: 'rules-prom',
        name: 'Rules Prom',
        type: 'prometheus',
        url: LOGOUT_PATH,
      })
    );

    const { result } = renderHook(() => useRulesSourcesWithRuler(), { wrapper: StoreProvider });
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expectNoSessionRoute(seen);
    expectBuildInfoStaysOnProxyAndDoesNotFollowRedirects(seen);
  });

  it('does not request session rotation when silences discover the external Alertmanager', async () => {
    setupDataSources(
      directSource({
        uid: 'silences-am',
        name: 'Silences AM',
        type: 'alertmanager',
        url: ORG_SWITCH_PATH,
      })
    );

    const { result } = renderHook(
      () => featureDiscoveryApi.useDiscoverAmFeaturesQuery({ amSourceName: 'Silences AM' }),
      { wrapper: StoreProvider }
    );

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expectNoSessionRoute(seen);
    expectBuildInfoStaysOnProxyAndDoesNotFollowRedirects(seen);
  });
});
