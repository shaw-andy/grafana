import { InMemoryProvider, OpenFeature } from '@openfeature/web-sdk';
import { lastValueFrom } from 'rxjs';
import { fromFetch } from 'rxjs/fetch';

import { type DataQueryRequest, type DataSourceInstanceSettings } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';

import { BackendSrv } from 'app/core/services/backend_srv';
import { type ContextSrv } from 'app/core/services/context_srv';
import { getTemplateSrv } from 'app/features/templating/template_srv';
import { AzureQueryType } from 'app/plugins/datasource/azuremonitor/dataquery.gen';
import Datasource from 'app/plugins/datasource/azuremonitor/datasource';
import { type AzureMonitorQuery } from 'app/plugins/datasource/azuremonitor/types/query';
import { type AzureMonitorDataSourceJsonData } from 'app/plugins/datasource/azuremonitor/types/types';

const datasourceUid = 'azure-ds';

// Seven parent segments separate a relative datasource resource URL from the
// application root once the leading slash has been removed and the document
// base URL has been applied: api, datasources, uid, <uid>, resources,
// azuremonitor, subscriptions.
const parentSegments = '../'.repeat(7);
const logoutSubscription = `${parentSegments}logout?`;
const switchOrgSubscription = `${parentSegments}profile/switch-org/2?`;
const logoutFragmentSubscription = `${parentSegments}logout#`;
const benignSubscription = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

interface CapturedRequest {
  pathname: string;
  search: string;
  method: string;
  credentials: RequestCredentials | undefined;
}

function setDocumentBase(href: string) {
  document.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.href = href;
  document.head.appendChild(base);
}

function installBackend() {
  const captured: CapturedRequest[] = [];
  const originalFetch = global.fetch;
  global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    // Same URL parser fetch uses for a relative request against the document base.
    const resolved = new URL(raw, document.baseURI);
    captured.push({
      pathname: resolved.pathname,
      search: resolved.search,
      method: (init?.method ?? 'GET').toUpperCase(),
      credentials: init?.credentials,
    });
    return new Response(JSON.stringify({ value: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  setBackendSrv(
    new BackendSrv({
      fromFetch,
      contextSrv: { user: { orgId: 1, isSignedIn: true } } as ContextSrv,
      logout: () => undefined,
    })
  );

  return {
    captured,
    restore() {
      global.fetch = originalFetch;
    },
  };
}

function createDatasource() {
  return new Datasource({
    id: 1,
    uid: datasourceUid,
    type: 'grafana-azure-monitor-datasource',
    name: 'Azure',
    access: 'proxy',
    jsonData: {},
    meta: { id: 'grafana-azure-monitor-datasource' },
  } as DataSourceInstanceSettings<AzureMonitorDataSourceJsonData>);
}

function resourcePrefix(basePath = '') {
  return `${basePath}/api/datasources/uid/${datasourceUid}/resources/`;
}

function assertRequestsStayOnDatasourceResources(captured: CapturedRequest[], prefix: string) {
  for (const request of captured) {
    expect(request.method).toBe('GET');
    expect(request.credentials).toBe('same-origin');
    expect(request.pathname).toEqual(expect.stringMatching(new RegExp(`^${escapeRegExp(prefix)}`)));
  }
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function runVariableQuery(ds: Datasource, query: AzureMonitorQuery) {
  const request = { targets: [query] } as DataQueryRequest<AzureMonitorQuery>;
  await lastValueFrom(ds.variables.query(request));
}

describe('Azure Monitor datasource resource paths', () => {
  let captured: CapturedRequest[];
  let restore: () => void;
  let ds: Datasource;

  beforeEach(() => {
    delete window.__grafanaSceneContext;
    setDocumentBase('/');
    getTemplateSrv().init([]);
    ({ captured, restore } = installBackend());
    ds = createDatasource();
  });

  afterEach(async () => {
    restore();
    await OpenFeature.clearProviders();
  });

  it('loads locations for a subscription id under the datasource resource route', async () => {
    await runVariableQuery(ds, {
      refId: 'A',
      queryType: AzureQueryType.LocationsQuery,
      subscription: benignSubscription,
    });

    expect(captured).toEqual([
      {
        pathname: `/api/datasources/uid/${datasourceUid}/resources/azuremonitor/subscriptions/${benignSubscription}/locations`,
        search: '?api-version=2020-01-01',
        method: 'GET',
        credentials: 'same-origin',
      },
    ]);
  });

  it.each([
    ['literal logout subscription', logoutSubscription],
    ['literal organization switch subscription', switchOrgSubscription],
    ['literal logout fragment subscription', logoutFragmentSubscription],
  ])('keeps a locations variable with a %s on the datasource resource route', async (_label, subscription) => {
    await runVariableQuery(ds, {
      refId: 'A',
      queryType: AzureQueryType.LocationsQuery,
      subscription,
    });

    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });

  it('keeps a locations variable whose subscription is another variable on the datasource resource route', async () => {
    getTemplateSrv().init([
      {
        name: 'sub',
        type: 'custom',
        current: { value: logoutSubscription, text: logoutSubscription, selected: true },
      },
    ]);
    ds = createDatasource();

    await runVariableQuery(ds, {
      refId: 'A',
      queryType: AzureQueryType.LocationsQuery,
      subscription: '$sub',
    });

    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });

  it('keeps a locations variable on the datasource resource route when the application is served from a subpath', async () => {
    setDocumentBase('/grafana/');
    expect(document.baseURI).toBe('http://localhost/grafana/');
    ds = createDatasource();

    await runVariableQuery(ds, {
      refId: 'A',
      queryType: AzureQueryType.LocationsQuery,
      subscription: logoutSubscription,
    });

    assertRequestsStayOnDatasourceResources(captured, resourcePrefix('/grafana'));
  });

  it.each([
    [
      'workspaces',
      {
        refId: 'A',
        queryType: AzureQueryType.WorkspacesQuery,
        subscription: logoutSubscription,
      },
    ],
    [
      'metric names',
      {
        refId: 'A',
        queryType: AzureQueryType.MetricNamesQuery,
        subscription: switchOrgSubscription,
        resourceGroup: 'rg',
        namespace: 'microsoft.compute/virtualmachines',
        resource: 'vm',
      },
    ],
    [
      'custom namespaces',
      {
        refId: 'A',
        queryType: AzureQueryType.CustomNamespacesQuery,
        subscription: logoutSubscription,
        resourceGroup: 'rg',
        namespace: 'microsoft.compute/virtualmachines',
        resource: 'vm',
      },
    ],
    [
      'custom metric names',
      {
        refId: 'A',
        queryType: AzureQueryType.CustomMetricNamesQuery,
        subscription: logoutFragmentSubscription,
        resourceGroup: 'rg',
        namespace: 'microsoft.compute/virtualmachines',
        resource: 'vm',
        customNamespace: 'custom',
      },
    ],
  ])('keeps a %s variable on the datasource resource route', async (_label, query) => {
    await runVariableQuery(ds, query);
    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });

  it('keeps a legacy workspaces() variable on the datasource resource route', async () => {
    await runVariableQuery(ds, `workspaces("${logoutSubscription}")` as unknown as AzureMonitorQuery);
    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });

  it('keeps a direct locations resource read on the datasource resource route', async () => {
    await ds.azureMonitorDatasource.getResource(
      `azuremonitor/subscriptions/${logoutSubscription}/locations?api-version=2020-01-01`
    );
    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });

  it('keeps a log analytics workspace lookup on the datasource resource route', async () => {
    await ds.azureLogAnalyticsDatasource.getWorkspaces(switchOrgSubscription);
    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });

  it('keeps a workspace metadata lookup on the datasource resource route', async () => {
    await ds.azureLogAnalyticsDatasource.getKustoSchema(`/${parentSegments}logout?`);
    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });

  it('keeps metric metadata and provider lookups on the datasource resource route', async () => {
    try {
      await ds.azureMonitorDatasource.getMetricMetadata({
        subscription: logoutSubscription,
        resourceGroup: 'rg',
        metricNamespace: 'microsoft.compute/virtualmachines',
        resourceName: 'vm',
        metricName: 'Percentage CPU',
      });
    } catch {
      // Response parsing runs after the resource request is issued.
    }
    try {
      await ds.azureMonitorDatasource.getProvider(`${parentSegments}logout?`);
    } catch {
      // Response parsing runs after the resource request is issued.
    }
    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });

  it('keeps a locations lookup on the datasource resource route when resources are served from the apis route', async () => {
    await OpenFeature.setProviderAndWait(
      'internal-grafana-core',
      new InMemoryProvider({
        'datasources.apiserver.useNewAPIsForDatasourceResources': {
          variants: { on: true, off: false },
          defaultVariant: 'on',
          disabled: false,
        },
      })
    );
    ds = createDatasource();

    await runVariableQuery(ds, {
      refId: 'A',
      queryType: AzureQueryType.LocationsQuery,
      subscription: `${'../'.repeat(10)}logout?`,
    });

    const namespace = config.namespace;
    assertRequestsStayOnDatasourceResources(
      captured,
      `/apis/grafana-azure-monitor-datasource.datasource.grafana.app/v0alpha1/namespaces/${namespace}/datasources/${datasourceUid}/resources/`
    );
  });

  it('keeps a workspace table plan lookup on the datasource resource route', async () => {
    // The lookup returns before building a URL unless the resource identifies a Log Analytics workspace.
    const workspaceUri = `/subscriptions/abc/resourceGroups/rg/providers/microsoft.operationalinsights/workspaces/${'../'.repeat(13)}logout?`;
    try {
      await ds.azureMonitorDatasource.getWorkspaceTablePlan([workspaceUri], 'Heartbeat');
    } catch {
      // Response parsing runs after the resource request is issued.
    }
    assertRequestsStayOnDatasourceResources(captured, resourcePrefix());
  });
});
