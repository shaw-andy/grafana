import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { lastValueFrom } from 'rxjs';
import { fromFetch } from 'rxjs/fetch';

import {
  type DataQueryRequest,
  type EventBusExtended,
  getDefaultTimeRange,
  type QueryVariableModel,
} from '@grafana/data';
import { setBackendSrv, setTemplateSrv } from '@grafana/runtime';
import { locationSearchToObject } from '../../../../packages/grafana-runtime/src/services/LocationService';

import { BackendSrv } from 'app/core/services/backend_srv';
import { type ContextSrv, type User } from 'app/core/services/context_srv';
import { TemplateSrv } from 'app/features/templating/template_srv';
import { ensureStringValues } from 'app/features/variables/ensureStringValues';
import { VARIABLE_PREFIX } from 'app/features/variables/constants';
import { runRequest } from 'app/features/query/state/runRequest';
import { QueryRunners } from 'app/features/variables/query/queryRunners';
import Datasource from 'app/plugins/datasource/azuremonitor/datasource';
import { AzureQueryType } from 'app/plugins/datasource/azuremonitor/dataquery.gen';
import { createMockInstanceSetttings } from 'app/plugins/datasource/azuremonitor/mocks/instanceSettings';
import { type AzureMonitorQuery } from 'app/plugins/datasource/azuremonitor/types/query';

const DATA_SOURCE_UID = 'abc';
const RESOURCE_PREFIX = `/api/datasources/uid/${DATA_SOURCE_UID}/resources/`;

// Thirty-two parent segments is enough to walk off the datasource resource route
// back to the Grafana origin. The question mark ends the path before the metric
// API suffix is appended.
const LOGOUT_PATH = 'x/' + '../'.repeat(32) + 'logout?';

interface CapturedRequest {
  rawUrl: string;
  credentials: RequestCredentials | undefined;
  pathname: string;
}

describe('Azure Monitor metric resource requests', () => {
  let templateSrv: TemplateSrv;
  let datasource: Datasource;
  let captured: CapturedRequest[];

  beforeEach(() => {
    document.head.querySelectorAll('base').forEach((node) => node.remove());
    const base = document.createElement('base');
    base.href = '/';
    document.head.appendChild(base);

    captured = [];
    globalThis.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      captured.push({
        rawUrl,
        credentials: init?.credentials,
        pathname: await pathnameSentToOrigin(rawUrl),
      });
      return new Response(JSON.stringify({ value: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });

    templateSrv = new TemplateSrv();
    setTemplateSrv(templateSrv);
    const appEvents = { emit: jest.fn(), publish: jest.fn() } as unknown as EventBusExtended;
    const backendSrv = new BackendSrv({
      fromFetch,
      appEvents,
      contextSrv: { user: { isSignedIn: true, orgId: 1 } as User } as ContextSrv,
      logout: jest.fn(),
    });
    setBackendSrv(backendSrv);
    datasource = new Datasource(createMockInstanceSetttings());
  });

  afterEach(() => {
    Reflect.deleteProperty(globalThis, 'fetch');
  });

  it('requests metric names for an ordinary resource under the datasource resource route', async () => {
    await runSavedVariable(metricNamesQuery('sub', 'group', 'Microsoft.Compute/virtualMachines', 'vm1'));

    expect(captured).toHaveLength(1);
    expect(captured[0].credentials).toBe('same-origin');
    expect(captured[0].pathname).toBe(
      '/api/datasources/uid/abc/resources/azuremonitor/subscriptions/sub/resourceGroups/group/providers/Microsoft.Compute/virtualMachines/vm1/providers/microsoft.insights/metricdefinitions'
    );
  });

  it('does not send a viewer who opens a dashboard to logout when the metric-names resource group was saved', async () => {
    await runSavedVariable(metricNamesQuery('sub', LOGOUT_PATH, 'Microsoft.Compute/virtualMachines', 'vm1'));

    expectRequestsStayOnResourceRoute();
  });

  it('does not send a viewer to logout when the metric-names subscription was saved', async () => {
    await runSavedVariable(metricNamesQuery(LOGOUT_PATH, 'group', 'Microsoft.Compute/virtualMachines', 'vm1'));

    expectRequestsStayOnResourceRoute();
  });

  it('does not send a viewer to logout when a dashboard URL sets the resource group used by metric names', async () => {
    const search = `?${VARIABLE_PREFIX}rg=${encodeURIComponent(LOGOUT_PATH)}`;
    const fromUrl = locationSearchToObject(search)[`${VARIABLE_PREFIX}rg`];
    const value = ensureStringValues(fromUrl);
    templateSrv.init([
      {
        name: 'rg',
        type: 'custom',
        current: { text: value, value, selected: false },
      },
    ]);

    await runSavedVariable(metricNamesQuery('sub', '$rg', 'Microsoft.Compute/virtualMachines', 'vm1'));

    expectRequestsStayOnResourceRoute();
  });

  it('does not send a viewer to logout when the custom-namespaces resource group was saved', async () => {
    await runSavedVariable(customNamespacesQuery('sub', LOGOUT_PATH, 'Microsoft.Compute/virtualMachines', 'vm1'));

    expectRequestsStayOnResourceRoute();
  });

  it('does not send a viewer to logout when a dashboard URL sets the namespace used by custom namespaces', async () => {
    const search = `?${VARIABLE_PREFIX}ns=${encodeURIComponent(LOGOUT_PATH)}`;
    const fromUrl = locationSearchToObject(search)[`${VARIABLE_PREFIX}ns`];
    const value = ensureStringValues(fromUrl);
    templateSrv.init([
      {
        name: 'ns',
        type: 'custom',
        current: { text: value, value, selected: false },
      },
    ]);

    await runSavedVariable(customNamespacesQuery('sub', 'group', '$ns', 'vm1'));

    expectRequestsStayOnResourceRoute();
  });

  it('does not send a viewer to logout when the custom metric names resource group was saved', async () => {
    await runSavedVariable(
      customMetricNamesQuery('sub', LOGOUT_PATH, 'Microsoft.Compute/virtualMachines', 'vm1', 'custom.namespace')
    );

    expectRequestsStayOnResourceRoute();
  });

  it('does not send a viewer to logout when a legacy metric-names template function saved the resource group', async () => {
    await runSavedVariable({
      refId: 'A',
      queryType: AzureQueryType.GrafanaTemplateVariableFn,
      grafanaTemplateVariableFn: {
        kind: 'MetricNamesQuery',
        subscription: 'sub',
        resourceGroup: LOGOUT_PATH,
        metricNamespace: 'Microsoft.Compute/virtualMachines',
        resourceName: 'vm1',
      },
    });

    expectRequestsStayOnResourceRoute();
  });

  it('does not send a viewer to logout when the locations variable subscription was saved', async () => {
    await runSavedVariable({
      refId: 'A',
      queryType: AzureQueryType.LocationsQuery,
      subscription: LOGOUT_PATH,
    });

    expectRequestsStayOnResourceRoute();
  });

  it('does not send a viewer to logout when the workspaces variable subscription was saved', async () => {
    await runSavedVariable({
      refId: 'A',
      queryType: AzureQueryType.WorkspacesQuery,
      subscription: LOGOUT_PATH,
    });

    expectRequestsStayOnResourceRoute();
  });

  it('does not send the editor to logout when metric metadata is loaded for a saved resource group', async () => {
    await datasource.azureMonitorDatasource
      .getMetricMetadata({
        subscription: 'sub',
        resourceGroup: LOGOUT_PATH,
        metricNamespace: 'Microsoft.Compute/virtualMachines',
        resourceName: 'vm1',
        metricName: 'Percentage CPU',
      })
      .catch(() => undefined);

    expectRequestsStayOnResourceRoute();
  });

  async function runSavedVariable(query: AzureMonitorQuery) {
    const variable = {
      type: 'query',
      name: 'metric',
      query,
    } as QueryVariableModel;
    const runner = new QueryRunners().getRunnerForDatasource(datasource);
    const target = runner.getTarget({ datasource, variable });
    const request = {
      targets: [target],
      range: getDefaultTimeRange(),
    } as DataQueryRequest<AzureMonitorQuery>;

    await lastValueFrom(
      runner.runRequest(
        {
          datasource,
          variable,
          timeSrv: { timeRange: () => request.range } as never,
          runRequest,
        },
        request
      )
    ).catch(() => undefined);
  }

  function expectRequestsStayOnResourceRoute() {
    expect(captured.map((request) => ({ pathname: request.pathname, credentials: request.credentials }))).toEqual(
      captured.map(() => ({
        pathname: expect.stringMatching(new RegExp(`^${RESOURCE_PREFIX}`)),
        credentials: 'same-origin',
      }))
    );
  }
});

function metricNamesQuery(
  subscription: string,
  resourceGroup: string,
  namespace: string,
  resource: string
): AzureMonitorQuery {
  return {
    refId: 'A',
    queryType: AzureQueryType.MetricNamesQuery,
    subscription,
    resourceGroup,
    namespace,
    resource,
  };
}

function customNamespacesQuery(
  subscription: string,
  resourceGroup: string,
  namespace: string,
  resource: string
): AzureMonitorQuery {
  return {
    refId: 'A',
    queryType: AzureQueryType.CustomNamespacesQuery,
    subscription,
    resourceGroup,
    namespace,
    resource,
  };
}

function customMetricNamesQuery(
  subscription: string,
  resourceGroup: string,
  namespace: string,
  resource: string,
  customNamespace: string
): AzureMonitorQuery {
  return {
    refId: 'A',
    queryType: AzureQueryType.CustomMetricNamesQuery,
    subscription,
    resourceGroup,
    namespace,
    resource,
    customNamespace,
  };
}

function pathnameSentToOrigin(rawUrl: string): Promise<string> {
  const resolved = new URL(rawUrl, document.baseURI);
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      response.writeHead(204);
      response.end();
      const pathname = new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
      server.close();
      resolve(pathname);
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo;
      const target = new URL(resolved.pathname + resolved.search, `http://127.0.0.1:${address.port}/`);
      const outbound = http.request(target, { method: 'GET' });
      outbound.on('error', (error) => {
        server.close();
        reject(error);
      });
      outbound.end();
    });
  });
}
