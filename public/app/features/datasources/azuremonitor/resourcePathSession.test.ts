import { lastValueFrom, of } from 'rxjs';

import { type DataQueryRequest } from '@grafana/data';
import { setBackendSrv } from '@grafana/runtime';
import { EmbeddedScene, SceneCanvasText, SceneVariableSet, TextBoxVariable } from '@grafana/scenes';

import { BackendSrv, type BackendSrvDependencies } from '../../../core/services/backend_srv';
import { type ContextSrv } from '../../../core/services/context_srv';
import { getTemplateSrv } from '../../templating/template_srv';
import Datasource from '../../../plugins/datasource/azuremonitor/datasource';
import { AzureQueryType } from '../../../plugins/datasource/azuremonitor/dataquery.gen';
import { createMockInstanceSetttings } from '../../../plugins/datasource/azuremonitor/mocks/instanceSettings';
import { type AzureMonitorQuery } from '../../../plugins/datasource/azuremonitor/types/query';

/**
 * Parent-directory segments past the datasource resource prefix. Extra segments
 * collapse at the origin, so the same value escapes both the legacy
 * `/api/datasources/...` URL and the longer apiserver URL.
 */
const CLIMB = '../'.repeat(20);

const LOGOUT_QUERY = `${CLIMB}logout?`;
const LOGOUT_HASH = `${CLIMB}logout#`;
const LOGOUT_ENCODED_DOTS = `${'%2e%2e/'.repeat(20)}logout?`;
const BENIGN_SUBSCRIPTION = '11111111-1111-1111-1111-111111111111';

interface CapturedRequest {
  url: string;
  method?: string;
  credentials?: RequestCredentials;
}

const captured: CapturedRequest[] = [];
let deactivateScene: (() => void) | undefined;

function installPageBase() {
  let base = document.querySelector('base');
  if (!base) {
    base = document.createElement('base');
    document.head.appendChild(base);
  }
  base.setAttribute('href', '/');
}

function resolvedPath(url: string): string {
  // fetch() parses a relative URL against the document base URL (<base href="/">).
  return new URL(url, document.baseURI).pathname;
}

function installBackend() {
  const fromFetch = jest.fn().mockImplementation((input: string | Request, init?: RequestInit) => {
    captured.push({
      url: typeof input === 'string' ? input : input.url,
      method: init?.method,
      credentials: init?.credentials,
    });
    return of(
      new Response(JSON.stringify({ value: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
  });

  const backendSrv = new BackendSrv({
    fromFetch,
    contextSrv: { user: { isSignedIn: true, orgId: 1 } } as ContextSrv,
    logout: jest.fn(),
  } as BackendSrvDependencies);
  setBackendSrv(backendSrv);
}

function expectRequestsStayOnDatasourceResource() {
  expect(new URL(document.baseURI).pathname).toBe('/');
  for (const call of captured) {
    const pathname = resolvedPath(call.url);
    expect({ method: call.method, credentials: call.credentials, pathname }).toEqual({
      method: 'GET',
      credentials: 'same-origin',
      pathname: expect.stringMatching(/^\/api\/datasources\/uid\/abc\/resources\//),
    });
  }
}

function queryRequest(target: AzureMonitorQuery | string): DataQueryRequest<AzureMonitorQuery> {
  return { targets: [target] } as DataQueryRequest<AzureMonitorQuery>;
}

describe('Azure Monitor resource URLs', () => {
  let datasource: Datasource;

  beforeEach(() => {
    captured.length = 0;
    installPageBase();
    installBackend();
    // Installing the app TemplateSrv makes datasource calls use dashboard interpolation.
    getTemplateSrv();
    datasource = new Datasource(createMockInstanceSetttings());
    deactivateScene = new EmbeddedScene({
      body: new SceneCanvasText({ text: 'dashboard' }),
    }).activate();
  });

  afterEach(() => {
    deactivateScene?.();
    deactivateScene = undefined;
    delete window.__grafanaSceneContext;
  });

  it('loads workspaces for a subscription id under the datasource resource route', async () => {
    const result = await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.WorkspacesQuery,
          subscription: BENIGN_SUBSCRIPTION,
        })
      )
    );

    expect(result.data).toEqual([]);
    expect(captured).toHaveLength(1);
    expect(resolvedPath(captured[0].url)).toBe(
      `/api/datasources/uid/abc/resources/azuremonitor/subscriptions/${BENIGN_SUBSCRIPTION}/providers/Microsoft.OperationalInsights/workspaces`
    );
    expect(captured[0]).toMatchObject({ method: 'GET', credentials: 'same-origin' });
  });

  it('does not request logout when a workspaces variable subscription climbs out of the resource path', async () => {
    const result = await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.WorkspacesQuery,
          subscription: LOGOUT_QUERY,
        })
      )
    );

    expect(result.data).toEqual([]);
    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout when the subscription is percent-encoded parent segments', async () => {
    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.WorkspacesQuery,
          subscription: LOGOUT_ENCODED_DOTS,
        })
      )
    );

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout when a hash in the subscription ends the resource path', async () => {
    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.WorkspacesQuery,
          subscription: LOGOUT_HASH,
        })
      )
    );

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout when a viewer sets the subscription from a text box variable', async () => {
    deactivateScene?.();
    const subscription = new TextBoxVariable({ name: 'sub', value: '' });
    subscription.updateFromUrl({ 'var-sub': LOGOUT_QUERY });
    deactivateScene = new EmbeddedScene({
      $variables: new SceneVariableSet({ variables: [subscription] }),
      body: new SceneCanvasText({ text: 'dashboard' }),
    }).activate();

    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.WorkspacesQuery,
          subscription: '$sub',
        })
      )
    );

    expect(subscription.getValue()).toBe(LOGOUT_QUERY);
    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout for a legacy workspaces() variable string', async () => {
    await lastValueFrom(datasource.variables.query(queryRequest(`workspaces(${LOGOUT_QUERY})`)));

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout for a legacy WorkspacesQuery template function', async () => {
    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.GrafanaTemplateVariableFn,
          grafanaTemplateVariableFn: {
            kind: 'WorkspacesQuery',
            rawQuery: 'workspaces()',
            subscription: LOGOUT_QUERY,
          },
        })
      )
    );

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout for a locations variable subscription', async () => {
    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.LocationsQuery,
          subscription: LOGOUT_QUERY,
        })
      )
    );

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout for a metric names variable subscription', async () => {
    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.MetricNamesQuery,
          subscription: LOGOUT_QUERY,
          resourceGroup: 'rg',
          namespace: 'Microsoft.Compute/virtualMachines',
          resource: 'vm1',
        })
      )
    );

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout when the resource group segment climbs out of the metric names path', async () => {
    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.MetricNamesQuery,
          subscription: BENIGN_SUBSCRIPTION,
          resourceGroup: LOGOUT_QUERY,
          namespace: 'Microsoft.Compute/virtualMachines',
          resource: 'vm1',
        })
      )
    );

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout for a custom namespaces variable subscription', async () => {
    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.CustomNamespacesQuery,
          subscription: LOGOUT_QUERY,
          resourceGroup: 'rg',
          namespace: 'Microsoft.Compute/virtualMachines',
          resource: 'vm1',
        })
      )
    );

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout for a custom metric names variable subscription', async () => {
    await lastValueFrom(
      datasource.variables.query(
        queryRequest({
          refId: 'A',
          queryType: AzureQueryType.CustomMetricNamesQuery,
          subscription: LOGOUT_QUERY,
          resourceGroup: 'rg',
          namespace: 'Microsoft.Compute/virtualMachines',
          resource: 'vm1',
          customNamespace: 'custom',
        })
      )
    );

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout when a log analytics resource uri climbs out of the metadata path', async () => {
    await datasource.azureLogAnalyticsDatasource.getKustoSchema(`${CLIMB}logout?`).catch(() => undefined);

    expectRequestsStayOnDatasourceResource();
  });

  it('does not request logout when a workspace resource uri climbs out of the table plan path', async () => {
    const resourceUri = `/subscriptions/${BENIGN_SUBSCRIPTION}/providers/Microsoft.OperationalInsights/workspaces/${CLIMB}logout?`;
    await datasource.azureMonitorDatasource.getWorkspaceTablePlan([resourceUri], 'Heartbeat').catch(() => undefined);

    expectRequestsStayOnDatasourceResource();
  });
});
