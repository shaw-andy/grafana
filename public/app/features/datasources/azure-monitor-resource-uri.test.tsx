import { render, waitFor } from '@testing-library/react';
import { fromFetch } from 'rxjs/fetch';

import { CoreApp } from '@grafana/data';
import { setBackendSrv, setTemplateSrv, type TemplateSrv } from '@grafana/runtime';

import { BackendSrv, type BackendSrvDependencies } from '../../core/services/backend_srv';
import AzureLogAnalyticsDatasource from '../../plugins/datasource/azuremonitor/azure_log_analytics/azure_log_analytics_datasource';
import AzureMonitorDatasource from '../../plugins/datasource/azuremonitor/azure_monitor/azure_monitor_datasource';
import LogsQueryEditor from '../../plugins/datasource/azuremonitor/components/LogsQueryEditor/LogsQueryEditor';
import QueryEditor from '../../plugins/datasource/azuremonitor/components/QueryEditor/QueryEditor';
import VariableEditor from '../../plugins/datasource/azuremonitor/components/VariableEditor/VariableEditor';
import { AzureQueryType, LogsEditorMode } from '../../plugins/datasource/azuremonitor/dataquery.gen';
import Datasource from '../../plugins/datasource/azuremonitor/datasource';
import { createMockInstanceSetttings } from '../../plugins/datasource/azuremonitor/mocks/instanceSettings';
import createMockQuery from '../../plugins/datasource/azuremonitor/mocks/query';
import { variableRegex } from '../variables/utils';

jest.mock('app/plugins/datasource/azuremonitor/components/LogsQueryEditor/QueryField', () => ({
  __esModule: true,
  default: () => null,
}));

// Default <base href="/"> from public/views/index.html when server.root_url has no path.
const APP_ROOT = 'http://localhost:3000/';
const RESOURCE_PREFIX = '/api/datasources/uid/abc/resources/';

// Enough ../ segments to climb out of either resource URL shape the client builds.
const climb = (tail: string) => `/${'../'.repeat(16)}${tail}`;

const logoutResource = climb('logout?');
const switchOrgResource = climb('profile/switch-org/2?');
const backslashLogoutResource = `/${'..\\'.repeat(16)}logout?`;
const tablePlanResource = climb('logout?microsoft.operationalinsights/workspaces');
const legitimateResource = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws';

interface SeenRequest {
  url: string;
  credentials: RequestCredentials | undefined;
  method: string | undefined;
}

function pathnameAgainstAppRoot(url: string): string {
  return new URL(url, APP_ROOT).pathname;
}

function requestsOutsideResourcePrefix(seen: SeenRequest[]) {
  return seen
    .map((request) => ({
      url: request.url,
      pathname: pathnameAgainstAppRoot(request.url),
      credentials: request.credentials,
      method: request.method,
    }))
    .filter((request) => !request.pathname.startsWith(RESOURCE_PREFIX));
}

function templateSrv(): TemplateSrv {
  return {
    getVariables: () => [],
    replace: (target?: string) => {
      if (!target) {
        return target ?? '';
      }
      variableRegex.lastIndex = 0;
      // No variable matches: the saved resource is returned unchanged, as TemplateSrv does.
      return target.replace(variableRegex, (match) => match);
    },
    getVariableName: () => null,
    containsTemplate: () => false,
    updateTimeRange: () => {},
  } as unknown as TemplateSrv;
}

function installBackend() {
  const seen: SeenRequest[] = [];
  const previousFetch = globalThis.fetch;
  globalThis.fetch = jest.fn(async () => {
    return new Response(JSON.stringify({ value: [], tables: [{ name: 'SigninLogs' }], functions: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  const backendSrv = new BackendSrv({
    fromFetch: (input, init) => {
      seen.push({
        url: typeof input === 'string' ? input : input.url,
        credentials: init?.credentials,
        method: init?.method,
      });
      return fromFetch(input, init);
    },
    appEvents: { emit: jest.fn(), publish: jest.fn() },
    contextSrv: { user: { isSignedIn: true, orgId: 1 } },
    logout: jest.fn(),
  } as unknown as BackendSrvDependencies);
  setBackendSrv(backendSrv);

  return {
    seen,
    restore() {
      globalThis.fetch = previousFetch;
    },
  };
}

async function settle(run: () => Promise<unknown>) {
  try {
    await run();
  } catch {
    // Rejection after the request is still a failure when the request left the resource prefix.
  }
}

describe('Azure Monitor logs resource URI', () => {
  let restore: () => void;
  let seen: SeenRequest[];

  beforeEach(() => {
    document.head.querySelectorAll('base').forEach((node) => node.remove());
    const base = document.createElement('base');
    base.href = APP_ROOT;
    document.head.appendChild(base);
    setTemplateSrv(templateSrv());
    const installed = installBackend();
    seen = installed.seen;
    restore = installed.restore;
  });

  afterEach(() => {
    restore();
  });

  it('keeps a workspace resource under the datasource resource prefix', async () => {
    const datasource = new AzureLogAnalyticsDatasource(createMockInstanceSetttings(), templateSrv());

    await settle(() => datasource.getKustoSchema(legitimateResource));

    expect(seen.map((request) => pathnameAgainstAppRoot(request.url))).toEqual([
      '/api/datasources/uid/abc/resources/loganalytics/v1/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/metadata',
    ]);
    expect(seen[0].method).toBe('GET');
    expect(seen[0].credentials).toBe('same-origin');
  });

  it('does not let a saved logs resource issue GET /logout', async () => {
    const datasource = new AzureLogAnalyticsDatasource(createMockInstanceSetttings(), templateSrv());

    await settle(() => datasource.getKustoSchema(logoutResource));

    expect(requestsOutsideResourcePrefix(seen)).toEqual([]);
  });

  it('does not let a saved logs resource issue GET /profile/switch-org/:id', async () => {
    const datasource = new AzureLogAnalyticsDatasource(createMockInstanceSetttings(), templateSrv());

    await settle(() => datasource.getKustoSchema(switchOrgResource));

    expect(requestsOutsideResourcePrefix(seen)).toEqual([]);
  });

  it('does not let a backslash logs resource climb out of the datasource path', async () => {
    const datasource = new AzureLogAnalyticsDatasource(createMockInstanceSetttings(), templateSrv());

    await settle(() => datasource.getKustoSchema(backslashLogoutResource));

    expect(requestsOutsideResourcePrefix(seen)).toEqual([]);
  });

  it('does not let getWorkspaceTablePlan issue GET /logout for the same workspace URI', async () => {
    const datasource = new AzureMonitorDatasource(createMockInstanceSetttings(), templateSrv());

    await settle(() => datasource.getWorkspaceTablePlan([tablePlanResource], 'SigninLogs'));

    expect(requestsOutsideResourcePrefix(seen)).toEqual([]);
  });

  it('does not issue an escaped request when the panel query editor opens a saved logs query', async () => {
    const datasource = new Datasource(createMockInstanceSetttings());
    const schema = jest.spyOn(datasource.azureLogAnalyticsDatasource, 'getKustoSchema');
    const query = createMockQuery({
      queryType: AzureQueryType.LogAnalytics,
      azureLogAnalytics: {
        resources: [logoutResource],
        mode: LogsEditorMode.Raw,
        query: 'SigninLogs',
      },
    });

    render(
      <QueryEditor
        app={CoreApp.Dashboard}
        query={query}
        datasource={datasource}
        onChange={jest.fn()}
        onRunQuery={jest.fn()}
      />
    );

    await waitFor(() => expect(schema).toHaveBeenCalledWith(logoutResource));
    expect(requestsOutsideResourcePrefix(seen)).toEqual([]);
  });

  it('does not issue an escaped request when the logs query editor loads schema and table plan', async () => {
    const datasource = new Datasource(createMockInstanceSetttings());
    const schema = jest.spyOn(datasource.azureLogAnalyticsDatasource, 'getKustoSchema');
    const tablePlan = jest.spyOn(datasource.azureMonitorDatasource, 'getWorkspaceTablePlan');
    const query = createMockQuery({
      queryType: AzureQueryType.LogAnalytics,
      azureLogAnalytics: {
        resources: [tablePlanResource],
        mode: LogsEditorMode.Builder,
        query: 'SigninLogs',
      },
    });

    render(
      <LogsQueryEditor
        query={query}
        datasource={datasource}
        basicLogsEnabled={false}
        onChange={jest.fn()}
        onQueryChange={jest.fn()}
        setError={jest.fn()}
        variableOptionGroup={{ label: 'Template variables', options: [] }}
      />
    );

    await waitFor(() => expect(schema).toHaveBeenCalledWith(tablePlanResource));
    await waitFor(() => expect(tablePlan).toHaveBeenCalled());
    expect(requestsOutsideResourcePrefix(seen)).toEqual([]);
  });

  it('does not issue an escaped request when the variable editor opens a saved logs query', async () => {
    const datasource = new Datasource(createMockInstanceSetttings());
    const schema = jest.spyOn(datasource.azureLogAnalyticsDatasource, 'getKustoSchema');
    const query = createMockQuery({
      queryType: AzureQueryType.LogAnalytics,
      subscription: '',
      subscriptions: [],
      azureLogAnalytics: {
        resources: [switchOrgResource],
        mode: LogsEditorMode.Raw,
        query: 'SigninLogs',
      },
    });

    render(<VariableEditor query={query} datasource={datasource} onChange={jest.fn()} />);

    await waitFor(() => expect(schema).toHaveBeenCalledWith(switchOrgResource));
    expect(requestsOutsideResourcePrefix(seen)).toEqual([]);
  });
});
