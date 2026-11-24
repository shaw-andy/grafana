import { act, renderHook, waitFor } from '@testing-library/react';
import { createMemoryHistory } from 'history';
import { stringify } from 'querystring';
import { type ReactNode } from 'react';
import { of } from 'rxjs';
import { TestProvider } from 'test/helpers/TestProvider';
import { seedDataSources, watchDataSourceFallbacks } from 'test/helpers/seedDataSources';
import { getGrafanaContextMock } from 'test/mocks/getGrafanaContextMock';

import { type DataSourceInstanceSettings, LoadingState, PluginType, store, type UrlQueryMap } from '@grafana/data';
import {
  type BackendSrv,
  type BackendSrvRequest,
  HistoryWrapper,
  setBackendSrv,
  setTemplateSrv,
  type TemplateSrv,
} from '@grafana/runtime';
import { TestDataDataSource } from 'app/plugins/datasource/grafana-testdata-datasource/datasource';
import { GraphiteDatasource } from 'app/plugins/datasource/graphite/datasource';
import { MIXED_DATASOURCE_NAME, MixedDatasource } from 'app/plugins/datasource/mixed/MixedDataSource';
import { configureStore } from 'app/store/configureStore';
import { type ExploreItemState } from 'app/types/explore';

import { runQueries } from '../../state/query';

import { useStateSync } from './';

const ORG_ID = 1;
const LAST_USED_KEY = `grafana.explore.datasource.${ORG_ID}`;
const GRAPHITE_TARGET = 'explore.csrf.canary';
const RAW_SQL = 'SELECT explore_csrf_canary';
const LEFT_TARGET = 'explore.csrf.left';
const RIGHT_TARGET = 'explore.csrf.right';

const requests: BackendSrvRequest[] = [];

function requestText(req: BackendSrvRequest): string {
  const body = typeof req.data === 'string' ? req.data : JSON.stringify(req.data ?? '');
  return `${req.url ?? ''} ${body}`;
}

function requestsContaining(marker: string): BackendSrvRequest[] {
  return requests.filter((req) => requestText(req).includes(marker));
}

function settings(
  partial: Pick<DataSourceInstanceSettings, 'uid' | 'name' | 'type'> &
    Partial<Pick<DataSourceInstanceSettings, 'id' | 'isDefault' | 'url'>>
): DataSourceInstanceSettings {
  return {
    id: partial.id ?? 1,
    uid: partial.uid,
    name: partial.name,
    type: partial.type,
    access: 'proxy',
    url: partial.url ?? `/api/datasources/proxy/uid/${partial.uid}`,
    jsonData: {},
    readOnly: false,
    isDefault: partial.isDefault,
    meta: {
      id: partial.type,
      name: partial.name,
      type: PluginType.datasource,
      module: '',
      baseUrl: '',
      info: {
        author: { name: '' },
        description: '',
        links: [],
        logos: { small: '', large: '' },
        screenshots: [],
        updated: '',
        version: '',
      },
    },
  };
}

const identityTemplateSrv: TemplateSrv = {
  getVariables: () => [],
  replace: (target?: string) => target ?? '',
  containsTemplate: () => false,
  updateTimeRange: () => undefined,
};

function recordingBackend(): BackendSrv {
  return {
    fetch: (req: BackendSrvRequest) => {
      requests.push(req);
      const url = req.url ?? '';
      let data: unknown = { results: {} };
      if (url.includes('/api/datasources/correlations')) {
        data = { correlations: [], page: 0, limit: 1000, totalCount: 0 };
      } else if (url.includes('/render')) {
        data = [];
      }
      return of({
        data,
        ok: true,
        status: 200,
        statusText: 'OK',
        url,
        config: req,
      });
    },
    get: async () => ({}),
    post: async () => ({}),
    put: async () => ({}),
    patch: async () => ({}),
    delete: async () => ({}),
    request: async () => ({}),
    datasourceRequest: async () => ({ data: {}, ok: true, status: 200, statusText: 'OK' }),
  } as BackendSrv;
}

function setup(queryParams: UrlQueryMap) {
  const history = createMemoryHistory({
    initialEntries: [{ pathname: '/explore', search: stringify(queryParams) }],
  });
  const location = new HistoryWrapper(history);
  const reduxStore = configureStore({
    user: {
      orgId: ORG_ID,
      fiscalYearStartMonth: 0,
      isUpdating: false,
      orgs: [],
      orgsAreLoading: false,
      sessions: [],
      sessionsAreLoading: false,
      teams: [],
      teamsAreLoading: false,
      timeZone: 'utc',
      user: null,
      weekStart: 'monday',
    },
  });
  const context = getGrafanaContextMock();
  const wrapper = ({ children }: { children: ReactNode }) => (
    <TestProvider grafanaContext={{ ...context, location }} store={reduxStore}>
      {children}
    </TestProvider>
  );

  const hook = renderHook(({ params }) => useStateSync(params), {
    wrapper,
    initialProps: { children: null, params: queryParams },
  });

  return { ...hook, location, store: reduxStore };
}

function pane(store: ReturnType<typeof setup>['store'], exploreId: string): ExploreItemState | undefined {
  return store.getState().explore.panes[exploreId];
}

async function queriesLoaded(
  reduxStore: ReturnType<typeof setup>['store'],
  exploreId: string,
  marker: string
): Promise<ExploreItemState> {
  let loaded: ExploreItemState | undefined;
  await waitFor(() => {
    loaded = pane(reduxStore, exploreId);
    expect(JSON.stringify(loaded?.queries ?? [])).toContain(marker);
  });
  // initializeExplore dispatches runQueries without waiting for it. Give that thunk
  // time to reach datasource.query before asserting that it did not.
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 250));
  });
  return loaded!;
}

describe('Explore URL query execution', () => {
  const fallbacks = watchDataSourceFallbacks();
  let graphite: GraphiteDatasource;
  let sqlShaped: TestDataDataSource;
  let otherGraphite: GraphiteDatasource;
  let mixed: MixedDatasource;

  beforeEach(() => {
    requests.length = 0;
    store.delete(LAST_USED_KEY);
    setTemplateSrv(identityTemplateSrv);
    setBackendSrv(recordingBackend());

    const graphiteSettings = settings({
      id: 1,
      uid: 'graphite-uid',
      name: 'graphite',
      type: 'graphite',
    });
    const sqlSettings = settings({
      id: 2,
      uid: 'mysql-uid',
      name: 'mysql',
      type: 'grafana-testdata-datasource',
      isDefault: true,
    });
    const otherSettings = settings({
      id: 3,
      uid: 'other-graphite-uid',
      name: 'other-graphite',
      type: 'graphite',
    });
    const mixedSettings = settings({
      id: 4,
      uid: MIXED_DATASOURCE_NAME,
      name: MIXED_DATASOURCE_NAME,
      type: 'mixed',
    });

    graphite = new GraphiteDatasource(graphiteSettings, identityTemplateSrv);
    sqlShaped = new TestDataDataSource(sqlSettings, identityTemplateSrv);
    otherGraphite = new GraphiteDatasource(otherSettings, identityTemplateSrv);
    mixed = new MixedDatasource(mixedSettings);

    seedDataSources(
      [
        { settings: graphiteSettings, api: graphite },
        { settings: sqlSettings, api: sqlShaped },
        { settings: otherSettings, api: otherGraphite },
        { settings: mixedSettings, api: mixed },
      ],
      { legacySrv: 'mock' }
    );
  });

  afterEach(() => {
    fallbacks.expectNoFallbacks();
  });

  it('loads a uid-addressed query from the panes parameter and does not execute it', async () => {
    const { store: reduxStore } = setup({
      schemaVersion: 1,
      panes: JSON.stringify({
        abc: {
          datasource: 'graphite-uid',
          queries: [{ refId: 'A', target: GRAPHITE_TARGET }],
          range: { from: 'now-1h', to: 'now' },
        },
      }),
    });

    const loaded = await queriesLoaded(reduxStore, 'abc', GRAPHITE_TARGET);

    expect(requestsContaining(GRAPHITE_TARGET)).toEqual([]);
    expect(loaded.datasourceInstance?.uid).toBe('graphite-uid');
    expect(loaded.queryResponse.state).toBe(LoadingState.NotStarted);
  });

  it('loads a name-addressed query from the panes parameter and does not execute it', async () => {
    const { store: reduxStore } = setup({
      schemaVersion: 1,
      panes: JSON.stringify({
        abc: {
          datasource: 'graphite',
          queries: [{ refId: 'A', target: GRAPHITE_TARGET }],
          range: { from: 'now-1h', to: 'now' },
        },
      }),
    });

    const loaded = await queriesLoaded(reduxStore, 'abc', GRAPHITE_TARGET);

    expect(requestsContaining(GRAPHITE_TARGET)).toEqual([]);
    expect(loaded.datasourceInstance?.uid).toBe('graphite-uid');
    expect(loaded.queryResponse.state).toBe(LoadingState.NotStarted);
  });

  it('loads a query whose datasource name does not exist onto the default datasource and does not execute it', async () => {
    const { store: reduxStore } = setup({
      schemaVersion: 1,
      panes: JSON.stringify({
        abc: {
          datasource: 'not-a-real-datasource',
          queries: [{ refId: 'A', rawSql: RAW_SQL, rawQuery: true, editorMode: 'code', format: 'table' }],
          range: { from: 'now-1h', to: 'now' },
        },
      }),
    });

    const loaded = await queriesLoaded(reduxStore, 'abc', RAW_SQL);

    expect(requestsContaining(RAW_SQL)).toEqual([]);
    expect(loaded.datasourceInstance?.uid).toBe('mysql-uid');
    expect(loaded.queryResponse.state).toBe(LoadingState.NotStarted);
  });

  it('loads queries for several datasources from one mixed pane and does not execute them', async () => {
    const { store: reduxStore } = setup({
      schemaVersion: 1,
      panes: JSON.stringify({
        abc: {
          datasource: MIXED_DATASOURCE_NAME,
          queries: [
            { refId: 'A', target: LEFT_TARGET, datasource: { type: 'graphite', uid: 'graphite-uid' } },
            { refId: 'B', target: RIGHT_TARGET, datasource: { type: 'graphite', uid: 'other-graphite-uid' } },
          ],
          range: { from: 'now-1h', to: 'now' },
        },
      }),
    });

    const loaded = await queriesLoaded(reduxStore, 'abc', LEFT_TARGET);

    expect([...requestsContaining(LEFT_TARGET), ...requestsContaining(RIGHT_TARGET)]).toEqual([]);
    expect(loaded.datasourceInstance?.name).toBe(MIXED_DATASOURCE_NAME);
    expect(JSON.stringify(loaded.queries)).toContain(RIGHT_TARGET);
    expect(loaded.queryResponse.state).toBe(LoadingState.NotStarted);
  });

  it('loads a legacy left-pane URL and does not execute its query', async () => {
    const { store: reduxStore } = setup({
      left: JSON.stringify({
        datasource: 'graphite-uid',
        queries: [{ refId: 'A', target: GRAPHITE_TARGET }],
        range: { from: 'now-1h', to: 'now' },
      }),
    });

    await waitFor(() => {
      const panes = reduxStore.getState().explore.panes;
      expect(Object.values(panes).some((item) => JSON.stringify(item?.queries ?? []).includes(GRAPHITE_TARGET))).toBe(
        true
      );
    });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 250));
    });

    const loaded = Object.values(reduxStore.getState().explore.panes).find((item) =>
      JSON.stringify(item?.queries ?? []).includes(GRAPHITE_TARGET)
    );

    expect(requestsContaining(GRAPHITE_TARGET)).toEqual([]);
    expect(loaded?.datasourceInstance?.uid).toBe('graphite-uid');
    expect(loaded?.queryResponse.state).toBe(LoadingState.NotStarted);
  });

  it('does not execute a query applied by a later panes change on an open Explore page', async () => {
    const initial = {
      schemaVersion: 1,
      panes: JSON.stringify({
        abc: {
          datasource: 'graphite-uid',
          queries: [{ refId: 'A' }],
          range: { from: 'now-1h', to: 'now' },
        },
      }),
    };
    const { store: reduxStore, rerender } = setup(initial);

    await waitFor(() => {
      expect(pane(reduxStore, 'abc')?.initialized).toBe(true);
    });
    requests.length = 0;

    rerender({
      children: null,
      params: {
        schemaVersion: 1,
        panes: JSON.stringify({
          abc: {
            datasource: 'graphite-uid',
            queries: [{ refId: 'A', target: GRAPHITE_TARGET }],
            range: { from: 'now-1h', to: 'now' },
          },
        }),
      },
    });

    const loaded = await queriesLoaded(reduxStore, 'abc', GRAPHITE_TARGET);

    expect(requestsContaining(GRAPHITE_TARGET)).toEqual([]);
    expect(loaded.queryResponse.state).toBe(LoadingState.NotStarted);
  });

  it('does not execute a query for a pane that appears from a later panes change', async () => {
    const { store: reduxStore, rerender } = setup({
      schemaVersion: 1,
      panes: JSON.stringify({
        abc: {
          datasource: 'graphite-uid',
          queries: [{ refId: 'A' }],
          range: { from: 'now-1h', to: 'now' },
        },
      }),
    });

    await waitFor(() => {
      expect(pane(reduxStore, 'abc')?.initialized).toBe(true);
    });
    requests.length = 0;

    rerender({
      children: null,
      params: {
        schemaVersion: 1,
        panes: JSON.stringify({
          abc: {
            datasource: 'graphite-uid',
            queries: [{ refId: 'A' }],
            range: { from: 'now-1h', to: 'now' },
          },
          def: {
            datasource: 'mysql',
            queries: [{ refId: 'A', rawSql: RAW_SQL, rawQuery: true }],
            range: { from: 'now-1h', to: 'now' },
          },
        }),
      },
    });

    const loaded = await queriesLoaded(reduxStore, 'def', RAW_SQL);

    expect(requestsContaining(RAW_SQL)).toEqual([]);
    expect(loaded.datasourceInstance?.uid).toBe('mysql-uid');
    expect(loaded.queryResponse.state).toBe(LoadingState.NotStarted);
  });

  it('executes the loaded query when runQueries is dispatched', async () => {
    const { store: reduxStore } = setup({
      schemaVersion: 1,
      panes: JSON.stringify({
        abc: {
          datasource: 'graphite-uid',
          queries: [{ refId: 'A', target: GRAPHITE_TARGET }],
          range: { from: 'now-1h', to: 'now' },
        },
      }),
    });

    await queriesLoaded(reduxStore, 'abc', GRAPHITE_TARGET);
    requests.length = 0;

    await act(async () => {
      await reduxStore.dispatch(runQueries({ exploreId: 'abc' }));
    });

    expect(requestsContaining(GRAPHITE_TARGET).length).toBeGreaterThan(0);
    expect(requestsContaining(GRAPHITE_TARGET).some((req) => (req.url ?? '').includes('/render'))).toBe(true);
  });
});
