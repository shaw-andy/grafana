import { VariableRefresh } from '@grafana/data';
import {
  CustomVariable,
  QueryVariable,
  SceneGridLayout,
  SceneQueryRunner,
  SceneTimeRange,
  SceneVariableSet,
  VizPanel,
} from '@grafana/scenes';
import { type Spec as DashboardV2Spec } from '@grafana/schema/apis/dashboard.grafana.app/v2';
import {
  getDashboardSnapshotSrv,
  type DashboardSnapshotSrv,
  type SnapshotCreateResponse,
} from 'app/features/dashboard/services/SnapshotSrv';

import { DashboardScene } from '../scene/DashboardScene';
import { DashboardGridItem } from '../scene/layout-default/DashboardGridItem';
import { DefaultGridLayoutManager } from '../scene/layout-default/DefaultGridLayoutManager';
import { RowItem } from '../scene/layout-rows/RowItem';
import { RowsLayoutManager } from '../scene/layout-rows/RowsLayoutManager';
import { TabItem } from '../scene/layout-tabs/TabItem';
import { TabsLayoutManager } from '../scene/layout-tabs/TabsLayoutManager';

import { ShareSnapshot } from './ShareButton/share-snapshot/ShareSnapshot';
import { ShareSnapshotTab } from './ShareSnapshotTab';

jest.mock('app/features/dashboard/services/SnapshotSrv', () => ({
  getDashboardSnapshotSrv: jest.fn(),
}));

jest.mock('app/store/store', () => ({
  ...jest.requireActual('app/store/store'),
  dispatch: jest.fn(),
}));

const V2_API_VERSION = 'dashboard.grafana.app/v2beta1';

const DASH_QUERY = 'dash-promql-node_cpu_seconds_total';
const DASH_DEFINITION = 'dash-definition-node_cpu_seconds_total';
const PANEL_QUERY = 'panel-promql-process_resident_memory_bytes';

const ROW_QUERY = 'row-promql-up{job="payments-api"}';
const ROW_DEFINITION = 'row-definition-label_values(up{job="payments-api"},instance)';
const ROW_DATASOURCE = 'ds-row-prom';

const ROW_REPEAT_QUERY = 'row-repeat-promql-up{job="payments-clone"}';
const ROW_REPEAT_DEFINITION = 'row-repeat-definition-label_values(payments-clone)';
const ROW_REPEAT_DATASOURCE = 'ds-row-repeat-prom';

const NESTED_ROW_QUERY = 'nested-row-promql-rate(http_requests_total{namespace="billing"}[5m])';
const NESTED_ROW_DEFINITION = 'nested-row-definition-rate-billing';
const NESTED_ROW_DATASOURCE = 'ds-nested-row-prom';

const ROW_NESTED_TAB_QUERY = 'row-nested-tab-sql-SELECT secret FROM credentials';
const ROW_NESTED_TAB_DEFINITION = 'row-nested-tab-definition-credentials';
const ROW_NESTED_TAB_DATASOURCE = 'ds-row-nested-tab-sql';

const NESTED_TAB_QUERY = 'nested-tab-sql-SELECT token FROM service_accounts';
const NESTED_TAB_DEFINITION = 'nested-tab-definition-service-accounts';
const NESTED_TAB_DATASOURCE = 'ds-nested-tab-sql';

const TAB_QUERY_SQL = 'tab-sql-SELECT password FROM users';
const TAB_QUERY_DEFINITION = 'tab-definition-SELECT password FROM users';
const TAB_DATASOURCE = 'ds-tab-sql';

const TAB_NESTED_ROW_QUERY = 'tab-nested-row-promql-kube_pod_info{namespace="payments"}';
const TAB_NESTED_ROW_DEFINITION = 'tab-nested-row-definition-kube-pod-info';
const TAB_NESTED_ROW_DATASOURCE = 'ds-tab-nested-row-prom';

const ROW_CUSTOM_QUERY = 'row-custom-internal-host-a,internal-host-b';

const SECTION_SECRETS = [
  ROW_QUERY,
  ROW_DEFINITION,
  ROW_DATASOURCE,
  ROW_REPEAT_QUERY,
  ROW_REPEAT_DEFINITION,
  ROW_REPEAT_DATASOURCE,
  NESTED_ROW_QUERY,
  NESTED_ROW_DEFINITION,
  NESTED_ROW_DATASOURCE,
  ROW_NESTED_TAB_QUERY,
  ROW_NESTED_TAB_DEFINITION,
  ROW_NESTED_TAB_DATASOURCE,
  NESTED_TAB_QUERY,
  NESTED_TAB_DEFINITION,
  NESTED_TAB_DATASOURCE,
  TAB_QUERY_SQL,
  TAB_QUERY_DEFINITION,
  TAB_DATASOURCE,
  TAB_NESTED_ROW_QUERY,
  TAB_NESTED_ROW_DEFINITION,
  TAB_NESTED_ROW_DATASOURCE,
  ROW_CUSTOM_QUERY,
];

let createSnapshot: jest.Mock<Promise<SnapshotCreateResponse>>;

interface PublishedVariable {
  name: string;
  query: unknown;
  definition: unknown;
}

describe('snapshot section queries', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    createSnapshot = jest.fn().mockResolvedValue({ key: 'abc', url: '/dashboard/snapshot/abc', deleteUrl: '' });
    jest.mocked(getDashboardSnapshotSrv).mockReturnValue(buildSnapshotSrv(createSnapshot));
  });

  it('strips row and nested section queries from a local v2 snapshot', async () => {
    const dashboard = await publish(buildRowsScene(), false);

    expectPublishedSnapshotCleared(
      dashboard,
      'RowsLayout',
      ['dash_promql', 'row_promql', 'row_promql_repeat', 'nested_row_promql', 'row_nested_tab_sql'],
      ['row_custom']
    );
  });

  it('strips row and nested section queries from an external v2 snapshot', async () => {
    const dashboard = await publish(buildRowsScene(), true);

    expectPublishedSnapshotCleared(
      dashboard,
      'RowsLayout',
      ['dash_promql', 'row_promql', 'row_promql_repeat', 'nested_row_promql', 'row_nested_tab_sql'],
      ['row_custom']
    );
  });

  it('strips tab and nested section queries from a local v2 snapshot', async () => {
    const dashboard = await publish(buildTabsScene(), false);

    expectPublishedSnapshotCleared(
      dashboard,
      'TabsLayout',
      ['dash_promql', 'tab_sql', 'nested_tab_sql', 'tab_nested_row_promql'],
      []
    );
  });

  it('strips tab and nested section queries from an external v2 snapshot', async () => {
    const dashboard = await publish(buildTabsScene(), true);

    expectPublishedSnapshotCleared(
      dashboard,
      'TabsLayout',
      ['dash_promql', 'tab_sql', 'nested_tab_sql', 'tab_nested_row_promql'],
      []
    );
  });

  it('does not put section queries in a v1 snapshot', async () => {
    const scene = new DashboardScene({
      title: 'Payments',
      uid: 'pay-1',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-6h', to: 'now' }),
      body: buildRowsBody(),
    });
    const dashboard = await publish(scene, false);
    const published = JSON.stringify(dashboard);

    expect(published).not.toContain(ROW_QUERY);
    expect(published).not.toContain(ROW_DEFINITION);
    expect(published).not.toContain(ROW_DATASOURCE);
    expect(published).not.toContain(NESTED_ROW_QUERY);
    expect(published).not.toContain(ROW_NESTED_TAB_QUERY);
    expect(published).not.toContain(ROW_CUSTOM_QUERY);
    expect(dashboard).not.toHaveProperty('layout.kind', 'RowsLayout');
  });
});

function expectPublishedSnapshotCleared(
  dashboard: unknown,
  layoutKind: string,
  queryVariableNames: string[],
  customVariableNames: string[]
) {
  expect(layoutKindOf(dashboard)).toBe(layoutKind);

  const published = JSON.stringify(dashboard);
  expect(published).not.toContain(DASH_QUERY);
  expect(published).not.toContain(PANEL_QUERY);

  const queryVariables = collectVariables(dashboard, 'QueryVariable');
  expect(queryVariables.map((variable) => variable.name).sort()).toEqual([...queryVariableNames].sort());

  const dashboardVariable = queryVariables.find((variable) => variable.name === 'dash_promql');
  expect(dashboardVariable?.query ?? '').toBe('');

  const customVariables = collectVariables(dashboard, 'CustomVariable');
  expect(customVariables.map((variable) => variable.name).sort()).toEqual([...customVariableNames].sort());

  const leakedQueryVariables = queryVariables
    .filter((variable) => variable.name !== 'dash_promql')
    .filter((variable) => !isCleared(variable.query) || !isCleared(variable.definition))
    .map((variable) => ({
      name: variable.name,
      query: variable.query,
      definition: variable.definition,
    }));
  const leakedCustomVariables = customVariables
    .filter((variable) => !isCleared(variable.query))
    .map((variable) => ({ name: variable.name, query: variable.query }));
  expect({ queryVariables: leakedQueryVariables, customVariables: leakedCustomVariables }).toEqual({
    queryVariables: [],
    customVariables: [],
  });

  for (const secret of SECTION_SECRETS) {
    expect(published).not.toContain(secret);
  }
}

function isCleared(value: unknown): boolean {
  return value === undefined || value === '';
}

function layoutKindOf(dashboard: unknown): string | undefined {
  if (!dashboard || typeof dashboard !== 'object' || !('layout' in dashboard)) {
    return undefined;
  }
  const layout = dashboard.layout;
  if (!layout || typeof layout !== 'object' || !('kind' in layout) || typeof layout.kind !== 'string') {
    return undefined;
  }
  return layout.kind;
}

function collectVariables(value: unknown, kind: string, found: PublishedVariable[] = []): PublishedVariable[] {
  if (!value || typeof value !== 'object') {
    return found;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectVariables(item, kind, found);
    }
    return found;
  }

  const record = Object.fromEntries(Object.entries(value));
  if (record.kind === kind && record.spec && typeof record.spec === 'object') {
    const spec = Object.fromEntries(Object.entries(record.spec));
    found.push({
      name: typeof spec.name === 'string' ? spec.name : '',
      query: spec.query,
      definition: spec.definition,
    });
  }

  for (const child of Object.values(record)) {
    collectVariables(child, kind, found);
  }
  return found;
}

async function publish(scene: DashboardScene, external: boolean): Promise<DashboardV2Spec | object> {
  const Tab = external ? ShareSnapshot : ShareSnapshotTab;
  const tab = new Tab({ dashboardRef: scene.getRef() });
  scene.setState({ overlay: tab });

  await tab.onSnapshotCreate(external);

  const command = createSnapshot.mock.calls.at(-1)?.[0];
  expect(command).toMatchObject({ external });
  return command.dashboard;
}

function buildSnapshotSrv(create: jest.Mock<Promise<SnapshotCreateResponse>>): DashboardSnapshotSrv {
  return {
    create,
    getSnapshots: jest.fn(),
    getSharingOptions: jest.fn().mockResolvedValue({}),
    deleteSnapshot: jest.fn(),
    getSnapshot: jest.fn(),
  };
}

function buildRowsScene(): DashboardScene {
  return buildV2Scene(buildRowsBody());
}

function buildTabsScene(): DashboardScene {
  return buildV2Scene(buildTabsBody());
}

function buildV2Scene(body: RowsLayoutManager | TabsLayoutManager): DashboardScene {
  const scene = new DashboardScene(
    {
      title: 'Payments',
      uid: 'pay-1',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-6h', to: 'now' }),
      $variables: new SceneVariableSet({
        variables: [queryVariable('dash_promql', DASH_QUERY, DASH_DEFINITION, 'ds-dashboard-prom', 'prometheus')],
      }),
      body,
    },
    'v2'
  );
  scene.setInitialSaveModel(undefined, undefined, V2_API_VERSION);
  return scene;
}

function buildRowsBody(): RowsLayoutManager {
  const repeatedRow = new RowItem({
    key: 'row-payments-clone',
    title: 'Payments clone',
    repeatSourceKey: 'row-payments',
    $variables: new SceneVariableSet({
      variables: [
        queryVariable(
          'row_promql_repeat',
          ROW_REPEAT_QUERY,
          ROW_REPEAT_DEFINITION,
          ROW_REPEAT_DATASOURCE,
          'prometheus'
        ),
      ],
    }),
    layout: emptyGrid(),
  });

  const paymentsRow = new RowItem({
    key: 'row-payments',
    title: 'Payments',
    $variables: new SceneVariableSet({
      variables: [
        queryVariable('row_promql', ROW_QUERY, ROW_DEFINITION, ROW_DATASOURCE, 'prometheus'),
        new CustomVariable({
          name: 'row_custom',
          query: ROW_CUSTOM_QUERY,
          value: 'chosen',
          text: 'chosen',
        }),
      ],
    }),
    layout: gridWithPanel('panel-payments', PANEL_QUERY),
    repeatedRows: [repeatedRow],
  });

  const nestedRows = new RowItem({
    key: 'row-outer',
    title: 'Outer row',
    layout: new RowsLayoutManager({
      rows: [
        new RowItem({
          key: 'row-inner',
          title: 'Inner row',
          $variables: new SceneVariableSet({
            variables: [
              queryVariable(
                'nested_row_promql',
                NESTED_ROW_QUERY,
                NESTED_ROW_DEFINITION,
                NESTED_ROW_DATASOURCE,
                'prometheus'
              ),
            ],
          }),
          layout: emptyGrid(),
        }),
      ],
    }),
  });

  const rowWithTabs = new RowItem({
    key: 'row-with-tabs',
    title: 'Row with tabs',
    layout: new TabsLayoutManager({
      tabs: [
        new TabItem({
          key: 'tab-in-row',
          title: 'SQL',
          $variables: new SceneVariableSet({
            variables: [
              queryVariable(
                'row_nested_tab_sql',
                { rawSql: ROW_NESTED_TAB_QUERY, refId: 'A' },
                ROW_NESTED_TAB_DEFINITION,
                ROW_NESTED_TAB_DATASOURCE,
                'mysql'
              ),
            ],
          }),
          layout: emptyGrid(),
        }),
      ],
    }),
  });

  return new RowsLayoutManager({ rows: [paymentsRow, nestedRows, rowWithTabs] });
}

function buildTabsBody(): TabsLayoutManager {
  const sqlTab = new TabItem({
    key: 'tab-sql',
    title: 'SQL',
    $variables: new SceneVariableSet({
      variables: [
        queryVariable(
          'tab_sql',
          { rawSql: TAB_QUERY_SQL, refId: 'A' },
          TAB_QUERY_DEFINITION,
          TAB_DATASOURCE,
          'postgres'
        ),
      ],
    }),
    layout: emptyGrid(),
  });

  const nestedTabs = new TabItem({
    key: 'tab-outer',
    title: 'Outer tab',
    layout: new TabsLayoutManager({
      tabs: [
        new TabItem({
          key: 'tab-inner',
          title: 'Inner tab',
          $variables: new SceneVariableSet({
            variables: [
              queryVariable(
                'nested_tab_sql',
                { rawSql: NESTED_TAB_QUERY, refId: 'A' },
                NESTED_TAB_DEFINITION,
                NESTED_TAB_DATASOURCE,
                'mysql'
              ),
            ],
          }),
          layout: emptyGrid(),
        }),
      ],
    }),
  });

  const tabWithRows = new TabItem({
    key: 'tab-with-rows',
    title: 'Rows',
    layout: new RowsLayoutManager({
      rows: [
        new RowItem({
          key: 'row-in-tab',
          title: 'Pods',
          $variables: new SceneVariableSet({
            variables: [
              queryVariable(
                'tab_nested_row_promql',
                TAB_NESTED_ROW_QUERY,
                TAB_NESTED_ROW_DEFINITION,
                TAB_NESTED_ROW_DATASOURCE,
                'prometheus'
              ),
            ],
          }),
          layout: emptyGrid(),
        }),
      ],
    }),
  });

  return new TabsLayoutManager({ tabs: [sqlTab, nestedTabs, tabWithRows] });
}

function queryVariable(
  name: string,
  query: string | { rawSql: string; refId: string },
  definition: string,
  datasourceUid: string,
  datasourceType: string
) {
  return new QueryVariable({
    name,
    label: name,
    value: 'chosen',
    text: 'chosen',
    query,
    definition,
    datasource: { uid: datasourceUid, type: datasourceType },
    refresh: VariableRefresh.onDashboardLoad,
  });
}

function emptyGrid() {
  return new DefaultGridLayoutManager({
    grid: new SceneGridLayout({ children: [] }),
  });
}

function gridWithPanel(panelKey: string, expr: string) {
  return new DefaultGridLayoutManager({
    grid: new SceneGridLayout({
      children: [
        new DashboardGridItem({
          x: 0,
          y: 0,
          width: 12,
          height: 8,
          body: new VizPanel({
            key: panelKey,
            pluginId: 'timeseries',
            title: 'Memory',
            $data: new SceneQueryRunner({
              datasource: { uid: 'panel-live-ds', type: 'prometheus' },
              queries: [{ refId: 'A', expr }],
            }),
          }),
        }),
      ],
    }),
  });
}
