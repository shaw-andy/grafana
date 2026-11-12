import {
  dataFrameFromJSON,
  FieldType,
  getDefaultTimeRange,
  LoadingState,
  type DataFrame,
  type PanelData,
} from '@grafana/data';
import {
  LocalValueVariable,
  SceneDataNode,
  SceneDataTransformer,
  SceneGridLayout,
  SceneQueryRunner,
  SceneTimeRange,
  SceneVariableSet,
  VizPanel,
} from '@grafana/scenes';
import {
  getDashboardSnapshotSrv,
  type DashboardSnapshotSrv,
  type SnapshotCreateResponse,
} from 'app/features/dashboard/services/SnapshotSrv';

import { DashboardScene } from '../scene/DashboardScene';
import { DashboardGridItem } from '../scene/layout-default/DashboardGridItem';
import { DefaultGridLayoutManager } from '../scene/layout-default/DefaultGridLayoutManager';

import { ShareSnapshotTab } from './ShareSnapshotTab';

jest.mock('app/features/dashboard/services/SnapshotSrv', () => ({
  getDashboardSnapshotSrv: jest.fn(),
}));

jest.mock('app/store/store', () => ({
  ...jest.requireActual('app/store/store'),
  dispatch: jest.fn(),
}));

// Distinct from the panel target text. CloudWatch copies the executed metric expression onto the
// response frame (pkg/tsdb/cloudwatch/response_parser.go createMeta), and the query API delivers
// that string as schema.meta.executedQueryString.
const CLOUDWATCH_EXECUTED_QUERY =
  'SEARCH(\'{AWS/EC2,InstanceId} MetricName="CPUUtilization" InstanceId="i-snapshot-leak"\', \'Average\', 300)';
const ANNOTATION_EXECUTED_QUERY = 'filter accountId = "acct-snapshot-leak"';
const TRANSFORM_SOURCE_QUERY =
  'SELECT AVG(CPUUtilization) FROM SCHEMA("AWS/EC2", InstanceId) WHERE InstanceId = \'i-snapshot-sql\'';
const REPEATED_PANEL_QUERY =
  'SEARCH(\'{AWS/Lambda,FunctionName} MetricName="Errors" FunctionName="billing-fn" query-id-repeat-leak\', \'Sum\', 60)';

const TARGET_ONLY_EXPRESSION = 'target-expression-removed-before-publish';
const SERIES_VALUE = 42.5;
const TRANSFORM_VALUE = 17.25;
const REPEATED_VALUE = 63.75;

// Tokens that appear only inside executed query text. JSON.stringify escapes quotes, so a
// substring check for the raw query would miss the leak.
const LEAK_TOKENS = ['i-snapshot-leak', 'acct-snapshot-leak', 'i-snapshot-sql', 'query-id-repeat-leak'];

describe('Share snapshot executed query strings', () => {
  let createSnapshot: jest.Mock<Promise<SnapshotCreateResponse>>;

  beforeEach(() => {
    jest.clearAllMocks();
    createSnapshot = jest.fn().mockResolvedValue({ key: 'abc', url: '/dashboard/snapshot/abc', deleteUrl: '' });
    jest.mocked(getDashboardSnapshotSrv).mockReturnValue(buildSnapshotSrv(createSnapshot));
  });

  it.each([
    { schema: 'v1' as const, external: false },
    { schema: 'v1' as const, external: true },
    { schema: 'v2' as const, external: false },
    { schema: 'v2' as const, external: true },
  ])(
    'schema $schema publish (external=$external) keeps series values and drops executed queries',
    async ({ schema, external }) => {
      const scene = buildScene(schema);
      const tab = new ShareSnapshotTab({ dashboardRef: scene.getRef() });
      scene.setState({ overlay: tab });

      await tab.onSnapshotCreate(external);

      expect(createSnapshot).toHaveBeenCalledTimes(1);
      const dashboard = createSnapshot.mock.calls[0][0].dashboard;
      const published = JSON.stringify(dashboard);

      expect(published).toContain(String(SERIES_VALUE));
      expect(published).toContain(String(TRANSFORM_VALUE));
      expect(published).toContain(String(REPEATED_VALUE));
      expect(published).not.toContain(TARGET_ONLY_EXPRESSION);
      expect(executedQueryStrings(dashboard)).toEqual([]);
      for (const token of LEAK_TOKENS) {
        expect(published).not.toContain(token);
      }
      expect(createSnapshot.mock.calls[0][0].external).toBe(external);
    }
  );

  it.each([{ schema: 'v1' as const }, { schema: 'v2' as const }])(
    'schema $schema single-panel snapshot drops that panel executed query and the other panels',
    async ({ schema }) => {
      const scene = buildScene(schema);
      const panel = scene.state.body.getVizPanels().find((vizPanel) => vizPanel.state.key === 'panel-1');
      if (!panel) {
        throw new Error('panel-1 was not built');
      }
      const tab = new ShareSnapshotTab({ dashboardRef: scene.getRef(), panelRef: panel.getRef() });
      scene.setState({ overlay: tab });

      await tab.onSnapshotCreate(false);

      const dashboard = createSnapshot.mock.calls[0][0].dashboard;
      const published = JSON.stringify(dashboard);
      expect(published).toContain(String(SERIES_VALUE));
      expect(published).not.toContain(String(TRANSFORM_VALUE));
      expect(published).not.toContain(String(REPEATED_VALUE));
      expect(executedQueryStrings(dashboard)).toEqual([]);
      for (const token of LEAK_TOKENS) {
        expect(published).not.toContain(token);
      }
    }
  );
});

function buildSnapshotSrv(create: jest.Mock<Promise<SnapshotCreateResponse>>): DashboardSnapshotSrv {
  return {
    create,
    getSnapshots: jest.fn(),
    getSharingOptions: jest.fn().mockResolvedValue({}),
    deleteSnapshot: jest.fn(),
    getSnapshot: jest.fn(),
  };
}

function buildScene(schema: 'v1' | 'v2'): DashboardScene {
  const cloudwatch = new VizPanel({
    key: 'panel-1',
    title: 'CPU',
    pluginId: 'timeseries',
    $data: new SceneQueryRunner({
      datasource: { type: 'cloudwatch', uid: 'cw' },
      queries: [
        {
          refId: 'A',
          datasource: { type: 'cloudwatch', uid: 'cw' },
          expression: TARGET_ONLY_EXPRESSION,
        },
      ],
      data: panelData(
        executedFrame('CPUUtilization', CLOUDWATCH_EXECUTED_QUERY, SERIES_VALUE),
        executedFrame('annotation', ANNOTATION_EXECUTED_QUERY, 1)
      ),
    }),
  });

  const transformed = new VizPanel({
    key: 'panel-2',
    title: 'SQL',
    pluginId: 'timeseries',
    $data: new SceneDataTransformer({
      transformations: [{ id: 'reduce', options: {} }],
      $data: new SceneDataNode({
        data: panelData(executedFrame('sql-result', TRANSFORM_SOURCE_QUERY, TRANSFORM_VALUE)),
      }),
    }),
  });

  const repeatSource = new VizPanel({
    key: 'panel-3',
    title: 'Errors',
    pluginId: 'timeseries',
    $variables: new SceneVariableSet({
      variables: [new LocalValueVariable({ name: 'fn', value: 'billing-fn', text: 'billing-fn' })],
    }),
    $data: new SceneQueryRunner({
      queries: [{ refId: 'A', expression: TARGET_ONLY_EXPRESSION }],
      data: panelData(executedFrame('Errors', REPEATED_PANEL_QUERY, REPEATED_VALUE)),
    }),
  });
  const repeatClone = repeatSource.clone({
    key: 'panel-3-clone-1',
    repeatSourceKey: 'panel-3',
  });

  const scene = new DashboardScene(
    {
      title: 'billing',
      uid: 'dash-billing',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-6h', to: 'now' }),
      body: new DefaultGridLayoutManager({
        grid: new SceneGridLayout({
          children: [
            new DashboardGridItem({
              key: 'grid-item-1',
              x: 0,
              y: 0,
              width: 12,
              height: 8,
              body: cloudwatch,
            }),
            new DashboardGridItem({
              key: 'grid-item-2',
              x: 12,
              y: 0,
              width: 12,
              height: 8,
              body: transformed,
            }),
            new DashboardGridItem({
              key: 'grid-item-3',
              x: 0,
              y: 8,
              width: 24,
              height: 8,
              itemHeight: 8,
              variableName: 'fn',
              repeatDirection: 'h',
              maxPerRow: 2,
              body: repeatSource,
              repeatedPanels: [repeatClone],
            }),
          ],
        }),
      }),
    },
    schema
  );

  if (schema === 'v2') {
    scene.serializer.apiVersion = 'dashboard.grafana.app/v2beta1';
  }

  return scene;
}

// Same JSON shape grafana-plugin-sdk-go writes for a frame and toDataQueryResponse reads back.
function executedFrame(name: string, executedQueryString: string, value: number): DataFrame {
  return dataFrameFromJSON({
    schema: {
      name,
      refId: 'A',
      meta: {
        type: 'timeseries-multi',
        executedQueryString,
        custom: { period: 300, id: 'a' },
      },
      fields: [
        { name: 'Time', type: FieldType.time },
        { name, type: FieldType.number },
      ],
    },
    data: { values: [[1700000000000], [value]] },
  });
}

function executedQueryStrings(value: unknown): string[] {
  const found: string[] = [];
  const visit = (node: unknown) => {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (!node || typeof node !== 'object') {
      return;
    }
    for (const [key, child] of Object.entries(node)) {
      if (key === 'executedQueryString' && typeof child === 'string' && child !== '') {
        found.push(child);
      }
      visit(child);
    }
  };
  visit(value);
  return found;
}

function panelData(series: DataFrame, annotation?: DataFrame): PanelData {
  return {
    series: [series],
    annotations: annotation ? [annotation] : [],
    state: LoadingState.Done,
    timeRange: getDefaultTimeRange(),
  };
}
