import { type TimeRange } from '@grafana/data';
import { QueryVariable, SceneVariableSet, sceneUtils } from '@grafana/scenes';
import { type Dashboard } from '@grafana/schema';
import { type QueryVariableKind } from '@grafana/schema/apis/dashboard.grafana.app/v2';
import { DashboardModel } from 'app/features/dashboard/state/DashboardModel';
import { getTimeRange } from 'app/features/dashboard/utils/timeRange';
import { variableAdapters } from 'app/features/variables/adapters';
import { createQueryVariableAdapter } from 'app/features/variables/query/adapter';
import { type DashboardDataDTO } from 'app/types/dashboard';

import { ShareSnapshot } from '../../dashboard/components/ShareModal/ShareSnapshot';
import { getDashboardSnapshotSrv } from '../../dashboard/services/SnapshotSrv';
import { DashboardScene } from '../scene/DashboardScene';
import { DefaultGridLayoutManager } from '../scene/layout-default/DefaultGridLayoutManager';
import { transformSaveModelToScene } from '../serialization/transformSaveModelToScene';
import { transformSceneToSaveModel, trimDashboardForSnapshot } from '../serialization/transformSceneToSaveModel';
import {
  transformSceneToSaveModelSchemaV2,
  trimDashboardForSnapshot as trimDashboardForSnapshotV2,
} from '../serialization/transformSceneToSaveModelSchemaV2';

import { ShareSnapshotTab } from './ShareSnapshotTab';

jest.mock('../../dashboard/services/SnapshotSrv', () => ({
  getDashboardSnapshotSrv: jest.fn(),
}));

jest.mock('app/store/store', () => ({
  ...jest.requireActual('app/store/store'),
  dispatch: jest.fn(),
}));

jest.mock('app/features/dashboard/services/TimeSrv', () => {
  const actual = jest.requireActual('app/features/dashboard/services/TimeSrv');
  return {
    ...actual,
    getTimeSrv: () => ({
      timeRange: () => ({
        from: '2023-01-01T14:00:00.000Z',
        to: '2023-01-01T20:00:00.000Z',
      }),
    }),
  };
});

// Readable copies of the variable queries an editor was told would be removed.
const PROMQL = 'label_values(up{cluster="prod"}, namespace)';
const LOGQL = '{namespace="prod"} |= "error"';
const LEGACY_OBJECT_QUERY = 'label_values(backend)';

const TEMPLATE_QUERIES = [PROMQL, LOGQL, LEGACY_OBJECT_QUERY];

variableAdapters.setInit(() => [createQueryVariableAdapter()]);

interface PublishedQueryVariable {
  name: string;
  query: unknown;
  definition?: string;
}

describe('snapshot template query removal', () => {
  let createSnapshot: jest.Mock;

  beforeEach(() => {
    createSnapshot = jest.fn().mockResolvedValue({ key: 'snap-key', url: '/dashboard/snapshot/snap-key', deleteUrl: '' });
    jest.mocked(getDashboardSnapshotSrv).mockReturnValue({
      create: createSnapshot,
      getSnapshots: jest.fn(),
      getSharingOptions: jest.fn().mockResolvedValue({
        externalEnabled: true,
        externalSnapshotName: 'Publish to snapshots.raintank.io',
        externalSnapshotURL: 'https://snapshots.raintank.io',
        snapshotEnabled: true,
      }),
      deleteSnapshot: jest.fn(),
      getSnapshot: jest.fn(),
    });
  });

  describe('schema v1 trimDashboardForSnapshot', () => {
    it('clears definition on query variables after the save model copies it', () => {
      const scene = buildScene();
      expect(queryDefinitions(scene)).toEqual([PROMQL, LOGQL, LEGACY_OBJECT_QUERY]);

      const saveModel = transformSceneToSaveModel(scene, true);
      const published = trimDashboardForSnapshot('Shared snapshot', snapshotTimeRange(), saveModel);

      expectPublishedQueriesRemoved(v1QueryVariables(published));
    });
  });

  describe('schema v2 trimDashboardForSnapshot', () => {
    it('clears spec.definition on query variables after the save model copies it', () => {
      const scene = buildScene('v2');
      expect(queryDefinitions(scene)).toEqual([PROMQL, LOGQL, LEGACY_OBJECT_QUERY]);

      const saveModel = transformSceneToSaveModelSchemaV2(scene, true);
      const published = trimDashboardForSnapshotV2('Shared snapshot', snapshotTimeRange(), saveModel);

      expectPublishedQueriesRemoved(v2QueryVariables(published.variables));
    });
  });

  describe('ShareSnapshotTab.prepareSnapshot', () => {
    it.each([
      { external: false, label: 'local' },
      { external: true, label: 'external' },
    ])('publishes a schema v1 $label snapshot without template queries', async ({ external }) => {
      const scene = transformSaveModelToScene({
        dashboard: savedDashboard() as DashboardDataDTO,
        meta: {},
      });
      expect(queryDefinitions(scene)).toEqual([PROMQL, LOGQL, LEGACY_OBJECT_QUERY]);

      await publishSceneSnapshot(scene, external);

      const command = createSnapshot.mock.calls[0][0];
      expect(command.external).toBe(external);
      expect(command.dashboard.templating).toBeDefined();
      expectPublishedQueriesRemoved(v1QueryVariables(command.dashboard));
    });

    it.each([
      { external: false, label: 'local' },
      { external: true, label: 'external' },
    ])('publishes a schema v2 $label snapshot without template queries', async ({ external }) => {
      const scene = buildScene('v2');
      scene.setInitialSaveModel(undefined, undefined, 'dashboard.grafana.app/v2beta1');
      expect(queryDefinitions(scene)).toEqual([PROMQL, LOGQL, LEGACY_OBJECT_QUERY]);

      await publishSceneSnapshot(scene, external);

      const command = createSnapshot.mock.calls[0][0];
      expect(command.external).toBe(external);
      expect(Array.isArray(command.dashboard.variables)).toBe(true);
      expectPublishedQueriesRemoved(v2QueryVariables(command.dashboard.variables));
    });
  });

  describe('legacy ShareSnapshot.saveSnapshot', () => {
    it.each([
      { external: false, label: 'local' },
      { external: true, label: 'external' },
    ])('posts a $label snapshot whose query variable definition is cleared', async ({ external }) => {
      const dashboard = savedDashboard();
      const model = new DashboardModel(dashboard, {}, {
        getVariablesFromState: () => dashboard.templating.list,
      });
      const tab = new ShareSnapshot({ dashboard: model });
      // saveSnapshot updates React state after the snapshot is posted. This instance is not
      // mounted, and React warns on that setState. Keep the post and the scrub, and apply the
      // state update directly so the warning is not part of the result.
      tab.setState = (update) => {
        const partial = typeof update === 'function' ? update(tab.state) : update;
        tab.state = { ...tab.state, ...partial };
      };

      await tab.saveSnapshot(model, external);

      const command = createSnapshot.mock.calls[0][0];
      expect(command.external).toBe(external);
      expectPublishedQueriesRemoved(v1QueryVariables(command.dashboard));
    });
  });
});

function expectPublishedQueriesRemoved(variables: PublishedQueryVariable[]) {
  expect(
    variables.map((variable) => ({
      name: variable.name,
      definition: variable.definition ?? '',
      query: variable.query,
    }))
  ).toEqual([
    { name: 'env', definition: '', query: '' },
    { name: 'logs', definition: '', query: '' },
    { name: 'backend', definition: '', query: '' },
  ]);

  const published = JSON.stringify(variables);
  for (const query of TEMPLATE_QUERIES) {
    expect(published).not.toContain(query);
  }
}

function v1QueryVariables(dashboard: Dashboard): PublishedQueryVariable[] {
  return (dashboard.templating?.list ?? [])
    .filter((variable) => variable.type === 'query')
    .map((variable) => ({
      name: variable.name,
      query: variable.query,
      definition: 'definition' in variable && typeof variable.definition === 'string' ? variable.definition : undefined,
    }));
}

function v2QueryVariables(variables: QueryVariableKind[]): PublishedQueryVariable[] {
  return variables
    .filter((variable) => variable.kind === 'QueryVariable')
    .map((variable) => ({
      name: variable.spec.name,
      query: variable.spec.query,
      definition: variable.spec.definition,
    }));
}

function queryDefinitions(scene: DashboardScene): string[] {
  const set = scene.state.$variables;
  if (!(set instanceof SceneVariableSet)) {
    throw new Error('dashboard scene has no variable set');
  }

  return set.state.variables.filter(sceneUtils.isQueryVariable).map((variable) => variable.state.definition ?? '');
}

function buildScene(serializerVersion: 'v1' | 'v2' = 'v1'): DashboardScene {
  return new DashboardScene(
    {
      title: 'Shared dashboard',
      uid: 'dash-1',
      $variables: new SceneVariableSet({
        variables: [
          new QueryVariable({
            name: 'env',
            query: PROMQL,
            definition: PROMQL,
            datasource: { uid: 'prom', type: 'prometheus' },
            value: 'prod',
            text: 'prod',
          }),
          new QueryVariable({
            name: 'logs',
            query: LOGQL,
            definition: LOGQL,
            datasource: { uid: 'loki', type: 'loki' },
            value: 'prod',
            text: 'prod',
          }),
          new QueryVariable({
            name: 'backend',
            query: { qryType: 1, query: LEGACY_OBJECT_QUERY, refId: 'VariableQuery' },
            definition: LEGACY_OBJECT_QUERY,
            datasource: { uid: 'prom', type: 'prometheus' },
            value: 'annotations',
            text: 'annotations',
          }),
        ],
      }),
      body: DefaultGridLayoutManager.fromVizPanels([]),
    },
    serializerVersion
  );
}

function savedDashboard() {
  return {
    title: 'Shared dashboard',
    uid: 'dash-1',
    schemaVersion: 42,
    version: 1,
    editable: true,
    time: { from: 'now-6h', to: 'now' },
    panels: [],
    annotations: { list: [] },
    templating: {
      list: [
        {
          name: 'env',
          type: 'query',
          query: PROMQL,
          definition: PROMQL,
          datasource: { type: 'prometheus', uid: 'prom' },
          current: { text: 'prod', value: 'prod', selected: true },
          options: [{ text: 'prod', value: 'prod', selected: true }],
          refresh: 1,
          regex: '',
          hide: 0,
          sort: 0,
        },
        {
          name: 'logs',
          type: 'query',
          query: LOGQL,
          definition: LOGQL,
          datasource: { type: 'loki', uid: 'loki' },
          current: { text: 'prod', value: 'prod' },
          options: [],
          refresh: 1,
          regex: '',
          hide: 0,
          sort: 0,
        },
        {
          name: 'backend',
          type: 'query',
          query: { qryType: 1, query: LEGACY_OBJECT_QUERY, refId: 'VariableQuery' },
          definition: LEGACY_OBJECT_QUERY,
          datasource: { type: 'prometheus', uid: 'prom' },
          current: { text: 'annotations', value: 'annotations' },
          options: [],
          refresh: 1,
          regex: '',
          hide: 0,
          sort: 0,
        },
      ],
    },
  };
}

function snapshotTimeRange(): TimeRange {
  return getTimeRange({ from: 'now-6h', to: 'now' });
}

async function publishSceneSnapshot(scene: DashboardScene, external: boolean) {
  const tab = new ShareSnapshotTab({ dashboardRef: scene.getRef() });
  scene.setState({ overlay: tab });
  await tab.onSnapshotCreate(external);
}
