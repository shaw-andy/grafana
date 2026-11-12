import { dateTime, type TimeRange } from '@grafana/data';
import { getPanelPlugin } from '@grafana/data/test';
import { setPluginImportUtils } from '@grafana/runtime';
import { dataLayers, QueryVariable, SceneVariableSet, VizPanel } from '@grafana/scenes';
import {
  defaultSpec as defaultDashboardV2Spec,
  type AnnotationQueryKind,
  type Spec as DashboardV2Spec,
  type TextVariableKind,
} from '@grafana/schema/apis/dashboard.grafana.app/v2';
import { getDashboardSnapshotSrv } from 'app/features/dashboard/services/SnapshotSrv';

import { DashboardDataLayerSet } from '../scene/DashboardDataLayerSet';
import { DashboardScene } from '../scene/DashboardScene';
import { DefaultGridLayoutManager } from '../scene/layout-default/DefaultGridLayoutManager';
import { transformSceneToSaveModelSchemaV2, trimDashboardForSnapshot } from '../serialization/transformSceneToSaveModelSchemaV2';

import { ShareSnapshotTab } from './ShareSnapshotTab';

jest.mock('app/features/dashboard/services/SnapshotSrv', () => ({
  getDashboardSnapshotSrv: jest.fn(),
}));

jest.mock('app/store/store', () => ({
  ...jest.requireActual('app/store/store'),
  dispatch: jest.fn(),
}));

setPluginImportUtils({
  importPanelPlugin: () => Promise.resolve(getPanelPlugin({})),
  getPanelPluginFromCache: () => undefined,
});

// Tokens are unique so a query that survives under another field still fails the test.
const PROM_EXPR = 'sum(rate(payments_api_annotation_query[5m]))';
const PROM_DS_UID = 'prom_ds_uid_annotation_7f3a';
const SQL = 'SELECT secret_col FROM billing_customers_annotation_query WHERE id = 42';
const SQL_DS_UID = 'mysql_ds_uid_annotation_9c1e';
const DISABLED_SQL = 'SELECT secret_col FROM disabled_annotation_query_secret WHERE id = 1';
const BUILTIN_TAG = 'builtin_annotation_query_internal_release';
const VARIABLE_QUERY = 'variable_query_should_be_cleared';

const LEAKED = [PROM_EXPR, PROM_DS_UID, SQL, SQL_DS_UID, DISABLED_SQL, BUILTIN_TAG];

function absoluteRange(): TimeRange {
  return {
    from: dateTime('2023-01-01T14:00:00.000Z'),
    to: dateTime('2023-01-01T20:00:00.000Z'),
    raw: { from: 'now-6h', to: 'now' },
  };
}

function annotation(spec: AnnotationQueryKind['spec']): AnnotationQueryKind {
  return { kind: 'AnnotationQuery', spec };
}

function v2Dashboard(): DashboardV2Spec {
  const textVariable: TextVariableKind = {
    kind: 'TextVariable',
    spec: {
      name: 'metric',
      current: { text: 'up', value: 'up' },
      query: VARIABLE_QUERY,
      hide: 'dontHide',
      skipUrlSync: false,
    },
  };

  return {
    ...defaultDashboardV2Spec(),
    title: 'Annotated dashboard',
    variables: [textVariable],
    annotations: [
      annotation({
        name: 'Prom annotations',
        enable: true,
        hide: false,
        iconColor: 'red',
        builtIn: false,
        query: {
          kind: 'DataQuery',
          group: 'prometheus',
          version: 'v0',
          datasource: { name: PROM_DS_UID },
          spec: { expr: PROM_EXPR, refId: 'Anno' },
        },
      }),
      annotation({
        name: 'SQL annotations',
        enable: true,
        hide: false,
        iconColor: 'blue',
        builtIn: false,
        query: {
          kind: 'DataQuery',
          group: 'mysql',
          version: 'v0',
          datasource: { name: SQL_DS_UID },
          spec: { rawSql: SQL, refId: 'Anno' },
        },
      }),
      annotation({
        name: 'Disabled SQL',
        enable: false,
        hide: true,
        iconColor: 'purple',
        builtIn: false,
        query: {
          kind: 'DataQuery',
          group: 'mysql',
          version: 'v0',
          datasource: { name: SQL_DS_UID },
          spec: { rawSql: DISABLED_SQL, refId: 'Anno' },
        },
      }),
      annotation({
        name: 'Built-in annotations',
        enable: true,
        hide: true,
        iconColor: 'rgba(0, 211, 255, 1)',
        builtIn: true,
        query: {
          kind: 'DataQuery',
          group: 'grafana',
          version: 'v0',
          datasource: { name: 'grafana' },
          spec: { tags: [BUILTIN_TAG], type: 'dashboard', limit: 100 },
        },
      }),
    ],
  };
}

function expectAnnotationQueriesRemoved(published: DashboardV2Spec) {
  const encoded = JSON.stringify(published);
  for (const secret of LEAKED) {
    expect(encoded).not.toContain(secret);
  }
  expect(encoded).not.toContain(VARIABLE_QUERY);

  const byName = new Map(published.annotations.map((annotation) => [annotation.spec.name, annotation]));
  expect(byName.has('Disabled SQL')).toBe(false);

  for (const name of ['Prom annotations', 'SQL annotations', 'Built-in annotations']) {
    const layer = byName.get(name);
    expect(layer).toBeDefined();
    expect(layer?.spec.query.datasource).toBeUndefined();
    expect(layer?.spec.query.group).toBe('');
    expect(layer?.spec.query.spec).toEqual({});
  }

  const variable = published.variables[0];
  expect(variable.kind).toBe('TextVariable');
  if (variable.kind === 'TextVariable') {
    expect(variable.spec.query).toBe('');
  }
}

describe('schema v2 snapshot annotation queries', () => {
  describe('trimDashboardForSnapshot', () => {
    it('drops prometheus and SQL annotation targets while keeping the layer name and color', () => {
      const source = v2Dashboard();
      const sourceBefore = JSON.stringify(source);

      const published = trimDashboardForSnapshot('Snap title', absoluteRange(), source);

      expect(sourceBefore).toContain(PROM_EXPR);
      expect(sourceBefore).toContain(SQL);
      expect(JSON.stringify(source)).toContain(PROM_EXPR);
      expect(JSON.stringify(source)).toContain(SQL);
      expectAnnotationQueriesRemoved(published);
      expect(published.annotations.find((layer) => layer.spec.name === 'Prom annotations')?.spec.iconColor).toBe('red');
      expect(published.annotations.find((layer) => layer.spec.name === 'Prom annotations')?.spec.enable).toBe(true);
      expect(published.annotations.find((layer) => layer.spec.name === 'SQL annotations')?.spec.iconColor).toBe('blue');
    });

    it('drops annotation targets when the snapshot is limited to one panel', () => {
      const source = v2Dashboard();
      source.elements = {
        'panel-1': {
          kind: 'Panel',
          spec: {
            id: 1,
            title: 'Requests',
            description: '',
            links: [],
            data: { kind: 'QueryGroup', spec: { queries: [], transformations: [], queryOptions: {} } },
            vizConfig: {
              kind: 'VizConfig',
              group: 'timeseries',
              version: '',
              spec: { options: {}, fieldConfig: { defaults: {}, overrides: [] } },
            },
          },
        },
      };
      const panel = new VizPanel({ key: 'panel-1', pluginId: 'timeseries', title: 'Requests' });

      const published = trimDashboardForSnapshot('Snap title', absoluteRange(), source, panel);

      expectAnnotationQueriesRemoved(published);
      expect(Object.keys(published.elements)).toEqual(['panel-1']);
    });
  });

  describe('ShareSnapshotTab', () => {
    const createSnapshot = jest.fn().mockResolvedValue({ key: 'abc', url: '/dashboard/snapshot/abc', deleteUrl: '' });

    beforeEach(() => {
      window.localStorage.clear();
      createSnapshot.mockClear();
      jest.mocked(getDashboardSnapshotSrv).mockReturnValue({
        create: createSnapshot,
        getSnapshots: jest.fn(),
        getSharingOptions: jest.fn().mockResolvedValue({}),
        deleteSnapshot: jest.fn(),
        getSnapshot: jest.fn(),
      });
    });

    function sceneWithAnnotationQueries(): { scene: DashboardScene; panel: VizPanel } {
      const panel = new VizPanel({ key: 'panel-1', pluginId: 'timeseries', title: 'Requests' });
      const scene = new DashboardScene(
        {
          title: 'Annotated dashboard',
          uid: 'dashuid01',
          meta: { canEdit: true },
          $variables: new SceneVariableSet({
            variables: [
              new QueryVariable({
                name: 'metric',
                query: VARIABLE_QUERY,
                value: 'up',
                text: 'up',
              }),
            ],
          }),
          $data: new DashboardDataLayerSet({
            annotationLayers: [
              new dataLayers.AnnotationsDataLayer({
                name: 'Prom annotations',
                isEnabled: true,
                isHidden: false,
                query: {
                  name: 'Prom annotations',
                  enable: true,
                  hide: false,
                  iconColor: 'red',
                  datasource: { type: 'prometheus', uid: PROM_DS_UID },
                  target: { expr: PROM_EXPR, refId: 'Anno' },
                },
              }),
              new dataLayers.AnnotationsDataLayer({
                name: 'SQL annotations',
                isEnabled: true,
                isHidden: false,
                query: {
                  name: 'SQL annotations',
                  enable: true,
                  hide: false,
                  iconColor: 'blue',
                  datasource: { type: 'mysql', uid: SQL_DS_UID },
                  target: { rawSql: SQL, refId: 'Anno' },
                },
              }),
              new dataLayers.AnnotationsDataLayer({
                name: 'Disabled SQL',
                isEnabled: false,
                isHidden: true,
                query: {
                  name: 'Disabled SQL',
                  enable: false,
                  hide: true,
                  iconColor: 'purple',
                  datasource: { type: 'mysql', uid: SQL_DS_UID },
                  target: { rawSql: DISABLED_SQL, refId: 'Anno' },
                },
              }),
              new dataLayers.AnnotationsDataLayer({
                name: 'Built-in annotations',
                isEnabled: true,
                isHidden: true,
                query: {
                  name: 'Built-in annotations',
                  enable: true,
                  hide: true,
                  iconColor: 'rgba(0, 211, 255, 1)',
                  builtIn: 1,
                  type: 'dashboard',
                  datasource: { type: 'grafana', uid: '-- Grafana --' },
                  target: { tags: [BUILTIN_TAG], type: 'dashboard', limit: 100 },
                },
              }),
            ],
          }),
          body: DefaultGridLayoutManager.fromVizPanels([panel]),
        },
        'v2'
      );
      scene.setInitialSaveModel(defaultDashboardV2Spec(), { name: 'dashuid01' }, 'dashboard.grafana.app/v2');
      return { scene, panel };
    }

    async function publish(external: boolean, singlePanel: boolean) {
      const { scene, panel } = sceneWithAnnotationQueries();
      const tab = new ShareSnapshotTab({
        dashboardRef: scene.getRef(),
        panelRef: singlePanel ? panel.getRef() : undefined,
      });
      scene.setState({ overlay: tab });

      const untrimmed = transformSceneToSaveModelSchemaV2(scene, true);
      const untrimmedJson = JSON.stringify(untrimmed);
      expect(untrimmedJson).toContain(PROM_EXPR);
      expect(untrimmedJson).toContain(PROM_DS_UID);
      expect(untrimmedJson).toContain(SQL);
      expect(untrimmedJson).toContain(SQL_DS_UID);
      expect(untrimmedJson).toContain(DISABLED_SQL);
      expect(untrimmedJson).toContain(BUILTIN_TAG);

      await tab.onSnapshotCreate(external);

      expect(createSnapshot).toHaveBeenCalledTimes(1);
      const command = createSnapshot.mock.calls[0][0] as { dashboard: DashboardV2Spec; external: boolean };
      expect(command.external).toBe(external);
      expectAnnotationQueriesRemoved(command.dashboard);
    }

    it('publishes a local snapshot without annotation query text', async () => {
      await publish(false, false);
    });

    it('publishes an external snapshot without annotation query text', async () => {
      await publish(true, false);
    });

    it('publishes a single-panel snapshot without annotation query text', async () => {
      await publish(false, true);
    });
  });
});
