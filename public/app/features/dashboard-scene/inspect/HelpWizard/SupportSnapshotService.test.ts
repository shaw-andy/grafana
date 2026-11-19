import saveAs from 'file-saver';

import { FieldType, getDefaultTimeRange, LoadingState, toDataFrame, type DataFrame } from '@grafana/data';
import { SceneQueryRunner, SceneTimeRange, VizPanel, VizPanelMenu } from '@grafana/scenes';

jest.mock('file-saver', () => jest.fn());

import { DashboardScene } from '../../scene/DashboardScene';
import { VizPanelLinks, VizPanelLinksMenu } from '../../scene/PanelLinks';
import { panelMenuBehavior } from '../../scene/PanelMenuBehavior';
import { DefaultGridLayoutManager } from '../../scene/layout-default/DefaultGridLayoutManager';

import { SnapshotTab, SupportSnapshotService } from './SupportSnapshotService';

async function setup() {
  const { panel } = await buildTestScene();

  return new SupportSnapshotService(panel);
}

describe('SupportSnapshotService', () => {
  it('Can create it with default state', async () => {
    const service = await setup();
    expect(service.state.currentTab).toBe(SnapshotTab.Support);
  });

  it('Can can build support snapshot dashboard', async () => {
    const service = await setup();
    await service.buildDebugDashboard();
    expect(service.state.snapshot.panels[0].targets[0]).toMatchInlineSnapshot(`
      {
        "datasource": {
          "type": "grafana",
          "uid": "grafana",
        },
        "queryType": "snapshot",
        "refId": "A",
        "snapshot": [
          {
            "data": {
              "values": [
                [
                  1,
                  2,
                  3,
                ],
                [
                  11,
                  22,
                  33,
                ],
              ],
            },
            "schema": {
              "fields": [
                {
                  "config": {},
                  "name": "Time",
                  "type": "time",
                },
                {
                  "config": {},
                  "name": "Value",
                  "type": "number",
                },
              ],
              "meta": undefined,
              "name": "http_requests_total",
              "refId": undefined,
            },
          },
        ],
      }
    `);
  });

  it('redacts label names in the github comment and downloaded dashboard when Labels is on', async () => {
    const { panel, queryRunner } = await buildLabeledScene();
    const service = new SupportSnapshotService(panel);

    service.onToggleRandomize('labels');
    expect(service.state.randomize).toEqual({ labels: true });
    await service.buildDebugDashboard();

    const markdown = service.onGetMarkdownForClipboard();
    service.onDownloadDashboard();
    const downloaded = await blobText(jest.mocked(saveAs).mock.calls[0][0] as Blob);

    expect(markdown).toContain('Panel debug snapshot dashboard');
    expect(downloaded).toBe(service.state.snapshotText);
    expect(queryRunner.state.data?.series[0].fields[1].labels).toEqual({
      acctowner: 'aliceperson',
      hostbox: 'webnode',
      exemplar: 'morningshift',
      __name__: 'metricname',
    });
    expect(queryRunner.state.data?.annotations?.[0].fields[0].labels).toEqual({
      namespaceid: 'prodcluster',
      owner_id: 'patperson',
    });

    expectPublishedLabelNamesRedacted(markdown);
    expectPublishedLabelNamesRedacted(downloaded);
    expectRedactedEmbeddedLabels(service.state.snapshot);
  });
});

const secretLabelText = [
  'acctowner',
  'hostbox',
  'exemplar',
  '__name__',
  'namespaceid',
  'owner_id',
  'aliceperson',
  'carolperson',
  'webnode',
  'morningshift',
  'metricname',
  'prodcluster',
  'patperson',
];

function expectPublishedLabelNamesRedacted(published: string) {
  for (const secret of secretLabelText) {
    expect(published).not.toContain(secret);
  }
}

type LabelMap = Record<string, string>;
interface LabelField {
  labels?: LabelMap;
}
interface EmbeddedFrame {
  schema?: { fields?: LabelField[] };
}
interface EmbeddedTarget {
  snapshot?: EmbeddedFrame[];
}
interface EmbeddedPanel {
  targets?: EmbeddedTarget[];
}
interface EmbeddedSnapshot {
  panels: EmbeddedPanel[];
}

function expectRedactedEmbeddedLabels(snapshot: EmbeddedSnapshot) {
  const maps =
    snapshot.panels[0].targets?.[0].snapshot?.flatMap((frame) =>
      (frame.schema?.fields ?? []).flatMap((field) => (field.labels ? [field.labels] : []))
    ) ?? [];
  expect(maps).toHaveLength(3);

  const series = maps.filter((labels) => Object.keys(labels).some((key) => /^[a-z]{9}$/.test(key)));
  expect(series).toHaveLength(2);
  const acctowner = keyMatching(series[0], /^[a-z]{9}$/);
  const hostbox = keyMatching(series[0], /^[a-z]{7}$/);
  expect(keyMatching(series[1], /^[a-z]{9}$/)).toBe(acctowner);
  expect(keyMatching(series[1], /^[a-z]{7}$/)).toBe(hostbox);
  expect(acctowner).not.toBe('acctowner');
  expect(hostbox).not.toBe('hostbox');
  expect(keyMatching(series[0], /^[a-z]{8}$/)).not.toBe('exemplar');
  expect(keyMatching(series[0], /^__[a-z]{4}__$/)).not.toBe('__name__');
  expect(series[0][acctowner]).toMatch(/^[a-z]{11}$/);
  expect(series[0][acctowner]).not.toBe('aliceperson');
  expect(series[1][acctowner]).not.toBe(series[0][acctowner]);
  expect(series[0][hostbox]).toBe(series[1][hostbox]);
  expect(series[0][hostbox]).not.toBe('webnode');

  const annotation = maps.find((labels) => Object.keys(labels).some((key) => /^[a-z]{5}_[a-z]{2}$/.test(key)));
  expect(annotation).toBeDefined();
  const namespaceid = keyMatching(annotation!, /^[a-z]{11}$/);
  const ownerId = keyMatching(annotation!, /^[a-z]{5}_[a-z]{2}$/);
  expect(namespaceid).not.toBe('namespaceid');
  expect(ownerId).not.toBe('owner_id');
  expect(annotation![namespaceid]).not.toBe('prodcluster');
  expect(annotation![ownerId]).not.toBe('patperson');
}

function keyMatching(labels: Record<string, string>, pattern: RegExp): string {
  const keys = Object.keys(labels).filter((key) => pattern.test(key));
  expect(keys).toHaveLength(1);
  return keys[0];
}

async function blobText(blob: Blob): Promise<string> {
  return blob.text();
}

async function buildTestScene() {
  const menu = new VizPanelMenu({
    $behaviors: [panelMenuBehavior],
  });

  const panel = new VizPanel({
    title: 'Panel A',
    pluginId: 'timeseries',
    key: 'panel-12',
    menu,
    titleItems: [new VizPanelLinks({ menu: new VizPanelLinksMenu({}) })],
    $data: new SceneQueryRunner({
      data: {
        state: LoadingState.Done,
        series: [
          toDataFrame({
            name: 'http_requests_total',
            fields: [
              { name: 'Time', type: FieldType.time, values: [1, 2, 3] },
              { name: 'Value', type: FieldType.number, values: [11, 22, 33] },
            ],
          }),
        ],
        timeRange: getDefaultTimeRange(),
      },
      datasource: { uid: 'my-uid' },
      queries: [{ query: 'QueryA', refId: 'A' }],
    }),
  });

  const scene = new DashboardScene({
    title: 'My dashboard',
    uid: 'dash-1',
    tags: ['database', 'panel'],
    $timeRange: new SceneTimeRange({
      from: 'now-5m',
      to: 'now',
      timeZone: 'Africa/Abidjan',
    }),
    meta: {
      canEdit: true,
      isEmbedded: false,
    },
    body: DefaultGridLayoutManager.fromVizPanels([panel]),
  });

  await new Promise((r) => setTimeout(r, 1));

  return { scene, panel, menu };
}

async function buildLabeledScene() {
  const seriesA = labeledSeries({
    acctowner: 'aliceperson',
    hostbox: 'webnode',
    exemplar: 'morningshift',
    __name__: 'metricname',
  });
  const seriesB = labeledSeries({
    acctowner: 'carolperson',
    hostbox: 'webnode',
  });
  const annotation = toDataFrame({
    name: 'annotation',
    fields: [
      {
        name: 'text',
        type: FieldType.string,
        values: ['note'],
        labels: {
          namespaceid: 'prodcluster',
          owner_id: 'patperson',
        },
      },
    ],
  });
  const queryRunner = new SceneQueryRunner({
    data: {
      state: LoadingState.Done,
      series: [seriesA, seriesB],
      annotations: [annotation],
      timeRange: getDefaultTimeRange(),
    },
    datasource: { uid: 'my-uid' },
    queries: [{ query: 'QueryA', refId: 'A' }],
  });
  const panel = new VizPanel({
    title: 'Panel A',
    pluginId: 'timeseries',
    key: 'panel-12',
    $data: queryRunner,
  });

  new DashboardScene({
    title: 'My dashboard',
    uid: 'dash-1',
    $timeRange: new SceneTimeRange({
      from: 'now-5m',
      to: 'now',
      timeZone: 'Africa/Abidjan',
    }),
    meta: {
      canEdit: true,
      isEmbedded: false,
    },
    body: DefaultGridLayoutManager.fromVizPanels([panel]),
  });

  await new Promise((r) => setTimeout(r, 1));

  return { panel, queryRunner };
}

function labeledSeries(labels: Record<string, string>): DataFrame {
  return toDataFrame({
    name: 'http_requests_total',
    fields: [
      { name: 'Time', type: FieldType.time, values: [1, 2, 3] },
      { name: 'Value', type: FieldType.number, values: [11, 22, 33], labels },
    ],
  });
}
