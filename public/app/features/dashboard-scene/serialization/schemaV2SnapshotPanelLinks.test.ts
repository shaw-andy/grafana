import { sceneGraph, SceneGridLayout, SceneTimeRange, VizPanel } from '@grafana/scenes';
import { type Spec as DashboardV2Spec } from '@grafana/schema/apis/dashboard.grafana.app/v2';
import {
  getDashboardSnapshotSrv,
  type DashboardSnapshotSrv,
  type SnapshotCreateResponse,
} from 'app/features/dashboard/services/SnapshotSrv';
import { getTimeRange } from 'app/features/dashboard/utils/timeRange';

import { DashboardScene } from '../scene/DashboardScene';
import { VizPanelLinks, VizPanelLinksMenu } from '../scene/PanelLinks';
import { DashboardGridItem } from '../scene/layout-default/DashboardGridItem';
import { DefaultGridLayoutManager } from '../scene/layout-default/DefaultGridLayoutManager';
import { NEW_LINK } from '../settings/links/utils';
import { ShareSnapshot } from '../sharing/ShareButton/share-snapshot/ShareSnapshot';

import { transformSceneToSaveModelSchemaV2, trimDashboardForSnapshot } from './transformSceneToSaveModelSchemaV2';

jest.mock('app/features/dashboard/services/SnapshotSrv', () => ({
  getDashboardSnapshotSrv: jest.fn(),
}));

jest.mock('app/store/store', () => ({
  ...jest.requireActual('app/store/store'),
  dispatch: jest.fn(),
}));

// Distinct from any fixture URL. The query parameter is the part an author would not want published.
const SOURCE_PANEL_URL = 'https://snapshot-leak-probe.example/d/ops-dashboard?db-host=db-1';
const CLONE_PANEL_URL = 'https://snapshot-leak-probe.example/d/ops-dashboard?db-host=db-2';
const OTHER_PANEL_URL = 'https://snapshot-leak-probe.example/d/billing?customer=acme';
const DASHBOARD_URL = 'https://snapshot-leak-probe.example/d/private-home';
const PROBE_HOST = 'snapshot-leak-probe.example';

const SNAPSHOT_TIME = getTimeRange({ from: '2023-01-01T14:00:00.000Z', to: '2023-01-01T20:00:00.000Z' });

describe('schema v2 snapshot panel links', () => {
  let createSnapshot: jest.Mock<Promise<SnapshotCreateResponse>>;

  beforeEach(() => {
    window.localStorage.clear();
    jest.clearAllMocks();
    createSnapshot = jest.fn().mockResolvedValue({ key: 'abc', url: '/dashboard/snapshot/abc', deleteUrl: '' });
    jest.mocked(getDashboardSnapshotSrv).mockReturnValue(buildSnapshotSrv(createSnapshot));
  });

  it('keeps panel link URLs when saving a schema v2 dashboard', () => {
    const scene = buildScene();

    const saved = transformSceneToSaveModelSchemaV2(scene, false);

    expect(panelLinkUrls(saved)).toEqual([SOURCE_PANEL_URL, OTHER_PANEL_URL]);
    expect(saved.links.map((link) => link.url)).toEqual([DASHBOARD_URL]);
  });

  it('removes every panel link URL when trimming a schema v2 snapshot, including repeat clones', () => {
    const scene = buildScene();
    const saveModel = transformSceneToSaveModelSchemaV2(scene, true);

    // The snapshot serializer copies the live panel links into each panel spec before trimming.
    expect(panelLinkUrls(saveModel).sort()).toEqual([CLONE_PANEL_URL, OTHER_PANEL_URL, SOURCE_PANEL_URL].sort());
    expect(saveModel.links.map((link) => link.url)).toEqual([DASHBOARD_URL]);

    const trimmed = trimDashboardForSnapshot('Published snapshot', SNAPSHOT_TIME, saveModel);

    expect(trimmed.title).toBe('Published snapshot');
    expect(trimmed.links).toEqual([]);
    expect(panelLinkUrls(trimmed)).toEqual([]);
    expect(JSON.stringify(trimmed)).not.toContain(PROBE_HOST);
    expect(Object.keys(trimmed.elements)).toEqual(expect.arrayContaining(['panel-10', 'panel-10-clone-1', 'panel-2']));
  });

  it('removes the panel link URL when trimming a single-panel schema v2 snapshot', () => {
    const scene = buildScene();
    const saveModel = transformSceneToSaveModelSchemaV2(scene, true);
    const panel = sceneGraph.findByKey(scene, 'panel-2') as VizPanel;

    const trimmed = trimDashboardForSnapshot('One panel', SNAPSHOT_TIME, saveModel, panel);

    expect(Object.keys(trimmed.elements)).toEqual(['panel-2']);
    expect(panelLinkUrls(trimmed)).toEqual([]);
    expect(JSON.stringify(trimmed)).not.toContain(PROBE_HOST);
    expect(trimmed.links).toEqual([]);
  });

  it.each([
    { external: false, label: 'a local' },
    { external: true, label: 'an external' },
  ])('publishes $label schema v2 snapshot without panel link URLs', async ({ external }) => {
    const scene = buildScene();
    const tab = parentShare(scene);

    await tab.onSnapshotCreate(external);

    expect(createSnapshot).toHaveBeenCalledTimes(1);
    const command = createSnapshot.mock.calls[0][0];
    expect(command.external).toBe(external);
    const published = command.dashboard as DashboardV2Spec;
    expect(published.elements).toBeDefined();
    expect(published).not.toHaveProperty('panels');
    expect(panelLinkUrls(published)).toEqual([]);
    expect(published.links).toEqual([]);
    expect(JSON.stringify(published)).not.toContain(PROBE_HOST);
  });

  it('publishes a single-panel schema v2 snapshot without that panel link URL', async () => {
    const scene = buildScene();
    const panel = sceneGraph.findByKey(scene, 'panel-2') as VizPanel;
    const tab = parentShare(scene, panel);

    await tab.onSnapshotCreate(true);

    const published = createSnapshot.mock.calls[0][0].dashboard as DashboardV2Spec;
    expect(createSnapshot.mock.calls[0][0].external).toBe(true);
    expect(Object.keys(published.elements)).toEqual(['panel-2']);
    expect(panelLinkUrls(published)).toEqual([]);
    expect(published.links).toEqual([]);
    expect(JSON.stringify(published)).not.toContain(PROBE_HOST);
  });
});

function panelLinkUrls(spec: DashboardV2Spec): string[] {
  return Object.values(spec.elements).flatMap((element) => {
    if (element.kind !== 'Panel') {
      return [];
    }
    return element.spec.links.map((link) => link.url);
  });
}

function panelWithLink(key: string, url: string): VizPanel {
  return new VizPanel({
    key,
    pluginId: 'timeseries',
    title: 'Panel',
    titleItems: [
      new VizPanelLinks({
        rawLinks: [{ title: 'Internal', url, targetBlank: false }],
        menu: new VizPanelLinksMenu({}),
      }),
    ],
  });
}

function buildScene(): DashboardScene {
  const source = panelWithLink('panel-10', SOURCE_PANEL_URL);
  const clone = source.clone({ key: 'panel-10-clone-1', repeatSourceKey: source.state.key });
  clone.setState({
    titleItems: [
      new VizPanelLinks({
        rawLinks: [{ title: 'Clone', url: CLONE_PANEL_URL, targetBlank: false }],
        menu: new VizPanelLinksMenu({}),
      }),
    ],
  });

  const scene = new DashboardScene(
    {
      title: 'Ops',
      uid: 'dash-1',
      links: [{ ...NEW_LINK, title: 'Home', url: DASHBOARD_URL, type: 'link' }],
      $timeRange: new SceneTimeRange({ from: 'now-6h', to: 'now' }),
      body: new DefaultGridLayoutManager({
        grid: new SceneGridLayout({
          children: [
            new DashboardGridItem({
              key: 'grid-item-10',
              x: 0,
              y: 0,
              width: 12,
              height: 8,
              body: source,
              variableName: 'server',
              repeatedPanels: [clone],
            }),
            new DashboardGridItem({
              key: 'grid-item-2',
              x: 12,
              y: 0,
              width: 12,
              height: 8,
              body: panelWithLink('panel-2', OTHER_PANEL_URL),
            }),
          ],
        }),
      }),
    },
    'v2'
  );

  // Loaded v2 resources store the Kubernetes apiVersion here. Share snapshot uses it to pick the v2 trimmer.
  scene.serializer.apiVersion = 'dashboard.grafana.app/v2beta1';
  return scene;
}

function parentShare(scene: DashboardScene, panel?: VizPanel): ShareSnapshot {
  const tab = new ShareSnapshot({
    dashboardRef: scene.getRef(),
    panelRef: panel?.getRef(),
    onDismiss: () => {},
  });
  scene.setState({ overlay: tab });
  return tab;
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
