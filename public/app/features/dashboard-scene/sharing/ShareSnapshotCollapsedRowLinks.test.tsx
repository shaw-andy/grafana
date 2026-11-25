import { screen } from '@testing-library/react';
import { render } from 'test/test-utils';

import { type GrafanaConfig, locationUtil } from '@grafana/data';
import { getPanelPlugin } from '@grafana/data/test';
import { setPluginImportUtils } from '@grafana/runtime';
import { SceneGridLayout, SceneGridRow, SceneTimeRange, VizPanel } from '@grafana/scenes';
import { type Dashboard, type Panel, type RowPanel } from '@grafana/schema';
import {
  getDashboardSnapshotSrv,
  type DashboardSnapshotSrv,
  type SnapshotCreateResponse,
} from 'app/features/dashboard/services/SnapshotSrv';
import { type DashboardDataDTO } from 'app/types/dashboard';

import { DashboardScene } from '../scene/DashboardScene';
import { VizPanelLinks, VizPanelLinksMenu } from '../scene/PanelLinks';
import { AutoGridItem } from '../scene/layout-auto-grid/AutoGridItem';
import { AutoGridLayout } from '../scene/layout-auto-grid/AutoGridLayout';
import { AutoGridLayoutManager } from '../scene/layout-auto-grid/AutoGridLayoutManager';
import { DashboardGridItem } from '../scene/layout-default/DashboardGridItem';
import { DefaultGridLayoutManager } from '../scene/layout-default/DefaultGridLayoutManager';
import { RowItem } from '../scene/layout-rows/RowItem';
import { RowsLayoutManager } from '../scene/layout-rows/RowsLayoutManager';
import { TabItem } from '../scene/layout-tabs/TabItem';
import { TabsLayoutManager } from '../scene/layout-tabs/TabsLayoutManager';
import { transformSaveModelToScene } from '../serialization/transformSaveModelToScene';
import { getVizPanelKeyForPanelId } from '../utils/utils-panels';

import { ShareSnapshotTab } from './ShareSnapshotTab';

jest.mock('app/features/dashboard/services/SnapshotSrv', () => ({
  getDashboardSnapshotSrv: jest.fn(),
}));

setPluginImportUtils({
  importPanelPlugin: () => Promise.resolve(getPanelPlugin({})),
  getPanelPluginFromCache: () => undefined,
});

// Same-origin path the product serves as GET /logout, which deletes the session cookie.
const SESSION_LINK = { title: 'Sign out', url: '/logout' };
const OUTSIDE_TITLE = 'Outside row';
const INSIDE_TITLE = 'Inside row';

locationUtil.initialize({
  config: { appSubUrl: '' } as GrafanaConfig,
  getVariablesUrlParams: () => ({}),
  getTimeRangeForUrl: () => ({ from: 'now-1h', to: 'now' }),
});

describe('classic snapshot panel links inside collapsed rows', () => {
  beforeEach(() => {
    jest.mocked(getDashboardSnapshotSrv).mockReset();
    jest
      .mocked(getDashboardSnapshotSrv)
      .mockReturnValue(
        buildSnapshotSrv(jest.fn().mockResolvedValue({ key: 'abc', url: '/dashboard/snapshot/abc', deleteUrl: '' }))
      );
  });

  it('strips a header link on a panel in a collapsed grid row before the snapshot is published', async () => {
    const scene = new DashboardScene({
      title: 'Linked dashboard',
      uid: 'dash-1',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-1h', to: 'now' }),
      body: new DefaultGridLayoutManager({
        grid: new SceneGridLayout({
          children: [
            gridItem(1, OUTSIDE_TITLE),
            new SceneGridRow({
              key: getVizPanelKeyForPanelId(2),
              title: 'Hidden',
              y: 8,
              isCollapsed: true,
              children: [gridItem(3, INSIDE_TITLE)],
            }),
          ],
        }),
      }),
    });

    await expectPublishedSnapshotDropsHeaderLink(scene);
  });

  it('strips a header link on a panel in a collapsed rows-layout row', async () => {
    const scene = new DashboardScene({
      title: 'Linked dashboard',
      uid: 'dash-1',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-1h', to: 'now' }),
      body: new RowsLayoutManager({
        rows: [
          new RowItem({
            title: 'Visible',
            collapse: false,
            layout: new DefaultGridLayoutManager({
              grid: new SceneGridLayout({ children: [gridItem(1, OUTSIDE_TITLE)] }),
            }),
          }),
          new RowItem({
            title: 'Hidden',
            collapse: true,
            layout: new DefaultGridLayoutManager({
              grid: new SceneGridLayout({ children: [gridItem(3, INSIDE_TITLE)] }),
            }),
          }),
        ],
      }),
    });

    await expectPublishedSnapshotDropsHeaderLink(scene);
  });

  it('strips a header link on an auto-grid panel stored in a collapsed row', async () => {
    const scene = new DashboardScene({
      title: 'Linked dashboard',
      uid: 'dash-1',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-1h', to: 'now' }),
      body: new RowsLayoutManager({
        rows: [
          new RowItem({
            title: 'Visible',
            collapse: false,
            layout: new DefaultGridLayoutManager({
              grid: new SceneGridLayout({ children: [gridItem(1, OUTSIDE_TITLE)] }),
            }),
          }),
          new RowItem({
            title: 'Hidden',
            collapse: true,
            layout: new AutoGridLayoutManager({
              layout: new AutoGridLayout({
                children: [new AutoGridItem({ body: panelWithLink(3, INSIDE_TITLE) })],
              }),
            }),
          }),
        ],
      }),
    });

    await expectPublishedSnapshotDropsHeaderLink(scene);
  });

  it('strips a header link on a tab panel flattened into a collapsed row', async () => {
    const scene = new DashboardScene({
      title: 'Linked dashboard',
      uid: 'dash-1',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-1h', to: 'now' }),
      body: new RowsLayoutManager({
        rows: [
          new RowItem({
            title: 'Visible',
            collapse: false,
            layout: new DefaultGridLayoutManager({
              grid: new SceneGridLayout({ children: [gridItem(1, OUTSIDE_TITLE)] }),
            }),
          }),
          new RowItem({
            title: 'Hidden',
            collapse: true,
            layout: new TabsLayoutManager({
              tabs: [
                new TabItem({
                  title: 'Nested tab',
                  layout: new DefaultGridLayoutManager({
                    grid: new SceneGridLayout({ children: [gridItem(3, INSIDE_TITLE)] }),
                  }),
                }),
              ],
            }),
          }),
        ],
      }),
    });

    await expectPublishedSnapshotDropsHeaderLink(scene);
  });

  it('strips a header link when the snapshot is of one panel that sits in a collapsed row', async () => {
    const inside = panelWithLink(3, INSIDE_TITLE);
    const scene = new DashboardScene({
      title: 'Linked dashboard',
      uid: 'dash-1',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-1h', to: 'now' }),
      body: new DefaultGridLayoutManager({
        grid: new SceneGridLayout({
          children: [
            gridItem(1, OUTSIDE_TITLE),
            new SceneGridRow({
              key: getVizPanelKeyForPanelId(2),
              title: 'Hidden',
              y: 8,
              isCollapsed: true,
              children: [
                new DashboardGridItem({
                  key: 'grid-item-3',
                  x: 0,
                  y: 9,
                  width: 12,
                  height: 8,
                  body: inside,
                }),
              ],
            }),
          ],
        }),
      }),
    });

    await expectPublishedSnapshotDropsHeaderLink(scene, inside);
  });
});

async function expectPublishedSnapshotDropsHeaderLink(scene: DashboardScene, panel?: VizPanel) {
  const tab = new ShareSnapshotTab({
    dashboardRef: scene.getRef(),
    panelRef: panel?.getRef(),
  });
  scene.setState({ overlay: tab });

  await tab.onSnapshotCreate();

  const posted = createSnapshotDashboard();
  const outside = posted.panels?.find((item) => item.title === OUTSIDE_TITLE);

  const viewed = transformSaveModelToScene({
    dashboard: posted as DashboardDataDTO,
    meta: { isSnapshot: true },
  });
  expandCollapsedRows(viewed);

  const opened = viewed.state.body.getVizPanels().find((item) => item.state.title === INSIDE_TITLE);
  const headerHref = opened ? renderedHeaderLinkHref(opened) : 'panel-missing';

  expect({
    outsideRowLinks: outside?.links ?? [],
    linksLeftOnCollapsedRows: linksStoredOnRows(posted),
    headerHrefAfterExpand: headerHref,
  }).toEqual({
    outsideRowLinks: [],
    linksLeftOnCollapsedRows: [],
    headerHrefAfterExpand: null,
  });
}

function createSnapshotDashboard(): Dashboard {
  const results = jest.mocked(getDashboardSnapshotSrv).mock.results;
  const service = results[results.length - 1]?.value as DashboardSnapshotSrv;
  const command = jest.mocked(service.create).mock.calls[0][0];
  return command.dashboard as Dashboard;
}

function linksStoredOnRows(dashboard: Dashboard): Panel['links'] {
  const links: NonNullable<Panel['links']> = [];
  for (const panel of dashboard.panels ?? []) {
    if (!isRowPanel(panel) || !panel.panels) {
      continue;
    }
    for (const nested of panel.panels) {
      links.push(...(nested.links ?? []));
    }
  }
  return links;
}

function isRowPanel(panel: Panel | RowPanel): panel is RowPanel {
  return panel.type === 'row';
}

function expandCollapsedRows(scene: DashboardScene) {
  const body = scene.state.body;
  if (!(body instanceof DefaultGridLayoutManager)) {
    return;
  }
  for (const child of body.state.grid.state.children) {
    if (child instanceof SceneGridRow && child.state.isCollapsed) {
      child.setState({ isCollapsed: false });
    }
  }
}

function renderedHeaderLinkHref(panel: VizPanel): string | null {
  const links = panel.state.titleItems?.find((item) => item instanceof VizPanelLinks);
  if (!(links instanceof VizPanelLinks)) {
    return null;
  }

  render(<links.Component model={links} />);
  return screen.queryByRole('link')?.getAttribute('href') ?? null;
}

function panelWithLink(id: number, title: string) {
  return new VizPanel({
    title,
    key: getVizPanelKeyForPanelId(id),
    pluginId: 'stat',
    titleItems: [
      new VizPanelLinks({
        rawLinks: [SESSION_LINK],
        menu: new VizPanelLinksMenu({}),
      }),
    ],
  });
}

function gridItem(id: number, title: string) {
  return new DashboardGridItem({
    key: `grid-item-${id}`,
    x: 0,
    y: 0,
    width: 12,
    height: 8,
    body: panelWithLink(id, title),
  });
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
