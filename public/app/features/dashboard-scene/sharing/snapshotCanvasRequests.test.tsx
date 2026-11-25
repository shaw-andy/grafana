import { waitFor } from '@testing-library/react';
import { of } from 'rxjs';
import { render } from 'test/test-utils';

import { ActionType, type TextDimensionConfig, ThemeContext, createTheme } from '@grafana/data';
import { config, setBackendSrv, setTemplateSrv } from '@grafana/runtime';
import { SceneGridLayout, SceneGridRow, SceneTimeRange, VizPanel } from '@grafana/scenes';
import { TextDimensionMode } from '@grafana/schema';
import { type Spec as DashboardV2Spec } from '@grafana/schema/apis/dashboard.grafana.app/v2';
import { BackendSrv } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';
import { type CanvasElementOptions } from 'app/features/canvas/element';
import { buttonItem } from 'app/features/canvas/elements/button';
import { type DashboardWithAccessInfo } from 'app/features/dashboard/api/types';
import { ShareSnapshot } from 'app/features/dashboard/components/ShareModal/ShareSnapshot';
import {
  getDashboardSnapshotSrv,
  type DashboardSnapshotSrv,
  type SnapshotCreateResponse,
} from 'app/features/dashboard/services/SnapshotSrv';
import { DASHBOARD_SCHEMA_VERSION } from 'app/features/dashboard/state/DashboardMigrator';
import { createDashboardModelFixture } from 'app/features/dashboard/state/__fixtures__/dashboardFixtures';
import { DashboardScene } from 'app/features/dashboard-scene/scene/DashboardScene';
import { VizPanelLinks } from 'app/features/dashboard-scene/scene/PanelLinks';
import { DashboardGridItem } from 'app/features/dashboard-scene/scene/layout-default/DashboardGridItem';
import { DefaultGridLayoutManager } from 'app/features/dashboard-scene/scene/layout-default/DefaultGridLayoutManager';
import { transformSaveModelSchemaV2ToScene } from 'app/features/dashboard-scene/serialization/transformSaveModelSchemaV2ToScene';
import { transformSaveModelToScene } from 'app/features/dashboard-scene/serialization/transformSaveModelToScene';
import { type DimensionContext } from 'app/features/dimensions/context';
import { getTextDimensionFromData } from 'app/features/dimensions/utils';
import { TemplateSrv } from 'app/features/templating/template_srv';
import { HttpRequestMethod } from 'app/plugins/panel/canvas/panelcfg.gen';

import { ShareSnapshotTab } from './ShareSnapshotTab';

jest.mock('app/features/dashboard/services/TimeSrv', () => ({
  getTimeSrv: () => ({
    timeRange: () => ({
      from: new Date('2020-01-01T00:00:00.000Z'),
      to: new Date('2020-01-01T01:00:00.000Z'),
    }),
  }),
}));

jest.mock('app/features/dashboard/services/SnapshotSrv', () => ({
  getDashboardSnapshotSrv: jest.fn(),
}));

// Same-origin paths a signed-in viewer can be made to call. They are unique to this fixture.
const ORG_SWITCH_ENDPOINT = '/api/user/using/2';
const ORG_SWITCH_BODY = '{"active":true}';
const ORG_SWITCH_HEADER = 'snapshot-header-value';
const ORG_SWITCH_QUERY = 'snapshot-query-value';
const NESTED_LOGOUT_ENDPOINT = '/logout';
const ELEMENT_LINK_URL = '/profile/switch-org/2';
const ELEMENT_ACTION_URL = '/api/user/using/3';
const ELEMENT_ACTION_BODY = 'action-body-marker';
const COLLAPSED_ROW_ENDPOINT = '/api/user/using/9';
const BUTTON_TEXT = 'Open the door';
const PANEL_LINK_URL = 'https://panel-link.example/docs';

const VIEWER_REQUEST_MARKERS = [
  ORG_SWITCH_ENDPOINT,
  ORG_SWITCH_BODY,
  ORG_SWITCH_HEADER,
  ORG_SWITCH_QUERY,
  NESTED_LOGOUT_ENDPOINT,
  ELEMENT_LINK_URL,
  ELEMENT_ACTION_URL,
  ELEMENT_ACTION_BODY,
  COLLAPSED_ROW_ENDPOINT,
];

interface RecordedFetch {
  url: string;
  method?: string;
  body?: BodyInit | null;
  credentials?: RequestCredentials;
  headers: Record<string, string>;
}

const theme = createTheme();
const dimensionContext = {
  getText: (textConfig: TextDimensionConfig) => getTextDimensionFromData(undefined, textConfig),
} as DimensionContext;

function buttonElement(
  name: string,
  text: string,
  endpoint: string,
  method: HttpRequestMethod,
  extra: Partial<CanvasElementOptions> = {}
): CanvasElementOptions {
  return {
    name,
    type: 'button',
    config: {
      text: { mode: TextDimensionMode.Fixed, fixed: text },
      api: {
        endpoint,
        method,
        data: method === HttpRequestMethod.GET ? undefined : ORG_SWITCH_BODY,
        contentType: 'application/json',
        queryParams: [['switch', ORG_SWITCH_QUERY]],
        headerParams: [['X-Snapshot-Test', ORG_SWITCH_HEADER]],
        successMessage: 'done',
      },
    },
    ...extra,
  };
}

function canvasOptions(elements: CanvasElementOptions[]) {
  return {
    inlineEditing: false,
    panZoom: false,
    showAdvancedTypes: false,
    zoomToContent: false,
    tooltip: { mode: 'single' },
    root: {
      name: 'root',
      type: 'frame',
      elements,
    },
  };
}

function rootElements(): CanvasElementOptions[] {
  return [
    buttonElement('door', BUTTON_TEXT, ORG_SWITCH_ENDPOINT, HttpRequestMethod.POST, {
      links: [{ title: 'Switch org', url: ELEMENT_LINK_URL, oneClick: true }],
      actions: [
        {
          type: ActionType.Fetch,
          title: 'Switch',
          oneClick: true,
          fetch: {
            method: 'POST',
            url: ELEMENT_ACTION_URL,
            body: ELEMENT_ACTION_BODY,
          },
        },
      ],
    }),
    {
      name: 'group',
      type: 'frame',
      elements: [buttonElement('leave', 'Leave', NESTED_LOGOUT_ENDPOINT, HttpRequestMethod.GET)],
    } as CanvasElementOptions,
  ];
}

function buildScene(version: 'v1' | 'v2' = 'v1') {
  const canvasPanel = new VizPanel({
    key: 'panel-1',
    pluginId: 'canvas',
    title: 'Canvas',
    options: canvasOptions(rootElements()),
    titleItems: [
      new VizPanelLinks({
        rawLinks: [{ title: 'Docs', url: PANEL_LINK_URL }],
      }),
    ],
  });

  const collapsedCanvas = new VizPanel({
    key: 'panel-4',
    pluginId: 'canvas',
    title: 'Collapsed canvas',
    options: canvasOptions([buttonElement('hidden', 'Hidden', COLLAPSED_ROW_ENDPOINT, HttpRequestMethod.POST)]),
  });

  const scene = new DashboardScene(
    {
      title: 'shared',
      uid: 'dash-1',
      meta: { canEdit: true },
      $timeRange: new SceneTimeRange({ from: 'now-1h', to: 'now' }),
      body: new DefaultGridLayoutManager({
        grid: new SceneGridLayout({
          children: [
            new DashboardGridItem({
              key: 'grid-item-1',
              x: 0,
              y: 0,
              width: 12,
              height: 8,
              body: canvasPanel,
            }),
            new SceneGridRow({
              key: 'panel-3',
              title: 'Hidden row',
              isCollapsed: true,
              y: 8,
              children: [
                new DashboardGridItem({
                  key: 'grid-item-4',
                  x: 0,
                  y: 9,
                  width: 12,
                  height: 8,
                  body: collapsedCanvas,
                }),
              ],
            }),
          ],
        }),
      }),
    },
    version
  );

  if (version === 'v2') {
    scene.setInitialSaveModel(undefined, undefined, 'dashboard.grafana.app/v2');
  }

  return { scene, canvasPanel };
}

function parentSnapshotTab(scene: DashboardScene, panel?: VizPanel) {
  const tab = new ShareSnapshotTab({
    dashboardRef: scene.getRef(),
    panelRef: panel?.getRef(),
  });
  scene.setState({ overlay: tab });
  return tab;
}

function expectSnapshotOmitsViewerRequests(dashboard: unknown) {
  const published = JSON.stringify(dashboard);
  expect(published).toContain(BUTTON_TEXT);
  for (const marker of VIEWER_REQUEST_MARKERS) {
    expect(published).not.toContain(marker);
  }
  expect(published).not.toContain(PANEL_LINK_URL);
}

function buttonsIn(value: unknown, found: CanvasElementOptions[] = []): CanvasElementOptions[] {
  if (!value || typeof value !== 'object') {
    return found;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      buttonsIn(item, found);
    }
    return found;
  }

  const record = value as CanvasElementOptions & { elements?: CanvasElementOptions[] };
  if (record.type === 'button') {
    found.push(record);
  }

  for (const child of Object.values(record)) {
    buttonsIn(child, found);
  }

  return found;
}

describe('snapshot canvas requests', () => {
  let createSnapshot: jest.Mock<Promise<SnapshotCreateResponse>>;
  let recorded: RecordedFetch[];

  beforeEach(() => {
    window.localStorage.clear();
    jest.clearAllMocks();
    recorded = [];
    config.appUrl = 'http://grafana.example/';
    config.appSubUrl = '';
    setTemplateSrv(new TemplateSrv());
    setBackendSrv(
      new BackendSrv({
        fromFetch: (input, init) => {
          const headers = new Headers(init?.headers);
          recorded.push({
            url: String(input),
            method: init?.method,
            body: init?.body,
            credentials: init?.credentials,
            headers: Object.fromEntries(headers.entries()),
          });
          return of(new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
        },
        appEvents: { subscribe: () => ({ unsubscribe: () => undefined }) } as never,
        contextSrv,
        logout: () => undefined,
      })
    );
    createSnapshot = jest.fn().mockResolvedValue({ key: 'abc', url: '/dashboard/snapshot/abc', deleteUrl: '' });
    jest.mocked(getDashboardSnapshotSrv).mockReturnValue({
      create: createSnapshot,
      getSnapshots: jest.fn(),
      getSharingOptions: jest.fn().mockResolvedValue({}),
      deleteSnapshot: jest.fn(),
      getSnapshot: jest.fn(),
    } as DashboardSnapshotSrv);
  });

  it('does not call the Grafana API as the viewer when a published canvas button is clicked', async () => {
    const { scene } = buildScene('v1');
    const tab = parentSnapshotTab(scene);

    await tab.onSnapshotCreate();

    const dashboard = createSnapshot.mock.calls[0][0].dashboard;
    const loaded = transformSaveModelToScene({ dashboard, meta: { isSnapshot: true } });
    const buttons = loaded.state.body.getVizPanels().flatMap((panel) => buttonsIn(panel.state.options));

    expect(buttons.map((button) => button.name).sort()).toEqual(['door', 'hidden', 'leave']);

    for (const button of buttons) {
      const data = buttonItem.prepareData!(dimensionContext, button);
      const Display = buttonItem.display;
      const view = render(
        <ThemeContext.Provider value={theme}>
          <Display config={button.config} data={data} />
        </ThemeContext.Provider>
      );
      await view.user.click(view.getByRole('button'));
      view.unmount();
    }

    await waitFor(() => expect(recorded.length).toBeGreaterThan(0), { timeout: 1000 }).catch(() => undefined);

    expect(recorded).toEqual([]);
  });

  it('strips canvas requests from a classic dashboard snapshot, including nested elements and collapsed rows', async () => {
    const { scene } = buildScene('v1');
    const tab = parentSnapshotTab(scene);

    await tab.onSnapshotCreate();

    expectSnapshotOmitsViewerRequests(createSnapshot.mock.calls[0][0].dashboard);
  });

  it('strips canvas requests when the snapshot is a single panel', async () => {
    const { scene, canvasPanel } = buildScene('v1');
    const tab = parentSnapshotTab(scene, canvasPanel);

    await tab.onSnapshotCreate();

    const dashboard = createSnapshot.mock.calls[0][0].dashboard;
    const published = JSON.stringify(dashboard);
    expect(published).toContain(BUTTON_TEXT);
    expect(published).not.toContain(ORG_SWITCH_ENDPOINT);
    expect(published).not.toContain(ORG_SWITCH_BODY);
    expect(published).not.toContain(ORG_SWITCH_HEADER);
    expect(published).not.toContain(ORG_SWITCH_QUERY);
    expect(published).not.toContain(NESTED_LOGOUT_ENDPOINT);
    expect(published).not.toContain(ELEMENT_LINK_URL);
    expect(published).not.toContain(ELEMENT_ACTION_URL);
    expect(published).not.toContain(ELEMENT_ACTION_BODY);
  });

  it('strips canvas requests from a schema v2 snapshot vizConfig', async () => {
    const { scene } = buildScene('v2');
    const tab = parentSnapshotTab(scene);

    await tab.onSnapshotCreate();

    expectSnapshotOmitsViewerRequests(createSnapshot.mock.calls[0][0].dashboard);
  });

  it('strips canvas requests from the legacy share dialog, including a panel inside a row', () => {
    const dashboard = createDashboardModelFixture(
      {
        title: 'legacy',
        uid: 'dash-1',
        schemaVersion: DASHBOARD_SCHEMA_VERSION,
        panels: [
          {
            id: 1,
            type: 'canvas',
            title: 'Canvas',
            options: canvasOptions(rootElements()),
            links: [{ title: 'Docs', url: PANEL_LINK_URL }],
          },
          {
            id: 3,
            type: 'row',
            title: 'Hidden row',
            collapsed: true,
            panels: [
              {
                id: 4,
                type: 'canvas',
                title: 'Collapsed canvas',
                options: canvasOptions([
                  buttonElement('hidden', 'Hidden', COLLAPSED_ROW_ENDPOINT, HttpRequestMethod.POST),
                ]),
              },
            ],
          },
        ],
      },
      { canEdit: true }
    );
    const share = new ShareSnapshot({ dashboard });
    const model = dashboard.getSaveModelCloneOld();

    share.scrubDashboard(model);

    expectSnapshotOmitsViewerRequests(model);
  });

  it('does not call the Grafana API when a schema v2 snapshot canvas button is clicked', async () => {
    const { scene } = buildScene('v2');
    const tab = parentSnapshotTab(scene);

    await tab.onSnapshotCreate();

    const spec = createSnapshot.mock.calls[0][0].dashboard as DashboardV2Spec;
    const loaded = transformSaveModelSchemaV2ToScene({
      kind: 'DashboardWithAccessInfo',
      apiVersion: 'dashboard.grafana.app/v2',
      metadata: {
        name: 'dash-1',
        namespace: 'default',
        generation: 1,
        resourceVersion: '1',
        creationTimestamp: '2020-01-01T00:00:00.000Z',
      },
      spec,
      access: {},
    } as DashboardWithAccessInfo<DashboardV2Spec>);
    const buttons = loaded.state.body.getVizPanels().flatMap((panel) => buttonsIn(panel.state.options));

    expect(buttons.map((button) => button.name)).toContain('door');

    for (const button of buttons) {
      const data = buttonItem.prepareData!(dimensionContext, button);
      const Display = buttonItem.display;
      const view = render(
        <ThemeContext.Provider value={theme}>
          <Display config={button.config} data={data} />
        </ThemeContext.Provider>
      );
      await view.user.click(view.getByRole('button'));
      view.unmount();
    }

    await waitFor(() => expect(recorded.length).toBeGreaterThan(0), { timeout: 1000 }).catch(() => undefined);

    expect(recorded).toEqual([]);
  });
});
