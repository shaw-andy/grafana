import { sceneGraph, VizPanel } from '@grafana/scenes';
import { type BackendSrv, config, locationService, setBackendSrv } from '@grafana/runtime';
import { contextSrv } from 'app/core/services/context_srv';
import { DASHBOARD_LIBRARY_ROUTES } from 'app/features/dashboard/dashgrid/types';
import { DASHBOARD_SCHEMA_VERSION } from 'app/features/dashboard/state/DashboardMigrator';
import { getAppRoutes } from 'app/routes/routes';
import { AccessControlAction } from 'app/types/accessControl';
import { DashboardRoutes } from 'app/types/dashboard';

import { type DashboardScene } from '../scene/DashboardScene';

import { UnifiedDashboardScenePageStateManager } from './DashboardScenePageStateManager';

jest.mock('app/features/plugins/routes', () => ({
  getAppPluginRoutes: () => [],
}));

/**
 * Panel types the dashboard library refuses before it will navigate to the template route.
 * Kept as literals so this spec fails if the template loader stops applying that denylist
 * to the JSON it actually turns into panels.
 */
const UNSAFE_PANEL_TYPES = [
  'aceiot-svg-panel',
  'ae3e-plotly-panel',
  'gapit-htmlgraphics-panel',
  'marcusolsson-dynamictext-panel',
  'volkovlabs-echarts-panel',
  'volkovlabs-form-panel',
] as const;

const GNET_ID = '4242';

interface GnetBody {
  json: ReturnType<typeof dashboardJson>;
  /** Decoy. The list API uses this field; the template response must not be trusted via it. */
  panelTypeSlugs: string[];
  dependencies: { items: Array<{ pluginSlug: string; pluginTypeCode: string }> };
}

function gridPos(y = 0) {
  return { h: 8, w: 12, x: 0, y };
}

function dashboardJson(panels: unknown[], title = 'Community dashboard') {
  return {
    title,
    uid: 'gnet-dash',
    schemaVersion: DASHBOARD_SCHEMA_VERSION,
    panels,
    time: { from: 'now-6h', to: 'now' },
    templating: { list: [] },
  };
}

function panel(overrides: Record<string, unknown>) {
  return {
    id: 1,
    title: 'Panel',
    gridPos: gridPos(),
    options: {},
    targets: [{ refId: 'A' }],
    fieldConfig: { defaults: {}, overrides: [] },
    ...overrides,
  };
}

function safePanel(marker: string) {
  return panel({
    id: 1,
    type: 'timeseries',
    title: 'CPU',
    options: { legend: { displayMode: 'list' }, marker },
  });
}

function gnetBody(panels: unknown[], title?: string): GnetBody {
  return {
    json: dashboardJson(panels, title),
    // These claim the dashboard is a plain timeseries dashboard. A check that trusts them
    // and then renders json.panels is still wrong.
    panelTypeSlugs: ['timeseries'],
    dependencies: { items: [{ pluginSlug: 'prometheus', pluginTypeCode: 'datasource' }] },
  };
}

function collectVizPanels(root: object | undefined): VizPanel[] {
  if (!root) {
    return [];
  }

  const found: VizPanel[] = [];
  const seen = new Set<object>();

  const visit = (value: unknown) => {
    if (!value || typeof value !== 'object') {
      return;
    }
    if (seen.has(value)) {
      return;
    }
    seen.add(value);

    if (value instanceof VizPanel) {
      found.push(value);
    }

    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }

    const state = (value as { state?: unknown }).state;
    if (state && typeof state === 'object') {
      Object.values(state).forEach(visit);
    }
  };

  visit(root);
  // Also walk the scene graph helper the dashboard itself uses, in case a panel is linked
  // from a field the state walk does not name.
  if ('state' in root) {
    sceneGraph
      .findAllObjects(root as DashboardScene, (obj) => obj instanceof VizPanel)
      .forEach((obj) => {
        if (obj instanceof VizPanel && !found.includes(obj)) {
          found.push(obj);
        }
      });
  }

  return found;
}

function panelSnapshot(panels: VizPanel[]) {
  return panels.map((vizPanel) => ({
    pluginId: vizPanel.state.pluginId,
    title: vizPanel.state.title,
    marker: vizPanel.state.options?.marker,
    content: vizPanel.state.options?.content,
  }));
}

describe('template route registration', () => {
  const originalFlags = {
    dashboardLibrary: config.featureToggles.dashboardLibrary,
    suggestedDashboards: config.featureToggles.suggestedDashboards,
    dashboardTemplates: config.featureToggles.dashboardTemplates,
  };
  const previousPermissions = contextSrv.user.permissions;

  afterEach(() => {
    config.featureToggles.dashboardLibrary = originalFlags.dashboardLibrary;
    config.featureToggles.suggestedDashboards = originalFlags.suggestedDashboards;
    config.featureToggles.dashboardTemplates = originalFlags.dashboardTemplates;
    contextSrv.user.permissions = previousPermissions;
  });

  function templateRoute() {
    return getAppRoutes().find((route) => route.path === DASHBOARD_LIBRARY_ROUTES.Template);
  }

  it('is not registered when dashboardLibrary, suggestedDashboards, and dashboardTemplates are off', () => {
    config.featureToggles.dashboardLibrary = false;
    config.featureToggles.suggestedDashboards = false;
    config.featureToggles.dashboardTemplates = false;

    expect(templateRoute()).toBeUndefined();
  });

  it.each(['dashboardLibrary', 'suggestedDashboards', 'dashboardTemplates'] as const)(
    'is registered for dashboard creators when only %s is on',
    (flag) => {
      config.featureToggles.dashboardLibrary = false;
      config.featureToggles.suggestedDashboards = false;
      config.featureToggles.dashboardTemplates = false;
      config.featureToggles[flag] = true;

      const route = templateRoute();
      expect(route?.routeName).toBe(DashboardRoutes.Template);

      contextSrv.user.permissions = {};
      expect(route?.roles?.()).toEqual(['Reject']);

      contextSrv.user.permissions = { [AccessControlAction.DashboardsCreate]: true };
      expect(route?.roles?.()).toEqual([]);
    }
  );
});

describe('template route Grafana.com dashboard screening', () => {
  const originalFlags = {
    dashboardLibrary: config.featureToggles.dashboardLibrary,
    suggestedDashboards: config.featureToggles.suggestedDashboards,
    dashboardTemplates: config.featureToggles.dashboardTemplates,
  };
  let restoreLocation: () => void;
  let publishedDuringLoad: Array<ReturnType<typeof panelSnapshot>>;

  beforeEach(() => {
    publishedDuringLoad = [];
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    config.featureToggles.dashboardLibrary = true;
    config.featureToggles.suggestedDashboards = false;
    config.featureToggles.dashboardTemplates = false;
  });

  afterEach(() => {
    restoreLocation?.();
    config.featureToggles.dashboardLibrary = originalFlags.dashboardLibrary;
    config.featureToggles.suggestedDashboards = originalFlags.suggestedDashboards;
    config.featureToggles.dashboardTemplates = originalFlags.dashboardTemplates;
    jest.restoreAllMocks();
  });

  function installLocation(initialSearch: string) {
    const holder = {
      pathname: '/dashboard/template',
      search: initialSearch,
    };
    const previousWindowLocation = window.location;
    const previousGetLocation = locationService.getLocation.bind(locationService);

    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: {
        pathname: holder.pathname,
        get search() {
          return holder.search;
        },
        href: 'http://localhost/dashboard/template',
      },
    });
    locationService.getLocation = () => ({ pathname: holder.pathname, search: holder.search });

    restoreLocation = () => {
      Object.defineProperty(window, 'location', {
        configurable: true,
        writable: true,
        value: previousWindowLocation,
      });
      locationService.getLocation = previousGetLocation;
    };

    return {
      setSearch(search: string) {
        holder.search = search;
      },
    };
  }

  function installGnet(handler: (url: string) => GnetBody) {
    const calls: string[] = [];
    setBackendSrv({
      get: (url: string) => {
        calls.push(url);
        if (url === `/apis/dashboard.grafana.app/` || url.startsWith('/apis/')) {
          return Promise.reject(new Error('discovery unused'));
        }
        if (!url.startsWith('/api/gnet/dashboards/')) {
          return Promise.reject(new Error(`unexpected GET ${url}`));
        }
        return Promise.resolve(handler(url));
      },
    } as unknown as BackendSrv);
    return calls;
  }

  async function loadTemplate(): Promise<UnifiedDashboardScenePageStateManager> {
    const manager = new UnifiedDashboardScenePageStateManager({});
    const setState = manager.setState.bind(manager);
    jest.spyOn(manager, 'setState').mockImplementation((state) => {
      if (state?.dashboard) {
        publishedDuringLoad.push(panelSnapshot(collectVizPanels(state.dashboard)));
      }
      return setState(state);
    });
    await manager.loadDashboard({ uid: '', route: DashboardRoutes.Template });
    return manager;
  }

  function expectDashboardRefused(manager: UnifiedDashboardScenePageStateManager, gnetCalls: string[]) {
    const live = panelSnapshot(collectVizPanels(manager.state.dashboard));
    expect(gnetCalls).toContain(`/api/gnet/dashboards/${GNET_ID}`);
    expect({
      live,
      publishedDuringLoad,
      loadError: manager.state.loadError?.message ?? null,
    }).toEqual({
      live: [],
      publishedDuringLoad: [],
      loadError: expect.any(String),
    });
    expect(manager.state.loadError?.message?.length).toBeGreaterThan(0);
    expect(manager.state.dashboard).toBeUndefined();
  }

  describe('community template URL (?gnetId&mappings)', () => {
    it.each(UNSAFE_PANEL_TYPES)(
      'does not publish a scene whose panel type is the denylisted plugin %s',
      async (pluginType) => {
        installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
        const calls = installGnet((url) => {
          expect(url).toBe(`/api/gnet/dashboards/${GNET_ID}`);
          return gnetBody([
            panel({
              type: pluginType,
              options: { content: 'plain text', marker: `denylist-${pluginType}` },
            }),
          ]);
        });

        const manager = await loadTemplate();

        expectDashboardRefused(manager, calls);
      }
    );

    it.each([
      ['options value', { options: { content: '<script>alert(1)</script>', marker: 'script-tag' } }],
      ['javascript URL in options', { options: { template: 'javascript:alert(1)', marker: 'javascript-url' } }],
      [
        'function declaration in a target',
        { targets: [{ refId: 'A', expr: 'function() { return 1 }' }], options: { marker: 'function-decl' } },
      ],
      ['beforeRender hook', { beforeRender: 'alert(1)', options: { marker: 'before-render' } }],
      ['arrow function in options', { options: { content: '() => { return 1 }', marker: 'arrow-fn' } }],
    ] as const)('does not publish a scene when a panel %s matches the library script scan', async (_label, extra) => {
      installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
      const calls = installGnet(() =>
        gnetBody([
          panel({
            type: 'text',
            ...extra,
          }),
        ])
      );

      const manager = await loadTemplate();

      expectDashboardRefused(manager, calls);
    });

    it('does not publish any panel when one panel is safe and another is denylisted', async () => {
      installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
      const calls = installGnet(() =>
        gnetBody([
          safePanel('kept'),
          panel({
            id: 2,
            type: 'volkovlabs-echarts-panel',
            gridPos: gridPos(8),
            options: { content: 'plain', marker: 'sibling-unsafe' },
          }),
        ])
      );

      const manager = await loadTemplate();

      expectDashboardRefused(manager, calls);
    });

    it('does not publish a denylisted panel nested in a collapsed row', async () => {
      installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
      const calls = installGnet(() =>
        gnetBody([
          {
            id: 10,
            type: 'row',
            title: 'Row',
            collapsed: true,
            gridPos: { h: 1, w: 24, x: 0, y: 0 },
            panels: [
              panel({
                id: 11,
                type: 'gapit-htmlgraphics-panel',
                options: { content: 'plain', marker: 'nested-unsafe' },
              }),
            ],
          },
        ])
      );

      const manager = await loadTemplate();

      expectDashboardRefused(manager, calls);
    });

    it('does not publish panels from a second fetch of the same Grafana.com id', async () => {
      installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
      const calls: string[] = [];
      installGnet((url) => {
        calls.push(url);
        if (calls.length === 1) {
          return gnetBody([safePanel('first-fetch')]);
        }
        return gnetBody([
          panel({
            type: 'marcusolsson-dynamictext-panel',
            options: { content: 'plain', marker: 'second-fetch' },
          }),
        ]);
      });

      const manager = await loadTemplate();
      const live = panelSnapshot(collectVizPanels(manager.state.dashboard));

      expect(live.map((panel) => panel.marker)).not.toContain('second-fetch');
      expect(live.map((panel) => panel.pluginId)).not.toContain('marcusolsson-dynamictext-panel');
      expect(publishedDuringLoad.flat().map((panel) => panel.marker)).not.toContain('second-fetch');
    });

    it('does not publish panels from a Grafana.com id read off the URL after the first response', async () => {
      const location = installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
      installGnet((url) => {
        if (url === `/api/gnet/dashboards/${GNET_ID}`) {
          location.setSearch('?gnetId=9999&mappings=%5B%5D');
          return gnetBody([safePanel('original-id')]);
        }
        if (url === '/api/gnet/dashboards/9999') {
          return gnetBody([
            panel({
              type: 'ae3e-plotly-panel',
              options: { content: 'plain', marker: 'swapped-id' },
            }),
          ]);
        }
        throw new Error(`unexpected url ${url}`);
      });

      const manager = await loadTemplate();
      const live = panelSnapshot(collectVizPanels(manager.state.dashboard));
      const published = publishedDuringLoad.flat();

      expect(live.map((panel) => panel.marker)).not.toContain('swapped-id');
      expect(published.map((panel) => panel.marker)).not.toContain('swapped-id');
      expect([...live, ...published].map((panel) => panel.pluginId)).not.toContain('ae3e-plotly-panel');
    });

    it('still publishes a timeseries dashboard the library scan would allow', async () => {
      installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
      installGnet(() => gnetBody([safePanel('safe')]));

      const manager = await loadTemplate();
      const live = panelSnapshot(collectVizPanels(manager.state.dashboard));

      expect(manager.state.loadError).toBeUndefined();
      expect(manager.state.dashboard?.state.isEditing).toBe(true);
      expect(manager.state.dashboard?.state.isDirty).toBe(true);
      expect(live).toEqual([{ pluginId: 'timeseries', title: 'CPU', marker: 'safe', content: undefined }]);
    });

    it('still publishes a dashboard whose only script-like text is the panel title and description', async () => {
      installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
      installGnet(() =>
        gnetBody([
          panel({
            type: 'timeseries',
            title: '<script>alert(1)</script>',
            description: 'javascript:alert(1)',
            options: { legend: { displayMode: 'list' }, marker: 'title-only' },
          }),
        ])
      );

      const manager = await loadTemplate();
      const live = panelSnapshot(collectVizPanels(manager.state.dashboard));

      expect(manager.state.loadError).toBeUndefined();
      expect(live).toEqual([
        {
          pluginId: 'timeseries',
          title: '<script>alert(1)</script>',
          marker: 'title-only',
          content: undefined,
        },
      ]);
    });
  });

  describe('Grafana.com template URL (?gnetId&datasource&pluginId)', () => {
    it('does not publish a denylisted panel loaded through the pluginId template branch', async () => {
      installLocation(`?gnetId=${GNET_ID}&datasource=prom-uid&pluginId=prometheus`);
      const calls = installGnet((url) => {
        expect(url).toBe(`/api/gnet/dashboards/${GNET_ID}`);
        return gnetBody([
          panel({
            type: 'volkovlabs-form-panel',
            options: { content: 'plain', marker: 'plugin-branch' },
          }),
        ]);
      });

      const manager = await loadTemplate();

      expectDashboardRefused(manager, calls);
    });

    it('does not publish a script-bearing panel loaded through the pluginId template branch', async () => {
      installLocation(`?gnetId=${GNET_ID}&datasource=prom-uid&pluginId=prometheus`);
      const calls = installGnet(() =>
        gnetBody([
          panel({
            type: 'text',
            options: { content: '<script>alert(1)</script>', marker: 'plugin-branch-script' },
          }),
        ])
      );

      const manager = await loadTemplate();

      expectDashboardRefused(manager, calls);
    });
  });

  describe.each([
    ['dashboardLibrary', { dashboardLibrary: true, suggestedDashboards: false, dashboardTemplates: false }],
    ['suggestedDashboards', { dashboardLibrary: false, suggestedDashboards: true, dashboardTemplates: false }],
    ['dashboardTemplates', { dashboardLibrary: false, suggestedDashboards: false, dashboardTemplates: true }],
  ] as const)('when only %s is enabled', (_name, flags) => {
    it('does not publish a denylisted Grafana.com dashboard', async () => {
      config.featureToggles.dashboardLibrary = flags.dashboardLibrary;
      config.featureToggles.suggestedDashboards = flags.suggestedDashboards;
      config.featureToggles.dashboardTemplates = flags.dashboardTemplates;
      installLocation(`?gnetId=${GNET_ID}&mappings=%5B%5D`);
      const calls = installGnet(() =>
        gnetBody([
          panel({
            type: 'aceiot-svg-panel',
            options: { content: 'plain', marker: 'flag-branch' },
          }),
        ])
      );

      const manager = await loadTemplate();

      expectDashboardRefused(manager, calls);
    });
  });
});
