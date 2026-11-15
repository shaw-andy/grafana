import { URL as NodeURL } from 'node:url';
import { of } from 'rxjs';

import { getPanelPlugin } from '@grafana/data/test';
import { config, setBackendSrv, setPluginImportUtils } from '@grafana/runtime';
import { setGetObservablePluginLinks } from '@grafana/runtime/internal';
import { VizPanel, type SceneObject } from '@grafana/scenes';
import { defaultDashboard } from '@grafana/schema';
import { type LibraryPanelKind } from '@grafana/schema/apis/dashboard.grafana.app/v2';
import { backendSrv } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';
import { LibraryPanelBehavior } from 'app/features/dashboard-scene/scene/LibraryPanelBehavior';
import { AutoGridItem } from 'app/features/dashboard-scene/scene/layout-auto-grid/AutoGridItem';
import { buildLibraryPanel } from 'app/features/dashboard-scene/serialization/layoutSerializers/utils';
import { transformSaveModelToScene } from 'app/features/dashboard-scene/serialization/transformSaveModelToScene';
import { type DashboardDTO } from 'app/types/dashboard';


import { libraryPanelsK8sClient } from '../../../api/clients/dashboard/v0alpha1/libraryPanels';
import { LibraryElementKind } from '../types';

import {
  deleteLibraryPanel,
  getLibraryPanel,
  getLibraryPanelConnectedDashboards,
  saveLibPanel,
  updateLibraryPanel,
} from './api';

/**
 * Requests the legacy loader issues for a library panel uid stored on a dashboard.
 * The page sets <base href="/"> (or the app subpath), so a relative URL is resolved
 * against that base. These are the pathnames Chrome requests for the same strings.
 */
const LOGOUT_PATH = '/logout';
const SWITCH_ORG_PATH = '/profile/switch-org/2';
const SUBPATH_LOGOUT_PATH = '/grafana/logout';
const SAFE_UID = 'panel_ok';
const SAFE_LIBRARY_ELEMENT_PATH = '/api/library-elements/panel_ok';
const TRAVERSAL_UID = '../../logout';
const SWITCH_ORG_UID = '../../profile/switch-org/2';
const ENCODED_TRAVERSAL_UID = '%2e%2e/%2e%2e/logout';
const CONNECTIONS_TRAVERSAL_UID = '../../logout?';
const K8S_TRAVERSAL_UID = '../../../../../../logout';
const K8S_LIBRARY_PANELS = '/apis/dashboard.grafana.app/v0alpha1/namespaces/default/librarypanels/';

setPluginImportUtils({
  importPanelPlugin: () => Promise.resolve(getPanelPlugin({})),
  getPanelPluginFromCache: () => undefined,
});

setGetObservablePluginLinks(() => of([]));
setBackendSrv(backendSrv);

interface CapturedRequest {
  pathname: string;
  method: string;
  credentials: RequestCredentials | undefined;
}

const captured: CapturedRequest[] = [];
const originalFetch = global.fetch;

function installBase(href: string) {
  let base = document.querySelector('base');
  if (!base) {
    base = document.createElement('base');
    document.head.prepend(base);
  }
  base.setAttribute('href', href);
}

function capturedPaths(): string[] {
  return captured.map((request) => request.pathname);
}

function installFetch() {
  captured.length = 0;
  global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const resolved = new NodeURL(raw, document.baseURI);
    captured.push({
      pathname: resolved.pathname,
      method: init?.method ?? 'GET',
      credentials: init?.credentials,
    });
    return new Response(
      JSON.stringify({
        result: {
          uid: SAFE_UID,
          name: 'Panel',
          kind: LibraryElementKind.Panel,
          type: 'text',
          version: 1,
          model: { type: 'text', title: 'Panel' },
        },
        message: 'ok',
        apiVersion: 'dashboard.grafana.app/v0alpha1',
        kind: 'LibraryPanel',
        metadata: {
          name: SAFE_UID,
          generation: 1,
          resourceVersion: '1',
          annotations: {},
        },
        spec: { type: 'text', title: 'Panel', options: {}, fieldConfig: {} },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }) as typeof fetch;
}

function assertNoSessionChangingPath(requests: CapturedRequest[]) {
  const escaped = requests
    .map((request) => request.pathname)
    .filter((pathname) => pathname === LOGOUT_PATH || pathname === SWITCH_ORG_PATH || pathname === SUBPATH_LOGOUT_PATH);
  expect(escaped).toEqual([]);
}

function assertOneSegmentUnder(pathname: string, prefix: string, suffix = '') {
  expect(pathname.startsWith(prefix)).toBe(true);
  let rest = pathname.slice(prefix.length);
  if (suffix) {
    expect(rest.endsWith(suffix)).toBe(true);
    rest = rest.slice(0, -suffix.length);
  }
  expect(rest.length).toBeGreaterThan(0);
  expect(rest.includes('/')).toBe(false);
}

function assertLibraryElementUidStaysOneSegment(pathname: string, suffix = '') {
  assertOneSegmentUnder(pathname, '/api/library-elements/', suffix);
}

function assertK8sLibraryPanelUidStaysOneSegment(pathname: string) {
  assertOneSegmentUnder(pathname, K8S_LIBRARY_PANELS);
}

async function settle() {
  await new Promise((resolve) => setTimeout(resolve, 20));
}

async function waitForPluginLoad(vizPanel: VizPanel) {
  const started = Date.now();
  while (Date.now() - started < 3000) {
    if (
      vizPanel.state._pluginLoadError ||
      vizPanel.state.pluginId !== LibraryPanelBehavior.LOADING_VIZ_PANEL_PLUGIN_ID
    ) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('library panel request did not settle');
}

function walk(object: SceneObject, visit: (object: SceneObject) => void) {
  visit(object);
  object.forEachChild((child) => walk(child, visit));
}

function libraryVizPanels(root: SceneObject): VizPanel[] {
  const panels: VizPanel[] = [];
  walk(root, (object) => {
    if (
      object instanceof VizPanel &&
      object.state.$behaviors?.some((behavior) => behavior instanceof LibraryPanelBehavior)
    ) {
      panels.push(object);
    }
  });
  return panels;
}

function libraryUid(panel: VizPanel): string | undefined {
  const behavior = panel.state.$behaviors?.find((item) => item instanceof LibraryPanelBehavior);
  return behavior instanceof LibraryPanelBehavior ? behavior.state.uid : undefined;
}

describe('library panel uid path', () => {
  beforeEach(() => {
    installBase('/');
    installFetch();
    config.namespace = 'default';
    contextSrv.user.orgId = 1;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('resolves a relative library-element url against the document base the same way the browser does', () => {
    installBase('/');
    expect(new NodeURL('api/library-elements/../../logout', document.baseURI).pathname).toBe(LOGOUT_PATH);
    expect(new NodeURL('api/library-elements/../../profile/switch-org/2', document.baseURI).pathname).toBe(
      SWITCH_ORG_PATH
    );
    expect(new NodeURL('api/library-elements/%2e%2e/%2e%2e/logout', document.baseURI).pathname).toBe(LOGOUT_PATH);
    expect(new NodeURL('api/library-elements/../../logout?/connections', document.baseURI).pathname).toBe(LOGOUT_PATH);

    installBase('/grafana/');
    expect(new NodeURL('api/library-elements/../../logout', document.baseURI).pathname).toBe(SUBPATH_LOGOUT_PATH);
  });

  it('fetches a short uid as one library-elements segment and sends the session cookie', async () => {
    await getLibraryPanel(SAFE_UID, true);

    expect(capturedPaths()).toEqual([SAFE_LIBRARY_ELEMENT_PATH]);
    expect(captured[0].method).toBe('GET');
    expect(captured[0].credentials).toBe('same-origin');
  });

  it('does not let getLibraryPanel turn a stored uid into logout or switch-org', async () => {
    for (const uid of [TRAVERSAL_UID, SWITCH_ORG_UID, ENCODED_TRAVERSAL_UID]) {
      captured.length = 0;
      await getLibraryPanel(uid, true).catch(() => undefined);
      assertNoSessionChangingPath(captured);
      for (const request of captured) {
        expect(request.method).toBe('GET');
        expect(request.credentials).toBe('same-origin');
        assertLibraryElementUidStaysOneSegment(request.pathname);
      }
    }
  });

  it('does not let updateLibraryPanel patch a traversal uid', async () => {
    const panelSaveModel = {
      libraryPanel: { name: 'Planted', uid: TRAVERSAL_UID, version: 1, folderUid: '' },
      type: 'text',
    };

    await updateLibraryPanel(panelSaveModel as never).catch(() => undefined);
    assertNoSessionChangingPath(captured);
    for (const request of captured) {
      expect(request.method).toBe('PATCH');
      assertLibraryElementUidStaysOneSegment(request.pathname);
    }
  });

  it('does not let deleteLibraryPanel delete through a traversal uid', async () => {
    await deleteLibraryPanel(TRAVERSAL_UID).catch(() => undefined);
    assertNoSessionChangingPath(captured);
    for (const request of captured) {
      expect(request.method).toBe('DELETE');
      assertLibraryElementUidStaysOneSegment(request.pathname);
    }
  });

  it('does not let a connections lookup turn a uid into logout', async () => {
    await getLibraryPanelConnectedDashboards(CONNECTIONS_TRAVERSAL_UID).catch(() => undefined);
    assertNoSessionChangingPath(captured);
    for (const request of captured) {
      expect(request.method).toBe('GET');
      expect(request.credentials).toBe('same-origin');
      assertLibraryElementUidStaysOneSegment(request.pathname, '/connections');
    }
  });

  it('does not let saveLibPanel patch a traversal uid', async () => {
    const panel = new VizPanel({ key: 'panel-1', pluginId: 'text', title: 'Title' });
    const behavior = new LibraryPanelBehavior({
      isLoaded: true,
      uid: TRAVERSAL_UID,
      name: 'Planted',
      _loadedPanel: {
        uid: TRAVERSAL_UID,
        name: 'Planted',
        type: 'text',
        model: { type: 'text', title: 'Title' },
        version: 1,
      },
    });
    panel.setState({ $behaviors: [behavior] });
    new AutoGridItem({ key: 'auto-grid-item-1', body: panel });

    captured.length = 0;
    await saveLibPanel(panel).catch(() => undefined);
    await settle();

    assertNoSessionChangingPath(captured);
    for (const request of captured) {
      expect(request.method).toBe('PATCH');
      assertLibraryElementUidStaysOneSegment(request.pathname);
    }
  });

  it('does not let the kubernetes library panel get escape its resource path', async () => {
    await libraryPanelsK8sClient.get(K8S_TRAVERSAL_UID, true).catch(() => undefined);
    assertNoSessionChangingPath(captured);
    if (captured[0]) {
      assertK8sLibraryPanelUidStaysOneSegment(captured[0].pathname);
    }
    for (const request of captured) {
      if (request.pathname.startsWith(K8S_LIBRARY_PANELS)) {
        assertK8sLibraryPanelUidStaysOneSegment(request.pathname);
      }
    }
  });

  it('does not let the kubernetes library panel remove escape its resource path', async () => {
    await libraryPanelsK8sClient.remove(K8S_TRAVERSAL_UID).catch(() => undefined);
    assertNoSessionChangingPath(captured);
    if (captured[0]) {
      assertK8sLibraryPanelUidStaysOneSegment(captured[0].pathname);
    }
  });

  it('does not let the kubernetes library panel update escape its resource path', async () => {
    await libraryPanelsK8sClient.update(K8S_TRAVERSAL_UID, 'Planted', { type: 'text' }, 1, '').catch(() => undefined);
    assertNoSessionChangingPath(captured);
    if (captured[0]) {
      assertK8sLibraryPanelUidStaysOneSegment(captured[0].pathname);
    }
  });

  it('loads a dashboard library panel uid through the scene and keeps the request on the collection', async () => {
    const scene = transformSaveModelToScene(dashboardWithLibraryPanel(TRAVERSAL_UID, SWITCH_ORG_UID));
    const panels = libraryVizPanels(scene);
    expect(panels.map((panel) => libraryUid(panel))).toEqual([TRAVERSAL_UID, SWITCH_ORG_UID]);
    const stop = panels.map((panel) => panel.activate());
    await Promise.all(panels.map((panel) => waitForPluginLoad(panel)));

    assertNoSessionChangingPath(captured);
    for (const request of captured) {
      if (request.pathname.startsWith('/api/library-elements/')) {
        expect(request.credentials).toBe('same-origin');
        assertLibraryElementUidStaysOneSegment(request.pathname);
      }
    }
    stop.forEach((deactivate) => deactivate());
  });

  it('loads a v2 library panel element through the same behavior', async () => {
    const element: LibraryPanelKind = {
      kind: 'LibraryPanel',
      spec: {
        id: 1,
        title: 'Planted',
        libraryPanel: { uid: TRAVERSAL_UID, name: 'Planted' },
      },
    };
    const vizPanel = buildLibraryPanel(element);
    const behavior = vizPanel.state.$behaviors?.find((item) => item instanceof LibraryPanelBehavior);
    expect(behavior).toBeInstanceOf(LibraryPanelBehavior);
    expect((behavior as LibraryPanelBehavior).state.uid).toBe(TRAVERSAL_UID);

    const stop = vizPanel.activate();
    await waitForPluginLoad(vizPanel);
    await settle();

    assertNoSessionChangingPath(captured);
    for (const request of captured) {
      if (request.pathname.startsWith('/api/library-elements/')) {
        assertLibraryElementUidStaysOneSegment(request.pathname);
      }
    }
    stop();
  });

  it('keeps a safe dashboard library panel on its own segment when the scene activates', async () => {
    const scene = transformSaveModelToScene(dashboardWithLibraryPanel(SAFE_UID, SAFE_UID));
    const panels = libraryVizPanels(scene);
    const stop = panels.map((panel) => panel.activate());
    await Promise.all(panels.map((panel) => waitForPluginLoad(panel)));

    expect(capturedPaths()).toContain(SAFE_LIBRARY_ELEMENT_PATH);
    expect(captured.find((request) => request.pathname === SAFE_LIBRARY_ELEMENT_PATH)?.credentials).toBe('same-origin');
    stop.forEach((deactivate) => deactivate());
  });

  it('does not retarget the request when the app is served from a subpath', async () => {
    installBase('/grafana/');
    await getLibraryPanel(TRAVERSAL_UID, true).catch(() => undefined);

    assertNoSessionChangingPath(captured);
    for (const request of captured) {
      assertLibraryElementUidStaysOneSegment(request.pathname);
    }
  });
});

function dashboardWithLibraryPanel(topLevelUid: string, rowUid: string): DashboardDTO {
  return {
    dashboard: {
      ...defaultDashboard,
      title: 'Planted',
      uid: 'dashuid',
      annotations: {
        list: [
          {
            builtIn: 1,
            datasource: { type: 'grafana', uid: '-- Grafana --' },
            enable: false,
            hide: true,
            iconColor: 'rgba(0, 211, 255, 1)',
            name: 'Annotations & Alerts',
            type: 'dashboard',
          },
        ],
      },
      panels: [
        {
          id: 1,
          title: 'Planted',
          type: 'timeseries',
          gridPos: { x: 0, y: 0, w: 12, h: 8 },
          libraryPanel: { uid: topLevelUid, name: 'Planted' },
        },
        {
          id: 2,
          type: 'row',
          title: 'Row',
          collapsed: true,
          gridPos: { x: 0, y: 8, w: 24, h: 1 },
          panels: [
            {
              id: 3,
              title: 'Nested',
              type: 'timeseries',
              gridPos: { x: 0, y: 9, w: 12, h: 8 },
              libraryPanel: { uid: rowUid, name: 'Nested' },
            },
          ],
        },
      ],
    },
    meta: {},
  };
}
