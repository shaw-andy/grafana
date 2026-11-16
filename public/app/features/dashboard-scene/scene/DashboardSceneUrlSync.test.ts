import { waitFor } from '@testing-library/react';
import { of } from 'rxjs';
import { seedDataSources } from 'test/helpers/seedDataSources';

import {
  type DataQuery,
  type DataSourceInstanceSettings,
  type DataSourceJsonData,
  type DataSourcePluginMeta,
  PluginType,
} from '@grafana/data';
import {
  type BackendSrv,
  type BackendSrvRequest,
  config,
  DataSourceWithBackend,
  getBackendSrv,
  locationService,
  setBackendSrv,
  setRunRequest,
} from '@grafana/runtime';
import { NewSceneObjectAddedEvent, SceneQueryRunner, UrlSyncManager, VizPanel } from '@grafana/scenes';
import { runRequest } from 'app/features/query/state/runRequest';
import { type DashboardMeta } from 'app/types/dashboard';

import { PanelDataQueriesTab } from '../panel-edit/PanelDataPane/PanelDataQueriesTab';
import { PanelDataPaneNext } from '../panel-edit/PanelEditNext/PanelDataPaneNext';

import { DashboardScene } from './DashboardScene';
import { LibraryPanelBehavior } from './LibraryPanelBehavior';
import { DefaultGridLayoutManager } from './layout-default/DefaultGridLayoutManager';
import { RowItem } from './layout-rows/RowItem';
import { RowsLayoutManager } from './layout-rows/RowsLayoutManager';
import { TabItem } from './layout-tabs/TabItem';
import { TabsLayoutManager } from './layout-tabs/TabsLayoutManager';

describe('DashboardSceneUrlSync', () => {
  describe('Given a standard scene', () => {
    it('Should set UNSAFE_fitPanels when url has autofitpanels', () => {
      const scene = buildTestScene();
      scene.urlSync?.updateFromUrl({ autofitpanels: '' });
      const layout = scene.state.body as DefaultGridLayoutManager;

      expect(layout.state.grid.state.UNSAFE_fitPanels).toBe(true);
    });

    it('Should get the autofitpanels from the scene state', () => {
      const scene = buildTestScene();

      expect(scene.urlSync?.getUrlState().autofitpanels).toBeUndefined();
      const layout = scene.state.body as DefaultGridLayoutManager;
      layout.state.grid.setState({ UNSAFE_fitPanels: true });
      expect(scene.urlSync?.getUrlState().autofitpanels).toBe('true');
    });
  });

  describe('Scroll to row', () => {
    let scrollIntoViewSpy: jest.Mock;
    let originalScrollIntoView: typeof HTMLElement.prototype.scrollIntoView;
    let locationPartialSpy: jest.SpyInstance;

    beforeEach(() => {
      // jsdom doesn't implement scrollIntoView, so patch the prototype rather than spy on it.
      originalScrollIntoView = HTMLElement.prototype.scrollIntoView;
      scrollIntoViewSpy = jest.fn();
      HTMLElement.prototype.scrollIntoView = scrollIntoViewSpy;
      locationPartialSpy = jest.spyOn(locationService, 'partial').mockImplementation(() => {});
    });

    afterEach(() => {
      HTMLElement.prototype.scrollIntoView = originalScrollIntoView;
      locationPartialSpy.mockRestore();
      document.body.innerHTML = '';
    });

    it('scrolls the matching row into view', () => {
      const { scene, element } = buildTestSceneWithRow('Traces Instance Stats');

      scene.urlSync?.updateFromUrl({ drow: 'Traces-Instance-Stats' });

      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(1);
      expect(scrollIntoViewSpy.mock.instances[0]).toBe(element);
    });

    it('expands a collapsed row', () => {
      const { scene, row } = buildTestSceneWithRow('Traces Instance Stats', { collapse: true });

      scene.urlSync?.updateFromUrl({ drow: 'Traces-Instance-Stats' });

      expect(row.state.collapse).toBe(false);
    });

    it('clears parameter from the url after scrolling so it acts as a one-shot action', () => {
      const { scene } = buildTestSceneWithRow('Traces Instance Stats');

      scene.urlSync?.updateFromUrl({ drow: 'Traces-Instance-Stats' });

      // replace: true so clearing drow does not push a history entry that Back would restore
      expect(locationPartialSpy).toHaveBeenCalledWith({ drow: null }, true);
    });

    it('expands all collapsed ancestor rows of a nested row', () => {
      const nestedRow = new RowItem({ title: 'Nested' });
      const middleRow = new RowItem({
        title: 'Middle',
        collapse: true,
        layout: new RowsLayoutManager({ rows: [nestedRow] }),
      });
      const outerRow = new RowItem({
        title: 'Outer',
        collapse: true,
        layout: new RowsLayoutManager({ rows: [middleRow] }),
      });
      const scene = new DashboardScene({
        title: 'hello',
        uid: 'dash-1',
        body: new RowsLayoutManager({ rows: [outerRow] }),
      });

      scene.urlSync?.updateFromUrl({ drow: 'Outer/Middle/Nested' });

      expect(outerRow.state.collapse).toBe(false);
      expect(middleRow.state.collapse).toBe(false);
    });

    it('switches to a non-active tab containing the target row', () => {
      const targetRow = new RowItem({ title: 'Target row' });
      const activeTab = new TabItem({ title: 'Active tab' });
      const targetTab = new TabItem({
        title: 'Target tab',
        layout: new RowsLayoutManager({ rows: [targetRow] }),
      });
      const tabsLayout = new TabsLayoutManager({ tabs: [activeTab, targetTab] });
      const scene = new DashboardScene({
        title: 'hello',
        uid: 'dash-1',
        body: tabsLayout,
      });
      tabsLayout.setState({ currentTabSlug: activeTab.getSlug() });

      scene.urlSync?.updateFromUrl({ drow: 'Target-tab/Target-row' });

      expect(tabsLayout.getCurrentTab()).toBe(targetTab);
    });

    it('scrolls the correct row when a nested row shares its slug with a top-level row', () => {
      const nestedRow = new RowItem({ title: 'Row 1' });
      const containerRow = new RowItem({ title: 'Row 2', layout: new RowsLayoutManager({ rows: [nestedRow] }) });
      const topLevelRow = new RowItem({ title: 'Row 1' });
      const scene = new DashboardScene({
        title: 'hello',
        uid: 'dash-1',
        body: new RowsLayoutManager({ rows: [topLevelRow, containerRow] }),
      });

      const topLevelElement = document.createElement('div');
      document.body.appendChild(topLevelElement);
      topLevelRow.containerRef.current = topLevelElement;

      const nestedElement = document.createElement('div');
      document.body.appendChild(nestedElement);
      nestedRow.containerRef.current = nestedElement;

      scene.urlSync?.updateFromUrl({ drow: 'Row-2/Row-1' });
      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(1);
      expect(scrollIntoViewSpy.mock.instances[0]).toBe(nestedElement);

      scene.urlSync?.updateFromUrl({ drow: 'Row-1' });
      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(2);
      expect(scrollIntoViewSpy.mock.instances[1]).toBe(topLevelElement);
    });

    it('distinguishes a row titled with a slash from a nested row with the same path segments', () => {
      const nestedRow = new RowItem({ title: 'Bar' });
      const parentRow = new RowItem({ title: 'Foo', layout: new RowsLayoutManager({ rows: [nestedRow] }) });
      const slashTitleRow = new RowItem({ title: 'Foo/Bar' });
      const scene = new DashboardScene({
        title: 'hello',
        uid: 'dash-1',
        body: new RowsLayoutManager({ rows: [slashTitleRow, parentRow] }),
      });

      const slashTitleElement = document.createElement('div');
      document.body.appendChild(slashTitleElement);
      slashTitleRow.containerRef.current = slashTitleElement;

      const nestedElement = document.createElement('div');
      document.body.appendChild(nestedElement);
      nestedRow.containerRef.current = nestedElement;

      // Encoded slash in the title segment must not match nested Foo/Bar path
      scene.urlSync?.updateFromUrl({ drow: 'Foo%2FBar' });
      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(1);
      expect(scrollIntoViewSpy.mock.instances[0]).toBe(slashTitleElement);

      scene.urlSync?.updateFromUrl({ drow: 'Foo/Bar' });
      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(2);
      expect(scrollIntoViewSpy.mock.instances[1]).toBe(nestedElement);
    });

    it('clears parameter but does not scroll when no row matches the slug', () => {
      const { scene } = buildTestSceneWithRow('Traces Instance Stats');

      scene.urlSync?.updateFromUrl({ drow: 'Does-Not-Exist' });

      expect(scrollIntoViewSpy).not.toHaveBeenCalled();
      expect(locationPartialSpy).toHaveBeenCalledWith({ drow: null }, true);
    });

    it('matches a repeated row clone by its own slug, without the source row as a path segment', () => {
      const sourceRow = new RowItem({ title: 'Web A' });
      // Repeat clones live in the source row's repeatedRows state, so their scene graph
      // parent is the source row even though they render as its siblings
      const cloneRow = new RowItem({ title: 'Web B', repeatSourceKey: sourceRow.state.key });
      sourceRow.setState({ repeatedRows: [cloneRow] });
      const scene = new DashboardScene({
        title: 'hello',
        uid: 'dash-1',
        body: new RowsLayoutManager({ rows: [sourceRow] }),
      });

      const cloneElement = document.createElement('div');
      document.body.appendChild(cloneElement);
      cloneRow.containerRef.current = cloneElement;

      scene.urlSync?.updateFromUrl({ drow: 'Web-B' });

      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(1);
      expect(scrollIntoViewSpy.mock.instances[0]).toBe(cloneElement);
    });

    it('scrolls to a repeated row that is created after url sync, when the repeater announces it', () => {
      const sourceRow = new RowItem({ title: 'Web A' });
      const scene = new DashboardScene({
        title: 'hello',
        uid: 'dash-1',
        body: new RowsLayoutManager({ rows: [sourceRow] }),
      });

      // On load the repeat variable has not resolved yet, so the clone does not exist
      scene.urlSync?.updateFromUrl({ drow: 'Web-B' });
      expect(scrollIntoViewSpy).not.toHaveBeenCalled();

      // Simulate the repeater performing repeats: it creates the clones and publishes
      // NewSceneObjectAddedEvent when done
      const cloneRow = new RowItem({ title: 'Web B', repeatSourceKey: sourceRow.state.key });
      sourceRow.setState({ repeatedRows: [cloneRow] });
      const cloneElement = document.createElement('div');
      document.body.appendChild(cloneElement);
      cloneRow.containerRef.current = cloneElement;
      sourceRow.publishEvent(new NewSceneObjectAddedEvent(sourceRow), true);

      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(1);
      expect(scrollIntoViewSpy.mock.instances[0]).toBe(cloneElement);

      // The retry is one-shot: later additions must not scroll again
      sourceRow.publishEvent(new NewSceneObjectAddedEvent(sourceRow), true);
      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(1);
    });

    it('replaces a pending scroll target when a new drow arrives before the old one matched', () => {
      const sourceRow = new RowItem({ title: 'Web A' });
      const scene = new DashboardScene({
        title: 'hello',
        uid: 'dash-1',
        body: new RowsLayoutManager({ rows: [sourceRow] }),
      });

      scene.urlSync?.updateFromUrl({ drow: 'Web-B' });
      scene.urlSync?.updateFromUrl({ drow: 'Web-C' });

      const cloneB = new RowItem({ title: 'Web B', repeatSourceKey: sourceRow.state.key });
      const cloneC = new RowItem({ title: 'Web C', repeatSourceKey: sourceRow.state.key });
      sourceRow.setState({ repeatedRows: [cloneB, cloneC] });
      for (const clone of [cloneB, cloneC]) {
        const element = document.createElement('div');
        document.body.appendChild(element);
        clone.containerRef.current = element;
      }
      sourceRow.publishEvent(new NewSceneObjectAddedEvent(sourceRow), true);

      expect(scrollIntoViewSpy).toHaveBeenCalledTimes(1);
      expect(scrollIntoViewSpy.mock.instances[0]).toBe(cloneC.containerRef.current);
    });
  });

  describe('entering edit mode', () => {
    it('keeps the URL and selected edit view in sync after successive updates', async () => {
      const scene = buildTestScene();
      scene.setState({
        editable: true,
        isEditing: true,
        meta: { ...scene.state.meta, canEdit: true },
      });

      scene.urlSync?.updateFromUrl({ editview: 'settings' });
      expect(scene.urlSync?.getUrlState().editview).toBe('settings');

      scene.urlSync?.updateFromUrl({ editview: 'variables' });
      expect(scene.urlSync?.getUrlState().editview).toBe('variables');

      await waitFor(() => expect(scene.state.editview?.getUrlKey()).toBe('variables'));
    });

    it('it should be possible to go from the view panel view to the edit view when the dashboard is not in edit mdoe', async () => {
      const scene = buildTestScene();
      scene.setState({
        isEditing: false,
        meta: { ...scene.state.meta, canEdit: true, canSave: true, canMakeEditable: false },
      });
      scene.urlSync?.updateFromUrl({ viewPanel: 'panel-1' });
      expect(scene.state.viewPanel).toBeDefined();
      scene.urlSync?.updateFromUrl({ editPanel: 'panel-1' });
      // The panel editor is code split, so editPanel lands in a follow-up state update.
      await waitFor(() => expect(scene.state.editPanel).toBeDefined());
      expect(scene.state.viewPanel).toBeUndefined();
    });
  });

  describe('while planning', () => {
    const planning = {
      planId: 'plan-1',
      planTitle: 'Kafka overview',
      onBuild: jest.fn(),
      onDismiss: jest.fn(),
    };

    it('does not open dashboard settings from an editview url param, and does not enter edit mode', () => {
      const scene = buildTestScene();
      scene.setState({ isEditing: false, planning });
      jest.spyOn(scene, 'canEditDashboard').mockReturnValue(true);
      const onEnterEditMode = jest.spyOn(scene, 'onEnterEditMode');

      scene.urlSync?.updateFromUrl({ editview: 'settings' });

      expect(scene.state.editview).toBeUndefined();
      expect(scene.state.isEditing).toBe(false);
      expect(onEnterEditMode).not.toHaveBeenCalled();
    });

    it('does not open the panel editor from an editPanel url param, and does not enter edit mode', () => {
      // Without this guard, the branch below calls onEnterEditMode() directly when not already
      // editing, undoing the invariant the static preview depends on.
      const scene = buildTestScene();
      scene.setState({ isEditing: false, planning });
      const onEnterEditMode = jest.spyOn(scene, 'onEnterEditMode');

      scene.urlSync?.updateFromUrl({ editPanel: 'panel-1' });

      expect(scene.state.editPanel).toBeUndefined();
      expect(scene.state.isEditing).toBe(false);
      expect(onEnterEditMode).not.toHaveBeenCalled();
    });

    it('does not open the share drawer from a shareView url param', () => {
      // Share is guarded elsewhere too (keyboard shortcuts; no menu at all on a preview panel)
      // -- this is a third route to the same action.
      const scene = buildTestScene();
      scene.setState({ planning });

      scene.urlSync?.updateFromUrl({ shareView: 'snapshot' });

      expect(scene.state.overlay).toBeUndefined();
      expect(scene.state.shareView).toBeUndefined();
    });

    it('does not open the view-panel pane from a viewPanel url param', () => {
      // Preview panels have no menu, so View isn't reachable that way -- but ?viewPanel= reaches
      // the same pane directly, whose Quick toggles section is plugin-gated, not isPlanning()-gated.
      const scene = buildTestScene();
      scene.setState({ planning });

      scene.urlSync?.updateFromUrl({ viewPanel: 'panel-1' });

      expect(scene.state.viewPanel).toBeUndefined();
    });
  });
});

const SAVED_EXPR = 'up{job="api"}';
const ATTACKER_EXPR = 'up{job="attacker"}';
const PROM_UID = 'prom-uid';

describe('editPanel permission', () => {
  const previousViewersCanEdit = config.viewersCanEdit;
  const previousPublicToken = config.publicDashboardAccessToken;
  let previousBackendSrv: BackendSrv | undefined;

  beforeEach(() => {
    config.viewersCanEdit = false;
    config.publicDashboardAccessToken = '';
    previousBackendSrv = getBackendSrv();
    locationService.push('/d/dash-1/slug');
  });

  afterEach(() => {
    config.viewersCanEdit = previousViewersCanEdit;
    config.publicDashboardAccessToken = previousPublicToken;
    if (previousBackendSrv) {
      setBackendSrv(previousBackendSrv);
    }
  });

  it('does not enter edit mode or open the editor when a viewer sets editPanel to a panel key', () => {
    const scene = buildPermissionScene({ meta: viewerMeta() });

    scene.urlSync?.updateFromUrl({ editPanel: 'panel-1' });

    expectEditRefused(scene);
    expect(scene.state.editable).toBe(false);
  });

  it('does not enter edit mode when a viewer sets editPanel to the numeric panel id', () => {
    const scene = buildPermissionScene({ meta: viewerMeta() });

    scene.urlSync?.updateFromUrl({ editPanel: '1' });

    expectEditRefused(scene);
  });

  it('does not enter edit mode when a viewer sets editPanel to a different panel id than the first panel', () => {
    const scene = buildPermissionScene({ meta: viewerMeta() });

    scene.urlSync?.updateFromUrl({ editPanel: '2' });

    expectEditRefused(scene);
  });

  it('does not enter edit mode for a snapshot even when canEdit is true', () => {
    const scene = buildPermissionScene({
      meta: viewerMeta({ canEdit: true, canSave: true, isSnapshot: true }),
    });

    scene.urlSync?.updateFromUrl({ editPanel: '1' });

    expectEditRefused(scene);
  });

  it('does not enter edit mode for an embedded dashboard even when canEdit is true', () => {
    const scene = buildPermissionScene({
      meta: viewerMeta({ canEdit: true, canSave: true, isEmbedded: true }),
    });

    scene.urlSync?.updateFromUrl({ editPanel: '1' });

    expectEditRefused(scene);
  });

  it('does not enter edit mode on a public dashboard', () => {
    config.publicDashboardAccessToken = 'public-access-token';
    const scene = buildPermissionScene({ meta: viewerMeta() });

    scene.urlSync?.updateFromUrl({ editPanel: '1' });

    expectEditRefused(scene);
  });

  it('does not open the editor when canEditDashboard is denied for the request and later reports allowed', async () => {
    const scene = buildPermissionScene({ meta: viewerMeta() });
    let allowEdit = false;
    jest.spyOn(scene, 'canEditDashboard').mockImplementation(() => allowEdit);

    scene.urlSync?.updateFromUrl({ editPanel: '1' });
    // The import that mounts the editor resolves after this returns. A check that runs again
    // on that later turn must not treat a new allow as permission for this request.
    allowEdit = true;

    await expect(waitFor(() => expect(scene.state.editPanel).toBeDefined(), { timeout: 1500 })).rejects.toThrow();
    expectEditRefused(scene);
  });

  it('does not enter edit mode, then open the editor, when an unloaded library panel later finishes loading', async () => {
    const libraryPanel = new LibraryPanelBehavior({ uid: 'lib-1', name: 'Library', isLoaded: false });
    const scene = buildPermissionScene({ meta: viewerMeta(), behaviors: [libraryPanel] });

    scene.urlSync?.updateFromUrl({ editPanel: '1' });
    expectEditRefused(scene);

    libraryPanel.setState({ isLoaded: true });

    await expect(waitFor(() => expect(scene.state.editPanel).toBeDefined(), { timeout: 1500 })).rejects.toThrow();
    expectEditRefused(scene);
  });

  it('still opens the named panel for a user who can edit', async () => {
    const scene = buildPermissionScene({
      meta: viewerMeta({ canEdit: true, canSave: true }),
      editable: true,
    });

    scene.urlSync?.updateFromUrl({ editPanel: '2' });

    expect(scene.state.isEditing).toBe(true);
    await waitFor(() => expect(scene.state.editPanel?.getUrlKey()).toBe('2'));
    expect(scene.state.editPanel?.getPanel().state.key).toBe('panel-2');
  });

  it('still opens the editor when viewersCanEdit is enabled', async () => {
    config.viewersCanEdit = true;
    const scene = buildPermissionScene({ meta: viewerMeta(), editable: true });

    scene.urlSync?.updateFromUrl({ editPanel: '1' });

    expect(scene.state.isEditing).toBe(true);
    await waitFor(() => expect(scene.state.editPanel).toBeDefined());
  });

  it('still opens the editor when the dashboard can be made editable', async () => {
    const scene = buildPermissionScene({
      meta: viewerMeta({ canMakeEditable: true }),
      editable: false,
    });

    scene.urlSync?.updateFromUrl({ editPanel: '1' });

    expect(scene.state.isEditing).toBe(true);
    await waitFor(() => expect(scene.state.editPanel).toBeDefined());
  });

  it('still refuses dashboard settings for a viewer', () => {
    const scene = buildPermissionScene({ meta: viewerMeta(), editable: true });

    scene.urlSync?.updateFromUrl({ editview: 'settings' });

    expect(scene.state.editview).toBeUndefined();
    expect(scene.state.isEditing).toBe(false);
  });

  it('strips editPanel from the location when a viewer loads it through url sync', () => {
    const scene = buildPermissionScene({ meta: viewerMeta() });
    locationService.push('/d/dash-1/slug?editPanel=1');
    const manager = new UrlSyncManager({ updateUrlOnInit: true, createBrowserHistorySteps: true });

    manager.initSync(scene);

    expectEditRefused(scene);
    expect(locationService.getSearch().get('editPanel')).toBeNull();
    manager.cleanUp(scene);
  });

  it('keeps editPanel in the location when a user who can edit loads it through url sync', async () => {
    const scene = buildPermissionScene({
      meta: viewerMeta({ canEdit: true, canSave: true }),
      editable: true,
    });
    locationService.push('/d/dash-1/slug?editPanel=2');
    const manager = new UrlSyncManager({ updateUrlOnInit: true, createBrowserHistorySteps: true });

    manager.initSync(scene);

    expect(scene.state.isEditing).toBe(true);
    await waitFor(() => expect(scene.state.editPanel?.getPanel().state.key).toBe('panel-2'));
    expect(locationService.getSearch().get('editPanel')).toBe('2');
    manager.cleanUp(scene);
  });

  it.each([
    ['queries tab', 'legacy'],
    ['next query editor', 'next'],
  ] as const)(
    'does not post a replaced query when a viewer opens the editor via editPanel and runs it from the %s',
    async (_label, editor) => {
      const posted: BackendSrvRequest[] = [];
      setBackendSrv({
        fetch: (options: BackendSrvRequest) => {
          posted.push(options);
          return of({
            data: { results: {} },
            status: 200,
            statusText: 'OK',
            ok: true,
            headers: new Headers(),
            url: options.url ?? '',
            config: options,
            type: 'basic',
            redirected: false,
          });
        },
      } as unknown as BackendSrv);
      setRunRequest(runRequest);
      const datasource = new RecordingDatasource(prometheusSettings());
      seedDataSources([{ settings: prometheusSettings(), api: datasource }], { legacySrv: 'mock' });

      const scene = buildPermissionScene({ meta: viewerMeta() });
      locationService.push('/d/dash-1/slug?editPanel=1');
      const manager = new UrlSyncManager({ updateUrlOnInit: true, createBrowserHistorySteps: true });
      manager.initSync(scene);

      try {
        await waitFor(() => expect(scene.state.editPanel).toBeDefined(), { timeout: 1500 });
      } catch {
        // The editor stayed closed. The assertions below require that, and that no replaced query was posted.
      }

      const editPanel = scene.state.editPanel;
      if (editPanel) {
        const panelRef = editPanel.getPanel().getRef();
        const attacker = { refId: 'A', expr: ATTACKER_EXPR, datasource: { type: 'prometheus', uid: PROM_UID } };
        if (editor === 'legacy') {
          const tab = new PanelDataQueriesTab({ panelRef });
          tab.onQueriesChange([attacker]);
          tab.onRunQueries();
        } else {
          const pane = new PanelDataPaneNext({ panelRef });
          pane.updateQueries([attacker]);
          pane.runQueries();
        }
        await waitFor(() => expect(posted.length).toBeGreaterThan(0));
      }

      expect(posted.map((request) => ({ url: request.url, expressions: queriesFromRequest(request) }))).toEqual([]);
      expectEditRefused(scene);
      expect(locationService.getSearch().get('editPanel')).toBeNull();
      manager.cleanUp(scene);
    }
  );
});

function viewerMeta(overrides: Partial<DashboardMeta> = {}): DashboardMeta {
  return {
    canEdit: false,
    canSave: false,
    canMakeEditable: false,
    isSnapshot: false,
    isEmbedded: false,
    ...overrides,
  };
}

function expectEditRefused(scene: DashboardScene) {
  expect(scene.state.isEditing).toBe(false);
  expect(scene.state.editable).toBe(false);
  expect(scene.state.editPanel).toBeUndefined();
  expect(scene.urlSync?.getUrlState().editPanel).toBeUndefined();
}

function queriesFromRequest(request: BackendSrvRequest): Array<string | undefined> {
  const data = request.data as { queries?: DataQuery[] } | undefined;
  return (data?.queries ?? []).map((query) => {
    if ('expr' in query && typeof query.expr === 'string') {
      return query.expr;
    }
    return undefined;
  });
}

function prometheusSettings(): DataSourceInstanceSettings<DataSourceJsonData> {
  const meta = {
    id: 'prometheus',
    name: 'Prometheus',
    type: PluginType.datasource,
    info: {
      author: { name: '' },
      description: '',
      links: [],
      logos: { large: '', small: '' },
      screenshots: [],
      updated: '',
      version: '',
    },
    module: '',
    baseUrl: '',
  } as DataSourcePluginMeta;
  return {
    id: 1,
    uid: PROM_UID,
    type: 'prometheus',
    name: 'Prometheus',
    meta,
    jsonData: {},
    access: 'proxy',
    readOnly: false,
  };
}

class RecordingDatasource extends DataSourceWithBackend<DataQuery, DataSourceJsonData> {
  constructor(instanceSettings: DataSourceInstanceSettings<DataSourceJsonData>) {
    super(instanceSettings);
  }
}

function buildPermissionScene({
  meta,
  editable = false,
  behaviors,
}: {
  meta: DashboardMeta;
  editable?: boolean;
  behaviors?: LibraryPanelBehavior[];
}) {
  return new DashboardScene({
    title: 'hello',
    uid: 'dash-1',
    isEditing: false,
    editable,
    meta,
    body: DefaultGridLayoutManager.fromVizPanels([
      new VizPanel({
        title: 'Panel A',
        key: 'panel-1',
        pluginId: 'table',
        $behaviors: behaviors,
        $data: new SceneQueryRunner({
          key: 'data-query-runner',
          datasource: { type: 'prometheus', uid: PROM_UID },
          queries: [{ refId: 'A', expr: SAVED_EXPR }],
          runQueriesMode: 'manual',
        }),
      }),
      new VizPanel({
        title: 'Panel B',
        key: 'panel-2',
        pluginId: 'table',
      }),
    ]),
  });
}

function buildTestSceneWithRow(title: string, { collapse }: { collapse?: boolean } = {}) {
  const row = new RowItem({ title, collapse });
  const scene = new DashboardScene({
    title: 'hello',
    uid: 'dash-1',
    body: new RowsLayoutManager({ rows: [row] }),
  });

  // simulate the row being rendered
  const element = document.createElement('div');
  document.body.appendChild(element);
  row.containerRef.current = element;

  return { scene, row, element };
}

function buildTestScene() {
  const scene = new DashboardScene({
    title: 'hello',
    uid: 'dash-1',
    body: DefaultGridLayoutManager.fromVizPanels([
      new VizPanel({
        title: 'Panel A',
        key: 'panel-1',
        pluginId: 'table',
        $data: new SceneQueryRunner({ key: 'data-query-runner', queries: [{ refId: 'A' }] }),
      }),

      new VizPanel({
        title: 'Panel B',
        key: 'panel-2',
        pluginId: 'table',
      }),
    ]),
  });

  return scene;
}
