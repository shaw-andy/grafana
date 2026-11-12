import { TextBoxVariable } from '@grafana/scenes';
import { type Dashboard } from '@grafana/schema';
import {
  defaultConstantVariableKind,
  defaultPanelSpec,
  type TextVariableKind,
} from '@grafana/schema/apis/dashboard.grafana.app/v2';

import { transformSaveModelToScene } from '../serialization/transformSaveModelToScene';
import { renderMatchingSoloPanels } from '../solo/SoloPanelContext';
import { dashboardSceneGraph } from '../utils/dashboardSceneGraph';
import { getTestDashboardSceneFromSaveModel } from '../utils/test-utils';

import { type DashboardScene } from './DashboardScene';
import { SoloPanelContextValueWithSearchStringFilter } from './PanelSearchLayout';

// `new RegExp('((a+)+)+$', 'i')` against 17 a's and a failing character stays above 900ms
// on the Node 22 V8 this repo tests with, including after that engine has already compiled
// the same pattern once. A literal or escaped match returns in well under this budget.
const NESTED_QUANTIFIER = '((a+)+)+$';
const BACKTRACKING_TITLE = `${'a'.repeat(17)}!`;
const MATCH_BUDGET_MS = 400;

function savedConstantDashboard(query: string, title: string): Dashboard {
  return {
    title: 'Panel filter',
    uid: 'panel-filter',
    schemaVersion: 39,
    version: 1,
    editable: true,
    panels: [
      {
        id: 1,
        type: 'timeseries',
        title,
        gridPos: { x: 0, y: 0, w: 12, h: 8 },
      },
    ],
    templating: {
      list: [
        {
          name: 'systemPanelFilterVar',
          type: 'constant',
          query,
          hide: 2,
          skipUrlSync: true,
        },
      ],
    },
    time: { from: 'now-6h', to: 'now' },
  } as Dashboard;
}

function sceneFromV1(dashboard: Dashboard): DashboardScene {
  const scene = transformSaveModelToScene({ dashboard, meta: {} });
  // Annotation layers query the built-in datasource when the scene activates.
  scene.setState({ $data: undefined });
  return scene;
}

function initializePanelSearch(scene: DashboardScene) {
  // Same private hook DashboardScene.activate runs before variable sets notify dependents.
  // @ts-expect-error activation calls this; it is not part of the public scene API
  scene._initializePanelSearch();
}

function activate(scene: DashboardScene) {
  const deactivate = scene.activate();
  return deactivate;
}

function applySavedFilter(scene: DashboardScene) {
  const panel = dashboardSceneGraph.getVizPanels(scene)[0];
  const filter = new SoloPanelContextValueWithSearchStringFilter(scene.state.panelSearch ?? '');
  const started = performance.now();
  // DashboardGridItemRenderer and AutoGridItemRenderer both enter the regex through here.
  renderMatchingSoloPanels(filter, [panel], false);
  return { elapsedMs: performance.now() - started, matched: filter.matchFound };
}

describe('systemPanelFilterVar', () => {
  it('applies a saved literal constant when the dashboard scene initializes panel search', () => {
    const scene = sceneFromV1(savedConstantDashboard('cpu', 'CPU Usage'));
    initializePanelSearch(scene);

    const result = applySavedFilter(scene);

    expect(scene.state.panelSearch).toBe('cpu');
    expect(result.matched).toBe(true);
    expect(result.elapsedMs).toBeLessThan(MATCH_BUDGET_MS);
  });

  it('finishes matching a saved nested quantifier while initializing panel search', () => {
    const scene = sceneFromV1(savedConstantDashboard(NESTED_QUANTIFIER, BACKTRACKING_TITLE));
    initializePanelSearch(scene);

    expect(dashboardSceneGraph.getVizPanels(scene)[0].state.title).toBe(BACKTRACKING_TITLE);
    expect(applySavedFilter(scene).elapsedMs).toBeLessThan(MATCH_BUDGET_MS);
  });

  it('finishes matching a saved nested quantifier when the dashboard scene activates', () => {
    const scene = sceneFromV1(savedConstantDashboard(NESTED_QUANTIFIER, BACKTRACKING_TITLE));
    const deactivate = activate(scene);
    try {
      expect(dashboardSceneGraph.getVizPanels(scene)[0].state.title).toBe(BACKTRACKING_TITLE);
      expect(applySavedFilter(scene).elapsedMs).toBeLessThan(MATCH_BUDGET_MS);
    } finally {
      deactivate();
    }
  });

  it('copies a later textbox value into panel search', () => {
    const scene = sceneFromV1({
      ...savedConstantDashboard('memory', 'CPU Usage'),
      templating: {
        list: [
          {
            name: 'systemPanelFilterVar',
            type: 'textbox',
            query: 'memory',
            current: { value: 'memory', text: 'memory', selected: true },
            hide: 2,
          },
        ],
      },
    });
    const deactivate = activate(scene);
    try {
      const variable = scene.state.$variables?.getByName('systemPanelFilterVar');
      expect(variable).toBeInstanceOf(TextBoxVariable);
      (variable as TextBoxVariable).setValue('cpu');

      expect(scene.state.panelSearch).toBe('cpu');
      const result = applySavedFilter(scene);
      expect(result.matched).toBe(true);
      expect(result.elapsedMs).toBeLessThan(MATCH_BUDGET_MS);
    } finally {
      deactivate();
    }
  });

  it('finishes matching after a textbox systemPanelFilterVar updates to a nested quantifier', () => {
    const scene = sceneFromV1({
      ...savedConstantDashboard('cpu', BACKTRACKING_TITLE),
      templating: {
        list: [
          {
            name: 'systemPanelFilterVar',
            type: 'textbox',
            query: 'cpu',
            current: { value: 'cpu', text: 'cpu', selected: true },
            hide: 2,
          },
        ],
      },
    });
    const deactivate = activate(scene);
    try {
      const variable = scene.state.$variables?.getByName('systemPanelFilterVar');
      expect(variable).toBeInstanceOf(TextBoxVariable);
      (variable as TextBoxVariable).setValue(NESTED_QUANTIFIER);

      expect(dashboardSceneGraph.getVizPanels(scene)[0].state.title).toBe(BACKTRACKING_TITLE);
      expect(applySavedFilter(scene).elapsedMs).toBeLessThan(MATCH_BUDGET_MS);
    } finally {
      deactivate();
    }
  });

  it('finishes matching a v2 constant systemPanelFilterVar when the dashboard scene activates', () => {
    const variable = defaultConstantVariableKind();
    variable.spec.name = 'systemPanelFilterVar';
    variable.spec.query = NESTED_QUANTIFIER;
    variable.spec.hide = 'hideVariable';

    const scene = getTestDashboardSceneFromSaveModel({
      elements: {
        'panel-1': {
          kind: 'Panel',
          spec: {
            ...defaultPanelSpec(),
            id: 1,
            title: BACKTRACKING_TITLE,
          },
        },
      },
      variables: [variable],
    });
    scene.setState({ $data: undefined });
    const deactivate = activate(scene);
    try {
      expect(dashboardSceneGraph.getVizPanels(scene)[0].state.title).toBe(BACKTRACKING_TITLE);
      expect(applySavedFilter(scene).elapsedMs).toBeLessThan(MATCH_BUDGET_MS);
    } finally {
      deactivate();
    }
  });

  it('finishes matching after a v2 text variable updates to a nested quantifier', () => {
    const variable: TextVariableKind = {
      kind: 'TextVariable',
      spec: {
        name: 'systemPanelFilterVar',
        query: 'cpu',
        current: { text: 'cpu', value: 'cpu' },
        hide: 'hideVariable',
        skipUrlSync: false,
      },
    };
    const scene = getTestDashboardSceneFromSaveModel({
      elements: {
        'panel-1': {
          kind: 'Panel',
          spec: {
            ...defaultPanelSpec(),
            id: 1,
            title: BACKTRACKING_TITLE,
          },
        },
      },
      variables: [variable],
    });
    scene.setState({ $data: undefined });
    const deactivate = activate(scene);
    try {
      const textbox = scene.state.$variables?.getByName('systemPanelFilterVar');
      expect(textbox).toBeInstanceOf(TextBoxVariable);
      (textbox as TextBoxVariable).setValue(NESTED_QUANTIFIER);

      expect(dashboardSceneGraph.getVizPanels(scene)[0].state.title).toBe(BACKTRACKING_TITLE);
      expect(applySavedFilter(scene).elapsedMs).toBeLessThan(MATCH_BUDGET_MS);
    } finally {
      deactivate();
    }
  });
});
