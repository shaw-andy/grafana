import { renderHook } from '@testing-library/react';

import { config } from '@grafana/runtime';
import { type Spec as DashboardV2Spec } from '@grafana/schema/apis/dashboard.grafana.app/v2';
import { type DashboardWithAccessInfo } from 'app/features/dashboard/api/types';

import { transformSaveModelSchemaV2ToScene } from '../../serialization/transformSaveModelSchemaV2ToScene';
import { type DashboardScene } from '../../scene/DashboardScene';
import { AutoGridLayoutManager } from '../../scene/layout-auto-grid/AutoGridLayoutManager';
import { RowsLayoutManager } from '../../scene/layout-rows/RowsLayoutManager';
import { TabsLayoutManager } from '../../scene/layout-tabs/TabsLayoutManager';
import { dashboardV2SpecSchema } from '../../v2schema/dashboardV2Schema';
import { ConditionalRenderingGroup } from '../group/ConditionalRenderingGroup';
import { useIsConditionallyHidden } from '../hooks/useIsConditionallyHidden';

import { ConditionalRenderingVariable } from './ConditionalRenderingVariable';

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  getDataSourceSrv: () => ({
    getInstanceSettings: jest.fn(),
  }),
}));

// A string of only the repeated character matches `(a+)+$` in linear time.
// One character that prevents a match forces every partition of the run.
// Twenty-eight `a`s plus that character stays above DEADLINE_MS on this runtime,
// including after the regexp compiler has already seen the pattern once.
const HANG_PATTERN = '(a+)+$';
const HANG_REPEAT = 28;
const HANG_VALUE = `${'a'.repeat(HANG_REPEAT)}!`;
const DEADLINE_MS = 300;

type StoredOperator = 'equals' | 'matches' | 'notMatches';
type LayoutKind = 'rows' | 'tabs' | 'autoGrid';

interface StoredRule {
  layout: LayoutKind;
  operator: StoredOperator;
  pattern: string;
  /** Name stored on the rule. The dashboard variable itself is always `probe`. */
  ruleVariable?: string;
  /** Text variable current value, or each selected value of a multi-value custom variable. */
  value: string | string[];
  canEdit?: boolean;
}

function textVariable(name: string, value: string) {
  return {
    kind: 'TextVariable' as const,
    spec: {
      name,
      query: value,
      current: { text: value, value },
    },
  };
}

function multiVariable(name: string, values: string[]) {
  return {
    kind: 'CustomVariable' as const,
    spec: {
      name,
      query: values.join(','),
      multi: true,
      includeAll: false,
      current: { text: values, value: values },
      options: values.map((value) => ({ text: value, value, selected: true })),
    },
  };
}

function conditionalRendering(rule: StoredRule) {
  return {
    kind: 'ConditionalRenderingGroup' as const,
    spec: {
      visibility: 'show' as const,
      condition: 'and' as const,
      items: [
        {
          kind: 'ConditionalRenderingVariable' as const,
          spec: {
            variable: rule.ruleVariable ?? 'probe',
            operator: rule.operator,
            value: rule.pattern,
          },
        },
      ],
    },
  };
}

function emptyAutoGrid() {
  return { kind: 'AutoGridLayout' as const, spec: { items: [] } };
}

function panelElement() {
  return {
    kind: 'Panel' as const,
    spec: {
      id: 1,
      title: 'Panel',
      links: [],
      data: {
        kind: 'QueryGroup' as const,
        spec: { queries: [], transformations: [], queryOptions: {} },
      },
      vizConfig: {
        kind: 'VizConfig' as const,
        group: 'text',
        spec: { options: {}, fieldConfig: { defaults: {}, overrides: [] } },
      },
    },
  };
}

function storedDashboard(rule: StoredRule) {
  const variable = Array.isArray(rule.value) ? multiVariable('probe', rule.value) : textVariable('probe', rule.value);
  const rendering = conditionalRendering(rule);

  if (rule.layout === 'rows') {
    return {
      title: 'Stored rule',
      editable: true,
      timeSettings: {},
      variables: [variable],
      elements: {},
      layout: {
        kind: 'RowsLayout' as const,
        spec: {
          rows: [
            {
              kind: 'RowsLayoutRow' as const,
              spec: {
                title: 'Row',
                conditionalRendering: rendering,
                layout: emptyAutoGrid(),
              },
            },
          ],
        },
      },
    };
  }

  if (rule.layout === 'tabs') {
    return {
      title: 'Stored rule',
      editable: true,
      timeSettings: {},
      variables: [variable],
      elements: {},
      layout: {
        kind: 'TabsLayout' as const,
        spec: {
          tabs: [
            {
              kind: 'TabsLayoutTab' as const,
              spec: {
                title: 'Tab',
                conditionalRendering: rendering,
                layout: emptyAutoGrid(),
              },
            },
          ],
        },
      },
    };
  }

  return {
    title: 'Stored rule',
    editable: true,
    timeSettings: {},
    variables: [variable],
    elements: { 'panel-1': panelElement() },
    layout: {
      kind: 'AutoGridLayout' as const,
      spec: {
        items: [
          {
            kind: 'AutoGridLayoutItem' as const,
            spec: {
              element: { kind: 'ElementReference' as const, name: 'panel-1' },
              conditionalRendering: rendering,
            },
          },
        ],
      },
    },
  };
}

function viewerDto(spec: DashboardV2Spec, canEdit: boolean): DashboardWithAccessInfo<DashboardV2Spec> {
  return {
    kind: 'DashboardWithAccessInfo',
    apiVersion: 'v2',
    metadata: {
      name: 'dash',
      namespace: 'default',
      labels: {},
      generation: 1,
      resourceVersion: '1',
      creationTimestamp: '2020-01-01T00:00:00Z',
      annotations: {},
    },
    spec,
    access: {
      canEdit,
      canSave: canEdit,
      canDelete: false,
      canAdmin: false,
    },
  };
}

interface LoadedRule {
  rejected: boolean;
  scene?: DashboardScene;
  condition?: ConditionalRenderingVariable;
  group?: ConditionalRenderingGroup;
}

/**
 * Parse the stored dashboard the way the viewer load path does, then build the scene.
 * Rejection of this rule, when the same dashboard with an ordinary pattern parses,
 * means the pattern never reaches evaluation.
 */
function loadStoredRule(rule: StoredRule): LoadedRule {
  const control = dashboardV2SpecSchema.safeParse(
    storedDashboard({
      ...rule,
      operator: 'matches',
      pattern: '^a+$',
      ruleVariable: 'probe',
      value: Array.isArray(rule.value) ? ['b', 'aaa'] : 'aaa',
    })
  );
  if (!control.success) {
    throw new Error(`control dashboard was rejected: ${control.error.message}`);
  }

  const parsed = dashboardV2SpecSchema.safeParse(storedDashboard(rule));
  if (!parsed.success) {
    return { rejected: true };
  }

  const scene = transformSaveModelSchemaV2ToScene(viewerDto(parsed.data, rule.canEdit ?? false));
  const found = findCondition(scene);
  return { rejected: false, scene, condition: found?.condition, group: found?.group };
}

function findCondition(
  scene: DashboardScene
): { condition: ConditionalRenderingVariable; group: ConditionalRenderingGroup } | undefined {
  const body = scene.state.body;
  let group: ConditionalRenderingGroup | undefined;

  if (body instanceof RowsLayoutManager) {
    group = body.state.rows[0]?.state.conditionalRendering;
  } else if (body instanceof TabsLayoutManager) {
    group = body.state.tabs[0]?.state.conditionalRendering;
  } else if (body instanceof AutoGridLayoutManager) {
    group = body.state.layout.state.children[0]?.state.conditionalRendering;
  }

  const condition = group?.state.conditions[0];
  if (!(condition instanceof ConditionalRenderingVariable) || !group) {
    return undefined;
  }
  return { condition, group };
}

function expectFast(elapsedMs: number) {
  expect(elapsedMs).toBeLessThan(DEADLINE_MS);
}

function elapsed(run: () => void): number {
  const start = performance.now();
  run();
  return performance.now() - start;
}

/**
 * Variable resolution runs before the row, tab, or panel activates its rule.
 * The layout item then calls `conditionalRendering.activate()`, which is also what
 * `useIsConditionallyHidden` does. Activating the group runs the stored pattern.
 * The panel body is left inactive so plugin startup stays out of this measurement.
 */
function settleVariables(scene: DashboardScene) {
  scene.state.$variables?.activate();
}

function activateStoredRule(loaded: LoadedRule): number {
  settleVariables(loaded.scene!);
  return elapsed(() => loaded.group!.activate());
}

describe('conditional rendering regex evaluation', () => {
  beforeAll(() => {
    config.featureToggles.dashboardNewLayouts = true;
  });

  it('matches a stored ordinary pattern when a viewer opens the row', () => {
    const loaded = loadStoredRule({
      layout: 'rows',
      operator: 'matches',
      pattern: '^a+$',
      value: 'aaa',
    });
    expect(loaded.rejected).toBe(false);
    expect(loaded.scene?.state.meta.canEdit).toBe(false);
    const ms = activateStoredRule(loaded);
    expectFast(ms);
    expect(loaded.condition?.state.result).toBe(true);
  });

  it('matches a stored ordinary pattern against one selected value of a multi-value variable', () => {
    const loaded = loadStoredRule({
      layout: 'autoGrid',
      operator: 'matches',
      pattern: '^a+$',
      value: ['b', 'aaa'],
    });
    expect(loaded.rejected).toBe(false);
    const ms = activateStoredRule(loaded);
    expectFast(ms);
    expect(loaded.condition?.state.result).toBe(true);
  });

  it('finishes a stored matches rule when a viewer opens the row', () => {
    const loaded = loadStoredRule({
      layout: 'rows',
      operator: 'matches',
      pattern: HANG_PATTERN,
      value: HANG_VALUE,
      canEdit: false,
    });
    if (loaded.rejected) {
      return;
    }
    expect(loaded.scene?.state.meta.canEdit).toBe(false);
    expectFast(activateStoredRule(loaded));
  });

  it('finishes a stored matches rule when an editor opens the row', () => {
    const loaded = loadStoredRule({
      layout: 'rows',
      operator: 'matches',
      pattern: HANG_PATTERN,
      value: HANG_VALUE,
      canEdit: true,
    });
    if (loaded.rejected) {
      return;
    }
    expect(loaded.scene?.state.meta.canEdit).toBe(true);
    expectFast(activateStoredRule(loaded));
  });

  it('finishes a stored notMatches rule when a viewer opens the tab', () => {
    const loaded = loadStoredRule({
      layout: 'tabs',
      operator: 'notMatches',
      pattern: HANG_PATTERN,
      value: HANG_VALUE,
    });
    if (loaded.rejected) {
      return;
    }
    expectFast(activateStoredRule(loaded));
  });

  it('finishes a stored matches rule against each selected value when a viewer opens the panel', () => {
    const loaded = loadStoredRule({
      layout: 'autoGrid',
      operator: 'matches',
      pattern: HANG_PATTERN,
      value: [HANG_VALUE, 'b'],
    });
    if (loaded.rejected) {
      return;
    }
    expectFast(activateStoredRule(loaded));
  });

  it('finishes when the row renderer subscribes through useIsConditionallyHidden', () => {
    const loaded = loadStoredRule({
      layout: 'rows',
      operator: 'matches',
      pattern: HANG_PATTERN,
      value: HANG_VALUE,
    });
    if (loaded.rejected) {
      return;
    }
    const group = loaded.group!;
    expect(group.isActive).toBe(false);
    settleVariables(loaded.scene!);
    expectFast(elapsed(() => renderHook(() => useIsConditionallyHidden(group))));
  });

  it('finishes when an active rule value changes to the stored pattern', () => {
    const loaded = loadStoredRule({
      layout: 'rows',
      operator: 'matches',
      pattern: '^z$',
      value: HANG_VALUE,
    });
    expect(loaded.rejected).toBe(false);
    activateStoredRule(loaded);
    expect(loaded.condition?.state.result).toBe(false);
    expectFast(elapsed(() => loaded.condition!.changeValue(HANG_PATTERN)));
  });

  it('finishes when an active rule operator changes to matches', () => {
    const loaded = loadStoredRule({
      layout: 'rows',
      operator: 'equals',
      pattern: HANG_PATTERN,
      value: HANG_VALUE,
    });
    expect(loaded.rejected).toBe(false);
    activateStoredRule(loaded);
    expect(loaded.condition?.state.result).toBe(false);
    expectFast(elapsed(() => loaded.condition!.changeOperator('=~')));
  });

  it('finishes when an active rule starts referencing the variable that holds the value', () => {
    const loaded = loadStoredRule({
      layout: 'rows',
      operator: 'matches',
      pattern: HANG_PATTERN,
      ruleVariable: 'absent',
      value: HANG_VALUE,
    });
    expect(loaded.rejected).toBe(false);
    activateStoredRule(loaded);
    expect(loaded.condition?.state.result).toBeUndefined();
    expectFast(elapsed(() => loaded.condition!.changeVariable('probe')));
  });

  it('finishes when the group rechecks after the pattern is applied to an active rule', () => {
    const loaded = loadStoredRule({
      layout: 'rows',
      operator: 'matches',
      pattern: '^z$',
      value: HANG_VALUE,
    });
    expect(loaded.rejected).toBe(false);
    activateStoredRule(loaded);
    loaded.condition!.setState({ value: HANG_PATTERN });
    expectFast(elapsed(() => loaded.group!.forceCheck()));
  });
});
