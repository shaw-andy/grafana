import {
  type DataSourceInstanceListItem,
  FieldType,
  stringToJsRegex,
  SupportedTransformationType,
  toDataFrame,
  VariableSort,
} from '@grafana/data';
import { getMockPlugins } from '@grafana/data/test';
import { CustomVariable, SceneVariableSet } from '@grafana/scenes';
import TimeSeries from 'app/core/time_series2';
import kbn from 'app/core/utils/kbn';
import { getTransformationVars } from 'app/features/correlations/transformations';
import { ConditionalRenderingVariable } from 'app/features/dashboard-scene/conditional-rendering/conditions/ConditionalRenderingVariable';
import { ConditionalRenderingGroup } from 'app/features/dashboard-scene/conditional-rendering/group/ConditionalRenderingGroup';
import { DashboardScene } from 'app/features/dashboard-scene/scene/DashboardScene';
import { AutoGridLayoutManager } from 'app/features/dashboard-scene/scene/layout-auto-grid/AutoGridLayoutManager';
import { RowItem } from 'app/features/dashboard-scene/scene/layout-rows/RowItem';
import { RowsLayoutManager } from 'app/features/dashboard-scene/scene/layout-rows/RowsLayoutManager';
import { activateFullSceneTree } from 'app/features/dashboard-scene/utils/test-utils';
import { addExtractedFields } from 'app/features/transformers/extractFields/extractFields';
import { FieldExtractorID } from 'app/features/transformers/extractFields/types';

import { createDataSourceVariableAdapter } from './datasource/adapter';
import { createDataSourceOptions, dataSourceVariableReducer } from './datasource/reducer';
import { createQueryVariableAdapter } from './query/adapter';
import { metricNamesToVariableValues, queryVariableReducer, updateVariableOptions } from './query/reducer';
import { getDataSourceInstanceSetting } from './shared/testing/helpers';
import { getVariableTestContext } from './state/helpers';
import { toVariablePayload } from './utils';

// See packages/grafana-data/src/text/storedRegexBacktracking.test.ts for why these lengths
// separate a backtracking match from a bounded one.
const ANCHORED_SUBJECT = `${'a'.repeat(29)}!`;
const OPEN_SUBJECT = `${'a'.repeat(28)}!`;
const BUDGET_MS = 250;

function expectMatchBounded(run: () => unknown) {
  const start = performance.now();
  try {
    run();
  } catch {
    // Rejecting the stored pattern is a fix, as long as the rejection itself is fast.
  }
  expect(performance.now() - start).toBeLessThan(BUDGET_MS);
}

function dataSourceListItem(name: string): DataSourceInstanceListItem {
  const plugin = getMockPlugins(1)[0];
  const settings = getDataSourceInstanceSetting(plugin.name, plugin);
  return {
    uid: settings.uid,
    type: settings.type,
    name,
    meta: settings.meta,
    isDefault: false,
  };
}

describe('stored variable, override, and link regular expressions must not backtrack without a bound', () => {
  jest.setTimeout(30000);

  it('builds query variable options from a slash-less nested regex within the budget', () => {
    expectMatchBounded(() => {
      metricNamesToVariableValues('(a+)+$', VariableSort.disabled, [
        { text: ANCHORED_SUBJECT, value: ANCHORED_SUBJECT },
      ]);
    });
  });

  it('builds query variable options from a slash-wrapped nested regex within the budget', () => {
    expectMatchBounded(() => {
      metricNamesToVariableValues('/(a+)+$/', VariableSort.disabled, [{ text: OPEN_SUBJECT, value: OPEN_SUBJECT }]);
    });
  });

  it('applies a refreshed query variable regex through the reducer within the budget', () => {
    const { initialState } = getVariableTestContext(createQueryVariableAdapter(), { includeAll: false });
    const payload = toVariablePayload(
      { id: '0', type: 'query' },
      {
        results: [{ text: ANCHORED_SUBJECT, value: ANCHORED_SUBJECT }],
        templatedRegex: '(a+)+$',
      }
    );

    expectMatchBounded(() => {
      queryVariableReducer(initialState, updateVariableOptions(payload));
    });
  });

  it('filters datasource variable options with a nested regex within the budget', () => {
    const source = dataSourceListItem(ANCHORED_SUBJECT);
    const { initialState } = getVariableTestContext(createDataSourceVariableAdapter(), {
      query: source.meta.id,
      includeAll: false,
    });

    expectMatchBounded(() => {
      const regex = stringToJsRegex('(a+)+$');
      const payload = toVariablePayload({ id: '0', type: 'datasource' }, { sources: [source], regex });
      dataSourceVariableReducer(initialState, createDataSourceOptions(payload));
    });
  });

  it('extracts fields with a slash-wrapped nested regex within the budget', () => {
    const frame = toDataFrame({
      fields: [{ name: 'line', type: FieldType.string, values: [OPEN_SUBJECT] }],
    });

    expectMatchBounded(() => {
      addExtractedFields(frame, {
        source: 'line',
        format: FieldExtractorID.RegExp,
        regExp: '/(a+)+$/',
      });
    });
  });

  it('applies a series override alias regex within the budget', () => {
    const series = new TimeSeries({ alias: OPEN_SUBJECT, datapoints: [] });

    expectMatchBounded(() => {
      series.applySeriesOverrides([{ alias: '/(a+)+$/', lines: true }]);
    });
  });

  it('matches through the deprecated kbn.stringToJsRegex wrapper within the budget', () => {
    // The wrapper logs a deprecation warning before it compiles. That warning is not the bug.
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      expectMatchBounded(() => {
        kbn.stringToJsRegex('(a+)+$').test(ANCHORED_SUBJECT);
      });
    } finally {
      warn.mockRestore();
    }
  });

  it('builds data-link variables from a nested correlation regex within the budget', () => {
    expectMatchBounded(() => {
      getTransformationVars({ type: SupportedTransformationType.Regex, expression: '(a+)+$' }, OPEN_SUBJECT, 'line');
    });
  });

  it('evaluates a dashboard conditional-rendering regex within the budget', () => {
    expectMatchBounded(() => {
      const variable = new CustomVariable({
        name: 'env',
        query: OPEN_SUBJECT,
        value: OPEN_SUBJECT,
        text: OPEN_SUBJECT,
      });
      const condition = new ConditionalRenderingVariable({
        variable: 'env',
        operator: '=~',
        value: '(a+)+$',
        result: undefined,
      });
      const group = new ConditionalRenderingGroup({
        condition: 'and',
        visibility: 'show',
        conditions: [condition],
        result: true,
        renderHidden: false,
      });
      const scene = new DashboardScene({
        $variables: new SceneVariableSet({ variables: [variable] }),
        body: new RowsLayoutManager({
          rows: [new RowItem({ conditionalRendering: group, layout: AutoGridLayoutManager.createEmpty() })],
        }),
      });
      activateFullSceneTree(scene);
    });
  });
});
