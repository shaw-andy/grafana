import { firstValueFrom } from 'rxjs';

import {
  DataTransformerID,
  FieldType,
  type DataTransformerConfig,
  standardTransformers,
  toDataFrame,
  transformDataFrame,
  ValueMatcherID,
} from '@grafana/data';
import {
  FilterByValueMatch,
  FilterByValueType,
  type FilterByValueTransformerOptions,
  mockTransformationsRegistry,
} from '@grafana/data/internal';
import { TemplateSrv } from 'app/features/templating/template_srv';

const MATCH_BUDGET_MS = 250;
const NESTED_PATTERN = '(a+)+$';
const NESTED_INPUT = `${'a'.repeat(30)}!`;
const SLOW_TEST_TIMEOUT_MS = 180_000;

const templateSrv = new TemplateSrv();

function filterConfig(pattern: string): DataTransformerConfig<FilterByValueTransformerOptions> {
  return {
    id: DataTransformerID.filterByValue,
    options: {
      type: FilterByValueType.include,
      match: FilterByValueMatch.all,
      filters: [
        {
          fieldName: 'message',
          config: {
            id: ValueMatcherID.regex,
            options: { value: pattern },
          },
        },
      ],
    },
  };
}

describe('filter-by-value stored regex on dashboard view', () => {
  beforeAll(() => {
    mockTransformationsRegistry([standardTransformers.filterByValueTransformer]);
  });

  it('template interpolation leaves a trailing $ in a nested pattern unchanged', () => {
    expect(templateSrv.replace(NESTED_PATTERN)).toBe(NESTED_PATTERN);
  });

  it(
    'returns within 250ms when PanelQueryRunner interpolation is applied to a nested filter regex',
    async () => {
      const previousScene = window.__grafanaSceneContext;
      delete window.__grafanaSceneContext;
      const stored = templateSrv.replace(NESTED_PATTERN);
      const frame = toDataFrame({
        fields: [{ name: 'message', type: FieldType.string, values: [NESTED_INPUT] }],
      });
      const startedAt = performance.now();
      try {
        await firstValueFrom(
          transformDataFrame([filterConfig(stored)], [frame], {
            interpolate: (value) => templateSrv.replace(value),
          })
        );
      } catch {
        // Refusing the stored pattern is inside the contract.
      } finally {
        if (previousScene === undefined) {
          delete window.__grafanaSceneContext;
        } else {
          window.__grafanaSceneContext = previousScene;
        }
      }
      expect(performance.now() - startedAt).toBeLessThan(MATCH_BUDGET_MS);
    },
    SLOW_TEST_TIMEOUT_MS
  );
});
