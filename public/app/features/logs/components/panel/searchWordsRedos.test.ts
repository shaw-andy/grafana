import { Token } from 'prismjs';
import { firstValueFrom } from 'rxjs';

import {
  DataFrameType,
  FieldType,
  findMatchesInText,
  LogsSortOrder,
  type DataQueryRequest,
  type DataSourceInstanceSettings,
} from '@grafana/data';
import { type TemplateSrv } from '@grafana/runtime';
import {
  type TestDataDataQuery,
  TestDataQueryType,
} from 'app/plugins/datasource/grafana-testdata-datasource/dataquery';
import { TestDataDataSource } from 'app/plugins/datasource/grafana-testdata-datasource/datasource';

import { dataFrameToLogsModel } from '../../logsModel';
import { OTEL_LOG_LINE_ATTRIBUTES_FIELD_NAME } from '../fieldSelector/logFields';

import { preProcessLogs, type LogListModel } from './processing';

// Repeated 'a' plus a non-match. The compiled pattern is /(?:(a+)+$)/g, and this
// length takes over a second in V8. Escaping, rejecting, or bounding the match
// finishes far under the budget.
const NESTED_QUANTIFIER = '(a+)+$';
const CATASTROPHIC_LINE = `${'a'.repeat(28)}X`;
const HIGHLIGHT_BUDGET_MS = 300;

const templateSrv = {
  replace: (value: string) => value,
} as TemplateSrv;

function expectWithinBudget<T>(run: () => T): T {
  const started = performance.now();
  const result = run();
  expect(performance.now() - started).toBeLessThan(HIGHLIGHT_BUDGET_MS);
  return result;
}

async function logsFromSavedRawFrame(frame: unknown) {
  const datasource = new TestDataDataSource(
    {
      name: 'TestData',
      type: 'grafana-testdata-datasource',
      uid: 'testdata',
      meta: {},
    } as DataSourceInstanceSettings,
    templateSrv
  );
  const response = await firstValueFrom(
    datasource.query({
      targets: [
        {
          refId: 'A',
          scenarioId: TestDataQueryType.RawFrame,
          rawFrameContent: JSON.stringify([frame]),
        },
      ],
    } as DataQueryRequest<TestDataDataQuery>)
  );

  return dataFrameToLogsModel(response.data);
}

function highlightLine(row: ReturnType<typeof dataFrameToLogsModel>['rows'][number]): LogListModel {
  return preProcessLogs([row], {
    escape: false,
    order: LogsSortOrder.Descending,
    prettifyJSON: false,
    timeZone: 'browser',
    wrapLogMessage: true,
  })[0];
}

describe('data-source search words cannot hang log highlighting', () => {
  test('a short raw-frame line with meta.searchWords is highlighted within the budget', async () => {
    const model = await logsFromSavedRawFrame({
      fields: [
        { name: 'time', type: FieldType.time, values: [1_700_000_000_000] },
        { name: 'line', type: FieldType.string, values: [CATASTROPHIC_LINE] },
      ],
      meta: { searchWords: [NESTED_QUANTIFIER] },
    });

    expect(model.rows).toHaveLength(1);
    expect(model.rows[0].entry).toBe(CATASTROPHIC_LINE);

    const line = highlightLine(model.rows[0]);
    expect(line.body).toBe(CATASTROPHIC_LINE);
    const tokens = expectWithinBudget(() => line.highlightedBodyTokens);
    expect(Array.isArray(tokens)).toBe(true);
  });

  test('a dataplane raw frame with meta.custom.searchWords highlights the body within the budget', async () => {
    const model = await logsFromSavedRawFrame({
      fields: [
        { name: 'timestamp', type: FieldType.time, values: [1_700_000_000_000] },
        { name: 'body', type: FieldType.string, values: [CATASTROPHIC_LINE] },
      ],
      meta: {
        type: DataFrameType.LogLines,
        searchWords: ['error'],
        custom: { searchWords: [NESTED_QUANTIFIER] },
      },
    });

    expect(model.rows).toHaveLength(1);
    expect(model.rows[0].entry).toBe(CATASTROPHIC_LINE);

    const line = highlightLine(model.rows[0]);
    const html = expectWithinBudget(() => line.highlightedBody);
    expect(typeof html).toBe('string');
  });

  test('search words from the raw frame do not hang attribute highlighting', async () => {
    const model = await logsFromSavedRawFrame({
      fields: [
        { name: 'time', type: FieldType.time, values: [1_700_000_000_000] },
        { name: 'line', type: FieldType.string, values: ['ok'] },
        {
          name: 'labels',
          type: FieldType.other,
          values: [{ [OTEL_LOG_LINE_ATTRIBUTES_FIELD_NAME]: CATASTROPHIC_LINE }],
        },
      ],
      meta: { searchWords: [NESTED_QUANTIFIER] },
    });

    const line = highlightLine(model.rows[0]);
    expect(line.labels[OTEL_LOG_LINE_ATTRIBUTES_FIELD_NAME]).toBe(CATASTROPHIC_LINE);

    const tokens = expectWithinBudget(() => line.highlightedLogAttributesTokens);
    expect(Array.isArray(tokens)).toBe(true);
  });

  test('findMatchesInText finishes within the budget for a raw-frame search word', async () => {
    const model = await logsFromSavedRawFrame({
      fields: [
        { name: 'time', type: FieldType.time, values: [1_700_000_000_000] },
        { name: 'line', type: FieldType.string, values: [CATASTROPHIC_LINE] },
      ],
      meta: { searchWords: [NESTED_QUANTIFIER] },
    });
    // The same pattern the raw frame stored. Match the attacker's text, not a copy the test rewrote.
    const searchWord = model.rows[0].searchWords?.[0] || NESTED_QUANTIFIER;

    const matches = expectWithinBudget(() => findMatchesInText(CATASTROPHIC_LINE, searchWord));
    expect(Array.isArray(matches)).toBe(true);
  });

  test('a literal search word still highlights the matching text', async () => {
    const model = await logsFromSavedRawFrame({
      fields: [
        { name: 'time', type: FieldType.time, values: [1_700_000_000_000] },
        { name: 'line', type: FieldType.string, values: ['disk error on node'] },
      ],
      meta: { searchWords: ['error'] },
    });

    const line = highlightLine(model.rows[0]);
    const tokens = expectWithinBudget(() => line.highlightedBodyTokens);
    expect(
      tokens.some((token) => token instanceof Token && token.type === 'log-search-match' && token.content === 'error')
    ).toBe(true);

    expect(findMatchesInText('disk error on node', model.rows[0].searchWords?.[0] ?? '')).toEqual([
      { text: 'error', start: 5, length: 5, end: 10 },
    ]);
  });
});
