// This file lives beside the TestData plugin, not inside it. The root Jest
// config ignores public/app/plugins/datasource/grafana-testdata-datasource, and
// that plugin's own Jest config cannot resolve app/ imports such as TemplateSrv.
import { firstValueFrom, toArray } from 'rxjs';

import { type DataFrame, type DataQueryRequest, type DataQueryResponse, FieldType } from '@grafana/data';

import { TemplateSrv } from 'app/features/templating/template_srv';

import { TestDataQueryType, type TestDataDataQuery } from './grafana-testdata-datasource/dataquery';
import { TestDataDataSource } from './grafana-testdata-datasource/datasource';

/**
 * Contract for the steps scenario.
 *
 * stepsQuery turns every non-empty csvContent line into a boolean field on the
 * frame it returns to the panel. A saved dashboard runs that path in the
 * viewer's browser, so the line count has to be bounded on the string that is
 * actually split (after template interpolation). 100 non-empty lines is the
 * maximum that may be turned into fields. The default scenario is three lines
 * (`a`, `b`, `c`); 100 is already more than a demo step list needs.
 *
 * Past that maximum, query() must report an error and must not emit a frame
 * that still contains one field per submitted line.
 */
const MAX_STEP_LINES = 100;

const templateSrv = new TemplateSrv({
  getVariables: () => [],
  getFilteredVariables: () => [],
  getVariableWithName: () => undefined,
});

function csvWithLines(count: number): string {
  return Array.from({ length: count }, (_, index) => `s${index}`).join('\n');
}

function datasource(): TestDataDataSource {
  return new TestDataDataSource(
    { id: 1, uid: 'testdata', type: 'grafana-testdata-datasource', name: 'TestData', jsonData: {} } as never,
    templateSrv
  );
}

function request(
  targets: TestDataDataQuery[],
  scopedVars: DataQueryRequest<TestDataDataQuery>['scopedVars'] = {}
): DataQueryRequest<TestDataDataQuery> {
  return {
    targets,
    scopedVars,
  } as DataQueryRequest<TestDataDataQuery>;
}

function booleanFieldCount(frame: DataFrame): number {
  return frame.fields.filter((field) => field.type === FieldType.boolean).length;
}

function messageFrom(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string') {
    return error.message;
  }
  return '';
}

async function runSteps(
  targets: TestDataDataQuery[],
  scopedVars?: DataQueryRequest<TestDataDataQuery>['scopedVars']
): Promise<{ packets: DataQueryResponse[]; thrown?: unknown }> {
  const ds = datasource();
  try {
    const packets = await firstValueFrom(ds.query(request(targets, scopedVars)).pipe(toArray()));
    return { packets };
  } catch (thrown) {
    return { packets: [], thrown };
  }
}

function reportedError(result: { packets: DataQueryResponse[]; thrown?: unknown }): unknown {
  if (result.thrown) {
    return result.thrown;
  }
  return result.packets.find((packet) => packet.error)?.error;
}

describe('TestData steps csvContent cap', () => {
  it('builds one boolean field per non-empty line for the default three-step list', async () => {
    const result = await runSteps([{ refId: 'A', scenarioId: TestDataQueryType.Steps, csvContent: 'a\nb\nc\n' }]);

    expect(reportedError(result)).toBeFalsy();
    expect(result.packets).toHaveLength(1);
    const frame = result.packets[0].data[0];
    expect(booleanFieldCount(frame)).toBe(3);
    expect(frame.fields.map((field) => field.name)).toEqual(['time', 'index', 'step', 'step-a', 'step-b', 'step-c']);
    expect(frame.fields[3].values[0]).toBe(true);
    expect(frame.fields[4].values[0]).toBe(false);
    expect(frame.fields[5].values[0]).toBe(false);
  });

  it('builds one boolean field per line when csvContent is exactly at the maximum', async () => {
    const result = await runSteps([
      { refId: 'A', scenarioId: TestDataQueryType.Steps, csvContent: csvWithLines(MAX_STEP_LINES) },
    ]);

    expect(reportedError(result)).toBeFalsy();
    expect(result.packets).toHaveLength(1);
    const frame = result.packets[0].data[0];
    expect(booleanFieldCount(frame)).toBe(MAX_STEP_LINES);
    expect(frame.fields).toHaveLength(MAX_STEP_LINES + 3);
    expect(frame.fields[3].name).toBe('step-s0');
    expect(frame.fields[3].values[0]).toBe(true);
    expect(frame.fields[4].name).toBe('step-s1');
    expect(frame.fields[4].values[0]).toBe(false);
  });

  it('ignores blank lines when counting toward the maximum', async () => {
    const csvContent = `${csvWithLines(MAX_STEP_LINES)}\n\n   \n`;
    const result = await runSteps([{ refId: 'A', scenarioId: TestDataQueryType.Steps, csvContent }]);

    expect(reportedError(result)).toBeFalsy();
    const frame = result.packets[0].data[0];
    expect(booleanFieldCount(frame)).toBe(MAX_STEP_LINES);
  });

  it('returns a query error and does not emit one field per line when csvContent is over the maximum', async () => {
    const lineCount = 5000;
    const result = await runSteps([
      { refId: 'A', scenarioId: TestDataQueryType.Steps, csvContent: csvWithLines(lineCount) },
    ]);

    const error = reportedError(result);
    expect(error).toBeTruthy();
    expect(messageFrom(error).length).toBeGreaterThan(0);

    for (const packet of result.packets) {
      for (const frame of packet.data ?? []) {
        expect(booleanFieldCount(frame)).toBeLessThanOrEqual(MAX_STEP_LINES);
        expect(frame.fields.length).toBeLessThanOrEqual(MAX_STEP_LINES + 3);
      }
    }
  });

  it('rejects one line past the maximum so the cap is not off by one', async () => {
    const result = await runSteps([
      { refId: 'A', scenarioId: TestDataQueryType.Steps, csvContent: csvWithLines(MAX_STEP_LINES + 1) },
    ]);

    expect(reportedError(result)).toBeTruthy();
    for (const packet of result.packets) {
      for (const frame of packet.data ?? []) {
        expect(booleanFieldCount(frame)).toBeLessThanOrEqual(MAX_STEP_LINES);
      }
    }
  });

  it('applies the cap to csvContent after template interpolation', async () => {
    const expanded = csvWithLines(MAX_STEP_LINES + 1);
    const result = await runSteps([{ refId: 'A', scenarioId: TestDataQueryType.Steps, csvContent: '${steps}' }], {
      steps: { text: expanded, value: expanded },
    });

    // The saved text is a single variable reference. The lines that become
    // fields are the interpolated value, so a check of the saved string alone
    // would miss this input.
    expect(reportedError(result)).toBeTruthy();
    for (const packet of result.packets) {
      for (const frame of packet.data ?? []) {
        expect(booleanFieldCount(frame)).toBeLessThanOrEqual(MAX_STEP_LINES);
        expect(booleanFieldCount(frame)).not.toBe(MAX_STEP_LINES + 1);
      }
    }
  });

  it('does not emit an uncapped frame when another query in the same request is within the cap', async () => {
    const result = await runSteps([
      { refId: 'A', scenarioId: TestDataQueryType.Steps, csvContent: 'a\nb\nc\n' },
      { refId: 'B', scenarioId: TestDataQueryType.Steps, csvContent: csvWithLines(5000) },
    ]);

    expect(reportedError(result)).toBeTruthy();
    const frames = result.packets.flatMap((packet) => packet.data ?? []);
    expect(frames.every((frame) => booleanFieldCount(frame) <= MAX_STEP_LINES)).toBe(true);
    expect(frames.some((frame) => booleanFieldCount(frame) === 5000)).toBe(false);
  });
});
