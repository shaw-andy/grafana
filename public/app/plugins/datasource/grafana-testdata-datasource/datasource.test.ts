import { firstValueFrom } from 'rxjs';

import { type DataQueryRequest, type DataSourceInstanceSettings, MutableDataFrame } from '@grafana/data';
import { type TemplateSrv } from '@grafana/runtime';

import { type TestDataDataQuery, TestDataQueryType } from './dataquery';
import { TestDataDataSource } from './datasource';

// datasource.ts imports nodeGraphUtils, which imports the ESM build of d3-random.
// This plugin's Jest config does not transform that package. The trace scenario never calls it.
jest.mock('d3-random', () => ({
  randomLcg: () => () => 0,
}));

/**
 * Maximum span rows a trace query may append.
 * A larger finite spanCount is reduced to this value before any further row is built.
 * A non-finite spanCount is ignored and the default of ten spans is used.
 */
const MAX_TRACE_SPANS = 100;
const DEFAULT_TRACE_SPANS = 10;

const templateSrv = {
  replace: (target?: string) => target ?? '',
} as TemplateSrv;

function createDatasource() {
  return new TestDataDataSource(
    {
      name: 'TestData',
      type: 'grafana-testdata-datasource',
      uid: 'testdata',
    } as DataSourceInstanceSettings,
    templateSrv
  );
}

async function runTraceQuery(spanCount?: number, includeSpanCount = true) {
  const target: TestDataDataQuery = {
    refId: 'A',
    scenarioId: TestDataQueryType.Trace,
  };
  if (includeSpanCount) {
    target.spanCount = spanCount;
  }

  const request = { targets: [target] } as DataQueryRequest<TestDataDataQuery>;
  const response = await firstValueFrom(createDatasource().query(request));
  return response.data[0];
}

function spanIds(frame: { fields: Array<{ name: string; values: { length: number; [index: number]: unknown } }> }) {
  const field = frame.fields.find((item) => item.name === 'spanID');
  if (!field) {
    throw new Error('trace response is missing spanID');
  }
  return field.values;
}

describe('TestData trace spanCount', () => {
  let restoreAdd: () => void;

  beforeEach(() => {
    const originalAdd = MutableDataFrame.prototype.add;
    const add = jest.spyOn(MutableDataFrame.prototype, 'add').mockImplementation(function (
      this: MutableDataFrame,
      value: unknown
    ) {
      if (add.mock.calls.length > MAX_TRACE_SPANS) {
        throw new Error(`trace span allocation exceeded ${MAX_TRACE_SPANS}`);
      }
      return originalAdd.call(this, value);
    });
    restoreAdd = () => add.mockRestore();
  });

  afterEach(() => {
    restoreAdd();
  });

  it('returns ten spans when spanCount is omitted', async () => {
    const frame = await runTraceQuery(undefined, false);

    expect(frame.meta?.preferredVisualisationType).toBe('trace');
    expect(frame.length).toBe(DEFAULT_TRACE_SPANS);
    expect(spanIds(frame).length).toBe(DEFAULT_TRACE_SPANS);
    expect(spanIds(frame)[0]).toBe('75c665dfb6810000');
    expect(spanIds(frame)[9]).toBe('75c665dfb6810009');
  });

  it('returns one span per spanCount when the count is within the maximum', async () => {
    const frame = await runTraceQuery(25);

    expect(frame.length).toBe(25);
    expect(spanIds(frame).length).toBe(25);
    expect(spanIds(frame)[0]).toBe('75c665dfb6810000');
    expect(spanIds(frame)[24]).toBe('75c665dfb6810024');
  });

  it('returns 100 spans when spanCount is the maximum', async () => {
    const frame = await runTraceQuery(MAX_TRACE_SPANS);

    expect(frame.length).toBe(MAX_TRACE_SPANS);
    expect(spanIds(frame).length).toBe(MAX_TRACE_SPANS);
    expect(spanIds(frame)[99]).toBe('75c665dfb6810099');
  });

  it('appends only 100 spans when a saved query sets spanCount to 101', async () => {
    const frame = await runTraceQuery(101);

    expect(frame.length).toBe(MAX_TRACE_SPANS);
    expect(spanIds(frame).length).toBe(MAX_TRACE_SPANS);
    expect(spanIds(frame)[0]).toBe('75c665dfb6810000');
    expect(spanIds(frame)[99]).toBe('75c665dfb6810099');
  });

  it('appends only 100 spans when a saved query sets spanCount to 5000', async () => {
    const frame = await runTraceQuery(5000);

    expect(frame.length).toBe(MAX_TRACE_SPANS);
    expect(spanIds(frame).length).toBe(MAX_TRACE_SPANS);
    expect(spanIds(frame)[99]).toBe('75c665dfb6810099');
  });

  it('returns the default ten spans when spanCount is NaN', async () => {
    const frame = await runTraceQuery(Number.NaN);

    expect(frame.length).toBe(DEFAULT_TRACE_SPANS);
    expect(spanIds(frame).length).toBe(DEFAULT_TRACE_SPANS);
    expect(spanIds(frame)[9]).toBe('75c665dfb6810009');
  });

  it('returns the default ten spans when spanCount is Infinity', async () => {
    const frame = await runTraceQuery(Number.POSITIVE_INFINITY);

    expect(frame.length).toBe(DEFAULT_TRACE_SPANS);
    expect(spanIds(frame).length).toBe(DEFAULT_TRACE_SPANS);
    expect(spanIds(frame)[0]).toBe('75c665dfb6810000');
    expect(spanIds(frame)[9]).toBe('75c665dfb6810009');
  });
});
