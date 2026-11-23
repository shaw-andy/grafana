import { fireEvent, render, screen } from '@testing-library/react';
import { firstValueFrom, toArray } from 'rxjs';

import {
  type DataFrameJSON,
  type DataQueryRequest,
  type DataSourceInstanceSettings,
  dateTime,
  FieldType,
  LoadingState,
  type ScopedVars,
} from '@grafana/data';
import type { TemplateSrv } from '@grafana/runtime';
import { TemplateSrv as GrafanaTemplateSrv } from 'app/features/templating/template_srv';
import { RawFrameEditor } from 'app/plugins/datasource/grafana-testdata-datasource/components/RawFrameEditor';
import {
  type TestDataDataQuery,
  TestDataQueryType,
} from 'app/plugins/datasource/grafana-testdata-datasource/dataquery';
import { TestDataDataSource } from 'app/plugins/datasource/grafana-testdata-datasource/datasource';

/**
 * Contract for the TestData raw-frame scenario. The browser query and the query editor
 * both have to enforce these limits. Dashboard saves accept a raw frame up to the request
 * body cap, and opening that dashboard runs this scenario in every viewer's browser.
 */
const MAX_RAW_FRAME_CONTENT_BYTES = 256 * 1024;
const MAX_RAW_FRAMES = 100;
const MAX_FIELDS_PER_FRAME = 100;
const MAX_ROWS_PER_FIELD = 5000;

type RecordedCalls = {
  toDataFrame: unknown[];
  dataFrameFromJSON: unknown[];
};

const recorded = (): RecordedCalls => {
  const holder = globalThis as { __rawFrameLimitCalls?: RecordedCalls };
  if (!holder.__rawFrameLimitCalls) {
    holder.__rawFrameLimitCalls = { toDataFrame: [], dataFrameFromJSON: [] };
  }
  return holder.__rawFrameLimitCalls;
};

jest.mock('@grafana/data', () => {
  const actual = jest.requireActual('@grafana/data');
  const holder = globalThis as { __rawFrameLimitCalls?: RecordedCalls };
  holder.__rawFrameLimitCalls = { toDataFrame: [], dataFrameFromJSON: [] };
  return {
    ...actual,
    toDataFrame: (data: unknown) => {
      holder.__rawFrameLimitCalls?.toDataFrame.push(data);
      return actual.toDataFrame(data);
    },
    dataFrameFromJSON: (data: unknown) => {
      holder.__rawFrameLimitCalls?.dataFrameFromJSON.push(data);
      return actual.dataFrameFromJSON(data);
    },
  };
});

jest.mock('@grafana/ui', () => {
  const actual = jest.requireActual('@grafana/ui');
  const React = require('react');
  const CodeEditor = ({
    value,
    onBlur,
    onSave,
  }: {
    value?: string;
    onBlur?: (text: string) => void;
    onSave?: (text: string) => void;
  }) => {
    const ref = React.useRef<HTMLTextAreaElement>(null);
    return React.createElement(
      'div',
      null,
      React.createElement('textarea', {
        'aria-label': 'Raw frames',
        ref,
        defaultValue: value ?? '',
      }),
      React.createElement(
        'button',
        { type: 'button', onClick: () => onBlur?.(ref.current?.value ?? '') },
        'blur raw frames'
      ),
      React.createElement(
        'button',
        { type: 'button', onClick: () => onSave?.(ref.current?.value ?? '') },
        'save raw frames'
      )
    );
  };
  return { ...actual, CodeEditor };
});

const ONE_FRAME = JSON.stringify([{ fields: [{ name: 'v', type: FieldType.number, values: [1] }] }]);

function withByteLength(json: string, bytes: number): string {
  if (json.length > bytes) {
    throw new Error(`fixture is ${json.length} bytes, above ${bytes}`);
  }
  return json + ' '.repeat(bytes - json.length);
}

function frames(count: number, rows = 1, fieldCount = 1): string {
  const body = Array.from({ length: count }, () => ({
    fields: Array.from({ length: fieldCount }, (_, index) => ({
      name: `f${index}`,
      type: FieldType.number,
      values: Array.from({ length: rows }, () => 1),
    })),
  }));
  return JSON.stringify(body);
}

function longestParse(spy: jest.SpyInstance): number {
  return spy.mock.calls.reduce((max, call) => Math.max(max, String(call[0]).length), 0);
}

function fieldCountOf(value: unknown): number {
  if (!value || typeof value !== 'object' || !('fields' in value)) {
    return 0;
  }
  const fields = (value as { fields?: unknown }).fields;
  return Array.isArray(fields) ? fields.length : 0;
}

function maxRowsOf(value: unknown): number {
  if (!value || typeof value !== 'object' || !('fields' in value)) {
    return 0;
  }
  const fields = (value as { fields?: Array<{ values?: unknown[] }> }).fields;
  if (!Array.isArray(fields)) {
    return 0;
  }
  return fields.reduce((max, field) => Math.max(max, field.values?.length ?? 0), 0);
}

function jsonFrameRows(value: unknown): number {
  const columns = (value as DataFrameJSON)?.data?.values;
  if (!Array.isArray(columns)) {
    return 0;
  }
  return columns.reduce((max, column) => Math.max(max, Array.isArray(column) ? column.length : 0), 0);
}

function realTemplateSrv(): TemplateSrv {
  return new GrafanaTemplateSrv({
    getFilteredVariables: () => [],
    getVariables: () => [],
    getVariableWithName: () => undefined,
  });
}

function createDatasource(): TestDataDataSource {
  const settings = {
    id: 1,
    uid: 'testdata',
    type: 'grafana-testdata-datasource',
    name: 'TestData',
    jsonData: {},
    meta: {},
  } as DataSourceInstanceSettings;
  return new TestDataDataSource(settings, realTemplateSrv());
}

function request(rawFrameContent: string, scopedVars: ScopedVars = {}): DataQueryRequest<TestDataDataQuery> {
  const from = dateTime(0);
  const to = dateTime(1);
  return {
    requestId: 'raw-frame',
    interval: '1s',
    intervalMs: 1000,
    range: { from, to, raw: { from: '0', to: '1' } },
    scopedVars,
    timezone: 'utc',
    app: 'dashboard',
    startTime: 0,
    targets: [
      {
        refId: 'A',
        scenarioId: TestDataQueryType.RawFrame,
        rawFrameContent,
      },
    ],
  };
}

async function runRawFrame(rawFrameContent: string, scopedVars?: ScopedVars) {
  const response = await firstValueFrom(createDatasource().query(request(rawFrameContent, scopedVars)).pipe(toArray()));
  expect(response).toHaveLength(1);
  return response[0];
}

describe('TestData raw frame query limits', () => {
  let parseSpy: jest.SpyInstance;

  beforeEach(() => {
    recorded().toDataFrame.length = 0;
    recorded().dataFrameFromJSON.length = 0;
    parseSpy = jest.spyOn(JSON, 'parse');
  });

  afterEach(() => {
    parseSpy.mockRestore();
  });

  it('returns one frame when the raw text is exactly the byte limit', async () => {
    const text = withByteLength(ONE_FRAME, MAX_RAW_FRAME_CONTENT_BYTES);
    const response = await runRawFrame(text);

    expect(response.error).toBeUndefined();
    expect(response.state).toBe(LoadingState.Done);
    expect(response.data).toHaveLength(1);
    expect(response.data[0].refId).toBe('A');
    expect(response.data[0].fields[0].name).toBe('v');
    expect(Array.from(response.data[0].fields[0].values)).toEqual([1]);
    expect(recorded().toDataFrame).toHaveLength(1);
    expect(longestParse(parseSpy)).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
  });

  it('rejects raw frame text one byte over the limit before parsing it', async () => {
    const text = withByteLength(ONE_FRAME, MAX_RAW_FRAME_CONTENT_BYTES + 1);
    const response = await runRawFrame(text);

    expect(response.data.length).toBe(0);
    expect(response.error).toBeTruthy();
    expect(longestParse(parseSpy)).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    expect(recorded().toDataFrame).toHaveLength(0);
  });

  it('rejects a raw frame that only exceeds the byte limit after template replacement', async () => {
    const expanded = withByteLength(ONE_FRAME, MAX_RAW_FRAME_CONTENT_BYTES + 1);
    const response = await runRawFrame('${raw}', {
      raw: { value: expanded, text: 'raw' },
    });

    expect(response.data.length).toBe(0);
    expect(response.error).toBeTruthy();
    expect(longestParse(parseSpy)).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    expect(recorded().toDataFrame).toHaveLength(0);
  });

  it('still runs a raw frame that is stored as a template variable inside the limit', async () => {
    const response = await runRawFrame('${raw}', {
      raw: { value: ONE_FRAME, text: 'raw' },
    });

    expect(response.error).toBeUndefined();
    expect(response.data).toHaveLength(1);
    expect(response.data[0].fields[0].name).toBe('v');
    expect(Array.from(response.data[0].fields[0].values)).toEqual([1]);
    expect(recorded().toDataFrame).toHaveLength(1);
  });

  it('rejects one frame more than the frame cap without converting the extras', async () => {
    const text = frames(MAX_RAW_FRAMES + 1);
    expect(text.length).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    const response = await runRawFrame(text);

    expect(response.data.length).toBe(0);
    expect(response.error).toBeTruthy();
    expect(recorded().toDataFrame.length).toBeLessThanOrEqual(MAX_RAW_FRAMES);
  });

  it('returns every frame when the count is exactly the cap', async () => {
    const text = frames(MAX_RAW_FRAMES);
    expect(text.length).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    const response = await runRawFrame(text);

    expect(response.error).toBeUndefined();
    expect(response.data).toHaveLength(MAX_RAW_FRAMES);
    expect(response.data[0].fields[0].values[0]).toBe(1);
    expect(recorded().toDataFrame).toHaveLength(MAX_RAW_FRAMES);
  });

  it('rejects a frame with one field over the field cap before converting it', async () => {
    const text = frames(1, 1, MAX_FIELDS_PER_FRAME + 1);
    expect(text.length).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    const response = await runRawFrame(text);

    expect(response.data.length).toBe(0);
    expect(response.error).toBeTruthy();
    expect(recorded().toDataFrame.every((value) => fieldCountOf(value) <= MAX_FIELDS_PER_FRAME)).toBe(true);
  });

  it('rejects a frame with one row over the row cap before converting it', async () => {
    const text = frames(1, MAX_ROWS_PER_FIELD + 1, 1);
    expect(text.length).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    const response = await runRawFrame(text);

    expect(response.data.length).toBe(0);
    expect(response.error).toBeTruthy();
    expect(recorded().toDataFrame.every((value) => maxRowsOf(value) <= MAX_ROWS_PER_FIELD)).toBe(true);
  });

  it('rejects an oversized non-array before parsing it', async () => {
    const text = withByteLength('{"not":"frames"}', MAX_RAW_FRAME_CONTENT_BYTES + 1);
    const response = await runRawFrame(text);

    expect(response.data.length).toBe(0);
    expect(response.error).toBeTruthy();
    expect(longestParse(parseSpy)).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    expect(recorded().toDataFrame).toHaveLength(0);
  });
});

describe('TestData raw frame editor limits', () => {
  let parseSpy: jest.SpyInstance;

  beforeEach(() => {
    recorded().toDataFrame.length = 0;
    recorded().dataFrameFromJSON.length = 0;
    parseSpy = jest.spyOn(JSON, 'parse');
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  function edit(rawFrameContent: string) {
    const onChange = jest.fn();
    render(
      <RawFrameEditor
        onChange={onChange}
        query={{ refId: 'A', scenarioId: TestDataQueryType.RawFrame, rawFrameContent }}
        ds={{} as TestDataDataSource}
      />
    );
    return onChange;
  }

  it('stores a raw frame array that is exactly the byte limit', () => {
    const text = withByteLength(ONE_FRAME, MAX_RAW_FRAME_CONTENT_BYTES);
    const onChange = edit(text);
    fireEvent.click(screen.getByRole('button', { name: 'blur raw frames' }));

    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange.mock.calls[0][0].rawFrameContent).toBe(text);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('does not store raw frame text one byte over the limit, and does not parse it', () => {
    const text = withByteLength(ONE_FRAME, MAX_RAW_FRAME_CONTENT_BYTES + 1);
    const onChange = edit(text);
    fireEvent.click(screen.getByRole('button', { name: 'blur raw frames' }));

    expect(onChange.mock.calls.length).toBe(0);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(longestParse(parseSpy)).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    expect(recorded().toDataFrame).toHaveLength(0);
  });

  it('does not store an over-limit raw frame from the save action either', () => {
    const text = withByteLength(ONE_FRAME, MAX_RAW_FRAME_CONTENT_BYTES + 1);
    const onChange = edit(text);
    fireEvent.click(screen.getByRole('button', { name: 'save raw frames' }));

    expect(onChange.mock.calls.length).toBe(0);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(longestParse(parseSpy)).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
  });

  it('does not store an array with one frame over the frame cap', () => {
    const text = frames(MAX_RAW_FRAMES + 1);
    expect(text.length).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    const onChange = edit(text);
    fireEvent.click(screen.getByRole('button', { name: 'blur raw frames' }));

    expect(onChange.mock.calls.length).toBe(0);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(recorded().toDataFrame.length).toBeLessThanOrEqual(MAX_RAW_FRAMES);
  });

  it('does not store a pasted panel result whose series exceed the row cap', () => {
    const text = JSON.stringify({
      state: 'Done',
      series: [
        {
          fields: [
            { name: 'v', type: FieldType.number, values: Array.from({ length: MAX_ROWS_PER_FIELD + 1 }, () => 1) },
          ],
        },
      ],
    });
    expect(text.length).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    const onChange = edit(text);
    fireEvent.click(screen.getByRole('button', { name: 'blur raw frames' }));

    expect(onChange.mock.calls.length).toBe(0);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(recorded().toDataFrame.every((value) => maxRowsOf(value) <= MAX_ROWS_PER_FIELD)).toBe(true);
  });

  it('does not store a pasted query response whose columns exceed the row cap', () => {
    const text = JSON.stringify({
      results: {
        A: {
          frames: [
            {
              schema: { fields: [{ name: 'v', type: FieldType.number }] },
              data: { values: [Array.from({ length: MAX_ROWS_PER_FIELD + 1 }, () => 1)] },
            },
          ],
        },
      },
    });
    expect(text.length).toBeLessThanOrEqual(MAX_RAW_FRAME_CONTENT_BYTES);
    const onChange = edit(text);
    fireEvent.click(screen.getByRole('button', { name: 'blur raw frames' }));

    expect(onChange.mock.calls.length).toBe(0);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(recorded().dataFrameFromJSON.every((value) => jsonFrameRows(value) <= MAX_ROWS_PER_FIELD)).toBe(true);
  });
});
