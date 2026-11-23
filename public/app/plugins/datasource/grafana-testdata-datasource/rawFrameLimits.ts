import { isArray } from 'lodash';

import { type BackendDataSourceResponse } from '@grafana/runtime';

// Raw frames are stored in the dashboard and converted in every viewer's browser.
export const MAX_RAW_FRAME_CONTENT_BYTES = 256 * 1024;
export const MAX_RAW_FRAMES = 100;
export const MAX_FIELDS_PER_FRAME = 100;
export const MAX_ROWS_PER_FIELD = 5000;
// Conversion allocates fields x rows values per frame even when the stored columns are short or rows are empty.
export const MAX_RAW_FRAME_VALUES = MAX_FIELDS_PER_FRAME * MAX_ROWS_PER_FIELD;

export class RawFrameLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RawFrameLimitError';
  }
}

type Shape = { fields: number; rows: number };
type Obj = Record<string, unknown>;

export function isJSONObject(value: unknown): value is Obj {
  return typeof value === 'object' && value !== null && !isArray(value);
}

const hasOwn = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);

function utf8ByteLength(text: string, limit: number): number {
  let bytes = 0;
  for (let i = 0; i < text.length && bytes <= limit; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      bytes += 4;
      i++;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

export function isRawFrameContentTooLarge(text: string): boolean {
  // Every UTF-16 code unit encodes to at least one UTF-8 byte.
  if (text.length > MAX_RAW_FRAME_CONTENT_BYTES) {
    return true;
  }
  return utf8ByteLength(text, MAX_RAW_FRAME_CONTENT_BYTES) > MAX_RAW_FRAME_CONTENT_BYTES;
}

export function parseRawFrameContent(text: string): unknown {
  if (isRawFrameContentTooLarge(text)) {
    throw new RawFrameLimitError(`Raw frame content is larger than ${MAX_RAW_FRAME_CONTENT_BYTES} bytes`);
  }
  return JSON.parse(text);
}

function asObject(value: unknown, what: string): Obj {
  if (!isJSONObject(value)) {
    throw new RawFrameLimitError(`${what} must be an object`);
  }
  return value;
}

function checkRows(values: unknown, what: string): number {
  if (!isArray(values)) {
    throw new RawFrameLimitError(`${what} must be an array`);
  }
  if (values.length > MAX_ROWS_PER_FIELD) {
    throw new RawFrameLimitError(`${what} has more than ${MAX_ROWS_PER_FIELD} rows`);
  }
  return values.length;
}

function checkFields(fields: unknown, what: string): unknown[] {
  if (!isArray(fields)) {
    throw new RawFrameLimitError(`${what} must be an array`);
  }
  if (fields.length > MAX_FIELDS_PER_FRAME) {
    throw new RawFrameLimitError(`A raw frame has more than ${MAX_FIELDS_PER_FRAME} fields`);
  }
  return fields;
}

function checkFrameList(frames: unknown, what: string): unknown[] {
  if (!isArray(frames)) {
    throw new RawFrameLimitError(`${what} must be an array`);
  }
  if (frames.length > MAX_RAW_FRAMES) {
    throw new RawFrameLimitError(`Raw frame content has more than ${MAX_RAW_FRAMES} frames`);
  }
  return frames;
}

/** Shape of a value passed to dataFrameFromJSON. */
function frameJSONShape(frame: unknown): Shape {
  const value = asObject(frame, 'Each raw frame');
  const schema = asObject(value.schema, 'Frame schema');
  const fields = checkFields(schema.fields, 'Frame schema fields').length;
  if (value.data == null) {
    return { fields, rows: 0 };
  }
  const columns = checkFields(asObject(value.data, 'Frame data').values, 'Frame data values');
  const rows = columns.reduce<number>((max, column) => Math.max(max, checkRows(column, 'Frame data column')), 0);
  return { fields: Math.max(fields, columns.length), rows };
}

/** Shape of a value passed to toDataFrame, following the same branches it takes. */
function frameShape(frame: unknown): Shape {
  if (isArray(frame)) {
    const rows = checkRows(frame, 'Frame');
    const first = frame.find((v) => v);
    let fields = 1;
    if (isArray(first)) {
      fields = first.length;
    } else if (first !== null && typeof first === 'object') {
      fields = Object.keys(first).length;
    }
    if (fields > MAX_FIELDS_PER_FRAME) {
      throw new RawFrameLimitError(`A raw frame has more than ${MAX_FIELDS_PER_FRAME} fields`);
    }
    return { fields, rows };
  }

  const value = asObject(frame, 'Each raw frame');

  if ('fields' in value) {
    const fields = checkFields(value.fields, 'Frame fields');
    let rows = 0;
    for (const field of fields) {
      const values = asObject(field, 'Each frame field').values;
      if (values != null) {
        rows = Math.max(rows, checkRows(values, 'Field values'));
      }
    }
    if ('length' in value) {
      const length = value.length;
      if (typeof length !== 'number' || !Number.isInteger(length) || length < 0 || length > MAX_ROWS_PER_FIELD) {
        throw new RawFrameLimitError(`Frame length must be a whole number up to ${MAX_ROWS_PER_FIELD}`);
      }
      rows = Math.max(rows, length);
    }
    return { fields: fields.length, rows };
  }

  if (hasOwn(value, 'type') && value.type === 'docs') {
    return { fields: 1, rows: checkRows(value.datapoints, 'Frame datapoints') };
  }

  if (hasOwn(value, 'datapoints') || hasOwn(value, 'points')) {
    return { fields: 2, rows: checkRows(value.datapoints || value.points, 'Frame datapoints') };
  }

  if (hasOwn(value, 'data')) {
    if (hasOwn(value, 'schema')) {
      return frameJSONShape(value);
    }
    return { fields: 2, rows: checkRows(value.data, 'Frame data') };
  }

  if (hasOwn(value, 'columns')) {
    const fields = checkFields(value.columns, 'Frame columns').length;
    return { fields, rows: checkRows(value.rows, 'Frame rows') };
  }

  throw new RawFrameLimitError('Unsupported raw frame format');
}

function createBudget() {
  let frames = 0;
  let values = 0;
  return ({ fields, rows }: Shape) => {
    frames++;
    if (frames > MAX_RAW_FRAMES) {
      throw new RawFrameLimitError(`Raw frame content has more than ${MAX_RAW_FRAMES} frames`);
    }
    values += Math.max(fields, 1) * rows;
    if (values > MAX_RAW_FRAME_VALUES) {
      throw new RawFrameLimitError(`Raw frame content has more than ${MAX_RAW_FRAME_VALUES} values`);
    }
  };
}

/** Checks a list of values that will each be passed to toDataFrame. */
export function assertRawFramesWithinLimits(frames: unknown): unknown[] {
  const list = checkFrameList(frames, 'Raw frames');
  const spend = createBudget();
  for (const frame of list) {
    spend(frameShape(frame));
  }
  return list;
}

/** Checks the `results` of a query response body before it is passed to toDataQueryResponse. */
export function assertQueryResultsWithinLimits(
  results: unknown
): asserts results is BackendDataSourceResponse['results'] {
  const spend = createBudget();
  for (const result of Object.values(asObject(results, 'Query results'))) {
    if (!result) {
      continue;
    }
    const { frames, series, tables } = asObject(result, 'Each query result');
    if (frames != null) {
      const list = checkFrameList(frames, 'Result frames');
      for (const frame of list) {
        spend(frameJSONShape(frame));
      }
      if (list.length) {
        continue;
      }
    }
    for (const [list, what] of [
      [series, 'Result series'],
      [tables, 'Result tables'],
    ] as const) {
      if (list != null) {
        for (const frame of checkFrameList(list, what)) {
          spend(frameShape(frame));
        }
      }
    }
  }
}
