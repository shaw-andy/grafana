import { lastValueFrom } from 'rxjs';

import { type DataFrame, DataFrameType, DataTransformerID, FieldType, transformDataFrame } from '@grafana/data';
import { mockTransformationsRegistry } from '@grafana/data/internal';
import { extractLogsFieldsTransform } from 'app/plugins/panel/logstable/transforms/extractLogsFieldsTransform';

import { extractFieldsTransformer } from './extractFields';
import { type ExtractFieldsOptions, FieldExtractorID } from './types';

/**
 * Distinct keys one frame may materialize. Past this, keys are dropped and no
 * values array of frame length is allocated for them. The limit is per frame
 * and applies to JSON, JSON paths, key-value, delimiter, regexp, and auto.
 */
const maxExtractedKeys = 100;
const overflowKeyCount = maxExtractedKeys + 25;
const rowCount = 5;

beforeAll(() => {
  mockTransformationsRegistry([extractFieldsTransformer]);
});

describe('extract fields key cap', () => {
  it('extracts every key of a small JSON value and allocates one frame-length array per key', async () => {
    const { frames, allocations } = await runExtract(
      { source: 'line', format: FieldExtractorID.JSON, replace: true },
      frameWithLine([jsonObject(2), null, null, null, null])
    );

    expect(extractedNames(frames[0])).toEqual(['k000', 'k001']);
    expect(fieldValues(frames[0], 'k000')).toEqual(['v0', undefined, undefined, undefined, undefined]);
    expect(fieldValues(frames[0], 'k001')).toEqual(['v1', undefined, undefined, undefined, undefined]);
    expect(allocations).toBe(2);
  });

  it('keeps the first keys from a JSON object and does not allocate a values array for the rest', async () => {
    const { frames, allocations } = await runExtract(
      { source: 'line', format: FieldExtractorID.JSON, replace: true },
      frameWithLine([
        jsonObject(overflowKeyCount),
        JSON.stringify({ k000: 'later', k150: 'dropped' }),
        null,
        null,
        null,
      ])
    );

    expect(extractedNames(frames[0])).toEqual(keptKeyNames());
    expect(fieldValues(frames[0], 'k000')).toEqual(['v0', 'later', undefined, undefined, undefined]);
    expect(fieldValues(frames[0], 'k099')).toEqual(['v99', undefined, undefined, undefined, undefined]);
    expect(frames[0].fields.find((field) => field.name === 'k100')).toBeUndefined();
    expect(frames[0].fields.find((field) => field.name === 'k150')).toBeUndefined();
    expect(allocations).toBe(maxExtractedKeys);
  });

  it('caps a JSON array and a JSON string, whose indexes are keys', async () => {
    const arrayPayload = JSON.stringify(Array.from({ length: overflowKeyCount }, (_, index) => `v${index}`));
    const stringPayload = JSON.stringify('x'.repeat(overflowKeyCount));

    const arrayResult = await runExtract(
      { source: 'line', format: FieldExtractorID.JSON, replace: true },
      frameWithLine([arrayPayload, null, null, null, null])
    );
    const stringResult = await runExtract(
      { source: 'line', format: FieldExtractorID.JSON, replace: true },
      frameWithLine([stringPayload, null, null, null, null])
    );

    expect(extractedNames(arrayResult.frames[0])).toEqual(indexNames(maxExtractedKeys));
    expect(fieldValues(arrayResult.frames[0], '0')).toEqual(['v0', undefined, undefined, undefined, undefined]);
    expect(fieldValues(arrayResult.frames[0], '99')).toEqual(['v99', undefined, undefined, undefined, undefined]);
    expect(arrayResult.frames[0].fields.find((field) => field.name === '100')).toBeUndefined();
    expect(arrayResult.allocations).toBe(maxExtractedKeys);

    expect(extractedNames(stringResult.frames[0])).toEqual(indexNames(maxExtractedKeys));
    expect(fieldValues(stringResult.frames[0], '0')).toEqual(['x', undefined, undefined, undefined, undefined]);
    expect(stringResult.frames[0].fields.find((field) => field.name === '100')).toBeUndefined();
    expect(stringResult.allocations).toBe(maxExtractedKeys);
  });

  it('caps JSON paths before allocating a values array per path', async () => {
    const { frames, allocations } = await runExtract(
      {
        source: 'line',
        format: FieldExtractorID.JSON,
        replace: true,
        jsonPaths: Array.from({ length: overflowKeyCount }, (_, index) => ({ path: keyName(index) })),
      },
      frameWithLine([jsonObject(overflowKeyCount), null, null, null, null])
    );

    expect(extractedNames(frames[0])).toEqual(keptKeyNames());
    expect(fieldValues(frames[0], 'k000')).toEqual(['v0', undefined, undefined, undefined, undefined]);
    expect(frames[0].fields.find((field) => field.name === 'k100')).toBeUndefined();
    expect(allocations).toBe(maxExtractedKeys);
  });

  it('caps key-value text', async () => {
    const { frames, allocations } = await runExtract(
      { source: 'line', format: FieldExtractorID.KeyValues, replace: true },
      frameWithLine([keyValueText(overflowKeyCount), null, null, null, null])
    );

    expect(extractedNames(frames[0])).toEqual(keptKeyNames());
    expect(fieldValues(frames[0], 'k000')).toEqual(['v0', undefined, undefined, undefined, undefined]);
    expect(fieldValues(frames[0], 'k099')).toEqual(['v99', undefined, undefined, undefined, undefined]);
    expect(frames[0].fields.find((field) => field.name === 'k100')).toBeUndefined();
    expect(allocations).toBe(maxExtractedKeys);
  });

  it('caps delimiter splits', async () => {
    const { frames, allocations } = await runExtract(
      { source: 'line', format: FieldExtractorID.Delimiter, replace: true, delimiter: ',' },
      frameWithLine([
        Array.from({ length: overflowKeyCount }, (_, index) => keyName(index)).join(','),
        null,
        null,
        null,
        null,
      ])
    );

    expect(extractedNames(frames[0])).toEqual(keptKeyNames());
    expect(fieldValues(frames[0], 'k000')).toEqual([1, undefined, undefined, undefined, undefined]);
    expect(frames[0].fields.find((field) => field.name === 'k100')).toBeUndefined();
    expect(allocations).toBe(maxExtractedKeys);
  });

  it('caps named regexp groups', async () => {
    const groups = keptKeyNames()
      .concat(
        Array.from({ length: overflowKeyCount - maxExtractedKeys }, (_, index) => keyName(maxExtractedKeys + index))
      )
      .map((name) => `(?<${name}>\\w)`)
      .join('');

    const { frames, allocations } = await runExtract(
      { source: 'line', format: FieldExtractorID.RegExp, replace: true, regExp: `/^${groups}$/` },
      frameWithLine(['a'.repeat(overflowKeyCount), null, null, null, null])
    );

    expect(extractedNames(frames[0])).toEqual(keptKeyNames());
    expect(fieldValues(frames[0], 'k000')).toEqual(['a', undefined, undefined, undefined, undefined]);
    expect(frames[0].fields.find((field) => field.name === 'k100')).toBeUndefined();
    expect(allocations).toBe(maxExtractedKeys);
  });

  it('caps auto mode for JSON and for key-value text', async () => {
    const jsonResult = await runExtract(
      { source: 'line', format: FieldExtractorID.Auto, replace: true },
      frameWithLine([jsonObject(overflowKeyCount), null, null, null, null])
    );
    const keyValueResult = await runExtract(
      { source: 'line', replace: true },
      frameWithLine([keyValueText(overflowKeyCount), null, null, null, null])
    );

    expect(extractedNames(jsonResult.frames[0])).toEqual(keptKeyNames());
    expect(jsonResult.frames[0].fields.find((field) => field.name === 'k100')).toBeUndefined();
    expect(jsonResult.allocations).toBe(maxExtractedKeys);

    expect(extractedNames(keyValueResult.frames[0])).toEqual(keptKeyNames());
    expect(fieldValues(keyValueResult.frames[0], 'k099')).toEqual(['v99', undefined, undefined, undefined, undefined]);
    expect(keyValueResult.frames[0].fields.find((field) => field.name === 'k100')).toBeUndefined();
    expect(keyValueResult.allocations).toBe(maxExtractedKeys);
  });

  it('caps an object value that is already parsed', async () => {
    const record: Record<string, string> = {};
    for (let index = 0; index < overflowKeyCount; index++) {
      record[keyName(index)] = `v${index}`;
    }

    const { frames, allocations } = await runExtract(
      { source: 'line', format: FieldExtractorID.JSON, replace: true },
      frameWithLine([record, null, null, null, null])
    );

    expect(extractedNames(frames[0])).toEqual(keptKeyNames());
    expect(fieldValues(frames[0], 'k000')).toEqual(['v0', undefined, undefined, undefined, undefined]);
    expect(frames[0].fields.find((field) => field.name === 'k100')).toBeUndefined();
    expect(allocations).toBe(maxExtractedKeys);
  });

  it('applies the cap separately to each frame', async () => {
    const { frames, allocations } = await runExtractFrames(
      { source: 'line', format: FieldExtractorID.JSON, replace: true },
      [
        frameWithLine([jsonObject(overflowKeyCount), null, null, null, null]),
        frameWithLine([jsonObject(overflowKeyCount), null, null, null, null]),
      ]
    );

    expect(frames).toHaveLength(2);
    expect(extractedNames(frames[0])).toEqual(keptKeyNames());
    expect(extractedNames(frames[1])).toEqual(keptKeyNames());
    expect(allocations).toBe(maxExtractedKeys * 2);
  });

  it('caps labels extracted for the logs table', async () => {
    const frame: DataFrame = {
      length: rowCount,
      meta: { type: DataFrameType.LogLines },
      fields: [
        {
          name: 'labels',
          type: FieldType.other,
          config: {},
          values: [jsonObject(overflowKeyCount), null, null, null, null],
        },
      ],
    };
    const configs = extractLogsFieldsTransform(frame);

    expect(configs).toEqual([
      {
        id: 'extractFields',
        options: {
          format: 'json',
          keepTime: false,
          replace: false,
          source: 'labels',
        },
      },
    ]);

    const { frames, allocations } = await runConfigured(configs, [frame]);
    const extracted = frames[0].fields.filter((field) => field.name !== 'labels');

    expect(extracted.map((field) => field.name)).toEqual(keptKeyNames());
    expect(extracted.find((field) => field.name === 'k100')).toBeUndefined();
    expect(allocations).toBe(maxExtractedKeys);
  });

  it('still keeps the time field when replace and keepTime are set', async () => {
    const source = frameWithLine([jsonObject(overflowKeyCount), null, null, null, null]);
    const { frames, allocations } = await runExtract(
      { source: 'line', format: FieldExtractorID.JSON, replace: true, keepTime: true },
      source
    );

    expect(frames[0].fields[0]).toBe(source.fields[0]);
    expect(extractedNames(frames[0]).slice(1)).toEqual(keptKeyNames());
    expect(allocations).toBe(maxExtractedKeys);
  });
});

async function runExtract(options: ExtractFieldsOptions, frame: DataFrame) {
  return runExtractFrames(options, [frame]);
}

async function runExtractFrames(options: ExtractFieldsOptions, frames: DataFrame[]) {
  return runConfigured([{ id: DataTransformerID.extractFields, options }], frames);
}

async function runConfigured(configs: Array<{ id: string; options?: ExtractFieldsOptions }>, frames: DataFrame[]) {
  const counter = installFrameLengthArrayCounter(rowCount);
  try {
    const transformed = await lastValueFrom(transformDataFrame(configs, frames));
    return { frames: transformed, allocations: counter.allocations() };
  } finally {
    counter.restore();
  }
}

function installFrameLengthArrayCounter(frameLength: number) {
  const Original = globalThis.Array;
  let allocations = 0;

  function CountingArray(this: unknown, ...args: unknown[]) {
    const created = new Original(...(args as []));
    if (args.length === 1 && args[0] === frameLength) {
      allocations += 1;
    }
    return created;
  }

  Object.setPrototypeOf(CountingArray, Original);
  CountingArray.prototype = Original.prototype;
  for (const key of Object.getOwnPropertyNames(Original)) {
    if (key === 'length' || key === 'name' || key === 'prototype') {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(Original, key);
    if (descriptor) {
      Object.defineProperty(CountingArray, key, descriptor);
    }
  }

  const previous = globalThis.Array;
  globalThis.Array = CountingArray as unknown as ArrayConstructor;

  return {
    allocations: () => allocations,
    restore: () => {
      globalThis.Array = previous;
    },
  };
}

function frameWithLine(values: unknown[]): DataFrame {
  return {
    length: rowCount,
    fields: [
      { name: 'Time', type: FieldType.time, config: {}, values: [1, 2, 3, 4, 5] },
      { name: 'line', type: FieldType.string, config: {}, values },
    ],
  };
}

function keyName(index: number): string {
  return `k${index.toString().padStart(3, '0')}`;
}

function keptKeyNames(): string[] {
  return Array.from({ length: maxExtractedKeys }, (_, index) => keyName(index));
}

function indexNames(count: number): string[] {
  return Array.from({ length: count }, (_, index) => String(index));
}

function jsonObject(count: number): string {
  const record: Record<string, string> = {};
  for (let index = 0; index < count; index++) {
    record[keyName(index)] = `v${index}`;
  }
  return JSON.stringify(record);
}

function keyValueText(count: number): string {
  return Array.from({ length: count }, (_, index) => `${keyName(index)}=v${index}`).join(',');
}

function extractedNames(frame: DataFrame): string[] {
  return frame.fields.map((field) => field.name);
}

function fieldValues(frame: DataFrame, name: string): unknown[] {
  const field = frame.fields.find((candidate) => candidate.name === name);
  if (!field) {
    throw new Error(`missing extracted field ${name}`);
  }
  return [...field.values];
}
