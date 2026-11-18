import { lastValueFrom, of } from 'rxjs';

import {
  DataTransformerID,
  type DataFrame,
  type DataFrameDTO,
  type DataTransformContext,
  type Field,
  FieldType,
  standardTransformersRegistry,
  toDataFrame,
  transformDataFrame,
  toDataFrameDTO,
} from '@grafana/data';

import { ModelType, getRegressionTransformer, type RegressionTransformerOptions } from './regression';

describe('Trendline transformation', () => {
  const RegressionTransformer = getRegressionTransformer();

  it('it should predict a linear regression to exactly fit the data when the data is f(x) = x', () => {
    const source = [
      toDataFrame({
        name: 'data',
        refId: 'A',
        fields: [
          { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5] },
          { name: 'value', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
        ],
      }),
    ];

    const config: RegressionTransformerOptions = {
      modelType: ModelType.linear,
      predictionCount: 6,
      xFieldName: 'time',
      yFieldName: 'value',
    };

    expect(toEquableDataFrames(RegressionTransformer.transformer(config, {} as DataTransformContext)(source))).toEqual(
      toEquableDataFrames([
        toEquableDataFrame({
          name: 'data',
          refId: 'A',
          fields: [
            { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5], config: {} },
            { name: 'value', type: FieldType.number, values: [0, 1, 2, 3, 4, 5], config: {} },
          ],
          length: 6,
        }),
        toEquableDataFrame({
          name: 'Linear regression',
          fields: [
            { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5], config: {} },
            { name: 'value', type: FieldType.number, values: [0, 1, 2, 3, 4, 5], config: {} },
          ],
          length: 6,
        }),
      ])
    );
  });
  it('it should predict a linear regression where f(x) = 1', () => {
    const source = [
      toDataFrame({
        name: 'data',
        refId: 'A',
        fields: [
          { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5] },
          { name: 'value', type: FieldType.number, values: [0, 1, 2, 2, 1, 0] },
        ],
      }),
    ];

    const config: RegressionTransformerOptions = {
      modelType: ModelType.linear,
      predictionCount: 6,
      xFieldName: 'time',
      yFieldName: 'value',
    };

    expect(toEquableDataFrames(RegressionTransformer.transformer(config, {} as DataTransformContext)(source))).toEqual(
      toEquableDataFrames([
        toEquableDataFrame({
          name: 'data',
          refId: 'A',
          fields: [
            { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5], config: {} },
            { name: 'value', type: FieldType.number, values: [0, 1, 2, 2, 1, 0], config: {} },
          ],
          length: 6,
        }),
        toEquableDataFrame({
          name: 'Linear regression',
          fields: [
            { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5], config: {} },
            { name: 'value', type: FieldType.number, values: [1, 1, 1, 1, 1, 1], config: {} },
          ],
          length: 6,
        }),
      ])
    );
  });

  it('it should predict a quadratic function', () => {
    const source = [
      toDataFrame({
        name: 'data',
        refId: 'A',
        fields: [
          { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5] },
          { name: 'value', type: FieldType.number, values: [0, 1, 2, 2, 1, 0] },
        ],
      }),
    ];

    const config: RegressionTransformerOptions = {
      modelType: ModelType.polynomial,
      degree: 2,
      predictionCount: 6,
      xFieldName: 'time',
      yFieldName: 'value',
    };

    const result = RegressionTransformer.transformer(config, {} as DataTransformContext)(source);

    expect(result[1].fields[1].values[0]).toBeCloseTo(-0.1, 1);
    expect(result[1].fields[1].values[1]).toBeCloseTo(1.2, 1);
    expect(result[1].fields[1].values[2]).toBeCloseTo(1.86, 1);
    expect(result[1].fields[1].values[3]).toBeCloseTo(1.86, 1);
    expect(result[1].fields[1].values[4]).toBeCloseTo(1.2, 1);
    expect(result[1].fields[1].values[5]).toBeCloseTo(-0.1, 1);
    expect(result[1].name).toBe('Quadratic polynomial regression');
  });

  it('should have the last x point be equal to the last x point of the data', () => {
    const source = [
      toDataFrame({
        name: 'data',
        refId: 'A',
        fields: [
          { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4] },
          { name: 'value', type: FieldType.number, values: [1, 1, 1, 1, 1] },
        ],
      }),
    ];

    const config: RegressionTransformerOptions = {
      modelType: ModelType.polynomial,
      degree: 2,
      predictionCount: 10,
      xFieldName: 'time',
      yFieldName: 'value',
    };

    const result = RegressionTransformer.transformer(config, {} as DataTransformContext)(source);

    expect(result[1].fields[0].values[0]).toBe(0);
    expect(result[1].fields[0].values[1]).toBeCloseTo(0.44, 1);
    expect(result[1].fields[0].values[4]).toBeCloseTo(1.76, 1);
    expect(result[1].fields[0].values[8]).toBeCloseTo(3.55, 1);
    expect(result[1].fields[0].values[9]).toBe(4);
    expect(result[1].name).toBe('Quadratic polynomial regression');
  });

  it('should filter NaNs', () => {
    const source = [
      toDataFrame({
        name: 'data',
        refId: 'A',
        fields: [
          { name: 'y', type: FieldType.number, values: [0, 1, 2, 3, NaN] },
          { name: 'x', type: FieldType.number, values: [0, 1, 2, 3, 4] },
        ],
      }),
    ];

    const config: RegressionTransformerOptions = {
      modelType: ModelType.linear,
      predictionCount: 5,
      xFieldName: 'x',
      yFieldName: 'y',
    };

    const result = RegressionTransformer.transformer(config, {} as DataTransformContext)(source);

    expect(result[1].fields[1].values[0]).toBe(0);
    expect(result[1].fields[1].values[1]).toBe(1);
    expect(result[1].fields[1].values[2]).toBe(2);
    expect(result[1].fields[1].values[3]).toBe(3);
    expect(result[1].fields[1].values[4]).toBe(4);
    expect(result[1].name).toBe('Linear regression');
  });
});

// A few thousand is the largest predicted series the missing cap may still emit.
// 100_001 is large enough to exhaust a viewer tab and small enough for this test to finish.
const MAX_PREDICTED_POINTS = 10_000;
const UNCAPPED_PREDICTION_COUNT = 100_001;

describe('Trendline prediction count', () => {
  const context = {} as DataTransformContext;

  beforeAll(() => {
    standardTransformersRegistry.setInit(() => [
      {
        id: DataTransformerID.regression,
        name: 'Trendline',
        transformation: () => Promise.resolve(getRegressionTransformer()),
        editor: () => null,
        imageDark: '',
        imageLight: '',
      },
    ]);
  });

  it('caps a saved dashboard prediction count before allocating the linear series', async () => {
    const frames = await runSavedTransformation({
      modelType: ModelType.linear,
      predictionCount: UNCAPPED_PREDICTION_COUNT,
      xFieldName: 'time',
      yFieldName: 'value',
    });

    assertBoundedTrendline(frames, 'Linear regression');
  });

  it('caps a saved dashboard prediction count before allocating the polynomial series', async () => {
    const frames = await runSavedTransformation({
      modelType: ModelType.polynomial,
      degree: 2,
      predictionCount: UNCAPPED_PREDICTION_COUNT,
      xFieldName: 'time',
      yFieldName: 'value',
    });

    assertBoundedTrendline(frames, 'Quadratic polynomial regression');
  });

  it('caps a numeric-string prediction count from dashboard JSON', async () => {
    const frames = await runSavedTransformation({
      modelType: ModelType.linear,
      predictionCount: String(UNCAPPED_PREDICTION_COUNT),
      xFieldName: 'time',
      yFieldName: 'value',
    });

    assertBoundedTrendline(frames, 'Linear regression');
  });

  it('uses the capped count when predictionCount is read again while allocating', () => {
    const options = {
      modelType: ModelType.linear,
      xFieldName: 'time',
      yFieldName: 'value',
      get predictionCount() {
        return UNCAPPED_PREDICTION_COUNT;
      },
    };

    const transformer = getRegressionTransformer();
    const fromTransformer = transformer.transformer(options, context)(sourceFrames());
    assertBoundedTrendline(fromTransformer, 'Linear regression');
  });

  it('caps the count on the operator used when a panel renders', async () => {
    const options = {
      modelType: ModelType.linear,
      xFieldName: 'time',
      yFieldName: 'value',
      get predictionCount() {
        return UNCAPPED_PREDICTION_COUNT;
      },
    };
    const transformer = getRegressionTransformer();
    const frames = await lastValueFrom(transformer.operator(options, context)(sourceObservable()));

    assertBoundedTrendline(frames, 'Linear regression');
  });

  it.each([
    ['zero', 0],
    ['a negative count', -8],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('falls back to the default series when predictionCount is %s', (_label, predictionCount) => {
    const transformer = getRegressionTransformer();
    const frames = transformer.transformer(
      {
        modelType: ModelType.linear,
        predictionCount,
        xFieldName: 'time',
        yFieldName: 'value',
      },
      context
    )(sourceFrames());

    expect(frames).toHaveLength(2);
    expect(frames[1].name).toBe('Linear regression');
    expect(frames[1].length).toBe(100);
    expect(frames[1].fields[0].values.length).toBe(100);
    expect(frames[1].fields[1].values.length).toBe(100);
  });

  it('falls back to the default series for a non-positive count stored in dashboard JSON', async () => {
    const frames = await runSavedTransformation({
      modelType: ModelType.linear,
      predictionCount: 0,
      xFieldName: 'time',
      yFieldName: 'value',
    });

    expect(frames).toHaveLength(2);
    expect(frames[1].length).toBe(100);
    expect(frames[1].fields[0].values.length).toBe(100);
    expect(frames[1].fields[1].values.length).toBe(100);
  });

  it('does not allocate a fractional prediction count', () => {
    const transformer = getRegressionTransformer();
    const frames = transformer.transformer(
      {
        modelType: ModelType.linear,
        predictionCount: UNCAPPED_PREDICTION_COUNT + 0.5,
        xFieldName: 'time',
        yFieldName: 'value',
      },
      context
    )(sourceFrames());

    assertBoundedTrendline(frames, 'Linear regression');
  });
});

function sourceFrames() {
  return [
    toDataFrame({
      name: 'data',
      refId: 'A',
      fields: [
        { name: 'time', type: FieldType.time, values: [0, 1, 2, 3, 4, 5] },
        { name: 'value', type: FieldType.number, values: [0, 1, 2, 3, 4, 5] },
      ],
    }),
  ];
}

function sourceObservable() {
  return of(sourceFrames());
}

async function runSavedTransformation(options: Record<string, unknown>) {
  const savedPanel = JSON.parse(
    JSON.stringify({
      transformations: [
        {
          id: DataTransformerID.regression,
          options,
        },
      ],
    })
  ) as { transformations: Array<{ id: string; options: RegressionTransformerOptions }> };

  return lastValueFrom(transformDataFrame(savedPanel.transformations, sourceFrames()));
}

function assertBoundedTrendline(frames: DataFrame[], name: string) {
  expect(frames).toHaveLength(2);
  const trend = frames[1];
  expect(trend.name).toBe(name);
  expect(trend.length).toBeGreaterThan(1);
  expect(trend.length).toBeLessThanOrEqual(MAX_PREDICTED_POINTS);
  expect(trend.fields[0].values.length).toBeLessThanOrEqual(MAX_PREDICTED_POINTS);
  expect(trend.fields[1].values.length).toBeLessThanOrEqual(MAX_PREDICTED_POINTS);
  expect(trend.fields[0].values.length).toBe(trend.length);
  expect(trend.fields[1].values.length).toBe(trend.length);
}

function toEquableDataFrame(source: DataFrame): DataFrame {
  return toDataFrame({
    ...source,
    fields: source.fields.map((field: Field) => {
      return {
        ...field,
        config: {},
      };
    }),
  });
}

function toEquableDataFrames(data: DataFrame[]): DataFrameDTO[] {
  return data.map((frame) => toDataFrameDTO(frame));
}
