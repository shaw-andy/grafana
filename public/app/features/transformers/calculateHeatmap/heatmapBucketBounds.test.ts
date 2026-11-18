import { createTheme, dateTime, FieldType, toDataFrame, type DataFrame } from '@grafana/data';
import { HeatmapCalculationMode, ScaleDistribution } from '@grafana/schema';
import { prepareHeatmapData } from 'app/plugins/panel/heatmap/fields';
import { type Options } from 'app/plugins/panel/heatmap/panelcfg.gen';

import { calculateHeatmapFromData, getHeatmapTransformer, type HeatmapTransformerOptions } from './heatmap';

/**
 * A calculated heatmap may not build more than this many bins on either axis.
 * The cell grid is the product, and that product must not be allocated at all
 * when the saved bucket size would exceed it. 500 is the fixed cap from the
 * bucket-size remediation: a few hundred bins per axis.
 */
const MAX_BINS_PER_AXIS = 500;
const MAX_CELLS = MAX_BINS_PER_AXIS * MAX_BINS_PER_AXIS;

const ONE_HOUR_MS = 60 * 60 * 1000;

const theme = createTheme();

function series(times: number[], values: number[]): DataFrame {
  return toDataFrame({
    fields: [
      { name: 'time', type: FieldType.time, values: times },
      { name: 'value', type: FieldType.number, values },
    ],
  });
}

function hourRange() {
  return { from: dateTime(0), to: dateTime(ONE_HOUR_MS), raw: { from: '0', to: '1h' } };
}

/**
 * initBins allocates with `new Array(xBins * yBins)` before it fills the grid.
 * Reject that allocation itself. A later slice of a smaller frame still fails
 * when the oversized array was constructed first.
 */
function callWithoutOversizedArray<T>(run: () => T): T {
  const realArray = globalThis.Array;
  const wrapped = new Proxy(realArray, {
    apply(target, thisArg, args) {
      rejectOversized(args);
      return Reflect.apply(target, thisArg, args);
    },
    construct(target, args, newTarget) {
      rejectOversized(args);
      return Reflect.construct(target, args, newTarget);
    },
  });

  globalThis.Array = wrapped as typeof Array;
  try {
    return run();
  } finally {
    globalThis.Array = realArray;
  }
}

function rejectOversized(args: unknown[]) {
  if (args.length === 1 && typeof args[0] === 'number' && args[0] > MAX_CELLS) {
    throw new Error(`heatmap allocated ${args[0]} cells; cap is ${MAX_CELLS}`);
  }
}

function distinctCount(values: ArrayLike<number>): number {
  const seen = new Set<number>();
  for (let i = 0; i < values.length; i++) {
    seen.add(values[i]);
  }
  return seen.size;
}

function sumCounts(values: ArrayLike<number>): number {
  let sum = 0;
  for (let i = 0; i < values.length; i++) {
    const value = values[i];
    if (typeof value === 'number' && Number.isFinite(value)) {
      sum += value;
    }
  }
  return sum;
}

function assertBoundedHeatmap(frame: DataFrame, sampleCount: number) {
  const xField = frame.fields.find((field) => field.name === 'xMin' || field.name === 'x');
  const yField = frame.fields.find((field) => field.name === 'yMin' || field.name === 'y');
  const countField = frame.fields.find((field) => field.name === 'Count' || field.name === 'count');

  expect(frame.meta?.type).toBe('heatmap-cells');
  expect(xField).toBeDefined();
  expect(yField).toBeDefined();
  expect(countField).toBeDefined();
  expect(countField!.values.length).toBeLessThanOrEqual(MAX_CELLS);
  expect(countField!.values.length).toBe(xField!.values.length);
  expect(distinctCount(xField!.values)).toBeLessThanOrEqual(MAX_BINS_PER_AXIS);
  expect(distinctCount(yField!.values)).toBeLessThanOrEqual(MAX_BINS_PER_AXIS);
  expect(sumCounts(countField!.values)).toBe(sampleCount);
}

describe('heatmap bucket size bounds', () => {
  const pointsInsideHour = series([1_000, 2_000], [10, 20]);

  it.each(['1', '1ms'])('keeps a %s x bucket over a one hour dashboard range within the bin cap', (xSize) => {
    const frame = callWithoutOversizedArray(() =>
      calculateHeatmapFromData([pointsInsideHour], {
        xBuckets: { mode: HeatmapCalculationMode.Size, value: xSize },
        yBuckets: { mode: HeatmapCalculationMode.Size, value: '10' },
        timeRange: hourRange(),
      })
    );

    assertBoundedHeatmap(frame, 2);
  });

  it('keeps a 1e-6 y bucket within the bin cap', () => {
    const frame = callWithoutOversizedArray(() =>
      calculateHeatmapFromData([series([0, ONE_HOUR_MS], [0, 1])], {
        xBuckets: { mode: HeatmapCalculationMode.Size, value: String(ONE_HOUR_MS) },
        yBuckets: { mode: HeatmapCalculationMode.Size, value: '1e-6' },
        timeRange: hourRange(),
      })
    );

    assertBoundedHeatmap(frame, 2);
  });

  it('keeps a log y split that subdivides the exponents within the bin cap', () => {
    const frame = callWithoutOversizedArray(() =>
      calculateHeatmapFromData([series([0, ONE_HOUR_MS], [1, 1_000_000])], {
        xBuckets: { mode: HeatmapCalculationMode.Size, value: String(ONE_HOUR_MS) },
        yBuckets: {
          mode: HeatmapCalculationMode.Size,
          value: '100000',
          scale: { type: ScaleDistribution.Log, log: 10 },
        },
        timeRange: hourRange(),
      })
    );

    assertBoundedHeatmap(frame, 2);
  });

  it('keeps a count-mode x bucket large enough to snap to 1ms within the bin cap', () => {
    const frame = callWithoutOversizedArray(() =>
      calculateHeatmapFromData([pointsInsideHour], {
        xBuckets: { mode: HeatmapCalculationMode.Count, value: '1000000000' },
        yBuckets: { mode: HeatmapCalculationMode.Size, value: '10' },
        timeRange: hourRange(),
      })
    );

    assertBoundedHeatmap(frame, 2);
  });

  it('keeps an ordinary size-mode calculation on the same grid as an uncapped 10ms by 5 calculation', () => {
    const frame = callWithoutOversizedArray(() =>
      calculateHeatmapFromData([series([10, 20, 30], [10, 20, 30])], {
        xBuckets: { mode: HeatmapCalculationMode.Size, value: '10' },
        yBuckets: {
          mode: HeatmapCalculationMode.Size,
          value: '5',
          scale: { type: ScaleDistribution.Linear },
        },
        timeRange: { from: dateTime(0), to: dateTime(50), raw: { from: '0', to: '50' } },
      })
    );

    expect(frame.fields.find((field) => field.name === 'Count')!.values).toEqual([
      0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    assertBoundedHeatmap(frame, 3);
  });
});

describe('heatmap transformer bucket size bounds', () => {
  it('keeps a 1ms x bucket within the bin cap when the series itself spans an hour', () => {
    const options: HeatmapTransformerOptions = {
      xBuckets: { mode: HeatmapCalculationMode.Size, value: '1ms' },
      yBuckets: { mode: HeatmapCalculationMode.Size, value: '10' },
    };

    const [frame] = callWithoutOversizedArray(() =>
      getHeatmapTransformer().transformer(options)([series([0, ONE_HOUR_MS], [10, 20])])
    );

    assertBoundedHeatmap(frame, 2);
  });
});

describe('heatmap panel calculate-from-data bucket size bounds', () => {
  const panelOptions = { color: {} } as Options;

  it('keeps a saved 1ms x bucket within the bin cap for the panel time range', () => {
    const info = callWithoutOversizedArray(() =>
      prepareHeatmapData({
        frames: [series([1_000, 2_000], [10, 20])],
        options: {
          ...panelOptions,
          calculate: true,
          calculation: {
            xBuckets: { mode: HeatmapCalculationMode.Size, value: '1ms' },
            yBuckets: { mode: HeatmapCalculationMode.Size, value: '10', scale: { type: ScaleDistribution.Linear } },
          },
        },
        palette: ['#000', '#fff'],
        theme,
        timeRange: hourRange(),
        replaceVariables: (value) => value,
      })
    );

    expect(info.warning).toBeUndefined();
    assertBoundedHeatmap(info.heatmap!, 2);
    expect(info.xBucketCount).toBeLessThanOrEqual(MAX_BINS_PER_AXIS);
    expect(info.yBucketCount).toBeLessThanOrEqual(MAX_BINS_PER_AXIS);
  });

  it('keeps a saved 1e-9 y bucket within the bin cap for the panel time range', () => {
    const info = callWithoutOversizedArray(() =>
      prepareHeatmapData({
        frames: [series([0, ONE_HOUR_MS], [0, 1])],
        options: {
          ...panelOptions,
          calculate: true,
          calculation: {
            xBuckets: { mode: HeatmapCalculationMode.Size, value: String(ONE_HOUR_MS) },
            yBuckets: {
              mode: HeatmapCalculationMode.Size,
              value: '1e-9',
              scale: { type: ScaleDistribution.Linear },
            },
          },
        },
        palette: ['#000', '#fff'],
        theme,
        timeRange: hourRange(),
        replaceVariables: (value) => value,
      })
    );

    expect(info.warning).toBeUndefined();
    assertBoundedHeatmap(info.heatmap!, 2);
  });
});
