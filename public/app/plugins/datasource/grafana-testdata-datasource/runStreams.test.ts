import { type DataQueryRequest, type DataSourceInstanceSettings, LoadingState } from '@grafana/data';
import { type TemplateSrv } from '@grafana/runtime';

import { type TestDataDataQuery } from './dataquery';
import { TestDataDataSource } from './datasource';

// datasource.ts imports node graph helpers that are not on the streaming path.
// Their dependency is ESM-only and this plugin's Jest config does not transform it.
jest.mock('./nodeGraphUtils', () => ({
  generateRandomEdges: jest.fn(),
  generateRandomNodes: jest.fn(),
  generateShowcaseData: jest.fn(),
  savedNodesResponse: {},
}));

/**
 * The streaming client editor only sets HTML min=10. Saved dashboard JSON can
 * carry a smaller speed, and signal streams can carry an unbounded bands count.
 * These tests are the bound the query path must enforce.
 */
const MIN_STREAM_SPEED_MS = 10;
const MAX_STREAM_BANDS = 100;

const originalSetTimeout = global.setTimeout;
const originalRandom = Math.random;

type StreamType = 'signal' | 'logs' | 'traces';

function createDatasource() {
  return new TestDataDataSource(
    {
      name: 'TestData',
      uid: 'testdata',
      type: 'grafana-testdata-datasource',
      meta: { id: 'grafana-testdata-datasource' },
    } as DataSourceInstanceSettings,
    { replace: (value: string) => value } as TemplateSrv
  );
}

function requestFromSavedDashboard(stream: TestDataDataQuery['stream'], maxDataPoints: number) {
  // The same shape PostDashboard stores and a viewer reload parses back out.
  const saved = JSON.parse(
    JSON.stringify({
      panels: [
        {
          targets: [
            {
              refId: 'A',
              scenarioId: 'streaming_client',
              stream,
            },
          ],
        },
      ],
    })
  ) as { panels: Array<{ targets: TestDataDataQuery[] }> };

  return {
    requestId: 'Q1',
    interval: '1s',
    intervalMs: 1000,
    maxDataPoints,
    range: { from: { valueOf: () => 0 }, to: { valueOf: () => 1 }, raw: { from: 'now-1h', to: 'now' } },
    scopedVars: {},
    targets: saved.panels[0].targets,
    timezone: 'utc',
    app: 'dashboard',
    panelId: 7,
    startTime: Date.now(),
  } as DataQueryRequest<TestDataDataQuery>;
}

async function waitFor(predicate: () => boolean) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > 1000) {
      throw new Error('timed out waiting for the stream to schedule its next frame');
    }
    await new Promise((resolve) => originalSetTimeout(resolve, 1));
  }
}

describe('TestData streaming_client bounds', () => {
  const datasource = createDatasource();

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('speed is floored before the next frame is scheduled', () => {
    it.each([
      ['signal', 0, MIN_STREAM_SPEED_MS],
      ['signal', -1, MIN_STREAM_SPEED_MS],
      ['signal', -1000, MIN_STREAM_SPEED_MS],
      ['signal', 1, MIN_STREAM_SPEED_MS],
      ['signal', 9, MIN_STREAM_SPEED_MS],
      ['signal', 10, 10],
      ['signal', 250, 250],
      ['logs', 0, MIN_STREAM_SPEED_MS],
      ['logs', -1, MIN_STREAM_SPEED_MS],
      ['logs', 9, MIN_STREAM_SPEED_MS],
      ['logs', 250, 250],
      ['traces', 0, MIN_STREAM_SPEED_MS],
      ['traces', -15, MIN_STREAM_SPEED_MS],
      ['traces', 9, MIN_STREAM_SPEED_MS],
      ['traces', 40, 40],
    ] satisfies Array<[StreamType, number, number]>)(
      '%s stream speed %s schedules the next frame after %s ms',
      async (type, speed, expectedDelay) => {
        const recurringDelays: number[] = [];
        let insideFrame = false;

        jest.spyOn(global, 'setTimeout').mockImplementation((handler, timeout, ...args) => {
          const delay = timeout as number;
          if (insideFrame) {
            recurringDelays.push(delay);
          }
          return originalSetTimeout(() => {
            insideFrame = true;
            try {
              (handler as TimerHandler)();
            } finally {
              insideFrame = false;
            }
          }, timeout, ...args) as ReturnType<typeof setTimeout>;
        });

        const subscription = datasource
          .query(
            requestFromSavedDashboard(
              {
                type,
                speed,
                spread: 1,
                noise: 1,
                bands: 1,
              },
              2
            )
          )
          .subscribe();

        try {
          await waitFor(() => recurringDelays.length > 0);
        } finally {
          subscription.unsubscribe();
        }

        expect(recurringDelays[0]).toBe(expectedDelay);
        expect(recurringDelays.every((delay) => delay === expectedDelay)).toBe(true);
      }
    );

    it('treats a null speed from saved JSON as the minimum, not an immediate timeout', async () => {
      const recurringDelays: number[] = [];
      let insideFrame = false;

      jest.spyOn(global, 'setTimeout').mockImplementation((handler, timeout, ...args) => {
        if (insideFrame) {
          recurringDelays.push(timeout as number);
        }
        return originalSetTimeout(() => {
          insideFrame = true;
          try {
            (handler as TimerHandler)();
          } finally {
            insideFrame = false;
          }
        }, timeout, ...args) as ReturnType<typeof setTimeout>;
      });

      const saved = JSON.parse(
        '{"refId":"A","scenarioId":"streaming_client","stream":{"type":"signal","speed":null,"spread":1,"noise":1,"bands":1}}'
      ) as TestDataDataQuery;

      const subscription = datasource
        .query({
          ...requestFromSavedDashboard(saved.stream, 2),
          targets: [saved],
        })
        .subscribe();

      try {
        await waitFor(() => recurringDelays.length > 0);
      } finally {
        subscription.unsubscribe();
      }

      expect(recurringDelays[0]).toBe(MIN_STREAM_SPEED_MS);
    });
  });

  describe('signal bands are capped for the schema and for every frame', () => {
    it.each([101, 1000, 10000])(
      'a saved bands value of %s is capped at 100 bands',
      async (bands) => {
        let phase: 'init' | 'frame' | 'idle' = 'idle';
        let initRandomCalls = 0;
        let frameRandomCalls = 0;

        jest.spyOn(Math, 'random').mockImplementation(() => {
          if (phase === 'init') {
            initRandomCalls++;
          } else if (phase === 'frame') {
            frameRandomCalls++;
          }
          return originalRandom();
        });

        let insideFrame = false;
        jest.spyOn(global, 'setTimeout').mockImplementation((handler, timeout, ...args) => {
          return originalSetTimeout(() => {
            const openingFrame = !insideFrame;
            insideFrame = true;
            if (openingFrame) {
              phase = 'frame';
            }
            try {
              (handler as TimerHandler)();
            } finally {
              phase = 'idle';
              insideFrame = false;
            }
          }, timeout, ...args) as ReturnType<typeof setTimeout>;
        });

        const frames: Array<{ fields: number }> = [];
        phase = 'init';
        const subscription = datasource
          .query(
            requestFromSavedDashboard(
              {
                type: 'signal',
                speed: 250,
                spread: 1,
                noise: 1,
                bands,
              },
              1
            )
          )
          .subscribe((response) => {
            const frame = response.data[0];
            frames.push({ fields: frame.fields.length });
            expect(response.state).toBe(LoadingState.Streaming);
          });
        phase = 'idle';

        try {
          await waitFor(() => frames.length > 0);
        } finally {
          subscription.unsubscribe();
        }

        // 100 bands: time + value + min/max per band = 202 fields.
        // The series is seeded once. Each row draws once, then twice per band.
        // One row is built while subscribing, and one row on the first frame.
        expect(frames[0].fields).toBe(202);
        expect(initRandomCalls).toBe(202);
        expect(frameRandomCalls).toBe(201);
      }
    );

    it('keeps a small bands value', async () => {
      const frames: number[] = [];
      const subscription = datasource
        .query(
          requestFromSavedDashboard(
            {
              type: 'signal',
              speed: 250,
              spread: 1,
              noise: 1,
              bands: 1,
            },
            1
          )
        )
        .subscribe((response) => {
          frames.push(response.data[0].fields.length);
        });

      try {
        await waitFor(() => frames.length > 0);
      } finally {
        subscription.unsubscribe();
      }

      expect(frames[0]).toBe(4);
    });
  });
});
