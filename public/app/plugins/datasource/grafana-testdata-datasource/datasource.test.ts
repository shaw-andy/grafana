// nodeGraphUtils imports d3-random, which this plugin's Jest config does not transform.
// Annotation queries do not call it.
jest.mock('./nodeGraphUtils', () => ({
  generateRandomEdges: jest.fn(),
  generateRandomNodes: jest.fn(),
  generateShowcaseData: jest.fn(),
  savedNodesResponse: jest.fn(),
}));

import { lastValueFrom } from 'rxjs';

import {
  CoreApp,
  DataTopic,
  type DataQueryRequest,
  type DataQueryResponse,
  type DataSourceInstanceSettings,
  dateTime,
} from '@grafana/data';
import { type TemplateSrv } from '@grafana/runtime';

import { type TestDataDataQuery, TestDataQueryType } from './dataquery';
import { TestDataDataSource } from './datasource';

// The logs scenario already refuses to generate more than this many rows from `lines`.
const MAX_ANNOTATION_EVENTS = 10000;
const ANNOTATION_TEXT = 'This is the text, <a href="https://grafana.com">Grafana.com</a>';

const templateSrv = {
  replace: (target?: string) => target ?? '',
} as TemplateSrv;

function createDatasource() {
  const instanceSettings = {
    id: 1,
    uid: 'testdata',
    type: 'grafana-testdata-datasource',
    name: 'TestData',
    jsonData: {},
    access: 'proxy',
    readOnly: false,
    meta: { id: 'grafana-testdata-datasource' },
  } as DataSourceInstanceSettings;

  return new TestDataDataSource(instanceSettings, templateSrv);
}

function annotationRequest(lines?: TestDataDataQuery['lines']): DataQueryRequest<TestDataDataQuery> {
  const target: TestDataDataQuery = {
    refId: 'A',
    scenarioId: TestDataQueryType.Annotations,
  };
  if (lines !== undefined) {
    target.lines = lines;
  }

  return {
    requestId: 'annotation-lines',
    interval: '1s',
    intervalMs: 1000,
    range: {
      from: dateTime(0),
      to: dateTime(60_000),
      raw: { from: 'now-1m', to: 'now' },
    },
    scopedVars: {},
    targets: [target],
    timezone: 'utc',
    app: CoreApp.Dashboard,
    startTime: 0,
  };
}

function isBuiltAnnotationEvent(item: unknown): boolean {
  return (
    item !== null &&
    typeof item === 'object' &&
    (item as { text?: unknown }).text === ANNOTATION_TEXT &&
    Array.isArray((item as { tags?: unknown }).tags)
  );
}

async function countBuiltAnnotationEvents(run: () => Promise<void>): Promise<number> {
  let built = 0;
  const originalPush = Array.prototype.push;
  Array.prototype.push = function push(this: unknown[], ...items: unknown[]) {
    for (const item of items) {
      if (isBuiltAnnotationEvent(item)) {
        built += 1;
      }
    }
    return originalPush.apply(this, items);
  };

  try {
    await run();
  } finally {
    Array.prototype.push = originalPush;
  }

  return built;
}

function textFieldLength(response: DataQueryResponse) {
  const frame = response.data[0];
  const text = frame?.fields.find((field) => field.name === 'text');
  return { frame, text };
}

describe('TestData annotation events', () => {
  it('builds 10 annotation events when the saved query omits lines', async () => {
    const ds = createDatasource();
    const built = await countBuiltAnnotationEvents(async () => {
      const response = await lastValueFrom(ds.query(annotationRequest()));
      const { frame, text } = textFieldLength(response);
      expect(frame?.meta?.dataTopic).toBe(DataTopic.Annotations);
      expect(frame?.length).toBe(10);
      expect(text?.values.length).toBe(10);
      expect(text?.values[0]).toBe(ANNOTATION_TEXT);
    });

    expect(built).toBe(10);
  });

  it('builds one annotation event per lines value when lines is 10000', async () => {
    const ds = createDatasource();
    const built = await countBuiltAnnotationEvents(async () => {
      const response = await lastValueFrom(ds.query(annotationRequest(MAX_ANNOTATION_EVENTS)));
      const { text } = textFieldLength(response);
      expect(text?.values.length).toBe(MAX_ANNOTATION_EVENTS);
      expect(text?.values[0]).toBe(ANNOTATION_TEXT);
      expect(text?.values[MAX_ANNOTATION_EVENTS - 1]).toBe(ANNOTATION_TEXT);
    });

    expect(built).toBe(MAX_ANNOTATION_EVENTS);
  });

  it('builds 10000 annotation events when the saved lines value is above 10000', async () => {
    const ds = createDatasource();
    let response: DataQueryResponse | undefined;
    const built = await countBuiltAnnotationEvents(async () => {
      response = await lastValueFrom(ds.query(annotationRequest(MAX_ANNOTATION_EVENTS + 1)));
    });
    const { frame, text } = textFieldLength(response!);

    expect(built).toBe(MAX_ANNOTATION_EVENTS);
    expect(frame?.length).toBe(MAX_ANNOTATION_EVENTS);
    expect(text?.values.length).toBe(MAX_ANNOTATION_EVENTS);
    expect(text?.values[0]).toBe(ANNOTATION_TEXT);
  });

  it('builds 10000 annotation events when lines is a numeric string above 10000', async () => {
    const ds = createDatasource();
    const request = annotationRequest();
    request.targets[0].lines = '10001' as unknown as number;

    const built = await countBuiltAnnotationEvents(async () => {
      const response = await lastValueFrom(ds.query(request));
      const { text } = textFieldLength(response);
      expect(text?.values.length).toBe(MAX_ANNOTATION_EVENTS);
      expect(text?.values[0]).toBe(ANNOTATION_TEXT);
    });

    expect(built).toBe(MAX_ANNOTATION_EVENTS);
  });

  it('does not build annotation events when lines is not finite', async () => {
    let reads = 0;
    const lines = {
      valueOf() {
        reads += 1;
        if (reads > 1) {
          throw new Error('non-finite annotation lines were read again');
        }
        return Number.POSITIVE_INFINITY;
      },
    } as unknown as number;

    const ds = createDatasource();
    let thrown: unknown;
    let response: DataQueryResponse | undefined;
    const built = await countBuiltAnnotationEvents(async () => {
      try {
        response = await lastValueFrom(ds.query(annotationRequest(lines)));
      } catch (error) {
        thrown = error;
      }
    });

    expect(built).toBe(0);
    expect(String(thrown instanceof Error ? thrown.message : '')).not.toContain('read again');
    if (!thrown) {
      expect(response?.data[0]?.length ?? 0).toBe(0);
    }
  });
});
