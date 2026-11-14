import { firstValueFrom } from 'rxjs';

import {
  type AnnotationQueryRequest,
  type DataQueryRequest,
  type DataSourceInstanceSettings,
  dateTime,
} from '@grafana/data';
import { type PanelPluginMetas } from '@grafana/runtime/internal';
import { type PanelQueryKind } from '@grafana/schema/apis/dashboard.grafana.app/v2';
import { backendSrv } from 'app/core/services/backend_srv'; // will use the version in __mocks__
import { PanelModel } from 'app/features/dashboard/state/PanelModel';
import { panelQueryKindToSceneQuery } from 'app/features/dashboard-scene/serialization/layoutSerializers/utils';
import { createPanelDataProvider } from 'app/features/dashboard-scene/utils/createPanelDataProvider';
import { getQueryRunnerFor } from 'app/features/dashboard-scene/utils/getQueryRunnerFor';

import { GrafanaDatasource } from './datasource';
import { type GrafanaAnnotationQuery, GrafanaAnnotationType, type GrafanaQuery, GrafanaQueryType } from './types';

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  getBackendSrv: () => backendSrv,
  getTemplateSrv: () => ({
    replace: (val: string) => {
      return val.replace('$var2', 'replaced__delimiter__replaced2').replace('$var', 'replaced');
    },
  }),
}));

function randomWalkRequest(targets: GrafanaQuery[]): DataQueryRequest<GrafanaQuery> {
  return {
    targets,
    range: {
      from: dateTime('2024-01-01T00:00:00Z'),
      to: dateTime('2024-01-01T01:00:00Z'),
      raw: { from: 'now-1h', to: 'now' },
    },
    intervalMs: 60000,
    maxDataPoints: 60,
    requestId: 'test',
    interval: '1m',
    scopedVars: {},
    timezone: 'browser',
    app: 'dashboard',
    startTime: 0,
  } as DataQueryRequest<GrafanaQuery>;
}

async function framesFor(targets: GrafanaQuery[]) {
  const ds = new GrafanaDatasource({} as DataSourceInstanceSettings);
  const response = await firstValueFrom(ds.query(randomWalkRequest(targets)));
  return response.data;
}

describe('RandomWalk query', () => {
  it('does not build one frame per series for a random-walk target above 500', async () => {
    const frames = await framesFor([{ refId: 'A', queryType: GrafanaQueryType.RandomWalk, seriesCount: 2000 }]);
    expect(frames.length).toBeGreaterThan(0);
    expect(frames.length).toBeLessThanOrEqual(500);
  });

  it('does not build one frame per series when a saved target omits queryType', async () => {
    const frames = await framesFor([{ refId: 'A', seriesCount: 2000 } as GrafanaQuery]);
    expect(frames.length).toBeGreaterThan(0);
    expect(frames.length).toBeLessThanOrEqual(500);
  });

  it('does not build one frame per series for the targets a saved panel hands to the query runner', async () => {
    const panel = new PanelModel({
      id: 1,
      type: 'timeseries',
      datasource: { type: 'grafana', uid: 'grafana' },
      targets: [
        {
          refId: 'A',
          datasource: { type: 'grafana', uid: 'grafana' },
          queryType: GrafanaQueryType.RandomWalk,
          seriesCount: 2000,
        },
      ],
    });

    const provider = createPanelDataProvider(panel, {} as PanelPluginMetas);
    const queries = (getQueryRunnerFor(provider)?.state.queries ?? []) as GrafanaQuery[];
    expect(queries[0]?.seriesCount).toBe(2000);

    const frames = await framesFor(queries);
    expect(frames.length).toBeGreaterThan(0);
    expect(frames.length).toBeLessThanOrEqual(500);
  });

  it('does not build one frame per series for a v2 panel query', async () => {
    const saved: PanelQueryKind = {
      kind: 'PanelQuery',
      spec: {
        refId: 'A',
        hidden: false,
        query: {
          kind: 'DataQuery',
          group: 'grafana',
          version: 'v0',
          datasource: { name: 'grafana' },
          spec: {
            queryType: GrafanaQueryType.RandomWalk,
            seriesCount: 2000,
          },
        },
      },
    };
    const sceneQuery = panelQueryKindToSceneQuery(saved) as GrafanaQuery;
    expect(sceneQuery.seriesCount).toBe(2000);

    const frames = await framesFor([sceneQuery]);
    expect(frames.length).toBeGreaterThan(0);
    expect(frames.length).toBeLessThanOrEqual(500);
  });

  it('each query emits a response with a distinct key matching its refId', (done) => {
    const ds = new GrafanaDatasource({} as DataSourceInstanceSettings);
    const request = {
      targets: [
        { refId: 'A', queryType: GrafanaQueryType.RandomWalk },
        { refId: 'B', queryType: GrafanaQueryType.RandomWalk },
      ],
      range: {
        from: dateTime('2024-01-01T00:00:00Z'),
        to: dateTime('2024-01-01T01:00:00Z'),
        raw: { from: 'now-1h', to: 'now' },
      },
      intervalMs: 60000,
      maxDataPoints: 60,
      requestId: 'test',
      interval: '1m',
      scopedVars: {},
      timezone: 'browser',
      app: 'dashboard',
      startTime: 0,
    } as unknown as DataQueryRequest<GrafanaQuery>;

    const keys: string[] = [];
    ds.query(request).subscribe({
      next: (response) => {
        expect(response.key).toBeDefined();
        keys.push(response.key!);
      },
      complete: () => {
        expect(keys).toHaveLength(2);
        expect(keys).toContain('A');
        expect(keys).toContain('B');
        done();
      },
    });
  });
});

describe('grafana data source', () => {
  const getMock = jest.spyOn(backendSrv, 'get');

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('when executing an annotations query', () => {
    let calledBackendSrvParams: Parameters<(typeof backendSrv)['get']>[1];
    let ds: GrafanaDatasource;
    beforeEach(() => {
      getMock.mockImplementation((url, options) => {
        calledBackendSrvParams = options;
        return Promise.resolve([]);
      });

      ds = new GrafanaDatasource({} as DataSourceInstanceSettings);
    });

    describe('with tags that have template variables', () => {
      const options = setupAnnotationQueryOptions({ tags: ['tag1:$var'] });

      beforeEach(() => {
        return ds.getAnnotations(options);
      });

      it('should interpolate template variables in tags in query options', () => {
        expect(calledBackendSrvParams?.tags[0]).toBe('tag1:replaced');
      });
    });

    describe('with tags that have multi value template variables', () => {
      const options = setupAnnotationQueryOptions({ tags: ['$var2'] });

      beforeEach(() => {
        return ds.getAnnotations(options);
      });

      it('should interpolate template variables in tags in query options', () => {
        expect(calledBackendSrvParams?.tags[0]).toBe('replaced');
        expect(calledBackendSrvParams?.tags[1]).toBe('replaced2');
      });
    });

    describe('with type dashboard', () => {
      const options = setupAnnotationQueryOptions(
        {
          type: GrafanaAnnotationType.Dashboard,
          tags: ['tag1'],
        },
        { uid: 'DSNdW0gVk' }
      );

      beforeEach(() => {
        return ds.getAnnotations(options);
      });

      it('should remove tags from query options', () => {
        expect(calledBackendSrvParams?.tags).toBe(undefined);
      });
    });
  });
});

function setupAnnotationQueryOptions(annotation: Partial<GrafanaAnnotationQuery>, dashboard?: { uid: string }) {
  return {
    annotation: {
      target: annotation,
    },
    dashboard,
    range: {
      from: dateTime(1432288354),
      to: dateTime(1432288401),
    },
    rangeRaw: { from: 'now-24h', to: 'now' },
  } as unknown as AnnotationQueryRequest<GrafanaQuery>;
}
