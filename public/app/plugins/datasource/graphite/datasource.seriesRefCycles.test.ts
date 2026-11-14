import { type Observable, of } from 'rxjs';

import { CoreApp, type DataQueryRequest, type DataQueryResponse, dateTime, PluginType } from '@grafana/data';
import { type BackendSrvRequest, config, type FetchResponse, getTemplateSrv } from '@grafana/runtime';

import { GraphiteDatasource } from './datasource';
import { type GraphiteQuery, GraphiteType } from './types';

const fetchMock = jest.fn();

jest.mock('@grafana/runtime', () => ({
  ...(jest.requireActual('@grafana/runtime') as unknown as object),
  getBackendSrv: () => ({
    fetch: fetchMock,
  }),
  getTemplateSrv: () => {
    return {
      replace: (value: string) => value,
    };
  },
}));

const createFetchResponse = <T>(data: T): FetchResponse<T> => ({
  data,
  status: 200,
  url: 'http://localhost:3000/api/query',
  config: { url: 'http://localhost:3000/api/query' },
  type: 'basic',
  statusText: 'Ok',
  redirected: false,
  headers: new Headers(),
  ok: true,
});

const instanceSettings = {
  uid: 'graphiteUid',
  type: 'graphite',
  readOnly: false,
  access: 'proxy' as const,
  meta: {
    id: '1',
    name: 'graphite',
    type: PluginType.datasource,
    info: {
      description: 'Graphite datasource',
      author: { name: 'Grafana Labs', url: 'https://grafana.com' },
      keywords: ['graphite', 'datasource'],
      links: [],
      logos: { large: '', small: '' },
      screenshots: [],
      updated: '',
      version: '',
    },
    module: '',
    baseUrl: '',
  },
  url: '/api/datasources/proxy/1',
  name: 'graphiteProd',
  jsonData: {
    rollupIndicatorEnabled: true,
    graphiteType: GraphiteType.Default,
  },
};

function dashboardRequest(targets: GraphiteQuery[]): DataQueryRequest<GraphiteQuery> {
  return {
    panelId: 3,
    dashboardUID: 'dash',
    range: {
      from: dateTime('2022-04-01T00:00:00'),
      to: dateTime('2022-07-01T00:00:00'),
      raw: { from: '1648789200', to: '1656655200' },
    },
    targets,
    maxDataPoints: 500,
    requestId: 'req',
    interval: '1m',
    intervalMs: 60000,
    scopedVars: {},
    timezone: 'utc',
    app: CoreApp.Dashboard,
    startTime: 0,
  };
}

function sentTargets(body: string): string[] {
  return body
    .split('&')
    .filter((part) => part.startsWith('target='))
    .map((part) => decodeURIComponent(part.slice('target='.length)));
}

describe('Graphite series reference cycles', () => {
  let ds: GraphiteDatasource;
  let previousBackendMode: boolean | undefined;

  beforeEach(() => {
    jest.clearAllMocks();
    previousBackendMode = config.featureToggles.graphiteBackendMode;
    fetchMock.mockImplementation(() => of(createFetchResponse([])));
    ds = new GraphiteDatasource(instanceSettings, getTemplateSrv());
  });

  afterEach(() => {
    config.featureToggles.graphiteBackendMode = previousBackendMode;
  });

  describe('frontend query path', () => {
    let requestOptions: BackendSrvRequest;

    beforeEach(() => {
      config.featureToggles.graphiteBackendMode = false;
      fetchMock.mockImplementation((options: BackendSrvRequest) => {
        requestOptions = options;
        return of(createFetchResponse([]));
      });
    });

    it('substitutes a self-reference once when another query pulls it in', () => {
      const response = ds.query(
        dashboardRequest([
          { refId: 'A', target: '#B' },
          { refId: 'B', target: '#B' },
        ])
      );

      // A repeated letter is substituted once with the text already stored for that query, and that copy is not
      // expanded again. That is the same stop used when the query being built references itself. The stored text on
      // this path is the aliasSub wrapper query() added before expansion.
      expect(response).toBeDefined();
      expect(sentTargets(requestOptions.data)).toEqual([
        'aliasSub(aliasSub(#B, "(^.*$)", "\\1 B"), "(^.*$)", "\\1 A")',
        'aliasSub(aliasSub(#B, "(^.*$)", "\\1 B"), "(^.*$)", "\\1 B")',
      ]);
    });

    it('substitutes a cycle between two other queries once', () => {
      ds.query(
        dashboardRequest([
          { refId: 'A', target: 'sumSeries(#B)' },
          { refId: 'B', target: '#C' },
          { refId: 'C', target: '#B' },
        ])
      );

      expect(sentTargets(requestOptions.data)).toEqual([
        'aliasSub(sumSeries(aliasSub(#C, "(^.*$)", "\\1 B")), "(^.*$)", "\\1 A")',
        'aliasSub(aliasSub(#C, "(^.*$)", "\\1 B"), "(^.*$)", "\\1 B")',
        'aliasSub(aliasSub(#B, "(^.*$)", "\\1 C"), "(^.*$)", "\\1 C")',
      ]);
    });

    it('keeps a series reference whose letter is not in the request and still expands the letters that are', () => {
      ds.query(
        dashboardRequest([
          { refId: 'A', target: 'asPercent(#B,#Z)' },
          { refId: 'B', target: 'series1' },
        ])
      );

      expect(sentTargets(requestOptions.data)).toEqual([
        'aliasSub(asPercent(series1,#Z), "(^.*$)", "\\1 A")',
        'aliasSub(series1, "(^.*$)", "\\1 B")',
      ]);
    });
  });

  describe('backend query path', () => {
    beforeEach(() => {
      config.featureToggles.graphiteBackendMode = true;
    });

    function builtTargets(targets: GraphiteQuery[]): GraphiteQuery[] {
      const request = dashboardRequest(targets);
      const response: Observable<DataQueryResponse> = ds.query(request);
      expect(response).toBeDefined();
      return request.targets;
    }

    it('substitutes a self-reference once when another query pulls it in', () => {
      const targets = builtTargets([
        { refId: 'A', target: '#B' },
        { refId: 'B', target: '#B' },
      ]);

      expect(targets.map((target) => target.target)).toEqual(['#B', '#B']);
      expect(targets.map((target) => target.targetFull)).toEqual(['#B', '#B']);
    });

    it('substitutes a cycle between two other queries once', () => {
      const targets = builtTargets([
        { refId: 'A', target: 'sumSeries(#B)' },
        { refId: 'B', target: '#C' },
        { refId: 'C', target: '#B' },
      ]);

      expect(targets.map((target) => target.target)).toEqual(['sumSeries(#C)', '#C', '#B']);
      expect(targets.map((target) => target.targetFull)).toEqual(['sumSeries(#C)', '#C', '#B']);
    });

    it('keeps a series reference whose letter is not in the request and still expands the letters that are', () => {
      const targets = builtTargets([
        { refId: 'A', target: 'asPercent(#B,#Z)' },
        { refId: 'B', target: 'series1' },
      ]);

      expect(targets.map((target) => target.target)).toEqual(['asPercent(series1,#Z)', 'series1']);
      expect(targets.map((target) => target.targetFull)).toEqual(['asPercent(series1,#Z)', 'series1']);
    });
  });
});
