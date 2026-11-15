import { of } from 'rxjs';
import { render, waitFor } from 'test/test-utils';

import {
  createDataFrame,
  type DataQueryRequest,
  type DataSourceInstanceSettings,
  type DataSourceJsonData,
  FieldType,
  PluginType,
} from '@grafana/data';
import { DataSourceWithBackend, setTemplateSrv } from '@grafana/runtime';
import { FlagKeys } from '@grafana/runtime/internal';
import { getDataSourceInstance, useDataSourceInstanceSettings } from '@grafana/runtime/unstable';
import { setTestFlags } from '@grafana/test-utils/unstable';

import { TemplateSrv } from '../../templating/template_srv';

import SpanFlameGraph from './components/TraceTimelineViewer/SpanDetail/SpanFlameGraph';
import { getTraceToLogsSpanQuery } from './components/logsLink';
import { type TraceSpan } from './components/types/trace';
import { createSpanLinkFactory, pyroscopeProfileIdTagKey } from './createSpanLink';
import { createTraceLogsLink } from './createTraceLink';
import { getFilteredTags } from './crossSignalConfig';
import { transformDataFrames } from './utils/transform';

jest.mock('app/core/services/context_srv', () => ({
  contextSrv: {
    hasAccessToExplore: () => true,
    user: { orgId: 1, timezone: 'utc', weekStart: 'monday' },
  },
}));

jest.mock('@grafana/runtime/unstable', () => ({
  ...jest.requireActual('@grafana/runtime/unstable'),
  getDataSourceInstance: jest.fn(),
  useDataSourceInstanceSettings: jest.fn().mockReturnValue({ isLoading: false, settings: undefined }),
}));

const getDataSourceInstanceMock = jest.mocked(getDataSourceInstance);
const useDataSourceInstanceSettingsMock = jest.mocked(useDataSourceInstanceSettings);

/**
 * Label-literal encoding the trace-to-logs query builders must apply before a span
 * attribute is placed inside a double-quoted matcher. Backslash first, then quote.
 */
function escapeLabelLiteral(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

const QUOTE_BREAKOUT = 'prod" or namespace!="';
const SLASH_AND_QUOTE = 'a\\b"c';
// Closes the quoted matcher and the surrounding selector, then ORs in a second selector.
const METRIC_OR_BREAKOUT = 'x"} or metric{namespace=~".+';

function logsSettings(type: string, uid = `${type}-uid`): DataSourceInstanceSettings<DataSourceJsonData> {
  return {
    uid,
    name: type,
    type,
    jsonData: {},
  } as DataSourceInstanceSettings<DataSourceJsonData>;
}

function traceFrame(tags: Array<{ key: string; value: string }>, serviceName = 'checkout') {
  return createDataFrame({
    fields: [
      { name: 'traceID', values: ['7946b05c2e2e4e5a'] },
      { name: 'spanID', values: ['6605c7b08e715d6c'] },
      { name: 'parentSpanID', values: [''] },
      { name: 'operationName', values: ['GET'] },
      { name: 'serviceName', values: [serviceName] },
      { name: 'startTime', values: [1_602_637_200_000] },
      { name: 'duration', values: [1000] },
      { name: 'serviceTags', values: [tags] },
      { name: 'tags', values: [[{ key: pyroscopeProfileIdTagKey, value: 'profile-1' }]] },
    ],
  });
}

function clickedQuery(splitOpenFn: jest.Mock): Record<string, unknown> {
  const call = splitOpenFn.mock.calls[0]?.[0] as { queries?: Array<Record<string, unknown>> } | undefined;
  expect(call?.queries).toHaveLength(1);
  return call!.queries![0];
}

describe('span attribute values inside related-signal queries', () => {
  beforeEach(() => {
    setTemplateSrv(new TemplateSrv());
    setTestFlags({});
    getDataSourceInstanceMock.mockReset();
    useDataSourceInstanceSettingsMock.mockReturnValue({ isLoading: false, settings: undefined });
  });

  afterEach(() => {
    setTestFlags({});
  });

  it('escapes quotes and backslashes in the tag literal shared by every logs backend', () => {
    const tags = [
      { key: 'namespace', value: QUOTE_BREAKOUT },
      { key: 'pod', value: SLASH_AND_QUOTE },
    ];
    const formatted = getFilteredTags(tags, [{ key: 'namespace' }, { key: 'pod' }]);

    expect(formatted).toEqual([
      `namespace="${escapeLabelLiteral(QUOTE_BREAKOUT)}"`,
      `pod="${escapeLabelLiteral(SLASH_AND_QUOTE)}"`,
    ]);
  });

  it('keeps a benign namespace value inside one quoted matcher', () => {
    const frame = traceFrame([{ key: 'namespace', value: 'prod' }]);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const splitOpenFn = jest.fn();
    const createLink = createSpanLinkFactory({
      splitOpenFn,
      trace: trace!,
      dataFrame: frame,
      traceToLogsOptions: { customQuery: false, datasourceUid: 'loki-uid' },
      logsDataSourceSettings: logsSettings('loki'),
    });

    const links = createLink!(trace!.spans[0]);
    links![0].onClick?.({ preventDefault() {} });

    expect(clickedQuery(splitOpenFn).expr).toBe('{namespace="prod"}');
  });

  it('escapes a namespace attribute copied from the trace frame into the legacy Loki query', () => {
    const frame = traceFrame([
      { key: 'namespace', value: QUOTE_BREAKOUT },
      { key: 'pod', value: SLASH_AND_QUOTE },
    ]);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const splitOpenFn = jest.fn();
    const createLink = createSpanLinkFactory({
      splitOpenFn,
      trace: trace!,
      dataFrame: frame,
      traceToLogsOptions: { customQuery: false, datasourceUid: 'loki-uid' },
      logsDataSourceSettings: logsSettings('loki'),
    });

    const links = createLink!(trace!.spans[0]);
    expect(links).toHaveLength(1);
    links![0].onClick?.({ preventDefault() {} });

    expect(clickedQuery(splitOpenFn)).toEqual(
      expect.objectContaining({
        expr: `{namespace="${escapeLabelLiteral(QUOTE_BREAKOUT)}", pod="${escapeLabelLiteral(SLASH_AND_QUOTE)}"}`,
        datasource: { type: 'loki', uid: 'loki-uid' },
      })
    );
  });

  it('escapes attribute values in every dynamic Loki selector, including the job regex literal', () => {
    setTestFlags({ [FlagKeys.GrafanaDynamicTraceToLogs]: true });
    const serviceName = 'checkout" or job=~".*';
    const frame = traceFrame([{ key: 'namespace', value: QUOTE_BREAKOUT }], serviceName);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const span = trace!.spans[0];
    span.tags = [...(span.tags ?? []), { key: 'service.name', value: serviceName }];

    const splitOpenFn = jest.fn();
    const createLink = createSpanLinkFactory({
      splitOpenFn,
      trace: trace!,
      dataFrame: frame,
      traceToLogsOptions: { customQuery: false, datasourceUid: 'loki-uid' },
      logsDataSourceSettings: logsSettings('loki'),
    });

    const links = createLink!(span);
    const link = links!.find((item) => item.type === 'log');
    expect(link).toBeDefined();
    const alternatives = link!.linkModel?.interpolatedParams?.alternativeQueries as Array<{ expr: string }>;
    expect(alternatives.length).toBeGreaterThan(1);
    expect(alternatives.some((query) => query.expr.includes('job=~'))).toBe(true);

    const escapedNamespace = escapeLabelLiteral(QUOTE_BREAKOUT);
    const escapedService = escapeLabelLiteral(serviceName);
    const regexService = serviceName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/"/g, '\\"');

    for (const query of alternatives) {
      expect(query.expr).not.toContain(`namespace="${QUOTE_BREAKOUT}"`);
      if (query.expr.includes('namespace=')) {
        expect(query.expr).toContain(`namespace="${escapedNamespace}"`);
      }
      if (query.expr.includes('job=~')) {
        expect(query.expr).toContain(`{job=~"(.*/)?(${regexService})"}`);
        expect(query.expr).not.toContain(`job=~"(.*/)?(${serviceName})"`);
      }
      if (query.expr.includes('service_name=')) {
        expect(query.expr).toContain(`service_name="${escapedService}"`);
      }
    }
  });

  it.each([
    ['elasticsearch', 'query', `namespace:"${escapeLabelLiteral(QUOTE_BREAKOUT)}"`],
    ['grafana-opensearch-datasource', 'query', `namespace:"${escapeLabelLiteral(QUOTE_BREAKOUT)}"`],
    ['grafana-splunk-datasource', 'query', `namespace="${escapeLabelLiteral(QUOTE_BREAKOUT)}"`],
    ['googlecloud-logging-datasource', 'query', `namespace="${escapeLabelLiteral(QUOTE_BREAKOUT)}"`],
    ['grafana-falconlogscale-datasource', 'lsql', `namespace="${escapeLabelLiteral(QUOTE_BREAKOUT)}"`],
    ['victoriametrics-logs-datasource', 'expr', `namespace:="${escapeLabelLiteral(QUOTE_BREAKOUT)}"`],
  ])('escapes the namespace attribute in the %s related-logs query', (type, field, expected) => {
    const frame = traceFrame([{ key: 'namespace', value: QUOTE_BREAKOUT }]);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const splitOpenFn = jest.fn();
    const settings = logsSettings(type);
    const createLink = createSpanLinkFactory({
      splitOpenFn,
      trace: trace!,
      dataFrame: frame,
      traceToLogsOptions: { customQuery: false, datasourceUid: settings.uid },
      logsDataSourceSettings: settings,
    });

    const links = createLink!(trace!.spans[0]);
    links![0].onClick?.({ preventDefault() {} });

    expect(clickedQuery(splitOpenFn)[field]).toBe(expected);
  });

  it('escapes the namespace attribute in the trace-level related logs query', () => {
    const frame = traceFrame([{ key: 'namespace', value: QUOTE_BREAKOUT }]);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const splitOpenFn = jest.fn();
    const link = createTraceLogsLink({
      splitOpenFn,
      trace: trace!,
      dataFrame: frame,
      traceToLogsOptions: { customQuery: false, datasourceUid: 'loki-uid' },
      logsDataSourceSettings: logsSettings('loki'),
    });

    expect(link).toBeDefined();
    link!.onClick?.({ preventDefault() {} });

    expect(clickedQuery(splitOpenFn).expr).toBe(`{namespace="${escapeLabelLiteral(QUOTE_BREAKOUT)}"}`);
  });

  it('escapes the tags variable inside a metrics query', () => {
    const frame = traceFrame([{ key: 'namespace', value: METRIC_OR_BREAKOUT }]);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const splitOpenFn = jest.fn();
    const settings = logsSettings('prometheus', 'prom-uid');
    const createLink = createSpanLinkFactory({
      splitOpenFn,
      trace: trace!,
      dataFrame: frame,
      traceToMetricsOptions: {
        datasourceUid: settings.uid,
        queries: [{ name: 'Span metrics', query: 'metric{${__tags}}' }],
        tags: [{ key: 'namespace' }],
      },
      metricsDataSourceSettings: settings,
    });

    const links = createLink!(trace!.spans[0]);
    const metrics = links!.find((link) => link.type === 'metric');
    expect(metrics).toBeDefined();
    metrics!.onClick?.({ preventDefault() {} });

    expect(clickedQuery(splitOpenFn).expr).toBe(`metric{namespace="${escapeLabelLiteral(METRIC_OR_BREAKOUT)}"}`);
  });

  it('escapes the span service name inside the default metrics selector', () => {
    // Closes the generated selector and rate() call, ORs every service, and comments out the template suffix.
    const serviceName = 'x"}[5m]) or rate(traces_spanmetrics_latency_bucket{service=~".+"}[5m])) by (le)) #';
    const frame = traceFrame([], serviceName);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const splitOpenFn = jest.fn();
    const settings = logsSettings('prometheus', 'prom-uid');
    const createLink = createSpanLinkFactory({
      splitOpenFn,
      trace: trace!,
      dataFrame: frame,
      traceToMetricsOptions: {
        datasourceUid: settings.uid,
        queries: [{ name: 'Default', query: '' }],
      },
      metricsDataSourceSettings: settings,
    });

    const links = createLink!(trace!.spans[0]);
    links![0].onClick?.({ preventDefault() {} });

    expect(clickedQuery(splitOpenFn).expr).toBe(
      `histogram_quantile(0.5, sum(rate(traces_spanmetrics_latency_bucket{service="${escapeLabelLiteral(serviceName)}"}[5m])) by (le))`
    );
  });

  it('escapes profile tag values in the pyroscope label selector', () => {
    const frame = traceFrame([{ key: 'service.namespace', value: QUOTE_BREAKOUT }]);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const profileFrame = createDataFrame({
      fields: [
        { name: 'traceID', values: ['7946b05c2e2e4e5a'] },
        { name: 'spanID', values: ['6605c7b08e715d6c'] },
        {
          name: 'tags',
          type: FieldType.other,
          config: {
            links: [
              {
                internal: {
                  query: {
                    labelSelector: '{${__tags}}',
                    groupBy: [],
                    profileTypeId: '',
                    queryType: 'profile',
                    spanSelector: ['${__span.spanId}'],
                    refId: '',
                  },
                  datasourceUid: 'pyroscope-uid',
                  datasourceName: 'pyroscope',
                },
                url: '',
                title: 'Profiles',
              },
            ],
          },
          values: [[]],
        },
      ],
    });
    const splitOpenFn = jest.fn();
    const createLink = createSpanLinkFactory({
      splitOpenFn,
      trace: trace!,
      dataFrame: profileFrame,
      traceToProfilesOptions: { customQuery: false, datasourceUid: 'pyroscope-uid' },
      profilesDataSourceSettings: logsSettings('grafana-pyroscope-datasource', 'pyroscope-uid'),
    });

    const links = createLink!(trace!.spans[0]);
    const profiles = links!.find((link) => link.href.includes('pyroscope-uid'));
    expect(profiles).toBeDefined();
    const left = new URL(profiles!.href, 'http://localhost').searchParams.get('left');
    const pane = JSON.parse(left!) as { queries: Array<{ labelSelector: string }> };

    expect(pane.queries[0].labelSelector).toBe(`{service_namespace="${escapeLabelLiteral(QUOTE_BREAKOUT)}"}`);
  });

  it('escapes attribute values in the span flame graph label selector sent to the profiles datasource', async () => {
    const settings = {
      uid: 'pyroscope-uid',
      id: 1,
      name: 'pyroscope',
      type: 'grafana-pyroscope-datasource',
      meta: {
        id: 'grafana-pyroscope-datasource',
        name: 'pyroscope',
        type: PluginType.datasource,
        module: '',
        baseUrl: '',
        info: {
          author: { name: 'test' },
          description: '',
          links: [],
          logos: { large: '', small: '' },
          screenshots: [],
          updated: '',
          version: '',
        },
      },
      jsonData: {},
      access: 'proxy',
      readOnly: false,
    } as DataSourceInstanceSettings<DataSourceJsonData>;
    useDataSourceInstanceSettingsMock.mockReturnValue({ isLoading: false, settings });

    const captured: DataQueryRequest[] = [];
    class CapturingProfiles extends DataSourceWithBackend {
      query(request: DataQueryRequest) {
        captured.push(request);
        return of({ data: [] });
      }
    }
    getDataSourceInstanceMock.mockResolvedValue(new CapturingProfiles(settings));

    const frame = traceFrame([{ key: 'service.name', value: QUOTE_BREAKOUT }]);
    const trace = transformDataFrames(frame);
    expect(trace).not.toBeNull();
    const span = trace!.spans[0];

    render(
      <SpanFlameGraph
        span={span}
        traceToProfilesOptions={{ customQuery: false, datasourceUid: settings.uid }}
        timeZone="utc"
        traceFlameGraphs={{}}
        setTraceFlameGraphs={() => {}}
        setRedrawListView={() => {}}
        traceDuration={trace!.duration}
        traceName={trace!.traceName}
      />
    );

    await waitFor(() => expect(captured).toHaveLength(1));
    const target = captured[0].targets[0] as { labelSelector: string };
    expect(target.labelSelector).toBe(`{service_name="${escapeLabelLiteral(QUOTE_BREAKOUT)}"}`);
  });

  it('builds the legacy Loki query from the same escaped tag string the link runs', () => {
    const span = {
      spanID: '6605c7b08e715d6c',
      traceID: '7946b05c2e2e4e5a',
      processID: 'p',
      operationName: 'GET',
      logs: [],
      startTime: 0,
      duration: 1,
      flags: 0,
      tags: [],
      process: {
        serviceName: 'checkout',
        tags: [{ key: 'namespace', value: QUOTE_BREAKOUT }],
      },
    } as unknown as TraceSpan;

    const { tags } = getTraceToLogsSpanQuery(span, logsSettings('loki'), {
      customQuery: false,
      datasourceUid: 'loki-uid',
    });

    expect(tags).toBe(`namespace="${escapeLabelLiteral(QUOTE_BREAKOUT)}"`);
  });
});
