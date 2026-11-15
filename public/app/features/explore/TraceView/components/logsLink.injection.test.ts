import {
  createDataFrame,
  type DataQuery,
  type DataSourceInstanceSettings,
  type DataSourceJsonData,
} from '@grafana/data';
import { type TraceToLogsOptionsV2 } from '@grafana/o11y-ds-frontend';
import { type DataSourceSrv, setDataSourceSrv, setTemplateSrv } from '@grafana/runtime';
import { FlagKeys } from '@grafana/runtime/internal';
import { setTestFlags } from '@grafana/test-utils/unstable';

import { TemplateSrv } from '../../../templating/template_srv';
import { createSpanLinkFactory } from '../createSpanLink';
import { createTraceLogsLink } from '../createTraceLink';
import { transformDataFrames } from '../utils/transform';

import { type SpanLinkDef } from './types/links';
import { type TraceSpan } from './types/trace';

/**
 * Characters a span author can put in a trace id. The legacy Loki builder places this
 * value in `${__span.traceId}` / `${__trace.traceId}` and Explore interpolates it with
 * the default glob formatter. The other builders paste it inside double quotes directly.
 */
const TRACE_ID = 'a\\b" or trace_id!="';
const SPAN_ID = 'sp\\an" or span_id!="';

/** Quote and backslash escaped once, in that order: `\` then `"`. */
const ESCAPED_TRACE_ID = 'a\\\\b\\" or trace_id!=\\"';
const ESCAPED_SPAN_ID = 'sp\\\\an\\" or span_id!=\\"';

const BENIGN_TRACE_ID = '7946b05c2e2e4e5a';
const BENIGN_SPAN_ID = '6605c7b08e715d6c';

const TAG_SELECTOR = 'cluster="cluster1", hostname="hostname1", service_namespace="namespace1"';

type LogsSettings = DataSourceInstanceSettings<DataSourceJsonData>;

const DATA_SOURCES: Record<string, LogsSettings> = {
  loki: { uid: 'loki', name: 'Loki', type: 'loki' } as LogsSettings,
  splunk: { uid: 'splunk', name: 'Splunk', type: 'grafana-splunk-datasource' } as LogsSettings,
  elasticsearch: { uid: 'es', name: 'Elasticsearch', type: 'elasticsearch' } as LogsSettings,
  opensearch: { uid: 'os', name: 'OpenSearch', type: 'grafana-opensearch-datasource' } as LogsSettings,
  falcon: { uid: 'falcon', name: 'Falcon', type: 'grafana-falconlogscale-datasource' } as LogsSettings,
  google: { uid: 'gcl', name: 'Google Cloud Logging', type: 'googlecloud-logging-datasource' } as LogsSettings,
  victorialogs: { uid: 'vl', name: 'VictoriaLogs', type: 'victoriametrics-logs-datasource' } as LogsSettings,
};

function traceFromFrame(traceID: string, spanID: string, serviceName = 'checkout', hostname = 'hostname1') {
  const frame = createDataFrame({
    fields: [
      { name: 'traceID', values: [traceID] },
      { name: 'spanID', values: [spanID] },
      { name: 'parentSpanID', values: [''] },
      { name: 'operationName', values: ['GET /checkout'] },
      { name: 'serviceName', values: [serviceName] },
      {
        name: 'serviceTags',
        values: [
          [
            { key: 'cluster', value: 'cluster1' },
            { key: 'hostname', value: hostname },
            { key: 'service.namespace', value: 'namespace1' },
          ],
        ],
      },
      { name: 'startTime', values: [1_602_637_200_000] },
      { name: 'duration', values: [1000] },
      { name: 'tags', values: [[]] },
    ],
  });

  const trace = transformDataFrames(frame);
  if (!trace) {
    throw new Error('transformDataFrames returned null');
  }
  return { trace, span: trace.spans[0], frame };
}

function logsOptions(datasourceUid: string): TraceToLogsOptionsV2 {
  return {
    customQuery: false,
    datasourceUid,
    filterByTraceID: true,
    filterBySpanID: true,
  };
}

function openLogsQuery(splitOpenFn: jest.Mock, link: SpanLinkDef): DataQuery {
  link.onClick?.({ preventDefault() {} });
  const options = splitOpenFn.mock.calls.at(-1)?.[0] as { queries?: DataQuery[] } | undefined;
  const query = options?.queries?.[0];
  if (!query) {
    throw new Error('clicking the logs link did not pass a query to Explore');
  }
  return query;
}

function spanLogsLink(
  span: TraceSpan,
  settings: LogsSettings,
  frame: ReturnType<typeof createDataFrame>,
  traceID: string
) {
  const splitOpenFn = jest.fn();
  const createLink = createSpanLinkFactory({
    splitOpenFn,
    traceToLogsOptions: logsOptions(settings.uid),
    trace: { duration: 10, traceID, traceName: 'checkout', spans: [span] } as never,
    dataFrame: frame,
    logsDataSourceSettings: settings,
  });
  const link = createLink?.(span)?.find((item) => item.type === 'log');
  if (!link) {
    throw new Error(`no related-logs link for ${settings.type}`);
  }
  return { splitOpenFn, link };
}

describe('trace-to-logs id quoting', () => {
  beforeAll(() => {
    setDataSourceSrv({
      getInstanceSettings(uid: string) {
        return Object.values(DATA_SOURCES).find((settings) => settings.uid === uid);
      },
    } as unknown as DataSourceSrv);
    setTemplateSrv(new TemplateSrv());
  });

  beforeEach(() => {
    setTestFlags({});
  });

  afterEach(() => {
    setTestFlags({});
  });

  describe('legacy Loki query opened from a span', () => {
    it('keeps a quote and a backslash inside the trace id and span id literals', () => {
      setTestFlags({ [FlagKeys.GrafanaDynamicTraceToLogs]: false });
      const { span, frame } = traceFromFrame(TRACE_ID, SPAN_ID);

      // The dataframe trace id reaches the span unchanged, including the quote.
      expect(span.traceID).toBe(TRACE_ID);
      expect(span.spanID).toBe(SPAN_ID);

      const { splitOpenFn, link } = spanLogsLink(span, DATA_SOURCES.loki, frame, TRACE_ID);
      const query = openLogsQuery(splitOpenFn, link);

      expect(query).toMatchObject({
        expr:
          `{${TAG_SELECTOR}}` +
          ' | label_format log_line_contains_trace_id=`{{ contains "' +
          ESCAPED_TRACE_ID +
          '" __line__  }}` | log_line_contains_trace_id="true" or trace_id="' +
          ESCAPED_TRACE_ID +
          '" | label_format log_line_contains_span_id=`{{ contains "' +
          ESCAPED_SPAN_ID +
          '" __line__  }}` | log_line_contains_span_id="true" or span_id="' +
          ESCAPED_SPAN_ID +
          '"',
      });
      expect(String(query.expr)).not.toContain('or trace_id!=""');
      expect(String(query.expr)).not.toContain('or span_id!=""');
    });

    it('keeps the reported trace id payload inside one quoted matcher', () => {
      setTestFlags({ [FlagKeys.GrafanaDynamicTraceToLogs]: false });
      const traceId = 'abc" or trace_id!="';
      const { span, frame } = traceFromFrame(traceId, BENIGN_SPAN_ID);
      const { splitOpenFn, link } = spanLogsLink(span, DATA_SOURCES.loki, frame, traceId);
      const query = openLogsQuery(splitOpenFn, link);

      expect(query.expr).toContain('or trace_id="abc\\" or trace_id!=\\""');
      expect(query.expr).not.toContain('or trace_id!=""');
    });
  });

  describe('legacy Loki query opened from the whole trace', () => {
    it('interpolates __trace.traceId with quotes and backslashes escaped', () => {
      setTestFlags({ [FlagKeys.GrafanaDynamicTraceToLogs]: false });
      const { trace, frame } = traceFromFrame(TRACE_ID, SPAN_ID);
      const splitOpenFn = jest.fn();
      const link = createTraceLogsLink({
        splitOpenFn,
        trace,
        traceToLogsOptions: logsOptions(DATA_SOURCES.loki.uid),
        logsDataSourceSettings: DATA_SOURCES.loki,
        dataFrame: frame,
      });

      expect(link?.onClick).toEqual(expect.any(Function));
      link!.onClick?.({ preventDefault() {} });
      const query = (splitOpenFn.mock.calls.at(-1)?.[0] as { queries: DataQuery[] }).queries[0];

      expect(query.expr).toBe(
        `{${TAG_SELECTOR}}` +
          ' | label_format log_line_contains_trace_id=`{{ contains "' +
          ESCAPED_TRACE_ID +
          '" __line__  }}` | log_line_contains_trace_id="true" or trace_id="' +
          ESCAPED_TRACE_ID +
          '"'
      );
      expect(String(query.expr)).not.toContain('or trace_id!=""');
    });
  });

  describe('dynamic Loki queries', () => {
    it('escapes ids in every field-name variant, the job selector, and the line filter', () => {
      setTestFlags({ [FlagKeys.GrafanaDynamicTraceToLogs]: true });
      const { span, frame } = traceFromFrame(TRACE_ID, SPAN_ID);
      const { splitOpenFn, link } = spanLogsLink(span, DATA_SOURCES.loki, frame, TRACE_ID);
      const opened = openLogsQuery(splitOpenFn, link);
      const alternatives = link.linkModel?.interpolatedParams?.alternativeQueries as DataQuery[] | undefined;

      expect(alternatives?.map((query) => query.expr)).toEqual([
        `{${TAG_SELECTOR}} | logfmt | json | drop __error__ | trace_id="${ESCAPED_TRACE_ID}" | span_id="${ESCAPED_SPAN_ID}"`,
        `{job=~"(.*/)?(checkout)"} | logfmt | json | drop __error__ | trace_id="${ESCAPED_TRACE_ID}" | span_id="${ESCAPED_SPAN_ID}"`,
        `{${TAG_SELECTOR}} | logfmt | json | drop __error__ | traceID="${ESCAPED_TRACE_ID}" | spanID="${ESCAPED_SPAN_ID}"`,
        `{job=~"(.*/)?(checkout)"} | logfmt | json | drop __error__ | traceID="${ESCAPED_TRACE_ID}" | spanID="${ESCAPED_SPAN_ID}"`,
        `{${TAG_SELECTOR}} | logfmt | json | drop __error__ | traceId="${ESCAPED_TRACE_ID}" | spanId="${ESCAPED_SPAN_ID}"`,
        `{job=~"(.*/)?(checkout)"} | logfmt | json | drop __error__ | traceId="${ESCAPED_TRACE_ID}" | spanId="${ESCAPED_SPAN_ID}"`,
        `{${TAG_SELECTOR}} | logfmt | json | drop __error__ | TraceID="${ESCAPED_TRACE_ID}" | SpanID="${ESCAPED_SPAN_ID}"`,
        `{job=~"(.*/)?(checkout)"} | logfmt | json | drop __error__ | TraceID="${ESCAPED_TRACE_ID}" | SpanID="${ESCAPED_SPAN_ID}"`,
        `{${TAG_SELECTOR}} | logfmt | json | drop __error__ | TraceId="${ESCAPED_TRACE_ID}" | SpanId="${ESCAPED_SPAN_ID}"`,
        `{job=~"(.*/)?(checkout)"} | logfmt | json | drop __error__ | TraceId="${ESCAPED_TRACE_ID}" | SpanId="${ESCAPED_SPAN_ID}"`,
        `{${TAG_SELECTOR}} | logfmt | json | drop __error__ | otel_trace_id="${ESCAPED_TRACE_ID}" | otel_span_id="${ESCAPED_SPAN_ID}"`,
        `{job=~"(.*/)?(checkout)"} | logfmt | json | drop __error__ | otel_trace_id="${ESCAPED_TRACE_ID}" | otel_span_id="${ESCAPED_SPAN_ID}"`,
        `{${TAG_SELECTOR}} |= "${ESCAPED_TRACE_ID}" |= "${ESCAPED_SPAN_ID}"`,
      ]);
      expect(opened.expr).toBe(alternatives?.[0].expr);
      for (const query of alternatives ?? []) {
        expect(String(query.expr)).not.toContain('or trace_id!=""');
        expect(String(query.expr)).not.toContain('|= ""');
      }
    });

    it('escapes a quote in the service name before it is placed in the job selector', () => {
      setTestFlags({ [FlagKeys.GrafanaDynamicTraceToLogs]: true });
      const { span, frame } = traceFromFrame(BENIGN_TRACE_ID, BENIGN_SPAN_ID, 'pay"ments');
      const { link } = spanLogsLink(span, DATA_SOURCES.loki, frame, BENIGN_TRACE_ID);
      const alternatives = link.linkModel?.interpolatedParams?.alternativeQueries as Array<{
        expr: string;
        refId: string;
      }>;
      const jobQuery = alternatives.find((query) => query.refId === 't2l:job:trace_id');

      expect(jobQuery?.expr).toBe(
        '{job=~"(.*/)?(pay\\"ments)"} | logfmt | json | drop __error__ | trace_id="7946b05c2e2e4e5a" | span_id="6605c7b08e715d6c"'
      );
    });

    it('escapes a quote and a backslash in a mapped span tag', () => {
      setTestFlags({ [FlagKeys.GrafanaDynamicTraceToLogs]: true });
      const { span, frame } = traceFromFrame(BENIGN_TRACE_ID, BENIGN_SPAN_ID, 'checkout', 'h\\ost"name');
      const { splitOpenFn, link } = spanLogsLink(span, DATA_SOURCES.loki, frame, BENIGN_TRACE_ID);
      const query = openLogsQuery(splitOpenFn, link);

      expect(query.expr).toBe(
        '{cluster="cluster1", hostname="h\\\\ost\\"name", service_namespace="namespace1"} | logfmt | json | drop __error__ | trace_id="7946b05c2e2e4e5a" | span_id="6605c7b08e715d6c"'
      );
    });
  });

  describe.each([
    [
      'elasticsearch',
      'query',
      '"sp\\\\an\\" or span_id!=\\"" AND "a\\\\b\\" or trace_id!=\\"" AND cluster:"cluster1" AND hostname:"hostname1" AND service_namespace:"namespace1"',
    ],
    [
      'opensearch',
      'query',
      '"sp\\\\an\\" or span_id!=\\"" AND "a\\\\b\\" or trace_id!=\\"" AND cluster:"cluster1" AND hostname:"hostname1" AND service_namespace:"namespace1"',
    ],
    [
      'splunk',
      'query',
      'cluster="cluster1" hostname="hostname1" service_namespace="namespace1" "a\\\\b\\" or trace_id!=\\"" "sp\\\\an\\" or span_id!=\\""',
    ],
    [
      'google',
      'query',
      '"sp\\\\an\\" or span_id!=\\"" AND "a\\\\b\\" or trace_id!=\\"" AND cluster="cluster1" AND hostname="hostname1" AND service_namespace="namespace1"',
    ],
    [
      'falcon',
      'lsql',
      'cluster="cluster1" OR hostname="hostname1" OR service_namespace="namespace1" or "a\\\\b\\" or trace_id!=\\"" or "sp\\\\an\\" or span_id!=\\""',
    ],
    [
      'victorialogs',
      'expr',
      'span_id:="sp\\\\an\\" or span_id!=\\"" AND trace_id:="a\\\\b\\" or trace_id!=\\"" AND cluster:="cluster1" AND hostname:="hostname1" AND service_namespace:="namespace1"',
    ],
  ] as const)('%s', (key, field, expected) => {
    it('escapes trace and span ids in the query Explore runs', () => {
      setTestFlags({ [FlagKeys.GrafanaDynamicTraceToLogs]: false });
      const settings = DATA_SOURCES[key];
      const { span, frame } = traceFromFrame(TRACE_ID, SPAN_ID);
      const { splitOpenFn, link } = spanLogsLink(span, settings, frame, TRACE_ID);
      const query = openLogsQuery(splitOpenFn, link);

      expect(query[field]).toBe(expected);
      expect(String(query[field])).not.toContain('or trace_id!=""');
      expect(String(query[field])).not.toContain('or span_id!=""');
    });
  });
});
