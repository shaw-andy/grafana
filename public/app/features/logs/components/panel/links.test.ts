import { FieldType, getDefaultTimeRange, LogsSortOrder, toDataFrame } from '@grafana/data';
import { setTemplateSrv } from '@grafana/runtime';
import { contextSrv } from 'app/core/services/context_srv';
import { getFieldLinksForExplore } from 'app/features/explore/utils/links';
import { TemplateSrv } from 'app/features/templating/template_srv';
import { type GetFieldLinksFn } from 'app/plugins/panel/logs/types';

import { createLogLine } from '../mocks/logRow';

import { getTempoTraceFromLinks, getTraceIdFromLinkQuery, getTraceIdFromTraceQlQuery } from './links';
import { type LogListModel } from './processing';

describe('getTempoTraceFromLinks', () => {
  let log: LogListModel;

  beforeEach(() => {
    jest.spyOn(contextSrv, 'hasAccessToExplore').mockReturnValue(true);

    const getFieldLinks: GetFieldLinksFn = (field, rowIndex, dataFrame, vars) => {
      return getFieldLinksForExplore({ field, rowIndex, range: getDefaultTimeRange(), dataFrame, vars });
    };

    log = createLogLine(
      {
        dataFrame: toDataFrame({
          refId: 'A',
          fields: [
            { name: 'Time', type: FieldType.time, values: [1] },
            {
              name: 'Line',
              type: FieldType.string,
              values: ['log message 1 traceid=2203801e0171aa8b'],
            },
            {
              name: 'labels',
              type: FieldType.other,
              values: [
                { level: 'warn', logger: 'interceptor' },
                { method: 'POST', status: '200' },
                { kind: 'Event', stage: 'ResponseComplete' },
              ],
            },
            {
              name: 'link',
              type: FieldType.string,
              config: {
                links: [
                  {
                    internal: {
                      datasourceName: 'tempo',
                      datasourceUid: 'test',
                      query: {
                        query: '${__value.raw}',
                        queryType: 'traceql',
                      },
                    },
                    title: '',
                    url: '',
                  },
                ],
              },
              values: ['2203801e0171aa8b'],
            },
          ],
        }),
      },
      {
        escape: false,
        getFieldLinks,
        order: LogsSortOrder.Descending,
        timeZone: 'browser',
        wrapLogMessage: true,
      }
    );
    setTemplateSrv(new TemplateSrv());
  });

  test('Gets the trace information from a link', () => {
    expect(getTempoTraceFromLinks(log.fields)).toEqual({
      dsUID: 'test',
      query: '2203801e0171aa8b',
      queryType: 'traceql',
    });
  });
});

describe('getTraceIdFromTraceQlQuery', () => {
  test.each([
    ['{trace:id = "2203801e0171aa8b"}', '2203801e0171aa8b'],
    ['{ trace:id = "2203801e0171aa8b" }', '2203801e0171aa8b'],
    ['{trace:id="2203801e0171aa8b"}', '2203801e0171aa8b'],
    ['  {trace:id = "46b539f510ab12113b5011db58d5a334"}  ', '46b539f510ab12113b5011db58d5a334'],
    ['{trace:id = `2203801e0171aa8b`}', '2203801e0171aa8b'],
    ['{trace:id = "ABCDEF0123456789"}', 'ABCDEF0123456789'],
  ])('extracts the trace ID from a TraceQL trace-id lookup: %s', (query, expected) => {
    expect(getTraceIdFromTraceQlQuery(query)).toBe(expected);
  });

  test.each([
    ['2203801e0171aa8b'], // a bare trace ID is not a TraceQL query
    ['{ span.foo = "bar" }'], // a different TraceQL query
    ['{trace:id = "not-hex-zz"}'], // non-hex value
    ['{trace:id =~ "2203801e0171aa8b"}'], // regex operator, not an exact lookup
    ['{trace:id = "abc" && span.foo = "bar"}'], // compound query
    ['{trace:id = `2203801e0171aa8b"}'], // mismatched quote characters
    [''],
  ])('returns undefined for non trace-id lookups: %s', (query) => {
    expect(getTraceIdFromTraceQlQuery(query)).toBeUndefined();
  });
});

describe('getTraceIdFromLinkQuery', () => {
  test.each([
    ['2203801e0171aa8b', '2203801e0171aa8b'],
    [' 2203801e0171aa8b\n', '2203801e0171aa8b'],
    ['{ trace:id = "2203801e0171aa8b" }', '2203801e0171aa8b'],
    ['{trace:id = `ABCDEF0123456789`}', 'ABCDEF0123456789'],
  ])('returns the hex trace ID for %s', (query, expected) => {
    expect(getTraceIdFromLinkQuery(query)).toBe(expected);
  });

  test.each([
    ['{ resource.service.name = "payments" }'],
    ['{ trace:id = "abcd1234" } || { resource.service.name = "payments" } || { trace:id = "" }'],
    ['{ trace:id = "abcd1234" }\n|| { resource.service.name = "payments" }'],
    ['abcd1234\n{ resource.service.name = "payments" }'],
    ['abcd1234 || { true }'],
    ['{ true }'],
    ['0x2203801e0171aa8b'],
    [''],
    [undefined],
    [{ query: '2203801e0171aa8b' }],
  ])('returns undefined for queries that are not a trace ID: %s', (query) => {
    expect(getTraceIdFromLinkQuery(query)).toBeUndefined();
  });
});
