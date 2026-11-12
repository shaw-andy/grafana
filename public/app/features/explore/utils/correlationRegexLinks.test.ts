import {
  type DataFrame,
  type DataLink,
  type DataSourceInstanceSettings,
  dateTime,
  FieldType,
  getLinksSupplier,
  type InterpolateFunction,
  LoadingState,
  LogsSortOrder,
  type PanelData,
  SupportedTransformationType,
  type TimeRange,
  toDataFrame,
} from '@grafana/data';
import { type CorrelationData, setTemplateSrv } from '@grafana/runtime';
import { type DataQuery } from '@grafana/schema';

import { initTemplateSrv } from '../../../../test/helpers/initTemplateSrv';
import { CorrelationsService } from '../../../core/services/CorrelationsService';
import { type ContextSrv, setContextSrv } from '../../../core/services/context_srv';
import { createLogLine } from '../../logs/components/mocks/logRow';
import { setLinkSrv } from '../../panel/panellinks/link_srv';

import { decorateWithCorrelations } from './decorators';
import { getFieldLinksForExplore } from './links';

// A link builder runs on the UI thread. This is the longest it may spend on one stored expression.
const LINK_BUILD_BUDGET_MS = 250;

// Short nested expression. Length limits that still allow this pattern do not remove the hang.
const NESTED_EXPRESSION = '^(a+)+$';
const NESTED_FIELD_VALUE = `${'a'.repeat(30)}!`;

const STATIC_EXPLORE_HREF = `/explore?left=${encodeURIComponent(
  '{"range":{"from":"now-1h","to":"now"},"datasource":"uid_1","queries":[{"query":"http_requests{app=test}","datasource":{"uid":"uid_1"}}]}'
)}`;

describe('stored correlation regexes while building links', () => {
  const range: TimeRange = {
    from: dateTime('2020-10-14T00:00:00'),
    to: dateTime('2020-10-14T01:00:00'),
    raw: { from: 'now-1h', to: 'now' },
  };

  beforeEach(() => {
    setTemplateSrv(initTemplateSrv('key', []));
    setLinkSrv({
      getDataLinkUIModel(link: DataLink) {
        return {
          href: link.url,
          title: link.title,
          target: '_blank',
          origin: undefined,
        };
      },
      getAnchorInfo(link) {
        return { ...link, href: link.url ?? '' };
      },
      getLinkUrl(link) {
        return link.url ?? '';
      },
    });
  });

  function allowExplore(allowed: boolean) {
    setContextSrv({
      hasAccessToExplore: () => allowed,
    } as ContextSrv);
  }

  function internalLink(meta: DataLink['meta']): DataLink {
    return {
      title: '',
      url: '',
      internal: {
        query: { query: 'http_requests{app=test}' },
        datasourceUid: 'uid_1',
        datasourceName: 'test_ds',
      },
      meta,
    };
  }

  function frameWithLink(link: DataLink, value: string, extraFields: DataFrame['fields'] = []): DataFrame {
    return toDataFrame({
      refId: 'A',
      fields: [
        {
          name: 'Time',
          type: FieldType.time,
          values: [1],
        },
        {
          name: 'Line',
          type: FieldType.string,
          values: [value],
          config: { links: [link] },
        },
        ...extraFields,
      ],
    });
  }

  it('builds an Explore link from a safe data link regex', () => {
    allowExplore(true);
    const link = internalLink({
      transformations: [{ type: SupportedTransformationType.Regex, expression: 'app=(?<application>[a-z]+)' }],
    });
    const dataFrame = frameWithLink(
      {
        ...link,
        internal: {
          query: { query: 'http_requests{app=${application}}' },
          datasourceUid: 'uid_1',
          datasourceName: 'test_ds',
        },
      },
      'app=grafana'
    );
    const field = dataFrame.fields[1];

    const links = getFieldLinksForExplore({ field, rowIndex: 0, range, dataFrame });

    expect(links).toHaveLength(1);
    expect(links[0].href).toBe(
      `/explore?left=${encodeURIComponent(
        '{"range":{"from":"now-1h","to":"now"},"datasource":"uid_1","queries":[{"query":"http_requests{app=grafana}","datasource":{"uid":"uid_1"}}]}'
      )}`
    );
  });

  it('keeps a static internal link when the stored regex does not match', () => {
    allowExplore(true);
    const link = internalLink({
      transformations: [{ type: SupportedTransformationType.Regex, expression: '^$' }],
    });
    const dataFrame = frameWithLink(link, NESTED_FIELD_VALUE);
    const field = dataFrame.fields[1];

    const links = getFieldLinksForExplore({ field, rowIndex: 0, range, dataFrame });

    expect(links).toHaveLength(1);
    expect(links[0].href).toBe(STATIC_EXPLORE_HREF);
  });

  it('builds an Explore link from a data link regex without blocking on a nested expression', () => {
    allowExplore(true);
    const link = internalLink({
      transformations: [{ type: SupportedTransformationType.Regex, expression: NESTED_EXPRESSION }],
    });
    const dataFrame = frameWithLink(link, NESTED_FIELD_VALUE);
    const field = dataFrame.fields[1];

    const started = Date.now();
    const links = getFieldLinksForExplore({ field, rowIndex: 0, range, dataFrame });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(LINK_BUILD_BUDGET_MS);
    expect(links).toHaveLength(1);
    expect(links[0].href).toBe(STATIC_EXPLORE_HREF);
  }, 120000);

  it('reads the nested expression from the transformation field rather than the link field', () => {
    allowExplore(true);
    const link = internalLink({
      transformations: [
        {
          type: SupportedTransformationType.Regex,
          expression: NESTED_EXPRESSION,
          field: 'details',
        },
      ],
    });
    const dataFrame = frameWithLink(link, 'ordinary line', [
      {
        name: 'details',
        type: FieldType.string,
        values: [NESTED_FIELD_VALUE],
        config: {},
      },
    ]);
    const field = dataFrame.fields[1];

    const started = Date.now();
    const links = getFieldLinksForExplore({ field, rowIndex: 0, range, dataFrame });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(LINK_BUILD_BUDGET_MS);
    expect(links).toHaveLength(1);
    expect(links[0].href).toBe(STATIC_EXPLORE_HREF);
  }, 120000);

  it('builds links for a correlation saved with a nested regex', () => {
    allowExplore(true);
    const source = {
      uid: 'src-uid',
      name: 'Source',
      type: 'testdata',
      meta: { id: 'testdata' },
    } as DataSourceInstanceSettings;
    const target = { uid: 'uid_1', name: 'test_ds', type: 'loki', meta: { id: 'loki' } } as DataSourceInstanceSettings;
    const correlation = {
      uid: 'corr-1',
      type: 'query',
      label: 'nested',
      description: '',
      provisioned: false,
      orgId: 1,
      source,
      target,
      config: {
        field: 'Line',
        target: { query: 'http_requests{app=test}' },
        transformations: [{ type: SupportedTransformationType.Regex, expression: NESTED_EXPRESSION }],
      },
    } as CorrelationData;
    const dataFrame = toDataFrame({
      refId: 'A',
      fields: [
        { name: 'Time', type: FieldType.time, values: [1] },
        { name: 'Line', type: FieldType.string, values: [NESTED_FIELD_VALUE], config: { links: [] } },
      ],
    });
    const queries: DataQuery[] = [{ refId: 'A', datasource: { type: 'testdata', uid: 'src-uid' } }];
    const decorated = decorateWithCorrelations({
      showCorrelationEditorLinks: false,
      queries,
      correlations: [correlation],
    })({
      series: [dataFrame],
      state: LoadingState.Done,
      timeRange: range,
    } as PanelData);
    const field = decorated.series[0].fields[1];

    const started = Date.now();
    const links = getFieldLinksForExplore({ field, rowIndex: 0, range, dataFrame: decorated.series[0] });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(LINK_BUILD_BUDGET_MS);
    expect(links).toHaveLength(1);
    expect(links[0].href).toBe(STATIC_EXPLORE_HREF);
  }, 120000);

  it('keeps an external correlation link when the stored regex does not match', () => {
    allowExplore(false);
    const source = {
      uid: 'src-uid',
      name: 'Source',
      type: 'testdata',
      meta: { id: 'testdata' },
    } as DataSourceInstanceSettings;
    const correlation = {
      uid: 'corr-ext',
      type: 'external',
      label: 'external nested',
      description: '',
      provisioned: false,
      orgId: 1,
      source,
      config: {
        field: 'Line',
        target: { url: 'https://example.test/static' },
        transformations: [{ type: SupportedTransformationType.Regex, expression: '^$', mapValue: 'path' }],
      },
    } as CorrelationData;
    const dataFrame = toDataFrame({
      refId: 'A',
      fields: [
        { name: 'Time', type: FieldType.time, values: [1] },
        { name: 'Line', type: FieldType.string, values: [NESTED_FIELD_VALUE], config: { links: [] } },
      ],
    });
    const queries: DataQuery[] = [{ refId: 'A', datasource: { type: 'testdata', uid: 'src-uid' } }];
    const decorated = decorateWithCorrelations({
      showCorrelationEditorLinks: false,
      queries,
      correlations: [correlation],
    })({
      series: [dataFrame],
      state: LoadingState.Done,
      timeRange: range,
    } as PanelData);
    const field = decorated.series[0].fields[1];
    const links = getFieldLinksForExplore({ field, rowIndex: 0, range, dataFrame: decorated.series[0] });

    expect(links).toHaveLength(1);
    expect(links[0].href).toBe('https://example.test/static');
  });

  it('builds an external correlation link for a viewer without Explore access', () => {
    allowExplore(false);
    const source = {
      uid: 'src-uid',
      name: 'Source',
      type: 'testdata',
      meta: { id: 'testdata' },
    } as DataSourceInstanceSettings;
    const correlation = {
      uid: 'corr-ext',
      type: 'external',
      label: 'external nested',
      description: '',
      provisioned: false,
      orgId: 1,
      source,
      config: {
        field: 'Line',
        target: { url: 'https://example.test/static' },
        transformations: [{ type: SupportedTransformationType.Regex, expression: NESTED_EXPRESSION, mapValue: 'path' }],
      },
    } as CorrelationData;
    const dataFrame = toDataFrame({
      refId: 'A',
      fields: [
        { name: 'Time', type: FieldType.time, values: [1] },
        { name: 'Line', type: FieldType.string, values: [NESTED_FIELD_VALUE], config: { links: [] } },
      ],
    });
    const queries: DataQuery[] = [{ refId: 'A', datasource: { type: 'testdata', uid: 'src-uid' } }];
    const decorated = decorateWithCorrelations({
      showCorrelationEditorLinks: false,
      queries,
      correlations: [correlation],
    })({
      series: [dataFrame],
      state: LoadingState.Done,
      timeRange: range,
    } as PanelData);
    const field = decorated.series[0].fields[1];

    const started = Date.now();
    const links = getFieldLinksForExplore({ field, rowIndex: 0, range, dataFrame: decorated.series[0] });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(LINK_BUILD_BUDGET_MS);
    expect(links).toHaveLength(1);
    expect(links[0].href).toBe('https://example.test/static');
  }, 120000);

  it('builds panel field links through the correlations post processor', () => {
    allowExplore(true);
    const link = internalLink({
      transformations: [{ type: SupportedTransformationType.Regex, expression: NESTED_EXPRESSION }],
    });
    const dataFrame = frameWithLink(link, NESTED_FIELD_VALUE);
    const field = dataFrame.fields[1];
    const replaceVariables: InterpolateFunction = (value) => value ?? '';
    const postProcessor = new CorrelationsService().correlationsDataLinkPostProcessorFactory(range);
    const getLinks = getLinksSupplier(dataFrame, field, {}, replaceVariables, undefined, postProcessor);

    const started = Date.now();
    const links = getLinks({ valueRowIndex: 0 });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(LINK_BUILD_BUDGET_MS);
    expect(links).toHaveLength(1);
    expect(links[0].href).toBe(STATIC_EXPLORE_HREF);
  }, 120000);

  it('highlights a log line when the stored regex does not match', () => {
    allowExplore(true);
    const link = internalLink({
      transformations: [{ type: SupportedTransformationType.Regex, expression: '^$' }],
    });
    const dataFrame = frameWithLink(link, NESTED_FIELD_VALUE);
    const line = createLogLine(
      {
        rowIndex: 0,
        entry: NESTED_FIELD_VALUE,
        raw: NESTED_FIELD_VALUE,
        dataFrame,
      },
      {
        escape: false,
        order: LogsSortOrder.Descending,
        timeZone: 'browser',
        wrapLogMessage: true,
        getFieldLinks: (field, rowIndex, frame, vars) =>
          getFieldLinksForExplore({ field, rowIndex, range, dataFrame: frame, vars }),
      }
    );

    expect(line.highlightedBodyTokens.length).toBeGreaterThan(0);
  });

  it('highlights a log line whose field link carries a nested regex', () => {
    allowExplore(true);
    const link = internalLink({
      transformations: [{ type: SupportedTransformationType.Regex, expression: NESTED_EXPRESSION }],
    });
    const dataFrame = frameWithLink(link, NESTED_FIELD_VALUE);
    const line = createLogLine(
      {
        rowIndex: 0,
        entry: NESTED_FIELD_VALUE,
        raw: NESTED_FIELD_VALUE,
        dataFrame,
      },
      {
        escape: false,
        order: LogsSortOrder.Descending,
        timeZone: 'browser',
        wrapLogMessage: true,
        getFieldLinks: (field, rowIndex, frame, vars) =>
          getFieldLinksForExplore({ field, rowIndex, range, dataFrame: frame, vars }),
      }
    );

    const started = Date.now();
    const tokens = line.highlightedBodyTokens;
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(LINK_BUILD_BUDGET_MS);
    expect(tokens.length).toBeGreaterThan(0);
  }, 120000);
});
