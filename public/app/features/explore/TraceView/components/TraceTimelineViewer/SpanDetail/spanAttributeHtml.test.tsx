import { render, screen } from '@testing-library/react';
import { firstValueFrom } from 'rxjs';

import { CoreApp, type DataFrameDTO, type DataQueryRequest, dateTime, type TraceSpanRow } from '@grafana/data';
import { setPluginLinksHook, type TemplateSrv } from '@grafana/runtime';
import { TestDataDataSource } from 'app/plugins/datasource/grafana-testdata-datasource/datasource';
import {
  type TestDataDataQuery,
  TestDataQueryType,
} from 'app/plugins/datasource/grafana-testdata-datasource/dataquery';

import { transformDataFrames } from '../../../utils/transform';
import { type TraceSpan } from '../../types/trace';

import DetailState from './DetailState';
import SpanDetail, { type SpanDetailProps } from './index';

jest.mock('@grafana/runtime/unstable', () => ({
  ...jest.requireActual('@grafana/runtime/unstable'),
  useDataSourceInstanceSettings: jest.fn().mockReturnValue({ isLoading: false, settings: undefined }),
}));

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  useAppPluginInstalled: jest.fn().mockReturnValue({ loading: false, value: false, error: undefined }),
}));

jest.mock('./pluginPromo/attributePluginPromos', () => ({
  ...jest.requireActual('./pluginPromo/attributePluginPromos'),
  useAttributePluginPromoGetter: jest.fn(() => () => undefined),
}));

const LOGOUT_IMAGE = '<img src="/logout" alt="logout-image">';
const ORG_IMAGE = '<img src="/profile/switch-org/2" alt="org-image">';
const RESOURCE_TAGS = 'img, iframe, object, embed, video, audio, source, picture, link, image';

const templateSrv = {
  replace: (target?: string) => target ?? '',
} as TemplateSrv;

function traceFrame(row: TraceSpanRow): DataFrameDTO {
  const fields = Object.entries(row).map(([name, value]) => ({
    name,
    type:
      typeof value === 'number'
        ? ('number' as const)
        : typeof value === 'string'
          ? ('string' as const)
          : ('other' as const),
    values: [value],
  }));
  return { refId: 'A', fields };
}

async function spanFromRawFrame(row: TraceSpanRow): Promise<TraceSpan> {
  const datasource = new TestDataDataSource(
    { name: 'TestData', type: 'grafana-testdata-datasource', uid: 'testdata' } as never,
    templateSrv
  );
  const rawFrameContent = JSON.stringify([traceFrame(row)]);
  const response = await firstValueFrom(
    datasource.query({
      targets: [
        {
          refId: 'A',
          scenarioId: TestDataQueryType.RawFrame,
          rawFrameContent,
        },
      ],
    } as DataQueryRequest<TestDataDataQuery>)
  );
  const trace = transformDataFrames(response.data[0]);
  if (!trace || trace.spans.length !== 1) {
    throw new Error('raw frame did not become one trace span');
  }
  return trace.spans[0];
}

const baseRow: TraceSpanRow = {
  traceID: 'trace-1',
  spanID: 'span-1',
  parentSpanID: '',
  operationName: 'GET /dashboard',
  serviceName: 'dashboard',
  serviceTags: [],
  startTime: 1,
  duration: 2,
};

function renderSpan(span: TraceSpan, detailState = new DetailState()) {
  const added: Element[] = [];
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      record.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) {
          return;
        }
        if (node.matches(RESOURCE_TAGS)) {
          added.push(node);
        }
        node.querySelectorAll(RESOURCE_TAGS).forEach((element) => added.push(element));
      });
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

  const props: SpanDetailProps = {
    color: '#fff',
    detailState,
    logItemToggle: jest.fn(),
    logsToggle: jest.fn(),
    processToggle: jest.fn(),
    span,
    timeZone: 'browser',
    tagsToggle: jest.fn(),
    summaryAttributesToggle: jest.fn(),
    traceStartTime: 0,
    traceDuration: 2,
    traceName: 'trace-1',
    warningsToggle: jest.fn(),
    stackTracesToggle: jest.fn(),
    referenceItemToggle: jest.fn(),
    referencesToggle: jest.fn(),
    createFocusSpanLink: () => ({ href: '', title: '', origin: undefined, target: undefined }),
    datasourceType: 'grafana-testdata-datasource',
    datasourceUid: 'testdata',
    traceFlameGraphs: {},
    setTraceFlameGraphs: jest.fn(),
    setRedrawListView: jest.fn(),
    timeRange: {
      from: dateTime(0),
      to: dateTime(1_000),
      raw: { from: 'now-1h', to: 'now' },
    },
    app: CoreApp.Dashboard,
  };

  const view = render(<SpanDetail {...props} />);
  observer.takeRecords();
  observer.disconnect();
  return { ...view, addedResourceElements: added };
}

function resourceAddress(element: Element): string[] {
  return ['src', 'srcset', 'href', 'poster', 'data']
    .map((name) => element.getAttribute(name))
    .filter((value): value is string => Boolean(value));
}

function isSessionUrl(value: string) {
  return value.includes('/logout') || value.includes('/profile/switch-org/');
}

function expectNoResourceRequest(container: HTMLElement, added: Element[]) {
  const tables = container.querySelectorAll('[data-testid="KeyValueTable"]');
  expect(tables.length).toBeGreaterThan(0);
  tables.forEach((table) => {
    expect(table.querySelector(RESOURCE_TAGS)).toBeNull();
  });
  const requested = [...tables]
    .flatMap((table) => [...table.querySelectorAll('*')].flatMap(resourceAddress))
    .concat(added.flatMap(resourceAddress));
  expect(requested.filter(isSessionUrl)).toEqual([]);
}

describe('trace span attribute HTML', () => {
  beforeEach(() => {
    setPluginLinksHook(() => ({ isLoading: false, links: [] }));
  });

  it('shows a text or code attribute as text when the span detail opens', async () => {
    const span = await spanFromRawFrame({
      ...baseRow,
      tags: [
        { key: 'http.request', value: `marker-logout ${LOGOUT_IMAGE}`, type: 'text' },
        { key: 'note.code', value: `marker-code ${LOGOUT_IMAGE}`, type: 'code' },
        { key: 'custom.only', value: `marker-flat ${LOGOUT_IMAGE}`, type: 'text' },
      ],
      serviceTags: [{ key: 'service.version', value: `marker-org ${ORG_IMAGE}`, type: 'text' }],
    });

    const { container, addedResourceElements } = renderSpan(span);

    expect(container).toHaveTextContent('marker-logout');
    expect(container).toHaveTextContent('marker-code');
    expect(container).toHaveTextContent('marker-flat');
    expect(container).toHaveTextContent('marker-org');
    expect(container).toHaveTextContent('http.request');
    expect(container).toHaveTextContent('service.version');
    expect(screen.getByRole('switch', { name: /Span attributes/ })).toBeChecked();
    expect(screen.getByRole('switch', { name: /Resource attributes/ })).toBeChecked();
    expectNoResourceRequest(container, addedResourceElements);
  });

  it('shows one uncategorized text attribute as text without a category click', async () => {
    const span = await spanFromRawFrame({
      ...baseRow,
      tags: [{ key: 'custom.only', value: `marker-flat ${LOGOUT_IMAGE}`, type: 'text' }],
    });

    const { container, addedResourceElements } = renderSpan(span);

    expect(container).toHaveTextContent('marker-flat');
    expect(container).toHaveTextContent('custom.only');
    expect(screen.queryByTestId('AccordionCategorizedKeyValues--categories')).not.toBeInTheDocument();
    expectNoResourceRequest(container, addedResourceElements);
  });

  it('shows a stack trace string as text when the stack trace section is open', async () => {
    const span = await spanFromRawFrame({
      ...baseRow,
      stackTraces: [`marker-stack ${LOGOUT_IMAGE}`],
    });

    const { container, addedResourceElements } = renderSpan(span, new DetailState().toggleStackTraces());

    expect(screen.getByRole('switch', { name: /Stack trace/ })).toBeChecked();
    expect(container).toHaveTextContent('marker-stack');
    expectNoResourceRequest(container, addedResourceElements);
  });

  it('shows a log field of type text as text when the event is open', async () => {
    const span = await spanFromRawFrame({
      ...baseRow,
      logs: [
        {
          timestamp: 5,
          fields: [{ key: 'message', value: `marker-log ${LOGOUT_IMAGE}`, type: 'text' }],
        },
      ],
    });
    const log = span.logs![0];

    const { container, addedResourceElements } = renderSpan(span, new DetailState().toggleLogs().toggleLogItem(log));

    expect(container).toHaveTextContent('marker-log');
    expect(container).toHaveTextContent('message');
    expectNoResourceRequest(container, addedResourceElements);
  });

  it('shows a summary attribute of type text as text when that section is open', async () => {
    const span = await spanFromRawFrame({
      ...baseRow,
      tags: [
        { key: 'aggregation.is_summary', value: true },
        { key: 'aggregation.note', value: `marker-summary ${ORG_IMAGE}`, type: 'text' },
      ],
    });

    const { container, addedResourceElements } = renderSpan(span, new DetailState().toggleSummaryAttributes());

    expect(screen.getByRole('switch', { name: /Summary attributes/ })).toBeChecked();
    expect(container).toHaveTextContent('marker-summary');
    expect(container).toHaveTextContent('aggregation.note');
    expectNoResourceRequest(container, addedResourceElements);
  });

  it('shows an untyped attribute and a warning as text', async () => {
    const warning = `marker-warning ${LOGOUT_IMAGE}`;
    const span = await spanFromRawFrame({
      ...baseRow,
      tags: [{ key: 'custom.plain', value: `marker-plain ${LOGOUT_IMAGE}` }],
      warnings: [warning],
    });

    const { container, addedResourceElements } = renderSpan(span, new DetailState().toggleWarnings());

    expect(container).toHaveTextContent('marker-plain');
    expect(container).toHaveTextContent(LOGOUT_IMAGE);
    expect(container).toHaveTextContent('marker-warning');
    expectNoResourceRequest(container, addedResourceElements);
  });
});
