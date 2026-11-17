import { firstValueFrom } from 'rxjs';
import { fromFetch } from 'rxjs/fetch';
import { filter } from 'rxjs/operators';

import {
  applyFieldOverrides,
  createTheme,
  type DataFrame,
  type DataQueryRequest,
  DataTopic,
  EventBusSrv,
  FieldConfigOptionsRegistry,
  type DataSourceInstanceSettings,
  FieldType,
  getDefaultTimeRange,
  LoadingState,
} from '@grafana/data';
import { maybeSortFrame } from '@grafana/data/internal';
import { config, setBackendSrv, type TemplateSrv } from '@grafana/runtime';
import { FlagKeys, getFeatureFlagClient } from '@grafana/runtime/internal';
import { type PanelContext } from '@grafana/ui';
import { BackendSrv, type BackendSrvDependencies } from 'app/core/services/backend_srv';
import { type ContextSrv } from 'app/core/services/context_srv';
import { runRequest } from 'app/features/query/state/runRequest';
import { TestDataQueryType } from 'app/plugins/datasource/grafana-testdata-datasource/dataquery';
import { TestDataDataSource } from 'app/plugins/datasource/grafana-testdata-datasource/datasource';
import { getAnnotationTooltip } from 'app/plugins/panel/timeseries/plugins/annotations/getAnnotationTooltip';
import { type AnnotationVals } from 'app/plugins/panel/timeseries/plugins/annotations/types';
import { getXAnnotationFrames } from 'app/plugins/panel/timeseries/plugins/utils';

import { setDashboardPanelContext } from '../dashboard-scene/scene/setDashboardPanelContext';
import { transformSaveModelToScene } from '../dashboard-scene/serialization/transformSaveModelToScene';
import { findVizPanelByKey } from '../dashboard-scene/utils/findVizPanel';

import { annotationServer } from './api';
import { isAnnotationApiAvailable } from './isAnnotationApiAvailable';

jest.mock('./isAnnotationApiAvailable');
jest.mock('@grafana/runtime/internal', () => ({
  ...jest.requireActual('@grafana/runtime/internal'),
  getFeatureFlagClient: jest.fn(),
}));

const mockIsAnnotationApiAvailable = jest.mocked(isAnnotationApiAvailable);
const mockGetFeatureFlagClient = jest.mocked(getFeatureFlagClient);
const getBooleanValueFn = jest.fn();

function annotationColumns(frame: DataFrame): AnnotationVals {
  const vals: Record<string, unknown> = {};
  for (const field of frame.fields) {
    vals[field.name] = field.values;
  }
  return vals as unknown as AnnotationVals;
}

function columnValue(frame: DataFrame, name: string): unknown {
  const field = frame.fields.find((item) => item.name === name);
  const values = field?.values as unknown as { [index: number]: unknown; get?: (index: number) => unknown };
  return values?.[0] ?? values?.get?.(0);
}

interface CapturedRequest {
  input: string;
  init: RequestInit;
}

function resolvedPathname(input: string): string {
  return new URL(input, document.baseURI).pathname;
}

function assertRequestStaysOnOneAnnotation(call: CapturedRequest) {
  const pathname = resolvedPathname(call.input);
  const parts = pathname.split('/').filter((part) => part.length > 0);
  const annotationsAt = parts.lastIndexOf('annotations');
  expect(call.init.credentials).toBe('same-origin');
  expect(pathname).toMatch(/\/annotations\/[^/]+$/);
  expect(annotationsAt).toBeGreaterThan(-1);
  expect(parts).toHaveLength(annotationsAt + 2);
}

function setBaseHref(href: string) {
  let base = document.querySelector('base');
  if (!base) {
    base = document.createElement('base');
    document.head.appendChild(base);
  }
  base.setAttribute('href', href);
}

function rawFrame(id: string): string {
  return JSON.stringify([
    {
      meta: { dataTopic: DataTopic.Annotations },
      fields: [
        { name: 'time', type: FieldType.time, values: [1700000000000] },
        { name: 'id', type: FieldType.string, values: [id] },
        { name: 'dashboardUID', type: FieldType.string, values: ['dash-1'] },
        { name: 'text', type: FieldType.string, values: ['marker'] },
      ],
    },
  ]);
}

const templateSrv = {
  replace: (target?: string) => target ?? '',
} as unknown as TemplateSrv;

describe('annotation delete and update keep the request on one annotation', () => {
  const calls: CapturedRequest[] = [];
  let context: PanelContext;

  beforeAll(() => {
    mockGetFeatureFlagClient.mockReturnValue({
      getBooleanValue: getBooleanValueFn,
    } as unknown as ReturnType<typeof getFeatureFlagClient>);

    const fetchMock = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input: String(input), init: init ?? {} });
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const backendSrv = new BackendSrv({
      fromFetch,
      appEvents: { emit: jest.fn(), publish: jest.fn() },
      contextSrv: { user: { isSignedIn: true, orgId: 1 } } as unknown as ContextSrv,
      logout: jest.fn(),
    } as unknown as BackendSrvDependencies);
    // BackendSrv takes fromFetch through its dependency object. The global fetch is what rxjs fromFetch calls.
    global.fetch = fetchMock as typeof fetch;
    setBackendSrv(backendSrv);
  });

  beforeEach(() => {
    calls.length = 0;
    setBaseHref('/');
    config.namespace = 'stack-1';
    getBooleanValueFn.mockImplementation((key: string, defaultValue: boolean) =>
      key === FlagKeys.GrafanaKubernetesAnnotationsClient ? false : defaultValue
    );
    mockIsAnnotationApiAvailable.mockResolvedValue(false);
    context = buildDeleteContext();
  });

  async function annotationFrameFromTestData(id: string): Promise<DataFrame> {
    const ds = new TestDataDataSource(
      {
        id: 1,
        uid: 'testdata',
        type: 'grafana-testdata-datasource',
        name: 'TestData',
        jsonData: {},
        meta: { id: 'grafana-testdata-datasource' },
      } as DataSourceInstanceSettings,
      templateSrv
    );
    const request = {
      range: getDefaultTimeRange(),
      targets: [
        {
          refId: 'A',
          scenarioId: TestDataQueryType.RawFrame,
          rawFrameContent: rawFrame(id),
        },
      ],
    } as DataQueryRequest;
    const panelData = await firstValueFrom(
      runRequest(ds, request).pipe(
        filter((data) => data.state === LoadingState.Done || data.state === LoadingState.Error)
      )
    );
    expect(panelData.state).toBe(LoadingState.Done);
    const overridden = applyFieldOverrides({
      data: panelData.annotations ?? [],
      fieldConfig: { defaults: {}, overrides: [] },
      replaceVariables: (value) => value,
      theme: createTheme(),
      fieldConfigRegistry: new FieldConfigOptionsRegistry(),
    });
    const [frame] = getXAnnotationFrames(overridden.map((item) => maybeSortFrame(item, 0)));
    expect(frame).toBeDefined();
    return frame;
  }

  async function issuedDuring(fn: () => Promise<unknown>): Promise<CapturedRequest[]> {
    const start = calls.length;
    try {
      await fn();
    } catch {
      // A refusal before any request is a valid fix. A request already recorded still counts.
    }
    return calls.slice(start);
  }

  it('sends a decimal id to the legacy annotation resource with the viewer credentials', async () => {
    const frame = await annotationFrameFromTestData('42');
    expect(columnValue(frame, 'id')).toBe('42');
    const issued = await issuedDuring(() => context.onAnnotationDelete!('42'));
    expect(issued).toHaveLength(1);
    expect(issued[0].init.method).toBe('DELETE');
    expect(resolvedPathname(issued[0].input)).toBe('/api/annotations/42');
    expect(issued[0].init.credentials).toBe('same-origin');
  });

  it.each([
    ['parent segments to the admin user route', '../../api/admin/users/2', '/api/admin/users/2'],
    ['percent-encoded dots', '%2e%2e/%2e%2e/api/admin/users/2', '/api/admin/users/2'],
    [
      'parent segments to another dashboard',
      '../../api/dashboards/uid/other-dashboard',
      '/api/dashboards/uid/other-dashboard',
    ],
    ['a parent segment on its own', '..', '/api/'],
  ])(
    'does not let a TestData annotation id (%s) choose the delete or update route',
    async (_label, id, escapedPath) => {
      const frame = await annotationFrameFromTestData(id);
      expect(columnValue(frame, 'id')).toBe(id);
      expect(columnValue(frame, 'dashboardUID')).toBe('dash-1');

      const deleted = await issuedDuring(() => context.onAnnotationDelete!(id));
      const updated = await issuedDuring(() =>
        context.onAnnotationUpdate!({ id, from: 100, to: 100, description: 'marker', tags: [] })
      );
      const issued = [...deleted, ...updated];
      expect(issued.every((call) => call.init.credentials === 'same-origin')).toBe(true);
      expect(issued.map((call) => resolvedPathname(call.input))).not.toContain(escapedPath);
      for (const call of [...deleted, ...updated]) {
        assertRequestStaysOnOneAnnotation(call);
      }
    }
  );

  it.each([
    ['parent segments to the admin user route', '../../api/admin/users/2'],
    ['percent-encoded dots', '%2e%2e/%2e%2e/api/admin/users/2'],
  ])('does not offer edit or delete for an annotation id with %s', async (_label, id) => {
    const frame = await annotationFrameFromTestData(id);
    const tooltip = getAnnotationTooltip(
      annotationColumns(frame),
      0,
      'utc',
      context.canEditAnnotations!,
      context.canDeleteAnnotations!,
      context.onAnnotationDelete as (annotationId: number) => void
    );
    expect(context.canDeleteAnnotations!('dash-1')).toBe(true);
    expect(tooltip.canEdit).toBe(false);
    expect(tooltip.canDelete).toBe(false);
    expect(tooltip.onDelete).toBeUndefined();
  });

  it('resolves a relative annotation id against the page base href', async () => {
    setBaseHref('/grafana/');
    const id = '../../api/admin/users/2';
    const frame = await annotationFrameFromTestData(id);
    expect(columnValue(frame, 'id')).toBe(id);
    const deleted = await issuedDuring(() => context.onAnnotationDelete!(id));
    for (const call of deleted) {
      expect(resolvedPathname(call.input)).not.toBe('/grafana/api/admin/users/2');
      assertRequestStaysOnOneAnnotation(call);
    }
  });

  it('does not let the kubernetes annotation client put the id outside the annotation resource', async () => {
    getBooleanValueFn.mockImplementation((key: string, defaultValue: boolean) =>
      key === FlagKeys.GrafanaKubernetesAnnotationsClient ? true : defaultValue
    );
    mockIsAnnotationApiAvailable.mockResolvedValue(true);
    const id = '../../../../../../api/admin/users/2';
    const frame = await annotationFrameFromTestData(id);
    expect(columnValue(frame, 'id')).toBe(id);

    const deleted = await issuedDuring(() => context.onAnnotationDelete!(id));
    const updated = await issuedDuring(() =>
      context.onAnnotationUpdate!({ id, from: 100, to: 100, description: 'marker', tags: [] })
    );
    for (const call of [...deleted, ...updated]) {
      expect(resolvedPathname(call.input)).not.toBe('/api/admin/users/2');
      assertRequestStaysOnOneAnnotation(call);
    }
  });

  it('sends a decimal id to the kubernetes annotation resource', async () => {
    getBooleanValueFn.mockImplementation((key: string, defaultValue: boolean) =>
      key === FlagKeys.GrafanaKubernetesAnnotationsClient ? true : defaultValue
    );
    mockIsAnnotationApiAvailable.mockResolvedValue(true);
    const safe = await issuedDuring(() => annotationServer().delete({ id: '42' }));
    expect(safe).toHaveLength(1);
    expect(safe[0].init.method).toBe('DELETE');
    expect(safe[0].init.credentials).toBe('same-origin');
    expect(resolvedPathname(safe[0].input)).toBe(
      '/apis/annotation.grafana.app/v0alpha1/namespaces/stack-1/annotations/a-42'
    );
  });
});

function buildDeleteContext(): PanelContext {
  const scene = transformSaveModelToScene({
    dashboard: {
      title: 'hello',
      uid: 'dash-1',
      schemaVersion: 38,
      annotations: {
        list: [
          {
            builtIn: 1,
            datasource: { type: 'grafana', uid: '-- Grafana --' },
            enable: false,
            hide: true,
            iconColor: 'rgba(0, 211, 255, 1)',
            name: 'Annotations & Alerts',
            target: { refId: 'A' },
            type: 'dashboard',
          },
        ],
      },
      panels: [{ type: 'timeseries', id: 4, targets: [] }],
    },
    meta: {
      annotationsPermissions: {
        dashboard: { canAdd: true, canEdit: true, canDelete: true },
      },
    },
  });
  const vizPanel = findVizPanelByKey(scene, 'panel-4')!;
  const panelContext: PanelContext = { eventBus: new EventBusSrv(), eventsScope: 'global' };
  setDashboardPanelContext(vizPanel, panelContext);
  return panelContext;
}
