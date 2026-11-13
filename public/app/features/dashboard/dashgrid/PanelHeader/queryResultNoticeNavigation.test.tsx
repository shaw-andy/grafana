import { render } from '@testing-library/react';
import { firstValueFrom } from 'rxjs';

import {
  type DataQueryRequest,
  type DataSourceInstanceSettings,
  getDefaultTimeRange,
  preProcessPanelData,
} from '@grafana/data';
import { SceneDataNode, VizPanel } from '@grafana/scenes';
import { PanelModel } from 'app/features/dashboard/state/PanelModel';
import { StandardErrorsAndNoticesInspector } from 'app/features/dashboard-scene/inspect/StandardErrorsAndNoticesInspector';
import { PanelNotices } from 'app/features/dashboard-scene/scene/PanelNotices';
import { buildGridItemForPanel } from 'app/features/dashboard-scene/serialization/transformSaveModelToScene';
import { getQueryRunnerFor } from 'app/features/dashboard-scene/utils/getQueryRunnerFor';
import { runRequest } from 'app/features/query/state/runRequest';
import { TemplateSrv } from 'app/features/templating/template_srv';
import { type TestDataDataQuery, TestDataQueryType } from 'app/plugins/datasource/grafana-testdata-datasource/dataquery';
import { TestDataDataSource } from 'app/plugins/datasource/grafana-testdata-datasource/datasource';

/**
 * Destinations a query-result notice must not be able to send the viewer to.
 * The browser resolves these the same way an anchor click does, including
 * percent-decoding and HTML-entity decoding done before the href is set.
 */
const NOTICE_LINKS = [
  { name: 'logout', link: '/logout' },
  { name: 'logout with a query string', link: '/logout?redirect=%2F' },
  { name: 'percent-encoded logout', link: '/%6Cogout' },
  { name: 'entity-encoded logout', link: '/log&#111;ut' },
  { name: 'organization switch', link: '/profile/switch-org/2' },
  { name: 'organization switch with a trailing slash', link: '/profile/switch-org/2/' },
  { name: 'entity-encoded organization switch', link: '&#47;profile/switch-org/2' },
  { name: 'external site', link: 'https://evil.example/warning' },
  { name: 'protocol-relative site', link: '//evil.example/warning' },
  { name: 'same-origin absolute logout', link: 'http://localhost/logout' },
];

const MARKDOWN_LINKS = [
  { name: 'markdown logout', text: '[query failed](/logout)' },
  { name: 'markdown organization switch', text: '[query failed](/profile/switch-org/2)' },
  { name: 'markdown external site', text: '[query failed](https://evil.example/warning)' },
  { name: 'markdown protocol-relative site', text: '[query failed](//evil.example/warning)' },
  { name: 'markdown entity-encoded logout', text: '[query failed](/log&#111;ut)' },
];

function fieldsFrame(link: string, text = 'query failed') {
  return {
    fields: [{ name: 'Time', type: 'time', values: [1700000000000] }],
    length: 1,
    meta: { notices: [{ severity: 'warning', text, link }] },
  };
}

function fieldsFrameWithoutLength(link: string) {
  return {
    fields: [{ name: 'Time', type: 'time', values: [1700000000000] }],
    meta: { notices: [{ severity: 'warning', text: 'query failed', link }] },
  };
}

function schemaFrame(link: string) {
  return {
    schema: {
      fields: [{ name: 'Time', type: 'time' }],
      meta: { notices: [{ severity: 'warning', text: 'query failed', link }] },
    },
    data: { values: [[1700000000000]] },
  };
}

function storedQuery(rawFrame: unknown): TestDataDataQuery {
  const query: TestDataDataQuery = {
    refId: 'A',
    scenarioId: TestDataQueryType.RawFrame,
    datasource: { type: 'grafana-testdata-datasource', uid: 'testdata' },
    rawFrameContent: JSON.stringify([rawFrame]),
  };
  // Dashboard save/load sends this object as JSON. Keep the value the viewer receives.
  return JSON.parse(JSON.stringify(query)) as TestDataDataQuery;
}

async function panelDataForQuery(query: TestDataDataQuery) {
  const templateSrv = new TemplateSrv({
    getFilteredVariables: () => [],
    getVariables: () => [],
    getVariableWithName: () => undefined,
  });
  const datasource = new TestDataDataSource(
    {
      id: 1,
      uid: 'testdata',
      type: 'grafana-testdata-datasource',
      name: 'TestData',
      jsonData: {},
      access: 'proxy',
      readOnly: true,
    } as DataSourceInstanceSettings,
    templateSrv
  );
  const request = {
    requestId: 'notice-link',
    interval: '1s',
    intervalMs: 1000,
    range: getDefaultTimeRange(),
    scopedVars: {},
    targets: [query],
    timezone: 'utc',
    app: 'dashboard',
    startTime: Date.now(),
  } as DataQueryRequest<TestDataDataQuery>;

  const result = await firstValueFrom(runRequest(datasource, request));
  return preProcessPanelData(result);
}

function headerFromSavedPanel(query: TestDataDataQuery, data: Awaited<ReturnType<typeof panelDataForQuery>>) {
  const model = new PanelModel({
    id: 1,
    type: 'timeseries',
    title: 'Notice',
    gridPos: { x: 0, y: 0, w: 12, h: 8 },
    targets: [query],
  });
  const gridItem = buildGridItemForPanel(model);
  const vizPanel = gridItem.state.body as VizPanel;
  const stored = getQueryRunnerFor(vizPanel)?.state.queries[0] as TestDataDataQuery | undefined;
  if (stored?.rawFrameContent !== query.rawFrameContent) {
    throw new Error('saved panel query did not keep rawFrameContent');
  }

  let notices = vizPanel.state.titleItems?.find((item): item is PanelNotices => item instanceof PanelNotices);
  if (!notices) {
    // Library panels and the v2 layout mount this same title item. Render it even if this
    // builder stopped adding one, so the link sink is what the test specifies.
    notices = new PanelNotices();
    vizPanel.setState({ titleItems: [...(vizPanel.state.titleItems ?? []), notices] });
  }

  vizPanel.setState({ $data: new SceneDataNode({ data, key: 'notice-data' }) });
  return render(<notices.Component model={notices} />);
}

/**
 * Anchors the browser will request. about:blank is the sanitizer dead-end and is not a navigation.
 * The resolved href is what the click loads, so a check that rewrites one string and navigates to another still fails.
 */
function navigableDestinations(container: HTMLElement): string[] {
  const destinations: string[] = [];
  container.querySelectorAll('a, area').forEach((element) => {
    const raw = element.getAttribute('href');
    if (raw == null || raw.trim() === '' || raw.trim() === '#') {
      return;
    }
    const resolved = element instanceof HTMLAnchorElement || element instanceof HTMLAreaElement ? element.href : raw;
    if (!isAboutBlank(resolved)) {
      destinations.push(resolved || raw);
    }
  });
  return destinations;
}

function isAboutBlank(href: string): boolean {
  try {
    const url = new URL(href, window.location.href);
    return url.protocol === 'about:' && url.pathname.replace(/^\/+/, '') === 'blank';
  } catch {
    return false;
  }
}

describe('query-result notice links', () => {
  describe('panel header', () => {
    it.each(NOTICE_LINKS)('does not navigate when a raw frame notice links to $name', async ({ link }) => {
      const query = storedQuery(fieldsFrame(link));
      const data = await panelDataForQuery(query);
      const { container } = headerFromSavedPanel(query, data);

      expect(navigableDestinations(container)).toEqual([]);
    });

    it('does not navigate when the raw frame omits length and the notice links to logout', async () => {
      const query = storedQuery(fieldsFrameWithoutLength('/logout'));
      const data = await panelDataForQuery(query);
      const { container } = headerFromSavedPanel(query, data);

      expect(navigableDestinations(container)).toEqual([]);
    });

    it('does not navigate when the raw frame uses schema and data and the notice links to logout', async () => {
      const query = storedQuery(schemaFrame('/logout'));
      const data = await panelDataForQuery(query);
      const { container } = headerFromSavedPanel(query, data);

      expect(navigableDestinations(container)).toEqual([]);
    });
  });

  describe('errors and notices inspector', () => {
    it.each(NOTICE_LINKS)('does not navigate from Learn more to $name', async ({ link }) => {
      const data = await panelDataForQuery(storedQuery(fieldsFrame(link)));
      const { container } = render(<StandardErrorsAndNoticesInspector data={data.series} />);

      expect(navigableDestinations(container)).toEqual([]);
    });

    it.each(MARKDOWN_LINKS)('does not navigate from notice text to $name', async ({ text }) => {
      const frame = {
        fields: [{ name: 'Time', type: 'time', values: [1700000000000] }],
        length: 1,
        meta: { notices: [{ severity: 'warning', text }] },
      };
      const data = await panelDataForQuery(storedQuery(frame));
      const { container } = render(<StandardErrorsAndNoticesInspector data={data.series} />);

      expect(navigableDestinations(container)).toEqual([]);
    });
  });
});
