import { render, screen } from 'test/test-utils';

import { CoreApp, createDataFrame, FieldType, type Field, type LinkModel, type TimeRange } from '@grafana/data';
import { HistoryWrapper, locationService, usePluginLinks } from '@grafana/runtime';

import { SpanDetailLinkButtons } from './components/TraceTimelineViewer/SpanDetail/SpanDetailLinkButtons';
import { type SpanLinkFunc, SpanLinkType } from './components/types/links';
import { type TraceSpan } from './components/types/trace';
import { createSpanLinkFactory } from './createSpanLink';
import { transformDataFrames } from './utils/transform';

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  usePluginLinks: jest.fn().mockReturnValue({ isLoading: false, links: [] }),
}));

jest.mock('@grafana/runtime/unstable', () => ({
  ...jest.requireActual('@grafana/runtime/unstable'),
  useDataSourceInstanceSettings: jest.fn().mockReturnValue({ isLoading: false, settings: undefined }),
  useDataSourceInstanceList: jest.fn().mockReturnValue({ isLoading: false, items: [] }),
  getDataSourceInstance: jest.fn().mockResolvedValue({ query: jest.fn() }),
}));

// A session link may only address one path segment for the app id and one for the
// session id. Resolving the href the way the browser resolves an anchor or
// history.pushState drops dot segments, so the resolved path is what gets requested.
const CONFINED_SESSION_PATH = /^\/a\/grafana-kowalski-app\/apps\/[^/]+\/sessions\/[^/]+$/;

type SessionKey = 'session_id' | 'session.id';

const escapes: Array<{ name: string; appId: string; sessionKey: SessionKey; sessionId: string }> = [
  {
    name: 'slash segments to switch-org and a dot-segment session id',
    appId: '../../../profile/switch-org/2',
    sessionKey: 'session_id',
    sessionId: '..',
  },
  {
    name: 'slash segments to logout and a dot-segment session id',
    appId: '../../../logout',
    sessionKey: 'session.id',
    sessionId: '..',
  },
  {
    name: 'backslash segments to switch-org',
    appId: '..\\..\\..\\profile\\switch-org\\2',
    sessionKey: 'session_id',
    sessionId: '..',
  },
  {
    name: 'backslash segments to logout',
    appId: '..\\..\\..\\logout',
    sessionKey: 'session.id',
    sessionId: '..',
  },
  {
    name: 'percent-encoded dot segments to switch-org',
    appId: '%2e%2e/%2e%2e/%2e%2e/profile/switch-org/2',
    sessionKey: 'session_id',
    sessionId: '%2e%2e',
  },
  {
    name: 'percent-encoded dot segments to logout',
    appId: '%2e%2e/%2e%2e/%2e%2e/logout',
    sessionKey: 'session.id',
    sessionId: '..',
  },
  {
    name: 'a session id made of dot segments',
    appId: 'app-1',
    sessionKey: 'session_id',
    sessionId: '../../../../logout',
  },
];

function traceWithSessionTags(appId: string, sessionKey: SessionKey, sessionId: string) {
  const frame = createDataFrame({
    fields: [
      { name: 'traceID', values: ['trace1'] },
      { name: 'spanID', values: ['span1'] },
      { name: 'operationName', values: ['documentLoad'] },
      { name: 'serviceName', values: ['frontend'] },
      { name: 'startTime', values: [1_700_000_000_000] },
      { name: 'duration', values: [15] },
      {
        name: 'serviceTags',
        values: [[{ key: 'gf.feo11y.app.id', value: appId }]],
      },
      {
        name: 'tags',
        values: [[{ key: sessionKey, value: sessionId }]],
      },
    ],
    meta: { preferredVisualisationType: 'trace' },
  });
  const trace = transformDataFrames(frame);
  if (!trace) {
    throw new Error('transformDataFrames dropped the trace frame');
  }
  const createLink = createSpanLinkFactory({
    splitOpenFn: jest.fn(),
    trace,
    dataFrame: frame,
  });
  if (!createLink) {
    throw new Error('createSpanLinkFactory returned no link builder');
  }
  const href = createLink(trace.spans[0])?.find((link) => link.type === SpanLinkType.Session)?.href;
  return { trace, createLink, href };
}

function expectConfinedSessionHref(href: string | undefined) {
  if (href === undefined) {
    return;
  }
  const url = new URL(href, 'http://grafana.example');
  expect(url.origin).toBe('http://grafana.example');
  expect(url.pathname).toMatch(CONFINED_SESSION_PATH);
}

const timeRange = { from: new Date(0), to: new Date(1000) } as unknown as TimeRange;
const focusSpanLink = { href: '/focus', title: 'Focus', target: '_self', origin: {} } as unknown as LinkModel;

function renderSessionButtons(span: TraceSpan, createSpanLink: SpanLinkFunc) {
  return render(
    <SpanDetailLinkButtons
      span={span}
      createSpanLink={createSpanLink}
      datasourceType="tempo"
      datasourceUid="tempo-uid"
      traceToProfilesOptions={undefined}
      timeRange={timeRange}
      app={CoreApp.Explore}
      focusSpanLink={focusSpanLink}
    />
  );
}

function signedInLocation(): HistoryWrapper {
  const service = locationService as HistoryWrapper;
  service.setOrgIdGetter(() => 2);
  return service;
}

describe('frontend observability session links', () => {
  beforeEach(() => {
    jest.mocked(usePluginLinks).mockReturnValue({ isLoading: false, links: [] });
  });

  it('keeps an ordinary app id and session id as two path segments', () => {
    const { href } = traceWithSessionTags('appId', 'session_id', 'the-session-id');
    expect(href).toBe('/a/grafana-kowalski-app/apps/appId/sessions/the-session-id');
  });

  it.each(escapes)('does not let $name out of the frontend observability app', ({ appId, sessionKey, sessionId }) => {
    const { href } = traceWithSessionTags(appId, sessionKey, sessionId);
    expectConfinedSessionHref(href);
  });

  it.each(escapes)(
    'puts only a confined address on the Session for this span control for $name',
    async ({ appId, sessionKey, sessionId }) => {
      const { trace, createLink } = traceWithSessionTags(appId, sessionKey, sessionId);
      const { user } = renderSessionButtons(trace.spans[0], createLink);
      const anchor = screen.queryByRole('link', { name: 'Session for this span' });
      if (!anchor) {
        return;
      }
      expectConfinedSessionHref(anchor.getAttribute('href') ?? undefined);
      const service = signedInLocation();
      await user.click(anchor);
      expectConfinedSessionHref(service.getLocation().pathname);
    }
  );

  it('does not let the grouped Links menu navigate to a session tag outside the app', async () => {
    const { trace, createLink } = traceWithSessionTags('../../../logout', 'session_id', '..');
    const field: Field = {
      name: 'spanID',
      type: FieldType.string,
      config: {},
      values: [],
    };
    const grouped: SpanLinkFunc = (span) => {
      const links = createLink(span) ?? [];
      const fillers = [1, 2, 3].map((n) => ({
        href: `/a/grafana-kowalski-app/apps/safe${n}/sessions/safe${n}`,
        title: `Other ${n}`,
        type: SpanLinkType.Unknown,
        content: null,
        field,
      }));
      return [...links, ...fillers];
    };

    const { user } = renderSessionButtons(trace.spans[0], grouped);
    const direct = screen.queryByRole('link', { name: 'Session for this span' });
    if (direct) {
      expectConfinedSessionHref(direct.getAttribute('href') ?? undefined);
      return;
    }

    const menuButton = screen.queryByRole('button', { name: 'Links' });
    if (!menuButton) {
      return;
    }
    await user.click(menuButton);
    const item = screen.queryByRole('menuitem', { name: 'Session for this span' });
    if (!item) {
      return;
    }
    const service = signedInLocation();
    await user.click(item);
    expectConfinedSessionHref(service.getLocation().pathname);
  });
});
