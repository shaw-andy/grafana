import { render, screen } from '@testing-library/react';

import { dateTime, EventBusSrv, LoadingState, type InterpolateFunction, type ScopedVars } from '@grafana/data';
import config from 'app/core/config';
import { getTemplateSrv } from 'app/features/templating/template_srv';

import { TextMode } from './panelcfg.gen';
import { type Props, TextPanel } from './v1/TextPanel';
import { renderContent } from './v2/renderContent';
import { TextNGHtmlView } from './v2/TextNGHtmlView';

/**
 * Variable values are substituted before sanitization. The default html format
 * escapes a whole tag, but a raw/text format and a value placed in a media URL
 * do not. The rendered panel must not contain a subresource whose URL is a
 * same-origin logout, organization-switch, or token-rotation route.
 */

const PAGE = 'http://localhost/';
const BLOCKED_PATH = /^\/(?:logout|profile\/switch-org\/[0-9]+|user\/auth-tokens\/rotate)$/;

function decodedPathname(pathname: string): string {
  try {
    return decodeURIComponent(pathname);
  } catch {
    return pathname;
  }
}

function sessionSubresourcePaths(html: string): string[] {
  const found: string[] = [];
  const doc = new DOMParser().parseFromString(`<div id="root">${html}</div>`, 'text/html');
  const consider = (raw: string | null) => {
    if (!raw) {
      return;
    }
    let url: URL;
    try {
      url = new URL(raw, PAGE);
    } catch {
      return;
    }
    if (url.origin !== new URL(PAGE).origin) {
      return;
    }
    const path = decodedPathname(url.pathname);
    if (BLOCKED_PATH.test(path)) {
      found.push(path);
    }
  };
  doc.querySelectorAll('*').forEach((el) => {
    if (el.hasAttribute('src')) {
      consider(el.getAttribute('src'));
    }
    if (el.hasAttribute('poster')) {
      consider(el.getAttribute('poster'));
    }
  });
  return found;
}

function setMediaVariable(value: string) {
  getTemplateSrv().setGlobalVariable('media', { value, text: value });
}

const replaceVariables: InterpolateFunction = (value: string, scopedVars?: ScopedVars, format?: string | Function) =>
  getTemplateSrv().replace(value ?? '', scopedVars, format);

function panelProps(content: string, mode: TextMode): Props {
  return {
    id: 1,
    data: {
      state: LoadingState.Done,
      series: [{ fields: [], length: 0 }],
      timeRange: {
        from: dateTime('2022-01-01T15:55:00Z'),
        to: dateTime('2022-07-12T15:55:00Z'),
        raw: { from: 'now-15m', to: 'now' },
      },
    },
    timeRange: {
      from: dateTime('2022-07-11T15:55:00Z'),
      to: dateTime('2022-07-12T15:55:00Z'),
      raw: { from: 'now-15m', to: 'now' },
    },
    timeZone: 'utc',
    transparent: false,
    width: 400,
    height: 200,
    fieldConfig: { defaults: {}, overrides: [] },
    renderCounter: 1,
    title: 'Text',
    eventBus: new EventBusSrv(),
    options: { content, mode },
    onOptionsChange: jest.fn(),
    onFieldConfigChange: jest.fn(),
    replaceVariables,
    onChangeTimeRange: jest.fn(),
  };
}

function renderedPaths(): string[] {
  return sessionSubresourcePaths(screen.getByTestId('TextPanel-converted-content').innerHTML);
}

describe('text panel rendering keeps session routes out of media requests', () => {
  beforeEach(() => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    config.disableSanitizeHtml = false;
    setMediaVariable('');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each([
    [TextMode.HTML, '<img src="/logout">'],
    [TextMode.HTML, '<audio src="/profile/switch-org/2"></audio>'],
    [TextMode.HTML, '<video poster="/user/auth-tokens/rotate"></video>'],
    [TextMode.Markdown, '![x](/logout)'],
    [TextMode.Markdown, '<video src="/profile/switch-org/2"></video>'],
  ])('v1 %s panel does not emit a session request for %s', (mode, content) => {
    render(<TextPanel {...panelProps(content, mode)} />);
    expect(renderedPaths()).toEqual([]);
  });

  it.each([
    [TextMode.HTML, '<img src="${media}">'],
    [TextMode.Markdown, '![x](${media})'],
    [TextMode.HTML, '<video poster="${media}"></video>'],
  ])('v1 substitutes a variable into a media URL and still blocks %s %s', (mode, content) => {
    setMediaVariable('/logout');
    render(<TextPanel {...panelProps(content, mode)} />);
    expect(renderedPaths()).toEqual([]);
  });

  it.each([
    [TextMode.HTML, '${media:raw}'],
    [TextMode.Markdown, '${media:raw}'],
    [TextMode.HTML, '${media:text}'],
    [TextMode.Markdown, '[[media:raw]]'],
  ])('v1 does not let an unescaped variable format become a session request (%s %s)', (mode, content) => {
    setMediaVariable('<img src="/profile/switch-org/2">');
    render(<TextPanel {...panelProps(content, mode)} />);
    expect(renderedPaths()).toEqual([]);
  });

  it('v1 html format escapes a whole tag stored in a variable', () => {
    setMediaVariable('<img src="/logout">');
    render(<TextPanel {...panelProps('${media}', TextMode.HTML)} />);
    expect(renderedPaths()).toEqual([]);
  });

  it.each([
    [TextMode.HTML, '<img src="/logout">'],
    [TextMode.HTML, '<audio src="/user/auth-tokens/rotate"></audio>'],
    [TextMode.Markdown, '![x](/profile/switch-org/2)'],
    [TextMode.HTML, '<img src="${media}">'],
    [TextMode.HTML, '${media:raw}'],
  ])('v2 renderContent and html view do not emit a session request for %s %s', (mode, content) => {
    setMediaVariable(content.includes('${media:raw}') ? '<img src="/logout">' : '/logout');
    const html = renderContent({ content, mode }, replaceVariables, false);
    expect(sessionSubresourcePaths(html)).toEqual([]);

    render(<TextNGHtmlView html={html} testId="TextPanel-converted-content" />);
    expect(renderedPaths()).toEqual([]);
  });
});
