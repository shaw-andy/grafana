import { act, render, screen } from '@testing-library/react';
import React from 'react';
import { type MouseEvent as ReactMouseEvent } from 'react';
import type uPlot from 'uplot';

import {
  applyFieldOverrides,
  createTheme,
  FieldType,
  type GrafanaConfig,
  locationUtil,
  type InterpolateFunction,
  toDataFrame,
} from '@grafana/data';
import { mockThemeContext, TooltipPlugin2, UPlotConfigBuilder, VizTooltipFooter } from '@grafana/ui';
import { TooltipHoverMode } from '@grafana/ui/internal';
import { ElementState } from 'app/features/canvas/runtime/element';
import { rectangleItem } from 'app/features/canvas/elements/rectangle';
import { type DimensionContext } from 'app/features/dimensions/context';

// frame.tsx extends ElementState while element.tsx is still evaluating, because
// element.tsx imports canvas utils which import frame.tsx. Jest's CommonJS load
// hits that cycle before the class exists. The click path under test does not use
// FrameState; the parent passed below only has to answer isRoot() and expose the scene.
jest.mock('app/features/canvas/runtime/frame', () => ({
  FrameState: class FrameState {},
}));
import { type DimensionSupplier } from 'app/features/dimensions/types';
import { initTemplateSrv } from 'test/helpers/initTemplateSrv';

/**
 * One-click plot and canvas links navigate with window.open. These tests are the
 * spec for that behavior: a plot click or a canvas click must not send the viewer
 * to logout or to the organization switch page, including when the stored URL only
 * becomes one of those paths after newline removal, URL sanitizing, or variable
 * interpolation. The viewer accepting a confirmation dialog, or activating a control
 * that the click revealed, still must not open those paths.
 *
 * TooltipPlugin2 is the click handler for the time series, trend, candlestick,
 * barchart, xychart, state timeline, and status history panels. Those panels pass
 * field.getLinks into that handler. Histogram and heatmap mount the same plugin but
 * do not pass getDataLinks, so a one-click field link there does not take this path.
 * Canvas uses ElementState.onElementClick instead, and is covered separately.
 */

type Attack = {
  name: string;
  url: string;
  targetBlank?: boolean;
  appSubUrl?: string;
  /** Row macros need a plotted field. Canvas builds its link field with no values. */
  plotOnly?: boolean;
};

const attacks: Attack[] = [
  { name: 'logout path', url: '/logout' },
  { name: 'logout path with a query string', url: '/logout?redirect=%2F' },
  { name: 'organization switch path', url: '/profile/switch-org/2' },
  { name: 'newline removed before the url is opened', url: '/\nlogout' },
  { name: 'control character removed by the url sanitizer', url: '/\u0000logout' },
  { name: 'slash written as an html entity', url: '&#47;logout' },
  { name: 'leading whitespace trimmed by the url sanitizer', url: '  /profile/switch-org/2' },
  { name: 'dashboard variable that resolves to logout', url: '/${dest}' },
  { name: 'dashboard variable that resolves to an organization id', url: '/profile/switch-org/${org}' },
  {
    name: 'hovered point value used as the organization id',
    url: '/profile/switch-org/${__value.raw}',
    plotOnly: true,
  },
  { name: 'same-origin absolute logout url', url: '' },
  { name: 'protocol-relative logout url', url: '' },
  { name: 'logout path opened in a new tab', url: '/logout', targetBlank: true },
  { name: 'logout path under an app sub url', url: '/logout', appSubUrl: '/grafana' },
  { name: 'organization switch under an app sub url', url: '/profile/switch-org/2', appSubUrl: '/grafana' },
];

function attackUrl(attack: Attack): string {
  if (attack.name === 'same-origin absolute logout url') {
    return `${window.location.origin}/logout`;
  }
  if (attack.name === 'protocol-relative logout url') {
    return `//${window.location.host}/logout`;
  }
  return attack.url;
}

function isSessionChangingNavigation(href: string, appSubUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(href, window.location.origin);
  } catch {
    return false;
  }
  if (parsed.origin !== window.location.origin) {
    return false;
  }

  let path = parsed.pathname;
  if (appSubUrl !== '' && (path === appSubUrl || path.startsWith(`${appSubUrl}/`))) {
    path = path.slice(appSubUrl.length) || '/';
  }

  if (path === '/logout' || path === '/logout/') {
    return true;
  }
  return /^\/profile\/switch-org\/[0-9]+\/?$/.test(path);
}

function installNavigationRecorder() {
  const opened: string[] = [];
  const open = jest.spyOn(window, 'open').mockImplementation((url) => {
    if (url != null && String(url) !== '') {
      opened.push(String(url));
    }
    return null;
  });
  const confirm = jest.spyOn(window, 'confirm').mockImplementation(() => true);

  const onClick = (event: Event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    const anchor = target.closest('a');
    if (!(anchor instanceof HTMLAnchorElement)) {
      return;
    }
    const href = anchor.getAttribute('href');
    if (href) {
      opened.push(href);
    }
    event.preventDefault();
  };
  document.addEventListener('click', onClick, true);

  return {
    opened,
    restore() {
      document.removeEventListener('click', onClick, true);
      open.mockRestore();
      confirm.mockRestore();
    },
  };
}

async function acceptRevealedControls() {
  for (const button of screen.queryAllByRole('button')) {
    await act(async () => {
      button.click();
    });
  }
  for (const link of screen.queryAllByRole('link')) {
    await act(async () => {
      link.click();
    });
  }
}

function replaceVariables(): InterpolateFunction {
  const templateSrv = initTemplateSrv('one-click-session', [
    { type: 'query', name: 'dest', current: { value: 'logout', text: 'logout' } },
    { type: 'query', name: 'org', current: { value: '2', text: '2' } },
  ]);
  return (value, scopedVars, format) => templateSrv.replace(value ?? '', scopedVars, format);
}

function withFieldLinks(url: string, targetBlank: boolean | undefined, interpolate: InterpolateFunction) {
  const frame = toDataFrame({
    refId: 'A',
    fields: [
      { name: 'Time', type: FieldType.time, values: [1, 2, 3, 4, 5, 6], config: {} },
      { name: 'Value', type: FieldType.number, values: [0, 0, 0, 0, 0, 2], config: {} },
    ],
  });

  const [processed] = applyFieldOverrides({
    data: [frame],
    fieldConfig: {
      defaults: {
        links: [{ title: 'View details', url, oneClick: true, targetBlank }],
      },
      overrides: [],
    },
    replaceVariables: interpolate,
    theme: createTheme(),
  });

  return processed;
}

function supplier<T>(value: T): DimensionSupplier<T> {
  return { value: () => value, get: () => value };
}

const dimensionContext = {
  getColor: () => supplier('transparent'),
  getScale: () => supplier(1),
  getScalar: () => supplier(1),
  getText: () => supplier(''),
  getResource: () => supplier(''),
  getDirection: () => supplier('forward'),
  getPanelData: () => undefined,
} as DimensionContext;

function clickCanvas(url: string, targetBlank: boolean | undefined, interpolate: InterpolateFunction) {
  const frame = toDataFrame({
    refId: 'A',
    fields: [
      { name: 'Time', type: FieldType.time, values: [1], config: {} },
      { name: 'Value', type: FieldType.number, values: [2], config: {} },
    ],
  });
  const scene = {
    data: { series: [frame] },
    panel: { props: { replaceVariables: interpolate } },
    byName: new Map<string, ElementState>(),
    getNextElementName: () => 'Element',
  };
  const parent = {
    isRoot: () => true,
    scene,
  } as unknown as ElementState;

  const element = new ElementState(
    rectangleItem,
    {
      name: 'box',
      type: rectangleItem.id,
      links: [{ title: 'View details', url, oneClick: true, targetBlank }],
    },
    parent
  );
  element.div = document.createElement('div');
  element.updateData(dimensionContext);
  element.onElementClick({} as ReactMouseEvent);
}

describe('one-click data links do not change the viewer session', () => {
  let restoreTheme: () => void;

  beforeEach(() => {
    restoreTheme = mockThemeContext(createTheme());
  });

  afterEach(() => {
    restoreTheme();
    locationUtil.initialize({
      config: { appSubUrl: '' } as GrafanaConfig,
      getTimeRangeForUrl: () => ({ from: 'now-6h', to: 'now' }),
      getVariablesUrlParams: () => ({}),
    });
  });

  describe('time series plot click', () => {
    it.each(attacks)('$name', async (attack) => {
      const appSubUrl = attack.appSubUrl ?? '';
      locationUtil.initialize({
        config: { appSubUrl } as GrafanaConfig,
        getTimeRangeForUrl: () => ({ from: 'now-6h', to: 'now' }),
        getVariablesUrlParams: () => ({}),
      });

      const url = attackUrl(attack);
      const interpolate = replaceVariables();
      const frame = withFieldLinks(url, attack.targetBlank, interpolate);
      const navigation = installNavigationRecorder();
      const config = new UPlotConfigBuilder();
      const addHookSpy = jest.spyOn(config, 'addHook');

      const view = render(
        <TooltipPlugin2
          config={config}
          hoverMode={TooltipHoverMode.xOne}
          clientZoom={true}
          queryZoom={() => undefined}
          getDataLinks={(seriesIdx, dataIdx) => frame.fields[seriesIdx].getLinks?.({ valueRowIndex: dataIdx }) ?? []}
          render={(_u, _dataIdxs, _seriesIdx, _isPinned, _dismiss, _timeRange, _viaSync, dataLinks) => (
            <VizTooltipFooter dataLinks={dataLinks} />
          )}
        />
      );

      const hook = (name: string) => addHookSpy.mock.calls.filter((call) => call[0] === name).at(-1)?.[1];
      const over = document.createElement('div');
      const mockUPlot = {
        over,
        root: document.createElement('div'),
        rect: { left: 0, top: 0, width: 800, height: 400, bottom: 400, right: 800 },
        cursor: {
          left: 50,
          top: 50,
          event: new MouseEvent('mousemove', { clientX: 100, clientY: 100 }),
          idxs: [null, 5],
          drag: { x: true, y: false, setScale: false },
        },
        scales: { x: { ori: 0 } },
        select: { left: 0, top: 0, width: 0, height: 0 },
        setCursor: jest.fn(),
        setScale: jest.fn(),
        setSelect: jest.fn(),
      } as unknown as uPlot;

      await act(async () => {
        hook('init')(mockUPlot);
        hook('setLegend')(mockUPlot);
        hook('setSeries')(mockUPlot, 1);
      });

      try {
        await act(async () => {
          over.dispatchEvent(new MouseEvent('click', { bubbles: true }));
        });
        await acceptRevealedControls();

        const sessionChanging = navigation.opened.filter((href) => isSessionChangingNavigation(href, appSubUrl));
        expect(sessionChanging).toEqual([]);
      } finally {
        view.unmount();
        navigation.restore();
        addHookSpy.mockRestore();
      }
    });
  });

  describe('canvas element click', () => {
    it.each(attacks.filter((attack) => !attack.plotOnly))('$name', async (attack) => {
      const appSubUrl = attack.appSubUrl ?? '';
      locationUtil.initialize({
        config: { appSubUrl } as GrafanaConfig,
        getTimeRangeForUrl: () => ({ from: 'now-6h', to: 'now' }),
        getVariablesUrlParams: () => ({}),
      });

      const navigation = installNavigationRecorder();
      try {
        clickCanvas(attackUrl(attack), attack.targetBlank, replaceVariables());
        await acceptRevealedControls();

        const sessionChanging = navigation.opened.filter((href) => isSessionChangingNavigation(href, appSubUrl));
        expect(sessionChanging).toEqual([]);
      } finally {
        navigation.restore();
      }
    });
  });
});
