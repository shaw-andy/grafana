import { act, render, screen, waitFor } from '@testing-library/react';
import type uPlot from 'uplot';

import {
  applyFieldOverrides,
  createTheme,
  FieldConfigOptionsRegistry,
  FieldType,
  type GrafanaConfig,
  locationUtil,
  toDataFrame,
} from '@grafana/data';
import { DashboardCursorSync } from '@grafana/schema';
import { mockThemeContext, UPlotConfigBuilder, VizTooltipFooter } from '@grafana/ui';
import { getTemplateSrv } from 'app/features/templating/template_srv';

import {
  TooltipHoverMode,
  TooltipPlugin2,
} from '../../../../../packages/grafana-ui/src/components/uPlot/plugins/TooltipPlugin2';

const shapeLabel = 'Server status';

const destinations = [
  { name: 'a logout path', url: '/logout' },
  { name: 'an external https address', url: 'https://example.com/status' },
  { name: 'a protocol-relative address', url: '//example.com/status' },
];

function viewerVisibleText(): string {
  const parts = [document.body.innerText];
  document.body.querySelectorAll('*').forEach((node) => {
    if (!(node instanceof HTMLElement)) {
      return;
    }
    for (const attr of ['title', 'href', 'aria-label'] as const) {
      const value = node.getAttribute(attr);
      if (value) {
        parts.push(value);
      }
    }
  });
  return parts.join('\n');
}

function linksFor(url: string) {
  const frame = toDataFrame({
    fields: [
      { name: 'time', type: FieldType.time, values: [1, 2, 3, 4, 5, 6] },
      {
        name: 'value',
        type: FieldType.number,
        values: [1, 2, 3, 4, 5, 6],
        config: { links: [{ title: shapeLabel, url, oneClick: true }] },
      },
    ],
  });
  const processed = applyFieldOverrides({
    data: [frame],
    fieldConfig: { defaults: {}, overrides: [] },
    replaceVariables: (value, scopedVars, format) => getTemplateSrv().replace(value ?? '', scopedVars, format),
    theme: createTheme(),
    fieldConfigRegistry: new FieldConfigOptionsRegistry(() => []),
  });
  return processed[0].fields[1].getLinks?.({ valueRowIndex: 5 }) ?? [];
}

describe('uPlot one-click data links', () => {
  let openSpy: jest.SpiedFunction<typeof window.open>;
  let restoreTheme: () => void;
  const openedWithoutBeingShown: string[] = [];

  beforeEach(() => {
    openedWithoutBeingShown.length = 0;
    restoreTheme = mockThemeContext(createTheme());
    locationUtil.initialize({
      config: { appSubUrl: '', disableSanitizeHtml: false } as GrafanaConfig,
      getTimeRangeForUrl: () => ({ from: '', to: '' }),
      getVariablesUrlParams: () => ({}),
    });
    openSpy = jest.spyOn(window, 'open').mockImplementation((url, target) => {
      const destination = String(url);
      if (!viewerVisibleText().includes(destination)) {
        openedWithoutBeingShown.push(`${destination} (target ${String(target)})`);
      }
      return null;
    });
  });

  afterEach(() => {
    openSpy.mockRestore();
    restoreTheme();
  });

  it.each(destinations)(
    'does not follow $name from a plot click until the viewer has been shown the address',
    async ({ url }) => {
      const links = linksFor(url);
      expect(links.map((link) => ({ href: link.href, oneClick: link.oneClick, target: link.target }))).toEqual([
        { href: url, oneClick: true, target: undefined },
      ]);
      const config = new UPlotConfigBuilder();
      const over = document.createElement('div');
      const root = document.createElement('div');
      const mockUPlot = {
        root,
        over,
        rect: { left: 0, top: 0, width: 800, height: 400, bottom: 400, right: 800 },
        cursor: {
          left: 50,
          top: 50,
          event: new MouseEvent('mousemove', { clientX: 100, clientY: 100 }),
          idxs: [null, 5],
          drag: { x: true, y: false, setScale: false },
        },
        scales: { x: { ori: 0 } },
        setCursor: jest.fn(),
        setScale: jest.fn(),
        setSelect: jest.fn(),
        select: { left: 0, top: 0, width: 0, height: 0 },
        posToVal: (pos: number) => pos,
      } as unknown as uPlot;

      const hooks = new Map<string, (...args: unknown[]) => void>();
      jest.spyOn(config, 'addHook').mockImplementation((name, hook) => {
        hooks.set(name, hook as (...args: unknown[]) => void);
      });

      const view = render(
        <TooltipPlugin2
          config={config}
          hoverMode={TooltipHoverMode.xOne}
          syncMode={DashboardCursorSync.Off}
          getDataLinks={() => links}
          render={(_u, _dataIdxs, _seriesIdx, _isPinned, _dismiss, _timeRange, _viaSync, dataLinks) => (
            <VizTooltipFooter dataLinks={dataLinks} />
          )}
        />
      );

      const init = hooks.get('init');
      const setLegend = hooks.get('setLegend');
      const setSeries = hooks.get('setSeries');
      expect(init).toBeDefined();

      await act(async () => {
        init?.(mockUPlot);
        setLegend?.(mockUPlot);
        setSeries?.(mockUPlot, 1);
      });

      await waitFor(() => {
        expect(screen.getByText(`Click to open ${shapeLabel}`)).toBeInTheDocument();
      });

      await act(async () => {
        over.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      });

      expect(openedWithoutBeingShown).toEqual([]);
      view.unmount();
    }
  );
});
