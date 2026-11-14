import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import {
  EventBusSrv,
  FieldType,
  type GrafanaConfig,
  getDefaultTimeRange,
  LoadingState,
  locationUtil,
  toDataFrame,
} from '@grafana/data';
import { TooltipDisplayMode } from '@grafana/schema';
import { getDashboardSrv } from 'app/features/dashboard/services/DashboardSrv';
import { DashboardModel } from 'app/features/dashboard/state/DashboardModel';
import { getTemplateSrv } from 'app/features/templating/template_srv';

import { CanvasPanel } from './CanvasPanel';
import { HorizontalConstraint, type Options, VerticalConstraint } from './panelcfg.gen';

const shapeLabel = 'Server status';

const cases = [
  { dashboard: 'inline editing is off', inlineEditing: false, editable: true },
  { dashboard: 'the dashboard is not editable', inlineEditing: true, editable: false },
].flatMap((dashboard) =>
  [
    { destination: 'a logout path', url: '/logout' },
    { destination: 'an external https address', url: 'https://example.com/status' },
    { destination: 'a protocol-relative address', url: '//example.com/status' },
  ].map((link) => ({ ...dashboard, ...link }))
);

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

function canvasOptions(url: string, inlineEditing: boolean): Options {
  return {
    inlineEditing,
    showAdvancedTypes: false,
    panZoom: false,
    zoomToContent: false,
    tooltip: {
      mode: TooltipDisplayMode.Single,
      disableForOneClick: false,
    },
    root: {
      name: 'Canvas Root',
      type: 'frame',
      elements: [
        {
          type: 'text',
          name: 'Status',
          config: {
            align: 'center',
            valign: 'middle',
            color: { fixed: 'text' },
            size: 16,
            text: { fixed: shapeLabel, mode: 'fixed' },
          },
          constraint: {
            horizontal: HorizontalConstraint.Left,
            vertical: VerticalConstraint.Top,
          },
          placement: { left: 10, top: 10, width: 180, height: 40 },
          links: [{ title: shapeLabel, url, oneClick: true }],
        },
      ],
    },
  };
}

function renderCanvas(options: Options) {
  const timeRange = getDefaultTimeRange();

  return (
    <CanvasPanel
      id={1}
      title=""
      timeZone="utc"
      timeRange={timeRange}
      width={400}
      height={200}
      transparent={false}
      renderCounter={0}
      options={options}
      fieldConfig={{ defaults: {}, overrides: [] }}
      data={{
        state: LoadingState.Done,
        timeRange,
        series: [toDataFrame({ fields: [{ name: 'value', type: FieldType.number, values: [1] }] })],
      }}
      eventBus={new EventBusSrv()}
      onOptionsChange={() => {}}
      onFieldConfigChange={() => {}}
      onChangeTimeRange={() => {}}
      replaceVariables={(value, scopedVars, format) => getTemplateSrv().replace(value ?? '', scopedVars, format)}
    />
  );
}

describe('canvas one-click data links', () => {
  let openSpy: jest.SpiedFunction<typeof window.open>;
  const openedWithoutBeingShown: string[] = [];

  beforeEach(() => {
    openedWithoutBeingShown.length = 0;
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
    getDashboardSrv().setCurrent(undefined);
  });

  it.each(cases)(
    'does not follow $destination when $dashboard until the viewer has been shown the address',
    async ({ inlineEditing, editable, url }) => {
      getDashboardSrv().setCurrent(new DashboardModel({ title: 'View', editable, schemaVersion: 41, panels: [] }));
      const user = userEvent.setup();
      render(renderCanvas(canvasOptions(url, inlineEditing)));
      const shape = screen.getByRole('button', { name: shapeLabel });

      await user.hover(shape);
      expect(shape).toHaveStyle({ cursor: 'pointer' });
      expect(shape).toHaveTextContent(shapeLabel);

      await user.click(shape);

      expect(openedWithoutBeingShown).toEqual([]);
    }
  );
});
