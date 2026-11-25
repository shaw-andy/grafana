import { render, waitFor } from '@testing-library/react';
import { initTemplateSrv } from 'test/helpers/initTemplateSrv';

import { dateTime, EventBusSrv, FieldType, LoadingState, toDataFrame } from '@grafana/data';
import { credentialedResourceUrls } from 'test/credentialedResourceUrls';

import { RenderMode, TextMode } from './panelcfg.gen';
import { TextPanel, type Props } from './v1/TextPanel';
import { renderContent } from './v2/renderContent';
import { transformContent } from './v2/utils';

const payloads = [
  'visible ![alt](/logout)',
  'visible ![alt](/profile/switch-org/2)',
  'visible <img src="/logout">',
  'visible <audio src="/logout"></audio>',
  'visible <video poster="/logout"></video>',
  'visible <div style="background-image:url(/profile/switch-org/2)"></div>',
  'visible <iframe src="/logout"></iframe>',
  'visible <meta http-equiv="refresh" content="0;url=/logout">',
];

describe('text panel content', () => {
  describe.each([false, true])('disableSanitizeHtml=%s', (disableSanitizeHtml) => {
    it.each(payloads)('markdown mode does not emit a credentialed URL: %s', (payload) => {
      const html = transformContent(TextMode.Markdown, payload, disableSanitizeHtml);
      expect(credentialedResourceUrls(html)).toEqual([]);
      expect(html).toContain('visible');
    });

    it.each(payloads)('html mode does not emit a credentialed URL: %s', (payload) => {
      const html = transformContent(TextMode.HTML, payload, disableSanitizeHtml);
      expect(credentialedResourceUrls(html)).toEqual([]);
      expect(html).toContain('visible');
    });
  });

  it.each(payloads)('interpolates a query field into markdown without a credentialed URL: %s', (payload) => {
    const templateSrv = initTemplateSrv('hello', []);
    const series = [
      toDataFrame({
        fields: [{ name: 'note', type: FieldType.string, values: [payload] }],
      }),
    ];
    const html = renderContent(
      {
        content: '${__data.fields.note}',
        mode: TextMode.Markdown,
        series,
        renderMode: RenderMode.PerRow,
        format: 'html',
      },
      (target, scopedVars, format) => templateSrv.replace(target ?? '', scopedVars, format),
      false
    );
    expect(credentialedResourceUrls(html)).toEqual([]);
    expect(html).toContain('visible');
  });
});

describe('text panel v1', () => {
  const baseProps: Props = {
    id: 1,
    data: {
      state: LoadingState.Done,
      series: [{ fields: [], length: 0 }],
      timeRange: {
        from: dateTime('2022-01-01T00:00:00Z'),
        to: dateTime('2022-01-01T01:00:00Z'),
        raw: { from: 'now-1h', to: 'now' },
      },
    },
    timeRange: {
      from: dateTime('2022-01-01T00:00:00Z'),
      to: dateTime('2022-01-01T01:00:00Z'),
      raw: { from: 'now-1h', to: 'now' },
    },
    timeZone: 'utc',
    transparent: false,
    width: 200,
    height: 100,
    fieldConfig: { defaults: {}, overrides: [] },
    renderCounter: 1,
    title: 'Text',
    eventBus: new EventBusSrv(),
    options: { content: 'visible ![alt](/logout)', mode: TextMode.Markdown },
    onOptionsChange: jest.fn(),
    onFieldConfigChange: jest.fn(),
    replaceVariables: (value) => value ?? '',
    onChangeTimeRange: jest.fn(),
  };

  it.each([
    TextMode.Markdown,
    TextMode.HTML,
  ])('inserts %s content without a credentialed URL', async (mode) => {
    const { container } = render(
      <TextPanel {...baseProps} options={{ content: 'visible ![alt](/logout)\n\n<img src="/profile/switch-org/2">', mode }} />
    );
    await waitFor(() => {
      expect(container).toHaveTextContent('visible');
    });
    expect(credentialedResourceUrls(container.innerHTML)).toEqual([]);
  });
});
