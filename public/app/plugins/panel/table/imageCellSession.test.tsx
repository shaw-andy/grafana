import { Suspense } from 'react';
import { render, screen } from '@testing-library/react';

import {
  applyFieldOverrides,
  createTheme,
  type DataFrame,
  FieldMatcherID,
  FieldType,
  MappingType,
  standardEditorsRegistry,
  standardFieldConfigEditorRegistry,
  toDataFrame,
  type ValueMapping,
} from '@grafana/data';
import { TableCellDisplayMode } from '@grafana/schema';
import { mockClientSize } from '@grafana/test-utils';
import { Table } from '@grafana/ui';
import { TableNG } from '@grafana/ui/unstable';
import { getAllOptionEditors, getAllStandardFieldConfigs } from 'app/core/components/OptionsUI/registry';

import { plugin } from './module';

// The table plugin's field config registry resolves standard editors the first time it is read.
standardEditorsRegistry.setInit(getAllOptionEditors);
standardFieldConfigEditorRegistry.setInit(getAllStandardFieldConfigs);

beforeAll(() => {
  // react-data-grid sizes its viewport from the client box, which jsdom reports as 0.
  mockClientSize({ width: 800, height: 600 });
});

const SAFE_HTTPS = 'https://example.com/image.png';
const SAFE_HTTP = 'http://cdn.example/picture.png';

/**
 * Addresses the browser would request from this Grafana origin, including forms that
 * only match after URL resolution (userinfo, whitespace, protocol-relative, dot segments).
 * The assertion reads the DOM's resolved image URL, so a check that accepts one of these
 * strings and then assigns it to src still fails.
 */
function credentialedAddresses(): string[] {
  const { origin, host, protocol, hostname, port } = window.location;
  const upperHost = `${protocol}//${hostname.toUpperCase()}${port ? `:${port}` : ''}/logout`;
  return [
    '/logout',
    '/profile/switch-org/2',
    'logout',
    './logout',
    `//${host}/logout`,
    `${origin}/logout`,
    `${origin}/profile/switch-org/2`,
    ` ${origin}/logout`,
    `${origin}/logout `,
    `${origin}/foo/../logout`,
    `http://evil.example@${host}/logout`,
    upperHost,
  ];
}

function applyTableFieldConfig(
  values: string[],
  source: {
    defaults?: Record<string, unknown>;
    overrides?: Array<{
      matcher: { id: string; options: string };
      properties: Array<{ id: string; value: unknown }>;
    }>;
    fieldCustom?: Record<string, unknown>;
    mappings?: ValueMapping[];
  }
): DataFrame {
  const frame = toDataFrame({
    name: 'query',
    fields: [
      {
        name: 'image',
        type: FieldType.string,
        values,
        config: {
          ...(source.mappings ? { mappings: source.mappings } : {}),
          ...(source.fieldCustom ? { custom: source.fieldCustom } : {}),
        },
      },
    ],
  });

  return applyFieldOverrides({
    data: [frame],
    fieldConfig: {
      defaults: { custom: source.defaults ?? {} },
      overrides: source.overrides ?? [],
    },
    fieldConfigRegistry: plugin.fieldConfigRegistry,
    replaceVariables: (value: string) => value,
    theme: createTheme(),
    timeZone: 'utc',
  })[0];
}

function renderCurrentTable(data: DataFrame) {
  return render(<TableNG data={data} width={800} height={600} enableVirtualization={false} />);
}

async function renderLegacyTable(data: DataFrame) {
  const view = render(
    <Suspense fallback={null}>
      <Table data={data} width={800} height={600} />
    </Suspense>
  );
  await screen.findByRole('table');
  return view;
}

function imageRequestsThisOrigin(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll('img'))
    .map((img) => img.src)
    .filter((src) => {
      const url = new URL(src);
      return url.origin === window.location.origin;
    });
}

function expectExternalImage(container: HTMLElement, src: string) {
  const rendered = Array.from(container.querySelectorAll('img')).find((img) => img.getAttribute('src') === src);
  expect(rendered?.getAttribute('src')).toBe(src);
  expect(new URL(rendered!.src).origin).toBe(new URL(src).origin);
}

describe('table image cells and the viewer session', () => {
  const dangerous = credentialedAddresses();

  it('keeps a column set to Image on the panel from requesting this origin', () => {
    const values = [...dangerous, SAFE_HTTPS, SAFE_HTTP];
    const frame = applyTableFieldConfig(values, {
      defaults: { cellOptions: { type: TableCellDisplayMode.Image } },
    });

    // The query string survives the display processor and is what the cell receives.
    expect(frame.fields[0].display!(values[0]).text).toBe('/logout');
    expect(frame.fields[0].display!(SAFE_HTTPS).text).toBe(SAFE_HTTPS);

    const { container } = renderCurrentTable(frame);

    expectExternalImage(container, SAFE_HTTPS);
    expectExternalImage(container, SAFE_HTTP);
    expect(imageRequestsThisOrigin(container)).toEqual([]);
  });

  it('keeps a column override of Image from requesting this origin', () => {
    const frame = applyTableFieldConfig(['/logout', SAFE_HTTPS], {
      overrides: [
        {
          matcher: { id: FieldMatcherID.byName, options: 'image' },
          properties: [{ id: 'custom.cellOptions', value: { type: TableCellDisplayMode.Image } }],
        },
      ],
    });

    const { container } = renderCurrentTable(frame);

    expectExternalImage(container, SAFE_HTTPS);
    expect(imageRequestsThisOrigin(container)).toEqual([]);
  });

  it('keeps a legacy displayMode of image from requesting this origin', () => {
    const frame = applyTableFieldConfig(['/profile/switch-org/2', SAFE_HTTPS], {
      fieldCustom: { displayMode: TableCellDisplayMode.Image },
    });

    const { container } = renderCurrentTable(frame);

    expectExternalImage(container, SAFE_HTTPS);
    expect(imageRequestsThisOrigin(container)).toEqual([]);
  });

  it('keeps a value mapping that rewrites the cell text to a same-origin path from being requested', () => {
    const frame = applyTableFieldConfig(['fine'], {
      defaults: { cellOptions: { type: TableCellDisplayMode.Image } },
      mappings: [
        {
          type: MappingType.ValueToText,
          options: { fine: { text: '/logout' } },
        },
      ],
    });

    expect(frame.fields[0].display!('fine').text).toBe('/logout');

    const { container } = renderCurrentTable(frame);
    expect(imageRequestsThisOrigin(container)).toEqual([]);
  });

  it('keeps a regex mapping that rewrites the cell text to a same-origin path from being requested', () => {
    const frame = applyTableFieldConfig(['anything'], {
      defaults: { cellOptions: { type: TableCellDisplayMode.Image } },
      mappings: [
        {
          type: MappingType.RegexToText,
          options: { pattern: '.*', result: { text: '/profile/switch-org/2' } },
        },
      ],
    });

    expect(frame.fields[0].display!('anything').text).toBe('/profile/switch-org/2');

    const { container } = renderCurrentTable(frame);
    expect(imageRequestsThisOrigin(container)).toEqual([]);
  });

  it('keeps the legacy table image cell from requesting this origin', async () => {
    const values = [...dangerous, SAFE_HTTPS];
    const frame = applyTableFieldConfig(values, {
      defaults: { cellOptions: { type: TableCellDisplayMode.Image } },
    });

    // Legacy ImageCell spreads react-table cell props, which include a key. That warning
    // is unrelated to the address the image requests.
    jest.spyOn(console, 'error').mockImplementation(() => {});

    const { container } = await renderLegacyTable(frame);

    expectExternalImage(container, SAFE_HTTPS);
    expect(imageRequestsThisOrigin(container)).toEqual([]);
  });

  it('keeps a markdown cell image from requesting this origin', () => {
    const frame = applyTableFieldConfig([`![x](/logout)`, `![x](${SAFE_HTTPS})`], {
      defaults: { cellOptions: { type: TableCellDisplayMode.Markdown } },
    });

    const { container } = renderCurrentTable(frame);

    expect(container.querySelector(`img[src="${SAFE_HTTPS}"]`)?.getAttribute('src')).toBe(SAFE_HTTPS);
    expect(imageRequestsThisOrigin(container)).toEqual([]);
  });
});
