import { flush } from '@emotion/css';
import { render } from '@testing-library/react';
import { type ComponentType } from 'react';

import {
  createDataFrame,
  FieldColorModeId,
  FieldType,
  type GrafanaTheme2,
  LoadingState,
  type PanelData,
  ThemeContext,
} from '@grafana/data';
import { config } from '@grafana/runtime';
import { TextDimensionMode } from '@grafana/schema';
import { type DimensionContext } from 'app/features/dimensions/context';
import {
  getColorDimensionFromData,
  getScalarDimensionFromData,
  getTextDimensionFromData,
} from 'app/features/dimensions/utils';

import { type CanvasElementOptions } from '../element';
import { Align, type TextConfig, VAlign } from '../types';

import { buttonItem } from './button';
import { cloudItem } from './cloud';
import { ellipseItem } from './ellipse';
import { metricValueItem } from './metricValue';
import { parallelogramItem } from './parallelogram';
import { rectangleItem } from './rectangle';
import { serverItem } from './server/server';
import { textItem } from './text';
import { triangleItem } from './triangle';

/**
 * Saved canvas colors, alignment, and sizes are copied into emotion style objects.
 * These tests render that path and require the resulting document styles not to
 * name an extra URL. They fail while a saved string can become another CSS declaration.
 */

const PROBE_PREFIX = '/canvas-css-probe-';

interface PreparedDisplay {
  display: ComponentType<{ config?: unknown; data?: unknown }>;
  prepareData: (ctx: DimensionContext, options: CanvasElementOptions) => unknown;
}

function viewerContext(data?: PanelData): DimensionContext {
  return {
    getColor: (color) => getColorDimensionFromData(data, color),
    getScale: () => {
      throw new Error('scale dimension is not part of this path');
    },
    getScalar: (scalar) => getScalarDimensionFromData(data, scalar),
    getText: (text) => getTextDimensionFromData(data, text),
    getResource: () => {
      throw new Error('resource dimension is not part of this path');
    },
    getDirection: () => {
      throw new Error('direction dimension is not part of this path');
    },
    getPanelData: () => data,
  };
}

function stylesheetText(): string {
  const parts: string[] = [];
  document.querySelectorAll('style').forEach((tag) => {
    if (tag.textContent) {
      parts.push(tag.textContent);
    }
    const sheet = tag.sheet;
    if (!sheet) {
      return;
    }
    for (const rule of Array.from(sheet.cssRules)) {
      parts.push(rule.cssText);
    }
  });
  return parts.join('\n');
}

function renderPrepared(item: PreparedDisplay, options: CanvasElementOptions, data?: PanelData) {
  const prepared = item.prepareData(viewerContext(data), options);
  const Display = item.display;
  return render(
    <ThemeContext.Provider value={config.theme2}>
      <Display config={options.config} data={prepared} />
    </ThemeContext.Provider>
  );
}

function expectNoProbe(probe: string) {
  expect(stylesheetText()).not.toContain(probe);
  const nodes: Element[] = [document.documentElement, document.body, ...Array.from(document.querySelectorAll('*'))];
  for (const node of nodes) {
    expect(getComputedStyle(node).backgroundImage).not.toContain(probe);
    expect(node.getAttribute('style') ?? '').not.toContain(probe);
  }
}

function textOptions(
  config: Partial<TextConfig> & { align?: string; valign?: string; size?: unknown }
): CanvasElementOptions {
  return {
    name: 'element',
    type: 'text',
    config: {
      text: { mode: TextDimensionMode.Fixed, fixed: 'saved label' },
      align: Align.Center,
      valign: VAlign.Middle,
      ...config,
    },
  };
}

const textLike: Array<{ id: string; item: PreparedDisplay }> = [
  { id: 'text', item: textItem },
  { id: 'rectangle', item: rectangleItem },
  { id: 'metric-value', item: metricValueItem },
];

const shapes: Array<{ id: string; item: PreparedDisplay }> = [
  { id: 'ellipse', item: ellipseItem },
  { id: 'cloud', item: cloudItem },
  { id: 'parallelogram', item: parallelogramItem },
  { id: 'triangle', item: triangleItem },
];

describe('canvas saved styles', () => {
  beforeEach(() => {
    flush();
  });

  describe.each(textLike)('$id', ({ id, item }) => {
    it('does not let an unknown saved color add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-color`;
      renderPrepared(
        item,
        textOptions({
          color: { fixed: `notacolor;background:url("${probe}")` },
        })
      );
      expectNoProbe(probe);
    });

    it('does not let a hex saved color add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-hex`;
      renderPrepared(
        item,
        textOptions({
          color: { fixed: `#112233;background:url("${probe}")` },
        })
      );
      expectNoProbe(probe);
    });

    it('does not let an rgb() saved color add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-rgb`;
      renderPrepared(
        item,
        textOptions({
          color: { fixed: `rgb(1, 2, 3);background:url("${probe}")` },
        })
      );
      expectNoProbe(probe);
    });

    it('does not let a saved color close the style rule', () => {
      const probe = `${PROBE_PREFIX}${id}-brace`;
      renderPrepared(
        item,
        textOptions({
          color: { fixed: `red}body{background:url("${probe}")` },
        })
      );
      expectNoProbe(probe);
    });

    it('does not let saved alignment add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-align`;
      renderPrepared(
        item,
        textOptions({
          align: `left;background:url("${probe}")`,
          color: { fixed: '#112233' },
        })
      );
      expectNoProbe(probe);
    });

    it('does not let saved vertical alignment add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-valign`;
      renderPrepared(
        item,
        textOptions({
          valign: `top;background:url("${probe}")`,
          color: { fixed: '#112233' },
        })
      );
      expectNoProbe(probe);
    });

    it('does not let a saved text size add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-size`;
      renderPrepared(
        item,
        textOptions({
          size: `1;background:url("${probe}");font-size:1`,
          color: { fixed: '#112233' },
        })
      );
      expectNoProbe(probe);
    });
  });

  it('keeps one hex color, alignment, and numeric size on a text element', () => {
    const view = renderPrepared(
      textItem,
      textOptions({
        color: { fixed: '#112233' },
        align: Align.Left,
        valign: VAlign.Middle,
        size: 18,
      })
    );
    const span = view.container.querySelector('span');
    expect(span).not.toBeNull();
    const style = getComputedStyle(span!);
    expect(style.color).toBe('rgb(17, 34, 51)');
    expect(style.textAlign).toBe('left');
    expect(style.fontSize).toBe('18px');
    expect(style.verticalAlign).toBe('middle');
    expect(stylesheetText()).not.toContain(PROBE_PREFIX);
  });

  it('resolves a known color name before writing the text color', () => {
    const theme: GrafanaTheme2 = config.theme2;
    const resolved = theme.visualization.getColorByName('green');
    const view = renderPrepared(textItem, textOptions({ color: { fixed: 'green' }, size: 16 }));
    const span = view.container.querySelector('span');
    expect(span).not.toBeNull();
    expect(getComputedStyle(span!).color).toBe(hexOrRgb(resolved));
  });

  it('does not let a field fixed color bypass the saved color written into the text element', () => {
    const probe = `${PROBE_PREFIX}field-fixed`;
    const frame = createDataFrame({
      fields: [
        {
          name: 'value',
          type: FieldType.number,
          values: [1],
          config: {
            color: { mode: FieldColorModeId.Fixed, fixedColor: `notacolor;background:url("${probe}")` },
          },
        },
      ],
    });
    const panelData = { series: [frame], state: LoadingState.Done } as PanelData;
    renderPrepared(textItem, textOptions({ color: { field: 'value', fixed: '#112233' } }), panelData);
    expectNoProbe(probe);
  });

  describe('button', () => {
    it('does not let a saved color add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}button-color`;
      renderPrepared(buttonItem, {
        name: 'button',
        type: 'button',
        config: {
          text: { mode: TextDimensionMode.Fixed, fixed: 'Press' },
          align: Align.Center,
          size: 14,
          color: { fixed: `notacolor;background:url("${probe}")` },
        },
      });
      expectNoProbe(probe);
    });

    it('does not let saved alignment add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}button-align`;
      renderPrepared(buttonItem, {
        name: 'button',
        type: 'button',
        config: {
          text: { mode: TextDimensionMode.Fixed, fixed: 'Press' },
          align: `left;background:url("${probe}")`,
          size: 14,
          color: { fixed: '#112233' },
        },
      });
      expectNoProbe(probe);
    });

    it('does not let a saved text size add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}button-size`;
      renderPrepared(buttonItem, {
        name: 'button',
        type: 'button',
        config: {
          text: { mode: TextDimensionMode.Fixed, fixed: 'Press' },
          align: Align.Center,
          size: `1;background:url("${probe}");font-size:1`,
          color: { fixed: '#112233' },
        },
      });
      expectNoProbe(probe);
    });

    it('keeps a hex color and numeric size', () => {
      const view = renderPrepared(buttonItem, {
        name: 'button',
        type: 'button',
        config: {
          text: { mode: TextDimensionMode.Fixed, fixed: 'Press' },
          align: Align.Right,
          size: 21,
          color: { fixed: '#112233' },
        },
      });
      const span = view.container.querySelector('span');
      expect(span).not.toBeNull();
      const style = getComputedStyle(span!);
      expect(style.color).toBe('rgb(17, 34, 51)');
      expect(style.textAlign).toBe('right');
      expect(style.fontSize).toBe('21px');
    });
  });

  describe.each(shapes)('$id', ({ id, item }) => {
    it('does not let a saved text color add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-color`;
      renderPrepared(item, {
        name: id,
        type: id,
        config: {
          text: { mode: TextDimensionMode.Fixed, fixed: 'shape' },
          align: Align.Center,
          valign: VAlign.Middle,
          color: { fixed: `notacolor;background:url("${probe}")` },
          size: 12,
        },
      });
      expectNoProbe(probe);
    });

    it('does not let a saved text size add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-size`;
      renderPrepared(item, {
        name: id,
        type: id,
        config: {
          align: Align.Center,
          valign: VAlign.Middle,
          color: { fixed: '#112233' },
          size: `1;background:url("${probe}");font-size:1`,
        },
      });
      expectNoProbe(probe);
    });

    it('does not let a saved border color add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-border`;
      renderPrepared(item, {
        name: id,
        type: id,
        config: {
          align: Align.Center,
          valign: VAlign.Middle,
          color: { fixed: '#112233' },
        },
        border: { color: { fixed: `notacolor;background:url("${probe}")` }, width: 2 },
      });
      expectNoProbe(probe);
    });

    it('does not let a saved border width add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}${id}-border-width`;
      renderPrepared(item, {
        name: id,
        type: id,
        config: {
          align: Align.Center,
          valign: VAlign.Middle,
          color: { fixed: '#112233' },
        },
        border: {
          color: { fixed: '#112233' },
          width: `2;background:url("${probe}")` as unknown as number,
        },
      });
      expectNoProbe(probe);
    });
  });

  describe('server', () => {
    it.each(['Single', 'Stack', 'Database', 'Terminal'])(
      'does not let a saved status color add a stylesheet request for %s',
      (type) => {
        const probe = `${PROBE_PREFIX}server-${type}-status`;
        renderPrepared(serverItem, {
          name: 'server',
          type: 'server',
          config: {
            type,
            statusColor: { fixed: `notacolor;background:url("${probe}")` },
          },
        });
        expectNoProbe(probe);
      }
    );

    it('does not let a saved bulb color add a stylesheet request', () => {
      const probe = `${PROBE_PREFIX}server-bulb`;
      renderPrepared(serverItem, {
        name: 'server',
        type: 'server',
        config: {
          type: 'Single',
          bulbColor: { fixed: `#00ff00;background:url("${probe}")` },
        },
      });
      expectNoProbe(probe);
    });
  });
});

function hexOrRgb(color: string): string {
  const match = /^#([0-9a-f]{6})$/i.exec(color.trim());
  if (!match) {
    return color;
  }
  const hex = match[1];
  const r = parseInt(hex.slice(0, 2), 16);
  const g = parseInt(hex.slice(2, 4), 16);
  const b = parseInt(hex.slice(4, 6), 16);
  return `rgb(${r}, ${g}, ${b})`;
}
