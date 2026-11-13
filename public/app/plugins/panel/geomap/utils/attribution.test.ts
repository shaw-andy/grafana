// ol-mapbox-style and geotiff fail to parse under jest; stub them so the real
// layer registry (and everything it transitively imports) can still load.
jest.mock('ol-mapbox-style', () => ({}));
jest.mock('geotiff', () => ({}));

import LayerGroup from 'ol/layer/Group';
import TileLayer from 'ol/layer/Tile';
import { type Attribution } from 'ol/source/Source';
import XYZ from 'ol/source/XYZ';

import { type MapLayerHandler, type MapLayerOptions } from '@grafana/data';

import { geomapLayerRegistry } from '../layers/registry';
import { type MapLayerState } from '../types';

import {
  captureLayerAttribution,
  guardLayerAttribution,
  sanitizeAttribution,
  updateAttributionVisibility,
} from './attribution';

const getIfExists = jest.spyOn(geomapLayerRegistry, 'getIfExists');

const frameState = {} as Parameters<Attribution>[0];

const tileLayer = (attributions?: string) =>
  new TileLayer({ source: new XYZ({ url: 'http://x/{z}/{x}/{y}', attributions }) });

const attributionOf = (layer: TileLayer<XYZ>) => {
  const attributions = layer.getSource()?.getAttributions();
  return attributions ? attributions(frameState) : null;
};

const attributionsOf = (layer: TileLayer<XYZ>) => {
  const attribution = attributionOf(layer);
  if (attribution == null) {
    return [];
  }
  return Array.isArray(attribution) ? attribution : [attribution];
};

const XSS_ATTRIBUTION = '© Tiles<img src="x" onerror="window.__pwned = 1">';
const SAFE_ATTRIBUTION = '© Tiles';
const LEGITIMATE_ATTRIBUTION = '<a href="https://carto.com/attribution/">©CARTO</a>';

const layerState = (layer: MapLayerState['layer'], options: Partial<MapLayerOptions> = {}): MapLayerState => ({
  options: { name: 'Basemap', type: 'xyz', ...options },
  layer,
  handler: {} as MapLayerHandler,
  onChange: jest.fn(),
  getName: () => 'Basemap',
});

const optional = { id: 'xyz', name: 'XYZ', create: jest.fn() };
const required = { id: 'carto', name: 'CARTO', create: jest.fn(), requiresAttribution: true };

beforeEach(() => {
  jest.clearAllMocks();
});

describe('sanitizeAttribution', () => {
  it.each([
    ['an image', '© Tiles<img src="/logout">'],
    ['a responsive image', '© Tiles<picture><source srcset="/logout"><img src="/logout"></picture>'],
    ['an image input', '© Tiles<input type="image" src="/logout">'],
    ['media', '© Tiles<video poster="/logout"><source src="/logout"></video><audio src="/logout"></audio>'],
    ['an embedded object', '© Tiles<object data="/logout"></object><embed src="/logout">'],
    ['an svg image', '© Tiles<svg><image href="/logout"></image></svg>'],
    ['a stylesheet', '© Tiles<link rel="stylesheet" href="/logout"><style>@import "/logout";</style>'],
    ['a background', '© Tiles<div style="background:url(/logout)"></div><table background="/logout"></table>'],
    ['a styled inline element', '© <span style="background:url(/logout)">Tiles</span>'],
  ])('drops markup that loads an address on its own: %s', (_label, attribution) => {
    const container = document.createElement('div');
    container.innerHTML = sanitizeAttribution(attribution);

    expect(container.textContent).toBe('© Tiles');
    expect(container.querySelector('[src], [srcset], [poster], [data], [background], [style], [href]')).toBeNull();
  });

  it('keeps the text of a dropped element', () => {
    expect(sanitizeAttribution('<div>© <u>Tiles</u></div>')).toBe('© <u>Tiles</u>');
  });

  it.each([
    ['a relative link', '/profile/switch-org/2'],
    ['a link to this server', `${window.location.origin}/logout`],
    ['a protocol relative link to this server', `//${window.location.host}/logout`],
    ['a script link', 'javascript:alert(1)'],
    ['a data link', 'data:text/html,hi'],
  ])('removes the address of %s', (_label, href) => {
    expect(sanitizeAttribution(`<a href="${href}">© Tiles</a>`)).toBe('<a>© Tiles</a>');
  });

  it('drops a target other than a new tab', () => {
    expect(sanitizeAttribution('<a href="https://tiles.example/" target="grafana">© Tiles</a>')).toBe(
      '<a href="https://tiles.example/">© Tiles</a>'
    );
  });
});

describe('guardLayerAttribution', () => {
  it('filters attribution the source was created with', () => {
    const layer = tileLayer(XSS_ATTRIBUTION);

    guardLayerAttribution(layer);

    expect(attributionsOf(layer)).toEqual([SAFE_ATTRIBUTION]);
  });

  it('filters attribution the source picks up later', () => {
    const layer = tileLayer();
    guardLayerAttribution(layer);

    layer.getSource()?.setAttributions(XSS_ATTRIBUTION);

    expect(attributionsOf(layer)).toEqual([SAFE_ATTRIBUTION]);
  });

  it('filters attribution a source reports through a function', () => {
    const layer = tileLayer();
    guardLayerAttribution(layer);

    layer.getSource()?.setAttributions(() => [XSS_ATTRIBUTION]);

    expect(attributionsOf(layer)).toEqual([SAFE_ATTRIBUTION]);
  });

  it('strips a script payload', () => {
    const layer = tileLayer('<script>window.__pwned = 1</script>© Tiles');

    guardLayerAttribution(layer);

    expect(attributionsOf(layer)).toEqual(['© Tiles']);
  });

  it('strips an iframe rather than leaving a blank entry', () => {
    const layer = tileLayer('<iframe src="https://tiles.example/beacon"></iframe>');

    guardLayerAttribution(layer);

    expect(attributionsOf(layer)).toEqual([]);
  });

  it('marks a link that opens in a new tab as noopener', () => {
    const layer = tileLayer('<a href="https://www.openstreetmap.org/copyright" target="_blank">©OpenStreetMap</a>');

    guardLayerAttribution(layer);

    expect(attributionsOf(layer)).toEqual([
      '<a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">©OpenStreetMap</a>',
    ]);
  });

  it('keeps the markup a real attribution needs', () => {
    const layer = tileLayer(LEGITIMATE_ATTRIBUTION);

    guardLayerAttribution(layer);

    expect(attributionsOf(layer)).toEqual([LEGITIMATE_ATTRIBUTION]);
  });

  it('filters the sources inside nested layer groups', () => {
    const child = tileLayer(XSS_ATTRIBUTION);
    const group = new LayerGroup({ layers: [new LayerGroup({ layers: [child] })] });

    guardLayerAttribution(group);

    expect(attributionsOf(child)).toEqual([SAFE_ATTRIBUTION]);
  });

  it('filters layers added to the group after it was guarded', () => {
    const group = new LayerGroup({ layers: [] });
    guardLayerAttribution(group);

    // A layer built from a remote style adds its layers once the style has loaded
    const child = tileLayer(XSS_ATTRIBUTION);
    group.getLayers().push(child);

    expect(attributionsOf(child)).toEqual([SAFE_ATTRIBUTION]);
  });

  it('leaves a source alone when it carries no attribution', () => {
    // A data layer reads the features it loaded on the source's change event, so guarding a source
    // must not mark it as changed
    const layer = tileLayer();
    const onChange = jest.fn();
    layer.getSource()?.on('change', onChange);

    guardLayerAttribution(layer);

    expect(onChange).not.toHaveBeenCalled();
  });

  it('filters a source put on the layer after it was guarded', () => {
    const layer = tileLayer();
    guardLayerAttribution(layer);

    layer.setSource(new XYZ({ url: 'http://x/{z}/{x}/{y}', attributions: XSS_ATTRIBUTION }));

    expect(attributionsOf(layer)).toEqual([SAFE_ATTRIBUTION]);
  });
});

describe('updateAttributionVisibility', () => {
  it('hides attribution when the map control is off', () => {
    getIfExists.mockReturnValue(optional);
    const layer = tileLayer('© Tiles');
    captureLayerAttribution(layer);

    updateAttributionVisibility([layerState(layer)], { showAttribution: false });

    expect(attributionOf(layer)).toBeNull();
  });

  it('keeps required attribution when the map control is off', () => {
    getIfExists.mockReturnValue(required);
    const layer = tileLayer('©CARTO');
    captureLayerAttribution(layer);

    updateAttributionVisibility([layerState(layer, { type: 'carto' })], { showAttribution: false });

    expect(attributionOf(layer)).toEqual(['©CARTO']);
  });

  it('asks the layer type when the requirement depends on the configuration', () => {
    const requiresAttribution = jest.fn((cfg: MapLayerOptions) => cfg.config?.server !== 'custom');
    getIfExists.mockReturnValue({ id: 'esri-xyz', name: 'ArcGIS', create: jest.fn(), requiresAttribution });
    const preset = tileLayer('© ArcGIS');
    const custom = tileLayer('© Mine');
    captureLayerAttribution(preset);
    captureLayerAttribution(custom);

    updateAttributionVisibility(
      [
        layerState(preset, { type: 'esri-xyz', config: { server: 'topo' } }),
        layerState(custom, { type: 'esri-xyz', config: { server: 'custom' } }),
      ],
      { showAttribution: false }
    );

    expect(attributionOf(preset)).toEqual(['© ArcGIS']);
    expect(attributionOf(custom)).toBeNull();
  });

  it('shows attribution by default', () => {
    getIfExists.mockReturnValue(optional);
    const layer = tileLayer('© Tiles');
    captureLayerAttribution(layer);

    updateAttributionVisibility([layerState(layer)]);

    expect(attributionOf(layer)).toEqual(['© Tiles']);
  });

  it('restores attribution that it hid earlier', () => {
    getIfExists.mockReturnValue(optional);
    const layer = tileLayer('© Tiles');
    captureLayerAttribution(layer);

    updateAttributionVisibility([layerState(layer)], { showAttribution: false });
    updateAttributionVisibility([layerState(layer)], { showAttribution: true });

    expect(attributionOf(layer)).toEqual(['© Tiles']);
  });

  it('reaches the sources inside a layer group', () => {
    getIfExists.mockReturnValue(optional);
    const child = tileLayer('© Tiles');
    const group = new LayerGroup({ layers: [child] });
    captureLayerAttribution(group);

    updateAttributionVisibility([layerState(group)], { showAttribution: false });

    expect(attributionOf(child)).toBeNull();
  });

  it('hides attribution that was filtered first', () => {
    getIfExists.mockReturnValue(optional);
    const layer = tileLayer('© Tiles');
    guardLayerAttribution(layer);
    captureLayerAttribution(layer);

    updateAttributionVisibility([layerState(layer)], { showAttribution: false });

    expect(attributionOf(layer)).toBeNull();
  });

  it('restores filtered attribution that it hid earlier', () => {
    getIfExists.mockReturnValue(optional);
    const layer = tileLayer(XSS_ATTRIBUTION);
    guardLayerAttribution(layer);
    captureLayerAttribution(layer);

    updateAttributionVisibility([layerState(layer)], { showAttribution: false });
    updateAttributionVisibility([layerState(layer)], { showAttribution: true });

    expect(attributionsOf(layer)).toEqual([SAFE_ATTRIBUTION]);
  });

  it('leaves attribution that arrives after the layer was created', () => {
    getIfExists.mockReturnValue(required);
    const layer = tileLayer();
    captureLayerAttribution(layer);

    layer.getSource()?.setAttributions('© Style');
    updateAttributionVisibility([layerState(layer, { type: 'maplibre' })], { showAttribution: false });

    expect(attributionOf(layer)).toEqual(['© Style']);
  });
});
