import type OpenLayersMap from 'ol/Map';
import LayerGroup from 'ol/layer/Group';

import { type EventBus, type GrafanaTheme2, type MapLayerOptions } from '@grafana/data';

// ol-mapbox-style is untransformed ESM under jest and only its side effect (apply) matters here.
const applyMock = jest.fn().mockResolvedValue(undefined);
jest.mock('ol-mapbox-style', () => ({
  apply: (...args: unknown[]) => applyMock(...args),
}));

import { ensureInstanceOf } from '../test-utils';

import { type MaplibreConfig, maplibreLayers } from './maplibre';

const [maplibreLayer] = maplibreLayers;

const DEFAULT_STYLE_URL = 'https://tiles.stadiamaps.com/styles/alidade_smooth.json';

const map = {} as OpenLayersMap;
const eventBus = {} as EventBus;
const theme = { isDark: false } as GrafanaTheme2;

async function initLayer(overrides: Partial<MapLayerOptions<Partial<MaplibreConfig>>>): Promise<LayerGroup> {
  const options: MapLayerOptions<Partial<MaplibreConfig>> = {
    name: 'maplibre',
    type: 'maplibre',
    config: {},
    ...overrides,
  };
  const handler = await maplibreLayer.create(map, options, eventBus, theme);
  return ensureInstanceOf(handler.init(), LayerGroup);
}

describe('maplibre basemap', () => {
  beforeEach(() => {
    applyMock.mockClear();
    jest.spyOn(global, 'fetch').mockResolvedValue(new Response(JSON.stringify({ layers: [] }), { status: 200 }));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('returns a LayerGroup and defaults opacity to 1', async () => {
    const layer = await initLayer({});
    expect(layer).toBeInstanceOf(LayerGroup);
    expect(layer.getOpacity()).toBe(1);
  });

  it('applies the configured layer opacity to the group', async () => {
    const layer = await initLayer({ opacity: 0.4 });
    expect(layer.getOpacity()).toBe(0.4);
  });

  it('fetches the default style URL when no config url is set', async () => {
    await initLayer({ config: {} });
    expect(fetch).toHaveBeenCalledWith(DEFAULT_STYLE_URL, { credentials: 'omit' });
  });

  it('fetches the configured style URL when one is provided', async () => {
    const url = 'https://tiles.example.com/style.json';
    await initLayer({ config: { url } });
    expect(fetch).toHaveBeenCalledWith(url, { credentials: 'omit' });
  });

  it('does not fetch a style URL on this server outside public/maps', async () => {
    await initLayer({ config: { url: '/logout' } });
    expect(fetch).not.toHaveBeenCalled();
    const transformRequest = applyMock.mock.calls[0][2].transformRequest;
    await expect(transformRequest('http://localhost/logout', 'Style')).rejects.toThrow();
  });

  it('loads resources referenced by the style without credentials and refuses ones on this server', async () => {
    await initLayer({ config: { url: 'https://tiles.example.com/style.json' } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    const transformRequest = applyMock.mock.calls[0][2].transformRequest;

    const tile = transformRequest('https://tiles.example.com/1/2/3.pbf', 'Tiles');
    expect(tile).toBeInstanceOf(Request);
    expect(tile.credentials).toBe('omit');
    await expect(transformRequest('/logout', 'Sprite')).rejects.toThrow();
  });

  it('drops a webfonts template that could point at this server', async () => {
    jest
      .spyOn(global, 'fetch')
      .mockResolvedValue(
        new Response(JSON.stringify({ layers: [], metadata: { 'ol:webfonts': '{font-family}' } }), { status: 200 })
      );
    await initLayer({ config: { url: 'https://tiles.example.com/style.json' } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(applyMock.mock.calls[0][1].metadata).toEqual({});
  });
});
