import { waitFor } from '@testing-library/react';
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

  it('fetches the default style URL without credentials when no config url is set', async () => {
    await initLayer({ config: {} });
    expect(fetch).toHaveBeenCalledWith(DEFAULT_STYLE_URL, { credentials: 'omit' });
  });

  it('fetches the configured style URL without credentials when one is provided', async () => {
    const url = 'https://tiles.example.com/style.json';
    await initLayer({ config: { url } });
    expect(fetch).toHaveBeenCalledWith(url, { credentials: 'omit' });
  });

  it.each(['/logout', `${window.location.origin}/logout`, `//${window.location.host}/logout`, ' /logout'])(
    'does not load a style URL on the Grafana origin: %s',
    async (url) => {
      const warn = jest.spyOn(console, 'warn').mockImplementation();
      await initLayer({ config: { url } });
      await waitFor(() => expect(warn).toHaveBeenCalled());
      expect(fetch).not.toHaveBeenCalled();
      expect(applyMock).not.toHaveBeenCalled();
    }
  );

  it('pins the webfont template so the style cannot choose where label fonts load from', async () => {
    const style = { layers: [], metadata: { 'ol:webfonts': `${window.location.origin}/logout?{font-family}` } };
    jest.spyOn(global, 'fetch').mockResolvedValue(new Response(JSON.stringify(style), { status: 200 }));
    await initLayer({ config: { url: 'https://tiles.example.com/style.json' } });
    await waitFor(() => expect(applyMock).toHaveBeenCalled());
    const [, appliedStyle] = applyMock.mock.calls[0];
    expect(appliedStyle.metadata['ol:webfonts']).toBe('data:text/css,');
  });

  describe('resources the style references', () => {
    async function getTransformRequest() {
      await initLayer({ config: { url: 'https://tiles.example.com/style.json' } });
      await waitFor(() => expect(applyMock).toHaveBeenCalled());
      const [, , applyOptions] = applyMock.mock.calls[0];
      return applyOptions.transformRequest;
    }

    it('requests external resources without credentials', async () => {
      const transformRequest = await getTransformRequest();
      const request = transformRequest('https://tiles.example.com/sprite.json', 'Sprite');
      expect(request).toBeInstanceOf(Request);
      expect(request.url).toBe('https://tiles.example.com/sprite.json');
      expect(request.credentials).toBe('omit');
    });

    it.each([
      `${window.location.origin}/logout`,
      `${window.location.protocol}//${window.location.host}%5C@tiles.example.com/`,
    ])('refuses resources on the Grafana origin: %s', async (url) => {
      const transformRequest = await getTransformRequest();
      const fetchCalls = jest.mocked(fetch).mock.calls.length;
      for (const type of ['Style', 'Source', 'Sprite', 'SpriteImage', 'Tiles', 'GeoJSON']) {
        const result = await transformRequest(decodeURI(url), type);
        expect(result).toBeInstanceOf(Response);
        expect(result.type).toBe('error');
      }
      expect(fetch).toHaveBeenCalledTimes(fetchCalls);
    });
  });
});
