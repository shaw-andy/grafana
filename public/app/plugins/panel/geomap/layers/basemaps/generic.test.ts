import ImageTile from 'ol/ImageTile';
import type OpenLayersMap from 'ol/Map';
import TileState from 'ol/TileState';
import TileLayer from 'ol/layer/Tile';
import { get as getProjection } from 'ol/proj';
import Projection from 'ol/proj/Projection';
import XYZ from 'ol/source/XYZ';

import { type EventBus, type GrafanaTheme2, type MapLayerOptions } from '@grafana/data';

import { ensureInstanceOf, getTileSource } from '../test-utils';

import { xyzTiles, type XYZConfig } from './generic';

const replaceMock = jest.fn((text: string) => text);
jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  getTemplateSrv: () => ({
    replace: replaceMock,
  }),
}));

describe('XYZ tile layer', () => {
  let mockMap: OpenLayersMap;
  let mockEventBus: EventBus;
  let mockTheme: GrafanaTheme2;

  beforeEach(() => {
    mockMap = {} as OpenLayersMap;
    mockEventBus = {} as EventBus;
    mockTheme = {} as GrafanaTheme2;
    replaceMock.mockClear();
  });

  it('should interpolate variables in URL and attribution', async () => {
    const rawUrl = 'https://example.com/$version/{z}/{x}/{y}.png';
    const interpolatedUrl = 'https://example.com/v1/{z}/{x}/{y}.png';
    const rawAttr = 'Map version $version';
    const interpolatedAttr = 'Map version v1';

    replaceMock.mockImplementation((text) => {
      if (text === rawUrl) {
        return interpolatedUrl;
      }
      if (text === rawAttr) {
        return interpolatedAttr;
      }
      return text;
    });

    const options: MapLayerOptions<XYZConfig> = {
      name: 'Test Layer',
      type: 'xyz',
      config: {
        url: rawUrl,
        attribution: rawAttr,
      },
    };

    const result = await xyzTiles.create(mockMap, options, mockEventBus, mockTheme);
    const layer = result.init();
    const source = getTileSource(layer, XYZ);

    expect(replaceMock).toHaveBeenCalledWith(rawUrl);
    expect(replaceMock).toHaveBeenCalledWith(rawAttr);
    expect(source.getUrls()).toContain(interpolatedUrl);
    // attribution and url are normalized before use
    expect(source.getAttributions()).toBeDefined();
  });

  describe('noRepeat functionality', () => {
    it('should set wrapX to false when noRepeat is true', async () => {
      const options: MapLayerOptions<XYZConfig> = {
        name: 'Test Layer',
        type: 'xyz',
        config: {
          url: 'https://example.com/{z}/{x}/{y}.png',
          attribution: 'Test Attribution',
        },
        noRepeat: true,
      };

      const result = await xyzTiles.create(mockMap, options, mockEventBus, mockTheme);
      const layer = result.init();

      expect(layer).toBeInstanceOf(TileLayer);
      const source = getTileSource(layer, XYZ);
      expect(source).toBeInstanceOf(XYZ);
      expect(source.getWrapX()).toBe(false);
    });

    it('should set wrapX to true when noRepeat is false', async () => {
      const options: MapLayerOptions<XYZConfig> = {
        name: 'Test Layer',
        type: 'xyz',
        config: {
          url: 'https://example.com/{z}/{x}/{y}.png',
          attribution: 'Test Attribution',
        },
        noRepeat: false,
      };

      const result = await xyzTiles.create(mockMap, options, mockEventBus, mockTheme);
      const layer = result.init();

      const source = getTileSource(layer, XYZ);
      expect(source.getWrapX()).toBe(true);
    });

    it('should set wrapX to true when noRepeat is undefined', async () => {
      const options: MapLayerOptions<XYZConfig> = {
        name: 'Test Layer',
        type: 'xyz',
        config: {
          url: 'https://example.com/{z}/{x}/{y}.png',
          attribution: 'Test Attribution',
        },
      };

      const result = await xyzTiles.create(mockMap, options, mockEventBus, mockTheme);
      const layer = result.init();
      const source = getTileSource(layer, XYZ);
      expect(source.getWrapX()).toBe(true);
    });
  });

  describe('zoom configuration', () => {
    it('should apply minZoom to both Layer and Source', async () => {
      const options: MapLayerOptions<XYZConfig> = {
        name: 'Zoom Test Layer',
        type: 'xyz',
        config: {
          url: 'https://example.com',
          attribution: 'Test Attribution',
          minZoom: 4,
        },
      };

      const result = await xyzTiles.create(mockMap, options, mockEventBus, mockTheme);
      const layer = result.init();
      const source = getTileSource(layer, XYZ);

      expect(layer.getMinZoom()).toBe(4);
      expect(source.getTileGrid()?.getMinZoom()).toBe(4);
    });

    it('should apply maxZoom ONLY to Source (to enable digital zoom)', async () => {
      const options: MapLayerOptions<XYZConfig> = {
        name: 'Digital Zoom Layer',
        type: 'xyz',
        config: {
          url: 'https://example.com',
          attribution: 'Test Attribution',
          maxZoom: 18,
        },
      };

      const result = await xyzTiles.create(mockMap, options, mockEventBus, mockTheme);
      const layer = result.init();
      const source = getTileSource(layer, XYZ);

      expect(layer.getMaxZoom()).toBe(Infinity);
      expect(source.getTileGrid()?.getMaxZoom()).toBe(18);
    });

    it('should handle undefined zoom options correctly', async () => {
      const options: MapLayerOptions<XYZConfig> = {
        name: 'Default Zoom Layer',
        type: 'xyz',
        config: {
          url: 'https://example.com',
          attribution: 'Test Attribution',
        },
      };

      const result = await xyzTiles.create(mockMap, options, mockEventBus, mockTheme);
      const layer = result.init();
      const source = getTileSource(layer, XYZ);

      expect(layer.getMinZoom()).toBe(-Infinity);
      expect(layer.getMaxZoom()).toBe(Infinity);
      expect(source.getTileGrid()?.getMinZoom()).toBe(0);
    });
  });

  describe('tile addresses', () => {
    async function loadFirstTile(url: string) {
      const options: MapLayerOptions<XYZConfig> = { name: 'Tiles', type: 'xyz', config: { url, attribution: '' } };
      const layer = (await xyzTiles.create(mockMap, options, mockEventBus, mockTheme)).init();
      const projection = ensureInstanceOf(getProjection('EPSG:3857'), Projection);
      const tile = ensureInstanceOf(getTileSource(layer, XYZ).getTile(1, 0, 0, 1, projection), ImageTile);
      tile.load();
      return { tile, image: ensureInstanceOf(tile.getImage(), HTMLImageElement) };
    }

    it('loads tiles from another host', async () => {
      const { tile, image } = await loadFirstTile('https://tiles.example.com/{z}/{x}/{y}.png');
      expect(image.getAttribute('src')).toBe('https://tiles.example.com/1/0/0.png');
      expect(tile.getState()).toBe(TileState.LOADING);
    });

    it('does not load a tile whose {a-z} range expands to the Grafana host', async () => {
      const host = window.location.hostname;
      const firstLetterRange = `{${host[0]}-${host[0]}}`;
      const { tile, image } = await loadFirstTile(`http://${firstLetterRange}${host.slice(1)}/logout/{z}`);
      expect(image.getAttribute('src')).toBeNull();
      expect(tile.getState()).toBe(TileState.ERROR);
    });
  });
});
