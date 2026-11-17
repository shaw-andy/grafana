import type { Extent } from 'ol/extent';
import { get as getProjection } from 'ol/proj';
import { renderFeature } from 'ol/renderer/vector';
import type VectorSource from 'ol/source/Vector';
import type { Style } from 'ol/style';

import {
  EventBusSrv,
  FieldType,
  FrameGeometrySourceMode,
  getDefaultTimeRange,
  LoadingState,
  type MapLayerOptions,
  type PanelData,
  toDataFrame,
} from '@grafana/data';
import { ResourceDimensionMode } from '@grafana/schema';

import type { GeomapPanel } from './GeomapPanel';
import type { MapLayerState } from './types';
import { initLayer } from './utils/layers';

const LAST_POINT = 'last-point-tracker';
const DYNAMIC_GEOJSON = 'dynamic-geojson';
const GEOJSON = 'geojson';
const XYZ = 'xyz';
const ESRI_XYZ = 'esri-xyz';
const MAPLIBRE = 'maplibre';
const MARKERS = 'markers';

jest.mock('ol-mapbox-style', () => ({
  apply: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('geotiff', () => ({}));
jest.mock('app/features/geo/gazetteer/gazetteer', () => ({
  ...jest.requireActual('app/features/geo/gazetteer/gazetteer'),
  getGazetteer: jest.fn().mockResolvedValue(undefined),
}));

const replace = jest.fn((value: string) => value);
jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  getTemplateSrv: () => ({ replace }),
}));

// OpenLayers loads an icon when the canvas renderer draws a feature that is inside the view,
// which is after the style object has merely stored the address.
const WORLD: Extent = [-20037508.342789244, -20037508.342789244, 20037508.342789244, 20037508.342789244];

const pointData = (): PanelData => ({
  state: LoadingState.Done,
  timeRange: getDefaultTimeRange(),
  series: [
    toDataFrame({
      fields: [
        { name: 'time', type: FieldType.time, values: [0] },
        { name: 'lat', type: FieldType.number, values: [20] },
        { name: 'lon', type: FieldType.number, values: [60] },
      ],
    }),
  ],
});

const emptyData = (): PanelData => ({
  state: LoadingState.Done,
  timeRange: getDefaultTimeRange(),
  series: [],
});

function createPanel(data: PanelData = emptyData()): GeomapPanel {
  return {
    map: {},
    layers: [],
    byName: new Map<string, MapLayerState>(),
    props: { eventBus: new EventBusSrv(), data, options: { controls: {} } },
  } as unknown as GeomapPanel;
}

function sameOriginLogout(extra = ''): string {
  return new URL(`/logout${extra}`, window.location.href).href;
}

function requestsLogout(urls: string[]): string[] {
  return urls.filter((url) => {
    try {
      const parsed = new URL(url, window.location.href);
      return parsed.origin === window.location.origin && parsed.pathname === '/logout';
    } catch {
      return false;
    }
  });
}

function tapCredentialedRequests(): { urls: string[]; restore: () => void } {
  const urls: string[] = [];
  const originalFetch = window.fetch;
  window.fetch = ((input: RequestInfo | URL) => {
    if (typeof input === 'string') {
      urls.push(input);
    } else if (input instanceof URL) {
      urls.push(input.href);
    } else {
      urls.push(input.url);
    }
    return Promise.resolve(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }));
  }) as typeof window.fetch;

  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (this: XMLHttpRequest, ...args: Parameters<XMLHttpRequest['open']>) {
    urls.push(String(args[1]));
    return originalOpen.apply(this, args as unknown as Parameters<XMLHttpRequest['open']>);
  } as typeof XMLHttpRequest.prototype.open;

  const src = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
  if (!src?.get || !src.set) {
    throw new Error('HTMLImageElement.src cannot be observed');
  }
  Object.defineProperty(HTMLImageElement.prototype, 'src', {
    configurable: true,
    enumerable: src.enumerable,
    get() {
      return src.get!.call(this);
    },
    set(value: string) {
      urls.push(String(value));
      src.set!.call(this, value);
    },
  });

  return {
    urls,
    restore() {
      window.fetch = originalFetch;
      XMLHttpRequest.prototype.open = originalOpen;
      Object.defineProperty(HTMLImageElement.prototype, 'src', src);
    },
  };
}

async function initSavedLayer(type: string, config: object, data?: PanelData): Promise<MapLayerState> {
  return initLayer(
    createPanel(data),
    {} as never,
    { type, name: type, config } as MapLayerOptions,
    type === ESRI_XYZ || type === XYZ || type === MAPLIBRE
  );
}

function drawFeaturesInView(state: MapLayerState) {
  const source = (state.layer as { getSource?: () => VectorSource }).getSource?.();
  if (!source || typeof source.getFeaturesInExtent !== 'function') {
    throw new Error('expected a vector source');
  }
  const features = source.getFeaturesInExtent(WORLD);
  expect(features).not.toHaveLength(0);
  for (const feature of features) {
    const styled = feature.getStyleFunction()?.(feature, 1);
    const styles = (Array.isArray(styled) ? styled : styled ? [styled] : []) as Style[];
    for (const style of styles) {
      try {
        renderFeature(undefined as never, feature, style, 0, () => undefined, undefined, false, 0);
      } catch {
        // Drawing asks the replay group for a builder only after the icon image has started loading.
      }
    }
  }
}

function loadVectorUrl(state: MapLayerState) {
  const source = (state.layer as { getSource?: () => VectorSource }).getSource?.();
  if (!source || typeof source.loadFeatures !== 'function') {
    throw new Error('expected a vector source');
  }
  source.loadFeatures(WORLD, 1, getProjection('EPSG:3857')!);
}

function loadTile(state: MapLayerState) {
  const source = (state.layer as { getSource?: () => { getTile: Function } }).getSource?.();
  if (!source || typeof source.getTile !== 'function') {
    throw new Error('expected a tile source');
  }
  const tile = source.getTile(0, 0, 0, 1, getProjection('EPSG:3857'));
  tile.load();
}

describe('saved geomap layer addresses', () => {
  let tap: ReturnType<typeof tapCredentialedRequests>;

  beforeEach(() => {
    replace.mockClear();
    replace.mockImplementation((value: string) => value);
    window.__grafana_public_path__ = `${window.location.origin}/public/`;
    tap = tapCredentialedRequests();
  });

  afterEach(() => {
    tap.restore();
  });

  it('does not load a saved last-point icon from the logout path', async () => {
    const state = await initSavedLayer(LAST_POINT, { icon: '/logout' }, pointData());
    drawFeaturesInView(state);
    expect(requestsLogout(tap.urls)).toEqual([]);
  });

  it('does not load a saved last-point icon from a same-origin logout URL', async () => {
    const state = await initSavedLayer(LAST_POINT, { icon: sameOriginLogout() }, pointData());
    drawFeaturesInView(state);
    expect(requestsLogout(tap.urls)).toEqual([]);
  });

  it('does not load a saved last-point icon whose path normalizes to logout', async () => {
    const state = await initSavedLayer(LAST_POINT, { icon: '/public/../logout' }, pointData());
    drawFeaturesInView(state);
    expect(requestsLogout(tap.urls)).toEqual([]);
  });

  it('does not fetch a saved dynamic geojson address from the logout path', async () => {
    const state = await initSavedLayer(DYNAMIC_GEOJSON, { src: '/logout' });
    loadVectorUrl(state);
    expect(requestsLogout(tap.urls)).toEqual([]);
  });

  it('does not fetch a saved geojson address from a same-origin logout URL', async () => {
    const state = await initSavedLayer(GEOJSON, { src: sameOriginLogout() });
    loadVectorUrl(state);
    expect(requestsLogout(tap.urls)).toEqual([]);
  });

  it('does not request a saved xyz tile address whose path is logout', async () => {
    const state = await initSavedLayer(XYZ, { url: '/logout?z={z}&x={x}&y={y}' });
    loadTile(state);
    expect(requestsLogout(tap.urls)).toEqual([]);
  });

  it('does not request a saved arcgis tile address whose path is logout', async () => {
    const state = await initSavedLayer(ESRI_XYZ, {
      server: 'custom',
      url: '/logout?z={z}&x={x}&y={y}',
    });
    loadTile(state);
    expect(requestsLogout(tap.urls)).toEqual([]);
  });

  it('does not fetch a saved maplibre style from the logout path', async () => {
    await initSavedLayer(MAPLIBRE, { url: '/logout' });
    expect(requestsLogout(tap.urls)).toEqual([]);
  });

  it('does not fetch a saved marker symbol whose request path is logout', async () => {
    await initSavedLayer(MARKERS, {
      showLegend: false,
      style: {
        symbol: { mode: ResourceDimensionMode.Fixed, fixed: sameOriginLogout('?.svg') },
      },
    });
    expect(requestsLogout(tap.urls)).toEqual([]);
  });
});
