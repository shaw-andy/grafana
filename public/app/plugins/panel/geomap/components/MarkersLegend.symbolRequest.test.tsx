import { act } from '@testing-library/react';
import type OpenLayersMap from 'ol/Map';

import {
  createTheme,
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
import { render } from 'test/test-utils';

import { type MarkersConfig, markersLayer } from '../layers/data/markersLayer';
import { type NetworkConfig, networkLayer } from '../layers/data/networkLayer';
import { getMarkerMaker, getWebGLStyle } from '../style/markers';
import { defaultStyleConfig, type StyleConfigState } from '../style/types';

import { MarkersLegend } from './MarkersLegend';

jest.mock('app/features/geo/gazetteer/gazetteer', () => ({
  ...jest.requireActual('app/features/geo/gazetteer/gazetteer'),
  getGazetteer: jest.fn().mockResolvedValue(undefined),
}));

// Shipped webpack publicPath. index.html sets <base href="/"> when AppSubURL is empty.
const BUILD_PATH = 'public/build/';
const PAGE = 'http://localhost:3000/';
const ICON_DIRECTORY = '/public/build/img/icons/';

const TRAVERSAL = '../../../../logout';
const ENCODED = '%2e%2e/%2e%2e/%2e%2e/%2e%2e/logout';
const BACKSLASH = '..\\..\\..\\..\\logout';
const PREFIXED = 'img/icons/marker/../../../../../logout';
const SAFE_ICON = 'img/icons/marker/circle.svg';

function resolvedPath(src: string): string {
  return new URL(src, PAGE).pathname;
}

function isIconFile(src: string): boolean {
  const path = resolvedPath(src);
  return path.startsWith(ICON_DIRECTORY) && path.endsWith('.svg');
}

function symbolSources(): string[] {
  return Array.from(document.querySelectorAll('svg'))
    .map((node) => node.getAttribute('id') ?? '')
    .filter((src) => src.length > 0);
}

function styleConfig(symbol: string): StyleConfigState {
  return {
    config: {
      ...defaultStyleConfig,
      color: { fixed: 'dark-green' },
      symbol: { mode: ResourceDimensionMode.Fixed, fixed: symbol },
    },
    base: { color: '#006400', opacity: 0.4 },
    maker: () => [],
  };
}

const pointData = (): PanelData => ({
  state: LoadingState.Done,
  timeRange: getDefaultTimeRange(),
  series: [
    toDataFrame({
      fields: [
        { name: 'time', type: FieldType.time, values: [0] },
        { name: 'lat', type: FieldType.number, values: [46] },
        { name: 'lon', type: FieldType.number, values: [6] },
      ],
    }),
  ],
});

describe('geomap symbol requests', () => {
  beforeEach(() => {
    window.__grafana_build_path__ = BUILD_PATH;
  });

  it.each([TRAVERSAL, ENCODED, BACKSLASH, PREFIXED])(
    'markers legend does not request a symbol that resolves outside the icon directory (%s)',
    (symbol) => {
      render(<MarkersLegend layerName="Markers" styleConfig={styleConfig(symbol)} />);

      const sources = symbolSources();
      expect(sources.every(isIconFile)).toBe(true);
      expect(sources.map(resolvedPath)).not.toContain('/logout');
    }
  );

  it('markers legend still requests a symbol that stays inside the icon directory', () => {
    render(<MarkersLegend layerName="Markers" styleConfig={styleConfig(SAFE_ICON)} />);

    expect(symbolSources().map(resolvedPath)).toEqual(['/public/build/img/icons/marker/circle.svg']);
  });

  it('markers layer passes a saved traversal symbol through to the legend once series data arrives', async () => {
    const options: MapLayerOptions<MarkersConfig> = {
      type: 'markers',
      name: 'Markers',
      location: { mode: FrameGeometrySourceMode.Coords, latitude: 'lat', longitude: 'lon' },
      config: {
        style: {
          ...defaultStyleConfig,
          symbol: { mode: ResourceDimensionMode.Fixed, fixed: TRAVERSAL },
        },
      },
    };
    const handler = await markersLayer.create({} as OpenLayersMap, options, new EventBusSrv(), createTheme());
    handler.update!(pointData());
    render(<>{handler.legend}</>);
    await act(async () => {});

    expect(symbolSources().every(isIconFile)).toBe(true);
    expect(symbolSources().map(resolvedPath)).not.toContain('/logout');
  });

  it('network layer legend requests the same saved symbol when show legend is on', async () => {
    const options: MapLayerOptions<NetworkConfig> = {
      type: 'network',
      name: 'Network',
      location: { mode: FrameGeometrySourceMode.Coords, latitude: 'lat', longitude: 'lon' },
      config: {
        style: {
          ...defaultStyleConfig,
          symbol: { mode: ResourceDimensionMode.Fixed, fixed: ENCODED },
        },
        edgeStyle: defaultStyleConfig,
        arrow: 0,
        showLegend: true,
      },
    };
    const handler = await networkLayer.create({} as OpenLayersMap, options, new EventBusSrv(), createTheme());
    handler.update!(pointData());
    render(<>{handler.legend}</>);
    await act(async () => {});

    expect(symbolSources().every(isIconFile)).toBe(true);
    expect(symbolSources().map(resolvedPath)).not.toContain('/logout');
  });

  it('map icon loading does not fetch a symbol that normalizes outside the icon directory', async () => {
    const calls: string[] = [];
    const original = global.fetch;
    global.fetch = jest.fn(async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response('<svg xmlns="http://www.w3.org/2000/svg"></svg>', {
        status: 200,
        headers: { 'content-type': 'image/svg+xml' },
      });
    }) as typeof fetch;

    try {
      await getMarkerMaker(`${TRAVERSAL}.svg`, false);
      await getWebGLStyle(`${ENCODED}.svg`);
    } finally {
      global.fetch = original;
    }

    expect(calls.every(isIconFile)).toBe(true);
    expect(calls.map(resolvedPath)).not.toContain('/logout.svg');
  });
});
