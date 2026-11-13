import { act, render } from '@testing-library/react';
import { createElement } from 'react';
import { lastValueFrom, of } from 'rxjs';

// lastPointTracker imports the ol/source barrel, which pulls geotiff's untransformed ESM.
jest.mock('ol/source', () => ({
  Vector: jest.requireActual('ol/source/Vector').default,
}));

import {
  createTheme,
  EventBusSrv,
  FieldType,
  FrameGeometrySourceMode,
  type MapLayerOptions,
  toDataFrame,
} from '@grafana/data';
import { type FrameGeometrySource } from '@grafana/schema';
import { GazetteerPathEditor } from 'app/features/geo/editor/GazetteerPathEditor';
import { fieldLookupTransformer } from 'app/features/transformers/lookupGazetteer/fieldLookup';
import { SpatialAction, SpatialOperation } from 'app/features/transformers/spatial/models.gen';
import { getSpatialTransformer } from 'app/features/transformers/spatial/spatialTransformer';
import { heatmapLayer } from 'app/plugins/panel/geomap/layers/data/heatMap';
import { lastPointTracker } from 'app/plugins/panel/geomap/layers/data/lastPointTracker';
import { markersLayer } from 'app/plugins/panel/geomap/layers/data/markersLayer';
import { networkLayer } from 'app/plugins/panel/geomap/layers/data/networkLayer';
import { photosLayer } from 'app/plugins/panel/geomap/layers/data/photosLayer';
import { routeLayer } from 'app/plugins/panel/geomap/layers/data/routeLayer';

import { getLocationMatchers } from '../utils/location';

import { GAZETTEER_OPTIONS, getGazetteer } from './gazetteer';

/**
 * A gazetteer fetch is unsafe when the URL the browser would actually request is a
 * same-origin application route, or when the request still uses the viewer's session.
 * Resolving with the document base catches a check of the raw path that then fetches
 * a rewritten or relative URL.
 */
interface RecordedFetch {
  input: string;
  credentials: RequestCredentials;
  href: string;
}

const recorded: RecordedFetch[] = [];
const transformContext = { interpolate: (value: string) => value };

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  return input.url;
}

function builtinGazetteerDirectory(): URL {
  const base = window.__grafana_build_path__.endsWith('/')
    ? window.__grafana_build_path__
    : `${window.__grafana_build_path__}/`;
  return new URL('gazetteer/', new URL(base, window.location.href));
}

function isBuiltinGazetteerFile(href: string): boolean {
  const url = new URL(href);
  const directory = builtinGazetteerDirectory();
  if (url.origin !== directory.origin || !url.pathname.startsWith(directory.pathname)) {
    return false;
  }
  const rest = decodeURIComponent(url.pathname.slice(directory.pathname.length));
  return rest.length > 0 && rest.split('/').every((part) => part !== '' && part !== '.' && part !== '..');
}

function installFetchRecorder() {
  recorded.length = 0;
  jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = requestUrl(input);
    recorded.push({
      input: raw,
      credentials: new Request(raw, init).credentials,
      href: new URL(raw, window.location.href).href,
    });
    return new Response(JSON.stringify({ type: 'FeatureCollection', features: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  });
}

function unsafeFetches() {
  return recorded
    .map((call) => {
      const sameOriginApplication =
        new URL(call.href).origin === window.location.origin && !isBuiltinGazetteerFile(call.href);
      return {
        href: call.href,
        credentials: call.credentials,
        sameOriginApplication,
      };
    })
    .filter((call) => call.sameOriginApplication || call.credentials !== 'omit');
}

function expectViewerSessionNotAttached() {
  expect(unsafeFetches()).toEqual([]);
}

function lookupSource(gazetteer: string): FrameGeometrySource {
  return {
    mode: FrameGeometrySourceMode.Lookup,
    gazetteer,
    lookup: 'name',
  };
}

function layerOptions<TConfig>(type: string, gazetteer: string, config: TConfig): MapLayerOptions<TConfig> {
  return {
    type,
    name: type,
    location: lookupSource(gazetteer),
    config,
  };
}

async function loadThrough(run: () => Promise<unknown>) {
  recorded.length = 0;
  try {
    await run();
  } catch {
    // The request is already on the wire before a later parse or render error.
  }
  expectViewerSessionNotAttached();
}

describe('gazetteer requests must not carry the viewer session', () => {
  beforeAll(() => {
    window.__grafana_build_path__ = `${window.location.origin}/public/build/`;
  });

  beforeEach(() => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    installFetchRecorder();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('still loads the built-in gazetteer files, without the viewer session', async () => {
    const origin = window.location.origin;
    const loaded: Array<[string, RequestCredentials]> = [];
    for (const path of [GAZETTEER_OPTIONS.usaStates.path, 'public/gazetteer/airports.geojson', undefined]) {
      recorded.length = 0;
      await getGazetteer(path);
      loaded.push(...recorded.map((call): [string, RequestCredentials] => [call.href, call.credentials]));
    }
    expect(loaded).toEqual([
      [`${origin}/public/build/gazetteer/usa-states.json`, 'omit'],
      [`${origin}/public/build/gazetteer/airports.geojson`, 'omit'],
      [`${origin}/public/build/gazetteer/countries.json`, 'omit'],
    ]);
  });

  it('does not request a same-origin application path chosen as the gazetteer', async () => {
    const origin = window.location.origin;
    const paths = [
      '/logout',
      '/logout?redirect=/',
      '/api/user',
      '/api/org',
      `${origin}/logout`,
      `${origin}/api/datasources`,
      `//${window.location.host}/logout`,
      'public/gazetteer/../../../logout',
      '/%6Cogout',
    ];

    const failures: Array<{ path: string; unsafe: ReturnType<typeof unsafeFetches> }> = [];
    for (const path of paths) {
      recorded.length = 0;
      await getGazetteer(path);
      const unsafe = unsafeFetches();
      if (unsafe.length > 0) {
        failures.push({ path, unsafe });
      }
    }
    expect(failures).toEqual([]);
  });

  it('does not attach the viewer session when a custom http(s) gazetteer is loaded', async () => {
    await getGazetteer('https://example.com/gazetteer.json');
    expectViewerSessionNotAttached();
  });

  it('loads the gazetteer selected for a location matcher without the viewer session', async () => {
    await loadThrough(() => getLocationMatchers(lookupSource('/logout?via=location')));
  });

  it('loads the gazetteer for a field lookup without the viewer session', async () => {
    const frame = toDataFrame({
      fields: [{ name: 'name', type: FieldType.string, values: ['US'] }],
    });
    await loadThrough(() =>
      lastValueFrom(
        of([frame]).pipe(
          fieldLookupTransformer.operator({ lookupField: 'name', gazetteer: '/api/folders' }, transformContext)
        )
      )
    );
  });

  it('loads both gazetteers for a spatial line without the viewer session', async () => {
    await loadThrough(() =>
      lastValueFrom(
        of([]).pipe(
          getSpatialTransformer().operator(
            {
              action: SpatialAction.Modify,
              source: lookupSource('/logout?via=spatial-source'),
              modify: {
                op: SpatialOperation.LineBuilder,
                target: lookupSource('/logout?via=spatial-target'),
              },
            },
            transformContext
          )
        )
      )
    );
  });

  it.each([
    ['markers', '/logout?via=markers', markersLayer, { style: { symbol: { fixed: 'circle' } }, showLegend: false }],
    ['route', '/logout?via=route', routeLayer, { style: { symbol: { fixed: 'circle' } } }],
    [
      'photos',
      '/logout?via=photos',
      photosLayer,
      { kind: 'square', border: 0, shadow: false, crop: false, radius: 1, color: '#fff' },
    ],
    ['heatmap', '/logout?via=heatmap', heatmapLayer, { weight: { fixed: 1, min: 0, max: 1 }, blur: 1, radius: 1 }],
    [
      'network',
      '/logout?via=network',
      networkLayer,
      { style: { symbol: { fixed: 'circle' } }, edgeStyle: { symbol: { fixed: 'circle' } }, showLegend: false },
    ],
    ['last point', '/logout?via=last', lastPointTracker, { icon: 'data:,' }],
  ] as const)('loads the %s layer gazetteer without the viewer session', async (type, gazetteer, layer, config) => {
    const options = layerOptions(type, gazetteer, config);
    await loadThrough(() => layer.create({} as never, options, new EventBusSrv(), createTheme()));
  });

  it('loads the gazetteer shown in the path editor without the viewer session', async () => {
    await loadThrough(async () => {
      await act(async () => {
        render(
          createElement(GazetteerPathEditor, {
            value: '/logout?via=editor',
            onChange: () => undefined,
            context: { data: [] },
            item: { id: 'gazetteer', name: 'Gazetteer', editor: GazetteerPathEditor },
          })
        );
        await new Promise((resolve) => setTimeout(resolve, 0));
        await new Promise((resolve) => setTimeout(resolve, 0));
      });
    });
  });
});
