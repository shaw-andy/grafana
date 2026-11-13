import type Feature from 'ol/Feature';
import type OpenLayersMap from 'ol/Map';
import VectorImage from 'ol/layer/VectorImage';
import Photo from 'ol-ext/style/Photo';

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

import { ensureInstanceOf } from '../test-utils';

import { type PhotoConfig, photosLayer } from './photosLayer';

jest.mock('app/features/geo/gazetteer/gazetteer', () => ({
  ...jest.requireActual('app/features/geo/gazetteer/gazetteer'),
  getGazetteer: jest.fn().mockResolvedValue(undefined),
}));

const defaultConfig: PhotoConfig = {
  kind: 'square',
  border: 2,
  shadow: true,
  crop: true,
  radius: 20,
  color: 'rgb(200, 200, 200)',
};

const photoData = (urls: string[], fieldName = 'photo'): PanelData => ({
  state: LoadingState.Done,
  timeRange: getDefaultTimeRange(),
  series: [
    toDataFrame({
      fields: [
        { name: 'time', type: FieldType.time, values: urls.map((_, i) => i) },
        { name: 'lat', type: FieldType.number, values: urls.map((_, i) => 46 + i) },
        { name: 'lon', type: FieldType.number, values: urls.map((_, i) => 6 + i) },
        { name: fieldName, type: FieldType.string, values: urls },
      ],
    }),
  ],
});

async function setup(config: Partial<PhotoConfig> = {}) {
  const options: MapLayerOptions<PhotoConfig> = {
    type: 'photos',
    name: 'Photos',
    location: { mode: FrameGeometrySourceMode.Coords, latitude: 'lat', longitude: 'lon' },
    config: { ...defaultConfig, ...config },
  };
  const handler = await photosLayer.create({} as OpenLayersMap, options, new EventBusSrv(), createTheme());
  return { handler, layer: ensureInstanceOf<VectorImage>(handler.init(), VectorImage) };
}

const safePhotoA = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
const safePhotoB = 'data:image/gif;base64,R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=';

/** The layer renders a stack of styles per feature; the photo itself is always the last one */
function photoElement(layer: VectorImage, feature: Feature): HTMLImageElement {
  const styles = layer.getStyleFunction()!(feature, 1);
  if (!Array.isArray(styles)) {
    throw new Error('expected a stack of styles');
  }
  return ensureInstanceOf(styles[styles.length - 1].getImage(), Photo).getPhoto();
}

function photoSrc(layer: VectorImage, feature: Feature): string {
  return photoElement(layer, feature).src;
}

type NetLoad = { via: 'image' | 'fetch' | 'xhr'; url: string; credentials?: string; redirect?: string };

/**
 * Records the addresses Photo hands to the browser while the style function runs.
 * ol-ext assigns `img.src` with no crossOrigin, which is a no-cors image request.
 */
function capturePhotoLoads(run: () => void): NetLoad[] {
  const loads: NetLoad[] = [];
  const proto = HTMLImageElement.prototype;
  const desc = Object.getOwnPropertyDescriptor(proto, 'src');
  if (!desc?.set || !desc.get || !desc.configurable) {
    throw new Error('HTMLImageElement.src cannot be observed');
  }
  Object.defineProperty(proto, 'src', {
    configurable: true,
    enumerable: desc.enumerable ?? true,
    get() {
      return desc.get!.call(this);
    },
    set(value: string) {
      loads.push({ via: 'image', url: String(value) });
      desc.set!.call(this, value);
    },
  });

  const originalFetch = window.fetch;
  window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const request = typeof Request !== 'undefined' && input instanceof Request ? input : undefined;
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    loads.push({
      via: 'fetch',
      url,
      credentials: init?.credentials ?? request?.credentials ?? 'same-origin',
      redirect: init?.redirect ?? request?.redirect ?? 'follow',
    });
    return originalFetch.call(window, input, init);
  }) as typeof window.fetch;

  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function open(
    method: string,
    url: string | URL,
    async?: boolean,
    username?: string | null,
    password?: string | null
  ) {
    loads.push({ via: 'xhr', url: String(url) });
    return originalOpen.call(this, method, url, async ?? true, username, password);
  };

  try {
    run();
  } finally {
    Object.defineProperty(proto, 'src', desc);
    window.fetch = originalFetch;
    XMLHttpRequest.prototype.open = originalOpen;
  }
  return loads;
}

/** data and blob URLs are not fetched with the session cookie. http(s) and path URLs are. */
function expectCredentialFreeAddress(src: string) {
  const resolved = new URL(src, window.location.href);
  expect(['data:', 'blob:']).toContain(resolved.protocol);
}

function expectLoadsStayCredentialFree(loads: NetLoad[]) {
  const images = loads.filter((load) => load.via === 'image');
  expect(images.length).toBeGreaterThan(0);
  for (const load of images) {
    expectCredentialFreeAddress(load.url);
  }
  for (const load of loads) {
    if (load.via === 'fetch') {
      expect(load.credentials).toBe('omit');
      expect(load.redirect === 'manual' || load.redirect === 'error').toBe(true);
      expect(new URL(load.url, window.location.href).hostname).not.toBe(window.location.hostname);
    }
    if (load.via === 'xhr') {
      expectCredentialFreeAddress(load.url);
    }
  }
}

describe('photosLayer', () => {
  it('update() adds one feature per row', async () => {
    const { handler, layer } = await setup();
    handler.update!(photoData(['a.png', 'b.png', 'c.png']));
    expect(layer.getSource()!.getFeatures()).toHaveLength(3);
  });

  it('update() clears the features when there is no data', async () => {
    const { handler, layer } = await setup();
    handler.update!(photoData(['a.png']));
    handler.update!({ state: LoadingState.Done, timeRange: getDefaultTimeRange(), series: [] });
    expect(layer.getSource()!.getFeatures()).toHaveLength(0);
  });

  it('renders each feature with the image from the configured source field', async () => {
    const { handler, layer } = await setup({ src: 'photo' });
    handler.update!(photoData([safePhotoA, safePhotoB]));

    const [first, second] = layer.getSource()!.getFeatures();
    expect(photoSrc(layer, first)).toBe(safePhotoA);
    expect(photoSrc(layer, second)).toBe(safePhotoB);
  });

  it('falls back to the first string field when no source field is configured', async () => {
    const { handler, layer } = await setup();
    handler.update!(photoData([safePhotoA], 'someOtherName'));

    const [first] = layer.getSource()!.getFeatures();
    expect(photoSrc(layer, first)).toBe(safePhotoA);
  });

  const otherPort = window.location.port === '1' ? '2' : '1';
  const credentialedAddresses: Array<[string, string]> = [
    ['a root-relative path', '/logout'],
    ['a path relative to the current page', 'logout'],
    ['a root-relative path with a leading space', ' /logout'],
    ['a protocol-relative URL on this host', `//${window.location.host}/logout`],
    ['an absolute URL on this origin', `${window.location.origin}/logout`],
    [
      'an absolute URL on this hostname and another port',
      `${window.location.protocol}//${window.location.hostname}:${otherPort}/logout`,
    ],
    ['a percent-encoded path on this origin', '/%6Cogout'],
    ['a cross-origin http(s) URL', 'https://cdn.example/photo.png'],
  ];

  const fieldSources: Array<[string, Partial<PhotoConfig>, string]> = [
    ['the configured source field', { src: 'photo' }, 'photo'],
    ['the first string field', {}, 'caption'],
  ];

  describe('session cookie', () => {
    it.each(
      fieldSources.flatMap(([source, config, fieldName]) =>
        credentialedAddresses.map(([label, value]) => ({ source, config, fieldName, label, value }))
      )
    )('does not load $label from $source as a photo', async ({ config, fieldName, value }) => {
      const { handler, layer } = await setup(config);
      const loads = capturePhotoLoads(() => {
        handler.update!(photoData([value], fieldName));
        for (const feature of layer.getSource()!.getFeatures()) {
          expectCredentialFreeAddress(photoSrc(layer, feature));
        }
      });
      expectLoadsStayCredentialFree(loads);
    });

    it('keeps a data URL on one row while refusing a same-origin path on another', async () => {
      const { handler, layer } = await setup({ src: 'photo' });
      const loads = capturePhotoLoads(() => {
        handler.update!(photoData([safePhotoA, '/logout']));
        const [first, second] = layer.getSource()!.getFeatures();
        expect(photoSrc(layer, first)).toBe(safePhotoA);
        expectCredentialFreeAddress(photoSrc(layer, second));
      });
      expectLoadsStayCredentialFree(loads);
    });
  });
});
