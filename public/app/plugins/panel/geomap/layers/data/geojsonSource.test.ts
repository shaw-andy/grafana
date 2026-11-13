import { get as getProjection } from 'ol/proj';

import { createGeoJSONSource, resolveGeoJSONUrl } from './geojsonSource';

const featureCollection = JSON.stringify({
  type: 'FeatureCollection',
  features: [{ type: 'Feature', id: 'a', geometry: { type: 'Point', coordinates: [1, 2] }, properties: {} }],
});

function loadAll(source: ReturnType<typeof createGeoJSONSource>) {
  const projection = getProjection('EPSG:3857')!;
  source.loadFeatures(projection.getExtent(), 1000, projection);
}

describe('resolveGeoJSONUrl', () => {
  beforeEach(() => {
    window.__grafana_public_path__ = 'http://localhost/public/';
  });

  it('reads a relative path from the public folder, not the dashboard URL', () => {
    expect(resolveGeoJSONUrl('public/maps/countries.geojson')).toBe('http://localhost/public/maps/countries.geojson');
  });

  it.each(['/logout', '../../logout', '//localhost/logout', 'http://localhost/logout'])('refuses %s', (src) => {
    expect(resolveGeoJSONUrl(src)).toBeUndefined();
  });
});

describe('createGeoJSONSource', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('loads the URL without credentials and adds the features', async () => {
    const fetchSpy = jest.spyOn(global, 'fetch').mockResolvedValue(new Response(featureCollection, { status: 200 }));
    const source = createGeoJSONSource('https://maps.example.com/borders.geojson');
    loadAll(source);

    await new Promise((resolve) => source.once('change', resolve));
    expect(fetchSpy).toHaveBeenCalledWith('https://maps.example.com/borders.geojson', { credentials: 'omit' });
    expect(source.getFeatures().map((f) => f.getId())).toEqual(['a']);
  });

  it('adds no features when the response fails', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValue(new Response('nope', { status: 404 }));
    const source = createGeoJSONSource('https://maps.example.com/missing.geojson');
    const failed = new Promise((resolve) => source.once('featuresloaderror', resolve));
    loadAll(source);

    await failed;
    expect(source.getFeatures()).toEqual([]);
  });

  it('makes no request without a URL', () => {
    const fetchSpy = jest.spyOn(global, 'fetch');
    const source = createGeoJSONSource(undefined);
    loadAll(source);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
