import GeoJSON from 'ol/format/GeoJSON';
import VectorSource from 'ol/source/Vector';

import { mapResourceFetchOptions, resolveMapResourceUrl } from '../../utils/resourceUrl';

/**
 * Resolves a saved GeoJSON source. Relative values are read from the public folder, and a result on
 * this Grafana host must stay inside `public/maps/`.
 */
export function resolveGeoJSONUrl(src: string): string | undefined {
  const publicPath = window.__grafana_public_path__ || 'public/';
  const value = /^https?:\/\//i.test(src) ? src : `${publicPath}${src.replace(/^(public\/)/, '')}`;
  return resolveMapResourceUrl(value, document.baseURI, 'maps/')?.href;
}

/**
 * OpenLayers' own URL loader uses XMLHttpRequest, which sends the viewer's cookies to this host.
 * This loader fetches the already resolved URL without credentials.
 */
export function createGeoJSONSource(url: string | undefined): VectorSource {
  const format = new GeoJSON();
  if (!url) {
    return new VectorSource({ format });
  }

  const source: VectorSource = new VectorSource({
    url,
    format,
    loader: (extent, _resolution, projection, success, failure) => {
      fetch(url, mapResourceFetchOptions)
        .then((response) => {
          if (!response.ok) {
            throw new Error(`Failed to load GeoJSON from ${url}: ${response.status}`);
          }
          return response.text();
        })
        .then((text) => {
          const features = format.readFeatures(text, { extent, featureProjection: projection });
          source.addFeatures(features);
          success?.(features);
        })
        .catch(() => {
          source.removeLoadedExtent(extent);
          failure?.();
        });
    },
  });
  return source;
}
