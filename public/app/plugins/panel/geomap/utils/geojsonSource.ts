import GeoJSON from 'ol/format/GeoJSON';
import VectorSource from 'ol/source/Vector';

/**
 * The URL is saved with the panel, so the request must not carry (or let the response replace) the
 * viewer's cookies. OpenLayers' default XHR loader sends them on same-origin requests.
 */
export function createGeoJSONSource(url: string | undefined): VectorSource {
  const format = new GeoJSON();
  const source: VectorSource = new VectorSource({
    url,
    format,
    loader: (extent, _resolution, projection, success, failure) => {
      if (!url) {
        failure?.();
        return;
      }
      fetch(url, { credentials: 'omit' })
        .then((response) => (response.ok ? response.json() : Promise.reject(new Error(response.statusText))))
        .then((json) => {
          const features = format.readFeatures(json, { extent, featureProjection: projection });
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
