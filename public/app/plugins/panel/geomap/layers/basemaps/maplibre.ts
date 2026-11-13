import LayerGroup from 'ol/layer/Group';
import { apply } from 'ol-mapbox-style';

import { type MapLayerRegistryItem } from '@grafana/data';

import { mapResourceFetchOptions, resolveMapResourceUrl } from '../../utils/resourceUrl';

// MapLibre Style Specification constants
const LAYER_TYPE_BACKGROUND = 'background';
const PAINT_BACKGROUND_OPACITY = 'background-opacity';
const WEBFONTS_METADATA = 'ol:webfonts';

export interface MaplibreConfig {
  url: string;
  accessToken?: string;
}

const sampleURL = 'https://tiles.stadiamaps.com/styles/alidade_smooth.json';

const defaultMaplibreConfig: MaplibreConfig = {
  url: sampleURL,
};

/**
 * Saved panel options are only ever partial, so fill in the gaps once here and let everything
 * downstream work with a complete config.
 */
function resolveMaplibreConfig(config: Partial<MaplibreConfig> = {}): MaplibreConfig {
  return { ...config, url: config.url || defaultMaplibreConfig.url };
}

interface StyleWithMetadata {
  metadata?: Record<string, unknown>;
}

/**
 * ol-mapbox-style fills this template with font names from the style and adds it as a stylesheet link,
 * which carries the viewer's cookies. Keep it only when the host is fixed before any placeholder and is
 * not this Grafana server.
 */
function withSafeWebfonts<T extends StyleWithMetadata>(style: T): T {
  const template = style?.metadata?.[WEBFONTS_METADATA];
  if (template === undefined) {
    return style;
  }
  const fixedOrigin = typeof template === 'string' ? /^https?:\/\/[^/\\?#{}]+\//i.exec(template)?.[0] : undefined;
  if (fixedOrigin && resolveMapResourceUrl(fixedOrigin, document.baseURI, 'maps/')) {
    return style;
  }
  const metadata = { ...style.metadata };
  delete metadata[WEBFONTS_METADATA];
  return { ...style, metadata };
}

/**
 * Every style, source, sprite and tile request ol-mapbox-style makes goes through here, so URLs taken
 * from a style document are held to the same rules as the configured style URL.
 */
function transformRequest(url: string, resourceType: string): Request | Promise<Response> {
  const resolved = resolveMapResourceUrl(url, document.baseURI, 'maps/');
  if (!resolved) {
    return Promise.reject(new Error(`MapLibre layer: not loading ${resourceType} from "${url}"`));
  }
  const request = new Request(resolved.href, mapResourceFetchOptions);
  if (resourceType !== 'Style') {
    return request;
  }
  return fetch(request)
    .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`Failed to load MapLibre style from ${url}`))))
    .then((style) => new Response(JSON.stringify(withSafeWebfonts(style))));
}

const maplibreLayer: MapLayerRegistryItem<Partial<MaplibreConfig>> = {
  id: 'maplibre',
  name: 'MapLibre layer',
  description: 'Add layer using MapLibre style.json URL',
  isBaseMap: true,
  // Attribution comes from the style, so the tile provider terms are unknown here
  requiresAttribution: true,

  create: async (_map, options) => ({
    init: () => {
      const cfg = resolveMaplibreConfig(options.config);
      const layerOpacity = options.opacity ?? 1;
      const noRepeat = options.noRepeat ?? false;
      const layer = new LayerGroup({
        opacity: layerOpacity,
      });

      const applyNoRepeat = () => {
        if (noRepeat) {
          // Set wrapX: false on the first layer source to prevent world repetition
          const firstLayer = layer.getLayers().item(0);
          if (firstLayer && 'getSource' in firstLayer && typeof firstLayer.getSource === 'function') {
            const source = firstLayer.getSource();
            if (source && 'setWrapX' in source && typeof source.setWrapX === 'function') {
              source.setWrapX(false);
            }
          }
        }
      };

      // Handle async operations in the background
      const loadStyle = async () => {
        try {
          const styleUrl = resolveMapResourceUrl(cfg.url, document.baseURI, 'maps/');
          if (!styleUrl) {
            // mapbox:// style URLs are resolved by ol-mapbox-style and checked again in transformRequest
            await tryFallbackApply();
            return;
          }
          const res = await fetch(styleUrl.href, mapResourceFetchOptions);
          if (!res.ok) {
            console.warn(`Failed to load MapLibre style from ${cfg.url}: ${res.status} ${res.statusText}`);
            // Try fallback approach
            await tryFallbackApply();
            return;
          }

          const style = await res.json();

          // Adjust background opacity - let LayerGroup opacity handle everything else
          if (Array.isArray(style?.layers)) {
            for (const l of style.layers) {
              if (l && l.type === LAYER_TYPE_BACKGROUND) {
                l.paint = l.paint || {};
                l.paint[PAINT_BACKGROUND_OPACITY] = layerOpacity;
              }
            }
          }

          await apply(layer, withSafeWebfonts(style), {
            styleUrl: styleUrl.href,
            accessToken: cfg.accessToken,
            transformRequest,
          });
          applyNoRepeat();
        } catch (error) {
          console.warn('Failed to parse or apply MapLibre style JSON:', error);
          // Try fallback approach
          await tryFallbackApply();
        }
      };

      const tryFallbackApply = async () => {
        try {
          await apply(layer, cfg.url, { accessToken: cfg.accessToken, transformRequest });
          applyNoRepeat();
        } catch (fallbackError) {
          console.warn('Failed to load MapLibre style from both JSON and direct URL approaches:', fallbackError);
        }
      };

      // Start loading the style asynchronously
      loadStyle();

      return layer;
    },
    registerOptionsUI: (builder) => {
      builder
        .addTextInput({
          path: 'config.url',
          name: 'URL template',
          description: 'URL to the styles.json file.',
          settings: {
            placeholder: defaultMaplibreConfig.url,
          },
        })
        .addTextInput({
          path: 'config.accessToken',
          name: 'Public access token',
          description: 'Public access token for mapbox:// urls',
          settings: {
            placeholder: '',
          },
        });
    },
  }),
};

export const maplibreLayers = [maplibreLayer];
