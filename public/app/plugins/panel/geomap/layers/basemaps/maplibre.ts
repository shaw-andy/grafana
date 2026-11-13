import LayerGroup from 'ol/layer/Group';
import { apply } from 'ol-mapbox-style';

import { type MapLayerRegistryItem } from '@grafana/data';

// MapLibre Style Specification constants
const LAYER_TYPE_BACKGROUND = 'background';
const PAINT_BACKGROUND_OPACITY = 'background-opacity';

// ol-mapbox-style loads label fonts by adding a stylesheet <link> built from this template and the
// font names, which bypasses transformRequest and sends cookies. A template without placeholders
// keeps a style, or the tiles feeding its font expressions, from pointing that link anywhere.
const WEBFONTS_METADATA = 'ol:webfonts';
const NO_WEBFONTS = 'data:text/css,';

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

/**
 * The style URL is chosen by an editor but loaded by every viewer, and the style names further URLs
 * of its own. None of them may reach Grafana itself, and none may carry the viewer's credentials.
 */
function toExternalUrl(url: string): string | undefined {
  let target: URL;
  try {
    target = new URL(url, window.location.href);
  } catch {
    return undefined;
  }
  return target.origin === window.location.origin ? undefined : target.href;
}

function transformRequest(url: string, type: string, layerOpacity: number) {
  const target = toExternalUrl(url);
  if (!target) {
    return Response.error();
  }
  if (type === 'Style') {
    return fetchStyle(target, layerOpacity).then((style) => new Response(JSON.stringify(style)));
  }
  return new Request(target, { credentials: 'omit' });
}

async function fetchStyle(url: string, layerOpacity: number) {
  const res = await fetch(url, { credentials: 'omit' });
  if (!res.ok) {
    throw new Error(`Failed to load MapLibre style from ${url}: ${res.status} ${res.statusText}`);
  }
  const style = await res.json();
  if (typeof style !== 'object' || style === null) {
    throw new Error(`MapLibre style from ${url} is not a JSON object`);
  }

  // Adjust background opacity - let LayerGroup opacity handle everything else
  if (Array.isArray(style?.layers)) {
    for (const l of style.layers) {
      if (l && l.type === LAYER_TYPE_BACKGROUND) {
        l.paint = l.paint || {};
        l.paint[PAINT_BACKGROUND_OPACITY] = layerOpacity;
      }
    }
  }
  style.metadata = { ...style.metadata, [WEBFONTS_METADATA]: NO_WEBFONTS };
  return style;
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

      const styleUrl = toExternalUrl(cfg.url);
      const applyOptions = {
        accessToken: cfg.accessToken,
        transformRequest: (url: string, type: string) => transformRequest(url, type, layerOpacity),
      };

      // Handle async operations in the background
      const loadStyle = async () => {
        if (!styleUrl) {
          console.warn(`Refusing to load MapLibre style from ${cfg.url}: it must be an external URL`);
          return;
        }
        try {
          const style = await fetchStyle(styleUrl, layerOpacity);
          await apply(layer, style, { ...applyOptions, styleUrl });
          applyNoRepeat();
        } catch (error) {
          console.warn('Failed to load or apply MapLibre style JSON:', error);
          // Try fallback approach
          await tryFallbackApply(styleUrl);
        }
      };

      // ol-mapbox-style resolves mapbox:// style URLs itself, which fetch cannot
      const tryFallbackApply = async (url: string) => {
        try {
          await apply(layer, url, applyOptions);
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
