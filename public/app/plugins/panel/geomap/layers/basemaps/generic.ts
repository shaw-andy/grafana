import TileLayer from 'ol/layer/Tile';
import XYZ from 'ol/source/XYZ';
import { expandUrl } from 'ol/uri';

import { type MapLayerRegistryItem, textUtil } from '@grafana/data';
import { getTemplateSrv } from '@grafana/runtime';

import { resolveMapResourceUrl } from '../../utils/resourceUrl';

export interface XYZConfig {
  url: string;
  attribution: string;
  minZoom?: number;
  maxZoom?: number;
}

const sampleURL = 'https://services.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer';
export const defaultXYZConfig: XYZConfig = {
  url: sampleURL + '/tile/{z}/{y}/{x}',
  attribution: `Tiles © <a href="${sampleURL}">ArcGIS</a>`,
};

/** A layer config whose XYZ fields are still unset, as saved panel options have them. */
export type UnresolvedXYZConfig<T extends XYZConfig = XYZConfig> = Omit<T, keyof XYZConfig> & Partial<XYZConfig>;

/** The same config once the XYZ fields are guaranteed present. */
type ResolvedXYZConfig<T extends XYZConfig = XYZConfig> = Omit<T, keyof XYZConfig> & XYZConfig;

/**
 * Saved panel options are only ever partial, so fill in the gaps once here with defaults if needed
 * and let everything downstream work with a complete config.
 */
export function resolveXYZConfig<T extends XYZConfig = XYZConfig>(
  config: UnresolvedXYZConfig<T>
): ResolvedXYZConfig<T> {
  if (!config.url) {
    return {
      ...config,
      url: defaultXYZConfig.url,
      attribution: config.attribution ?? defaultXYZConfig.attribution,
    };
  }
  return { ...config, url: config.url, attribution: config.attribution ?? '' };
}

// Lowercase letters only: hostnames are lowercased when parsed, and the digits OpenLayers puts in their
// place later cannot form a dot segment or an encoded separator.
const TILE_PLACEHOLDERS: Array<[placeholder: string, token: string]> = [
  ['{-y}', 'grafanatileminusy'],
  ['{z}', 'grafanatilez'],
  ['{x}', 'grafanatilex'],
  ['{y}', 'grafanatiley'],
];

/**
 * Expands and resolves a tile URL template. Tile images are plain image requests that carry the viewer's
 * cookies, so a template that lands on this Grafana host outside `public/maps/`, or that puts a tile
 * coordinate in the host name, yields no URLs.
 */
export function resolveTileUrls(template: string): string[] {
  const urls: string[] = [];
  for (const expanded of expandUrl(template)) {
    const lower = expanded.toLowerCase();
    if (TILE_PLACEHOLDERS.some(([, token]) => lower.includes(token))) {
      return [];
    }
    const tokenized = TILE_PLACEHOLDERS.reduce(
      (url, [placeholder, token]) => url.split(placeholder).join(token),
      expanded
    );
    const resolved = resolveMapResourceUrl(tokenized, document.baseURI, 'maps/');
    if (!resolved || TILE_PLACEHOLDERS.some(([, token]) => resolved.host.includes(token))) {
      return [];
    }
    urls.push(
      TILE_PLACEHOLDERS.reduce((url, [placeholder, token]) => url.split(token).join(placeholder), resolved.href)
    );
  }
  return urls;
}

export const xyzTiles: MapLayerRegistryItem<UnresolvedXYZConfig<XYZConfig>> = {
  id: 'xyz',
  name: 'XYZ Tile layer',
  description: 'Add map from a generic tile layer',
  isBaseMap: true,

  create: async (_map, options) => ({
    init: () => {
      const cfg = resolveXYZConfig(options.config ?? {});
      const noRepeat = options.noRepeat ?? false;
      const interpolatedUrl = textUtil.sanitizeUrl(getTemplateSrv().replace(cfg.url));
      const interpolatedAttribution = textUtil.sanitizeTextPanelContent(getTemplateSrv().replace(cfg.attribution));
      const urls = resolveTileUrls(interpolatedUrl);

      return new TileLayer({
        source: new XYZ({
          urls: urls.length ? urls : undefined,
          // An empty string would add a blank entry to the attribution control
          attributions: interpolatedAttribution || undefined,
          wrapX: !noRepeat,
          minZoom: cfg.minZoom,
          maxZoom: cfg.maxZoom,
        }),
        minZoom: cfg.minZoom,
      });
    },
    registerOptionsUI: (builder) => {
      builder
        .addTextInput({
          path: 'config.url',
          name: 'URL template',
          description: 'Must include {x}, {y} or {-y}, and {z} placeholders. Dashboard variables are supported.',
          settings: {
            placeholder: defaultXYZConfig.url,
          },
        })
        .addTextInput({
          path: 'config.attribution',
          name: 'Attribution',
          settings: {
            placeholder: defaultXYZConfig.attribution,
          },
        })
        .addNumberInput({
          path: 'config.minZoom',
          name: 'Min zoom',
          description: 'Minimum zoom level. Tiles are not loaded below this level.',
          settings: {
            placeholder: '0',
            min: 0,
            max: 30,
          },
        })
        .addNumberInput({
          path: 'config.maxZoom',
          name: 'Max zoom',
          description: 'Maximum zoom level provided by the server. Beyond this level, tiles are upscaled.',
          settings: {
            placeholder: '18',
            min: 0,
            max: 30,
          },
        });
    },
  }),
};

export const genericLayers = [xyzTiles];
