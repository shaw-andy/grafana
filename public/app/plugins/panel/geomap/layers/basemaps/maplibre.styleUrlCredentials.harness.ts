import type OpenLayersMap from 'ol/Map';

import { type EventBus, type GrafanaTheme2, type MapLayerOptions } from '@grafana/data';

import { type MaplibreConfig, maplibreLayers } from './maplibre';

const [maplibreLayer] = maplibreLayers;

/**
 * Calls the production MapLibre basemap init for one saved style URL.
 * The browser page drives this; the fetch itself stays the real one.
 */
export async function initMaplibreStyle(url: string): Promise<void> {
  const options: MapLayerOptions<Partial<MaplibreConfig>> = {
    name: 'maplibre',
    type: 'maplibre',
    config: { url },
  };
  const handler = await maplibreLayer.create({} as OpenLayersMap, options, {} as EventBus, { isDark: false } as GrafanaTheme2);
  handler.init();
}

declare global {
  interface Window {
    initMaplibreStyle: (url: string) => Promise<void>;
  }
}

window.initMaplibreStyle = initMaplibreStyle;
