// ol-mapbox-style and geotiff fail to parse under jest; stub them so the real
// layer registry (and everything it transitively imports) can still load.
jest.mock('ol-mapbox-style', () => ({}));
jest.mock('geotiff', () => ({}));

import Map from 'ol/Map';
import View from 'ol/View';
import AttributionControl from 'ol/control/Attribution';
import LayerGroup from 'ol/layer/Group';
import TileLayer from 'ol/layer/Tile';
import VectorLayer from 'ol/layer/Vector';
import TileJSON from 'ol/source/TileJSON';
import VectorSource from 'ol/source/Vector';
import XYZ from 'ol/source/XYZ';

import { type MapLayerOptions } from '@grafana/data';
import { setTemplateSrv } from '@grafana/runtime';
import { TemplateSrv } from 'app/features/templating/template_srv';

import { type GeomapPanel } from '../GeomapPanel';
import { esriLayers } from '../layers/basemaps/esri';
import { xyzTiles, type XYZConfig } from '../layers/basemaps/generic';
import { type MapLayerState } from '../types';

import { guardLayerAttribution } from './attribution';
import { initLayer } from './layers';

const MARKER = '© Probe';

// Strings an editor can save, or a MapLibre/TileJSON document can carry.
// Each one is markup that asks the browser for a session URL when the attribution
// control assigns it with innerHTML.
const sessionPayloads: Array<[string, string]> = [
  ['image source /logout', `${MARKER}<img src="/logout">`],
  ['image source /profile/switch-org/2', `${MARKER}<img src="/profile/switch-org/2">`],
  [
    'image source with an event handler stripped around it',
    `${MARKER}<img src="/logout" onerror="window.__pwned = 1">`,
  ],
  ['image srcset', `${MARKER}<img src="/tiles.png" srcset="/logout 1x, /profile/switch-org/2 2x">`],
  ['image source written with a character reference', `${MARKER}<img src="&#47;logout">`],
  ['image source with whitespace in the attribute', `${MARKER}<img src = "/profile/switch-org/2">`],
  ['video poster', `${MARKER}<video poster="/logout"></video>`],
  ['audio source', `${MARKER}<audio src="/profile/switch-org/2"></audio>`],
  ['media source element', `${MARKER}<video><source src="/logout"></video>`],
  ['table background', `${MARKER}<table background="/logout"><tr><td>x</td></tr></table>`],
  ['css background image', `${MARKER}<div style="background-image:url(/logout)"></div>`],
];

function createPanel(): GeomapPanel {
  return {
    map: {},
    layers: [],
    byName: new Map<string, MapLayerState>(),
    props: { eventBus: {}, data: {}, options: { controls: {} } },
  } as unknown as GeomapPanel;
}

/**
 * Same insertion the OpenLayers attribution control performs: one list item
 * per attribution string, assigned with innerHTML. Driving it through the
 * control's render keeps the test on that path, including collapsed markup
 * still being present in the document.
 */
async function renderAttribution(layer: LayerGroup | TileLayer<XYZ> | VectorLayer): Promise<HTMLElement> {
  const target = document.createElement('div');
  target.style.width = '200px';
  target.style.height = '200px';
  document.body.appendChild(target);
  const map = new Map({
    target,
    layers: [layer],
    controls: [new AttributionControl({ collapsed: true, collapsible: true })],
    view: new View({ center: [0, 0], zoom: 2 }),
  });
  // jsdom does not lay the target out, so the map would skip the frame and the
  // control would never copy attribution into the document.
  map.setSize([200, 200]);
  map.renderSync();
  // Attribution updates after the promises OpenLayers wraps each credit in.
  await Promise.resolve();
  await Promise.resolve();
  const rendered = target.querySelector('.ol-attribution');
  if (!(rendered instanceof HTMLElement)) {
    map.setTarget(undefined);
    throw new Error('attribution control did not render');
  }
  map.setTarget(undefined);
  return rendered;
}

function sessionSubresourcePaths(root: ParentNode): string[] {
  const base = document.baseURI;
  const found = new Set<string>();

  const consider = (raw: string | null | undefined) => {
    if (!raw) {
      return;
    }
    let url: URL;
    try {
      url = new URL(raw, base);
    } catch {
      return;
    }
    if (url.origin !== new URL(base).origin) {
      return;
    }
    const path = url.pathname.replace(/\/+$/, '') || '/';
    if (path === '/logout' || /^\/profile\/switch-org\/\d+$/.test(path)) {
      found.add(`${url.pathname}${url.search}`);
    }
  };

  const considerSrcset = (srcset: string | null) => {
    if (!srcset) {
      return;
    }
    for (const candidate of srcset.split(',')) {
      consider(candidate.trim().split(/\s+/)[0]);
    }
  };

  const considerCss = (css: string | null) => {
    if (!css) {
      return;
    }
    const pattern = /url\(\s*(['"]?)(.*?)\1\s*\)/gi;
    for (const match of css.matchAll(pattern)) {
      consider(match[2]);
    }
  };

  root.querySelectorAll('*').forEach((element) => {
    if (!(element instanceof HTMLElement || element instanceof SVGElement)) {
      return;
    }
    consider(element.getAttribute('src'));
    consider(element.getAttribute('poster'));
    consider(element.getAttribute('data'));
    consider(element.getAttribute('background'));
    considerSrcset(element.getAttribute('srcset'));
    considerCss(element.getAttribute('style'));
    if (element instanceof HTMLLinkElement) {
      const rel = element.rel.toLowerCase();
      if (/(^|\s)(stylesheet|preload|icon|prefetch|modulepreload)(\s|$)/.test(rel)) {
        consider(element.getAttribute('href'));
      }
    }
    if (element.localName === 'image') {
      consider(element.getAttribute('href'));
      consider(element.getAttribute('xlink:href'));
    }
  });

  root.querySelectorAll('style').forEach((element) => considerCss(element.textContent));

  return [...found].sort();
}

async function xyzLayer(attribution: string): Promise<TileLayer<XYZ>> {
  const options: MapLayerOptions<XYZConfig> = {
    name: 'Basemap',
    type: 'xyz',
    config: { url: 'https://tiles.example/{z}/{x}/{y}.png', attribution },
  };
  const handler = await xyzTiles.create({} as never, options, {} as never, {} as never);
  const layer = handler.init() as TileLayer<XYZ>;
  // initLayer always guards after the layer handler builds the source.
  guardLayerAttribution(layer);
  return layer;
}

beforeAll(() => {
  setTemplateSrv(new TemplateSrv());
});

afterEach(() => {
  document.body.innerHTML = '';
});

describe('geomap attribution session requests', () => {
  it('still shows an ordinary credit line', async () => {
    const layer = await xyzLayer(`${MARKER} <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>`);
    const rendered = await renderAttribution(layer);

    expect(rendered.textContent).toContain('OpenStreetMap');
    expect(sessionSubresourcePaths(rendered)).toEqual([]);
  });

  it.each(sessionPayloads)('XYZ attribution does not load a session URL from %s', async (_label, attribution) => {
    const layer = await xyzLayer(attribution);
    const rendered = await renderAttribution(layer);

    expect(rendered.textContent).toContain(MARKER);
    expect(sessionSubresourcePaths(rendered)).toEqual([]);
  });

  it.each(sessionPayloads)(
    'initLayer XYZ attribution does not load a session URL from %s',
    async (_label, attribution) => {
      const state = await initLayer(
        createPanel(),
        {} as never,
        {
          type: 'xyz',
          name: 'Basemap',
          config: { url: 'https://tiles.example/{z}/{x}/{y}.png', attribution },
        },
        true
      );
      const rendered = await renderAttribution(state.layer as TileLayer<XYZ>);

      expect(rendered.textContent).toContain(MARKER);
      expect(sessionSubresourcePaths(rendered)).toEqual([]);
    }
  );

  it.each(sessionPayloads)(
    'custom ArcGIS attribution does not load a session URL from %s',
    async (_label, attribution) => {
      const [esri] = esriLayers;
      const handler = await esri.create(
        {} as never,
        {
          name: 'ArcGIS',
          type: 'esri-xyz',
          config: {
            server: 'custom',
            url: 'https://tiles.example/{z}/{x}/{y}.png',
            attribution,
          },
        },
        {} as never,
        {} as never
      );
      const layer = handler.init() as TileLayer<XYZ>;
      guardLayerAttribution(layer);
      const rendered = await renderAttribution(layer);

      expect(rendered.textContent).toContain(MARKER);
      expect(sessionSubresourcePaths(rendered)).toEqual([]);
    }
  );

  it.each(sessionPayloads)(
    'a source added to a guarded layer group does not load a session URL from %s',
    async (_label, attribution) => {
      const group = new LayerGroup({ layers: [] });
      guardLayerAttribution(group);

      const child = new TileLayer({
        source: new XYZ({ url: 'https://tiles.example/{z}/{x}/{y}.png', attributions: attribution }),
      });
      group.getLayers().push(child);
      const rendered = await renderAttribution(group);

      expect(rendered.textContent).toContain(MARKER);
      expect(sessionSubresourcePaths(rendered)).toEqual([]);
    }
  );

  it.each(sessionPayloads)(
    'attribution set after the guard does not load a session URL from %s',
    async (_label, attribution) => {
      const layer = new TileLayer({ source: new XYZ({ url: 'https://tiles.example/{z}/{x}/{y}.png' }) });
      guardLayerAttribution(layer);
      layer.getSource()?.setAttributions(attribution);
      const rendered = await renderAttribution(layer);

      expect(rendered.textContent).toContain(MARKER);
      expect(sessionSubresourcePaths(rendered)).toEqual([]);
    }
  );

  it.each(sessionPayloads)(
    'a TileJSON attribution string does not load a session URL from %s',
    async (_label, attribution) => {
      // A MapLibre raster source is copied onto a TileJSON document, and OpenLayers
      // reads that document's attribution field when the source is constructed.
      const source = new TileJSON({
        tileJSON: {
          tiles: ['https://tiles.example/{z}/{x}/{y}.png'],
          attribution,
        },
      });
      const layer = new TileLayer();
      const group = new LayerGroup({ layers: [layer] });
      guardLayerAttribution(group);
      layer.setSource(source);
      const rendered = await renderAttribution(group);

      expect(rendered.textContent).toContain(MARKER);
      expect(sessionSubresourcePaths(rendered)).toEqual([]);
    }
  );

  it.each(sessionPayloads)(
    'a vector source attribution string does not load a session URL from %s',
    async (_label, attribution) => {
      const source = new VectorSource({ attributions: attribution });
      const layer = new VectorLayer({ source });
      const group = new LayerGroup({ layers: [] });
      guardLayerAttribution(group);
      group.getLayers().push(layer);
      const rendered = await renderAttribution(group);

      expect(rendered.textContent).toContain(MARKER);
      expect(sessionSubresourcePaths(rendered)).toEqual([]);
    }
  );
});
