jest.mock('ol-mapbox-style', () => ({}));
jest.mock('geotiff', () => ({}));

import { EventBusSrv } from '@grafana/data';
import { getTemplateSrv } from 'app/features/templating/template_srv';

import { xyzTiles } from '../layers/basemaps/generic';

import { guardLayerAttribution } from './attribution';

/**
 * Geomap attribution is sanitized with the text-panel filter and then with
 * DOMPurify, and OpenLayers assigns that string to innerHTML. A variable in
 * the attribution is replaced with no format, so the value is not HTML-escaped.
 */

const PAGE = 'http://localhost/';
const BLOCKED_PATH = /^\/(?:logout|profile\/switch-org\/[0-9]+|user\/auth-tokens\/rotate)$/;
const TILE_URL = 'https://tiles.example/{z}/{x}/{y}';

function sessionSubresourcePaths(html: string): string[] {
  const found: string[] = [];
  const doc = new DOMParser().parseFromString(`<div id="root">${html}</div>`, 'text/html');
  doc.querySelectorAll('[src], [poster]').forEach((el) => {
    for (const name of ['src', 'poster']) {
      const raw = el.getAttribute(name);
      if (!raw) {
        continue;
      }
      let url: URL;
      try {
        url = new URL(raw, PAGE);
      } catch {
        continue;
      }
      if (url.origin !== new URL(PAGE).origin) {
        continue;
      }
      let path = url.pathname;
      try {
        path = decodeURIComponent(path);
      } catch {
        // Keep the pathname the URL parser produced.
      }
      if (BLOCKED_PATH.test(path)) {
        found.push(path);
      }
    }
  });
  const style = doc.body.innerHTML;
  for (const match of style.matchAll(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi)) {
    let url: URL;
    try {
      url = new URL(match[2], PAGE);
    } catch {
      continue;
    }
    if (url.origin === new URL(PAGE).origin && BLOCKED_PATH.test(decodeURIComponent(url.pathname))) {
      found.push(decodeURIComponent(url.pathname));
    }
  }
  return found;
}

async function attributionHtml(attribution: string): Promise<string> {
  const handler = await xyzTiles.create(
    undefined as never,
    { type: 'xyz', config: { url: TILE_URL, attribution } },
    new EventBusSrv(),
    {} as never
  );
  const layer = handler.init();
  guardLayerAttribution(layer);
  const source = layer.getSource();
  const value = source?.getAttributions()?.({} as never);
  if (value == null) {
    return '';
  }
  return Array.isArray(value) ? value.join('\n') : value;
}

describe('geomap attribution must not request session routes', () => {
  beforeEach(() => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    getTemplateSrv().setGlobalVariable('media', { value: '', text: '' });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each([
    '<img src="/logout">',
    '<audio src="/profile/switch-org/2"></audio>',
    '<video poster="/user/auth-tokens/rotate"></video>',
    '<img src="/%6Cogout">',
    '<div style="background-image:url(/logout)"></div>',
  ])('drops a session request from attribution %s', async (attribution) => {
    expect(sessionSubresourcePaths(await attributionHtml(attribution))).toEqual([]);
  });

  it('drops a session request when the attribution variable holds a media tag', async () => {
    getTemplateSrv().setGlobalVariable('media', {
      value: '<img src="/logout">',
      text: '<img src="/logout">',
    });
    expect(sessionSubresourcePaths(await attributionHtml('${media}'))).toEqual([]);
  });

  it('drops a session request when the attribution variable is the media URL', async () => {
    getTemplateSrv().setGlobalVariable('media', { value: '/profile/switch-org/2', text: '/profile/switch-org/2' });
    expect(sessionSubresourcePaths(await attributionHtml('<img src="${media}">'))).toEqual([]);
  });
});
