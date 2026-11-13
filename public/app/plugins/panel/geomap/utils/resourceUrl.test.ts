import { config } from '@grafana/runtime';

import { resolveMapResourceUrl } from './resourceUrl';

const BASE = 'http://localhost/d/abc/dashboard';

describe('resolveMapResourceUrl', () => {
  const originalAppSubUrl = config.appSubUrl;

  beforeEach(() => {
    window.__grafana_public_path__ = 'http://localhost/public/';
  });

  afterEach(() => {
    config.appSubUrl = originalAppSubUrl;
  });

  it('allows a file inside the public subdirectory of this server', () => {
    expect(resolveMapResourceUrl('/public/maps/countries.geojson', BASE, 'maps/')?.href).toBe(
      'http://localhost/public/maps/countries.geojson'
    );
  });

  it('allows any path on another host', () => {
    expect(resolveMapResourceUrl('https://tiles.example.com/logout', BASE, 'maps/')?.href).toBe(
      'https://tiles.example.com/logout'
    );
  });

  it.each([
    ['a route on this server', '/logout'],
    ['a path relative to the dashboard', '../../logout'],
    ['parent segments after the allowed directory', '/public/maps/../../logout'],
    ['encoded parent segments', '/public/maps/%2e%2e/%2e%2e/logout'],
    ['an encoded slash', '/public/maps/..%2f..%2flogout'],
    ['an encoded backslash', '/public/maps/..%5c..%5clogout'],
    ['backslash separators', '/public/maps\\..\\..\\logout'],
    ['a protocol-relative URL to this host', '//localhost/logout'],
    ['another port on this host', 'http://localhost:3001/logout'],
    ['another scheme on this host', 'https://localhost/logout'],
    ['this host with a trailing dot', 'http://localhost./logout'],
    ['a sibling of the allowed directory', '/public/mapsx/file.geojson'],
  ])('refuses %s', (_label, value) => {
    expect(resolveMapResourceUrl(value, BASE, 'maps/')).toBeUndefined();
  });

  it.each(['javascript:alert(1)', 'data:application/json,{}', 'file:///etc/passwd'])(
    'refuses the non-http URL %s',
    (value) => {
      expect(resolveMapResourceUrl(value, BASE, 'maps/')).toBeUndefined();
    }
  );

  it('allows the whole public folder when no subdirectory is given', () => {
    expect(resolveMapResourceUrl('public/build/img/icons/marker/circle.svg', 'http://localhost/', '')).toBeDefined();
    expect(resolveMapResourceUrl('/api/user', BASE, '')).toBeUndefined();
  });

  it('honours a Grafana sub path', () => {
    config.appSubUrl = '/grafana';
    window.__grafana_public_path__ = '/grafana/public/';
    expect(resolveMapResourceUrl('/grafana/public/maps/countries.geojson', BASE, 'maps/')).toBeDefined();
    expect(resolveMapResourceUrl('/grafana/logout', BASE, 'maps/')).toBeUndefined();
  });
});
