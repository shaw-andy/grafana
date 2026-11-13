import { isAllowedResourceUrl } from './resourceUrl';

describe('isAllowedResourceUrl', () => {
  const { origin, host, hostname } = window.location;
  let previousPublicPath: string;

  beforeEach(() => {
    previousPublicPath = window.__grafana_public_path__;
    window.__grafana_public_path__ = `${origin}/public/`;
  });

  afterEach(() => {
    window.__grafana_public_path__ = previousPublicPath;
  });

  it.each(['https://tiles.example.com/{z}/{x}/{y}.png', 'http://tiles.internal:8080/{z}/{x}/{y}.png'])(
    'allows %s on another host',
    (url) => {
      expect(isAllowedResourceUrl(url)).toBe(true);
    }
  );

  it.each([
    'public/maps/countries.geojson',
    `${origin}/public/maps/countries.geojson`,
    `${origin}/public/build/gazetteer/countries.json`,
  ])('allows the static file %s in the public folder', (url) => {
    expect(isAllowedResourceUrl(url)).toBe(true);
  });

  it.each([
    '/logout',
    'logout',
    '/profile/switch-org/2',
    `${origin}/logout`,
    `//${host}/logout`,
    `https://${hostname}:1/logout`,
    `http://${hostname}./logout`,
    `${origin}/public//logout`,
    `${origin}/public/../logout`,
    `${origin}/public/%2e%2e/logout`,
    `${origin}/public/..%2flogout`,
  ])('refuses %s on the Grafana host', (url) => {
    expect(isAllowedResourceUrl(url)).toBe(false);
  });

  it.each(['javascript:alert(1)', 'data:text/plain,hi', '', undefined])('refuses %s', (url) => {
    expect(isAllowedResourceUrl(url)).toBe(false);
  });

  it('allows the local public folder when assets come from a CDN', () => {
    window.__grafana_public_path__ = 'https://cdn.example.com/grafana/public/';
    expect(isAllowedResourceUrl('public/maps/countries.geojson')).toBe(true);
    expect(isAllowedResourceUrl('https://cdn.example.com/grafana/public/maps/countries.geojson')).toBe(true);
    expect(isAllowedResourceUrl(`${origin}/logout`)).toBe(false);
  });
});
