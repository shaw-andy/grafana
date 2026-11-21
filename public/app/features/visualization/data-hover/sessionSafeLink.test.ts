import { type LinkModel } from '@grafana/data';
import { config } from '@grafana/runtime';

import { getSessionSafeLink } from './sessionSafeLink';

const origin = window.location.origin;

function link(href: string): LinkModel {
  return { title: 'Link', href, target: '_blank', origin: {} };
}

describe('getSessionSafeLink', () => {
  const originalUser = config.bootData.user;
  const originalAppUrl = config.appUrl;

  beforeEach(() => {
    config.bootData.user = { ...originalUser, orgId: 1 };
    config.appUrl = '';
  });

  afterAll(() => {
    config.bootData.user = originalUser;
    config.appUrl = originalAppUrl;
  });

  it.each([
    '/logout',
    `${origin}/logout`,
    `${origin}/LOGOUT`,
    `${origin}/logout/`,
    `${origin}/logou%74`,
    `${origin}/logout/saml`,
    `${origin}/grafana/logout`,
    `${origin}/a%2Flogout`,
    `${origin}/x/../logout`,
    `${origin}/login/github`,
    `${origin}/profile/switch-org/2`,
    `${origin}/user/auth-tokens/rotate`,
    `${origin}/user/email/update?code=placeholder`,
    `${origin}/goto/abc`,
    '//localhost/logout',
    'https://localhost:4443/logout',
  ])('drops the session action %s', (href) => {
    expect(getSessionSafeLink(link(href))).toBeUndefined();
  });

  it.each([
    `${origin}/d/abc?orgId=2`,
    '/d/abc?orgId=2',
    `${origin}/d/abc?orgid=2`,
    `${origin}/d/abc?org%49d=2`,
    `${origin}/d/abc?orgId=1&orgId=2`,
    `${origin}/d/abc?orgId=2&orgId=1`,
    `${origin}/d/abc?orgId=+2`,
  ])('drops %s because it switches to another organization', (href) => {
    expect(getSessionSafeLink(link(href))).toBeUndefined();
  });

  it('drops links that carry an orgId when the active organization is unknown', () => {
    config.bootData.user = { ...originalUser, orgId: undefined as unknown as number };
    expect(getSessionSafeLink(link('/d/abc?orgId=1'))).toBeUndefined();
  });

  it('removes an orgId that names the active organization', () => {
    expect(getSessionSafeLink(link('/d/abc?orgId=1&var-a=x#panel'))?.href).toBe('/d/abc?var-a=x#panel');
    expect(getSessionSafeLink(link(`${origin}/d/abc?orgId=1`))?.href).toBe(`${origin}/d/abc`);
  });

  it('treats the configured app URL host as this server', () => {
    config.appUrl = 'https://grafana.example.net/';
    expect(getSessionSafeLink(link('https://grafana.example.net/logout'))).toBeUndefined();
    expect(getSessionSafeLink(link('https://grafana.example.net/d/abc?orgId=2'))).toBeUndefined();
  });

  it('keeps ordinary links unchanged', () => {
    const external = link('https://example.com/logout?orgId=2');
    const dashboard = link('/d/abc?var-a=x');
    expect(getSessionSafeLink(external)).toBe(external);
    expect(getSessionSafeLink(dashboard)).toBe(dashboard);
  });
});
