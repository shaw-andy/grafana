import { type GrafanaConfig, locationUtil } from '@grafana/data';
import { locationService } from '@grafana/runtime';

import { contextSrv, RedirectToUrlKey } from '../services/context_srv';

import { handleRedirectTo } from './handleRedirectTo';

describe('handleRedirectTo', () => {
  // These tests replace shared globals and singleton methods, so keep the originals to restore test isolation.
  const originalLocation = window.location;
  const originalReplace = locationService.replace;
  const originalGetSearch = locationService.getSearch;
  const originalIsSignedIn = contextSrv.user.isSignedIn;
  const originalOrgId = contextSrv.user.orgId;

  beforeEach(() => {
    sessionStorage.clear();

    locationUtil.initialize({
      config: { appSubUrl: '/grafana' } as GrafanaConfig,
      getVariablesUrlParams: jest.fn(),
      getTimeRangeForUrl: jest.fn(),
    });

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        ...originalLocation,
        origin: 'http://grafana.local',
        pathname: '/',
        replace: jest.fn(),
      },
    });

    const mockLocationService = locationService as jest.Mocked<typeof locationService>;
    mockLocationService.replace = jest.fn();
    mockLocationService.getSearch = jest.fn().mockReturnValue(new URLSearchParams());

    contextSrv.user.isSignedIn = false;
    contextSrv.user.orgId = 1;
  });

  afterEach(() => {
    locationService.replace = originalReplace;
    locationService.getSearch = originalGetSearch;
    contextSrv.user.isSignedIn = originalIsSignedIn;
    contextSrv.user.orgId = originalOrgId;
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
    jest.restoreAllMocks();
  });

  it('clears the stored redirect when handling URL login', () => {
    const mockLocationService = locationService as jest.Mocked<typeof locationService>;
    mockLocationService.getSearch.mockReturnValue(new URLSearchParams('auth_token=test-token'));
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent('/grafana/d/test?orgId=2'));

    handleRedirectTo();

    expect(sessionStorage.getItem(RedirectToUrlKey)).toBeNull();
    expect(window.location.replace).not.toHaveBeenCalled();
    expect(locationService.replace).not.toHaveBeenCalled();
  });

  it('stores redirectTo from non-root paths and removes it from the URL', () => {
    const mockLocationService = locationService as jest.Mocked<typeof locationService>;
    const replaceStateSpy = jest.spyOn(window.history, 'replaceState');
    const queryParams = new URLSearchParams();
    queryParams.set('redirectTo', '/grafana/d/test?orgId=2');
    queryParams.set('foo', 'bar');
    mockLocationService.getSearch.mockReturnValue(queryParams);

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        ...window.location,
        pathname: '/login',
      },
    });

    handleRedirectTo();

    expect(sessionStorage.getItem(RedirectToUrlKey)).toBe(encodeURIComponent('/grafana/d/test?orgId=2'));
    expect(queryParams.has('redirectTo')).toBe(false);
    expect(replaceStateSpy).toHaveBeenCalledWith({}, '', '/login');
    expect(window.location.replace).not.toHaveBeenCalled();
    expect(locationService.replace).not.toHaveBeenCalled();
  });

  it('does not consume the stored redirect before the user is signed in', () => {
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent('/grafana/d/test?orgId=2'));

    handleRedirectTo();

    expect(sessionStorage.getItem(RedirectToUrlKey)).toBe(encodeURIComponent('/grafana/d/test?orgId=2'));
    expect(window.location.replace).not.toHaveBeenCalled();
    expect(locationService.replace).not.toHaveBeenCalled();
  });

  it('hard redirects goto URLs through the backend', () => {
    contextSrv.user.isSignedIn = true;
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent('/goto/abc123'));

    handleRedirectTo();

    expect(window.location.replace).toHaveBeenCalledWith('/grafana/goto/abc123');
    expect(locationService.replace).not.toHaveBeenCalled();
  });

  it('does not hard redirect cross-origin URLs even when orgId changes', () => {
    contextSrv.user.isSignedIn = true;
    contextSrv.user.orgId = 1;
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent('https://evil.com/d/test?orgId=2'));

    handleRedirectTo();

    expect(window.location.replace).not.toHaveBeenCalled();
    expect(locationService.replace).toHaveBeenCalledWith('https://evil.com/d/test?orgId=2');
  });

  it('hard redirects same-origin URLs that switch orgs', () => {
    contextSrv.user.isSignedIn = true;
    contextSrv.user.orgId = 1;
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent('/grafana/d/test?orgId=2'));

    handleRedirectTo();

    expect(window.location.replace).toHaveBeenCalledWith('/grafana/d/test?orgId=2');
    expect(locationService.replace).not.toHaveBeenCalled();
  });

  it.each([
    { desc: 'logout', redirectTo: '/logout' },
    { desc: 'logout under the sub path', redirectTo: '/grafana/logout/' },
    { desc: 'logout with an org switch', redirectTo: '/grafana/logout?orgId=2' },
    { desc: 'logout through a goto dot segment', redirectTo: '/goto/../logout' },
    { desc: 'logout through an encoded dot segment', redirectTo: '/goto/%2e%2e/logout' },
    { desc: 'percent-encoded logout', redirectTo: '/%6cogout?orgId=2' },
    { desc: 'organization switch', redirectTo: '/grafana/profile/switch-org/2?orgId=2' },
    { desc: 'encoded organization switch', redirectTo: '/profile%2Fswitch-org/2?orgId=2' },
  ])('drops the stored redirect to $desc without navigating', ({ redirectTo }) => {
    contextSrv.user.isSignedIn = true;
    contextSrv.user.orgId = 1;
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent(redirectTo));

    handleRedirectTo();

    expect(sessionStorage.getItem(RedirectToUrlKey)).toBeNull();
    expect(window.location.replace).not.toHaveBeenCalled();
    expect(locationService.replace).not.toHaveBeenCalled();
  });

  it('still navigates to pages whose path only contains an action name', () => {
    contextSrv.user.isSignedIn = true;
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent('/grafana/d/logout'));

    handleRedirectTo();

    expect(locationService.replace).toHaveBeenCalledWith('/d/logout');
  });

  it('falls back to frontend navigation for same-origin redirects in the current org', () => {
    contextSrv.user.isSignedIn = true;
    contextSrv.user.orgId = 1;
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent('/grafana/d/test?orgId=1'));

    handleRedirectTo();

    expect(window.location.replace).not.toHaveBeenCalled();
    expect(locationService.replace).toHaveBeenCalledWith('/d/test?orgId=1');
  });
});
