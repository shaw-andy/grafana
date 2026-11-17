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

  it('falls back to frontend navigation for same-origin redirects in the current org', () => {
    contextSrv.user.isSignedIn = true;
    contextSrv.user.orgId = 1;
    sessionStorage.setItem(RedirectToUrlKey, encodeURIComponent('/grafana/d/test?orgId=1'));

    handleRedirectTo();

    expect(window.location.replace).not.toHaveBeenCalled();
    expect(locationService.replace).toHaveBeenCalledWith('/d/test?orgId=1');
  });

  // `new URL` is the resolution Chrome applies before it requests a location.replace target.
  // A check of the raw string misses a parent segment that is still percent-encoded at that point.
  function routesFromFullPageNavigation(appSubUrl: string): string[] {
    return (window.location.replace as jest.Mock).mock.calls.map((call) => {
      const pathname = new URL(String(call[0]), 'http://grafana.local').pathname;
      if (appSubUrl && (pathname === appSubUrl || pathname.startsWith(`${appSubUrl}/`))) {
        const rest = pathname.slice(appSubUrl.length);
        return rest.startsWith('/') ? rest : `/${rest}`;
      }
      return pathname;
    });
  }

  function signInFromLoginQuery(appSubUrl: string, query: string) {
    locationUtil.initialize({
      config: { appSubUrl } as GrafanaConfig,
      getVariablesUrlParams: jest.fn(),
      getTimeRangeForUrl: jest.fn(),
    });

    const replace = jest.fn();
    const location = {
      origin: 'http://grafana.local',
      pathname: '/login',
      replace,
    };
    Object.defineProperty(window, 'location', { configurable: true, value: location });

    const mockLocationService = locationService as jest.Mocked<typeof locationService>;
    mockLocationService.getSearch.mockReturnValue(new URLSearchParams(query));
    contextSrv.user.isSignedIn = false;
    contextSrv.user.orgId = 1;

    handleRedirectTo();

    mockLocationService.getSearch.mockReturnValue(new URLSearchParams());
    contextSrv.user.isSignedIn = true;
    location.pathname = '/';

    handleRedirectTo();
  }

  describe('post-login full-page navigation', () => {
    it.each([
      ['parent segment then logout', 'redirectTo=%2Fgoto%2F..%2Flogout'],
      ['nested parent segments then logout', 'redirectTo=%2Fgoto%2Ffoo%2F..%2F..%2Flogout'],
      ['percent-encoded parent segment then logout', 'redirectTo=%2Fgoto%2F%252e%252e%2Flogout'],
      ['parent segment then org switch', 'redirectTo=%2Fgoto%2F..%2Fprofile%2Fswitch-org%2F2'],
      ['percent-encoded parent segment then org switch', 'redirectTo=%2Fgoto%2F%252e%252e%2Fprofile%2Fswitch-org%2F2'],
      ['parent segment then auth token rotation', 'redirectTo=%2Fgoto%2F..%2Fuser%2Fauth-tokens%2Frotate'],
    ])('does not request a state-changing route for a /goto/ %s', (_name, query) => {
      signInFromLoginQuery('', query);

      const routes = routesFromFullPageNavigation('');
      // A full-page /goto/ navigation is only a short-url lookup. Anything else is a request
      // the browser will send with the session cookie, including paths produced by dot removal.
      for (const route of routes) {
        expect(route).toMatch(/^\/goto\/[A-Za-z0-9_-]+$/);
      }
    });

    it('still full-page navigates a single short-url key', () => {
      signInFromLoginQuery('', 'redirectTo=%2Fgoto%2Fabc123');

      expect(routesFromFullPageNavigation('')).toEqual(['/goto/abc123']);
    });

    it.each([
      ['logout with a different orgId', 'redirectTo=%2Flogout%3ForgId%3D2', '/logout'],
      [
        'org switch with a different orgId',
        'redirectTo=%2Fprofile%2Fswitch-org%2F2%3ForgId%3D2',
        '/profile/switch-org/2',
      ],
    ])('does not full-page navigate to %s', (_name, query, forbidden) => {
      signInFromLoginQuery('', query);

      expect(routesFromFullPageNavigation('')).not.toContain(forbidden);
    });

    it('does not full-page navigate to logout when the app is served from a subpath', () => {
      signInFromLoginQuery('/grafana', 'redirectTo=%2Fgoto%2F..%2Flogout');

      expect(routesFromFullPageNavigation('/grafana')).not.toContain('/logout');
    });
  });
});
