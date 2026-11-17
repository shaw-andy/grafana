import { configureStore } from '@reduxjs/toolkit';
import { render } from '@testing-library/react';
import { createBrowserHistory } from 'history';

import { config, HistoryWrapper, setBackendSrv, setLocationService } from '@grafana/runtime';
import { scopeAPIv0alpha1 } from 'app/api/clients/scope/v0alpha1';
import { backendSrv } from 'app/core/services/backend_srv';
import { setStore } from 'app/store/store';

import { ScopesContextProvider } from './ScopesContextProvider';

/**
 * Spec for the scope query path injection.
 *
 * These tests fail while a scopes or scope_node value from the page URL is placed
 * into an API path without encoding. The HTTP client strips the leading slash, fetch
 * resolves the remainder against the document base URL, and parent-directory segments
 * walk out of /apis/scope.grafana.app/ to GET /logout or /profile/switch-org/:id
 * with same-origin credentials.
 *
 * They pass when every such name is encoded as a single path segment, or the request
 * is refused before fetch is called. The asserted URL is the one passed to fetch.
 */

const SCOPE_API_PREFIX = '/apis/scope.grafana.app/';
// Enough parent segments to climb out of the scope API path at the site root and
// under a /grafana/ subpath. Extra segments stay at the origin root.
const PARENT_SEGMENTS = '../'.repeat(16);
const LOGOUT_NAME = `${PARENT_SEGMENTS}logout`;
const SWITCH_ORG_NAME = `${PARENT_SEGMENTS}profile/switch-org/2`;
const BACKSLASH_LOGOUT_NAME = `${'..\\'.repeat(16)}logout`;

type CapturedRequest = {
  url: string;
  method: string;
  credentials: string;
};

type ResolvedRequest = {
  pathname: string;
  method: string;
  credentials: string;
};

const nameEndpoints = [
  'getScope',
  'replaceScope',
  'deleteScope',
  'updateScope',
  'getScopeNode',
  'replaceScopeNode',
  'deleteScopeNode',
  'updateScopeNode',
  'getScopeDashboardBinding',
  'replaceScopeDashboardBinding',
  'deleteScopeDashboardBinding',
  'updateScopeDashboardBinding',
  'getScopeDashboardBindingStatus',
  'replaceScopeDashboardBindingStatus',
  'updateScopeDashboardBindingStatus',
  'getScopeNavigation',
  'replaceScopeNavigation',
  'deleteScopeNavigation',
  'updateScopeNavigation',
  'getScopeNavigationStatus',
  'replaceScopeNavigationStatus',
  'updateScopeNavigationStatus',
] as const;

function setDocumentBase(href: string) {
  let base = document.head.querySelector('base');
  if (!base) {
    base = document.createElement('base');
    document.head.prepend(base);
  }
  base.setAttribute('href', href);
}

function installFetchRecorder() {
  const captured: CapturedRequest[] = [];
  const previous = globalThis.fetch;
  const record: typeof fetch = async (input, init) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    // Same resolution fetch uses: the document base URL, including <base href>.
    const url = new URL(raw, document.baseURI).href;
    captured.push({
      url,
      method: (init?.method ?? 'GET').toUpperCase(),
      credentials: init?.credentials ?? 'same-origin',
    });
    return new Response('{}', {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  };
  globalThis.fetch = record;
  window.fetch = record;
  return {
    captured,
    restore() {
      globalThis.fetch = previous;
      window.fetch = previous;
    },
  };
}

function resolvedRequests(captured: CapturedRequest[]): ResolvedRequest[] {
  return captured.map((request) => ({
    pathname: new URL(request.url).pathname,
    method: request.method,
    credentials: request.credentials,
  }));
}

function scopeApiPrefix() {
  const basePath = new URL(document.baseURI).pathname.replace(/\/$/, '');
  return `${basePath}${SCOPE_API_PREFIX}`;
}

function requestsOutsideScopeApi(captured: CapturedRequest[]): ResolvedRequest[] {
  const prefix = scopeApiPrefix();
  return resolvedRequests(captured).filter((request) => !request.pathname.startsWith(prefix));
}

function openCraftedLink(search: string) {
  const href = search.startsWith('?') ? `/${search}` : `/?${search}`;
  window.history.pushState(null, '', href);
  // Production builds this from window.location (HistoryWrapper uses createBrowserHistory
  // outside tests). Pass that history so the query string is read the same way.
  setLocationService(new HistoryWrapper(createBrowserHistory()));
}

async function settleScopeReads(captured: CapturedRequest[]) {
  let lastCount = -1;
  let stableTicks = 0;
  for (let tick = 0; tick < 100 && stableTicks < 5; tick++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    if (captured.length === lastCount) {
      stableTicks += 1;
    } else {
      lastCount = captured.length;
      stableTicks = 0;
    }
  }
}

describe('scope query path injection', () => {
  let restoreFetch: () => void;
  let captured: CapturedRequest[];
  let store: ReturnType<typeof configureStore>;

  beforeEach(() => {
    // Failed lookups log. The assertion is the request URL, including when the client refuses the call.
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    config.featureToggles.scopeFilters = false;
    setDocumentBase('/');
    const recorder = installFetchRecorder();
    captured = recorder.captured;
    restoreFetch = recorder.restore;
    setBackendSrv(backendSrv);

    store = configureStore({
      reducer: {
        [scopeAPIv0alpha1.reducerPath]: scopeAPIv0alpha1.reducer,
      },
      middleware: (getDefaultMiddleware) =>
        getDefaultMiddleware({ serializableCheck: false, immutableCheck: false }).concat(scopeAPIv0alpha1.middleware),
    });
    setStore(store);
    store.dispatch(scopeAPIv0alpha1.util.resetApiState());
  });

  afterEach(() => {
    restoreFetch();
    jest.restoreAllMocks();
  });

  async function mountShell(search: string, baseHref = '/') {
    setDocumentBase(baseHref);
    openCraftedLink(search);
    const view = render(
      <ScopesContextProvider>
        <div />
      </ScopesContextProvider>
    );
    await settleScopeReads(captured);
    return view;
  }

  it('does not let a scopes query value escape the scope API when scope filters are off', async () => {
    expect(config.featureToggles.scopeFilters).toBe(false);
    await mountShell(`?scopes=${encodeURIComponent(LOGOUT_NAME)}`);

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });

  it('does not let a raw parent-directory scopes value request logout', async () => {
    await mountShell(`?scopes=${LOGOUT_NAME}`);

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });

  it('does not let one of several scopes query values request logout', async () => {
    const params = new URLSearchParams();
    params.append('scopes', 'team-a');
    params.append('scopes', LOGOUT_NAME);
    await mountShell(`?${params.toString()}`);

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });

  it('does not let a scope_node query value switch the active organization', async () => {
    await mountShell(`?scope_node=${encodeURIComponent(SWITCH_ORG_NAME)}`);

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });

  it('does not let scopes and scope_node together reach logout or switch-org', async () => {
    const params = new URLSearchParams();
    params.append('scopes', LOGOUT_NAME);
    params.set('scope_node', SWITCH_ORG_NAME);
    await mountShell(`?${params.toString()}`);

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });

  it('does not let a backslash scope name escape the scope API', async () => {
    await mountShell(`?scopes=${encodeURIComponent(BACKSLASH_LOGOUT_NAME)}`);

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });

  it('does not let a scope name escape when the document base is a subpath', async () => {
    await mountShell(`?scopes=${encodeURIComponent(LOGOUT_NAME)}`, '/grafana/');

    expect(new URL(document.baseURI).pathname).toBe('/grafana/');
    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });

  it('still requests an ordinary scope name inside the scope API', async () => {
    await mountShell('?scopes=team-a');

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
    expect(resolvedRequests(captured)).toEqual(
      expect.arrayContaining([
        {
          pathname: '/apis/scope.grafana.app/v0alpha1/namespaces/default/scopes/team-a',
          method: 'GET',
          credentials: 'same-origin',
        },
      ])
    );
  });

  it.each(nameEndpoints)('keeps %s inside the scope API when the name walks up to logout', async (endpointName) => {
    const endpoint = scopeAPIv0alpha1.endpoints[endpointName] as {
      initiate: (
        arg: { name: string },
        options: { subscribe: false }
      ) => Promise<unknown> & { unsubscribe?: () => void };
    };
    const subscription = store.dispatch(endpoint.initiate({ name: LOGOUT_NAME }, { subscribe: false }));
    try {
      await subscription;
    } catch {
      // A refusal or an HTTP error is fine. The request must not have escaped.
    } finally {
      subscription.unsubscribe?.();
    }
    await settleScopeReads(captured);

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });

  it('keeps getScopeNode inside the scope API when the name walks up to switch-org', async () => {
    const subscription = store.dispatch(
      scopeAPIv0alpha1.endpoints.getScopeNode.initiate({ name: SWITCH_ORG_NAME }, { subscribe: false })
    );
    try {
      await subscription;
    } catch {
      // A refusal or an HTTP error is fine. The request must not have escaped.
    } finally {
      subscription.unsubscribe?.();
    }
    await settleScopeReads(captured);

    expect(requestsOutsideScopeApi(captured)).toEqual([]);
  });
});
