import { render, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { MemoryRouter, Route, Routes } from 'react-router-dom-v5-compat';

import { setBackendSrv } from '@grafana/runtime';
import { backendSrv } from 'app/core/services/backend_srv';
import { configureStore } from 'app/store/configureStore';

import { ProviderConfigPage } from './ProviderConfigPage';

setBackendSrv(backendSrv);

jest.mock('app/core/components/PageNotFound/PageNotFound', () => ({
  PageNotFound: () => <div>not found</div>,
}));

type RecordedRequest = {
  url: string;
  method: string;
  credentials: RequestCredentials | undefined;
};

// public/views/index.html sets <base href="/"> when the server has no subpath.
// The browser resolves a relative fetch against that base.
function browserRequestPath(url: string): string {
  const base = document.baseURI;
  if (new URL(base).pathname !== '/') {
    throw new Error(`document base pathname is ${new URL(base).pathname}`);
  }
  return new URL(url, base).pathname;
}

function installDocumentBase() {
  let base = document.head.querySelector('base');
  if (!base) {
    base = document.createElement('base');
    document.head.appendChild(base);
  }
  base.setAttribute('href', '/');
}

function renderProvider(pathname: string) {
  render(
    <Provider store={configureStore()}>
      <MemoryRouter
        initialEntries={[pathname]}
        future={{ v7_relativeSplatPath: true, v7_startTransition: true }}
      >
        <Routes>
          <Route path="/admin/authentication/:provider" element={<ProviderConfigPage />} />
        </Routes>
      </MemoryRouter>
    </Provider>
  );
}

describe('ProviderConfigPage SSO settings request target', () => {
  const requests: RecordedRequest[] = [];
  let originalFetch: typeof fetch;

  beforeEach(() => {
    installDocumentBase();
    requests.length = 0;
    originalFetch = globalThis.fetch;
    globalThis.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      requests.push({
        url,
        method: (init?.method ?? 'GET').toUpperCase(),
        credentials: init?.credentials,
      });
      return new Response(JSON.stringify({ provider: 'unmatched', settings: {} }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function paths(): string[] {
    return requests.map((request) => browserRequestPath(request.url));
  }

  it('requests the SSO settings API for a known provider', async () => {
    renderProvider('/admin/authentication/github');

    await waitFor(() => {
      expect(paths()).toContain('/api/v1/sso-settings/github');
    });

    const match = requests.find((request) => browserRequestPath(request.url) === '/api/v1/sso-settings/github');
    expect(match?.method).toBe('GET');
    expect(match?.credentials).toBe('same-origin');
  });

  it.each([
    ['/admin/authentication/..%2F..%2F..%2Flogout', '/logout'],
    ['/admin/authentication/..%2F..%2F..%2Fprofile%2Fswitch-org%2F2', '/profile/switch-org/2'],
  ])('does not retarget %s onto %s', async (pathname, forbiddenPath) => {
    renderProvider(pathname);

    // The page fetches on mount today. A fix may reject the provider before fetch.
    try {
      await waitFor(() => {
        expect(requests.length).toBeGreaterThan(0);
      });
    } catch {
      expect(requests).toEqual([]);
    }

    expect(paths()).not.toContain(forbiddenPath);
    for (const path of paths()) {
      expect(path.startsWith('/api/v1/sso-settings/')).toBe(true);
    }
    for (const request of requests) {
      expect(request.method).toBe('GET');
      expect(request.credentials).toBe('same-origin');
    }
  });
});
