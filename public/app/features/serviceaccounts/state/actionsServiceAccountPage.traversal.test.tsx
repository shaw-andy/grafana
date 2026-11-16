import { cleanup, render, waitFor } from '@testing-library/react';
import { from } from 'rxjs';
import { TestProvider } from 'test/helpers/TestProvider';

import { OrgRole } from '@grafana/data';
import { locationService, setBackendSrv } from '@grafana/runtime';
import { useParams, Routes, Route } from 'react-router-dom-v5-compat';

import { BackendSrv } from 'app/core/services/backend_srv';
import { type ServiceAccountDTO } from 'app/types/serviceaccount';

import ServiceAccountPage from '../ServiceAccountPage';

import {
  createServiceAccountToken,
  deleteServiceAccount,
  deleteServiceAccountToken,
  loadServiceAccount,
  loadServiceAccountTokens,
  updateServiceAccount,
} from './actionsServiceAccountPage';
import {
  createServiceAccountToken as createServiceAccountTokenFromList,
  deleteServiceAccount as deleteServiceAccountFromList,
  updateServiceAccount as updateServiceAccountFromList,
} from './actions';

/**
 * Spec for service-account id path traversal.
 *
 * These tests fail while an id taken from the address is concatenated onto
 * /api/serviceaccounts/ without encoding. With <base href="/"> the browser
 * resolves parent-directory segments in that relative URL, so the session
 * cookie is sent to /logout or /profile/switch-org/:id.
 *
 * They pass once every service-account id is encoded or rejected before a
 * request is issued. A fix that only checks the id and then requests the
 * original value still fails, because the assertion is on the request target.
 *
 * ServiceAccountCreatePage's updateServiceAccount concatenates a uid the same
 * way, but that uid is the one returned by the create API, not the address, so
 * these tests do not call it.
 */

interface RecordedRequest {
  method: string;
  pathname: string;
  search: string;
  credentials?: RequestCredentials;
}

function installDocumentBase(): void {
  document.head.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  // public/views/index.html sets this to the site root when AppSubUrl is empty.
  base.setAttribute('href', '/');
  document.head.appendChild(base);
}

function resolveAsBrowser(input: string): URL {
  // Fetch resolves a relative URL against the document base URL (the <base> tag).
  return new URL(input, document.baseURI);
}

function installRecordingBackend(): RecordedRequest[] {
  const requests: RecordedRequest[] = [];
  const backendSrv = new BackendSrv({
    fromFetch: (input, init) => {
      const raw = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      const resolved = resolveAsBrowser(raw);
      const method = (init?.method ?? 'GET').toUpperCase();
      requests.push({
        method,
        pathname: resolved.pathname,
        search: resolved.search,
        credentials: init?.credentials,
      });
      const body =
        method === 'GET' && resolved.pathname.endsWith('/tokens')
          ? '[]'
          : method === 'GET'
            ? JSON.stringify({
                id: 1,
                uid: 'sa-uid',
                name: 'account',
                login: 'sa-account',
                orgId: 1,
                role: 'Viewer',
                isDisabled: false,
                teams: [],
                tokens: 0,
                createdAt: '2022-01-01 00:00:00',
              })
            : '{}';
      return from(
        Promise.resolve(
          new Response(body, {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        )
      );
    },
    appEvents: { emit: jest.fn(), publish: jest.fn() } as any,
    contextSrv: { user: { orgId: 1, isSignedIn: true } } as any,
    logout: jest.fn(),
  });
  setBackendSrv(backendSrv);
  return requests;
}

type Thunk = (dispatch: (action: unknown) => unknown, getState: () => unknown) => unknown;

async function runThunk(thunk: Thunk): Promise<void> {
  const dispatch = (action: unknown): unknown => {
    if (typeof action === 'function') {
      return (action as Thunk)(dispatch, () => ({}));
    }
    return action;
  };
  await thunk(dispatch, () => ({}));
}

function routeParam(pathname: string): string {
  cleanup();
  let id = '';
  function Probe() {
    id = useParams().id ?? '';
    return null;
  }
  // history's createLocation decodes the path with decodeURI, which keeps %2F.
  locationService.replace(decodeURI(pathname));
  render(
    <TestProvider>
      <Routes>
        <Route path="/org/serviceaccounts/:id" element={<Probe />} />
      </Routes>
    </TestProvider>
  );
  return id;
}

const account = (uid: string): ServiceAccountDTO => ({
  id: 1,
  uid,
  name: 'account',
  login: 'sa-account',
  orgId: 1,
  role: OrgRole.Viewer,
  isDisabled: false,
  teams: [],
  tokens: 0,
  createdAt: '2022-01-01 00:00:00',
});

function leavesServiceAccountApi(request: RecordedRequest): boolean {
  return !request.pathname.startsWith('/api/serviceaccounts/') || request.pathname.split('/').includes('..');
}

describe('service account id path traversal', () => {
  beforeEach(() => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    installDocumentBase();
  });

  afterEach(() => {
    cleanup();
    jest.restoreAllMocks();
  });

  it('reads a percent-encoded parent segment from the service account route as a real slash', () => {
    expect(routeParam('/org/serviceaccounts/..%2F..%2Flogout')).toBe('../../logout');
    expect(routeParam('/org/serviceaccounts/..%2f..%2flogout')).toBe('../../logout');
    expect(routeParam('/org/serviceaccounts/..%2F..%2Fprofile%2Fswitch-org%2F2')).toBe('../../profile/switch-org/2');
  });

  it('does not request logout when the service account page loads a traversal id', async () => {
    const requests = installRecordingBackend();
    expect(routeParam('/org/serviceaccounts/..%2F..%2Flogout')).toBe('../../logout');

    // The address bar keeps the slash encoded. The real page reads that param on load.
    locationService.replace('/org/serviceaccounts/..%2F..%2Flogout');
    render(
      <TestProvider>
        <Routes>
          <Route path="/org/serviceaccounts/:id" element={<ServiceAccountPage />} />
        </Routes>
      </TestProvider>
    );

    await waitFor(() => {
      expect(requests.length).toBeGreaterThan(0);
    });

    expect(requests.filter(leavesServiceAccountApi)).toEqual([]);
    expect(requests).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ pathname: '/logout' })])
    );
  });

  it('does not switch organization when the service account page loads a traversal id', async () => {
    const requests = installRecordingBackend();
    locationService.replace('/org/serviceaccounts/..%2F..%2Fprofile%2Fswitch-org%2F2');
    render(
      <TestProvider>
        <Routes>
          <Route path="/org/serviceaccounts/:id" element={<ServiceAccountPage />} />
        </Routes>
      </TestProvider>
    );

    await waitFor(() => {
      expect(requests.length).toBeGreaterThan(0);
    });

    expect(requests.filter((request) => request.pathname.startsWith('/profile/switch-org/'))).toEqual([]);
    expect(requests.filter(leavesServiceAccountApi)).toEqual([]);
  });

  it('still loads a normal service account id with the session credentials', async () => {
    const requests = installRecordingBackend();
    locationService.replace('/org/serviceaccounts/sa-uid');
    render(
      <TestProvider>
        <Routes>
          <Route path="/org/serviceaccounts/:id" element={<ServiceAccountPage />} />
        </Routes>
      </TestProvider>
    );

    await waitFor(() => {
      expect(requests.map((request) => request.pathname)).toEqual(
        expect.arrayContaining(['/api/serviceaccounts/sa-uid', '/api/serviceaccounts/sa-uid/tokens'])
      );
    });

    expect(requests).toEqual(
      expect.arrayContaining([
        {
          method: 'GET',
          pathname: '/api/serviceaccounts/sa-uid',
          search: '?accesscontrol=true',
          credentials: 'same-origin',
        },
        {
          method: 'GET',
          pathname: '/api/serviceaccounts/sa-uid/tokens',
          search: '',
          credentials: 'same-origin',
        },
      ])
    );
  });

  it.each([
    ['loadServiceAccount', (id: string) => loadServiceAccount(id)],
    ['loadServiceAccountTokens', (id: string) => loadServiceAccountTokens(id)],
    ['updateServiceAccount', (id: string) => updateServiceAccount(account(id))],
    ['deleteServiceAccount', (id: string) => deleteServiceAccount(id)],
    [
      'createServiceAccountToken',
      (id: string) => createServiceAccountToken(id, { name: 'token' }, () => undefined),
    ],
    ['deleteServiceAccountToken', (id: string) => deleteServiceAccountToken(id, 7)],
    ['list updateServiceAccount', (id: string) => updateServiceAccountFromList(account(id))],
    ['list deleteServiceAccount', (id: string) => deleteServiceAccountFromList(id)],
    [
      'list createServiceAccountToken',
      (id: string) => createServiceAccountTokenFromList(id, { name: 'token' }, () => undefined),
    ],
  ])('keeps %s on /api/serviceaccounts when the id traverses to logout', async (_name, makeThunk) => {
    const requests = installRecordingBackend();
    await runThunk(makeThunk('../../logout') as Thunk).catch(() => undefined);
    expect(requests.filter(leavesServiceAccountApi)).toEqual([]);
  });

  it.each([
    ['loadServiceAccount', (id: string) => loadServiceAccount(id)],
    ['loadServiceAccountTokens', (id: string) => loadServiceAccountTokens(id)],
  ])('keeps %s off organization switch when the id traverses there', async (_name, makeThunk) => {
    const requests = installRecordingBackend();
    await runThunk(makeThunk('../../profile/switch-org/2') as Thunk).catch(() => undefined);
    expect(requests.filter((request) => request.pathname.startsWith('/profile/switch-org/'))).toEqual([]);
    expect(requests.filter(leavesServiceAccountApi)).toEqual([]);
  });
});
