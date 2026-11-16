import { useEffect } from 'react';
import { Route, Routes, useParams } from 'react-router-dom-v5-compat';
import { fromFetch } from 'rxjs/fetch';
import { render, waitFor } from 'test/test-utils';

import { setBackendSrv } from '@grafana/runtime';
import config from 'app/core/config';
import { BackendSrv } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';
import { loadProviders } from 'app/features/auth-config/state/actions';
import {
  loadServiceAccount,
  loadServiceAccountTokens,
} from 'app/features/serviceaccounts/state/actionsServiceAccountPage';
import { AccessControlAction } from 'app/types/accessControl';
import { useDispatch } from 'app/types/store';

import { loadAdminUserPage } from './actions';

interface CapturedRequest {
  pathname: string;
  search: string;
  method: string;
  credentials: RequestCredentials | undefined;
}

const originalFetch = global.fetch;
let requests: CapturedRequest[] = [];
let observedIds: string[] = [];
let settledCount = 0;

function installFetchCapture() {
  requests = [];
  observedIds = [];
  settledCount = 0;
  document.head.querySelectorAll('base[data-path-test="true"]').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.setAttribute('data-path-test', 'true');
  base.href = '/';
  document.head.appendChild(base);

  window.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const resolved = new URL(raw, document.baseURI);
    requests.push({
      pathname: resolved.pathname,
      search: resolved.search,
      method: (init?.method ?? 'GET').toUpperCase(),
      credentials: init?.credentials,
    });
    return new Response(JSON.stringify([]), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
}

function removeFetchCapture() {
  window.fetch = originalFetch;
  document.head.querySelectorAll('base[data-path-test="true"]').forEach((node) => node.remove());
}

function escapedStateChanges() {
  return requests
    .filter((request) => request.pathname === '/logout' || /^\/profile\/switch-org\/[^/]+$/.test(request.pathname))
    .map(
      (request) => `${request.method} ${request.pathname}${request.search} credentials=${request.credentials ?? ''}`
    );
}

function UserAdminProbe() {
  const { id = '' } = useParams();
  const dispatch = useDispatch();

  useEffect(() => {
    let active = true;
    observedIds.push(id);
    Promise.resolve(dispatch(loadAdminUserPage(id))).finally(() => {
      if (active) {
        settledCount += 1;
      }
    });
    return () => {
      active = false;
    };
  }, [dispatch, id]);

  return null;
}

function ServiceAccountProbe() {
  const { id = '' } = useParams();
  const dispatch = useDispatch();

  useEffect(() => {
    let active = true;
    observedIds.push(id);
    Promise.all([
      Promise.resolve(dispatch(loadServiceAccount(id))),
      Promise.resolve(dispatch(loadServiceAccountTokens(id))),
    ]).finally(() => {
      if (active) {
        settledCount += 1;
      }
    });
    return () => {
      active = false;
    };
  }, [dispatch, id]);

  return null;
}

function ProviderProbe() {
  const { provider = '' } = useParams();
  const dispatch = useDispatch();

  useEffect(() => {
    let active = true;
    observedIds.push(provider);
    Promise.resolve(dispatch(loadProviders(provider))).finally(() => {
      if (active) {
        settledCount += 1;
      }
    });
    return () => {
      active = false;
    };
  }, [dispatch, provider]);

  return null;
}

async function open(path: string, entry: string, element: JSX.Element) {
  render(
    <Routes>
      <Route path={path} element={element} />
    </Routes>,
    {
      historyOptions: { initialEntries: [{ pathname: entry }] },
      preloadedState: {},
    }
  );

  await waitFor(() => {
    expect(settledCount).toBeGreaterThan(0);
  });
}

describe('admin and account routes that insert the route id into a backend path', () => {
  const previousPermissions = contextSrv.user.permissions;
  const previousOrgId = contextSrv.user.orgId;
  const previousSignedIn = contextSrv.user.isSignedIn;
  const previousLdap = config.ldapEnabled;

  beforeEach(() => {
    config.ldapEnabled = false;
    contextSrv.user.isSignedIn = true;
    contextSrv.user.orgId = 1;
    contextSrv.user.permissions = {
      ...previousPermissions,
      [AccessControlAction.UsersRead]: true,
      [AccessControlAction.UsersAuthTokenList]: true,
    };
    installFetchCapture();
    setBackendSrv(new BackendSrv({ fromFetch }));
  });

  afterEach(() => {
    config.ldapEnabled = previousLdap;
    contextSrv.user.permissions = previousPermissions;
    contextSrv.user.orgId = previousOrgId;
    contextSrv.user.isSignedIn = previousSignedIn;
    removeFetchCapture();
  });

  it('requests the profile, organizations, and sessions for a user id with no slash', async () => {
    await open('/admin/users/edit/:id', '/admin/users/edit/useruid01', <UserAdminProbe />);

    expect(observedIds).toContain('useruid01');
    expect(requests.map((request) => request.pathname)).toEqual(
      expect.arrayContaining([
        '/api/users/useruid01',
        '/api/users/useruid01/orgs',
        '/api/admin/users/useruid01/auth-tokens',
      ])
    );
    expect(requests.every((request) => request.credentials === 'same-origin')).toBe(true);
    expect(escapedStateChanges()).toEqual([]);
  });

  it('does not let a percent-encoded parent path in the user id log the caller out', async () => {
    await open('/admin/users/edit/:id', '/admin/users/edit/..%2F..%2Flogout', <UserAdminProbe />);

    expect(observedIds).toContain('../../logout');
    expect(escapedStateChanges()).toEqual([]);
  });

  it('does not let a percent-encoded parent path in the user id switch the caller organization', async () => {
    await open('/admin/users/edit/:id', '/admin/users/edit/..%2F..%2Fprofile%2Fswitch-org%2F2', <UserAdminProbe />);

    expect(observedIds).toContain('../../profile/switch-org/2');
    expect(escapedStateChanges()).toEqual([]);
  });

  it('does not let a question mark hide the same escape on the organization and session requests', async () => {
    await open('/admin/users/edit/:id', '/admin/users/edit/..%2F..%2F..%2Flogout%3F', <UserAdminProbe />);

    expect(observedIds).toContain('../../../logout?');
    expect(escapedStateChanges()).toEqual([]);
  });

  it('does not let the service account id escape into logout from the account or token request', async () => {
    await open('/org/serviceaccounts/:id', '/org/serviceaccounts/..%2F..%2Flogout%3F', <ServiceAccountProbe />);

    expect(observedIds).toContain('../../logout?');
    expect(escapedStateChanges()).toEqual([]);
  });

  it('does not let a question mark hide an organization switch on the profile, organization, and session requests', async () => {
    await open(
      '/admin/users/edit/:id',
      '/admin/users/edit/..%2F..%2F..%2Fprofile%2Fswitch-org%2F2%3F',
      <UserAdminProbe />
    );

    expect(observedIds).toContain('../../../profile/switch-org/2?');
    expect(escapedStateChanges()).toEqual([]);
  });

  it('does not let the authentication provider id escape into logout', async () => {
    await open('/admin/authentication/:provider', '/admin/authentication/..%2F..%2F..%2Flogout', <ProviderProbe />);

    expect(observedIds).toContain('../../../logout');
    expect(escapedStateChanges()).toEqual([]);
  });
});
