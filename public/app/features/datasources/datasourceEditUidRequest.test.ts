import { createMemoryHistory } from 'history';
import { matchRoutes } from 'react-router-dom-v5-compat';

import { deleteDataSource, getDataSourceByUid } from './api';
import { ROUTES } from '../connections/constants';

// `<base href="/">` when server.root_url has no subpath. Fetch resolves a
// relative URL against that base. Chrome does the same for this string.
const DOCUMENT_BASE_URL = 'http://127.0.0.1/';

// history 4.10.1's production bundle decodes the pathname with decodeURI
// (node_modules/history/cjs/history.min.js). The development bundle Jest
// loads does not, so apply that production step before createMemoryHistory.
function pathnameAfterHistory(browserPathname: string): string {
  const decoded = decodeURI(browserPathname);
  return createMemoryHistory({ initialEntries: [decoded] }).location.pathname;
}

function uidFromEditPath(browserPathname: string): string {
  const pathname = pathnameAfterHistory(browserPathname);
  const childPath = ROUTES.DataSourcesEdit.replace(ROUTES.Base, '').replace(/^\//, '');
  const matches = matchRoutes(
    [
      {
        path: '/connections/*',
        children: [{ path: childPath }],
      },
      { path: '/datasources/edit/:uid' },
    ],
    pathname
  );
  const uid = matches?.map((match) => match.params.uid).find((value) => value != null && value !== '');
  if (!uid) {
    throw new Error(`edit route did not match ${pathname}`);
  }
  return uid;
}

interface CapturedRequest {
  input: string;
  method: string;
  credentials: RequestCredentials | undefined;
}

function installFetchCapture() {
  const captured: CapturedRequest[] = [];
  const fetchMock = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    captured.push({
      input: url,
      method: init?.method ?? 'GET',
      credentials: init?.credentials,
    });
    return new Response(JSON.stringify({ id: 1, uid: 'unused', name: 'unused', type: 'prometheus', jsonData: {} }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  const previous = globalThis.fetch;
  globalThis.fetch = fetchMock;
  return {
    captured,
    restore() {
      globalThis.fetch = previous;
    },
  };
}

function resolvedPathname(requestUrl: string): string {
  return new URL(requestUrl, DOCUMENT_BASE_URL).pathname;
}

// A fixed loader either refuses the uid before calling fetch, or asks for that
// uid as one encoded path segment. Either way the browser must not turn the
// request into /logout or /profile/switch-org/:id.
function expectRequestsStayOnDatasourceUid(captured: CapturedRequest[], uid: string) {
  const allowed = `/api/datasources/uid/${encodeURIComponent(uid)}`;
  for (const request of captured) {
    expect(request.credentials).toBe('same-origin');
    expect(resolvedPathname(request.input)).toBe(allowed);
  }
}

describe('data source edit uid', () => {
  const cases = [
    {
      name: 'six percent-encoded parent segments and logout',
      browserPath: `/connections/datasources/edit/${'..%2f'.repeat(6)}logout`,
    },
    {
      name: 'six fully percent-encoded parent segments and logout',
      browserPath: `/connections/datasources/edit/${'%2e%2e%2f'.repeat(6)}logout`,
    },
    {
      name: 'six percent-encoded parent segments and an organization switch',
      browserPath: `/connections/datasources/edit/${'..%2f'.repeat(6)}profile%2fswitch-org%2f2`,
    },
    {
      name: 'the legacy edit route with six percent-encoded parent segments and logout',
      browserPath: `/datasources/edit/${'..%2f'.repeat(6)}logout`,
    },
  ];

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each(cases)('does not load $name outside the data source API', async ({ browserPath }) => {
    const uid = uidFromEditPath(browserPath);
    const { captured, restore } = installFetchCapture();
    try {
      await getDataSourceByUid(uid).catch(() => undefined);
      expectRequestsStayOnDatasourceUid(captured, uid);
    } finally {
      restore();
    }
  });

  it.each(cases)('does not delete $name outside the data source API', async ({ browserPath }) => {
    const uid = uidFromEditPath(browserPath);
    const { captured, restore } = installFetchCapture();
    try {
      await deleteDataSource(uid).catch(() => undefined);
      expectRequestsStayOnDatasourceUid(captured, uid);
    } finally {
      restore();
    }
  });
});
