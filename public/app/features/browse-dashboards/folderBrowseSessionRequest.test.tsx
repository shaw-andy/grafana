import { type ComponentProps, act } from 'react';
import { Route, Routes, useParams } from 'react-router-dom-v5-compat';
import type AutoSizer from 'react-virtualized-auto-sizer';
import { render, waitFor } from 'test/test-utils';

// jsdom stores the resolved request on the XMLHttpRequest impl, behind a symbol that is not
// shared across Jest's module copies. Find that impl by its flag.uri field.
function xhrImpl(xhr: XMLHttpRequest): {
  flag?: { uri?: string };
  status: number;
  statusText: string;
  readyState: number;
  responseURL: string;
  properties?: {
    responseBuffer: Buffer | null;
    totalReceivedChunkSize: number;
    responseHeaders: Record<string, string>;
  };
} | null {
  for (const symbol of Object.getOwnPropertySymbols(xhr)) {
    const value = (xhr as unknown as Record<symbol, unknown>)[symbol];
    if (value && typeof value === 'object' && 'flag' in value) {
      return value as ReturnType<typeof xhrImpl>;
    }
  }
  return null;
}

import { folderAPIv1beta1 } from 'app/api/clients/folder/v1beta1';
import { useGetFolderQueryFacade } from 'app/api/clients/folder/v1beta1/hooks';
import { config, setBackendSrv } from '@grafana/runtime';
import { setTestFlags } from '@grafana/test-utils/unstable';
import { backendSrv } from 'app/core/services/backend_srv';
import { type FolderDTO } from 'app/types/folders';

import { browseDashboardsAPI } from './api/browseDashboardsAPI';
import BrowseDashboardsPage from './BrowseDashboardsPage';

setBackendSrv(backendSrv);

jest.mock('react-virtualized-auto-sizer', () => {
  return {
    __esModule: true,
    default(props: ComponentProps<typeof AutoSizer>) {
      return (
        <div>
          {props.children({
            width: 800,
            scaledWidth: 800,
            scaledHeight: 600,
            height: 600,
          })}
        </div>
      );
    },
  };
});

const PARENT_SEGMENTS = '../'.repeat(8);
const LOGOUT_NAME = `${PARENT_SEGMENTS}logout`;
const SWITCH_ORG_NAME = `${PARENT_SEGMENTS}profile/switch-org/2`;
const LOGOUT_QUERY_NAME = `${PARENT_SEGMENTS}logout?`;
const SWITCH_ORG_QUERY_NAME = `${PARENT_SEGMENTS}profile/switch-org/2?`;
const LOGOUT_HASH_NAME = `${PARENT_SEGMENTS}logout#`;

interface CapturedRequest {
  url: string;
  method: string;
  credentials: RequestCredentials | undefined;
}

const captured: CapturedRequest[] = [];
let restoreTransport: (() => void) | undefined;

function installDocumentBase() {
  let base = document.querySelector('base');
  if (!base) {
    base = document.createElement('base');
    document.head.prepend(base);
  }
  base.setAttribute('href', '/');
}

// One body that satisfies the folder, access, and parents responses the browse page stitches
// together, plus an empty team list so a successful mutation can refresh without throwing.
function responseBody(pathname: string): unknown {
  if (pathname.endsWith('/user/teams') || pathname.endsWith('/folders')) {
    return [];
  }
  return {
    apiVersion: 'folder.grafana.app/v1beta1',
    kind: 'Folder',
    metadata: {
      name: 'folder-abc',
      namespace: 'default',
      annotations: {},
      labels: {},
      generation: 1,
      resourceVersion: '1',
    },
    spec: { title: 'Folder' },
    status: {},
    items: [],
    hits: [],
    counts: [],
    uid: 'folder-abc',
    title: 'Folder',
    id: 1,
    version: 1,
    canSave: false,
    canEdit: false,
    canAdmin: false,
    canDelete: false,
    accessControl: {},
    parents: [],
    hasAcl: false,
    url: '/dashboards/f/folder-abc',
    created: '2020-01-01T00:00:00Z',
    updated: '2020-01-01T00:00:00Z',
  };
}

function installBrowserTransport() {
  installDocumentBase();
  const xhrProto = XMLHttpRequest.prototype;
  const originalOpen = xhrProto.open;
  const originalSend = xhrProto.send;
  const originalFetch = globalThis.fetch;
  // jsdom still opens a socket for requests this stub does not finish, and moveFolders
  // resolves an empty result that RTK logs. Neither log is the session bug.
  const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  let credentials: RequestCredentials | undefined;

  globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    credentials =
      init?.credentials ?? (typeof input === 'object' && input !== null && 'credentials' in input ? input.credentials : undefined);
    return originalFetch(input, init);
  }) as typeof fetch;

  xhrProto.open = function (method: string, url: string | URL, async?: boolean, username?: string | null, password?: string | null) {
    originalOpen.call(this, method, url, async ?? true, username, password);
    const href = xhrImpl(this)?.flag?.uri;
    if (!href) {
      throw new Error('jsdom did not resolve the folder request URL');
    }
    captured.push({ url: href, method: String(method).toUpperCase(), credentials });
    return undefined;
  };

  // Stop after jsdom has resolved the URL. The assertion is that resolved URL, not the response.
  xhrProto.send = function () {
    const impl = xhrImpl(this);
    if (!impl?.flag?.uri || !impl.properties) {
      throw new Error('jsdom did not resolve the folder request URL');
    }
    const body = Buffer.from(JSON.stringify(responseBody(new URL(impl.flag.uri).pathname)));
    impl.properties.responseBuffer = body;
    impl.properties.totalReceivedChunkSize = body.length;
    impl.properties.responseHeaders = { 'content-type': 'application/json' };
    impl.readyState = 4;
    impl.status = 200;
    impl.statusText = 'OK';
    impl.responseURL = impl.flag.uri;
    const onload = this.onload;
    setTimeout(() => onload?.call(this, new ProgressEvent('load')), 0);
  };

  restoreTransport = () => {
    xhrProto.open = originalOpen;
    xhrProto.send = originalSend;
    globalThis.fetch = originalFetch;
    errorSpy.mockRestore();
  };
}

function resolvedPathname(url: string): string {
  return new URL(url, document.baseURI).pathname.replace(/\/+$/, '') || '/';
}

function isSessionChangingPath(pathname: string): boolean {
  return pathname === '/logout' || /^\/profile\/switch-org\/\d+$/.test(pathname);
}

function sessionChangingRequests() {
  return captured
    .map((entry) => ({
      ...entry,
      pathname: resolvedPathname(entry.url),
    }))
    .filter((entry) => isSessionChangingPath(entry.pathname));
}

function RouteUnderTest() {
  const { uid = '' } = useParams();
  const folder = useGetFolderQueryFacade(uid);
  const settled = Boolean(folder.isSuccess || folder.isError);
  return (
    <>
      <div data-testid="folder-uid">{uid}</div>
      <div data-testid="folder-query">{settled ? 'settled' : 'loading'}</div>
      <BrowseDashboardsPage queryParams={{}} />
    </>
  );
}

function renderFolderRoute(name: string) {
  return render(
    <Routes>
      <Route path="/dashboards/f/:uid" element={<RouteUnderTest />} />
      <Route path="/dashboards/f/:uid/:slug" element={<RouteUnderTest />} />
    </Routes>,
    {
      historyOptions: { initialEntries: [`/dashboards/f/${encodeURIComponent(name)}`] },
      preloadedState: {
        navIndex: { 'dashboards/browse': { text: 'Dashboards', id: 'dashboards/browse' } },
      },
    }
  );
}

async function settleFolderQuery() {
  await waitFor(() => {
    expect(document.querySelector('[data-testid="folder-query"]')?.textContent).toBe('settled');
  });
}

describe('folder browse links must not navigate the session', () => {
  beforeEach(() => {
    config.appSubUrl = '';
    config.namespace = 'default';
    captured.length = 0;
    installBrowserTransport();
  });

  afterEach(async () => {
    restoreTransport?.();
    await act(async () => {
      setTestFlags({});
    });
  });

  it.each([
    ['app platform', true, LOGOUT_NAME],
    ['app platform', true, SWITCH_ORG_NAME],
    ['app platform', true, LOGOUT_QUERY_NAME],
    ['app platform', true, SWITCH_ORG_QUERY_NAME],
    ['app platform', true, LOGOUT_HASH_NAME],
    ['legacy', false, LOGOUT_NAME],
    ['legacy', false, SWITCH_ORG_NAME],
    ['legacy', false, LOGOUT_QUERY_NAME],
  ])(
    'opening /dashboards/f with %s folders API does not request logout or an org switch (%j)',
    async (_api, foldersAppPlatformAPI, name) => {
      await act(async () => {
        setTestFlags({ foldersAppPlatformAPI });
      });
      const view = renderFolderRoute(name);

      expect(view.getByTestId('folder-uid')).toHaveTextContent(name);
      await settleFolderQuery();
      expect(await view.findByRole('heading', { name: 'Folder' })).toBeInTheDocument();

      expect(sessionChangingRequests()).toEqual([]);
    }
  );

  it('still loads a normal folder and sends the session credential', async () => {
    await act(async () => {
      setTestFlags({ foldersAppPlatformAPI: true });
    });
    renderFolderRoute('folder-abc');
    await settleFolderQuery();

    const folderReads = captured
      .map((entry) => ({ ...entry, pathname: resolvedPathname(entry.url) }))
      .filter((entry) => entry.pathname.endsWith('/folders/folder-abc'));

    expect(folderReads.length).toBeGreaterThan(0);
    expect(folderReads.every((entry) => entry.credentials === 'same-origin')).toBe(true);
    expect(sessionChangingRequests()).toEqual([]);
  });
});

describe('folder name path joins', () => {
  beforeEach(async () => {
    config.appSubUrl = '';
    config.namespace = 'default';
    captured.length = 0;
    await act(async () => {
      setTestFlags({ foldersAppPlatformAPI: true });
    });
    installBrowserTransport();
  });

  afterEach(async () => {
    restoreTransport?.();
    await act(async () => {
      setTestFlags({});
    });
  });

  const names = [LOGOUT_NAME, SWITCH_ORG_NAME, LOGOUT_QUERY_NAME, SWITCH_ORG_QUERY_NAME, LOGOUT_HASH_NAME];

  it.each(names)('app platform folder reads for %j stay off logout and org switch', async (name) => {
    const { store } = render(<div />, { preloadedState: {} });
    await Promise.all([
      store.dispatch(folderAPIv1beta1.endpoints.getFolder.initiate({ name })),
      store.dispatch(folderAPIv1beta1.endpoints.getFolderAccess.initiate({ name })),
      store.dispatch(folderAPIv1beta1.endpoints.getFolderParents.initiate({ name })),
      store.dispatch(folderAPIv1beta1.endpoints.getFolderChildren.initiate({ name })),
      store.dispatch(folderAPIv1beta1.endpoints.getFolderCounts.initiate({ name })),
      store.dispatch(folderAPIv1beta1.endpoints.getAffectedItems.initiate({ folderUIDs: [name], dashboardUIDs: [] })),
    ]);

    expect(sessionChangingRequests()).toEqual([]);
  });

  it.each(names)('app platform folder writes for %j stay off logout and org switch', async (name) => {
    const { store } = render(<div />, { preloadedState: {} });
    await Promise.all([
      store
        .dispatch(
          folderAPIv1beta1.endpoints.deleteFolder.initiate({
            name,
          })
        )
        .unwrap()
        .catch(() => undefined),
      store
        .dispatch(
          folderAPIv1beta1.endpoints.replaceFolder.initiate({
            name,
            folder: { spec: { title: 'renamed' } },
          })
        )
        .unwrap()
        .catch(() => undefined),
      store
        .dispatch(
          folderAPIv1beta1.endpoints.updateFolder.initiate({
            name,
            patch: { spec: { title: 'renamed' } },
          })
        )
        .unwrap()
        .catch(() => undefined),
    ]);

    expect(sessionChangingRequests()).toEqual([]);
  });

  it.each(names)('legacy folder routes for %j stay off logout and org switch', async (name) => {
    const { store } = render(<div />, { preloadedState: {} });
    const folder = { uid: name, title: 'folder', version: 1 } as FolderDTO;
    // moveFolders and deleteFolders resolve { data: undefined }, which RTK logs. That log is not the bug.
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    await Promise.all([
      store.dispatch(
        browseDashboardsAPI.endpoints.getFolder.initiate({
          folderUID: name,
          accesscontrol: true,
          isLegacyCall: false,
        })
      ),
      store
        .dispatch(
          browseDashboardsAPI.endpoints.saveFolder.initiate({
            uid: name,
            title: 'renamed',
            version: 1,
          })
        )
        .unwrap()
        .catch(() => undefined),
      store
        .dispatch(
          browseDashboardsAPI.endpoints.moveFolder.initiate({
            folderUID: name,
            destinationUID: 'dest',
          })
        )
        .unwrap()
        .catch(() => undefined),
      store
        .dispatch(browseDashboardsAPI.endpoints.deleteFolder.initiate(folder))
        .unwrap()
        .catch(() => undefined),
      store
        .dispatch(
          browseDashboardsAPI.endpoints.moveFolders.initiate({
            folderUIDs: [name],
            destinationUID: 'dest',
          })
        )
        .unwrap()
        .catch(() => undefined),
      store
        .dispatch(
          browseDashboardsAPI.endpoints.deleteFolders.initiate({
            folderUIDs: [name],
          })
        )
        .unwrap()
        .catch(() => undefined),
      store.dispatch(
        browseDashboardsAPI.endpoints.getAffectedItems.initiate({
          folderUIDs: [name],
          dashboardUIDs: [],
        })
      ),
    ]);
    errorSpy.mockRestore();

    expect(sessionChangingRequests()).toEqual([]);
  });
});
