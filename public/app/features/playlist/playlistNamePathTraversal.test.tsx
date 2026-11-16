import { act, cleanup, render, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom-v5-compat';
import { TestProvider } from 'test/helpers/TestProvider';

import { locationService } from '@grafana/runtime';
import { playlistAPIv1, type Playlist } from 'app/api/clients/playlist/v1';
import { backendSrv } from 'app/core/services/backend_srv';
import { configureStore } from 'app/store/configureStore';

import { PlaylistEditPage } from './PlaylistEditPage';
import PlaylistStartPage from './PlaylistStartPage';

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  getBackendSrv: () => backendSrv,
}));

jest.mock('app/features/provisioning/hooks/useResourceRepositorySelection', () => ({
  useResourceRepositorySelection: () => ({ isAvailable: false, repositories: [] }),
}));

const PLAYLIST_API_PREFIX = '/apis/playlist.grafana.app/';
const LOGOUT_PATH = '/logout';
const SWITCH_ORG_PREFIX = '/profile/switch-org/';

// Six parent segments: apis, group, version, namespaces, namespace, playlists.
const PARENT_SEGMENTS = 6;

const encodedDotSlash = '%2e%2e%2f'.repeat(PARENT_SEGMENTS);
const encodedDotSlashUpper = '..%2f'.repeat(PARENT_SEGMENTS);

interface CapturedRequest {
  input: string;
  method: string;
  credentials: RequestCredentials | undefined;
}

const captured: CapturedRequest[] = [];

function resolvedPathname(input: string): string {
  return new URL(input, document.baseURI).pathname;
}

function installFetchSpy() {
  captured.length = 0;
  return jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    captured.push({
      input: url,
      method: init?.method ?? 'GET',
      credentials: init?.credentials,
    });
    return new Response(
      JSON.stringify({
        apiVersion: 'playlist.grafana.app/v1',
        kind: 'Playlist',
        metadata: { name: 'team-playlist', namespace: 'default' },
        spec: { title: 'Team', interval: '5m', items: [] },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  });
}

function isPlaylistNameRequest(pathname: string) {
  return (
    pathname.startsWith(PLAYLIST_API_PREFIX) ||
    pathname === LOGOUT_PATH ||
    pathname.startsWith(`${LOGOUT_PATH}/`) ||
    pathname.startsWith(SWITCH_ORG_PREFIX)
  );
}

function expectCapturedRequestsStayInsidePlaylistApi(store: ReturnType<typeof configureStore>) {
  const requests = captured
    .map((request) => ({
      method: request.method,
      pathname: resolvedPathname(request.input),
      credentials: request.credentials,
    }))
    .filter((request) => isPlaylistNameRequest(request.pathname));
  const entries = [
    ...Object.values(store.getState().playlistAPIv1?.queries ?? {}),
    ...Object.values(store.getState().playlistAPIv1?.mutations ?? {}),
  ] as Array<{ status?: string }>;
  if (entries.some((entry) => entry.status === 'fulfilled')) {
    expect(requests.length).toBeGreaterThan(0);
  }
  // A fix may refuse the name before fetch. A request that is sent must stay on the playlist API.
  expect(requests).toEqual(
    requests.map((request) => ({
      method: request.method,
      pathname: expect.stringMatching(/^\/apis\/playlist\.grafana\.app\//),
      credentials: 'same-origin',
    }))
  );
}

async function settlePlaylistQueries(store: ReturnType<typeof configureStore>) {
  await waitFor(() => {
    const queries = store.getState().playlistAPIv1?.queries ?? {};
    const mutations = store.getState().playlistAPIv1?.mutations ?? {};
    const statuses = [...Object.values(queries), ...Object.values(mutations)].map(
      (entry) => (entry as { status?: string }).status
    );
    expect(statuses.some((status) => status === 'fulfilled' || status === 'rejected')).toBe(true);
  });
}

function renderPlaylistRoute(store: ReturnType<typeof configureStore>, pathname: string) {
  locationService.push(pathname);
  return render(
    <TestProvider store={store}>
      <Routes>
        <Route path="/playlists/play/:uid" element={<PlaylistStartPage />} />
        <Route path="/playlists/edit/:uid" element={<PlaylistEditPage />} />
      </Routes>
    </TestProvider>
  );
}

describe('playlist name path traversal', () => {
  let fetchSpy: jest.SpyInstance;

  beforeEach(() => {
    document.head.querySelectorAll('base[data-playlist-traversal]').forEach((node) => node.remove());
    document.head.insertAdjacentHTML('beforeend', '<base href="/" data-playlist-traversal="1" />');
    fetchSpy = installFetchSpy();
  });

  afterEach(() => {
    cleanup();
    act(() => {
      locationService.replace('/');
    });
    fetchSpy.mockRestore();
    document.head.querySelectorAll('base[data-playlist-traversal]').forEach((node) => node.remove());
  });

  it('loads an ordinary playlist name from inside the playlist API with the session credential mode', async () => {
    const store = configureStore();
    renderPlaylistRoute(store, '/playlists/play/team-playlist');
    await settlePlaylistQueries(store);

    const playlistRequests = captured.filter((request) => resolvedPathname(request.input).includes('/playlists/'));
    expect(playlistRequests).toEqual([
      {
        input: 'apis/playlist.grafana.app/v1/namespaces/default/playlists/team-playlist',
        method: 'GET',
        credentials: 'same-origin',
      },
    ]);
    expect(resolvedPathname(playlistRequests[0].input)).toBe(
      '/apis/playlist.grafana.app/v1/namespaces/default/playlists/team-playlist'
    );
  });

  it.each([
    ['play', 'percent-encoded dots', LOGOUT_PATH, `/playlists/play/${encodedDotSlash}logout`],
    ['play', 'encoded slashes', LOGOUT_PATH, `/playlists/play/${encodedDotSlashUpper}logout`],
    [
      'edit',
      'percent-encoded dots',
      `${SWITCH_ORG_PREFIX}2`,
      `/playlists/edit/${encodedDotSlash}profile%2fswitch-org%2f2`,
    ],
    [
      'edit',
      'encoded slashes',
      `${SWITCH_ORG_PREFIX}2`,
      `/playlists/edit/${encodedDotSlashUpper}profile%2fswitch-org%2f2`,
    ],
  ])('opening the %s page with %s does not request %s', async (_page, _encoding, forbiddenPath, pathname) => {
    const store = configureStore();
    renderPlaylistRoute(store, pathname);
    await settlePlaylistQueries(store);

    expectCapturedRequestsStayInsidePlaylistApi(store);
    const escaped = captured.filter((request) => resolvedPathname(request.input) === forbiddenPath);
    expect(escaped).toEqual([]);
  });

  const traversalNames = [
    `${'../'.repeat(PARENT_SEGMENTS)}logout`,
    `${'../'.repeat(PARENT_SEGMENTS)}profile/switch-org/2`,
  ];

  const playlistBody = {
    apiVersion: 'playlist.grafana.app/v1',
    kind: 'Playlist',
    metadata: { name: 'team-playlist' },
    spec: { title: 'Team', interval: '5m', items: [] },
  } as Playlist;

  it.each(traversalNames)('getPlaylist keeps %s inside the playlist API', async (name) => {
    const store = configureStore();
    await store.dispatch(playlistAPIv1.endpoints.getPlaylist.initiate({ name }));
    await settlePlaylistQueries(store);
    expectCapturedRequestsStayInsidePlaylistApi(store);
  });

  it.each(traversalNames)('replacePlaylist keeps %s inside the playlist API', async (name) => {
    const store = configureStore();
    await store.dispatch(playlistAPIv1.endpoints.replacePlaylist.initiate({ name, playlist: playlistBody }));
    await settlePlaylistQueries(store);
    expectCapturedRequestsStayInsidePlaylistApi(store);
  });

  it.each(traversalNames)('deletePlaylist keeps %s inside the playlist API', async (name) => {
    const store = configureStore();
    await store.dispatch(playlistAPIv1.endpoints.deletePlaylist.initiate({ name }));
    await settlePlaylistQueries(store);
    expectCapturedRequestsStayInsidePlaylistApi(store);
  });

  it.each(traversalNames)('updatePlaylist keeps %s inside the playlist API', async (name) => {
    const store = configureStore();
    await store.dispatch(playlistAPIv1.endpoints.updatePlaylist.initiate({ name, patch: {} }));
    await settlePlaylistQueries(store);
    expectCapturedRequestsStayInsidePlaylistApi(store);
  });

  it.each(traversalNames)('getPlaylistStatus keeps %s inside the playlist API', async (name) => {
    const store = configureStore();
    await store.dispatch(playlistAPIv1.endpoints.getPlaylistStatus.initiate({ name }));
    await settlePlaylistQueries(store);
    expectCapturedRequestsStayInsidePlaylistApi(store);
  });

  it.each(traversalNames)('replacePlaylistStatus keeps %s inside the playlist API', async (name) => {
    const store = configureStore();
    await store.dispatch(playlistAPIv1.endpoints.replacePlaylistStatus.initiate({ name, playlist: playlistBody }));
    await settlePlaylistQueries(store);
    expectCapturedRequestsStayInsidePlaylistApi(store);
  });

  it.each(traversalNames)('updatePlaylistStatus keeps %s inside the playlist API', async (name) => {
    const store = configureStore();
    await store.dispatch(playlistAPIv1.endpoints.updatePlaylistStatus.initiate({ name, patch: {} }));
    await settlePlaylistQueries(store);
    expectCapturedRequestsStayInsidePlaylistApi(store);
  });
});
