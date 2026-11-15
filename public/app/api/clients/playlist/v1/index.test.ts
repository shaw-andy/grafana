import { configureStore } from '@reduxjs/toolkit';

import { setBackendSrv } from '@grafana/runtime';
import { backendSrv } from 'app/core/services/backend_srv';

import { type Playlist, playlistAPIv1 } from './index';

setBackendSrv(backendSrv);

const integerIdLookup = /^\/(?:grafana\/)?api\/dashboards\/ids\/[0-9]+(?:,[0-9]+)*$/;
const playlistRead = /^\/(?:grafana\/)?apis\/playlist\.grafana\.app\/v1\/namespaces\/default\/playlists\/[^/]+$/;

interface RecordedRequest {
  raw: string;
  pathname: string;
  method: string;
  credentials: RequestCredentials | undefined;
}

function requestURL(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }
  if (input instanceof URL) {
    return input.toString();
  }
  return input.url;
}

function installFetchRecorder() {
  const seen: RecordedRequest[] = [];
  const previous = globalThis.fetch;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const raw = requestURL(input);
    const resolved = new URL(raw, document.baseURI);
    seen.push({
      raw,
      pathname: resolved.pathname,
      method: init?.method ?? 'GET',
      credentials: init?.credentials,
    });

    const body = resolved.pathname.includes('/playlists/') ? JSON.stringify(currentPlaylist) : JSON.stringify([]);
    return new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return {
    seen,
    restore() {
      globalThis.fetch = previous;
    },
  };
}

function setBaseHref(href: string) {
  document.head.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.href = href;
  document.head.appendChild(base);
}

let currentPlaylist: Playlist;

function playlistWith(
  name: string,
  items: Array<{ type: 'dashboard_by_id' | 'dashboard_by_uid'; value: string }>
): Playlist {
  return {
    apiVersion: 'playlist.grafana.app/v1',
    kind: 'Playlist',
    metadata: { name, namespace: 'default' },
    spec: {
      title: name,
      interval: '5m',
      items,
    },
  };
}

async function loadPlaylist(name: string) {
  const store = configureStore({
    reducer: { [playlistAPIv1.reducerPath]: playlistAPIv1.reducer },
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().concat(playlistAPIv1.middleware),
  });
  const subscription = store.dispatch(playlistAPIv1.endpoints.getPlaylist.initiate({ name }));
  const result = await subscription;
  subscription.unsubscribe();
  store.dispatch(playlistAPIv1.util.resetApiState());
  return result;
}

describe('getPlaylist dashboard_by_id migration', () => {
  let recorder: ReturnType<typeof installFetchRecorder>;

  beforeEach(() => {
    recorder = installFetchRecorder();
  });

  afterEach(() => {
    recorder.restore();
  });

  it.each(['http://localhost/', 'http://localhost/grafana/'])(
    'resolves a saved id against base %s only when every id is an integer',
    async (baseHref) => {
      setBaseHref(baseHref);
      expect(document.baseURI).toBe(baseHref);
      // Same resolution Chrome applies to the relative URL this client hands to fetch.
      expect(new URL('api/dashboards/ids/../../../logout', document.baseURI).pathname).toBe(
        new URL('logout', baseHref).pathname
      );

      currentPlaylist = playlistWith('numeric', [{ type: 'dashboard_by_id', value: '1,2' }]);
      const numeric = await loadPlaylist('numeric');
      expect(numeric.error).toBeUndefined();
      const numericLookups = recorder.seen.filter((request) => request.pathname.includes('/api/dashboards/ids/'));
      expect(numericLookups.map((request) => request.pathname)).toEqual([
        new URL('api/dashboards/ids/1,2', baseHref).pathname,
      ]);
      expect(numericLookups.every((request) => request.method === 'GET' && request.credentials === 'same-origin')).toBe(
        true
      );

      recorder.seen.length = 0;
      currentPlaylist = playlistWith('unsafe', [
        { type: 'dashboard_by_id', value: '7' },
        { type: 'dashboard_by_id', value: '../../../logout' },
        { type: 'dashboard_by_id', value: '../../../profile/switch-org/2' },
        { type: 'dashboard_by_id', value: '%2e%2e/%2e%2e/%2e%2e/logout' },
        { type: 'dashboard_by_id', value: '..%2f..%2f..%2flogout' },
        { type: 'dashboard_by_uid', value: 'kept-uid' },
      ]);
      await loadPlaylist('unsafe');

      const outsidePlaylistRead = recorder.seen.filter((request) => !playlistRead.test(request.pathname));
      expect(
        outsidePlaylistRead.map((request) => ({ method: request.method, credentials: request.credentials }))
      ).toEqual(outsidePlaylistRead.map(() => ({ method: 'GET', credentials: 'same-origin' })));
      expect(
        outsidePlaylistRead.map((request) => request.pathname).filter((pathname) => !integerIdLookup.test(pathname))
      ).toEqual([]);
    }
  );
});
