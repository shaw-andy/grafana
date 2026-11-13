import { waitFor, render } from '@testing-library/react';
import { Routes, Route } from 'react-router-dom-v5-compat';
import { Observable } from 'rxjs';
import { TestProvider } from 'test/helpers/TestProvider';
import { renderHook } from 'test/test-utils';

import { locationService, setBackendSrv } from '@grafana/runtime';

import { type Playlist } from '../../api/clients/playlist/v1';
import { appEvents } from '../../core/app_events';
import { BackendSrv } from '../../core/services/backend_srv';
import { contextSrv } from '../../core/services/context_srv';

import { PlaylistSrv, playlistSrv } from './PlaylistSrv';
import PlaylistStartPage from './PlaylistStartPage';
import { type PlaylistItemUI } from './types';
import { usePlaylistItems } from './usePlaylistItems';
import { loadDashboards } from './utils';

// Playback must not turn a saved playlist into an unbounded burst of dashboard
// searches. These bounds are the contract: at most this many searches are
// issued, at most this many run at once, and each asks for at most this many hits.
const maxPlaylistSearches = 100;
const maxConcurrentPlaylistSearches = 4;
const maxHitsPerPlaylistSearch = 50;

class SearchGate {
  urls: string[] = [];
  inflightDashboard = 0;
  maxInflightDashboard = 0;
  private waiters: Array<() => void> = [];
  private playlist: Playlist | undefined;

  constructor(playlist?: Playlist) {
    this.playlist = playlist;
    const fromFetch = (input: string | Request): Observable<Response> => {
      const url = typeof input === 'string' ? input : input.url;
      this.urls.push(url);
      const dashboard = isDashboardSearch(url);
      if (dashboard) {
        this.inflightDashboard += 1;
        this.maxInflightDashboard = Math.max(this.maxInflightDashboard, this.inflightDashboard);
      }
      return new Observable<Response>((subscriber) => {
        const finish = () => {
          if (dashboard) {
            this.inflightDashboard -= 1;
          }
          subscriber.next(responseFor(url, this.playlist));
          subscriber.complete();
        };
        if (dashboard) {
          this.waiters.push(finish);
        } else {
          finish();
        }
      });
    };

    setBackendSrv(
      new BackendSrv({
        fromFetch,
        appEvents,
        contextSrv,
        logout: () => undefined,
      })
    );
  }

  dashboardUrls(): string[] {
    return this.urls.filter(isDashboardSearch);
  }

  releaseOne(): void {
    this.waiters.shift()?.();
  }

  releaseAll(): void {
    const pending = this.waiters.splice(0);
    for (const finish of pending) {
      finish();
    }
  }
}

function responseFor(url: string, playlist: Playlist | undefined): Response {
  if (url.includes('/api/dashboards/ids/') || url.includes('api/dashboards/ids/')) {
    const id = url.split('/').pop() ?? '0';
    return jsonResponse([`uid-${id}`]);
  }
  if (playlist && url.includes('/playlists/')) {
    return jsonResponse(playlist);
  }
  return jsonResponse({ hits: [], totalHits: 0 });
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function isDashboardSearch(url: string): boolean {
  const params = new URL(url, 'http://localhost').searchParams;
  return params.getAll('type').includes('dashboard');
}

function isMatchAllDashboardSearch(url: string): boolean {
  const params = new URL(url, 'http://localhost').searchParams;
  if (!params.getAll('type').includes('dashboard')) {
    return false;
  }
  const query = params.get('query');
  const broad = query === '*' || query === '' || query == null;
  const narrowed = params.has('tag') || params.has('name');
  return broad && !narrowed;
}

function limitOf(url: string): number {
  return Number(new URL(url, 'http://localhost').searchParams.get('limit'));
}

function tagItems(count: number): PlaylistItemUI[] {
  return Array.from({ length: count }, (_, index) => ({
    type: 'dashboard_by_tag' as const,
    value: `tag-${index}`,
  }));
}

function playlistOf(items: PlaylistItemUI[], name = 'wall'): Playlist {
  return {
    apiVersion: 'playlist.grafana.app/v1',
    kind: 'Playlist',
    metadata: { name },
    spec: { title: 'wall', interval: '5m', items },
    status: {},
  };
}

async function drain(pending: Promise<unknown>, gate: SearchGate): Promise<void> {
  const settled = pending.then(
    () => ({ ok: true as const }),
    (error: unknown) => ({ ok: false as const, error })
  );
  for (let step = 0; step < 400; step++) {
    const winner = await Promise.race([
      settled.then((value) => ({ done: true as const, value })),
      new Promise<{ done: false }>((resolve) => setTimeout(() => resolve({ done: false }), 0)),
    ]);
    if (winner.done) {
      if (!winner.value.ok) {
        throw winner.value.error;
      }
      return;
    }
    gate.releaseOne();
  }
  gate.releaseAll();
  const result = await settled;
  if (!result.ok) {
    throw result.error;
  }
}

describe('playlist playback search fan-out', () => {
  beforeEach(() => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    playlistSrv.stop();
  });

  it('searches one tag with a small limit', async () => {
    const gate = new SearchGate();
    const pending = loadDashboards(tagItems(1));
    await drain(pending, gate);

    expect(gate.dashboardUrls()).toHaveLength(1);
    expect(gate.dashboardUrls()[0]).toContain('tag=tag-0');
    expect(limitOf(gate.dashboardUrls()[0])).toBeLessThanOrEqual(maxHitsPerPlaylistSearch);
  });

  it('does not start every tag search at once', async () => {
    const gate = new SearchGate();
    const pending = loadDashboards(tagItems(20));

    await waitFor(() => {
      expect(gate.dashboardUrls().length).toBeGreaterThan(0);
    });
    expect(gate.maxInflightDashboard).toBeLessThanOrEqual(maxConcurrentPlaylistSearches);
    for (const url of gate.dashboardUrls()) {
      expect(limitOf(url)).toBeLessThanOrEqual(maxHitsPerPlaylistSearch);
    }

    await drain(pending, gate);
    expect(gate.dashboardUrls()).toHaveLength(20);
    expect(gate.maxInflightDashboard).toBeLessThanOrEqual(maxConcurrentPlaylistSearches);
    expect(gate.dashboardUrls().some(isMatchAllDashboardSearch)).toBe(false);
  });

  it('does not search every item once the playlist is past the cap', async () => {
    const gate = new SearchGate();
    const pending = loadDashboards(tagItems(maxPlaylistSearches + 50));
    await drain(pending, gate);

    expect(gate.dashboardUrls().length).toBeLessThanOrEqual(maxPlaylistSearches);
    expect(gate.maxInflightDashboard).toBeLessThanOrEqual(maxConcurrentPlaylistSearches);
    for (const url of gate.dashboardUrls()) {
      expect(limitOf(url)).toBeLessThanOrEqual(maxHitsPerPlaylistSearch);
    }
  });

  it('does not issue a match-all dashboard search for an unrecognized item', async () => {
    const gate = new SearchGate();
    let state: 'pending' | 'done' | 'error' = 'pending';
    const pending = loadDashboards([{ type: 'not_a_playlist_type', value: 'x' } as PlaylistItemUI]).then(
      () => {
        state = 'done';
      },
      () => {
        state = 'error';
      }
    );

    await waitFor(() => {
      expect(state !== 'pending' || gate.dashboardUrls().length > 0).toBe(true);
    });
    expect(gate.dashboardUrls().filter(isMatchAllDashboardSearch)).toHaveLength(0);
    gate.releaseAll();
    await pending;
  });

  it('starts playback through the same search limits', async () => {
    const gate = new SearchGate();
    const srv = new PlaylistSrv();
    const pending = srv.start(playlistOf(tagItems(20)));

    await waitFor(() => {
      expect(gate.dashboardUrls().length).toBeGreaterThan(0);
    });
    expect(gate.maxInflightDashboard).toBeLessThanOrEqual(maxConcurrentPlaylistSearches);
    for (const url of gate.dashboardUrls()) {
      expect(limitOf(url)).toBeLessThanOrEqual(maxHitsPerPlaylistSearch);
    }

    await drain(pending, gate);
    expect(gate.dashboardUrls()).toHaveLength(20);
    srv.stop();
  });

  it('loads edit-form items through the same search limits', async () => {
    const items = tagItems(20);
    const gate = new SearchGate();
    renderHook(() => usePlaylistItems(items));

    await waitFor(() => {
      expect(gate.dashboardUrls().length).toBeGreaterThan(0);
    });
    expect(gate.maxInflightDashboard).toBeLessThanOrEqual(maxConcurrentPlaylistSearches);
    for (const url of gate.dashboardUrls()) {
      expect(limitOf(url)).toBeLessThanOrEqual(maxHitsPerPlaylistSearch);
      expect(url).toContain('tag=tag-');
    }

    for (let step = 0; step < 40; step++) {
      gate.releaseOne();
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    await waitFor(() => {
      expect(gate.dashboardUrls()).toHaveLength(20);
    });
  });

  it('fires the searches when the play page receives the playlist', async () => {
    const items = tagItems(20);
    const gate = new SearchGate(playlistOf(items, 'wall'));
    locationService.push('/playlists/play/wall');
    render(
      <TestProvider>
        <Routes>
          <Route path="/playlists/play/:uid" element={<PlaylistStartPage />} />
        </Routes>
      </TestProvider>
    );

    await waitFor(() => {
      expect(gate.dashboardUrls().length).toBeGreaterThan(0);
    });
    expect(gate.maxInflightDashboard).toBeLessThanOrEqual(maxConcurrentPlaylistSearches);
    for (const url of gate.dashboardUrls()) {
      expect(limitOf(url)).toBeLessThanOrEqual(maxHitsPerPlaylistSearch);
      expect(isMatchAllDashboardSearch(url)).toBe(false);
    }
    gate.releaseAll();
  });

  it('still limits searches after a saved dashboard id is migrated to a uid', async () => {
    const items: PlaylistItemUI[] = Array.from({ length: 8 }, (_, index) => ({
      type: 'dashboard_by_id' as const,
      value: String(index + 1),
    }));
    const gate = new SearchGate(playlistOf(items, 'legacy'));
    locationService.push('/playlists/play/legacy');
    render(
      <TestProvider>
        <Routes>
          <Route path="/playlists/play/:uid" element={<PlaylistStartPage />} />
        </Routes>
      </TestProvider>
    );

    await waitFor(() => {
      expect(gate.dashboardUrls().length).toBeGreaterThan(0);
    });
    expect(gate.maxInflightDashboard).toBeLessThanOrEqual(maxConcurrentPlaylistSearches);
    for (const url of gate.dashboardUrls()) {
      expect(limitOf(url)).toBeLessThanOrEqual(maxHitsPerPlaylistSearch);
      expect(isMatchAllDashboardSearch(url)).toBe(false);
      expect(url).toContain('name=uid-');
    }
    gate.releaseAll();
  });
});
