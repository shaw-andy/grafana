import { useFlagPlaylistsRBAC } from '@grafana/runtime/internal';
import { AccessControlAction } from 'app/types/accessControl';

import { type Playlist } from '../../api/clients/playlist/v1';
import { contextSrv } from '../../core/services/context_srv';
import { getGrafanaSearcher } from '../search/service/searcher';
import { type DashboardQueryResult, type SearchQuery } from '../search/service/types';

import { type PlaylistItemUI } from './types';

/** Matches MaxPlaylistItems enforced by the playlist API on create and update. */
export const MAX_PLAYLIST_ITEMS = 100;
const MAX_CONCURRENT_SEARCHES = 4;
const MAX_DASHBOARDS_PER_TAG = 50;

export function useCanWritePlaylists(): boolean {
  const enabled = useFlagPlaylistsRBAC();
  return enabled ? contextSrv.hasPermission(AccessControlAction.PlaylistsWrite) : contextSrv.isEditor;
}

function toSearchQuery(item: PlaylistItemUI): SearchQuery | undefined {
  switch (item.type) {
    case 'dashboard_by_id':
      throw new Error('invalid item (with id)');

    case 'dashboard_by_uid':
      return item.value ? { query: '*', kind: ['dashboard'], uid: [item.value], limit: 1 } : undefined;

    case 'dashboard_by_tag':
      return item.value
        ? { query: '*', kind: ['dashboard'], tags: [item.value], limit: MAX_DASHBOARDS_PER_TAG }
        : undefined;

    default:
      // Anything else would be an unfiltered search over every dashboard.
      return undefined;
  }
}

/**
 * Returns a copy with the dashboards loaded.
 *
 * Playlists saved before the item cap existed can be longer than MAX_PLAYLIST_ITEMS, so only that many
 * items are searched, a few at a time; the rest get no dashboards.
 */
export async function loadDashboards(items: PlaylistItemUI[]): Promise<PlaylistItemUI[]> {
  if (!items?.length) {
    return [];
  }

  const queries = items.slice(0, MAX_PLAYLIST_ITEMS).map(toSearchQuery);
  const dashboards: DashboardQueryResult[][] = items.map(() => []);

  const searcher = getGrafanaSearcher();
  let next = 0;
  const worker = async () => {
    while (next < queries.length) {
      const index = next++;
      const query = queries[index];
      if (!query) {
        continue;
      }
      try {
        const result = await searcher.search(query);
        dashboards[index] = result.view.map((v) => ({ ...v }));
      } catch {
        // A failed search leaves the item without dashboards, same as an empty result.
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_SEARCHES, queries.length) }, worker));

  return items.map((item, index) => ({ ...item, dashboards: dashboards[index] }));
}

export function getDefaultPlaylist(): Playlist {
  return {
    apiVersion: 'playlist.grafana.app/v1',
    kind: 'Playlist',
    spec: {
      items: [],
      interval: '5m',
      title: '',
    },
    metadata: {
      name: '',
    },
    status: {},
  };
}

export function searchPlaylists(playlists: Playlist[], query?: string): Playlist[] {
  if (!query?.length) {
    return playlists;
  }
  query = query.toLowerCase();
  return playlists.filter((v) => v.spec?.title.toLowerCase().includes(query!));
}
