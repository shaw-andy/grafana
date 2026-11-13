import { type Store } from 'redux';
import configureMockStore from 'redux-mock-store';

import { locationService } from '@grafana/runtime';
import { setStore } from 'app/store/store';

import { type Playlist } from '../../api/clients/playlist/v1';
import { type DashboardQueryResult } from '../search/service/types';

import { PlaylistSrv } from './PlaylistSrv';
import { type PlaylistItemUI } from './types';

jest.mock('./utils', () => ({
  loadDashboards: (items: PlaylistItemUI[]) => {
    return Promise.resolve(
      items.map((v) => ({
        ...v, // same item with dashboard URLs filled in
        dashboards: [{ url: `/url/to/${v.value}` } as unknown as DashboardQueryResult],
      }))
    );
  },
}));

const mockPlaylist: Playlist = {
  apiVersion: 'playlist.grafana.app/v1',
  kind: 'Playlist',
  spec: {
    interval: '1s',
    title: 'The display',
    items: [
      { type: 'dashboard_by_uid', value: 'aaa' },
      { type: 'dashboard_by_uid', value: 'bbb' },
    ],
  },
  metadata: {
    name: 'xyz',
  },
  status: {},
};

const mockStore = configureMockStore();

setStore(
  mockStore({
    location: {},
  }) as Store
);

function createPlaylistSrv(): PlaylistSrv {
  locationService.push('/playlists/foo');
  return new PlaylistSrv();
}

const mockWindowLocation = (): [jest.Mock, () => void] => {
  const win: typeof globalThis = window;
  const oldLocation = win.location;
  const hrefMock = jest.fn();

  // JSDom defines window in a way that you cannot tamper with location so this seems to be the only way to change it.
  // https://github.com/facebook/jest/issues/5124#issuecomment-446659510
  //@ts-ignore
  delete win.location;

  win.location = {} as Location;

  // Only mocking href as that is all this test needs, but otherwise there is lots of things missing, so keep that
  // in mind if this is reused.
  Object.defineProperty(window.location, 'href', {
    set: hrefMock,
    get: hrefMock,
  });
  const unmock = () => {
    win.location = oldLocation;
  };
  return [hrefMock, unmock];
};

describe('PlaylistSrv', () => {
  let srv: PlaylistSrv;
  let hrefMock: jest.Mock;
  let unmockLocation: () => void;
  const initialUrl = 'http://localhost/playlist';

  beforeEach(() => {
    jest.clearAllMocks();

    srv = createPlaylistSrv();
    [hrefMock, unmockLocation] = mockWindowLocation();

    // This will be cached in the srv when start() is called
    hrefMock.mockReturnValue(initialUrl);
  });

  afterEach(() => {
    unmockLocation();
  });

  it('runs all dashboards in cycle and reloads page after 3 cycles', async () => {
    await srv.start(mockPlaylist);

    for (let i = 0; i < 6; i++) {
      srv.next();
    }

    expect(hrefMock).toHaveBeenCalledTimes(2);
    expect(hrefMock).toHaveBeenLastCalledWith(initialUrl);
  });

  it('keeps the refresh counter value after restarting', async () => {
    await srv.start(mockPlaylist);

    // 1 complete loop
    for (let i = 0; i < 3; i++) {
      srv.next();
    }

    srv.stop();
    await srv.start(mockPlaylist);

    // Another 2 loops
    for (let i = 0; i < 4; i++) {
      srv.next();
    }

    expect(hrefMock).toHaveBeenCalledTimes(3);
    expect(hrefMock).toHaveBeenLastCalledWith(initialUrl);
  });

  it('Should stop playlist when navigating away', async () => {
    await srv.start(mockPlaylist);

    locationService.push('/datasources');

    expect(srv.state.isPlaying).toBe(false);
  });

  it('storeUpdated should not stop playlist when navigating to next dashboard', async () => {
    await srv.start(mockPlaylist);

    // eslint-disable-next-line
    expect((srv as any).validPlaylistUrl).toBe('/url/to/aaa');

    srv.next();

    // eslint-disable-next-line
    expect((srv as any).validPlaylistUrl).toBe('/url/to/bbb');
    expect(srv.state.isPlaying).toBe(true);
  });

  it('should replace playlist start page in history when starting playlist', async () => {
    // Start at playlists page
    locationService.push('/playlists');

    // Navigate to playlist start page
    locationService.push('/playlists/play/foo');

    // Start the playlist
    await srv.start(mockPlaylist);

    // Get history entries via the underlying MemoryHistory (test-env only)
    const history = locationService.getHistory();
    const entries = (history as unknown as { base: { entries: Location[] } }).base.entries;

    // The current entry should be the first dashboard
    expect(entries[entries.length - 1].pathname).toBe('/url/to/aaa');

    // The previous entry should be the playlists page, not the start page
    expect(entries[entries.length - 2].pathname).toBe('/playlists');

    // Verify the start page (/playlists/play/foo) is not in history
    const hasStartPage = entries.some((entry: { pathname: string }) => entry.pathname === '/playlists/play/foo');
    expect(hasStartPage).toBe(false);
  });

  // describeInterval parses the count with parseInt, so fractional intervals such as
  // "0.5s" and "0.0s" are 0ms. Negative units and a bare "-1" are negative milliseconds.
  // A non-positive delay is what makes the play page rotate and then reload immediately.
  const nonPositiveIntervals = ['0s', '-1s', '0ms', '-1', '0.5s', '00s', '0.0s', '-0.1s'];
  const minimumNonPositiveDelayMs = 5000;

  function playlistWithInterval(interval: string): Playlist {
    return {
      ...mockPlaylist,
      spec: {
        title: 'The display',
        interval,
        items: [{ type: 'dashboard_by_uid', value: 'aaa' }],
      },
    };
  }

  function captureScheduledTimers() {
    const scheduled: Array<{ callback: () => void; delay: number }> = [];
    const spy = jest.spyOn(global, 'setTimeout').mockImplementation(((callback: TimerHandler, delay?: number) => {
      const numericDelay = typeof delay === 'number' ? delay : 0;
      scheduled.push({
        callback: () => {
          if (typeof callback === 'function') {
            callback();
          }
        },
        delay: numericDelay,
      });
      return scheduled.length as unknown as ReturnType<typeof setTimeout>;
    }) as typeof setTimeout);
    return { scheduled, restore: () => spy.mockRestore() };
  }

  // jsdom clamps a negative timeout to 0 and Node then runs a sub-1ms timeout on the next tick,
  // so a delay that is not positive fires before any later timer. Run only those callbacks.
  function runNonPositiveTimers(scheduled: Array<{ callback: () => void; delay: number }>) {
    let ran = 0;
    while (ran < 30) {
      const index = scheduled.findIndex((timer) => timer.delay <= 0);
      if (index < 0) {
        return;
      }
      const [timer] = scheduled.splice(index, 1);
      timer.callback();
      ran += 1;
    }
  }

  describe('when the stored interval is non-positive', () => {
    it.each(nonPositiveIntervals)('schedules %s at least 5 seconds later', async (interval) => {
      const { scheduled, restore } = captureScheduledTimers();
      try {
        await srv.start(playlistWithInterval(interval));

        expect(scheduled.length).toBeGreaterThan(0);
        for (const timer of scheduled) {
          expect(timer.delay).toBeGreaterThanOrEqual(minimumNonPositiveDelayMs);
        }
      } finally {
        restore();
        srv.stop();
      }
    });

    it.each(nonPositiveIntervals)(
      'does not assign the play URL back to the window when %s would fire immediately',
      async (interval) => {
        const { scheduled, restore } = captureScheduledTimers();
        try {
          await srv.start(playlistWithInterval(interval));
          runNonPositiveTimers(scheduled);

          expect(hrefMock).not.toHaveBeenCalledWith(initialUrl);
        } finally {
          restore();
          srv.stop();
        }
      }
    );
  });

  describe('when the stored interval is already a positive duration', () => {
    it.each([
      ['1s', 1000],
      ['5s', 5000],
      ['10s', 10000],
      ['5m', 300000],
    ])('schedules %s as %d milliseconds', async (interval, delay) => {
      const { scheduled, restore } = captureScheduledTimers();
      try {
        await srv.start(playlistWithInterval(interval));

        expect(scheduled).toHaveLength(1);
        expect(scheduled[0].delay).toBe(delay);
      } finally {
        restore();
        srv.stop();
      }
    });
  });
});
