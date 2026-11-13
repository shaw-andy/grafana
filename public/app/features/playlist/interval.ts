import { rangeUtil } from '@grafana/data';

export const DEFAULT_PLAYLIST_INTERVAL = '5m';

const MIN_INTERVAL_MS = 1000;
// Browsers run a setTimeout delay above a signed 32-bit integer immediately.
const MAX_INTERVAL_MS = 2147483647;
// Matches the formats the playlist API accepts.
const INTERVAL_PATTERN = /^\d+(?:\.\d+)?(ms|[Mwdhmsy])?$/;

function parseIntervalMs(interval: string): number | undefined {
  if (!INTERVAL_PATTERN.test(interval)) {
    return undefined;
  }
  try {
    const ms = rangeUtil.intervalToMs(interval);
    return Number.isFinite(ms) ? ms : undefined;
  } catch {
    return undefined;
  }
}

function parseValidIntervalMs(interval: string): number | undefined {
  const ms = parseIntervalMs(interval);
  return ms !== undefined && ms >= MIN_INTERVAL_MS && ms <= MAX_INTERVAL_MS ? ms : undefined;
}

export function isValidPlaylistInterval(interval: string): boolean {
  return parseValidIntervalMs(interval) !== undefined;
}

/**
 * Returns the delay between dashboards. Stored values outside the range the API accepts fall back to the default,
 * so the player never rotates (and periodically reloads the page) faster than once per second.
 */
export function getPlaylistIntervalMs(interval: string | undefined): number {
  return (
    (interval !== undefined && parseValidIntervalMs(interval)) || rangeUtil.intervalToMs(DEFAULT_PLAYLIST_INTERVAL)
  );
}
