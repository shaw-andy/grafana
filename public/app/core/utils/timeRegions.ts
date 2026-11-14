import { Cron } from 'croner';

import { type AbsoluteTimeRange, type TimeRange, durationToMilliseconds, parseDuration } from '@grafana/data';

export type TimeRegionMode = null | 'cron';
export interface TimeRegionConfig {
  mode?: TimeRegionMode;

  from?: string;
  fromDayOfWeek?: number; // 1-7

  to?: string;
  toDayOfWeek?: number; // 1-7

  timezone?: string;

  cronExpr?: string; // 0 9 * * 1-5
  duration?: string; // 8h
}

const secsInDay = 24 * 3600;

function getDurationSecs(
  fromDay: number,
  fromHour: number,
  fromMin: number,
  toDay: number,
  toHour: number,
  toMin: number
) {
  let days = toDay - fromDay;

  // account for rollover
  if (days < 0) {
    days += 7;
  }

  let fromSecs = fromHour * 3600 + fromMin * 60;
  let toSecs = toHour * 3600 + toMin * 60;

  let durSecs = 0;

  // account for toTime < fromTime on same day
  if (days === 0 && toSecs < fromSecs) {
    durSecs = 7 * secsInDay - (fromSecs - toSecs);
  } else {
    let daysSecs = days * secsInDay;
    durSecs = daysSecs - fromSecs + toSecs;
  }

  return durSecs;
}

export function convertToCron(
  fromDay?: number | null,
  from?: string | null,
  toDay?: number | null,
  to?: string | null
) {
  // valid defs must have a "from"
  if (fromDay == null && from == null) {
    return undefined;
  }

  const cronCfg = {
    cronExpr: '',
    duration: 0,
  };

  const isEveryDay = fromDay == null && toDay == null;
  // if the def contains only days of week, then they become end-day-inclusive
  const toDayEnd = fromDay != null && from == null && to == null;

  from ??= '00:00';

  // 1. create cron (only requires froms)
  let [fromHour, fromMin] = from.split(':').map((v) => +v);

  cronCfg.cronExpr = `${fromMin} ${fromHour} * * ${fromDay ?? '*'}`;

  // 2. determine duration
  fromDay ??= 1;
  toDay ??= fromDay;

  // e.g. from Wed to Fri (implies inclusive Fri)
  if (toDayEnd) {
    to = '00:00';
    toDay += toDay === 7 ? -6 : 1;
  }

  to ??= from;

  let [toHour, toMin] = to.split(':').map((v) => +v);

  let fromSecs = fromHour * 3600 + fromMin * 60;
  let toSecs = toHour * 3600 + toMin * 60;

  // e.g. every day from 22:00 to 02:00 (implied next day)
  // NOTE: the odd wrap-around case of toSecs < fromSecs in same day is handled inside getDurationSecs()
  if (isEveryDay && toSecs < fromSecs) {
    toDay += toDay === 7 ? -6 : 1;
  }

  cronCfg.duration = getDurationSecs(fromDay, fromHour, fromMin, toDay, toHour, toMin);

  return cronCfg;
}

export const MAX_TIME_REGION_RANGES = 1000;
export const MIN_TIME_REGION_CRON_INTERVAL_MS = 60_000;

export class TimeRegionLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TimeRegionLimitError';
  }
}

// A seconds field matching more than one second makes two of any three consecutive runs fall in the
// same minute, so checking the first three runs catches every sub-minute pattern.
function assertMinimumInterval(job: Cron, fromDate: Date) {
  const runs = job.nextRuns(3, fromDate);

  for (let i = 1; i < runs.length; i++) {
    if (+runs[i] - +runs[i - 1] < MIN_TIME_REGION_CRON_INTERVAL_MS) {
      throw new TimeRegionLimitError('Time region cron interval is shorter than 1 minute');
    }
  }
}

export function calculateTimesWithin(cfg: TimeRegionConfig, tRange: TimeRange): AbsoluteTimeRange[] {
  const ranges: AbsoluteTimeRange[] = [];

  let cronExpr = '';
  let durationMs = 0;

  let { fromDayOfWeek, from, toDayOfWeek, to, duration = '' } = cfg;

  if (cfg.mode === 'cron') {
    cronExpr = cfg.cronExpr ?? '';
    durationMs = durationToMilliseconds(parseDuration(duration));
  } else {
    // remove empty strings
    from = from === '' ? undefined : from;
    to = to === '' ? undefined : to;

    const cron = convertToCron(fromDayOfWeek, from, toDayOfWeek, to);

    if (cron != null) {
      cronExpr = cron.cronExpr;
      durationMs = cron.duration * 1e3;
    }
  }

  if (cronExpr === '') {
    return [];
  }

  try {
    let tz = cfg.timezone === 'browser' ? undefined : cfg.timezone === 'utc' ? 'Etc/UTC' : cfg.timezone;

    let job = new Cron(cronExpr, { timezone: tz });

    // get previous run that may overlap with start of timerange
    let fromDate: Date | null = new Date(tRange.from.valueOf() - durationMs);

    assertMinimumInterval(job, fromDate);

    let toMs = tRange.to.valueOf();
    let prevMs: number | undefined;
    let nextDate = job.nextRun(fromDate);

    while (nextDate != null) {
      let nextMs = +nextDate;

      if (nextMs > toMs) {
        break;
      } else if (prevMs != null && nextMs - prevMs < MIN_TIME_REGION_CRON_INTERVAL_MS) {
        throw new TimeRegionLimitError('Time region cron interval is shorter than 1 minute');
      } else if (ranges.length >= MAX_TIME_REGION_RANGES) {
        throw new TimeRegionLimitError(`Time region query exceeds the maximum of ${MAX_TIME_REGION_RANGES} ranges`);
      } else {
        ranges.push({
          from: nextMs,
          to: nextMs + durationMs,
        });
        prevMs = nextMs;
        nextDate = job.nextRun(nextDate);
      }
    }
  } catch (e) {
    if (e instanceof TimeRegionLimitError) {
      throw e;
    }

    // invalid expression
    console.error(e);
  }

  return ranges;
}
