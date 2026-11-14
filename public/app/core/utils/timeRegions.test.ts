import type { Duration } from 'date-fns';

import { type AbsoluteTimeRange, dateTimeForTimeZone, reverseParseDuration, type TimeRange } from '@grafana/data';
import { convertToCron, type TimeRegionConfig } from 'app/core/utils/timeRegions';

import { calculateTimesWithin } from './timeRegions';

// random from the interwebs
function durationFromSeconds(seconds: number): Duration {
  const secondsInYear = 31536000;
  const secondsInMonth = 2628000;
  const secondsInDay = 86400;
  const secondsInHour = 3600;
  const secondsInMinute = 60;

  let years = Math.floor(seconds / secondsInYear);
  let remainingSeconds = seconds % secondsInYear;

  let months = Math.floor(remainingSeconds / secondsInMonth);
  remainingSeconds %= secondsInMonth;

  let days = Math.floor(remainingSeconds / secondsInDay);
  remainingSeconds %= secondsInDay;

  let hours = Math.floor(remainingSeconds / secondsInHour);
  remainingSeconds %= secondsInHour;

  let minutes = Math.floor(remainingSeconds / secondsInMinute);
  let finalSeconds = remainingSeconds % secondsInMinute;

  return {
    years,
    months,
    days,
    hours,
    minutes,
    seconds: finalSeconds,
  };
}

function tsToDayOfWeek(ts: number, tz?: string) {
  return new Date(ts).toLocaleString('en', {
    timeZone: tz,
    weekday: 'short',
  });
}

function tsToDateTimeString(ts: number, tz?: string) {
  return new Date(ts).toLocaleString('sv', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: tz,
    timeZoneName: 'short',
  });
}

function formatAbsoluteRange(range: AbsoluteTimeRange, tz?: string) {
  return {
    fr: `${tsToDayOfWeek(range.from, tz)} | ${tsToDateTimeString(range.from, tz)}`.replaceAll('−', '-'),
    to: `${tsToDayOfWeek(range.to, tz)} | ${tsToDateTimeString(range.to, tz)}`.replaceAll('−', '-'),
  };
}

describe('timeRegions', () => {
  describe('day of week', () => {
    it('returns regions with 4 Mondays in March 2023', () => {
      const dashboardTz = 'America/Chicago';
      const regionsTz = dashboardTz;

      const cfg: TimeRegionConfig = {
        timezone: regionsTz,
        fromDayOfWeek: 1,
      };

      const tr: TimeRange = {
        from: dateTimeForTimeZone(dashboardTz, '2023-03-01'),
        to: dateTimeForTimeZone(dashboardTz, '2023-03-31'),
        raw: {
          to: '',
          from: '',
        },
      };

      const regions = calculateTimesWithin(cfg, tr);
      const formatted = regions.map((r) => formatAbsoluteRange(r, regionsTz));
      expect(formatted).toEqual([
        {
          fr: 'Mon | 2023-03-06 00:00:00 GMT-6',
          to: 'Tue | 2023-03-07 00:00:00 GMT-6',
        },
        {
          fr: 'Mon | 2023-03-13 00:00:00 GMT-5',
          to: 'Tue | 2023-03-14 00:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-20 00:00:00 GMT-5',
          to: 'Tue | 2023-03-21 00:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-27 00:00:00 GMT-5',
          to: 'Tue | 2023-03-28 00:00:00 GMT-5',
        },
      ]);
    });
  });
  describe('day and time of week', () => {
    it('returns regions with 4 Mondays at 20:00 in March 2023', () => {
      const dashboardTz = 'America/Chicago';
      const regionsTz = dashboardTz;

      const cfg: TimeRegionConfig = {
        timezone: regionsTz,
        fromDayOfWeek: 1,
        from: '20:00',
      };

      const tr: TimeRange = {
        from: dateTimeForTimeZone(dashboardTz, '2023-03-01'),
        to: dateTimeForTimeZone(dashboardTz, '2023-03-31'),
        raw: {
          to: '',
          from: '',
        },
      };

      const regions = calculateTimesWithin(cfg, tr);
      const formatted = regions.map((r) => formatAbsoluteRange(r, regionsTz));
      expect(formatted).toEqual([
        {
          fr: 'Mon | 2023-03-06 20:00:00 GMT-6',
          to: 'Mon | 2023-03-06 20:00:00 GMT-6',
        },
        {
          fr: 'Mon | 2023-03-13 20:00:00 GMT-5',
          to: 'Mon | 2023-03-13 20:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-20 20:00:00 GMT-5',
          to: 'Mon | 2023-03-20 20:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-27 20:00:00 GMT-5',
          to: 'Mon | 2023-03-27 20:00:00 GMT-5',
        },
      ]);
    });
  });
  describe('day of week range', () => {
    it('returns regions with days range', () => {
      const dashboardTz = 'America/Chicago';
      const regionsTz = dashboardTz;

      const cfg: TimeRegionConfig = {
        timezone: regionsTz,
        fromDayOfWeek: 1,
        toDayOfWeek: 3,
      };

      const tr: TimeRange = {
        from: dateTimeForTimeZone(dashboardTz, '2023-03-01'),
        to: dateTimeForTimeZone(dashboardTz, '2023-03-31'),
        raw: {
          to: '',
          from: '',
        },
      };

      const regions = calculateTimesWithin(cfg, tr);
      const formatted = regions.map((r) => formatAbsoluteRange(r, regionsTz));
      expect(formatted).toEqual([
        {
          fr: 'Mon | 2023-02-27 00:00:00 GMT-6',
          to: 'Thu | 2023-03-02 00:00:00 GMT-6',
        },
        {
          fr: 'Mon | 2023-03-06 00:00:00 GMT-6',
          to: 'Thu | 2023-03-09 00:00:00 GMT-6',
        },
        {
          fr: 'Mon | 2023-03-13 00:00:00 GMT-5',
          to: 'Thu | 2023-03-16 00:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-20 00:00:00 GMT-5',
          to: 'Thu | 2023-03-23 00:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-27 00:00:00 GMT-5',
          to: 'Thu | 2023-03-30 00:00:00 GMT-5',
        },
      ]);
    });

    it('returns regions with days range (browser time zone)', () => {
      const dashboardTz = process.env.TZ;
      const regionsTz = dashboardTz;

      const cfg: TimeRegionConfig = {
        timezone: regionsTz,
        fromDayOfWeek: 1,
        toDayOfWeek: 3,
      };

      const tr: TimeRange = {
        from: dateTimeForTimeZone(dashboardTz, '2023-03-01'),
        to: dateTimeForTimeZone(dashboardTz, '2023-03-31'),
        raw: {
          to: '',
          from: '',
        },
      };

      const regions = calculateTimesWithin(cfg, tr);
      const formatted = regions.map((r) => formatAbsoluteRange(r, regionsTz));
      expect(formatted).toEqual([
        {
          fr: 'Mon | 2023-02-27 00:00:00 GMT-5',
          to: 'Thu | 2023-03-02 00:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-06 00:00:00 GMT-5',
          to: 'Thu | 2023-03-09 00:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-13 00:00:00 GMT-5',
          to: 'Thu | 2023-03-16 00:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-20 00:00:00 GMT-5',
          to: 'Thu | 2023-03-23 00:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-27 00:00:00 GMT-5',
          to: 'Thu | 2023-03-30 00:00:00 GMT-5',
        },
      ]);
    });

    it('returns regions with days/times range', () => {
      const dashboardTz = 'America/Chicago';
      const regionsTz = dashboardTz;

      const cfg: TimeRegionConfig = {
        timezone: regionsTz,
        fromDayOfWeek: 1,
        from: '20:00',
        toDayOfWeek: 2,
        to: '10:00',
      };

      const tr: TimeRange = {
        from: dateTimeForTimeZone(dashboardTz, '2023-03-01'),
        to: dateTimeForTimeZone(dashboardTz, '2023-03-31'),
        raw: {
          to: '',
          from: '',
        },
      };

      const regions = calculateTimesWithin(cfg, tr);
      const formatted = regions.map((r) => formatAbsoluteRange(r, regionsTz));
      expect(formatted).toEqual([
        {
          fr: 'Mon | 2023-03-06 20:00:00 GMT-6',
          to: 'Tue | 2023-03-07 10:00:00 GMT-6',
        },
        {
          fr: 'Mon | 2023-03-13 20:00:00 GMT-5',
          to: 'Tue | 2023-03-14 10:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-20 20:00:00 GMT-5',
          to: 'Tue | 2023-03-21 10:00:00 GMT-5',
        },
        {
          fr: 'Mon | 2023-03-27 20:00:00 GMT-5',
          to: 'Tue | 2023-03-28 10:00:00 GMT-5',
        },
      ]);
    });
  });

  type TestDef = [
    name: string,
    fromDayOfWeek: number | null,
    from: string | null,
    toDayOfWeek: number | null,
    to: string | null,
    cronExpr: string,
    duration: string,
  ];

  let _ = null;

  describe('various scenarios (regions)', () => {
    /* eslint-disable */
    // prettier-ignore
    let tests: TestDef[] = [
      ['from every day (time before) to every day (time after)',  _, '10:27', _, '14:27', '27 10 * * *', '4h'],
      ['from every day (time after)  to every day (time before)', _, '22:27', _, '02:27', '27 22 * * *', '4h'],
      ['from every day (time)        to every day (no time)',     _, '10:27', _,       _, '27 10 * * *',   ''],
      ['from fri (no time)',                                      5,       _, _,       _,   '0 0 * * 5', '1d'],
      ['from fri (no time)           to tues (no time)',          5,       _, 2,       _,   '0 0 * * 5', '5d'],
      ['from fri (no time)           to tues (time)',             5,       _, 2, '02:27',   '0 0 * * 5', '4d 2h 27m'],
      ['from fri (time)              to tues (no time)',          5, '10:27', 2,       _, '27 10 * * 5', '4d'],
      ['from fri (time)              to tues (time)',             5, '10:27', 2, '14:27', '27 10 * * 5', '4d 4h'],

      // same day
      ['from fri (time before)       to fri (time after)',        5, '10:27', 5, '14:27', '27 10 * * 5', '4h'],
      // "toDay" should assume Fri
      ['from fri (time before)       to every day (time after)',  5, '10:27', _, '14:27', '27 10 * * 5', '4h'],
      // wrap-around case
      ['from fri (time after)        to fri (time before)',       5, '14:27', 5, '10:27', '27 14 * * 5', '6d 20h'],

    ];
    /* eslint-enable */

    tests.forEach(([name, fromDayOfWeek, from, toDayOfWeek, to, cronExpr, duration]) => {
      it(name, () => {
        const cron = convertToCron(fromDayOfWeek, from, toDayOfWeek, to);

        expect(cron).not.toBeUndefined();
        expect(cron?.cronExpr).toEqual(cronExpr);
        expect(reverseParseDuration(durationFromSeconds(cron?.duration ?? 0), false)).toEqual(duration);
      });
    });
  });

  describe('various scenarios (points)', () => {
    /* eslint-disable */
    // prettier-ignore
    let tests: TestDef[] = [
      ['from every day (time)',                            _, '10:03', _, _,       '3 10 * * *', ''],
      ['from every day (time)        to every day (time)', _, '10:03', _, '10:03', '3 10 * * *', ''],
      ['from tues      (time)',                            2, '10:03', _,       _, '3 10 * * 2', ''],
      ['from tues      (time)        to tues      (time)', 2, '10:03', _, '10:03', '3 10 * * 2', ''],
    ];
    /* eslint-enable */

    tests.forEach(([name, fromDayOfWeek, from, toDayOfWeek, to, cronExpr, duration]) => {
      it(name, () => {
        const cron = convertToCron(fromDayOfWeek, from, toDayOfWeek, to);

        expect(cron).not.toBeUndefined();
        expect(cron?.cronExpr).toEqual(cronExpr);
        expect(reverseParseDuration(durationFromSeconds(cron?.duration ?? 0), false)).toEqual(duration);
      });
    });
  });

  describe('convert simple time region config to cron string and duration', () => {
    it.each`
      from       | fromDOW | to         | toDOW | timezone     | expectedCron   | expectedDuration
      ${'03:03'} | ${1}    | ${'03:03'} | ${2}  | ${'browser'} | ${'3 3 * * 1'} | ${'1d'}
      ${'03:03'} | ${7}    | ${'03:03'} | ${1}  | ${'browser'} | ${'3 3 * * 7'} | ${'1d'}
      ${'09:03'} | ${7}    | ${'03:03'} | ${1}  | ${'browser'} | ${'3 9 * * 7'} | ${'18h'}
      ${'03:03'} | ${7}    | ${'04:03'} | ${7}  | ${'browser'} | ${'3 3 * * 7'} | ${'1h'}
      ${'03:03'} | ${7}    | ${'02:03'} | ${7}  | ${'browser'} | ${'3 3 * * 7'} | ${'6d 23h'}
      ${'03:03'} | ${7}    | ${'3:03'}  | ${7}  | ${'browser'} | ${'3 3 * * 7'} | ${''}
    `(
      "time region config with from time '$from' and DOW '$fromDOW', to: '$to' and DOW '$toDOW' should generate a cron string of '$expectedCron' and '$expectedDuration'",
      ({ from, fromDOW, to, toDOW, timezone, expectedCron, expectedDuration }) => {
        const timeConfig: TimeRegionConfig = { from, fromDayOfWeek: fromDOW, to, toDayOfWeek: toDOW, timezone };
        const convertedCron = convertToCron(
          timeConfig.fromDayOfWeek,
          timeConfig.from,
          timeConfig.toDayOfWeek,
          timeConfig.to
        )!;
        expect(convertedCron).not.toBeUndefined();
        expect(convertedCron.cronExpr).toEqual(expectedCron);
        expect(reverseParseDuration(durationFromSeconds(convertedCron.duration), false)).toEqual(expectedDuration);
      }
    );
  });

  // A stored cron is expanded once per tick for the whole dashboard range. Sub-minute
  // expressions are rejected, and every other walk stops at 1000 ranges, so opening a
  // dashboard cannot build one range object per second across that range.
  describe('range limits', () => {
    const hourStart = 1577836800000; // 2020-01-01T00:00:00.000Z
    const minuteMs = 60_000;
    const hourMs = 3_600_000;

    const range = (fromMs: number, toMs: number): TimeRange => ({
      from: dateTimeForTimeZone('utc', fromMs),
      to: dateTimeForTimeZone('utc', toMs),
      raw: { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() },
    });

    it('returns one range per hour for an hourly cron inside a six hour window', () => {
      const ranges = calculateTimesWithin(
        { mode: 'cron', cronExpr: '0 0 * * * *', duration: '1s', timezone: 'utc' },
        range(hourStart, hourStart + 5 * hourMs)
      );

      expect(ranges).toEqual([
        { from: hourStart, to: hourStart + 1000 },
        { from: hourStart + hourMs, to: hourStart + hourMs + 1000 },
        { from: hourStart + 2 * hourMs, to: hourStart + 2 * hourMs + 1000 },
        { from: hourStart + 3 * hourMs, to: hourStart + 3 * hourMs + 1000 },
        { from: hourStart + 4 * hourMs, to: hourStart + 4 * hourMs + 1000 },
        { from: hourStart + 5 * hourMs, to: hourStart + 5 * hourMs + 1000 },
      ]);
    });

    it('returns one range per minute for a five-field cron inside a ten minute window', () => {
      const ranges = calculateTimesWithin(
        { mode: 'cron', cronExpr: '* * * * *', duration: '1s', timezone: 'utc' },
        range(hourStart, hourStart + 10 * minuteMs)
      );

      expect(ranges.map((r) => r.from)).toEqual(
        Array.from({ length: 11 }, (_, index) => hourStart + index * minuteMs)
      );
    });

    it('rejects a cron expression that fires every second', () => {
      expect(() =>
        calculateTimesWithin(
          { mode: 'cron', cronExpr: '* * * * * *', duration: '1s', timezone: 'utc' },
          range(hourStart, hourStart + 2 * minuteMs)
        )
      ).toThrow('Time region cron interval is shorter than 1 minute');
    });

    it('rejects a cron expression that fires every thirty seconds', () => {
      expect(() =>
        calculateTimesWithin(
          { mode: 'cron', cronExpr: '*/30 * * * * *', duration: '1s', timezone: 'utc' },
          range(hourStart, hourStart + 5 * minuteMs)
        )
      ).toThrow('Time region cron interval is shorter than 1 minute');
    });

    it('stops a once-per-minute cron after 1000 ranges', () => {
      expect(() =>
        calculateTimesWithin(
          { mode: 'cron', cronExpr: '0 * * * * *', duration: '1s', timezone: 'utc' },
          range(hourStart, hourStart + 24 * hourMs)
        )
      ).toThrow('Time region query exceeds the maximum of 1000 ranges');
    });

    it('stops a five-field every-minute cron after 1000 ranges', () => {
      expect(() =>
        calculateTimesWithin(
          { mode: 'cron', cronExpr: '* * * * *', duration: '1s', timezone: 'utc' },
          range(hourStart, hourStart + 24 * hourMs)
        )
      ).toThrow('Time region query exceeds the maximum of 1000 ranges');
    });

    it('stops an every-day region after 1000 ranges', () => {
      const fromMs = hourStart;
      const toMs = Date.parse('2023-01-15T00:00:00.000Z');

      expect(() =>
        calculateTimesWithin({ from: '00:00', timezone: 'utc' }, range(fromMs, toMs))
      ).toThrow('Time region query exceeds the maximum of 1000 ranges');
    });
  });
});
