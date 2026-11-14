import { lastValueFrom } from 'rxjs';

import {
  type AnnotationQuery,
  type DataQueryRequest,
  type DataSourceInstanceSettings,
  dateTime,
  type TimeRange,
} from '@grafana/data';
import { executeAnnotationQuery } from 'app/features/annotations/executeAnnotationQuery';
import { createDashboardModelFixture } from 'app/features/dashboard/state/__fixtures__/dashboardFixtures';

import { GrafanaDatasource } from './datasource';
import { type GrafanaQuery, GrafanaQueryType } from './types';

const hourStart = 1577836800000; // 2020-01-01T00:00:00.000Z
const minuteMs = 60_000;
const hourMs = 3_600_000;

const intervalError = 'Time region cron interval is shorter than 1 minute';
const capError = 'Time region query exceeds the maximum of 1000 ranges';

function range(fromMs: number, toMs: number): TimeRange {
  return {
    from: dateTime(fromMs),
    to: dateTime(toMs),
    raw: { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() },
  };
}

function everySecondRegion() {
  return {
    mode: 'cron' as const,
    cronExpr: '* * * * * *',
    duration: '1s',
    timezone: 'utc',
  };
}

function savedTimeRegionAnnotation(cronExpr: string) {
  return {
    name: 'Time regions',
    enable: true,
    iconColor: 'red',
    datasource: { type: 'datasource', uid: '-- Grafana --' },
    target: {
      refId: 'Anno',
      queryType: GrafanaQueryType.TimeRegions,
      timeRegion: {
        mode: 'cron' as const,
        cronExpr,
        duration: '1s',
        timezone: 'utc',
      },
    },
  };
}

describe('time region query limits', () => {
  const ds = new GrafanaDatasource({} as DataSourceInstanceSettings);
  const twoMinutes = range(hourStart, hourStart + 2 * minuteMs);
  const oneDay = range(hourStart, hourStart + 24 * hourMs);

  it('rejects an every-second panel query before building a frame', () => {
    const request = {
      targets: [
        {
          refId: 'A',
          queryType: GrafanaQueryType.TimeRegions,
          timeRegion: everySecondRegion(),
        },
      ],
      range: twoMinutes,
    } as DataQueryRequest<GrafanaQuery>;

    expect(() => ds.query(request)).toThrow(intervalError);
  });

  it('rejects an every-minute panel query that would emit more than 1000 ranges', () => {
    const request = {
      targets: [
        {
          refId: 'A',
          queryType: GrafanaQueryType.TimeRegions,
          timeRegion: {
            mode: 'cron',
            cronExpr: '0 * * * * *',
            duration: '1s',
            timezone: 'utc',
          },
        },
      ],
      range: oneDay,
    } as DataQueryRequest<GrafanaQuery>;

    expect(() => ds.query(request)).toThrow(capError);
  });

  it('rejects an every-second annotation query loaded from the saved target', async () => {
    await expect(
      ds.getAnnotations({
        annotation: {
          name: 'Time regions',
          target: {
            queryType: GrafanaQueryType.TimeRegions,
            timeRegion: everySecondRegion(),
          },
        },
        range: twoMinutes,
        rangeRaw: twoMinutes.raw,
        dashboard: undefined,
      } as unknown as Parameters<GrafanaDatasource['getAnnotations']>[0])
    ).rejects.toThrow(intervalError);
  });

  it('rejects the annotation after prepareQuery rewrites the outer query type', () => {
    const prepared = ds.annotations!.prepareQuery!(
      savedTimeRegionAnnotation('* * * * * *') as unknown as AnnotationQuery
    );

    expect(prepared?.queryType).toBe(GrafanaQueryType.Annotations);
    expect(() =>
      ds.query({
        targets: [prepared as GrafanaQuery],
        range: twoMinutes,
      } as DataQueryRequest<GrafanaQuery>)
    ).toThrow(intervalError);
  });

  it('does not emit one annotation event per second when the dashboard query runs', async () => {
    const dashboard = createDashboardModelFixture({
      panels: [{ id: 1, type: 'timeseries' }],
      time: { from: twoMinutes.raw.from, to: twoMinutes.raw.to },
    });

    let thrown: unknown;
    let result: { events?: unknown[]; panelData?: { error?: { message?: string } } } | undefined;
    try {
      result = await lastValueFrom(
        executeAnnotationQuery(
          { range: twoMinutes, dashboard, panel: {} as never },
          ds,
          savedTimeRegionAnnotation('* * * * * *') as unknown as AnnotationQuery
        )
      );
    } catch (error) {
      thrown = error;
    }

    if (thrown instanceof Error) {
      expect(thrown.message).toContain(intervalError);
      return;
    }

    expect(result?.events ?? []).toEqual([]);
    expect(result?.panelData?.error?.message).toContain(intervalError);
  });

  it('does not emit more than 1000 events for a once-per-minute annotation across a day', async () => {
    const dashboard = createDashboardModelFixture({
      panels: [{ id: 1, type: 'timeseries' }],
      time: { from: oneDay.raw.from, to: oneDay.raw.to },
    });

    let thrown: unknown;
    let result: { events?: unknown[]; panelData?: { error?: { message?: string } } } | undefined;
    try {
      result = await lastValueFrom(
        executeAnnotationQuery(
          { range: oneDay, dashboard, panel: {} as never },
          ds,
          savedTimeRegionAnnotation('0 * * * * *') as unknown as AnnotationQuery
        )
      );
    } catch (error) {
      thrown = error;
    }

    if (thrown instanceof Error) {
      expect(thrown.message).toContain(capError);
      return;
    }

    expect(result?.events?.length ?? 0).toBeLessThanOrEqual(1000);
    expect(result?.panelData?.error?.message).toContain(capError);
  });
});
