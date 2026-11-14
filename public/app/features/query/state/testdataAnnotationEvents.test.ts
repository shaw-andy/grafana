import { lastValueFrom } from 'rxjs';

import { DataTopic, type DataSourceInstanceSettings, dateTime } from '@grafana/data';
import { type TemplateSrv } from '@grafana/runtime';
import { executeAnnotationQuery } from 'app/features/annotations/executeAnnotationQuery';
import { type PanelModel } from 'app/features/dashboard/state/PanelModel';
import { createDashboardModelFixture } from 'app/features/dashboard/state/__fixtures__/dashboardFixtures';
import { TestDataQueryType } from 'app/plugins/datasource/grafana-testdata-datasource/dataquery';
import { TestDataDataSource } from 'app/plugins/datasource/grafana-testdata-datasource/datasource';

import { runRequest } from './runRequest';

const MAX_ANNOTATION_EVENTS = 10000;
const ANNOTATION_TEXT = 'This is the text, <a href="https://grafana.com">Grafana.com</a>';

function createDatasource() {
  return new TestDataDataSource(
    {
      id: 1,
      uid: 'testdata',
      type: 'grafana-testdata-datasource',
      name: 'TestData',
      jsonData: {},
      access: 'proxy',
      readOnly: false,
      meta: { id: 'grafana-testdata-datasource' },
    } as DataSourceInstanceSettings,
    { replace: (target?: string) => target ?? '' } as TemplateSrv
  );
}

function countAnnotationPushes(run: () => Promise<void>): Promise<number> {
  let built = 0;
  const originalPush = Array.prototype.push;
  Array.prototype.push = function push(this: unknown[], ...items: unknown[]) {
    for (const item of items) {
      if (
        item !== null &&
        typeof item === 'object' &&
        (item as { text?: unknown }).text === ANNOTATION_TEXT &&
        Array.isArray((item as { tags?: unknown }).tags)
      ) {
        built += 1;
      }
    }
    return originalPush.apply(this, items);
  };

  return run()
    .finally(() => {
      Array.prototype.push = originalPush;
    })
    .then(() => built);
}

describe('TestData annotation queries through the dashboard runners', () => {
  const range = {
    from: dateTime(0),
    to: dateTime(60_000),
    raw: { from: 'now-1m', to: 'now' },
  };

  it('gives the panel 10000 annotation rows when the saved query lines value is above 10000', async () => {
    const ds = createDatasource();
    const built = await countAnnotationPushes(async () => {
      const panelData = await lastValueFrom(
        runRequest(ds, {
          requestId: 'panel',
          interval: '1s',
          intervalMs: 1000,
          range,
          scopedVars: {},
          targets: [{ refId: 'A', scenarioId: TestDataQueryType.Annotations, lines: MAX_ANNOTATION_EVENTS + 1 }],
          timezone: 'utc',
          app: 'dashboard',
          startTime: 1,
        })
      );
      const frame = panelData.annotations?.[0];
      const text = frame?.fields.find((field) => field.name === 'text');

      expect(frame?.meta?.dataTopic).toBe(DataTopic.Annotations);
      expect(frame?.length).toBe(MAX_ANNOTATION_EVENTS);
      expect(text?.values.length).toBe(MAX_ANNOTATION_EVENTS);
      expect(text?.values[0]).toBe(ANNOTATION_TEXT);
    });

    expect(built).toBe(MAX_ANNOTATION_EVENTS);
  });

  it('gives a dashboard annotation query 10000 events when its saved lines value is above 10000', async () => {
    const ds = createDatasource();
    const built = await countAnnotationPushes(async () => {
      const result = await lastValueFrom(
        executeAnnotationQuery(
          {
            range,
            dashboard: createDashboardModelFixture({ panels: [{ id: 1, type: 'timeseries' }] }),
            panel: {} as PanelModel,
          },
          ds,
          {
            name: 'Saved annotations',
            enable: true,
            iconColor: 'red',
            target: { refId: 'Anno', scenarioId: TestDataQueryType.Annotations, lines: MAX_ANNOTATION_EVENTS + 1 },
          }
        )
      );

      expect(result.events).toHaveLength(MAX_ANNOTATION_EVENTS);
      expect(result.events?.[0]?.text).toBe(ANNOTATION_TEXT);
    });

    // query() builds one event per counted line, then annotation processing copies each row.
    expect(built).toBe(MAX_ANNOTATION_EVENTS * 2);
  });
});
