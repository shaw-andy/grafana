import saveAs from 'file-saver';

import { FieldType, getDefaultTimeRange, LoadingState, toDataFrame, type DataFrame } from '@grafana/data';

import { PanelModel } from '../../state/PanelModel';

import { SnapshotTab, SupportSnapshotService } from './SupportSnapshotService';

jest.mock('file-saver', () => jest.fn());

describe('SupportSnapshotService', () => {
  const panel = new PanelModel({});
  panel.getQueryRunner().setLastResult({
    timeRange: getDefaultTimeRange(),
    state: LoadingState.Done,
    series: [
      toDataFrame({
        name: 'http_requests_total',
        fields: [
          { name: 'Time', type: FieldType.time, values: [1, 2, 3] },
          { name: 'Value', type: FieldType.number, values: [11, 22, 33] },
        ],
      }),
    ],
  });
  panel.getQueryRunner().resendLastResult();

  it('Can create it with default state', () => {
    const service = new SupportSnapshotService(panel);
    expect(service.state.currentTab).toBe(SnapshotTab.Support);
  });

  it('Can can build support snapshot dashboard', async () => {
    const service = new SupportSnapshotService(panel);
    await service.buildDebugDashboard();
    expect(service.state.snapshot.panels[0].targets[0]).toMatchInlineSnapshot(`
      {
        "datasource": {
          "type": "grafana",
          "uid": "grafana",
        },
        "queryType": "snapshot",
        "refId": "A",
        "snapshot": [
          {
            "data": {
              "values": [
                [
                  1,
                  2,
                  3,
                ],
                [
                  11,
                  22,
                  33,
                ],
              ],
            },
            "schema": {
              "fields": [
                {
                  "config": {},
                  "name": "Time",
                  "type": "time",
                },
                {
                  "config": {},
                  "name": "Value",
                  "type": "number",
                },
              ],
              "meta": undefined,
              "name": "http_requests_total",
              "refId": undefined,
            },
          },
        ],
      }
    `);
  });

  it('redacts label names in the github comment and downloaded dashboard when Labels is on', async () => {
    const seriesA = labeledSeries({
      acctowner: 'aliceperson',
      hostbox: 'webnode',
      exemplar: 'morningshift',
      __name__: 'metricname',
    });
    const seriesB = labeledSeries({
      acctowner: 'carolperson',
      hostbox: 'webnode',
    });
    const annotation = toDataFrame({
      name: 'annotation',
      fields: [
        {
          name: 'text',
          type: FieldType.string,
          values: ['note'],
          labels: {
            namespaceid: 'prodcluster',
            owner_id: 'patperson',
          },
        },
      ],
    });
    const panel = new PanelModel({});
    panel.getQueryRunner().setLastResult({
      timeRange: getDefaultTimeRange(),
      state: LoadingState.Done,
      series: [seriesA, seriesB],
      annotations: [annotation],
    });
    panel.getQueryRunner().resendLastResult();

    const service = new SupportSnapshotService(panel);
    service.onToggleRandomize('labels');
    expect(service.state.randomize).toEqual({ labels: true });
    await service.buildDebugDashboard();

    const markdown = service.onGetMarkdownForClipboard();
    service.onDownloadDashboard();
    const downloaded = await (jest.mocked(saveAs).mock.calls[0][0] as Blob).text();

    expect(markdown).toContain('Panel debug snapshot dashboard');
    expect(downloaded).toBe(service.state.snapshotText);
    expect(panel.getQueryRunner().getLastResult()?.series[0].fields[1].labels).toEqual({
      acctowner: 'aliceperson',
      hostbox: 'webnode',
      exemplar: 'morningshift',
      __name__: 'metricname',
    });
    expect(panel.getQueryRunner().getLastResult()?.annotations?.[0].fields[0].labels).toEqual({
      namespaceid: 'prodcluster',
      owner_id: 'patperson',
    });

    for (const secret of [
      'acctowner',
      'hostbox',
      'exemplar',
      '__name__',
      'namespaceid',
      'owner_id',
      'aliceperson',
      'carolperson',
      'webnode',
      'morningshift',
      'metricname',
      'prodcluster',
      'patperson',
    ]) {
      expect(markdown).not.toContain(secret);
      expect(downloaded).not.toContain(secret);
    }

    const frames: EmbeddedFrame[] = service.state.snapshot.panels[0].targets[0].snapshot ?? [];
    const maps = frames.flatMap((frame) =>
      (frame.schema?.fields ?? []).flatMap((field) => (field.labels ? [field.labels] : []))
    );
    expect(maps).toHaveLength(3);
    const series = maps.filter((labels) => Object.keys(labels).some((key) => /^[a-z]{9}$/.test(key)));
    expect(series).toHaveLength(2);
    const acctowner = Object.keys(series[0]).find((key: string) => /^[a-z]{9}$/.test(key));
    expect(acctowner).toBeDefined();
    expect(acctowner).not.toBe('acctowner');
    expect(Object.keys(series[1])).toContain(acctowner);
    const hostbox = Object.keys(series[0]).find((key: string) => /^[a-z]{7}$/.test(key));
    expect(hostbox).toBeDefined();
    expect(hostbox).not.toBe('hostbox');
    expect(series[0][hostbox!]).toBe(series[1][hostbox!]);
    expect(series[0][hostbox!]).not.toBe('webnode');
    expect(series[1][acctowner!]).not.toBe(series[0][acctowner!]);

    const annotationLabels = maps.find((labels) => Object.keys(labels).some((key) => /^[a-z]{5}_[a-z]{2}$/.test(key)));
    expect(annotationLabels).toBeDefined();
    expect(Object.keys(annotationLabels).some((key: string) => key === 'namespaceid' || key === 'owner_id')).toBe(
      false
    );
  });
});

type LabelMap = Record<string, string>;
interface LabelField {
  labels?: LabelMap;
}
interface EmbeddedFrame {
  schema?: { fields?: LabelField[] };
}

function labeledSeries(labels: LabelMap): DataFrame {
  return toDataFrame({
    name: 'http_requests_total',
    fields: [
      { name: 'Time', type: FieldType.time, values: [1, 2, 3] },
      { name: 'Value', type: FieldType.number, values: [11, 22, 33], labels },
    ],
  });
}
