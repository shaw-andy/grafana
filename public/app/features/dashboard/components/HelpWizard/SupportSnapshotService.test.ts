import saveAs from 'file-saver';

import { FieldType, getDefaultTimeRange, LoadingState, toDataFrame } from '@grafana/data';

import { PanelModel } from '../../state/PanelModel';

import { SnapshotTab, SupportSnapshotService } from './SupportSnapshotService';

jest.mock('file-saver', () => jest.fn());

const uppercaseStringValue = 'A'.repeat(32);
const uppercaseFieldName = 'B'.repeat(32);
const uppercaseLabelValue = 'C'.repeat(32);
const uppercaseAnnotationValue = 'D'.repeat(32);
const uppercaseAnnotationFieldName = 'E'.repeat(32);
const lowercaseStringValue = 'a'.repeat(32);

function changedLetterCount(original: string, actual: string): number {
  expect(actual).toHaveLength(original.length);
  let changed = 0;
  for (let i = 0; i < original.length; i++) {
    if (actual[i] !== original[i]) {
      changed++;
    }
  }
  return changed;
}

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

  it('hides uppercase label values, field names, and string values in the shared snapshot', async () => {
    const panel = new PanelModel({ title: 'Panel A' });
    panel.getQueryRunner().setLastResult({
      timeRange: getDefaultTimeRange(),
      state: LoadingState.Done,
      series: [
        toDataFrame({
          name: 'http_requests_total',
          fields: [
            { name: 'Time', type: FieldType.time, values: [1, 2] },
            {
              name: uppercaseFieldName,
              type: FieldType.string,
              values: [uppercaseStringValue, lowercaseStringValue],
              labels: { source: uppercaseLabelValue },
            },
          ],
        }),
      ],
      annotations: [
        toDataFrame({
          name: 'annotations',
          fields: [
            { name: 'Time', type: FieldType.time, values: [1] },
            { name: uppercaseAnnotationFieldName, type: FieldType.string, values: [uppercaseAnnotationValue] },
          ],
        }),
      ],
    });
    panel.getQueryRunner().resendLastResult();

    const service = new SupportSnapshotService(panel);
    service.onToggleRandomize('labels');
    service.onToggleRandomize('names');
    service.onToggleRandomize('values');
    await service.buildDebugDashboard();

    const frames = service.state.snapshot.panels[0].targets[0].snapshot;
    const series = frames[0];
    const stringField = series.schema.fields.find((field: { type?: string }) => field.type === FieldType.string);
    const annotation = frames[1];
    const annotationField = annotation.schema.fields.find(
      (field: { type?: string }) => field.type === FieldType.string
    );

    const comment = service.onGetMarkdownForClipboard();
    service.onDownloadDashboard();
    const blob = jest.mocked(saveAs).mock.calls.at(-1)?.[0];
    expect(blob).toBeInstanceOf(Blob);
    const download = await (blob as Blob).text();
    const published = `${comment}\n${download}`;

    const checks: Array<[string, string, string]> = [
      ['label value', uppercaseLabelValue, stringField.labels.source],
      ['field name', uppercaseFieldName, stringField.name],
      ['string value', uppercaseStringValue, series.data.values[1][0]],
      ['lowercase string value', lowercaseStringValue, series.data.values[1][1]],
      ['annotation field name', uppercaseAnnotationFieldName, annotationField.name],
      ['annotation string value', uppercaseAnnotationValue, annotation.data.values[1][0]],
    ];
    const unchanged = checks
      .filter(([, original, actual]) => changedLetterCount(original, actual) < original.length / 2)
      .map(([name]) => name);
    const leaked = [
      uppercaseStringValue,
      uppercaseFieldName,
      uppercaseLabelValue,
      uppercaseAnnotationValue,
      uppercaseAnnotationFieldName,
    ].filter((secret) => published.includes(secret));

    expect({
      unchanged,
      leaked,
      downloadIsSnapshotText: download === service.state.snapshotText,
      commentIncludesStringValue: comment.includes(series.data.values[1][0]),
      downloadIncludesLabelValue: download.includes(stringField.labels.source),
    }).toEqual({
      unchanged: [],
      leaked: [],
      downloadIsSnapshotText: true,
      commentIncludesStringValue: true,
      downloadIncludesLabelValue: true,
    });
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
});
