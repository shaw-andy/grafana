import { type ComponentType } from 'react';
import { lastValueFrom, of } from 'rxjs';
import { render, screen } from 'test/test-utils';

import { type DataFrame, FieldType, type Field } from '@grafana/data';
import { config } from '@grafana/runtime';
import { type CustomTransformOperator, type SceneDataTransformer, type SceneFlexItem, type VizPanel } from '@grafana/scenes';
import { type CustomCellRendererProps } from '@grafana/ui';

import { getMostFiredInstancesScene } from './MostFiredInstancesTable';

const ALERT_NAME = 'Disk almost full';
const SAFE_RULE_UID = 'abc_DEF-123';
const LOGOUT_RULE_UID = '../../../logout?';
const SWITCH_ORG_RULE_UID = '../../../profile/switch-org/2?';

/**
 * Instant-metric frames from the Loki datasource (grafana-loki-datasource 13.2.5,
 * src/makeTableFrames.ts). Metric labels on the value field become table columns.
 * The plugin builds those labels from the Loki vector's `metric` object
 * (grafana-prometheus-datasource pkg/promlib v0.0.19 converter.readMatrixOrVectorMulti).
 */
function makeTableFrames(instantMetricFrames: DataFrame[]): DataFrame[] {
  const framesWithRefId = instantMetricFrames.filter((frame) => frame.refId !== undefined);
  const byRefId = new Map<string, DataFrame[]>();
  for (const frame of framesWithRefId) {
    const refId = frame.refId!;
    const group = byRefId.get(refId) ?? [];
    group.push(frame);
    byRefId.set(refId, group);
  }

  return Array.from(byRefId.entries()).map(([refId, frames]) => {
    const tableTimeField: Field<number> = { name: 'Time', config: {}, values: [], type: FieldType.time };
    const tableValueField: Field<number> = {
      name: `Value #${refId}`,
      config: {},
      values: [],
      type: FieldType.number,
    };
    const labelNames = Array.from(
      new Set(frames.flatMap((frame) => frame.fields.flatMap((field) => Object.keys(field.labels ?? {}))))
    ).sort();
    const labelFields: Array<Field<string>> = labelNames.map((labelName) => ({
      name: labelName,
      config: { filterable: true },
      values: [],
      type: FieldType.string,
    }));

    for (const frame of frames) {
      const timeField = frame.fields.find((field) => field.type === FieldType.time);
      const valueField = frame.fields.find((field) => field.type === FieldType.number);
      if (timeField == null || valueField == null) {
        continue;
      }
      for (const time of timeField.values) {
        tableTimeField.values.push(time);
      }
      for (const sample of valueField.values) {
        tableValueField.values.push(sample);
      }
      const labels = valueField.labels ?? {};
      for (const labelField of labelFields) {
        const text = labels[labelField.name] ?? '';
        for (let i = 0; i < valueField.values.length; i++) {
          labelField.values.push(text);
        }
      }
    }

    return {
      fields: [tableTimeField, ...labelFields, tableValueField],
      refId,
      length: tableTimeField.values.length,
    };
  });
}

function instantVectorFrame(metric: Record<string, string>, sample: number): DataFrame {
  return {
    refId: 'A',
    length: 1,
    fields: [
      { name: 'Time', type: FieldType.time, config: {}, values: [1_700_000_000_000] },
      { name: 'Value', type: FieldType.number, config: {}, values: [sample], labels: metric },
    ],
  };
}

function ruleLinkOperator(): CustomTransformOperator {
  const scene = getMostFiredInstancesScene(
    { type: 'loki', uid: 'grafanacloud-alert-state-history' },
    'Top 10 firing instances'
  );
  const panel = (scene as SceneFlexItem).state.body as VizPanel;
  const transformer = panel.state.$data as SceneDataTransformer;
  const operator = transformer.state.transformations[0];
  if (typeof operator !== 'function') {
    throw new Error('most-fired scene did not register the rule link transform');
  }
  return operator as CustomTransformOperator;
}

async function linkedFrame(metric: Record<string, string>): Promise<DataFrame> {
  const [table] = makeTableFrames([instantVectorFrame(metric, 7)]);
  const frames = await lastValueFrom(of([table]).pipe(ruleLinkOperator()()));
  return frames[0];
}

function requestUrl(href: string): URL {
  return new URL(href, 'http://grafana.example');
}

function assertLinkStaysInsideAlertRule(href: string) {
  const url = requestUrl(href);
  const subPath = config.appSubUrl ?? '';
  expect(url.origin).toBe('http://grafana.example');
  expect(url.pathname).not.toBe('/logout');
  expect(url.pathname).not.toBe('/profile/switch-org/2');
  const prefix = `${subPath}/alerting/grafana/`;
  expect(url.pathname.startsWith(prefix)).toBe(true);
  const remainder = url.pathname.slice(prefix.length);
  const segments = remainder.split('/');
  expect(segments).toHaveLength(2);
  expect(segments[1]).toBe('view');
  expect(segments[0]).not.toBe('..');
  expect(segments[0]).not.toBe('.');
}

async function renderAlertNameCell(metric: Record<string, string>) {
  const frame = await linkedFrame(metric);
  const nameField = frame.fields.find((field) => field.name === 'labels_alertname');
  if (!nameField) {
    throw new Error('labels_alertname column missing from the instant-query table');
  }
  const cellOptions = nameField.config.custom?.cellOptions;
  const Cell = cellOptions?.cellComponent as ComponentType<CustomCellRendererProps> | undefined;
  if (!Cell) {
    render(<span>{String(nameField.values[0])}</span>);
    return;
  }
  const props: CustomCellRendererProps = {
    field: nameField,
    frame,
    rowIndex: 0,
    value: nameField.values[0],
  };
  render(<Cell {...props} />);
}

describe('most fired instances rule link', () => {
  it('links a short rule uid to that rule view', async () => {
    await renderAlertNameCell({ labels_alertname: ALERT_NAME, ruleUID: SAFE_RULE_UID });

    const link = screen.getByRole('link', { name: new RegExp(ALERT_NAME) });
    const subPath = config.appSubUrl ?? '';
    expect(requestUrl(link.getAttribute('href') ?? '').pathname).toBe(
      `${subPath}/alerting/grafana/${SAFE_RULE_UID}/view`
    );
  });

  it('does not navigate to logout when the log line sets ruleUID to a parent-directory path', async () => {
    await renderAlertNameCell({ labels_alertname: ALERT_NAME, ruleUID: LOGOUT_RULE_UID });

    expect(screen.getByText(ALERT_NAME)).toBeInTheDocument();
    const link = screen.queryByRole('link', { name: new RegExp(ALERT_NAME) });
    if (link) {
      expect(link).toHaveAttribute('target', '_blank');
      assertLinkStaysInsideAlertRule(link.getAttribute('href') ?? '');
    }
  });

  it('does not navigate to the organization switch page when ruleUID carries that path', async () => {
    await renderAlertNameCell({ labels_alertname: ALERT_NAME, ruleUID: SWITCH_ORG_RULE_UID });

    expect(screen.getByText(ALERT_NAME)).toBeInTheDocument();
    const link = screen.queryByRole('link', { name: new RegExp(ALERT_NAME) });
    if (link) {
      expect(link).toHaveAttribute('target', '_blank');
      assertLinkStaysInsideAlertRule(link.getAttribute('href') ?? '');
      expect(requestUrl(link.getAttribute('href') ?? '').pathname).not.toBe('/profile/switch-org/2');
    }
  });
});
