import { render, waitFor } from '@testing-library/react';

import {
  dateTime,
  EventBusSrv,
  FieldType,
  getDefaultTimeRange,
  type InterpolateFunction,
  LoadingState,
  toDataFrame,
  type PanelProps,
} from '@grafana/data';
import { sceneGraph, VizPanel, type SceneObject } from '@grafana/scenes';
import { defaultDashboard } from '@grafana/schema';
import config from 'app/core/config';
import { TextMode, type Options } from 'app/plugins/panel/text/panelcfg.gen';
import { TextPanel } from 'app/plugins/panel/text/v1/TextPanel';
import { TextNGPanel } from 'app/plugins/panel/text/v2/TextNGPanel';
import { type DashboardDataDTO } from 'app/types/dashboard';

import { transformSaveModelToScene } from '../../serialization/transformSaveModelToScene';
import { getQueryRunnerFor } from '../../utils/getQueryRunnerFor';

import { SupportSnapshotService } from './SupportSnapshotService';

const LOGOUT_PATH = '/logout';
const SWITCH_ORG_PATH = '/profile/switch-org/2';

// Saved by an editor on a shared dashboard. The panel type stays a real
// query panel so Get help is still offered; the payload rides fields the
// wizard concatenates into the debug HTML table.
const DATA_SOURCE_TYPE_MARKUP = `<img src="${LOGOUT_PATH}" alt="datasource-type">`;
const QUERY_REF_ID_MARKUP = `<video src="${LOGOUT_PATH}"></video>`;
const TRANSFORMATION_ID_MARKUP = `<img src="${SWITCH_ORG_PATH}" alt="transformation-id">`;
const PLUGIN_VERSION_MARKUP = `<audio src="${LOGOUT_PATH}"></audio>`;

const ATTACKER_PATHS = [LOGOUT_PATH, SWITCH_ORG_PATH];

function savedDashboard(): DashboardDataDTO {
  const dashboard = {
    ...defaultDashboard,
    title: 'Shared dashboard',
    uid: 'shared-dash',
    schemaVersion: 42,
    editable: true,
    time: { from: 'now-6h', to: 'now' },
    panels: [
      {
        id: 2,
        type: 'timeseries',
        title: 'Requests',
        pluginVersion: PLUGIN_VERSION_MARKUP,
        gridPos: { h: 8, w: 12, x: 0, y: 0 },
        datasource: { type: 'prometheus', uid: 'prom' },
        targets: [
          {
            refId: 'A',
            datasource: { type: 'prometheus', uid: 'prom' },
            expr: 'up',
          },
          {
            refId: QUERY_REF_ID_MARKUP,
            datasource: { type: DATA_SOURCE_TYPE_MARKUP, uid: 'other' },
            expr: 'up',
          },
        ],
        transformations: [{ id: TRANSFORMATION_ID_MARKUP, options: {} }],
      },
    ],
  };

  // Same JSON round-trip the dashboard API uses when it stores and returns the model.
  return JSON.parse(JSON.stringify(dashboard));
}

function panelWithReturnedData() {
  const scene = transformSaveModelToScene({
    dashboard: savedDashboard(),
    meta: { canEdit: true, isSnapshot: false, isEmbedded: false },
  });
  const panel = sceneGraph.findObject(scene, (obj) => obj instanceof VizPanel);
  if (!(panel instanceof VizPanel)) {
    throw new Error('saved panel was not loaded');
  }

  const runner = getQueryRunnerFor(panel);
  if (!runner) {
    throw new Error('saved panel has no query runner');
  }

  runner.setState({
    data: {
      state: LoadingState.Done,
      timeRange: getDefaultTimeRange(),
      series: [
        toDataFrame({
          name: 'up',
          fields: [
            { name: 'Time', type: FieldType.time, values: [1, 2, 3] },
            { name: 'Value', type: FieldType.number, values: [1, 1, 1] },
          ],
        }),
      ],
    },
  });

  return panel;
}

function findDebugPanel(root: SceneObject): VizPanel {
  const panel = sceneGraph.findObject(root, (obj) => obj instanceof VizPanel && obj.state.title === 'Debug info');
  if (!(panel instanceof VizPanel)) {
    throw new Error('support snapshot did not include the debug info text panel');
  }
  return panel;
}

function resourceUrls(root: ParentNode): string[] {
  const urls: string[] = [];
  root.querySelectorAll('*').forEach((element) => {
    for (const name of ['src', 'href', 'poster', 'data', 'srcset']) {
      const value = element.getAttribute(name);
      if (value) {
        urls.push(value);
      }
    }
  });
  return urls;
}

function attackerResourceUrls(root: ParentNode): string[] {
  return resourceUrls(root).filter((url) => ATTACKER_PATHS.some((path) => url.includes(path)));
}

function panelProps(options: Options, replaceVariables: InterpolateFunction): PanelProps<Options> {
  const range = {
    from: dateTime('2022-07-11T15:55:00Z'),
    to: dateTime('2022-07-12T15:55:00Z'),
    raw: { from: 'now-6h', to: 'now' },
  };

  return {
    id: 5,
    data: {
      state: LoadingState.Done,
      series: [{ fields: [], length: 0 }],
      timeRange: range,
    },
    timeRange: range,
    timeZone: 'utc',
    transparent: false,
    width: 400,
    height: 200,
    fieldConfig: { defaults: {}, overrides: [] },
    renderCounter: 1,
    title: 'Debug info',
    eventBus: new EventBusSrv(),
    options,
    onOptionsChange: jest.fn(),
    onFieldConfigChange: jest.fn(),
    replaceVariables,
    onChangeTimeRange: jest.fn(),
  };
}

async function expectPreviewDoesNotLoadAttackerUrls(
  Component: (props: PanelProps<Options>) => JSX.Element,
  options: Options,
  replaceVariables: InterpolateFunction
) {
  const view = render(<Component {...panelProps(options, replaceVariables)} />);

  if (options.mode === TextMode.HTML || options.mode === TextMode.Markdown) {
    await waitFor(() => {
      expect(view.container.textContent).toContain('prometheus');
      expect(view.container.textContent).toContain('timeseries');
    });
  }

  expect(attackerResourceUrls(view.container)).toEqual([]);
  view.unmount();
}

describe('support snapshot preview', () => {
  const originalDisableSanitizeHtml = config.disableSanitizeHtml;

  beforeEach(() => {
    config.disableSanitizeHtml = false;
  });

  afterEach(() => {
    config.disableSanitizeHtml = originalDisableSanitizeHtml;
  });

  it.each([
    ['text panel', TextPanel],
    ['new text panel', TextNGPanel],
  ])(
    'does not load image, audio, or video URLs taken from panel query and transform fields (%s)',
    async (_name, Component) => {
      const panel = panelWithReturnedData();
      const service = new SupportSnapshotService(panel);
      await service.buildDebugDashboard();

      const scene = service.state.scene;
      expect(scene).toBeDefined();
      const debugPanel = findDebugPanel(scene!);
      const options = debugPanel.state.options as Options;
      const replaceVariables: InterpolateFunction = (value, scopedVars, format) =>
        debugPanel.interpolate(value, scopedVars, format);

      expect(options.content).toContain('prometheus');
      expect(options.content).toContain('timeseries');

      await expectPreviewDoesNotLoadAttackerUrls(Component, options, replaceVariables);
    }
  );
});
