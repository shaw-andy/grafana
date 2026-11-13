import { lastValueFrom, of } from 'rxjs';

import { type DataQueryRequest, dateTime, type ScopedVars } from '@grafana/data';
import {
  CustomVariable,
  EmbeddedScene,
  SafeSerializableSceneObject,
  SceneCanvasText,
  SceneVariableSet,
  TextBoxVariable,
  type SceneVariable,
} from '@grafana/scenes';
import { TemplateSrv } from 'app/features/templating/template_srv';

import { LogsQueryLanguage, type CloudWatchLogsQuery } from '../../plugins/datasource/cloudwatch/dataquery.gen';
import { CloudWatchSettings } from '../../plugins/datasource/cloudwatch/mocks/CloudWatchDataSource';
import { CloudWatchLogsQueryRunner } from '../../plugins/datasource/cloudwatch/query-runner/CloudWatchLogsQueryRunner';
import { type CloudWatchQuery } from '../../plugins/datasource/cloudwatch/types';

const savedArn = 'arn:aws:logs:us-east-1:123456789012:log-group:saved:*';
const injectedArn =
  "arn:aws:logs:us-east-1:123456789012:log-group:allowed:*', 'arn:aws:logs:us-east-1:123456789012:log-group:other:*";
const escapedArn =
  "arn:aws:logs:us-east-1:123456789012:log-group:allowed:*'', ''arn:aws:logs:us-east-1:123456789012:log-group:other:*";
const firstMultiArn = 'arn:aws:logs:us-east-1:123456789012:log-group:a:*';
const secondMultiArn =
  "arn:aws:logs:us-east-1:123456789012:log-group:b:*', 'arn:aws:logs:us-east-1:123456789012:log-group:c:*";
const escapedSecondMultiArn =
  "arn:aws:logs:us-east-1:123456789012:log-group:b:*'', ''arn:aws:logs:us-east-1:123456789012:log-group:c:*";
const injectedLevel = "info' OR level = 'error";
const escapedLevel = "info'' OR level = ''error";

const logGroupsExpression = 'SELECT * FROM `logGroups(logGroupIdentifier: [$lg])`';
const bracedLogGroupsExpression = "SELECT * FROM `logGroups(logGroupIdentifier: ['${lg}'])`";
const levelExpression = "SELECT message WHERE level = '$level'";

function applyDashboardUrl(variable: SceneVariable, values: Record<string, string | string[]>) {
  const handler = (variable as unknown as { _urlSync?: { updateFromUrl: (next: typeof values) => void } })._urlSync;
  if (!handler) {
    throw new Error(`variable ${variable.state.name} has no url sync handler`);
  }
  handler.updateFromUrl(values);
}

function sceneWith(variable: SceneVariable) {
  return new EmbeddedScene({
    $variables: new SceneVariableSet({ variables: [variable] }),
    body: new SceneCanvasText({ text: 'panel' }),
  });
}

async function startQueryString(scene: EmbeddedScene, expression: string, refId = 'A'): Promise<string> {
  window.__grafanaSceneContext = scene;
  const runner = new CloudWatchLogsQueryRunner(CloudWatchSettings, new TemplateSrv());
  const query: CloudWatchLogsQuery = {
    queryMode: 'Logs',
    refId,
    id: '',
    region: 'us-east-1',
    hide: false,
    expression,
    queryLanguage: LogsQueryLanguage.SQL,
    logGroups: [],
  };
  const scopedVars: ScopedVars = { __sceneObject: new SafeSerializableSceneObject(scene) };
  const request = {
    scopedVars,
    range: {
      from: dateTime('2020-01-01T00:00:00Z'),
      to: dateTime('2020-01-01T01:00:00Z'),
      raw: { from: 'now-1h', to: 'now' },
    },
    requestId: 'logs-sql',
    targets: [],
    interval: '1s',
    intervalMs: 1000,
    timezone: 'utc',
    app: 'dashboard',
    startTime: 1,
  } as DataQueryRequest<CloudWatchQuery>;

  let queryString = '';
  await lastValueFrom(
    runner.handleLogQueries([query], request, (sent) => {
      const target = sent.targets[0] as { queryString?: string };
      queryString = target.queryString ?? '';
      return of({ data: [] });
    })
  );
  return queryString;
}

describe('CloudWatch Logs SQL template literals', () => {
  afterEach(() => {
    delete window.__grafanaSceneContext;
  });

  it('keeps a dashboard URL value inside one quoted log group identifier', async () => {
    const variable = new TextBoxVariable({ name: 'lg', value: savedArn });
    const scene = sceneWith(variable);
    applyDashboardUrl(variable, { 'var-lg': injectedArn });
    scene.activate();

    const queryString = await startQueryString(scene, logGroupsExpression);

    expect(queryString).toBe("SELECT * FROM `logGroups(logGroupIdentifier: ['" + escapedArn + "'])`");
  });

  it('escapes a URL value placed in an author-written quoted literal', async () => {
    const variable = new TextBoxVariable({ name: 'level', value: 'info' });
    const scene = sceneWith(variable);
    applyDashboardUrl(variable, { 'var-level': injectedLevel });
    scene.activate();

    const queryString = await startQueryString(scene, levelExpression);

    expect(queryString).toBe("SELECT message WHERE level = '" + escapedLevel + "'");
  });

  it('escapes an ARN URL value when the saved query already supplies the surrounding quotes', async () => {
    const variable = new TextBoxVariable({ name: 'lg', value: savedArn });
    const scene = sceneWith(variable);
    applyDashboardUrl(variable, { 'var-lg': injectedArn });
    scene.activate();

    const queryString = await startQueryString(scene, bracedLogGroupsExpression);

    expect(queryString).toBe("SELECT * FROM `logGroups(logGroupIdentifier: ['" + escapedArn + "'])`");
  });

  it('escapes each multi-value URL entry after variable validation', async () => {
    const variable = new CustomVariable({
      name: 'lg',
      value: savedArn,
      text: savedArn,
      query: savedArn,
      isMulti: true,
    });
    const scene = sceneWith(variable);
    applyDashboardUrl(variable, { 'var-lg': [firstMultiArn, secondMultiArn] });
    scene.activate();

    const queryString = await startQueryString(scene, logGroupsExpression);

    expect(queryString).toBe(
      "SELECT * FROM `logGroups(logGroupIdentifier: ['" + firstMultiArn + "','" + escapedSecondMultiArn + "'])`"
    );
  });
});
