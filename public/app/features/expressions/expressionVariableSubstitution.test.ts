import { of } from 'rxjs';

import { LoadingState } from '@grafana/data';
import {
  type BackendSrv,
  type DataSourceSrv,
  config,
  locationService,
  setBackendSrv,
  setDataSourceSrv,
  setRunRequest,
} from '@grafana/runtime';
import { setExpressionDataSourceInstance } from '@grafana/runtime/internal';
import {
  CustomVariable,
  EmbeddedScene,
  QueryVariable,
  SceneCanvasText,
  SceneQueryRunner,
  SceneTimeRange,
  SceneVariableSet,
  TextBoxVariable,
  UrlSyncManager,
} from '@grafana/scenes';

import { runRequest } from '../query/state/runRequest';

import { dataSource } from './ExpressionDatasource';
import { type ExpressionQuery, ExpressionQueryType } from './types';

// Registers the real template service, including the scene interpolator used by dashboard queries.
import 'app/features/templating/template_srv';

const SQL_ATTACK = "x' OR '1'='1";
const IDENT_ATTACK = 'value OR 1';
const MATH_ATTACK = '0 * $A + 100';
const WINDOW_ATTACK = "1s' OR '1'='1";
const REF_ATTACK = 'A + 1';

const SAVED_HOST_SQL = "SELECT count(*) AS n FROM A WHERE host = '${host}'";
const SAVED_ENV_SQL = "SELECT count(*) AS n FROM A WHERE env = '${env}'";
const SAVED_POD_SQL = "SELECT count(*) AS n FROM A WHERE pod = '${pod}'";
const SAVED_IDENT_SQL = 'SELECT ${col} FROM A';
const SAVED_MATH = '$A + ${offset}';
const SAVED_WINDOW = '${win}';
const SAVED_REF = '${series}';

interface PostedQuery {
  refId?: string;
  expression?: string;
  window?: string;
}

/**
 * A viewer's URL value is safe in a quoted SQL expression when it is left unsubstituted
 * or kept inside one single-quoted literal. Doubled quotes are the SQL escape for a quote.
 */
function sqlStringLiteralContainsValue(expression: string, value: string, saved: string): boolean {
  if (expression === saved) {
    return true;
  }
  const marker = " = '";
  const open = expression.lastIndexOf(marker);
  if (open < 0 || !expression.endsWith("'")) {
    return false;
  }
  const literal = expression.slice(open + marker.length, -1);
  if (decodeSqlSingleQuotedLiteral(literal) !== value) {
    return false;
  }
  return !hasUnescapedSqlQuote(literal);
}

function decodeSqlSingleQuotedLiteral(literal: string): string {
  return literal.replace(/''/g, "'");
}

function hasUnescapedSqlQuote(literal: string): boolean {
  for (let i = 0; i < literal.length; i++) {
    if (literal[i] !== "'") {
      continue;
    }
    if (literal[i + 1] === "'") {
      i++;
      continue;
    }
    return true;
  }
  return false;
}

function sqlIdentifierContainsValue(expression: string, value: string, saved: string): boolean {
  if (expression === saved) {
    return true;
  }
  const escaped = value.replace(/`/g, '``');
  return expression === 'SELECT `' + escaped + '` FROM A';
}

function fieldCheck(posted: string | undefined, safe: boolean): { posted?: string; safe: boolean } {
  if (posted === undefined) {
    return { safe: true };
  }
  return { posted, safe };
}

describe('expression queries substitute viewer URL variables', () => {
  const originalVersion = config.buildInfo.version;

  beforeEach(() => {
    // SceneQueryRunner wraps the scene object for interpolation only on Grafana >= 11.
    config.buildInfo.version = '13.3.0';
    setExpressionDataSourceInstance(dataSource);
    locationService.push('/d/abc/variables');
  });

  afterEach(() => {
    config.buildInfo.version = originalVersion;
    locationService.push('/d/abc/variables');
  });

  it('keeps a normal text value inside the saved SQL, math, window, and ref expressions', async () => {
    const posted = await postExpressions({
      host: 'web',
      env: 'prod',
      pod: 'api',
      col: 'value',
      offset: '1',
      win: '5m',
      series: 'A',
    });

    expect(posted.S.expression).toBe("SELECT count(*) AS n FROM A WHERE host = 'web'");
    expect(posted.E.expression).toBe("SELECT count(*) AS n FROM A WHERE env = 'prod'");
    expect(posted.P.expression).toBe("SELECT count(*) AS n FROM A WHERE pod = 'api'");
    expect(posted.I.expression).toBe('SELECT value FROM A');
    expect(posted.M.expression).toBe('$A + 1');
    expect(posted.W.window).toBe('5m');
    expect(posted.R.expression).toBe('A');
    expect(posted.T.expression).toBe('A');
  });

  it('does not let a dashboard link rewrite SQL predicates, math, resample windows, or expression refs', async () => {
    const posted = await postExpressions({
      host: SQL_ATTACK,
      env: SQL_ATTACK,
      pod: SQL_ATTACK,
      col: IDENT_ATTACK,
      offset: MATH_ATTACK,
      win: WINDOW_ATTACK,
      series: REF_ATTACK,
    });

    const checks = {
      hostSql: fieldCheck(
        posted.S?.expression,
        sqlStringLiteralContainsValue(posted.S?.expression ?? '', SQL_ATTACK, SAVED_HOST_SQL)
      ),
      customSql: fieldCheck(
        posted.E?.expression,
        sqlStringLiteralContainsValue(posted.E?.expression ?? '', SQL_ATTACK, SAVED_ENV_SQL)
      ),
      querySql: fieldCheck(
        posted.P?.expression,
        sqlStringLiteralContainsValue(posted.P?.expression ?? '', SQL_ATTACK, SAVED_POD_SQL)
      ),
      identifierSql: fieldCheck(
        posted.I?.expression,
        sqlIdentifierContainsValue(posted.I?.expression ?? '', IDENT_ATTACK, SAVED_IDENT_SQL)
      ),
      math: fieldCheck(posted.M?.expression, posted.M?.expression === SAVED_MATH || posted.M?.expression === '$A + 1'),
      resampleWindow: fieldCheck(posted.W?.window, posted.W?.window === SAVED_WINDOW || posted.W?.window === '5m'),
      reduceRef: fieldCheck(posted.R?.expression, posted.R?.expression === SAVED_REF || posted.R?.expression === 'A'),
      thresholdRef: fieldCheck(posted.T?.expression, posted.T?.expression === SAVED_REF || posted.T?.expression === 'A'),
    };
    expect(checks).toEqual({
      hostSql: { ...checks.hostSql, safe: true },
      customSql: { ...checks.customSql, safe: true },
      querySql: { ...checks.querySql, safe: true },
      identifierSql: { ...checks.identifierSql, safe: true },
      math: { ...checks.math, safe: true },
      resampleWindow: { ...checks.resampleWindow, safe: true },
      reduceRef: { ...checks.reduceRef, safe: true },
      thresholdRef: { ...checks.thresholdRef, safe: true },
    });
  });
});

async function postExpressions(values: {
  host: string;
  env: string;
  pod: string;
  col: string;
  offset: string;
  win: string;
  series: string;
}): Promise<Record<string, PostedQuery>> {
  const host = new TextBoxVariable({ name: 'host', value: 'web' });
  const env = new CustomVariable({ name: 'env', query: 'prod,staging', value: 'prod', text: 'prod' });
  const pod = new QueryVariable({
    name: 'pod',
    query: 'up',
    value: 'api',
    text: 'api',
    options: [
      { label: 'api', value: 'api' },
      { label: 'db', value: 'db' },
    ],
  });
  // The option list is what a query variable's datasource would return. Validation against that list,
  // including keeping a URL value that matches nothing, stays in MultiValueVariable.
  pod.getValueOptions = () =>
    of([
      { label: 'api', value: 'api' },
      { label: 'db', value: 'db' },
    ]);
  const col = new TextBoxVariable({ name: 'col', value: 'value' });
  const offset = new TextBoxVariable({ name: 'offset', value: '1' });
  const win = new TextBoxVariable({ name: 'win', value: '5m' });
  const series = new TextBoxVariable({ name: 'series', value: 'A' });
  const variables = new SceneVariableSet({ variables: [host, env, pod, col, offset, win, series] });
  const timeRange = new SceneTimeRange({ from: 'now-1h', to: 'now' });
  const queries = expressionQueries();
  const runner = new SceneQueryRunner({
    datasource: { uid: '__expr__', type: '__expr__' },
    queries,
  });
  const scene = new EmbeddedScene({
    $timeRange: timeRange,
    $variables: variables,
    $data: runner,
    body: new SceneCanvasText({ text: 'panel' }),
  });

  // DashboardScenePage mounts UrlSyncContextProvider around the scene and does not render the
  // scene until URL sync has copied var-* parameters. Variables are inactive at that point, so a
  // value that matches no option is kept through the following validation.
  const params = new URLSearchParams({ from: 'now-1h', to: 'now' });
  params.set('var-host', values.host);
  params.set('var-env', values.env);
  params.set('var-pod', values.pod);
  params.set('var-col', values.col);
  params.set('var-offset', values.offset);
  params.set('var-win', values.win);
  params.set('var-series', values.series);
  locationService.push(`/d/abc/variables?${params.toString()}`);
  new UrlSyncManager({ updateUrlOnInit: true, createBrowserHistorySteps: true }).initSync(scene);

  const requests: Array<{ data?: { queries?: PostedQuery[] } }> = [];
  setBackendSrv({
    fetch: (options: { data?: { queries?: PostedQuery[] } }) => {
      requests.push(options);
      return of({ data: { results: {} } });
    },
  } as unknown as BackendSrv);
  setDataSourceSrv({
    get: async () => dataSource,
    getList: () => [],
    getInstanceSettings: () => undefined,
    reload: async () => undefined,
    registerRuntimeDataSource: () => undefined,
  } as unknown as DataSourceSrv);
  setRunRequest(runRequest);
  setExpressionDataSourceInstance(dataSource);

  const seen = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('expression query did not finish')), 5000);
    const sub = runner.subscribeToState((state) => {
      const queryState = state.data?.state;
      if (queryState === LoadingState.Done || queryState === LoadingState.Error) {
        clearTimeout(timer);
        sub.unsubscribe();
        resolve();
      }
    });
  });
  const deactivate = scene.activate();
  try {
    await seen;
  } finally {
    deactivate();
  }

  expect(host.getValue()).toBe(values.host);
  expect(env.getValue()).toBe(values.env);
  expect(pod.getValue()).toBe(values.pod);

  if (requests.length === 0) {
    return {};
  }

  const posted: Record<string, PostedQuery> = {};
  for (const query of requests[0].data?.queries ?? []) {
    if (query.refId) {
      posted[query.refId] = query;
    }
  }
  return posted;
}

function expressionQueries(): ExpressionQuery[] {
  const datasource = { uid: '__expr__', type: '__expr__' };
  return [
    { refId: 'S', datasource, type: ExpressionQueryType.sql, expression: SAVED_HOST_SQL },
    { refId: 'E', datasource, type: ExpressionQueryType.sql, expression: SAVED_ENV_SQL },
    { refId: 'P', datasource, type: ExpressionQueryType.sql, expression: SAVED_POD_SQL },
    { refId: 'I', datasource, type: ExpressionQueryType.sql, expression: SAVED_IDENT_SQL },
    { refId: 'M', datasource, type: ExpressionQueryType.math, expression: SAVED_MATH },
    {
      refId: 'W',
      datasource,
      type: ExpressionQueryType.resample,
      expression: 'A',
      window: SAVED_WINDOW,
      downsampler: 'mean',
      upsampler: 'fillna',
    },
    { refId: 'R', datasource, type: ExpressionQueryType.reduce, expression: SAVED_REF, reducer: 'last' },
    {
      refId: 'T',
      datasource,
      type: ExpressionQueryType.threshold,
      expression: SAVED_REF,
      conditions: [
        {
          type: 'query',
          query: { params: ['A'] },
          evaluator: { params: [0], type: 'gt' as never },
        },
      ],
    },
  ];
}
