import { initTemplateSrv } from 'test/helpers/initTemplateSrv';

import { type DataFrame, FieldType, type InterpolateFunction, toDataFrame } from '@grafana/data';
import { FlagKeys } from '@grafana/runtime/internal';
import { setTestFlags } from '@grafana/test-utils/unstable';

import { RenderMode, TextMode } from '../panelcfg.gen';

import { catchTemplateError, interpolateTemplate, renderContent } from './renderContent';

/**
 * A nested quantifier against a long run of one character is exponential in the
 * JavaScript RegExp engine. These lengths take seconds through `new RegExp` and
 * return immediately from a rejection or a linear-time match.
 */
const NESTED_QUANTIFIER = '(a+)+$';
const DEEPER_NESTED_QUANTIFIER = '((a+)+)+$';
const RUN_LENGTH = 26;
const DEEPER_RUN_LENGTH = 16;
const TIME_BUDGET_MS = 200;

const sameCharacterRun = (length: number) => 'a'.repeat(length) + '!';

beforeEach(() => {
  setTestFlags({ [FlagKeys.TextNewFeatures]: true, [FlagKeys.GrafanaNewTextPanel]: true });
});

afterAll(() => {
  setTestFlags({});
});

function createReplaceVariables(variables: unknown[] = []): InterpolateFunction {
  const templateSrv = initTemplateSrv('hello', variables);
  return (target, scopedVars, format) => templateSrv.replace(target, scopedVars, format);
}

function interpolate(
  content: string,
  series: DataFrame[] = [],
  renderMode = RenderMode.Once,
  replaceVariables = createReplaceVariables()
) {
  return interpolateTemplate({ content, series, renderMode, mode: TextMode.Markdown }, replaceVariables);
}

type MatchOutcome =
  | { kind: 'value'; value: string; elapsedMs: number }
  | { kind: 'rejected'; error: unknown; elapsedMs: number };

function runMatch(render: () => string): MatchOutcome {
  const start = performance.now();
  try {
    return { kind: 'value', value: render(), elapsedMs: performance.now() - start };
  } catch (error) {
    return { kind: 'rejected', error, elapsedMs: performance.now() - start };
  }
}

/** A safe pattern still has to match. An implementation that drops the helper fails here. */
function expectExactMatch(render: () => string, expected: 'yes' | 'no') {
  const outcome = runMatch(render);
  expect(outcome.elapsedMs).toBeLessThan(TIME_BUDGET_MS);
  expect(outcome.kind).toBe('value');
  if (outcome.kind === 'value') {
    expect(outcome.value).toBe(expected);
  }
}

/**
 * The input does not match the pattern. The helper must either reject it or
 * return that result inside the budget. A backtracking match fails the budget.
 */
function expectNonMatchBounded(render: () => string) {
  const outcome = runMatch(render);
  expect(outcome.elapsedMs).toBeLessThan(TIME_BUDGET_MS);
  if (outcome.kind === 'rejected') {
    expect(outcome.error).toBeInstanceOf(Error);
    return;
  }
  expect(outcome.value).toBe('no');
}

function ifMatch(input: string, pattern: string) {
  return `{{#if (match "${input}" "${pattern}")}}yes{{else}}no{{/if}}`;
}

function rowFrame(value: string, pattern: string) {
  return toDataFrame({
    fields: [
      { name: 'value', type: FieldType.string, values: [value] },
      { name: 'pattern', type: FieldType.string, values: [pattern] },
    ],
  });
}

function customVariable(name: string, value: string) {
  return {
    type: 'custom',
    name,
    current: { value, text: value },
    options: [{ value, text: value, selected: true }],
  };
}

describe('text panel match helper', () => {
  it('matches literals from the saved template and does not backtrack on nested quantifiers', () => {
    expectExactMatch(() => interpolate(ifMatch('aaa', '^a+$')), 'yes');
    expectExactMatch(() => interpolate(ifMatch('aaab', '^a+$')), 'no');
    expectExactMatch(() => interpolate(ifMatch('a'.repeat(RUN_LENGTH), '^a+$')), 'yes');
    expectNonMatchBounded(() => interpolate(ifMatch(sameCharacterRun(RUN_LENGTH), NESTED_QUANTIFIER)));
  });

  it('does not backtrack on a quantifier nested more than once', () => {
    expectExactMatch(() => interpolate(ifMatch('aaa', '^a+$')), 'yes');
    expectNonMatchBounded(() => interpolate(ifMatch(sameCharacterRun(DEEPER_RUN_LENGTH), DEEPER_NESTED_QUANTIFIER)));
  });

  it('matches a pattern and input taken from query fields without backtracking', () => {
    const content = '{{#each data}}{{#if (match value pattern)}}yes{{else}}no{{/if}}{{/each}}';

    expectExactMatch(() => interpolate(content, [rowFrame('aaa', '^a+$')]), 'yes');
    expectExactMatch(() => interpolate(content, [rowFrame('aaab', '^a+$')]), 'no');
    expectNonMatchBounded(() => interpolate(content, [rowFrame(sameCharacterRun(RUN_LENGTH), NESTED_QUANTIFIER)]));
  });

  it('matches per-row query fields without backtracking', () => {
    const content = '{{#if (match value pattern)}}yes{{else}}no{{/if}}';

    expectExactMatch(() => interpolate(content, [rowFrame('web-1', '^web-')], RenderMode.PerRow), 'yes');
    expectExactMatch(() => interpolate(content, [rowFrame('db-1', '^web-')], RenderMode.PerRow), 'no');
    expectNonMatchBounded(() =>
      interpolate(content, [rowFrame(sameCharacterRun(RUN_LENGTH), NESTED_QUANTIFIER)], RenderMode.PerRow)
    );
  });

  it('matches a pattern and input taken from dashboard variables without backtracking', () => {
    const content = '{{#if (match (variableValue "input") (variableValue "pattern"))}}yes{{else}}no{{/if}}';
    const render = (input: string, pattern: string) =>
      interpolate(
        content,
        [],
        RenderMode.Once,
        createReplaceVariables([customVariable('input', input), customVariable('pattern', pattern)])
      );

    expectExactMatch(() => render('aaa', '^a+$'), 'yes');
    expectExactMatch(() => render('aaab', '^a+$'), 'no');
    expectNonMatchBounded(() => render(sameCharacterRun(RUN_LENGTH), NESTED_QUANTIFIER));
  });

  it('finishes the viewer render when the saved template calls match with a nested quantifier', () => {
    const replaceVariables = createReplaceVariables();
    const view = (content: string) =>
      catchTemplateError(() =>
        renderContent(
          { content, mode: TextMode.HTML, series: [], renderMode: RenderMode.Once, format: 'html' },
          replaceVariables,
          false
        )
      );

    const safe = view(ifMatch('aaa', '^a+$'));
    expect(safe.error).toBeUndefined();
    expect(safe.content).toBe('yes');

    const start = performance.now();
    const rendered = view(ifMatch(sameCharacterRun(RUN_LENGTH), NESTED_QUANTIFIER));
    expect(performance.now() - start).toBeLessThan(TIME_BUDGET_MS);

    if (rendered.error) {
      expect(rendered.content).toBe('');
      expect(rendered.error).toContain('Handlebars error:');
      return;
    }

    expect(rendered.content).toBe('no');
  });
});
