import { SupportedTransformationType } from '@grafana/data';

import { getTransformationVars } from './transformations';

// A link builder runs on the UI thread. This is the longest it may spend on one stored expression.
const LINK_BUILD_BUDGET_MS = 250;

// Short nested expression. Length limits that still allow this pattern do not remove the hang.
const NESTED_EXPRESSION = '^(a+)+$';
const NESTED_FIELD_VALUE = `${'a'.repeat(30)}!`;

describe('getTransformationVars', () => {
  it('extracts named capture groups from a stored regex', () => {
    const vars = getTransformationVars(
      {
        type: SupportedTransformationType.Regex,
        expression: 'trace=(?<traceId>[0-9a-f]+)',
        mapValue: 'unused',
      },
      'trace=abc123',
      'line'
    );

    expect(vars).toEqual({ traceId: { value: 'abc123' } });
  });

  it('extracts an unnamed capture group into mapValue', () => {
    const vars = getTransformationVars(
      {
        type: SupportedTransformationType.Regex,
        expression: 'trace=([0-9a-f]+)',
        mapValue: 'traceId',
      },
      'trace=abc123',
      'line'
    );

    expect(vars).toEqual({ traceId: { value: 'abc123' } });
  });

  it('parses logfmt transformations into link variables', () => {
    const vars = getTransformationVars({ type: SupportedTransformationType.Logfmt }, 'application=grafana', 'line');

    expect(vars).toEqual({ application: { value: 'grafana' } });
  });

  it('returns no variables for a stored nested regex without blocking the caller', () => {
    const started = Date.now();
    const vars = getTransformationVars(
      {
        type: SupportedTransformationType.Regex,
        expression: NESTED_EXPRESSION,
        mapValue: 'captured',
      },
      NESTED_FIELD_VALUE,
      'line'
    );
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(LINK_BUILD_BUDGET_MS);
    expect(vars).toEqual({});
  }, 120000);
});
