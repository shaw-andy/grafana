import { isLabelMatch, matchLabelsSet } from './utils';

/**
 * Alerting label matchers compile a stored matcher value with new RegExp and test it while
 * routes are matched in the browser. `(a+)+` is wrapped as `^(?:(a+)+)$`, which is exponential
 * on a string of 30 `a` characters followed by a non-match.
 */
const MAX_STORED_REGEX_LENGTH = 1024;
const MATCH_BUDGET_MS = 250;
const NESTED_INPUT = `${'a'.repeat(30)}!`;
const SLOW_TEST_TIMEOUT_MS = 180_000;

const maxLengthPattern = 'a'.repeat(MAX_STORED_REGEX_LENGTH);
const overLengthPattern = 'a'.repeat(MAX_STORED_REGEX_LENGTH + 1);

function expectWithinBudget(startedAt: number) {
  expect(performance.now() - startedAt).toBeLessThan(MATCH_BUDGET_MS);
}

async function expectSettlesWithinBudget(run: () => unknown) {
  const startedAt = performance.now();
  try {
    await run();
  } catch {
    // A fast refusal is inside the contract. matchLabelsSet already turns a thrown RegExp into false.
  }
  expectWithinBudget(startedAt);
}

describe('stored alerting regex matchers', () => {
  it('still matches a short regex and a stored pattern of exactly 1024 characters', () => {
    expect(isLabelMatch({ label: 'foo', type: '=~', value: 'ba.' }, ['foo', 'baz'])).toBe(true);
    expect(isLabelMatch({ label: 'foo', type: '=~', value: 'ba.' }, ['foo', 'nope'])).toBe(false);
    expect(matchLabelsSet([{ label: 'foo', type: '=~', value: maxLengthPattern }], [['foo', maxLengthPattern]])).toBe(
      true
    );
  });

  it('does not match a stored pattern longer than 1024 characters', () => {
    const startedAt = performance.now();
    const matched = matchLabelsSet(
      [{ label: 'foo', type: '=~', value: overLengthPattern }],
      [['foo', overLengthPattern]]
    );
    expectWithinBudget(startedAt);
    expect(matched).toBe(false);
  });

  it(
    'matchLabelsSet returns within 250ms for a nested =~ pattern',
    () =>
      expectSettlesWithinBudget(() =>
        matchLabelsSet([{ label: 'foo', type: '=~', value: '(a+)+' }], [['foo', NESTED_INPUT]])
      ),
    SLOW_TEST_TIMEOUT_MS
  );

  it(
    'isLabelMatch returns within 250ms for a nested !~ pattern',
    () =>
      expectSettlesWithinBudget(() =>
        isLabelMatch({ label: 'foo', type: '!~', value: '(a+)+' }, ['foo', NESTED_INPUT])
      ),
    SLOW_TEST_TIMEOUT_MS
  );
});
