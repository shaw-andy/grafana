import { isLabelMatch } from './utils';

// `(a+)+` is wrapped as `^(?:(a+)+)$` before it is tested. That is still exponential
// in the length of a near-miss, and this length takes well over a second today.
const SUBJECT = `${'a'.repeat(29)}!`;
const BUDGET_MS = 250;

describe('stored alert label regular expressions must not backtrack without a bound', () => {
  jest.setTimeout(30000);

  it('matches a nested =~ label matcher within the budget', () => {
    const start = performance.now();
    try {
      isLabelMatch({ label: 'path', type: '=~', value: '(a+)+' }, ['path', SUBJECT]);
    } catch {
      // Rejecting the matcher value is a fix, as long as the rejection itself is fast.
    }
    expect(performance.now() - start).toBeLessThan(BUDGET_MS);
  });
});
