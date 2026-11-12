import { LinearRegExp, UnsupportedRegExpError } from './linearRegExp';

const inputs = [
  '',
  'a',
  'CPU Usage',
  'cpu usage',
  'Total CPU',
  'Error rate',
  'rate limiter',
  'error request rate',
  'Memory (bytes)',
  'panel [invalid title',
  'a{2}',
  'aaa',
  'abcabc',
  'foo_bar-baz 42',
  'line one\nline two',
  'tab\there',
  'Ünïcödé Straße',
  'x\u2028y',
  '\\c',
  '{}',
];

const patterns = [
  '',
  'cpu',
  'cpu|memory',
  '^CPU',
  'rate$',
  'error.*rate',
  'e.+?r',
  '^$',
  'a*',
  'a+',
  'a?b',
  'a{2}',
  'a{2,}',
  'a{1,2}b?',
  '(?:abc){2}',
  '(abc)+',
  '(?<word>usage)',
  '[a-c]+',
  '[^a-z ]',
  '[\\d_-]+',
  '[\\w-]',
  '\\d+',
  '\\D',
  '\\w+\\s\\w+',
  '\\S+$',
  '\\bcpu\\b',
  '\\Brate',
  '\\(bytes\\)',
  '\\[invalid',
  '\\x41|\\u0042',
  '\\t',
  '\\n',
  'one$',
  '^line',
  '.',
  'x.y',
  '{',
  '{}',
  'a{,2}',
  '\\c',
  '[\\b]',
  'ü',
  'STRASSE|straße',
  '[ä-ü]',
  '(a|ab)(c|bcd)?',
  '(a*)*b',
  '(?:^|_)bar',
];

describe('LinearRegExp', () => {
  describe.each(['', 'i', 'm', 's', 'gims'])('with flags "%s"', (flags) => {
    it.each(patterns)('agrees with RegExp#test for %j', (pattern) => {
      const native = new RegExp(pattern, flags.replace('g', ''));
      const linear = new LinearRegExp(pattern, flags);

      for (const input of inputs) {
        expect({ input, matched: linear.test(input) }).toEqual({ input, matched: native.test(input) });
      }
    });
  });

  // Each of these takes exponential or high-polynomial time in a backtracking engine on this input.
  it.each([
    ['((a+)+)+$', false],
    ['(a+)+$', false],
    ['(a|a)+$', false],
    ['(a|aa)+$', false],
    ['^(([a-z])+.)+[A-Z]([a-z])+$', false],
    ['(.*a){12}!', true],
    ['(\\w*)*$', true],
  ])('evaluates %j against a long input without backtracking', (pattern, expected) => {
    const linear = new LinearRegExp(pattern, 'i');

    expect(linear.test(`${'a'.repeat(5000)}!`)).toBe(expected);
  });

  it.each(['(a)\\1', '\\k<x>(?<x>a)', '(?=a)', '(?!a)', '(?<=a)b', '(?<!a)b', '\\01'])(
    'rejects %j, which has no linear-time equivalent',
    (pattern) => {
      expect(() => new LinearRegExp(pattern)).toThrow(UnsupportedRegExpError);
    }
  );

  it('rejects patterns whose program would be too large', () => {
    expect(() => new LinearRegExp('(a{1000}){1000}')).toThrow(UnsupportedRegExpError);
    expect(() => new LinearRegExp('((?:){10000}){10000}')).toThrow(UnsupportedRegExpError);
  });

  it('rejects flags that change pattern syntax', () => {
    expect(() => new LinearRegExp('a', 'u')).toThrow(UnsupportedRegExpError);
  });

  it('throws the same SyntaxError as RegExp for invalid patterns', () => {
    expect(() => new LinearRegExp('(unclosed')).toThrow(SyntaxError);
    expect(() => new LinearRegExp('[invalid')).toThrow(SyntaxError);
    expect(() => new LinearRegExp('*a')).toThrow(SyntaxError);
  });

  it('returns the same result when reused, unlike a global RegExp', () => {
    const linear = new LinearRegExp('cpu', 'g');

    expect(linear.test('cpu')).toBe(true);
    expect(linear.test('cpu')).toBe(true);
  });
});
