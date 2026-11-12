import { parseFlags } from '@grafana/data';

import { LinearRegExp } from './linearRegExp';

function nativeTest(pattern: string, input: string): boolean {
  const { cleaned, flags } = parseFlags(pattern);
  return new RegExp(cleaned, flags.replace('g', '')).test(input);
}

describe('LinearRegExp', () => {
  const inputs = [
    '',
    'a',
    'prod',
    'PROD',
    'prod-eu-1',
    'staging',
    'Server_01',
    'foo bar',
    'line1\nline2',
    'a.b',
    'x{2}',
    'tab\there',
    'aaa',
    'ab',
    'abab',
    '{}[]-',
  ];

  const patterns = [
    'prod',
    '^prod$',
    '^prod',
    'prod$',
    '(?i)prod',
    '(?i)^[a-z]+$',
    '^(prod|staging)$',
    '^(?:prod|stag)(ing)?',
    'pr.d',
    '^.*$',
    '(?s)^line1.line2$',
    '^line1.line2$',
    '(?m)^line2$',
    '^line2$',
    '\\d+',
    '^\\D+$',
    '\\w+_\\d{2}',
    '\\s',
    '\\S+\\s\\S+',
    '\\bbar\\b',
    'o\\B',
    '[a-c]+',
    '[^a-z]',
    '[\\d-]',
    '[\\w.]+',
    '^[]',
    '[^]',
    'a{2}',
    'a{2,}',
    'a{1,2}b',
    '^(ab){2}$',
    '^(ab)*$',
    '^(ab)+?$',
    'a??b',
    'x{2',
    '\\{\\}',
    '}',
    ']',
    'a\\.b',
    '\\t',
    '\\x41',
    '(?i)\\x61',
    '\\u0070rod',
    '(?<env>prod)',
    '(a*)*b',
    '(|a)+$',
    '^$',
    '',
    '(?i)PROD-EU-\\d',
    '-',
    '[{}\\[\\]-]{5}',
  ];

  it.each(patterns)('matches like the native RegExp engine for %p', (pattern) => {
    const regex = LinearRegExp.compile(pattern);
    for (const input of inputs) {
      expect([input, regex.test(input)]).toEqual([input, nativeTest(pattern, input)]);
    }
  });

  it('evaluates nested quantifiers by their meaning', () => {
    const regex = LinearRegExp.compile('(a+)+$');
    expect(regex.test('aaaa')).toBe(true);
    expect(regex.test('aaaa!')).toBe(false);
  });

  it('matches when any one of several inputs matches', () => {
    const regex = LinearRegExp.compile('^prod$');
    expect(regex.testAny(['staging', 'prod'])).toBe(true);
    expect(regex.testAny(['staging', 'dev'])).toBe(false);
    expect(regex.testAny([])).toBe(false);
  });

  it.each([
    ['backreference', '(a)\\1'],
    ['named backreference', '(?<x>a)\\k<x>'],
    ['lookahead', 'a(?=b)'],
    ['negative lookahead', '^(?!prod)'],
    ['lookbehind', '(?<=a)b'],
    ['negative lookbehind', '(?<!a)b'],
    ['unterminated group', '(prod'],
    ['unmatched parenthesis', 'prod)'],
    ['unterminated class', '[a-'],
    ['reversed range', '[z-a]'],
    ['leading quantifier', '*prod'],
    ['double quantifier', 'a**'],
    ['quantified anchor', '^*'],
    ['trailing backslash', 'prod\\'],
    ['reversed repeat bounds', 'a{3,1}'],
    ['repeat count above the limit', 'a{1001}'],
    ['program above the size limit', '(a{1000}){20}'],
    ['deep group nesting', `${'('.repeat(101)}a${')'.repeat(101)}`],
    ['pattern above the length limit', 'a'.repeat(5001)],
  ])('rejects a pattern with a %s', (_, pattern) => {
    expect(() => LinearRegExp.compile(pattern)).toThrow(SyntaxError);
  });

  it('refuses inputs whose combined length exceeds the step budget', () => {
    const regex = LinearRegExp.compile('(a{1,50}){1,50}$');
    expect(() => regex.testAny(['a'.repeat(1000)])).toThrow(RangeError);
    expect(() => regex.testAny(Array(20).fill('a'.repeat(100)))).toThrow(RangeError);
  });
});
