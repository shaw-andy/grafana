import { RE2JS } from 're2js';

import { stringStartsAsRegEx } from './string';

// Matching time is linear in the input, multiplied by the size of the compiled program. Counted
// repetition expands when compiled ([a-z]{1000} is a thousand instructions), so both the stored
// text and the compiled program are capped.
export const MAX_STORED_REGEX_LENGTH = 1024;
export const MAX_REGEX_PROGRAM_SIZE = 2 * MAX_STORED_REGEX_LENGTH;

/**
 * A compiled regular expression that matches in time linear to its input.
 *
 * Unlike `RegExp`, it keeps no `lastIndex` state between calls, so `test` gives the same answer
 * for the same input even when the pattern carries the `g` flag.
 */
export interface SafeRegex {
  test(input: unknown): boolean;
  exec(input: string): RegExpMatchArray | null;
  /** Same replacement string syntax as `String.prototype.replace`. Replaces every match when the pattern has the `g` flag. */
  replace(input: string, replacement: string): string;
}

const CACHE_SIZE = 200;
const cache = new Map<string, SafeRegex>();

const neverMatches: SafeRegex = {
  test: () => false,
  exec: () => null,
  replace: (input) => input,
};

function toRE2Flags(flags: string) {
  let re2Flags = 0;
  let global = false;
  let sticky = false;
  for (const flag of flags) {
    switch (flag) {
      case 'g':
        global = true;
        break;
      case 'i':
        re2Flags |= RE2JS.CASE_INSENSITIVE;
        break;
      case 'm':
        re2Flags |= RE2JS.MULTILINE;
        break;
      case 's':
        re2Flags |= RE2JS.DOTALL;
        break;
      case 'y':
        sticky = true;
        break;
      case 'u':
      case 'd':
        break;
      default:
        throw new Error(`Invalid regular expression flag '${flag}'.`);
    }
  }
  return { re2Flags, global, sticky };
}

function build(source: string, flags: string): SafeRegex {
  const { re2Flags, global, sticky } = toRE2Flags(flags);

  // JavaScript's backtracking RegExp can take exponential time on nested quantifiers such as
  // (a+)+$, and a synchronous match cannot be interrupted. RE2 guarantees linear-time matching,
  // at the cost of rejecting backreferences and lookaround.
  const translated = RE2JS.translateRegExp(source);
  const re = RE2JS.compile(sticky ? `\\A(?:${translated})` : translated, re2Flags);

  if (re.programSize() > MAX_REGEX_PROGRAM_SIZE) {
    return neverMatches;
  }

  // test() runs on RE2's DFA, which is much cheaper than extracting capture groups, so check it
  // first and only pay for captures on inputs that match.
  return {
    test: (input) => re.test(String(input)),
    exec: (input) => (re.test(input) ? (re.matchAll(input).next().value ?? null) : null),
    replace: (input, replacement) => {
      if (!re.test(input)) {
        return input;
      }
      const matcher = re.matcher(input);
      return global ? matcher.replaceAll(replacement) : matcher.replaceFirst(replacement);
    },
  };
}

function compile(source: string, flags: string): SafeRegex {
  const key = `${flags}/${source}`;
  const cached = cache.get(key);
  if (cached) {
    return cached;
  }

  const safeRegex = build(source, flags);

  if (cache.size >= CACHE_SIZE) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) {
      cache.delete(oldest);
    }
  }
  cache.set(key, safeRegex);

  return safeRegex;
}

/**
 * Compiles a stored regular expression so it matches in linear time.
 *
 * A pattern longer than {@link MAX_STORED_REGEX_LENGTH}, or that compiles to more than
 * {@link MAX_REGEX_PROGRAM_SIZE} instructions, is refused and never matches. Throws when the
 * pattern is invalid or uses a feature that needs backtracking (backreferences, lookahead,
 * lookbehind).
 */
export function compileSafeRegex(pattern: string, flags = ''): SafeRegex {
  if (pattern.length > MAX_STORED_REGEX_LENGTH) {
    return neverMatches;
  }
  return compile(pattern, flags);
}

/**
 * Same parsing as `stringToJsRegex` (`/pattern/flags`, otherwise an exact `^pattern$` match),
 * with the limits of {@link compileSafeRegex}.
 */
export function stringToSafeRegex(str: string): SafeRegex {
  if (str.length > MAX_STORED_REGEX_LENGTH) {
    return neverMatches;
  }

  if (!stringStartsAsRegEx(str)) {
    return compile(`^${str}$`, '');
  }

  const match = str.match(new RegExp('^/(.*?)/(g?i?m?y?s?)$'));

  if (!match) {
    throw new Error(`'${str}' is not a valid regular expression.`);
  }

  return compile(match[1], match[2]);
}
