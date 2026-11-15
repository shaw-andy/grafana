import { escapeRegex } from './string';

export interface TextMatch {
  text: string;
  start: number;
  length: number;
  end: number;
}

/**
 * Adapt findMatchesInText for react-highlight-words findChunks handler.
 * See https://github.com/bvaughn/react-highlight-words#props
 */
export function findHighlightChunksInText({
  searchWords,
  textToHighlight,
}: {
  searchWords: Array<string | RegExp>;
  textToHighlight: string;
}) {
  const chunks: TextMatch[] = [];
  for (const term of searchWords) {
    if (typeof term === 'string') {
      chunks.push(...findMatchesInText(textToHighlight, term));
    }
  }
  return chunks;
}

const cleanNeedle = (needle: string): string => {
  return needle.replace(/[[{(][\w,.\/:;<=>?:*+]+$/, '');
};

/**
 * Upper bound for (backtracking paths × characters per path) from a single start position.
 * Search words come from data frames, so a pattern above this bound is matched as literal text.
 */
const MAX_SEARCH_PATTERN_COST = 100;

const QUANTIFIER_REGEXP = /^\{(\d+)(?:(,)(\d*))?\}/;

function readQuantifier(source: string, index: number): { min: number; max: number; length: number } | undefined {
  const char = source[index];
  if (char === '*') {
    return { min: 0, max: Infinity, length: 1 };
  }
  if (char === '+') {
    return { min: 1, max: Infinity, length: 1 };
  }
  if (char === '?') {
    return { min: 0, max: 1, length: 1 };
  }
  const braces = char === '{' ? QUANTIFIER_REGEXP.exec(source.slice(index)) : null;
  if (!braces) {
    return undefined;
  }
  const min = Number(braces[1]);
  const max = braces[2] ? (braces[3] ? Number(braces[3]) : Infinity) : min;
  return { min, max, length: braces[0].length };
}

interface PatternFrame {
  // Alternatives already closed by `|`
  closedPaths: number;
  closedSteps: number;
  // Alternative being read
  paths: number;
  steps: number;
}

const newFrame = (): PatternFrame => ({ closedPaths: 0, closedSteps: 0, paths: 1, steps: 0 });

const exceedsCost = (paths: number, steps: number) => paths * Math.max(steps, 1) > MAX_SEARCH_PATTERN_COST;

/**
 * A backtracking engine can take exponential or polynomial time on unbounded or nested quantifiers,
 * and even one unbounded quantifier is quadratic over a long line. Accept only patterns without loops,
 * where the work from one start position is bounded by the number of alternative paths times the
 * characters a path can consume.
 */
function hasBoundedBacktracking(source: string): boolean {
  const frames = [newFrame()];
  let i = 0;

  while (i < source.length) {
    const char = source[i];
    let atomPaths = 1;
    let atomSteps = 1;
    let isGroup = false;

    if (char === '\\') {
      // Backreferences match captured text of unbounded length.
      if (i + 1 >= source.length || /[1-9k]/.test(source[i + 1])) {
        return false;
      }
      i += 2;
    } else if (char === '[') {
      let j = i + 1;
      while (j < source.length && source[j] !== ']') {
        j += source[j] === '\\' ? 2 : 1;
      }
      if (j >= source.length) {
        return false;
      }
      i = j + 1;
    } else if (char === '(') {
      if (source[i + 1] === '?') {
        if (source[i + 2] === ':') {
          i += 3;
        } else if (source[i + 2] === '<' && source[i + 3] !== '=' && source[i + 3] !== '!') {
          const close = source.indexOf('>', i);
          if (close === -1) {
            return false;
          }
          i = close + 1;
        } else {
          return false;
        }
      } else {
        i += 1;
      }
      frames.push(newFrame());
      continue;
    } else if (char === '|') {
      const frame = frames[frames.length - 1];
      frame.closedPaths += frame.paths;
      frame.closedSteps = Math.max(frame.closedSteps, frame.steps);
      frame.paths = 1;
      frame.steps = 0;
      if (exceedsCost(frame.closedPaths, frame.closedSteps)) {
        return false;
      }
      i += 1;
      continue;
    } else if (char === ')') {
      const frame = frames.pop();
      if (!frame || !frames.length) {
        return false;
      }
      atomPaths = frame.closedPaths + frame.paths;
      atomSteps = Math.max(frame.closedSteps, frame.steps);
      isGroup = true;
      i += 1;
    } else if (char === '*' || char === '+' || char === '?') {
      return false;
    } else {
      i += 1;
    }

    const quantifier = readQuantifier(source, i);
    if (quantifier) {
      if (isGroup || quantifier.max === Infinity) {
        return false;
      }
      atomPaths *= quantifier.max - quantifier.min + 1;
      atomSteps = quantifier.max;
      i += quantifier.length;
      if (source[i] === '?') {
        i += 1;
      }
    }

    const frame = frames[frames.length - 1];
    frame.paths *= atomPaths;
    frame.steps += atomSteps;
    if (exceedsCost(frame.paths, frame.steps)) {
      return false;
    }
  }

  if (frames.length !== 1) {
    return false;
  }
  const [top] = frames;
  return !exceedsCost(top.closedPaths + top.paths, Math.max(top.closedSteps, top.steps));
}

/**
 * Compiles a search word (a regular expression with optional mode modifiers) for highlighting.
 * Patterns whose matching time is not bounded are matched as literal text instead.
 * Returns undefined when the search word is not a valid regular expression.
 */
export function searchWordToRegExp(needle: string): RegExp | undefined {
  const { cleaned, flags } = parseFlags(cleanNeedle(needle));
  try {
    const regexp = new RegExp(`(?:${cleaned})`, flags);
    return hasBoundedBacktracking(cleaned) ? regexp : new RegExp(escapeRegex(cleaned), flags);
  } catch (error) {
    return undefined;
  }
}

/**
 * Returns a list of substring regexp matches.
 */
export function findMatchesInText(haystack: string, needle: string): TextMatch[] {
  // Empty search can send re.exec() into infinite loop, exit early
  if (!haystack || !needle) {
    return [];
  }

  const matches: TextMatch[] = [];
  const regexp = searchWordToRegExp(needle);
  if (!regexp) {
    return matches;
  }

  haystack.replace(regexp, (substring, ...rest) => {
    if (substring) {
      const offset = rest[rest.length - 2];
      matches.push({
        text: substring,
        start: offset,
        length: substring.length,
        end: offset + substring.length,
      });
    }
    return '';
  });

  return matches;
}

const CLEAR_FLAG = '-';
const FLAGS_REGEXP = /\(\?([ims-]+)\)/g;

/**
 * Converts any mode modifiers in the text to the Javascript equivalent flag
 */
export function parseFlags(text: string): { cleaned: string; flags: string } {
  const flags: Set<string> = new Set(['g']);

  const cleaned = text.replace(FLAGS_REGEXP, (str, group) => {
    const clearAll = group.startsWith(CLEAR_FLAG);

    for (let i = 0; i < group.length; ++i) {
      const flag = group.charAt(i);
      if (clearAll || group.charAt(i - 1) === CLEAR_FLAG) {
        flags.delete(flag);
      } else if (flag !== CLEAR_FLAG) {
        flags.add(flag);
      }
    }
    return ''; // Remove flag from text
  });

  return {
    cleaned: cleaned,
    flags: Array.from(flags).join(''),
  };
}
