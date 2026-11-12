import { parseFlags } from '@grafana/data';

/**
 * Matcher for user-entered conditional rendering patterns.
 *
 * Patterns are stored in dashboards and evaluated in every viewer's browser, so they must never be
 * handed to the native backtracking RegExp engine, where patterns such as `(a+)+$` take exponential
 * time. This compiles the pattern to an NFA and simulates all threads in lockstep, so a match costs
 * at most (input length + 1) * program size steps, and both factors are capped.
 *
 * The accepted syntax is the subset of JavaScript RegExp syntax (non-unicode mode) that can be
 * matched this way, which is also the subset shared with RE2. Backreferences and lookaround
 * assertions are rejected as invalid, as RE2 does.
 */

const MAX_PATTERN_LENGTH = 5000;
const MAX_GROUP_DEPTH = 100;
const MAX_REPEAT = 1000;
const MAX_PROGRAM_SIZE = 10_000;
const MAX_STEPS = 2_000_000;

type CharMatcher = (code: number) => boolean;
type AssertionKind = 'lineStart' | 'lineEnd' | 'wordBoundary' | 'notWordBoundary';

type Node =
  | { type: 'char'; match: CharMatcher }
  | { type: 'assertion'; kind: AssertionKind }
  | { type: 'concat'; items: Node[] }
  | { type: 'alternation'; items: Node[] }
  | { type: 'repeat'; item: Node; min: number; max: number };

type Instruction =
  | { op: 'char'; match: CharMatcher }
  | { op: 'split'; x: number; y: number }
  | { op: 'jump'; x: number }
  | { op: 'assert'; kind: AssertionKind }
  | { op: 'match' };

interface Flags {
  ignoreCase: boolean;
  multiline: boolean;
  dotAll: boolean;
}

const BRACE_QUANTIFIER = /\{(\d+)(?:(,)(\d*))?\}/y;
const GROUP_NAME = /<([A-Za-z_$][\w$]*)>/y;
const HEX_DIGITS = /[0-9A-Fa-f]+/y;

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

function isWordChar(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95;
}

function isWhitespace(code: number): boolean {
  return (
    (code >= 9 && code <= 13) ||
    code === 32 ||
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000 ||
    code === 0xfeff
  );
}

function isLineTerminator(code: number): boolean {
  return code === 10 || code === 13 || code === 0x2028 || code === 0x2029;
}

/** Case folding used by JavaScript RegExp in non-unicode mode. */
function canonicalize(code: number): number {
  const upper = String.fromCharCode(code).toUpperCase();
  if (upper.length !== 1) {
    return code;
  }
  const upperCode = upper.charCodeAt(0);
  return code >= 128 && upperCode < 128 ? code : upperCode;
}

function caseInsensitive(match: CharMatcher): CharMatcher {
  return (code) => {
    if (match(code)) {
      return true;
    }
    const canonical = canonicalize(code);
    if (canonical !== code && match(canonical)) {
      return true;
    }
    const lower = String.fromCharCode(canonical).toLowerCase();
    if (lower.length !== 1) {
      return false;
    }
    const lowerCode = lower.charCodeAt(0);
    return lowerCode !== code && canonicalize(lowerCode) === canonical && match(lowerCode);
  };
}

function classEscape(ch: string): CharMatcher | undefined {
  switch (ch) {
    case 'd':
      return isDigit;
    case 'D':
      return (code) => !isDigit(code);
    case 'w':
      return isWordChar;
    case 'W':
      return (code) => !isWordChar(code);
    case 's':
      return isWhitespace;
    case 'S':
      return (code) => !isWhitespace(code);
  }
  return undefined;
}

class Parser {
  private pos = 0;
  private depth = 0;

  constructor(
    private readonly source: string,
    private readonly flags: Flags
  ) {}

  parse(): Node {
    const node = this.parseAlternation();
    if (this.pos < this.source.length) {
      throw new SyntaxError("Unmatched ')'");
    }
    return node;
  }

  private peek(offset = 0): string | undefined {
    return this.source[this.pos + offset];
  }

  private parseAlternation(): Node {
    const items = [this.parseSequence()];
    while (this.peek() === '|') {
      this.pos++;
      items.push(this.parseSequence());
    }
    return items.length === 1 ? items[0] : { type: 'alternation', items };
  }

  private parseSequence(): Node {
    const items: Node[] = [];
    while (this.pos < this.source.length) {
      const ch = this.peek();
      if (ch === '|' || ch === ')') {
        break;
      }
      items.push(this.parseTerm());
    }
    return { type: 'concat', items };
  }

  private parseTerm(): Node {
    const atom = this.parseAtom();
    const quantifier = this.parseQuantifier();
    if (!quantifier) {
      return atom;
    }
    if (atom.type === 'assertion') {
      throw new SyntaxError('Nothing to repeat');
    }
    if (this.peek() === '?') {
      this.pos++;
    }
    if (this.parseQuantifier()) {
      throw new SyntaxError('Nothing to repeat');
    }
    return { type: 'repeat', item: atom, ...quantifier };
  }

  private parseQuantifier(): { min: number; max: number } | undefined {
    switch (this.peek()) {
      case '*':
        this.pos++;
        return { min: 0, max: Infinity };
      case '+':
        this.pos++;
        return { min: 1, max: Infinity };
      case '?':
        this.pos++;
        return { min: 0, max: 1 };
      case '{': {
        BRACE_QUANTIFIER.lastIndex = this.pos;
        const match = BRACE_QUANTIFIER.exec(this.source);
        if (!match) {
          return undefined;
        }
        this.pos = BRACE_QUANTIFIER.lastIndex;
        const min = Number(match[1]);
        const max = match[2] ? (match[3] ? Number(match[3]) : Infinity) : min;
        if (max < min) {
          throw new SyntaxError('Numbers out of order in {} quantifier');
        }
        if (min > MAX_REPEAT || (max !== Infinity && max > MAX_REPEAT)) {
          throw new SyntaxError(`Repetition count above ${MAX_REPEAT} is not supported`);
        }
        return { min, max };
      }
    }
    return undefined;
  }

  private isBraceQuantifier(): boolean {
    BRACE_QUANTIFIER.lastIndex = this.pos;
    return BRACE_QUANTIFIER.test(this.source);
  }

  private parseAtom(): Node {
    const ch = this.source[this.pos];
    switch (ch) {
      case '(':
        return this.parseGroup();
      case '[':
        return this.parseClass();
      case '.':
        this.pos++;
        return { type: 'char', match: this.flags.dotAll ? () => true : (code) => !isLineTerminator(code) };
      case '^':
        this.pos++;
        return { type: 'assertion', kind: 'lineStart' };
      case '$':
        this.pos++;
        return { type: 'assertion', kind: 'lineEnd' };
      case '\\':
        return this.parseEscape();
      case '*':
      case '+':
      case '?':
        throw new SyntaxError('Nothing to repeat');
      case '{':
        if (this.isBraceQuantifier()) {
          throw new SyntaxError('Nothing to repeat');
        }
    }
    this.pos++;
    return this.literal(ch.charCodeAt(0));
  }

  private literal(code: number): Node {
    if (this.flags.ignoreCase) {
      const canonical = canonicalize(code);
      return { type: 'char', match: (c) => canonicalize(c) === canonical };
    }
    return { type: 'char', match: (c) => c === code };
  }

  private parseGroup(): Node {
    this.pos++;
    if (this.peek() === '?') {
      const kind = this.peek(1);
      if (kind === ':') {
        this.pos += 2;
      } else if (kind === '<' && this.peek(2) !== '=' && this.peek(2) !== '!') {
        GROUP_NAME.lastIndex = this.pos + 1;
        if (!GROUP_NAME.test(this.source)) {
          throw new SyntaxError('Invalid capture group name');
        }
        this.pos = GROUP_NAME.lastIndex;
      } else if (kind === '=' || kind === '!' || kind === '<') {
        throw new SyntaxError('Lookaround assertions are not supported');
      } else {
        throw new SyntaxError('Invalid group');
      }
    }

    if (++this.depth > MAX_GROUP_DEPTH) {
      throw new SyntaxError(`Group nesting deeper than ${MAX_GROUP_DEPTH} is not supported`);
    }
    const node = this.parseAlternation();
    if (this.peek() !== ')') {
      throw new SyntaxError('Unterminated group');
    }
    this.pos++;
    this.depth--;
    return node;
  }

  private parseEscape(): Node {
    this.pos++;
    if (this.pos >= this.source.length) {
      throw new SyntaxError('\\ at end of pattern');
    }
    const ch = this.source[this.pos++];
    if (ch === 'b') {
      return { type: 'assertion', kind: 'wordBoundary' };
    }
    if (ch === 'B') {
      return { type: 'assertion', kind: 'notWordBoundary' };
    }
    const cls = classEscape(ch);
    if (cls) {
      return { type: 'char', match: cls };
    }
    return this.literal(this.parseCharacterEscape(ch, false));
  }

  /** Called with the character after the backslash already consumed. */
  private parseCharacterEscape(ch: string, inClass: boolean): number {
    switch (ch) {
      case 't':
        return 9;
      case 'n':
        return 10;
      case 'v':
        return 11;
      case 'f':
        return 12;
      case 'r':
        return 13;
      case 'b':
        return 8;
      case '0':
        if (isDigit(this.source.charCodeAt(this.pos))) {
          throw new SyntaxError('Octal escapes are not supported');
        }
        return 0;
      case 'x':
        return this.parseHexEscape(2) ?? ch.charCodeAt(0);
      case 'u':
        return this.parseHexEscape(4) ?? ch.charCodeAt(0);
      case 'c': {
        const code = this.source.charCodeAt(this.pos);
        if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
          this.pos++;
          return code % 32;
        }
        throw new SyntaxError('Invalid control escape');
      }
      case 'k':
        if (!inClass && this.peek() === '<') {
          throw new SyntaxError('Backreferences are not supported');
        }
        break;
    }
    if (ch >= '1' && ch <= '9') {
      throw new SyntaxError('Backreferences are not supported');
    }
    return ch.charCodeAt(0);
  }

  private parseHexEscape(length: number): number | undefined {
    HEX_DIGITS.lastIndex = this.pos;
    const match = HEX_DIGITS.exec(this.source);
    if (!match || match[0].length < length) {
      return undefined;
    }
    this.pos += length;
    return parseInt(match[0].slice(0, length), 16);
  }

  private parseClass(): Node {
    this.pos++;
    let negate = false;
    if (this.peek() === '^') {
      negate = true;
      this.pos++;
    }

    const members: CharMatcher[] = [];
    while (true) {
      if (this.pos >= this.source.length) {
        throw new SyntaxError('Unterminated character class');
      }
      if (this.peek() === ']') {
        this.pos++;
        break;
      }
      const first = this.parseClassAtom();
      if (this.peek() === '-' && this.pos + 1 < this.source.length && this.peek(1) !== ']') {
        this.pos++;
        const second = this.parseClassAtom();
        if (typeof first === 'number' && typeof second === 'number') {
          if (first > second) {
            throw new SyntaxError('Range out of order in character class');
          }
          members.push((code) => code >= first && code <= second);
        } else {
          members.push(toMatcher(first), toMatcher(45), toMatcher(second)); // '-' is literal next to a class escape
        }
      } else {
        members.push(toMatcher(first));
      }
    }

    let match: CharMatcher = (code) => {
      for (const member of members) {
        if (member(code)) {
          return true;
        }
      }
      return false;
    };
    if (this.flags.ignoreCase) {
      match = caseInsensitive(match);
    }
    const inClass = match;
    return { type: 'char', match: negate ? (code) => !inClass(code) : inClass };
  }

  private parseClassAtom(): number | CharMatcher {
    const ch = this.source[this.pos++];
    if (ch !== '\\') {
      return ch.charCodeAt(0);
    }
    if (this.pos >= this.source.length) {
      throw new SyntaxError('\\ at end of pattern');
    }
    const escaped = this.source[this.pos++];
    return classEscape(escaped) ?? this.parseCharacterEscape(escaped, true);
  }
}

function toMatcher(member: number | CharMatcher): CharMatcher {
  return typeof member === 'number' ? (code) => code === member : member;
}

function programSize(node: Node): number {
  switch (node.type) {
    case 'char':
    case 'assertion':
      return 1;
    case 'concat':
      return node.items.reduce((sum, item) => sum + programSize(item), 0);
    case 'alternation':
      return node.items.reduce((sum, item) => sum + programSize(item), 0) + 2 * (node.items.length - 1);
    case 'repeat': {
      const itemSize = programSize(node.item);
      const optional = node.max === Infinity ? itemSize + 2 : (node.max - node.min) * (itemSize + 1);
      return node.min * itemSize + optional;
    }
  }
}

function compile(root: Node): Instruction[] {
  const program: Instruction[] = [];

  const emit = (node: Node) => {
    switch (node.type) {
      case 'char':
        program.push({ op: 'char', match: node.match });
        return;
      case 'assertion':
        program.push({ op: 'assert', kind: node.kind });
        return;
      case 'concat':
        node.items.forEach(emit);
        return;
      case 'alternation': {
        const exits: Array<{ op: 'jump'; x: number }> = [];
        node.items.forEach((item, index) => {
          if (index === node.items.length - 1) {
            emit(item);
            return;
          }
          const split: Instruction = { op: 'split', x: program.length + 1, y: -1 };
          program.push(split);
          emit(item);
          const exit = { op: 'jump' as const, x: -1 };
          program.push(exit);
          exits.push(exit);
          split.y = program.length;
        });
        exits.forEach((exit) => (exit.x = program.length));
        return;
      }
      case 'repeat': {
        for (let i = 0; i < node.min; i++) {
          emit(node.item);
        }
        if (node.max === Infinity) {
          const loop = program.length;
          const split: Instruction = { op: 'split', x: loop + 1, y: -1 };
          program.push(split);
          emit(node.item);
          program.push({ op: 'jump', x: loop });
          split.y = program.length;
          return;
        }
        const skips: Array<{ op: 'split'; x: number; y: number }> = [];
        for (let i = node.min; i < node.max; i++) {
          const split = { op: 'split' as const, x: program.length + 1, y: -1 };
          program.push(split);
          skips.push(split);
          emit(node.item);
        }
        skips.forEach((split) => (split.y = program.length));
        return;
      }
    }
  };

  emit(root);
  program.push({ op: 'match' });
  return program;
}

export class LinearRegExp {
  private constructor(
    private readonly program: Instruction[],
    private readonly multiline: boolean
  ) {}

  /**
   * Compiles a user-entered pattern, honouring RE2-style inline flags such as `(?i)` (the same syntax
   * accepted elsewhere in Grafana). Throws on invalid, unsupported, or oversized patterns.
   */
  public static compile(value: string): LinearRegExp {
    if (value.length > MAX_PATTERN_LENGTH) {
      throw new SyntaxError(`Patterns longer than ${MAX_PATTERN_LENGTH} characters are not supported`);
    }
    const { cleaned, flags } = parseFlags(value);
    const parsedFlags: Flags = {
      ignoreCase: flags.includes('i'),
      multiline: flags.includes('m'),
      dotAll: flags.includes('s'),
    };
    const root = new Parser(cleaned, parsedFlags).parse();
    if (programSize(root) + 1 > MAX_PROGRAM_SIZE) {
      throw new SyntaxError('Pattern is too large');
    }
    return new LinearRegExp(compile(root), parsedFlags.multiline);
  }

  /**
   * Whether the pattern matches anywhere in at least one input. Throws a RangeError, without
   * matching, when the inputs together would exceed the step budget.
   */
  public testAny(inputs: string[]): boolean {
    let budget = MAX_STEPS;
    for (const input of inputs) {
      budget -= (input.length + 1) * this.program.length;
      if (budget < 0) {
        throw new RangeError('Input is too long to match against this pattern');
      }
    }
    return inputs.some((input) => this.run(input));
  }

  public test(input: string): boolean {
    return this.testAny([input]);
  }

  private assertionHolds(kind: AssertionKind, input: string, position: number): boolean {
    switch (kind) {
      case 'lineStart':
        return position === 0 || (this.multiline && isLineTerminator(input.charCodeAt(position - 1)));
      case 'lineEnd':
        return position === input.length || (this.multiline && isLineTerminator(input.charCodeAt(position)));
      case 'wordBoundary':
        return isWordChar(input.charCodeAt(position - 1)) !== isWordChar(input.charCodeAt(position));
      case 'notWordBoundary':
        return isWordChar(input.charCodeAt(position - 1)) === isWordChar(input.charCodeAt(position));
    }
  }

  private run(input: string): boolean {
    const program = this.program;
    const size = program.length;
    // visited[pc] holds position + 1 once pc has been added to the thread list for that position.
    const visited = new Int32Array(size);
    const stack = new Int32Array(size);
    let current = new Int32Array(size);
    let next = new Int32Array(size);
    let currentCount = 0;

    const addThread = (list: Int32Array, count: number, start: number, position: number): number => {
      const mark = position + 1;
      if (visited[start] === mark) {
        return count;
      }
      let top = 0;
      visited[start] = mark;
      stack[top++] = start;
      const push = (pc: number) => {
        if (visited[pc] !== mark) {
          visited[pc] = mark;
          stack[top++] = pc;
        }
      };
      while (top > 0) {
        const pc = stack[--top];
        const instruction = program[pc];
        switch (instruction.op) {
          case 'jump':
            push(instruction.x);
            break;
          case 'split':
            push(instruction.x);
            push(instruction.y);
            break;
          case 'assert':
            if (this.assertionHolds(instruction.kind, input, position)) {
              push(pc + 1);
            }
            break;
          default:
            list[count++] = pc;
        }
      }
      return count;
    };

    for (let position = 0; ; position++) {
      currentCount = addThread(current, currentCount, 0, position);
      const code = position < input.length ? input.charCodeAt(position) : -1;
      let nextCount = 0;
      for (let i = 0; i < currentCount; i++) {
        const pc = current[i];
        const instruction = program[pc];
        if (instruction.op === 'match') {
          return true;
        }
        if (code >= 0 && instruction.op === 'char' && instruction.match(code)) {
          nextCount = addThread(next, nextCount, pc + 1, position + 1);
        }
      }
      if (position >= input.length) {
        return false;
      }
      const done = current;
      current = next;
      next = done;
      currentCount = nextCount;
    }
  }
}
