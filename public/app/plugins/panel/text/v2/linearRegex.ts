/**
 * Tests a JavaScript-syntax regular expression (no flags) against an input in time
 * linear in the input. Patterns come from dashboard content and query data, so the
 * native backtracking engine could hang the viewer's tab on a pattern such as `(a+)+$`.
 *
 * Supported: literals, `.`, classes, `\d \w \s` and their negations, `^ $ \b \B`,
 * groups (capturing, named and `(?:`), `|`, and greedy or lazy `* + ? {n} {n,} {n,m}`.
 * Backreferences and lookaround cannot be matched in linear time and throw instead.
 * Like `RegExp` without the `u` flag, input is matched one UTF-16 code unit at a time.
 */

export const MAX_PATTERN_LENGTH = 1000;
/** Bounds the NFA, which `{n,m}` grows by copying its operand. */
export const MAX_PROGRAM_COST = 2000;
/** Bounds the sum of program cost times input length, the worst-case work, across a matcher's calls. */
export const MAX_MATCH_WORK = 5_000_000;

type CharTest = (code: number) => boolean;
type AssertKind = 'start' | 'end' | 'wordBoundary' | 'notWordBoundary';

type Node =
  | { type: 'char'; test: CharTest; cost?: number }
  | { type: 'assert'; kind: AssertKind }
  | { type: 'concat'; items: Node[] }
  | { type: 'alt'; options: Node[] }
  | { type: 'repeat'; body: Node; min: number; max: number };

type Instruction =
  | { op: 'char'; test: CharTest; next: number }
  | { op: 'assert'; kind: AssertKind; next: number }
  | { op: 'split'; x: number; y: number }
  | { op: 'match' };

const MAX_REPEAT_COUNT = 1000;

const isDigit: CharTest = (c) => c >= 48 && c <= 57;
const isWord: CharTest = (c) => isDigit(c) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const isSpace: CharTest = (c) =>
  (c >= 9 && c <= 13) ||
  c === 32 ||
  c === 0xa0 ||
  c === 0x1680 ||
  (c >= 0x2000 && c <= 0x200a) ||
  c === 0x2028 ||
  c === 0x2029 ||
  c === 0x202f ||
  c === 0x205f ||
  c === 0x3000 ||
  c === 0xfeff;
const isLineTerminator: CharTest = (c) => c === 10 || c === 13 || c === 0x2028 || c === 0x2029;

const not =
  (test: CharTest): CharTest =>
  (c) =>
    !test(c);

const CLASS_ESCAPES: Record<string, CharTest> = {
  d: isDigit,
  D: not(isDigit),
  w: isWord,
  W: not(isWord),
  s: isSpace,
  S: not(isSpace),
};

const CONTROL_ESCAPES: Record<string, number> = { t: 9, n: 10, v: 11, f: 12, r: 13 };

class PatternError extends Error {
  constructor(message: string, pattern: string) {
    const shown = pattern.length > 40 ? `${pattern.slice(0, 40)}...` : pattern;
    super(`Invalid regular expression /${shown}/: ${message}`);
  }
}

class Parser {
  private pos = 0;
  private readonly groupNames = new Set<string>();

  constructor(private readonly pattern: string) {}

  parse(): Node {
    const node = this.parseAlternation();
    if (this.pos < this.pattern.length) {
      // parseAlternation only stops early on a `)` it did not open.
      throw this.error("Unmatched ')'");
    }
    return node;
  }

  private error(message: string): PatternError {
    return new PatternError(message, this.pattern);
  }

  private peek(offset = 0): string {
    return this.pattern.charAt(this.pos + offset);
  }

  private atEnd(): boolean {
    return this.pos >= this.pattern.length;
  }

  /** `sticky` must carry the `y` flag, so it only matches at the cursor. */
  private matchAt(sticky: RegExp): RegExpExecArray | null {
    sticky.lastIndex = this.pos;
    return sticky.exec(this.pattern);
  }

  private parseAlternation(): Node {
    const options = [this.parseSequence()];
    while (this.peek() === '|') {
      this.pos++;
      options.push(this.parseSequence());
    }
    return options.length === 1 ? options[0] : { type: 'alt', options };
  }

  private parseSequence(): Node {
    const items: Node[] = [];
    while (!this.atEnd() && this.peek() !== '|' && this.peek() !== ')') {
      items.push(this.parseQuantified());
    }
    return items.length === 1 ? items[0] : { type: 'concat', items };
  }

  private parseQuantified(): Node {
    // `RegExp` refuses to repeat a bare assertion but accepts one wrapped in a group.
    const isGroup = this.peek() === '(';
    const atom = this.parseAtom();
    const quantifier = this.parseQuantifier();
    if (!quantifier) {
      return atom;
    }
    if (atom.type === 'assert' && !isGroup) {
      throw this.error('Nothing to repeat');
    }
    // Laziness changes which match is found, not whether one exists.
    if (this.peek() === '?') {
      this.pos++;
    }
    return { type: 'repeat', body: atom, ...quantifier };
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
        const braces = this.readBraceQuantifier();
        if (braces) {
          this.pos = braces.end;
        }
        return braces;
      }
      default:
        return undefined;
    }
  }

  /** `{n}`, `{n,}` or `{n,m}` at the cursor; anything else leaves `{` a literal, as in `RegExp`. */
  private readBraceQuantifier(): { min: number; max: number; end: number } | undefined {
    const found = this.matchAt(/\{(\d+)(,(\d*))?\}/y);
    if (!found) {
      return undefined;
    }
    const min = this.toCount(found[1]);
    const max = found[2] === undefined ? min : found[3] === '' ? Infinity : this.toCount(found[3]);
    if (min > max) {
      throw this.error('numbers out of order in {} quantifier');
    }
    return { min, max, end: this.pos + found[0].length };
  }

  private toCount(digits: string): number {
    const count = Number(digits);
    if (count > MAX_REPEAT_COUNT) {
      throw this.error(`repetition count above ${MAX_REPEAT_COUNT}`);
    }
    return count;
  }

  private parseAtom(): Node {
    const ch = this.peek();
    switch (ch) {
      case '(':
        return this.parseGroup();
      case '[':
        return this.parseClass();
      case '.':
        this.pos++;
        return { type: 'char', test: not(isLineTerminator) };
      case '^':
        this.pos++;
        return { type: 'assert', kind: 'start' };
      case '$':
        this.pos++;
        return { type: 'assert', kind: 'end' };
      case '\\':
        return this.parseEscape();
      case '*':
      case '+':
      case '?':
        throw this.error('Nothing to repeat');
      case '{':
        if (this.readBraceQuantifier()) {
          throw this.error('Nothing to repeat');
        }
        break;
    }
    this.pos++;
    return literal(ch.charCodeAt(0));
  }

  private parseGroup(): Node {
    this.pos++;
    if (this.peek() === '?') {
      const named = this.matchAt(/\?<([A-Za-z_$][\w$]*)>/y);
      if (this.peek(1) === ':') {
        this.pos += 2;
      } else if (named) {
        if (this.groupNames.has(named[1])) {
          throw this.error('Duplicate capture group name');
        }
        this.groupNames.add(named[1]);
        this.pos += named[0].length;
      } else {
        throw this.error('lookahead and lookbehind are not supported');
      }
    }
    const body = this.parseAlternation();
    if (this.peek() !== ')') {
      throw this.error('Unterminated group');
    }
    this.pos++;
    return body;
  }

  private parseEscape(): Node {
    this.pos++;
    if (this.atEnd()) {
      throw this.error('\\ at end of pattern');
    }
    const ch = this.peek();
    if (ch === 'b' || ch === 'B') {
      this.pos++;
      return { type: 'assert', kind: ch === 'b' ? 'wordBoundary' : 'notWordBoundary' };
    }
    if ((ch >= '1' && ch <= '9') || ch === 'k') {
      throw this.error('backreferences are not supported');
    }
    return { type: 'char', test: toTest(this.readCharEscape()) };
  }

  /** The code unit an escape stands for, or the test for a class escape; the cursor is past the `\`. */
  private readCharEscape(): number | CharTest {
    const ch = this.peek();
    this.pos++;

    if (CLASS_ESCAPES[ch]) {
      return CLASS_ESCAPES[ch];
    }
    if (CONTROL_ESCAPES[ch] !== undefined) {
      return CONTROL_ESCAPES[ch];
    }
    if (ch === '0') {
      if (isDigit(this.pattern.charCodeAt(this.pos))) {
        throw this.error('octal escapes are not supported');
      }
      return 0;
    }
    if (ch >= '1' && ch <= '9') {
      throw this.error('octal escapes are not supported');
    }
    if (ch === 'x' || ch === 'u') {
      const digits = ch === 'x' ? 2 : 4;
      const hex = this.pattern.slice(this.pos, this.pos + digits);
      if (hex.length === digits && /^[0-9A-Fa-f]+$/.test(hex)) {
        this.pos += digits;
        return parseInt(hex, 16);
      }
      throw this.error(`invalid \\${ch} escape`);
    }
    if (ch === 'c') {
      const letter = this.pattern.charCodeAt(this.pos);
      if ((letter >= 65 && letter <= 90) || (letter >= 97 && letter <= 122)) {
        this.pos++;
        return letter % 32;
      }
      throw this.error('invalid \\c escape');
    }
    return ch.charCodeAt(0);
  }

  private parseClass(): Node {
    this.pos++;
    const negate = this.peek() === '^';
    if (negate) {
      this.pos++;
    }

    const tests: CharTest[] = [];
    while (this.peek() !== ']') {
      if (this.atEnd()) {
        throw this.error('Unterminated character class');
      }
      const low = this.parseClassAtom();
      if (this.peek() === '-' && this.peek(1) !== ']' && this.pos + 1 < this.pattern.length) {
        this.pos++;
        const high = this.parseClassAtom();
        if (typeof low === 'number' && typeof high === 'number') {
          if (low > high) {
            throw this.error('Range out of order in character class');
          }
          tests.push((c) => c >= low && c <= high);
          continue;
        }
        // A class escape at either end makes the `-` a literal, as in `RegExp`.
        tests.push(toTest(low), literalTest(45), toTest(high));
        continue;
      }
      tests.push(toTest(low));
    }
    this.pos++;

    const inClass: CharTest = (c) => tests.some((test) => test(c));
    return { type: 'char', test: negate ? not(inClass) : inClass, cost: Math.max(tests.length, 1) };
  }

  /** A code unit, or a test for a class escape such as `\d`. */
  private parseClassAtom(): number | CharTest {
    const ch = this.peek();
    if (ch !== '\\') {
      this.pos++;
      return ch.charCodeAt(0);
    }
    this.pos++;
    if (this.atEnd()) {
      throw this.error('\\ at end of pattern');
    }
    // Inside a class `\b` is a backspace, not a word boundary.
    if (this.peek() === 'b') {
      this.pos++;
      return 8;
    }
    return this.readCharEscape();
  }
}

const literalTest =
  (code: number): CharTest =>
  (c) =>
    c === code;

const literal = (code: number): Node => ({ type: 'char', test: literalTest(code) });

const toTest = (atom: number | CharTest): CharTest => (typeof atom === 'number' ? literalTest(atom) : atom);

/** Instructions, with a class weighted by its item count since it tests each one per input character. */
function programCost(node: Node): number {
  switch (node.type) {
    case 'char':
      return node.cost ?? 1;
    case 'assert':
      return 1;
    case 'concat':
      return node.items.reduce((sum, item) => sum + programCost(item), 0);
    case 'alt':
      return node.options.reduce((sum, option) => sum + programCost(option), node.options.length - 1);
    case 'repeat': {
      const body = programCost(node.body);
      return node.max === Infinity ? body * (node.min + 1) + 1 : body * node.max + (node.max - node.min);
    }
  }
}

/** Compiles back to front, so every instruction's successor already exists. Returns the entry point. */
function emit(node: Node, next: number, program: Instruction[]): number {
  switch (node.type) {
    case 'char':
      return program.push({ op: 'char', test: node.test, next }) - 1;
    case 'assert':
      return program.push({ op: 'assert', kind: node.kind, next }) - 1;
    case 'concat':
      return node.items.reduceRight((pc, item) => emit(item, pc, program), next);
    case 'alt': {
      const entries = node.options.map((option) => emit(option, next, program));
      return entries.reduceRight((pc, entry) => program.push({ op: 'split', x: entry, y: pc }) - 1);
    }
    case 'repeat': {
      let pc = next;
      if (node.max === Infinity) {
        const loop = program.push({ op: 'split', x: -1, y: next }) - 1;
        program[loop] = { op: 'split', x: emit(node.body, loop, program), y: next };
        pc = loop;
      } else {
        for (let i = node.min; i < node.max; i++) {
          pc = program.push({ op: 'split', x: emit(node.body, pc, program), y: next }) - 1;
        }
      }
      for (let i = 0; i < node.min; i++) {
        pc = emit(node.body, pc, program);
      }
      return pc;
    }
  }
}

function assertionHolds(kind: AssertKind, input: string, pos: number): boolean {
  switch (kind) {
    case 'start':
      return pos === 0;
    case 'end':
      return pos === input.length;
    case 'wordBoundary':
    case 'notWordBoundary': {
      const before = pos > 0 && isWord(input.charCodeAt(pos - 1));
      const after = pos < input.length && isWord(input.charCodeAt(pos));
      return (before !== after) === (kind === 'wordBoundary');
    }
  }
}

/** Steps every NFA thread in lockstep, so each instruction is visited at most once per input position. */
function run(program: Instruction[], start: number, input: string): boolean {
  const visited = new Uint32Array(program.length);
  const stack: number[] = [];
  // Starts above the zero the array is filled with, so nothing begins visited.
  let generation = 1;
  let current: number[] = [];
  let next: number[] = [];

  // Follows every non-consuming instruction from `pc`, collecting the `char` ones. True on reaching `match`.
  const addThread = (list: number[], pc: number, pos: number): boolean => {
    stack.push(pc);
    while (stack.length > 0) {
      const at = stack.pop()!;
      if (visited[at] === generation) {
        continue;
      }
      visited[at] = generation;
      const instruction = program[at];
      switch (instruction.op) {
        case 'match':
          stack.length = 0;
          return true;
        case 'char':
          list.push(at);
          break;
        case 'assert':
          if (assertionHolds(instruction.kind, input, pos)) {
            stack.push(instruction.next);
          }
          break;
        case 'split':
          stack.push(instruction.y, instruction.x);
          break;
      }
    }
    return false;
  };

  for (let pos = 0; ; pos++) {
    // A thread starts at every position, which makes the search unanchored like `RegExp.test`.
    if (addThread(current, start, pos)) {
      return true;
    }
    if (pos === input.length) {
      return false;
    }
    const code = input.charCodeAt(pos);
    generation++;
    for (const pc of current) {
      const instruction = program[pc];
      if (instruction.op === 'char' && instruction.test(code) && addThread(next, instruction.next, pos + 1)) {
        return true;
      }
    }
    [current, next] = [next, current];
    next.length = 0;
  }
}

export type LinearMatcher = (pattern: string, input: string) => boolean;

/**
 * Returns a `RegExp.test` equivalent whose calls share one work budget, so a template
 * cannot multiply the per-call bound by calling it once per row or many times over.
 * Throws for a pattern that is invalid, unsupported, or would exceed the budget.
 */
export function createLinearMatcher(maxWork = MAX_MATCH_WORK): LinearMatcher {
  let remainingWork = maxWork;

  return (pattern, input) => {
    if (pattern.length > MAX_PATTERN_LENGTH) {
      throw new PatternError(`longer than ${MAX_PATTERN_LENGTH} characters`, pattern);
    }

    const ast = new Parser(pattern).parse();
    const cost = programCost(ast) + 1;
    if (cost > MAX_PROGRAM_COST) {
      throw new PatternError('too many repetitions', pattern);
    }

    const work = cost * (input.length + 1);
    if (work > remainingWork) {
      throw new PatternError('matching would take too long', pattern);
    }
    remainingWork -= work;

    const program: Instruction[] = [{ op: 'match' }];
    return run(program, emit(ast, 0, program), input);
  };
}
