/**
 * A regular expression matcher for the RE2 syntax that Alertmanager uses for label matchers.
 *
 * Matcher values are user input: they come from policies other people saved and from filters in
 * the address bar. The JavaScript RegExp engine backtracks, so a pattern like "(a+)+$" against a
 * few dozen characters can lock up the page for minutes. This matcher compiles the pattern to an
 * NFA and simulates it, so a test costs at most O(program size × input length), and both of those
 * are capped below. It only answers whether the pattern matches; there are no captures.
 *
 * Syntax follows Go's regexp/syntax with Perl flags, which is what Alertmanager compiles matchers
 * with. Unicode classes (\p, \P) are not supported and fail to compile.
 */

const MAX_PATTERN_LENGTH = 16_384;
const MAX_PROGRAM_SIZE = 20_000;
const MAX_NESTING_DEPTH = 250;
// Same limit as RE2.
const MAX_REPEAT = 1000;
// Upper bound on instructions visited by a single test, whatever the input length. This is a few
// milliseconds of work, and far more than ordinary matchers need on ordinary label values.
const MAX_STEPS = 250_000;
// How many leading characters an alternation's branches are factored on; see factorAlternation.
const MAX_FACTOR_DEPTH = 64;

const MAX_CODE_POINT = 0x10ffff;
const NEWLINE = 0x0a;

export class RegexSyntaxError extends Error {
  constructor(message: string, pattern: string) {
    super(`invalid regular expression ${JSON.stringify(pattern)}: ${message}`);
    this.name = 'RegexSyntaxError';
  }
}

export class RegexBudgetError extends Error {
  constructor() {
    super('regular expression evaluation exceeded its step budget');
    this.name = 'RegexBudgetError';
  }
}

export interface CompiledRegex {
  /** Whether the pattern matches anywhere in the input, like RegExp.prototype.test. */
  test(input: string): boolean;
}

export function compileRegex(pattern: string): CompiledRegex {
  if (pattern.length > MAX_PATTERN_LENGTH) {
    throw new RegexSyntaxError(`pattern is longer than ${MAX_PATTERN_LENGTH} characters`, pattern);
  }
  const ast = new Parser(pattern).parse();
  return new Program(ast, pattern);
}

// ---------------------------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------------------------

type AssertKind = 'beginText' | 'endText' | 'beginLine' | 'endLine' | 'wordBoundary' | 'notWordBoundary';

/** Sorted, non-overlapping inclusive [lo, hi] pairs, flattened. */
type Ranges = number[];

interface CharSet {
  ranges: Ranges;
  negate: boolean;
  fold: boolean;
}

type Node =
  | { type: 'empty' }
  | { type: 'char'; set: CharSet }
  | { type: 'assert'; kind: AssertKind }
  | { type: 'concat'; items: Node[] }
  | { type: 'alt'; items: Node[]; factorDepth?: number }
  | { type: 'repeat'; min: number; max: number; sub: Node };

const EMPTY: Node = { type: 'empty' };

interface Flags {
  i: boolean;
  m: boolean;
  s: boolean;
}

const ANY: Ranges = [0, MAX_CODE_POINT];
const ANY_EXCEPT_NEWLINE: Ranges = [0, NEWLINE - 1, NEWLINE + 1, MAX_CODE_POINT];

const PERL_CLASSES = new Map<string, Ranges>([
  ['d', [0x30, 0x39]],
  ['s', [0x09, 0x0a, 0x0c, 0x0d, 0x20, 0x20]],
  ['w', [0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a]],
]);

const POSIX_CLASSES = new Map<string, Ranges>([
  ['alnum', [0x30, 0x39, 0x41, 0x5a, 0x61, 0x7a]],
  ['alpha', [0x41, 0x5a, 0x61, 0x7a]],
  ['ascii', [0x00, 0x7f]],
  ['blank', [0x09, 0x09, 0x20, 0x20]],
  ['cntrl', [0x00, 0x1f, 0x7f, 0x7f]],
  ['digit', [0x30, 0x39]],
  ['graph', [0x21, 0x7e]],
  ['lower', [0x61, 0x7a]],
  ['print', [0x20, 0x7e]],
  ['punct', [0x21, 0x2f, 0x3a, 0x40, 0x5b, 0x60, 0x7b, 0x7e]],
  ['space', [0x09, 0x0d, 0x20, 0x20]],
  ['upper', [0x41, 0x5a]],
  ['word', [0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a]],
  ['xdigit', [0x30, 0x39, 0x41, 0x46, 0x61, 0x66]],
]);

const ESCAPED_ASSERTIONS = new Map<string, AssertKind>([
  ['A', 'beginText'],
  ['z', 'endText'],
  ['b', 'wordBoundary'],
  ['B', 'notWordBoundary'],
]);

function normalizeRanges(ranges: Ranges): Ranges {
  const pairs: Array<[number, number]> = [];
  for (let i = 0; i < ranges.length; i += 2) {
    pairs.push([ranges[i], ranges[i + 1]]);
  }
  pairs.sort((a, b) => a[0] - b[0]);

  const merged: Ranges = [];
  for (const [lo, hi] of pairs) {
    const last = merged.length - 1;
    if (last > 0 && lo <= merged[last] + 1) {
      merged[last] = Math.max(merged[last], hi);
    } else {
      merged.push(lo, hi);
    }
  }
  return merged;
}

function complementRanges(ranges: Ranges): Ranges {
  const sorted = normalizeRanges(ranges);
  const result: Ranges = [];
  let next = 0;
  for (let i = 0; i < sorted.length; i += 2) {
    if (sorted[i] > next) {
      result.push(next, sorted[i] - 1);
    }
    next = sorted[i + 1] + 1;
  }
  if (next <= MAX_CODE_POINT) {
    result.push(next, MAX_CODE_POINT);
  }
  return result;
}

function singleCodePoint(text: string): number | undefined {
  const cp = text.codePointAt(0);
  if (cp === undefined || text.length !== (cp > 0xffff ? 2 : 1)) {
    return undefined;
  }
  return cp;
}

function simpleLower(cp: number): number {
  return singleCodePoint(String.fromCodePoint(cp).toLowerCase()) ?? cp;
}

function simpleUpper(cp: number): number {
  return singleCodePoint(String.fromCodePoint(cp).toUpperCase()) ?? cp;
}

function literal(cp: number, flags: Flags): Node {
  const ranges = flags.i
    ? normalizeRanges([cp, cp, simpleLower(cp), simpleLower(cp), simpleUpper(cp), simpleUpper(cp)])
    : [cp, cp];
  return { type: 'char', set: { ranges, negate: false, fold: flags.i } };
}

function isAsciiAlnum(cp: number): boolean {
  return (cp >= 0x30 && cp <= 0x39) || (cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a);
}

function isOctalDigit(cp: number | undefined): cp is number {
  return cp !== undefined && cp >= 0x30 && cp <= 0x37;
}

function hexValue(cp: number | undefined): number {
  if (cp === undefined) {
    return -1;
  }
  if (cp >= 0x30 && cp <= 0x39) {
    return cp - 0x30;
  }
  if (cp >= 0x41 && cp <= 0x46) {
    return cp - 0x41 + 10;
  }
  if (cp >= 0x61 && cp <= 0x66) {
    return cp - 0x61 + 10;
  }
  return -1;
}

function isNameChar(cp: number): boolean {
  return isAsciiAlnum(cp) || cp === 0x5f;
}

// ---------------------------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------------------------

class Parser {
  private readonly src: number[];
  private pos = 0;
  private readonly groupNames = new Set<string>();

  constructor(private readonly pattern: string) {
    this.src = Array.from(pattern, (ch) => ch.codePointAt(0)!);
  }

  parse(): Node {
    const node = this.parseAlternation({ i: false, m: false, s: false }, 0);
    if (this.pos < this.src.length) {
      throw this.error('unexpected )');
    }
    return node;
  }

  private error(message: string): RegexSyntaxError {
    return new RegexSyntaxError(message, this.pattern);
  }

  private peek(offset = 0): number | undefined {
    return this.src[this.pos + offset];
  }

  private is(char: string, offset = 0): boolean {
    return this.src[this.pos + offset] === char.charCodeAt(0);
  }

  private parseAlternation(flags: Flags, depth: number): Node {
    if (depth > MAX_NESTING_DEPTH) {
      throw this.error('expression nests too deeply');
    }

    const branches: Node[] = [this.parseConcat(flags, depth)];
    while (this.is('|')) {
      this.pos++;
      branches.push(this.parseConcat(flags, depth));
    }
    return branches.length === 1 ? branches[0] : { type: 'alt', items: branches };
  }

  private parseConcat(flags: Flags, depth: number): Node {
    const items: Node[] = [];
    while (this.pos < this.src.length && !this.is('|') && !this.is(')')) {
      const before = items.length;
      this.parseAtom(items, flags, depth);
      if (items.length > before) {
        items[items.length - 1] = this.parseRepeats(items[items.length - 1]);
      }
    }

    const nonEmpty = items.filter((item) => item.type !== 'empty');
    if (nonEmpty.length === 0) {
      return EMPTY;
    }
    return nonEmpty.length === 1 ? nonEmpty[0] : { type: 'concat', items: nonEmpty };
  }

  /** Parses one atom and appends what it produced; flag groups and empty \Q\E produce nothing. */
  private parseAtom(items: Node[], flags: Flags, depth: number): void {
    const c = this.peek()!;
    switch (String.fromCodePoint(c)) {
      case '(':
        this.parseGroup(items, flags, depth);
        return;
      case '[':
        items.push({ type: 'char', set: this.parseClass(flags) });
        return;
      case '.':
        this.pos++;
        items.push({ type: 'char', set: { ranges: flags.s ? ANY : ANY_EXCEPT_NEWLINE, negate: false, fold: false } });
        return;
      case '^':
        this.pos++;
        items.push({ type: 'assert', kind: flags.m ? 'beginLine' : 'beginText' });
        return;
      case '$':
        this.pos++;
        items.push({ type: 'assert', kind: flags.m ? 'endLine' : 'endText' });
        return;
      case '\\':
        this.parseEscapeAtom(items, flags);
        return;
      case '*':
      case '+':
      case '?':
        throw this.error('missing argument to repetition operator');
      case '{':
        if (this.tryParseBounds()) {
          throw this.error('missing argument to repetition operator');
        }
        this.pos++;
        items.push(literal(c, flags));
        return;
      default:
        this.pos++;
        items.push(literal(c, flags));
    }
  }

  private parseRepeats(atom: Node): Node {
    let node = atom;
    let repeated = false;

    while (this.pos < this.src.length) {
      let bounds: { min: number; max: number } | undefined;
      if (this.is('*')) {
        this.pos++;
        bounds = { min: 0, max: -1 };
      } else if (this.is('+')) {
        this.pos++;
        bounds = { min: 1, max: -1 };
      } else if (this.is('?')) {
        this.pos++;
        bounds = { min: 0, max: 1 };
      } else if (this.is('{')) {
        bounds = this.tryParseBounds();
      }
      if (!bounds) {
        break;
      }
      if (repeated) {
        throw this.error('invalid nested repetition operator');
      }
      repeated = true;

      // Laziness changes which match is reported, never whether there is one.
      if (this.is('?')) {
        this.pos++;
      }

      node = makeRepeat(node, bounds.min, bounds.max);
    }

    return node;
  }

  /** Parses {n}, {n,} or {n,m} at the cursor, or returns undefined without consuming anything. */
  private tryParseBounds(): { min: number; max: number } | undefined {
    const start = this.pos;
    this.pos++;

    const min = this.parseInt();
    if (min === undefined) {
      this.pos = start;
      return undefined;
    }

    let max = min;
    if (this.is(',')) {
      this.pos++;
      if (this.is('}')) {
        max = -1;
      } else {
        const parsed = this.parseInt();
        if (parsed === undefined) {
          this.pos = start;
          return undefined;
        }
        max = parsed;
      }
    }

    if (!this.is('}')) {
      this.pos = start;
      return undefined;
    }
    this.pos++;

    if (min > MAX_REPEAT || max > MAX_REPEAT || (max !== -1 && max < min)) {
      throw this.error('invalid repeat count');
    }
    return { min, max };
  }

  private parseInt(): number | undefined {
    const start = this.pos;
    let value = 0;
    while (this.pos < this.src.length && this.src[this.pos] >= 0x30 && this.src[this.pos] <= 0x39) {
      // Anything past the repeat limit is rejected later, so stop growing the number.
      value = Math.min(value * 10 + (this.src[this.pos] - 0x30), MAX_REPEAT + 1);
      this.pos++;
    }
    return this.pos === start ? undefined : value;
  }

  private parseGroup(items: Node[], flags: Flags, depth: number): void {
    this.pos++;

    if (!this.is('?')) {
      items.push(this.parseGroupBody({ ...flags }, depth));
      return;
    }
    this.pos++;

    if (this.is('P') && this.is('<', 1)) {
      this.pos += 2;
      this.parseGroupName();
      items.push(this.parseGroupBody({ ...flags }, depth));
      return;
    }
    if (this.is('<')) {
      this.pos++;
      this.parseGroupName();
      items.push(this.parseGroupBody({ ...flags }, depth));
      return;
    }

    const next = { ...flags };
    let negate = false;
    let sawFlag = false;
    while (this.pos < this.src.length) {
      const c = String.fromCodePoint(this.src[this.pos++]);
      switch (c) {
        case 'i':
          next.i = !negate;
          sawFlag = true;
          break;
        case 'm':
          next.m = !negate;
          sawFlag = true;
          break;
        case 's':
          next.s = !negate;
          sawFlag = true;
          break;
        case 'U':
          sawFlag = true;
          break;
        case '-':
          if (negate) {
            throw this.error('invalid or unsupported Perl syntax');
          }
          negate = true;
          sawFlag = false;
          break;
        case ':':
        case ')':
          if (negate && !sawFlag) {
            throw this.error('invalid or unsupported Perl syntax');
          }
          if (c === ':') {
            items.push(this.parseGroupBody(next, depth));
          } else {
            // A bare flag group changes the flags for the rest of the enclosing group.
            Object.assign(flags, next);
          }
          return;
        default:
          throw this.error('invalid or unsupported Perl syntax');
      }
    }
    throw this.error('missing closing )');
  }

  private parseGroupName(): void {
    const start = this.pos;
    while (this.pos < this.src.length && isNameChar(this.src[this.pos])) {
      this.pos++;
    }
    if (this.pos === start || !this.is('>')) {
      throw this.error('invalid named capture');
    }
    const name = String.fromCodePoint(...this.src.slice(start, this.pos));
    if (this.groupNames.has(name)) {
      throw this.error('duplicate capture group name');
    }
    this.groupNames.add(name);
    this.pos++;
  }

  private parseGroupBody(flags: Flags, depth: number): Node {
    const node = this.parseAlternation(flags, depth + 1);
    if (!this.is(')')) {
      throw this.error('missing closing )');
    }
    this.pos++;
    return node;
  }

  private parseClass(flags: Flags): CharSet {
    this.pos++;

    let negate = false;
    if (this.is('^')) {
      this.pos++;
      negate = true;
    }

    const ranges: Ranges = [];
    let first = true;
    while (true) {
      if (this.pos >= this.src.length) {
        throw this.error('missing closing ]');
      }
      if (this.is(']') && !first) {
        this.pos++;
        break;
      }
      first = false;

      if (this.is('[') && this.is(':', 1)) {
        const named = this.tryParseNamedClass();
        if (named) {
          ranges.push(...named);
          continue;
        }
      }

      if (this.is('\\')) {
        const perl = this.tryParsePerlClass();
        if (perl) {
          ranges.push(...perl);
          continue;
        }
      }

      const lo = this.parseClassChar();
      let hi = lo;
      if (this.is('-') && this.peek(1) !== undefined && !this.is(']', 1)) {
        this.pos++;
        hi = this.parseClassChar();
        if (hi < lo) {
          throw this.error('invalid character class range');
        }
      }
      ranges.push(lo, hi);
    }

    return { ranges: normalizeRanges(ranges), negate, fold: flags.i };
  }

  /** [:name:] or [:^name:]; anything without a closing ":]" is not a named class. */
  private tryParseNamedClass(): Ranges | undefined {
    let end = -1;
    for (let i = this.pos + 2; i + 1 < this.src.length; i++) {
      if (this.src[i] === 0x3a && this.src[i + 1] === 0x5d) {
        end = i;
        break;
      }
    }
    if (end < 0) {
      return undefined;
    }

    let name = String.fromCodePoint(...this.src.slice(this.pos + 2, end));
    const negated = name.startsWith('^');
    if (negated) {
      name = name.slice(1);
    }
    const ranges = POSIX_CLASSES.get(name);
    if (!ranges) {
      throw this.error('invalid character class range');
    }

    this.pos = end + 2;
    return negated ? complementRanges(ranges) : ranges;
  }

  private tryParsePerlClass(): Ranges | undefined {
    const c = this.peek(1);
    if (c === undefined) {
      return undefined;
    }
    const name = String.fromCodePoint(c);
    if (name === 'p' || name === 'P') {
      throw this.error('Unicode character classes are not supported');
    }
    const lower = name.toLowerCase();
    const ranges = PERL_CLASSES.get(lower);
    if (!ranges) {
      return undefined;
    }
    this.pos += 2;
    return name === lower ? ranges : complementRanges(ranges);
  }

  private parseClassChar(): number {
    if (this.is('\\')) {
      return this.parseEscapeChar();
    }
    return this.src[this.pos++];
  }

  private parseEscapeAtom(items: Node[], flags: Flags): void {
    const c = this.peek(1);
    if (c === undefined) {
      throw this.error('trailing backslash at end of expression');
    }

    const perl = this.tryParsePerlClass();
    if (perl) {
      items.push({ type: 'char', set: { ranges: perl, negate: false, fold: false } });
      return;
    }

    const name = String.fromCodePoint(c);
    const assertion = ESCAPED_ASSERTIONS.get(name);
    if (assertion) {
      this.pos += 2;
      items.push({ type: 'assert', kind: assertion });
      return;
    }

    if (name === 'Q') {
      this.pos += 2;
      while (this.pos < this.src.length && !(this.is('\\') && this.is('E', 1))) {
        items.push(literal(this.src[this.pos++], flags));
      }
      if (this.pos < this.src.length) {
        this.pos += 2;
      }
      return;
    }

    items.push(literal(this.parseEscapeChar(), flags));
  }

  /** Parses an escape that stands for a single character, starting at the backslash. */
  private parseEscapeChar(): number {
    this.pos++;
    const c = this.src[this.pos++];
    if (c === undefined) {
      throw this.error('trailing backslash at end of expression');
    }

    // \1 to \7 on their own would be backreferences, which RE2 does not have.
    if (c >= 0x31 && c <= 0x37 && !isOctalDigit(this.peek())) {
      throw this.error('invalid escape sequence');
    }
    if (c >= 0x30 && c <= 0x37) {
      let value = c - 0x30;
      for (let i = 0; i < 2 && isOctalDigit(this.peek()); i++) {
        value = value * 8 + (this.src[this.pos++] - 0x30);
      }
      return value;
    }

    switch (String.fromCodePoint(c)) {
      case 'x':
        return this.parseHexEscape();
      case 'a':
        return 0x07;
      case 'f':
        return 0x0c;
      case 'n':
        return 0x0a;
      case 'r':
        return 0x0d;
      case 't':
        return 0x09;
      case 'v':
        return 0x0b;
    }

    if (c < 0x80 && !isAsciiAlnum(c)) {
      return c;
    }
    throw this.error('invalid escape sequence');
  }

  private parseHexEscape(): number {
    if (this.is('{')) {
      this.pos++;
      let value = 0;
      let digits = 0;
      while (hexValue(this.peek()) >= 0) {
        value = value * 16 + hexValue(this.src[this.pos++]);
        digits++;
        if (value > MAX_CODE_POINT) {
          throw this.error('invalid escape sequence');
        }
      }
      if (digits === 0 || !this.is('}')) {
        throw this.error('invalid escape sequence');
      }
      this.pos++;
      return value;
    }

    const hi = hexValue(this.peek());
    const lo = hexValue(this.peek(1));
    if (hi < 0 || lo < 0) {
      throw this.error('invalid escape sequence');
    }
    this.pos += 2;
    return hi * 16 + lo;
  }
}

/**
 * Repeats that cannot add instructions are folded away here, so that the compiler never spends
 * time expanding something like ((?:){1000}){1000} that produces nothing.
 */
function makeRepeat(sub: Node, min: number, max: number): Node {
  if (sub.type === 'empty' || max === 0) {
    return EMPTY;
  }
  if (min === 1 && max === 1) {
    return sub;
  }
  return { type: 'repeat', min, max, sub };
}

function charSetKey(set: CharSet): string {
  return `${set.negate ? '^' : ''}${set.fold ? 'i' : ''}${set.ranges.join(',')}`;
}

function splitLeadingChar(node: Node): { head: Extract<Node, { type: 'char' }>; rest: Node } | undefined {
  if (node.type === 'char') {
    return { head: node, rest: EMPTY };
  }
  if (node.type === 'concat' && node.items[0].type === 'char') {
    const rest = node.items.slice(1);
    return { head: node.items[0], rest: rest.length === 1 ? rest[0] : { type: 'concat', items: rest } };
  }
  return undefined;
}

/**
 * Turns "ab|ac|d" into "a(?:b|c)|d".
 *
 * Without this, a long list of alternatives such as "service-1|service-2|…" puts a thread on
 * every branch at every position, which is slow and eats into the step budget. Only whether the
 * alternation matches is ever asked, not which branch matched, so branches can be regrouped freely.
 */
function factorAlternation(items: Node[], depth: number): Node[] {
  const flattened = items.flatMap((item) => (item.type === 'alt' ? item.items : [item]));
  const groups = new Map<string, { head: Extract<Node, { type: 'char' }>; rests: Node[] }>();
  const branches: Node[] = [];

  for (const item of flattened) {
    const split = splitLeadingChar(item);
    if (!split) {
      branches.push(item);
      continue;
    }
    const key = charSetKey(split.head.set);
    const group = groups.get(key);
    if (group) {
      group.rests.push(split.rest);
    } else {
      groups.set(key, { head: split.head, rests: [split.rest] });
    }
  }

  for (const { head, rests } of groups.values()) {
    const rest: Node = rests.length === 1 ? rests[0] : { type: 'alt', items: rests, factorDepth: depth + 1 };
    branches.push(rest.type === 'empty' ? head : { type: 'concat', items: [head, rest] });
  }

  return branches;
}

// ---------------------------------------------------------------------------------------------
// Compiler and NFA simulation
// ---------------------------------------------------------------------------------------------

const OP_CHAR = 0;
const OP_SPLIT = 1;
const OP_ASSERT = 2;
const OP_MATCH = 3;

type Inst =
  | { op: typeof OP_CHAR; set: CharSet; next: number }
  | { op: typeof OP_SPLIT; next: number; alt: number }
  | { op: typeof OP_ASSERT; kind: AssertKind; next: number }
  | { op: typeof OP_MATCH };

function inRanges(ranges: Ranges, cp: number): boolean {
  for (let i = 0; i < ranges.length; i += 2) {
    if (cp < ranges[i]) {
      return false;
    }
    if (cp <= ranges[i + 1]) {
      return true;
    }
  }
  return false;
}

function isWordChar(cp: number): boolean {
  return cp >= 0 && (isAsciiAlnum(cp) || cp === 0x5f);
}

class Program implements CompiledRegex {
  private readonly insts: Inst[] = [];
  private readonly start: number;
  private readonly hasFold: boolean;
  // A program that starts with \A (or ^ outside multi-line mode) can only match from position 0.
  private readonly anchoredStart: boolean;

  // Reused across calls; a test never runs re-entrantly.
  private current: Int32Array;
  private next: Int32Array;
  private readonly stack: Int32Array;
  private readonly mark: Uint32Array;
  private generation = 0;

  constructor(
    ast: Node,
    private readonly pattern: string
  ) {
    const match = this.emit({ op: OP_MATCH });
    this.start = this.compile(ast, match);
    this.hasFold = this.insts.some((inst) => inst.op === OP_CHAR && inst.set.fold);
    const first = this.insts[this.start];
    this.anchoredStart = first.op === OP_ASSERT && first.kind === 'beginText';

    const size = this.insts.length;
    this.current = new Int32Array(size);
    this.next = new Int32Array(size);
    this.stack = new Int32Array(size);
    this.mark = new Uint32Array(size);
  }

  private emit(inst: Inst): number {
    if (this.insts.length >= MAX_PROGRAM_SIZE) {
      throw new RegexSyntaxError('expression too large', this.pattern);
    }
    this.insts.push(inst);
    return this.insts.length - 1;
  }

  /** Emits code for `node` that continues at `next`, and returns where it starts. */
  private compile(node: Node, next: number): number {
    switch (node.type) {
      case 'empty':
        return next;
      case 'char':
        return this.emit({ op: OP_CHAR, set: node.set, next });
      case 'assert':
        return this.emit({ op: OP_ASSERT, kind: node.kind, next });
      case 'concat': {
        let start = next;
        for (let i = node.items.length - 1; i >= 0; i--) {
          start = this.compile(node.items[i], start);
        }
        return start;
      }
      case 'alt': {
        const depth = node.factorDepth ?? 0;
        const branches = depth < MAX_FACTOR_DEPTH ? factorAlternation(node.items, depth) : node.items;
        let start = this.compile(branches[branches.length - 1], next);
        for (let i = branches.length - 2; i >= 0; i--) {
          start = this.emit({ op: OP_SPLIT, next: this.compile(branches[i], next), alt: start });
        }
        return start;
      }
      case 'repeat': {
        let start = next;
        if (node.max === -1) {
          const loop = this.emit({ op: OP_SPLIT, next: -1, alt: next });
          const body = this.compile(node.sub, loop);
          this.insts[loop] = { op: OP_SPLIT, next: body, alt: next };
          start = loop;
        } else {
          for (let i = node.min; i < node.max; i++) {
            start = this.emit({ op: OP_SPLIT, next: this.compile(node.sub, start), alt: start });
          }
        }
        for (let i = 0; i < node.min; i++) {
          start = this.compile(node.sub, start);
        }
        return start;
      }
    }
  }

  test(input: string): boolean {
    let steps = 0;
    let currentCount = 0;

    // Previous and next code points around the position the closure is computed at; -1 at the edges.
    let before = -1;
    let after = input.length > 0 ? input.codePointAt(0)! : -1;

    const addClosure = (pc: number, list: Int32Array, count: number): number => {
      const { insts, stack, mark, generation } = this;
      if (mark[pc] === generation) {
        return count;
      }
      mark[pc] = generation;
      let top = 0;
      stack[top++] = pc;

      while (top > 0) {
        const inst = insts[stack[--top]];
        if (++steps > MAX_STEPS) {
          throw new RegexBudgetError();
        }

        let follow = -1;
        switch (inst.op) {
          case OP_MATCH:
            return -1;
          case OP_CHAR:
            list[count++] = stack[top];
            continue;
          case OP_SPLIT:
            if (mark[inst.alt] !== generation) {
              mark[inst.alt] = generation;
              stack[top++] = inst.alt;
            }
            follow = inst.next;
            break;
          case OP_ASSERT:
            if (!assertionHolds(inst.kind, before, after)) {
              continue;
            }
            follow = inst.next;
            break;
        }
        if (mark[follow] !== generation) {
          mark[follow] = generation;
          stack[top++] = follow;
        }
      }
      return count;
    };

    this.advanceGeneration();
    currentCount = addClosure(this.start, this.current, 0);

    let pos = 0;
    while (currentCount >= 0) {
      if (pos >= input.length || (currentCount === 0 && this.anchoredStart)) {
        return false;
      }

      const cp = after;
      const width = cp > 0xffff ? 2 : 1;
      const lower = this.hasFold ? simpleLower(cp) : cp;
      const upper = this.hasFold ? simpleUpper(cp) : cp;

      before = cp;
      after = pos + width < input.length ? input.codePointAt(pos + width)! : -1;

      this.advanceGeneration();
      let nextCount = 0;
      for (let i = 0; i < currentCount && nextCount >= 0; i++) {
        const inst = this.insts[this.current[i]];
        if (inst.op === OP_CHAR && charSetMatches(inst.set, cp, lower, upper)) {
          nextCount = addClosure(inst.next, this.next, nextCount);
        }
      }
      // The search is unanchored, like RegExp.prototype.test: a match may start at any position.
      if (nextCount >= 0 && !this.anchoredStart) {
        nextCount = addClosure(this.start, this.next, nextCount);
      }

      [this.current, this.next] = [this.next, this.current];
      currentCount = nextCount;
      pos += width;
    }

    return true;
  }

  private advanceGeneration(): void {
    if (this.generation === 0xffffffff) {
      this.mark.fill(0);
      this.generation = 0;
    }
    this.generation++;
  }
}

function charSetMatches(set: CharSet, cp: number, lower: number, upper: number): boolean {
  const hit = inRanges(set.ranges, cp) || (set.fold && (inRanges(set.ranges, lower) || inRanges(set.ranges, upper)));
  return set.negate ? !hit : hit;
}

function assertionHolds(kind: AssertKind, before: number, after: number): boolean {
  switch (kind) {
    case 'beginText':
      return before === -1;
    case 'endText':
      return after === -1;
    case 'beginLine':
      return before === -1 || before === NEWLINE;
    case 'endLine':
      return after === -1 || after === NEWLINE;
    case 'wordBoundary':
      return isWordChar(before) !== isWordChar(after);
    case 'notWordBoundary':
      return isWordChar(before) === isWordChar(after);
  }
}
