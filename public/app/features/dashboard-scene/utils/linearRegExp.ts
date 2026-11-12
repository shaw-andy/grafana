/**
 * A drop-in for `RegExp#test` on patterns that come from saved dashboards and run in every viewer's browser.
 *
 * The pattern is compiled to a Thompson NFA and simulated breadth-first, so a test costs at most
 * input length × program size steps whatever the pattern looks like. Native `RegExp` backtracks and can take
 * exponential time on patterns such as `(a+)+$`. Backreferences and lookaround have no linear-time
 * equivalent and are rejected, as are patterns whose program would exceed `MAX_PROGRAM_SIZE`.
 */

const MAX_PROGRAM_SIZE = 10_000;
const MAX_COMPILE_STEPS = 100_000;

export class UnsupportedRegExpError extends Error {
  public constructor(reason: string) {
    super(`Unsupported regular expression: ${reason}`);
    this.name = 'UnsupportedRegExpError';
  }
}

type CharPredicate = (code: number) => boolean;

type AssertionKind = 'start' | 'end' | 'wordBoundary' | 'notWordBoundary';

type Node =
  | { type: 'char'; test: CharPredicate }
  | { type: 'assert'; kind: AssertionKind }
  | { type: 'concat'; items: Node[] }
  | { type: 'alt'; items: Node[] }
  | { type: 'repeat'; node: Node; min: number; max: number };

type Instruction =
  | { op: 'char'; test: CharPredicate }
  | { op: 'split'; a: number; b: number }
  | { op: 'jmp'; to: number }
  | { op: 'assert'; kind: AssertionKind }
  | { op: 'match' };

export class LinearRegExp {
  private readonly program: Instruction[];
  private readonly multiline: boolean;

  /**
   * @throws SyntaxError when the browser would reject the pattern, UnsupportedRegExpError when it uses a
   * construct that cannot be matched in linear time.
   */
  public constructor(pattern: string, flags = '') {
    // Constructing a native RegExp only parses it, so this is a safe way to reject exactly what browsers reject.
    new RegExp(pattern, flags);

    let ignoreCase = false;
    let multiline = false;
    let dotAll = false;
    for (const flag of flags) {
      switch (flag) {
        case 'i':
          ignoreCase = true;
          break;
        case 'm':
          multiline = true;
          break;
        case 's':
          dotAll = true;
          break;
        case 'g':
          // test() here keeps no lastIndex state, so the global flag changes nothing.
          break;
        default:
          throw new UnsupportedRegExpError(`flag "${flag}"`);
      }
    }

    this.multiline = multiline;
    const ast = new Parser(pattern, ignoreCase, dotAll).parse();
    this.program = new Compiler().compile(ast);
  }

  public test(input: string): boolean {
    const program = this.program;
    const marks = new Int32Array(program.length).fill(-1);
    const stack: number[] = [];
    let current: number[] = [];
    let next: number[] = [];

    // Adds every instruction reachable from `startPc` without consuming input, at most once per position.
    const addThread = (list: number[], startPc: number, pos: number): boolean => {
      stack.push(startPc);
      while (stack.length > 0) {
        const pc = stack.pop()!;
        if (marks[pc] === pos) {
          continue;
        }
        marks[pc] = pos;
        const inst = program[pc];
        switch (inst.op) {
          case 'match':
            stack.length = 0;
            return true;
          case 'jmp':
            stack.push(inst.to);
            break;
          case 'split':
            stack.push(inst.b, inst.a);
            break;
          case 'assert':
            if (this.assertionHolds(inst.kind, input, pos)) {
              stack.push(pc + 1);
            }
            break;
          case 'char':
            list.push(pc);
            break;
        }
      }
      return false;
    };

    for (let pos = 0; ; pos++) {
      // Starting a thread at every position makes the search unanchored, like RegExp#test.
      if (addThread(current, 0, pos)) {
        return true;
      }
      if (pos === input.length) {
        return false;
      }

      const code = input.charCodeAt(pos);
      next.length = 0;
      for (const pc of current) {
        const inst = program[pc];
        if (inst.op === 'char' && inst.test(code) && addThread(next, pc + 1, pos + 1)) {
          return true;
        }
      }
      [current, next] = [next, current];
    }
  }

  private assertionHolds(kind: AssertionKind, input: string, pos: number): boolean {
    switch (kind) {
      case 'start':
        return pos === 0 || (this.multiline && isLineTerminator(input.charCodeAt(pos - 1)));
      case 'end':
        return pos === input.length || (this.multiline && isLineTerminator(input.charCodeAt(pos)));
      case 'wordBoundary':
        return isWordAt(input, pos - 1) !== isWordAt(input, pos);
      case 'notWordBoundary':
        return isWordAt(input, pos - 1) === isWordAt(input, pos);
    }
  }
}

class Parser {
  private pos = 0;

  public constructor(
    private readonly src: string,
    private readonly ignoreCase: boolean,
    private readonly dotAll: boolean
  ) {}

  public parse(): Node {
    const node = this.parseAlternation();
    if (this.pos < this.src.length) {
      throw new UnsupportedRegExpError(`unexpected "${this.src[this.pos]}"`);
    }
    return node;
  }

  private peek(offset = 0): string | undefined {
    return this.src[this.pos + offset];
  }

  private parseAlternation(): Node {
    const items = [this.parseSequence()];
    while (this.peek() === '|') {
      this.pos++;
      items.push(this.parseSequence());
    }
    return items.length === 1 ? items[0] : { type: 'alt', items };
  }

  private parseSequence(): Node {
    const items: Node[] = [];
    while (this.pos < this.src.length && this.peek() !== '|' && this.peek() !== ')') {
      items.push(this.parseQuantified());
    }
    return items.length === 1 ? items[0] : { type: 'concat', items };
  }

  private parseQuantified(): Node {
    const atom = this.parseAtom();
    const quantifier = this.parseQuantifier();
    if (!quantifier) {
      return atom;
    }
    // Lazy and greedy quantifiers accept the same inputs, which is all test() reports.
    if (this.peek() === '?') {
      this.pos++;
    }
    return { type: 'repeat', node: atom, ...quantifier };
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
        // Outside unicode mode a brace that does not form a valid quantifier is a literal character.
        const braced = /^\{(\d+)(?:(,)(\d*))?\}/.exec(this.src.slice(this.pos));
        if (!braced) {
          return undefined;
        }
        this.pos += braced[0].length;
        const min = Number(braced[1]);
        const max = braced[2] === undefined ? min : braced[3] === '' ? Infinity : Number(braced[3]);
        return { min, max };
      }
      default:
        return undefined;
    }
  }

  private parseAtom(): Node {
    const ch = this.src[this.pos++];
    switch (ch) {
      case '.':
        return { type: 'char', test: this.dotAll ? () => true : (code) => !isLineTerminator(code) };
      case '^':
        return { type: 'assert', kind: 'start' };
      case '$':
        return { type: 'assert', kind: 'end' };
      case '(':
        return this.parseGroup();
      case '[':
        return this.parseClass();
      case '\\':
        return this.parseEscape();
      case '*':
      case '+':
      case '?':
        throw new UnsupportedRegExpError('nothing to repeat');
      default:
        return this.literal(ch.charCodeAt(0));
    }
  }

  private parseGroup(): Node {
    if (this.peek() === '?') {
      const kind = this.peek(1);
      const afterKind = this.peek(2);
      if (kind === ':') {
        this.pos += 2;
      } else if (kind === '<' && afterKind !== '=' && afterKind !== '!') {
        const close = this.src.indexOf('>', this.pos);
        if (close === -1) {
          throw new UnsupportedRegExpError('unterminated group name');
        }
        this.pos = close + 1;
      } else {
        throw new UnsupportedRegExpError('lookaround and inline modifier groups');
      }
    }

    const inner = this.parseAlternation();
    if (this.peek() !== ')') {
      throw new UnsupportedRegExpError('unterminated group');
    }
    this.pos++;
    return inner;
  }

  private parseEscape(): Node {
    const ch = this.src[this.pos++];
    if (ch === undefined) {
      throw new UnsupportedRegExpError('trailing backslash');
    }
    switch (ch) {
      case 'b':
        return { type: 'assert', kind: 'wordBoundary' };
      case 'B':
        return { type: 'assert', kind: 'notWordBoundary' };
    }
    const classEscape = characterClassEscape(ch);
    if (classEscape) {
      return { type: 'char', test: classEscape };
    }
    return this.literal(this.parseCharacterEscape(ch, false));
  }

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
      case '0':
        if (isDecimalDigit(this.peek())) {
          throw new UnsupportedRegExpError('legacy octal escapes');
        }
        return 0;
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
      case 'k':
        throw new UnsupportedRegExpError('backreferences');
      case 'c': {
        const letter = this.peek();
        if (letter !== undefined && (/[a-zA-Z]/.test(letter) || (inClass && /[0-9_]/.test(letter)))) {
          this.pos++;
          return letter.charCodeAt(0) % 32;
        }
        // A "\c" that is not a control escape is a literal backslash, and the "c" is read as the next character.
        this.pos--;
        return 92;
      }
      case 'x': {
        const hex = this.src.slice(this.pos, this.pos + 2);
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          this.pos += 2;
          return parseInt(hex, 16);
        }
        return ch.charCodeAt(0);
      }
      case 'u': {
        const hex = this.src.slice(this.pos, this.pos + 4);
        if (/^[0-9a-fA-F]{4}$/.test(hex)) {
          this.pos += 4;
          return parseInt(hex, 16);
        }
        return ch.charCodeAt(0);
      }
      default:
        return ch.charCodeAt(0);
    }
  }

  private parseClass(): Node {
    let negate = false;
    if (this.peek() === '^') {
      negate = true;
      this.pos++;
    }

    const ranges: Array<[number, number]> = [];
    const predicates: CharPredicate[] = [];
    const add = (member: number | CharPredicate) => {
      if (typeof member === 'number') {
        ranges.push([member, member]);
      } else {
        predicates.push(member);
      }
    };

    while (this.peek() !== ']') {
      if (this.pos >= this.src.length) {
        throw new UnsupportedRegExpError('unterminated character class');
      }
      const from = this.parseClassAtom();
      if (this.peek() === '-' && this.peek(1) !== undefined && this.peek(1) !== ']') {
        this.pos++;
        const to = this.parseClassAtom();
        if (typeof from === 'number' && typeof to === 'number') {
          ranges.push([from, to]);
        } else {
          // Outside unicode mode a range with a class escape at either end is the union of its parts and "-".
          add(from);
          add(45);
          add(to);
        }
      } else {
        add(from);
      }
    }
    this.pos++;

    const inSet: CharPredicate = (code) =>
      ranges.some(([lo, hi]) => code >= lo && code <= hi) || predicates.some((predicate) => predicate(code));
    const matches: CharPredicate = this.ignoreCase ? (code) => caseVariants(code).some(inSet) : inSet;
    return { type: 'char', test: negate ? (code) => !matches(code) : matches };
  }

  private parseClassAtom(): number | CharPredicate {
    const ch = this.src[this.pos++];
    if (ch !== '\\') {
      return ch.charCodeAt(0);
    }
    const escaped = this.src[this.pos++];
    if (escaped === undefined) {
      throw new UnsupportedRegExpError('trailing backslash');
    }
    if (escaped === 'b') {
      return 8;
    }
    return characterClassEscape(escaped) ?? this.parseCharacterEscape(escaped, true);
  }

  private literal(code: number): Node {
    if (!this.ignoreCase) {
      return { type: 'char', test: (c) => c === code };
    }
    const canonical = canonicalize(code);
    return { type: 'char', test: (c) => canonicalize(c) === canonical };
  }
}

class Compiler {
  private readonly program: Instruction[] = [];
  private steps = 0;

  public compile(node: Node): Instruction[] {
    this.emitNode(node);
    this.emit({ op: 'match' });
    return this.program;
  }

  private emit(inst: Instruction): number {
    if (this.program.length >= MAX_PROGRAM_SIZE) {
      throw new UnsupportedRegExpError('pattern is too large');
    }
    this.program.push(inst);
    return this.program.length - 1;
  }

  private emitNode(node: Node): void {
    if (++this.steps > MAX_COMPILE_STEPS) {
      throw new UnsupportedRegExpError('pattern is too large');
    }

    switch (node.type) {
      case 'char':
        this.emit({ op: 'char', test: node.test });
        return;
      case 'assert':
        this.emit({ op: 'assert', kind: node.kind });
        return;
      case 'concat':
        node.items.forEach((item) => this.emitNode(item));
        return;
      case 'alt': {
        const jumps: number[] = [];
        node.items.forEach((item, index) => {
          if (index === node.items.length - 1) {
            this.emitNode(item);
            return;
          }
          const split = this.emit({ op: 'split', a: this.program.length + 1, b: -1 });
          this.emitNode(item);
          jumps.push(this.emit({ op: 'jmp', to: -1 }));
          this.patchSplit(split, this.program.length);
        });
        jumps.forEach((jump) => this.patchJump(jump, this.program.length));
        return;
      }
      case 'repeat':
        this.emitRepeat(node.node, node.min, node.max);
        return;
    }
  }

  private emitRepeat(body: Node, min: number, max: number): void {
    if (min > MAX_PROGRAM_SIZE || (max !== Infinity && max > MAX_PROGRAM_SIZE)) {
      throw new UnsupportedRegExpError('pattern is too large');
    }

    for (let i = 0; i < min; i++) {
      this.emitNode(body);
    }

    if (max === Infinity) {
      const loop = this.emit({ op: 'split', a: this.program.length + 1, b: -1 });
      this.emitNode(body);
      this.emit({ op: 'jmp', to: loop });
      this.patchSplit(loop, this.program.length);
      return;
    }

    const optional: number[] = [];
    for (let i = min; i < max; i++) {
      optional.push(this.emit({ op: 'split', a: this.program.length + 1, b: -1 }));
      this.emitNode(body);
    }
    optional.forEach((split) => this.patchSplit(split, this.program.length));
  }

  private patchSplit(pc: number, target: number) {
    const inst = this.program[pc];
    if (inst.op === 'split') {
      inst.b = target;
    }
  }

  private patchJump(pc: number, target: number) {
    const inst = this.program[pc];
    if (inst.op === 'jmp') {
      inst.to = target;
    }
  }
}

function isLineTerminator(code: number): boolean {
  return code === 10 || code === 13 || code === 0x2028 || code === 0x2029;
}

function isDecimalDigit(ch: string | undefined): boolean {
  return ch !== undefined && ch >= '0' && ch <= '9';
}

function isDigitCode(code: number): boolean {
  return code >= 48 && code <= 57;
}

function isWordCode(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || isDigitCode(code) || code === 95;
}

function isWhitespaceCode(code: number): boolean {
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

function isWordAt(input: string, index: number): boolean {
  return index >= 0 && index < input.length && isWordCode(input.charCodeAt(index));
}

function characterClassEscape(ch: string): CharPredicate | undefined {
  switch (ch) {
    case 'd':
      return isDigitCode;
    case 'D':
      return (code) => !isDigitCode(code);
    case 'w':
      return isWordCode;
    case 'W':
      return (code) => !isWordCode(code);
    case 's':
      return isWhitespaceCode;
    case 'S':
      return (code) => !isWhitespaceCode(code);
    default:
      return undefined;
  }
}

// Case folding as RegExp applies it to the `i` flag outside unicode mode.
function canonicalize(code: number): number {
  const upper = String.fromCharCode(code).toUpperCase();
  if (upper.length !== 1) {
    return code;
  }
  const upperCode = upper.charCodeAt(0);
  return code >= 128 && upperCode < 128 ? code : upperCode;
}

function caseVariants(code: number): number[] {
  const canonical = canonicalize(code);
  const lower = String.fromCharCode(canonical).toLowerCase();
  return lower.length === 1 ? [code, canonical, lower.charCodeAt(0)] : [code, canonical];
}
