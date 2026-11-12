import { type AST, RegExpParser } from '@eslint-community/regexpp';

/**
 * A backtracking matcher for JavaScript regular expressions (without the `u` and `v` flags) that gives up after a fixed
 * number of steps. It follows the matching semantics of the ECMAScript specification so that expressions written for
 * `RegExp` keep their meaning, while a pathological expression costs at most the step budget instead of blocking the
 * thread for an unbounded time.
 */

export class RegExpBudgetExceededError extends Error {}

export interface BoundedRegExpMatch {
  start: number;
  end: number;
  value: string;
  captures: Array<string | undefined>;
  groups?: Record<string, string | undefined>;
}

interface Flags {
  ignoreCase: boolean;
  multiline: boolean;
  dotAll: boolean;
}

type CharTest = (code: number) => boolean;

const OP_CHAR = 0;
const OP_SET = 1;
const OP_SPLIT = 2;
const OP_JUMP = 3;
const OP_SAVE = 4;
const OP_RESET = 5;
const OP_MARK = 6;
const OP_CHECK = 7;
const OP_START = 8;
const OP_END = 9;
const OP_WORD_BOUNDARY = 10;
const OP_BACKREFERENCE = 11;
const OP_LOOKAROUND = 12;
const OP_SUCCEED = 13;

interface Instruction {
  op: number;
  a: number;
  b: number;
  backward: boolean;
  flag: boolean;
  test?: CharTest;
  groups?: number[];
}

// Building a match result costs about as much as this many matching steps.
const MATCH_COST = 20;

const BACKTRACK_BRANCH = 0;
const BACKTRACK_CAPTURE = 1;
const BACKTRACK_REGISTER = 2;

const isLineTerminator = (c: number) => c === 0x0a || c === 0x0d || c === 0x2028 || c === 0x2029;
const isDigit = (c: number) => c >= 0x30 && c <= 0x39;
const isWordChar = (c: number) =>
  (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39) || c === 0x5f;
const isSpace = (c: number) =>
  (c >= 0x09 && c <= 0x0d) ||
  c === 0x20 ||
  c === 0xa0 ||
  c === 0x1680 ||
  (c >= 0x2000 && c <= 0x200a) ||
  c === 0x2028 ||
  c === 0x2029 ||
  c === 0x202f ||
  c === 0x205f ||
  c === 0x3000 ||
  c === 0xfeff;

let canonicalTable: Uint16Array | undefined;
let caseEquivalents: Map<number, number[]> | undefined;

function buildCaseTables() {
  const table = new Uint16Array(0x10000);
  const byCanonical = new Map<number, number[]>();
  for (let c = 0; c < 0x10000; c++) {
    const upper = String.fromCharCode(c).toUpperCase();
    let canonical = c;
    if (upper.length === 1) {
      const u = upper.charCodeAt(0);
      if (!(c >= 128 && u < 128)) {
        canonical = u;
      }
    }
    table[c] = canonical;
    const members = byCanonical.get(canonical);
    if (members) {
      members.push(c);
    } else {
      byCanonical.set(canonical, [c]);
    }
  }

  const equivalents = new Map<number, number[]>();
  for (const members of byCanonical.values()) {
    if (members.length > 1) {
      for (const member of members) {
        equivalents.set(member, members);
      }
    }
  }
  canonicalTable = table;
  caseEquivalents = equivalents;
}

/** Canonicalize from the specification for case-insensitive matching without the `u` or `v` flag. */
function canonicalize(c: number): number {
  if (!canonicalTable) {
    buildCaseTables();
  }
  return canonicalTable![c];
}

function equivalentsOf(c: number): number[] | undefined {
  if (!caseEquivalents) {
    buildCaseTables();
  }
  return caseEquivalents!.get(c);
}

function setTest(members: CharTest, negate: boolean, ignoreCase: boolean): CharTest {
  const found: CharTest = ignoreCase ? (c) => members(c) || (equivalentsOf(c)?.some(members) ?? false) : members;
  return negate ? (c) => !found(c) : found;
}

function escapeSetMembers(node: AST.EscapeCharacterSet): CharTest {
  const base = node.kind === 'digit' ? isDigit : node.kind === 'word' ? isWordChar : isSpace;
  return node.negate ? (c) => !base(c) : base;
}

function classMembers(node: AST.CharacterClass): CharTest {
  const tests: CharTest[] = node.elements.map((element) => {
    switch (element.type) {
      case 'Character':
        return (c) => c === element.value;
      case 'CharacterClassRange': {
        const min = element.min.value;
        const max = element.max.value;
        return (c) => c >= min && c <= max;
      }
      case 'CharacterSet':
        if (element.kind === 'property') {
          throw new SyntaxError('Unicode property escapes are not supported');
        }
        return escapeSetMembers(element);
      default:
        throw new SyntaxError(`Unsupported character class element ${element.type}`);
    }
  });
  return (c) => tests.some((test) => test(c));
}

class Compiler {
  readonly program: Instruction[] = [];
  readonly groupIndexes = new Map<AST.CapturingGroup, number>();
  readonly groupNames = new Map<string, number[]>();
  registerCount = 0;

  constructor(
    pattern: AST.Pattern,
    private readonly maxInstructions: number
  ) {
    this.numberGroups(pattern);
  }

  private numberGroups(node: AST.Node) {
    if (node.type === 'CapturingGroup') {
      const index = this.groupIndexes.size + 1;
      this.groupIndexes.set(node, index);
      if (node.name) {
        this.groupNames.set(node.name, [...(this.groupNames.get(node.name) ?? []), index]);
      }
    }
    for (const child of childrenOf(node)) {
      this.numberGroups(child);
    }
  }

  private groupRange(node: AST.Node): [number, number] | undefined {
    let first = Infinity;
    let last = -Infinity;
    const visit = (n: AST.Node) => {
      if (n.type === 'CapturingGroup') {
        const index = this.groupIndexes.get(n)!;
        first = Math.min(first, index);
        last = Math.max(last, index);
      }
      childrenOf(n).forEach(visit);
    };
    visit(node);
    return first === Infinity ? undefined : [first, last];
  }

  private emit(op: number, fields: Partial<Instruction> = {}): Instruction {
    if (this.program.length >= this.maxInstructions) {
      throw new SyntaxError('Regular expression is too large');
    }
    const instruction: Instruction = { op, a: -1, b: -1, backward: false, flag: false, ...fields };
    this.program.push(instruction);
    return instruction;
  }

  compilePattern(pattern: AST.Pattern) {
    this.alternatives(pattern.alternatives, { ignoreCase: true, multiline: false, dotAll: false }, false);
    this.emit(OP_SUCCEED);
  }

  private alternatives(alternatives: AST.Alternative[], flags: Flags, backward: boolean) {
    const exits: Instruction[] = [];
    alternatives.forEach((alternative, i) => {
      if (i === alternatives.length - 1) {
        this.alternative(alternative, flags, backward);
        return;
      }
      const split = this.emit(OP_SPLIT);
      split.a = this.program.length;
      this.alternative(alternative, flags, backward);
      exits.push(this.emit(OP_JUMP));
      split.b = this.program.length;
    });
    for (const exit of exits) {
      exit.a = this.program.length;
    }
  }

  private alternative(alternative: AST.Alternative, flags: Flags, backward: boolean) {
    const elements = backward ? [...alternative.elements].reverse() : alternative.elements;
    for (const element of elements) {
      this.element(element, flags, backward);
    }
  }

  private element(node: AST.Element, flags: Flags, backward: boolean) {
    switch (node.type) {
      case 'Character': {
        const value = flags.ignoreCase ? canonicalize(node.value) : node.value;
        this.emit(OP_CHAR, { a: value, backward, flag: flags.ignoreCase });
        return;
      }
      case 'CharacterSet': {
        if (node.kind === 'property') {
          throw new SyntaxError('Unicode property escapes are not supported');
        }
        const test =
          node.kind === 'any'
            ? flags.dotAll
              ? () => true
              : (c: number) => !isLineTerminator(c)
            : setTest(escapeSetMembers(node), false, flags.ignoreCase);
        this.emit(OP_SET, { test, backward });
        return;
      }
      case 'CharacterClass':
        this.emit(OP_SET, { test: setTest(classMembers(node), node.negate, flags.ignoreCase), backward });
        return;
      case 'Group':
        this.alternatives(node.alternatives, applyModifiers(flags, node.modifiers), backward);
        return;
      case 'CapturingGroup': {
        const index = this.groupIndexes.get(node)!;
        this.emit(OP_SAVE, { a: backward ? index * 2 + 1 : index * 2 });
        this.alternatives(node.alternatives, flags, backward);
        this.emit(OP_SAVE, { a: backward ? index * 2 : index * 2 + 1 });
        return;
      }
      case 'Assertion':
        switch (node.kind) {
          case 'start':
            this.emit(OP_START, { flag: flags.multiline });
            return;
          case 'end':
            this.emit(OP_END, { flag: flags.multiline });
            return;
          case 'word':
            this.emit(OP_WORD_BOUNDARY, { flag: node.negate });
            return;
          default: {
            const lookaround = this.emit(OP_LOOKAROUND, { flag: node.negate });
            lookaround.a = this.program.length;
            this.alternatives(node.alternatives, flags, node.kind === 'lookbehind');
            this.emit(OP_SUCCEED);
            lookaround.b = this.program.length;
            return;
          }
        }
      case 'Backreference': {
        const targets = Array.isArray(node.resolved) ? node.resolved : [node.resolved];
        const groups = targets.map((group) => this.groupIndexes.get(group)!);
        this.emit(OP_BACKREFERENCE, { groups, backward, flag: flags.ignoreCase });
        return;
      }
      case 'Quantifier':
        this.quantifier(node, flags, backward);
        return;
      default:
        throw new SyntaxError(`Unsupported regular expression element ${node.type}`);
    }
  }

  private quantifier(node: AST.Quantifier, flags: Flags, backward: boolean) {
    const { min, max, greedy, element } = node;
    if (min > this.maxInstructions) {
      throw new SyntaxError('Regular expression is too large');
    }
    const groups = this.groupRange(element);

    // Iterations past the minimum fail when they match the empty string, as RepeatMatcher specifies.
    const iteration = (optional: boolean) => {
      const register = optional ? this.registerCount++ : -1;
      if (optional) {
        this.emit(OP_MARK, { a: register });
      }
      if (groups) {
        this.emit(OP_RESET, { a: groups[0], b: groups[1] });
      }
      this.element(element, flags, backward);
      if (optional) {
        this.emit(OP_CHECK, { a: register });
      }
    };

    for (let i = 0; i < min; i++) {
      iteration(false);
    }

    const splits: Array<[Instruction, number]> = [];
    const optionalIteration = () => {
      splits.push([this.emit(OP_SPLIT), this.program.length]);
      iteration(true);
    };
    if (max === Infinity) {
      const loopStart = this.program.length;
      optionalIteration();
      this.emit(OP_JUMP, { a: loopStart });
    } else {
      for (let i = min; i < max; i++) {
        optionalIteration();
      }
    }

    const exit = this.program.length;
    for (const [split, body] of splits) {
      split.a = greedy ? body : exit;
      split.b = greedy ? exit : body;
    }
  }
}

function applyModifiers(flags: Flags, modifiers: AST.Modifiers | null): Flags {
  if (!modifiers) {
    return flags;
  }
  const pick = (name: keyof Flags) => (modifiers.add[name] ? true : modifiers.remove?.[name] ? false : flags[name]);
  return { ignoreCase: pick('ignoreCase'), multiline: pick('multiline'), dotAll: pick('dotAll') };
}

function childrenOf(node: AST.Node): AST.Node[] {
  switch (node.type) {
    case 'Pattern':
    case 'Group':
    case 'CapturingGroup':
      return node.alternatives;
    case 'Assertion':
      return node.kind === 'lookahead' || node.kind === 'lookbehind' ? node.alternatives : [];
    case 'Alternative':
      return node.elements;
    case 'Quantifier':
      return [node.element];
    default:
      return [];
  }
}

export class BoundedRegExp {
  private constructor(
    private readonly program: Instruction[],
    private readonly groupCount: number,
    private readonly groupNames: Map<string, number[]>,
    private readonly registerCount: number
  ) {}

  /** Compiles a pattern as `new RegExp(source, 'gi')` would, or throws a SyntaxError. */
  static compile(source: string, maxInstructions: number): BoundedRegExp {
    const pattern = new RegExpParser({ ecmaVersion: 2025 }).parsePattern(source, 0, source.length, {
      unicode: false,
      unicodeSets: false,
    });
    const compiler = new Compiler(pattern, maxInstructions);
    compiler.compilePattern(pattern);
    return new BoundedRegExp(compiler.program, compiler.groupIndexes.size, compiler.groupNames, compiler.registerCount);
  }

  get hasCaptures(): boolean {
    return this.groupCount > 0;
  }

  get programSize(): number {
    return this.program.length;
  }

  /**
   * Returns the same matches as `input.matchAll(regexp)`, or throws RegExpBudgetExceededError once matching has taken
   * more than maxSteps steps.
   */
  matchAll(input: string, maxSteps: number): BoundedRegExpMatch[] {
    const execution = new Execution(this.program, input, this.groupCount, this.registerCount, maxSteps);
    const matches: BoundedRegExpMatch[] = [];
    let lastIndex = 0;

    while (lastIndex <= input.length) {
      let start = lastIndex;
      let end = -1;
      for (; start <= input.length; start++) {
        end = execution.matchAt(start);
        if (end >= 0) {
          break;
        }
      }
      if (end < 0) {
        break;
      }

      execution.spend(MATCH_COST + this.groupCount);
      matches.push(this.toMatch(execution.captures, input, start, end));
      lastIndex = end === start ? end + 1 : end;
    }

    return matches;
  }

  private toMatch(captures: Int32Array, input: string, start: number, end: number): BoundedRegExpMatch {
    const capture = (index: number) => {
      const from = captures[index * 2];
      const to = captures[index * 2 + 1];
      return from < 0 || to < 0 ? undefined : input.slice(from, to);
    };

    const match: BoundedRegExpMatch = {
      start,
      end,
      value: input.slice(start, end),
      captures: Array.from({ length: this.groupCount }, (_, i) => capture(i + 1)),
    };
    if (this.groupNames.size > 0) {
      match.groups = {};
      for (const [name, indexes] of this.groupNames) {
        match.groups[name] = indexes.map(capture).find((value) => value !== undefined);
      }
    }
    return match;
  }
}

class Execution {
  readonly captures: Int32Array;
  private readonly registers: Int32Array;
  private steps = 0;

  constructor(
    private readonly program: Instruction[],
    private readonly input: string,
    groupCount: number,
    registerCount: number,
    private readonly maxSteps: number
  ) {
    this.captures = new Int32Array((groupCount + 1) * 2);
    this.registers = new Int32Array(registerCount);
  }

  matchAt(start: number): number {
    this.captures.fill(-1);
    const end = this.run(0, start);
    if (end >= 0) {
      this.captures[0] = start;
      this.captures[1] = end;
    }
    return end;
  }

  spend(steps: number) {
    this.steps += steps;
    if (this.steps > this.maxSteps) {
      throw new RegExpBudgetExceededError('Regular expression exceeded its step budget');
    }
  }

  private run(startPc: number, startPos: number): number {
    const { program, input, captures, registers } = this;
    const length = input.length;
    const stack: number[] = [];
    let pc = startPc;
    let pos = startPos;

    for (;;) {
      this.spend(1);
      const instruction = program[pc];
      let matched = true;

      switch (instruction.op) {
        case OP_CHAR:
        case OP_SET: {
          const index = instruction.backward ? pos - 1 : pos;
          if (index < 0 || index >= length) {
            matched = false;
            break;
          }
          const c = input.charCodeAt(index);
          matched =
            instruction.op === OP_SET
              ? instruction.test!(c)
              : (instruction.flag ? canonicalize(c) : c) === instruction.a;
          if (matched) {
            pos = instruction.backward ? pos - 1 : pos + 1;
            pc++;
          }
          break;
        }
        case OP_SPLIT:
          stack.push(instruction.b, pos, BACKTRACK_BRANCH);
          pc = instruction.a;
          break;
        case OP_JUMP:
          pc = instruction.a;
          break;
        case OP_SAVE:
          stack.push(instruction.a, captures[instruction.a], BACKTRACK_CAPTURE);
          captures[instruction.a] = pos;
          pc++;
          break;
        case OP_RESET:
          this.spend(instruction.b - instruction.a);
          for (let slot = instruction.a * 2; slot <= instruction.b * 2 + 1; slot++) {
            if (captures[slot] !== -1) {
              stack.push(slot, captures[slot], BACKTRACK_CAPTURE);
              captures[slot] = -1;
            }
          }
          pc++;
          break;
        case OP_MARK:
          stack.push(instruction.a, registers[instruction.a], BACKTRACK_REGISTER);
          registers[instruction.a] = pos;
          pc++;
          break;
        case OP_CHECK:
          matched = registers[instruction.a] !== pos;
          pc++;
          break;
        case OP_START:
          matched = pos === 0 || (instruction.flag && isLineTerminator(input.charCodeAt(pos - 1)));
          pc++;
          break;
        case OP_END:
          matched = pos === length || (instruction.flag && isLineTerminator(input.charCodeAt(pos)));
          pc++;
          break;
        case OP_WORD_BOUNDARY: {
          const before = pos > 0 && isWordChar(input.charCodeAt(pos - 1));
          const after = pos < length && isWordChar(input.charCodeAt(pos));
          matched = (before !== after) !== instruction.flag;
          pc++;
          break;
        }
        case OP_BACKREFERENCE: {
          const group = instruction.groups!.find((index) => captures[index * 2] >= 0 && captures[index * 2 + 1] >= 0);
          if (group === undefined) {
            pc++;
            break;
          }
          const from = captures[group * 2];
          const size = captures[group * 2 + 1] - from;
          const at = instruction.backward ? pos - size : pos;
          this.spend(size);
          if (at < 0 || at + size > length) {
            matched = false;
            break;
          }
          for (let i = 0; i < size && matched; i++) {
            const expected = input.charCodeAt(from + i);
            const actual = input.charCodeAt(at + i);
            matched = instruction.flag ? canonicalize(expected) === canonicalize(actual) : expected === actual;
          }
          if (matched) {
            pos = instruction.backward ? pos - size : pos + size;
            pc++;
          }
          break;
        }
        case OP_LOOKAROUND: {
          this.spend(captures.length);
          const before = captures.slice();
          const bodyMatched = this.run(instruction.a, pos) >= 0;
          const negate = instruction.flag;
          if (bodyMatched && !negate) {
            for (let slot = 0; slot < captures.length; slot++) {
              if (captures[slot] !== before[slot]) {
                stack.push(slot, before[slot], BACKTRACK_CAPTURE);
              }
            }
          } else {
            captures.set(before);
          }
          matched = bodyMatched !== negate;
          pc = instruction.b;
          break;
        }
        case OP_SUCCEED:
          return pos;
      }

      if (matched) {
        continue;
      }

      for (;;) {
        if (stack.length === 0) {
          return -1;
        }
        const kind = stack.pop()!;
        const value = stack.pop()!;
        const target = stack.pop()!;
        if (kind === BACKTRACK_BRANCH) {
          pc = target;
          pos = value;
          break;
        }
        if (kind === BACKTRACK_CAPTURE) {
          captures[target] = value;
        } else {
          registers[target] = value;
        }
      }
    }
  }
}
