import { BoundedRegExp, RegExpBudgetExceededError } from './boundedRegExp';

// Expressions come from saved correlations and data links and are matched on the UI thread of every viewer, so the
// work spent on one expression is bounded instead of being left to the backtracking of the native RegExp engine.
export const MAX_TRANSFORMATION_EXPRESSION_LENGTH = 512;
const MAX_PROGRAM_SIZE = 10_000;
const MAX_MATCH_STEPS = 1_000_000;
const MAX_CACHED_EXPRESSIONS = 500;

interface CompiledExpression {
  regex?: BoundedRegExp;
  exceededBudget: boolean;
}

export interface TransformationRegexMatch {
  start: number;
  end: number;
  value: string;
  firstGroup?: string;
  groups?: Record<string, string | undefined>;
}

const compiledExpressions = new Map<string, CompiledExpression>();

function compileWithinLimits(expression: string): BoundedRegExp | undefined {
  if (expression.length > MAX_TRANSFORMATION_EXPRESSION_LENGTH) {
    return undefined;
  }
  try {
    return BoundedRegExp.compile(expression, MAX_PROGRAM_SIZE);
  } catch (e) {
    return undefined;
  }
}

function compileExpression(expression: string): CompiledExpression {
  const cached = compiledExpressions.get(expression);
  if (cached) {
    return cached;
  }

  const compiled: CompiledExpression = { regex: compileWithinLimits(expression), exceededBudget: false };
  if (compiledExpressions.size >= MAX_CACHED_EXPRESSIONS) {
    compiledExpressions.delete(compiledExpressions.keys().next().value!);
  }
  compiledExpressions.set(expression, compiled);
  return compiled;
}

export function isValidTransformationRegex(expression: string): boolean {
  return compileExpression(expression).regex !== undefined;
}

/**
 * Returns the matches `value.matchAll(new RegExp(expression, 'gi'))` would return, or undefined when the expression is
 * invalid or too large, or matching it needs more steps than the budget. An expression that exceeds the budget once is
 * not run again, so it cannot cost the budget for every row it is applied to.
 */
export function findTransformationRegexMatches(
  expression: string,
  value: string
): TransformationRegexMatch[] | undefined {
  const compiled = compileExpression(expression);
  if (!compiled.regex || compiled.exceededBudget) {
    return undefined;
  }

  try {
    return compiled.regex.matchAll(value, MAX_MATCH_STEPS).map(({ start, end, value, captures, groups }) => ({
      start,
      end,
      value,
      firstGroup: captures[0],
      groups,
    }));
  } catch (e) {
    if (e instanceof RegExpBudgetExceededError) {
      compiled.exceededBudget = true;
      return undefined;
    }
    throw e;
  }
}
