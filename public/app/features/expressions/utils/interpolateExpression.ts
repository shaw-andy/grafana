import { type ScopedVars } from '@grafana/data';
import { type TemplateSrv } from '@grafana/runtime';
import { variableRegex } from 'app/features/variables/utils';

import { type ExpressionQuery, ExpressionQueryType } from '../types';

const NUMBER = /^(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;
const NEGATIVE_NUMBER = /^-(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;
const SQL_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MATH_NAME = /^\$?[A-Za-z_]\w*$/;
const REF_ID = /^\$?[\w-]+$/;
const DURATION = /^[0-9A-Za-z.µμ]+$/;
const HEX_DIGITS = /^[0-9A-Fa-f]*$/;
const BIT_DIGITS = /^[01]*$/;

// Words that would change the meaning of the statement if a value were inserted as a bare identifier.
// prettier-ignore
const SQL_KEYWORDS = new Set([
  'ALL', 'AND', 'ANY', 'AS', 'ASC', 'BETWEEN', 'BINARY', 'BY', 'CASE', 'COLLATE', 'DESC', 'DISTINCT', 'DIV',
  'ELSE', 'END', 'ESCAPE', 'EXCEPT', 'EXISTS', 'FALSE', 'FROM', 'GROUP', 'HAVING', 'IN', 'INTERSECT', 'INTERVAL',
  'IS', 'JOIN', 'LIKE', 'LIMIT', 'MOD', 'NOT', 'NULL', 'OFFSET', 'ON', 'OR', 'ORDER', 'REGEXP', 'RLIKE', 'SELECT',
  'SOME', 'SOUNDS', 'THEN', 'TRUE', 'UNION', 'UNKNOWN', 'WHEN', 'WHERE', 'WITH', 'XOR',
]);

// Formats whose output shape is rebuilt here from the raw values so it is quoted for go-mysql-server.
const SQL_STRUCTURED_FORMATS = new Set(['glob', 'raw', 'csv', 'sqlstring', 'singlequote', 'doublequote']);

interface VariableReference {
  text: string;
  unformatted: string;
  format?: string;
}

type Resolve = (reference: VariableReference) => string | undefined;

/**
 * Interpolates dashboard variables into the fields of an expression query. Variable values can be set
 * by anyone who opens the dashboard (for example from the URL), so each value is escaped or validated
 * for the position it is inserted at instead of being copied in raw. A value that is not valid for its
 * position leaves the variable reference as written, so the server only ever sees the saved text.
 */
export function interpolateExpressionQuery(
  query: ExpressionQuery,
  templateSrv: TemplateSrv,
  scopedVars: ScopedVars
): Pick<ExpressionQuery, 'expression' | 'window'> {
  const resolve: Resolve = (reference) => {
    const value = templateSrv.replace(reference.text, scopedVars);
    return value === reference.text ? undefined : value;
  };
  const resolveValues = (reference: VariableReference) => rawValues(reference, templateSrv, scopedVars);
  const matching = (pattern: RegExp) => (value: string) => (pattern.test(value) ? value : undefined);

  let expression: string;
  switch (query.type) {
    case ExpressionQueryType.sql:
      expression = interpolateSql(query.expression ?? '', resolve, resolveValues);
      break;
    case ExpressionQueryType.math:
      expression = interpolateTokens(query.expression ?? '', resolve, mathToken);
      break;
    default:
      expression = interpolateTokens(query.expression ?? '', resolve, matching(REF_ID));
  }

  return { expression, window: interpolateTokens(query.window ?? '', resolve, matching(DURATION)) };
}

function parseReference([text, var1, var2, fmt2, var3, fieldPath, fmt3]: Array<string | undefined>): VariableReference {
  text = text ?? '';
  let unformatted = text;
  if (var2) {
    unformatted = `[[${var2}]]`;
  } else if (var3) {
    unformatted = fieldPath ? `\${${var3}.${fieldPath}}` : `\${${var3}}`;
  } else if (var1) {
    unformatted = `$${var1}`;
  }
  return { text, unformatted, format: fmt2 || fmt3 };
}

function interpolateTokens(text: string, resolve: Resolve, accept: (value: string) => string | undefined): string {
  const regex = new RegExp(variableRegex.source, 'g');
  return text.replace(regex, (...groups: Array<string | undefined>) => {
    const reference = parseReference(groups);
    const value = resolve(reference);
    return (value === undefined ? undefined : accept(value)) ?? reference.text;
  });
}

function mathToken(value: string): string | undefined {
  if (NUMBER.test(value) || MATH_NAME.test(value)) {
    return value;
  }
  if (NEGATIVE_NUMBER.test(value)) {
    return `(${value})`;
  }
  return undefined;
}

/**
 * Returns the raw value(s) of a reference, ignoring any format in the reference, or undefined when the
 * template service produced the text some other way (custom all value, macro, unknown variable).
 */
function rawValues(
  reference: VariableReference,
  templateSrv: TemplateSrv,
  scopedVars: ScopedVars
): string | string[] | undefined {
  let calls = 0;
  let captured: string | string[] = '';
  let returned = '';
  const output = templateSrv.replace(reference.unformatted, scopedVars, (value: unknown) => {
    calls++;
    captured = Array.isArray(value) ? value.map(String) : String(value);
    returned = Array.isArray(captured) ? captured.join(',') : captured;
    return returned;
  });
  return calls === 1 && output === returned ? captured : undefined;
}

function escapeSqlString(value: string, quote: string): string {
  return value.replaceAll('\\', '\\\\').replaceAll(quote, quote + quote);
}

function sqlToken(value: string): string {
  if (value === '' || NUMBER.test(value)) {
    return value;
  }
  if (NEGATIVE_NUMBER.test(value)) {
    return `(${value})`;
  }
  if (SQL_IDENTIFIER.test(value) && !SQL_KEYWORDS.has(value.toUpperCase())) {
    return value;
  }
  return '`' + value.replaceAll('`', '``') + '`';
}

function sqlCodeValue(
  reference: VariableReference,
  resolve: Resolve,
  resolveValues: (reference: VariableReference) => string | string[] | undefined
): string | undefined {
  const format = reference.format?.split(':')[0];
  if (!format || SQL_STRUCTURED_FORMATS.has(format)) {
    const values = resolveValues(reference);
    if (values !== undefined) {
      const list = Array.isArray(values) ? values : [values];
      switch (format) {
        case 'sqlstring':
        case 'singlequote':
          return list.map((v) => `'${escapeSqlString(v, "'")}'`).join(',');
        case 'doublequote':
          return list.map((v) => `"${escapeSqlString(v, '"')}"`).join(',');
        default:
          return list.map(sqlToken).join(',');
      }
    }
  }
  const value = resolve(reference);
  return value === undefined ? undefined : sqlToken(value);
}

type SqlContext = 'code' | 'string' | 'identifier' | 'lineComment' | 'blockComment';

// X'..' and B'..' are hex and bit literals, which the tokenizer scans without any escapes.
function prefixedLiteralDigits(prefix: string | undefined): RegExp | undefined {
  switch (prefix) {
    case 'x':
    case 'X':
      return HEX_DIGITS;
    case 'b':
    case 'B':
      return BIT_DIGITS;
    default:
      return undefined;
  }
}

/**
 * Walks the SQL with the same quoting and comment rules as the vitess tokenizer used by SQL
 * expressions, so a substituted value can never close the literal, identifier, or comment it sits in.
 * References inside comments are left as written.
 */
function interpolateSql(
  sql: string,
  resolve: Resolve,
  resolveValues: (reference: VariableReference) => string | string[] | undefined
): string {
  const regex = new RegExp(variableRegex.source, 'y');
  let out = '';
  let context: SqlContext = 'code';
  let quote = '';
  let digits: RegExp | undefined;
  let i = 0;

  while (i < sql.length) {
    if (context !== 'lineComment' && context !== 'blockComment') {
      regex.lastIndex = i;
      const match = regex.exec(sql);
      if (match) {
        const reference = parseReference(match);
        let replacement: string | undefined;
        if (context === 'code') {
          replacement = sqlCodeValue(reference, resolve, resolveValues);
        } else {
          const value = resolve(reference);
          if (value !== undefined) {
            if (context === 'identifier') {
              replacement = value.replaceAll('`', '``');
            } else if (digits) {
              replacement = digits.test(value) ? value : undefined;
            } else {
              replacement = escapeSqlString(value, quote);
            }
          }
        }
        if (replacement !== undefined) {
          out += replacement;
          i += reference.text.length;
          continue;
        }
      }
    }

    const ch = sql[i];
    const next = sql[i + 1];
    switch (context) {
      case 'code':
        if (ch === "'" || ch === '"') {
          context = 'string';
          quote = ch;
          digits = ch === "'" ? prefixedLiteralDigits(out[out.length - 1]) : undefined;
        } else if (ch === '`') {
          context = 'identifier';
        } else if (ch === '#' || (ch === '-' && next === '-') || (ch === '/' && next === '/')) {
          context = 'lineComment';
        } else if (ch === '/' && next === '*') {
          context = 'blockComment';
          out += '/*';
          i += 2;
          continue;
        }
        break;
      case 'string':
        if (ch === '\\' && next !== undefined) {
          out += ch + next;
          i += 2;
          continue;
        }
        if (ch === quote) {
          if (next === quote) {
            out += ch + next;
            i += 2;
            continue;
          }
          context = 'code';
        }
        break;
      case 'identifier':
        if (ch === '`') {
          if (next === '`') {
            out += '``';
            i += 2;
            continue;
          }
          context = 'code';
        }
        break;
      case 'lineComment':
        if (ch === '\n') {
          context = 'code';
        }
        break;
      case 'blockComment':
        if (ch === '*' && next === '/') {
          out += '*/';
          i += 2;
          context = 'code';
          continue;
        }
        break;
    }
    out += ch;
    i++;
  }

  return out;
}
