import memoize from 'micro-memoize';
import { RE2JS } from 're2js';

import { parseFlags } from '@grafana/data';

import { type Label, type LabelMatcher } from './types';

type LabelMatchingResult = {
  // wether all of the labels match the given set of matchers
  matches: boolean;
  // details of which labels matched which matcher
  details: LabelMatchDetails[];
};

// LabelMatchDetails is a map of labels to their match results
export type LabelMatchDetails = {
  labelIndex: number; // index of the label in the labels array
  match: boolean;
  matcher: LabelMatcher | null;
} & (PositiveLabelMatch | NegativeLabelMatch);

type PositiveLabelMatch = {
  match: true;
  matcher: LabelMatcher;
};
type NegativeLabelMatch = {
  match: false;
  matcher: null;
};

/**
 * The same list of labels, with two lookup tables built over it.
 *
 * Matching a route tree checks the same label set against hundreds or thousands of matchers, and
 * each of those checks needs to find one label by name. Doing that by name on the list means
 * walking it every time, so build the lookups once and reuse them for the whole tree.
 *
 * `valueByName` keeps the last value for a repeated label name, which is what turning the list
 * into an object used to give us. `indicesByName` keeps every position a name appears at, in
 * order, so the details below can look at exactly the labels a matcher could apply to.
 */
export type IndexedLabels = {
  labels: Label[];
  valueByName: Map<string, string>;
  indicesByName: Map<string, number[]>;
};

export function indexLabels(labels: Label[]): IndexedLabels {
  const valueByName = new Map<string, string>();
  const indicesByName = new Map<string, number[]>();

  labels.forEach(([name, value], index) => {
    valueByName.set(name, value);

    const indices = indicesByName.get(name);
    if (indices) {
      indices.push(index);
    } else {
      indicesByName.set(name, [index]);
    }
  });

  return { labels, valueByName, indicesByName };
}

// returns a match results for given set of matchers (from a policy for instance) and a set of labels
export function matchLabels(matchers: LabelMatcher[], labels: Label[]): LabelMatchingResult {
  return matchIndexedLabels(matchers, indexLabels(labels));
}

// same as matchLabels, for callers that already built the lookups and want to reuse them
export function matchIndexedLabels(matchers: LabelMatcher[], indexedLabels: IndexedLabels): LabelMatchingResult {
  const matches = matchIndexedLabelsSet(matchers, indexedLabels);

  // create initial map of label => match result
  const details = indexedLabels.labels.map<LabelMatchDetails>((_label, index) => ({
    labelIndex: index,
    match: false,
    matcher: null,
  }));

  // for each matcher, check which label it matched for
  matchers.forEach((matcher) => {
    const matchingLabelIndex = findMatchingLabelIndex(matcher, indexedLabels);

    // record that matcher for the label
    if (matchingLabelIndex > -1) {
      details[matchingLabelIndex].match = true;
      details[matchingLabelIndex].matcher = matcher;
    }
  });

  return { matches, details };
}

/**
 * The first label this matcher accepts, or -1 if there is none.
 *
 * This is the same answer as checking the matcher against every label in order, because a matcher
 * can only ever accept a label that carries its own name. Labels with a different name are skipped
 * without running the operator, so an invalid regular expression still only throws when the label
 * set actually carries that name.
 */
function findMatchingLabelIndex(matcher: LabelMatcher, indexedLabels: IndexedLabels): number {
  const indices = indexedLabels.indicesByName.get(matcher.label);
  if (!indices) {
    return -1;
  }

  const matchFunction = OperatorFunctions[matcher.type];
  for (const index of indices) {
    if (matchFunction(indexedLabels.labels[index][1], matcher.value)) {
      return index;
    }
  }

  return -1;
}

// ⚠️ DO NOT USE THIS FUNCTION FOR ROUTE SELECTION ALGORITHM
// for route selection algorithm, always compare a single matcher to the entire label set
// see "matchLabelsSet"
export function isLabelMatch(matcher: LabelMatcher, label: Label): boolean {
  const [labelKey, labelValue] = label;
  const { label: matcherLabel, type: matcherType, value: matcherValue } = matcher;

  if (labelKey !== matcherLabel) {
    return false;
  }

  const matchFunction = OperatorFunctions[matcherType];
  return matchFunction(labelValue, matcherValue);
}

export function matchLabelsSet(matchers: LabelMatcher[], labels: Label[]): boolean {
  return matchIndexedLabelsSet(matchers, indexLabels(labels));
}

// same as matchLabelsSet, but takes the prebuilt lookups so callers in here can reuse them
function matchIndexedLabelsSet(matchers: LabelMatcher[], indexedLabels: IndexedLabels): boolean {
  for (const matcher of matchers) {
    if (!isLabelMatchInSet(matcher, indexedLabels)) {
      return false;
    }
  }
  return true;
}

/**
 * Checks if a label matcher matches any of the labels in the provided set.
 */
function isLabelMatchInSet(matcher: LabelMatcher, indexedLabels: IndexedLabels): boolean {
  const { label, type, value } = matcher;

  // matchers that have no labels are treated as empty string label values
  const labelValue = indexedLabels.valueByName.get(label) || '';

  const matchFunction = OperatorFunctions[type];
  try {
    // This can throw because the regex operators compile the matcher value, which throws on
    // invalid or too large regular expressions.
    //
    // This is usually a user-error (because matcher values are taken from user input)
    return matchFunction(labelValue, value);
  } catch (err) {
    return false;
  }
}

const MAX_MATCHER_REGEX_LENGTH = 1024;
const MAX_MATCHER_REGEX_PROGRAM_SIZE = 2 * MAX_MATCHER_REGEX_LENGTH;

// Compiling a regular expression is by far the most expensive thing in here, and route matching
// asks for the same matcher value over and over, so hold on to the compiled ones.
//
// Matcher values come from user input, and something like a label filter box will call in here on
// every keystroke, so cap the cache instead of letting it grow for the life of the page.
//
// Values that don't compile throw and are not cached. Callers above decide what to do with that,
// and recompiling a broken value is the rare path.
//
// Matching uses RE2 rather than the JavaScript regex engine because a backtracking engine can take
// exponential time on nested quantifiers such as (a+)+, and a synchronous match cannot be
// interrupted. RE2 matches in linear time, and is also the engine Alertmanager itself uses.
const getAnchoredRegex = memoize(
  (matcherValue: string): RE2JS => {
    if (matcherValue.length > MAX_MATCHER_REGEX_LENGTH) {
      throw new Error(`Regular expression is longer than ${MAX_MATCHER_REGEX_LENGTH} characters.`);
    }

    // At the time of writing, Alertmanager compiles to another (anchored) Regular Expression,
    // so we should also anchor our UI matches for consistency with this behaviour
    // https://github.com/prometheus/alertmanager/blob/fd37ce9c95898ca68be1ab4d4529517174b73c33/pkg/labels/matcher.go#L69
    const valueWithFlagsParsed = parseFlags(`^(?:${matcherValue})$`);

    let flags = 0;
    if (valueWithFlagsParsed.flags.includes('i')) {
      flags |= RE2JS.CASE_INSENSITIVE;
    }
    if (valueWithFlagsParsed.flags.includes('m')) {
      flags |= RE2JS.MULTILINE;
    }
    if (valueWithFlagsParsed.flags.includes('s')) {
      flags |= RE2JS.DOTALL;
    }

    const regex = RE2JS.compile(RE2JS.translateRegExp(valueWithFlagsParsed.cleaned), flags);
    // Counted repetition expands when compiled, and matching time grows with the program size.
    if (regex.programSize() > MAX_MATCHER_REGEX_PROGRAM_SIZE) {
      throw new Error('Regular expression is too large.');
    }
    return regex;
  },
  { maxSize: 500 }
);

type OperatorPredicate = (labelValue: string, matcherValue: string) => boolean;
const OperatorFunctions: Record<LabelMatcher['type'], OperatorPredicate> = {
  '=': (lv, mv) => lv === mv,
  '!=': (lv, mv) => lv !== mv,
  '=~': (lv, mv) => getAnchoredRegex(mv).test(lv),
  '!~': (lv, mv) => !getAnchoredRegex(mv).test(lv),
};
