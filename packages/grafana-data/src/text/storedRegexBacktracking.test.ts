import { lastValueFrom, of } from 'rxjs';

import { toDataFrame } from '../dataframe/processDataFrame';
import { getDisplayProcessor } from '../field/displayProcessor';
import { createTheme } from '../themes/createTheme';
import { getFieldMatcher, getFrameMatchers, getValueMatcher } from '../transformations/matchers';
import { FieldMatcherID, FrameMatcherID, ValueMatcherID } from '../transformations/matchers/ids';
import { filterFieldsByNameTransformer } from '../transformations/transformers/filterByName';
import {
  FilterByValueMatch,
  FilterByValueType,
  filterByValueTransformer,
} from '../transformations/transformers/filterByValue';
import { renameByRegexTransformer } from '../transformations/transformers/renameByRegex';
import { FieldType } from '../types/dataFrame';
import { MappingType } from '../types/valueMapping';
import { getValueMappingResult } from '../utils/valueMappings';

import { stringToJsRegex } from './string';
import { findMatchesInText } from './text';

// Nested quantifiers are exponential in this engine: each extra 'a' roughly doubles
// the time. These lengths finish in well over a second while the pattern is compiled
// and matched with no timeout, and in well under the budget once matching is bounded.
const ANCHORED_SUBJECT = `${'a'.repeat(29)}!`;
const OPEN_SUBJECT = `${'a'.repeat(28)}!`;
const BUDGET_MS = 250;

const context = { interpolate: (value: string) => value };

function regexMapping(pattern: string) {
  return [
    {
      type: MappingType.RegexToText as const,
      options: { pattern, result: { text: 'mapped' } },
    },
  ];
}

function frameWithName(name: string) {
  const frame = toDataFrame({
    name,
    fields: [{ name, type: FieldType.string, values: [name] }],
  });
  frame.refId = name;
  frame.name = name;
  return frame;
}

async function expectMatchBounded(run: () => unknown) {
  const start = performance.now();
  try {
    await run();
  } catch {
    // Rejecting the stored pattern is a fix, as long as the rejection itself is fast.
  }
  expect(performance.now() - start).toBeLessThan(BUDGET_MS);
}

describe('stored regular expressions must not backtrack without a bound', () => {
  jest.setTimeout(30000);

  const theme = createTheme();

  it('matches a slash-less nested pattern from stringToJsRegex within the budget', async () => {
    await expectMatchBounded(() => {
      stringToJsRegex('(a+)+$').test(ANCHORED_SUBJECT);
    });
  });

  it('matches a slash-wrapped nested pattern from stringToJsRegex within the budget', async () => {
    await expectMatchBounded(() => {
      stringToJsRegex('/(a+)+$/').test(OPEN_SUBJECT);
    });
  });

  it('resolves a slash-less regex value mapping within the budget', async () => {
    await expectMatchBounded(() => {
      getValueMappingResult(regexMapping('(a+)+$'), ANCHORED_SUBJECT);
    });
  });

  it('resolves a slash-wrapped regex value mapping within the budget', async () => {
    await expectMatchBounded(() => {
      getValueMappingResult(regexMapping('/(a+)+$/'), OPEN_SUBJECT);
    });
  });

  it('formats a cell through the display processor within the budget', async () => {
    await expectMatchBounded(() => {
      const processor = getDisplayProcessor({
        field: {
          type: FieldType.string,
          config: { mappings: regexMapping('(a+)+$') },
        },
        theme,
      });
      processor(ANCHORED_SUBJECT);
    });
  });

  it('renames fields by a nested regex within the budget', async () => {
    const frame = frameWithName(ANCHORED_SUBJECT);
    await expectMatchBounded(() =>
      lastValueFrom(
        renameByRegexTransformer.operator({ regex: '(a+)+$', renamePattern: 'renamed' }, context)(of([frame]))
      )
    );
  });

  it('filters fields by a nested name pattern within the budget', async () => {
    const frame = frameWithName(ANCHORED_SUBJECT);
    await expectMatchBounded(() =>
      lastValueFrom(filterFieldsByNameTransformer.operator({ include: { pattern: '(a+)+$' } }, context)(of([frame])))
    );
  });

  it('matches a field name by a nested regexp within the budget', async () => {
    const frame = frameWithName(ANCHORED_SUBJECT);
    await expectMatchBounded(() => {
      const matcher = getFieldMatcher({ id: FieldMatcherID.byRegexp, options: '(a+)+$' });
      matcher(frame.fields[0], frame, [frame]);
    });
  });

  it('matches a field name by a nested regexp or names pattern within the budget', async () => {
    const frame = frameWithName(ANCHORED_SUBJECT);
    await expectMatchBounded(() => {
      const matcher = getFieldMatcher({
        id: FieldMatcherID.byRegexpOrNames,
        options: { pattern: '(a+)+$', names: [] },
      });
      matcher(frame.fields[0], frame, [frame]);
    });
  });

  it('matches a frame name by a nested pattern within the budget', async () => {
    const frame = frameWithName(ANCHORED_SUBJECT);
    await expectMatchBounded(() => {
      const matcher = getFrameMatchers({ id: FrameMatcherID.byName, options: '(a+)+$' });
      matcher(frame);
    });
  });

  it('matches a query refId by a slash-wrapped nested pattern within the budget', async () => {
    const frame = frameWithName(OPEN_SUBJECT);
    await expectMatchBounded(() => {
      const matcher = getFrameMatchers({ id: FrameMatcherID.byRefId, options: '/(a+)+$/' });
      matcher(frame);
    });
  });

  it('filters rows by a nested value regex within the budget', async () => {
    const frame = toDataFrame({
      fields: [{ name: 'line', type: FieldType.string, values: [OPEN_SUBJECT] }],
    });
    await expectMatchBounded(() =>
      lastValueFrom(
        filterByValueTransformer.operator(
          {
            type: FilterByValueType.include,
            match: FilterByValueMatch.any,
            filters: [
              {
                fieldName: 'line',
                config: { id: ValueMatcherID.regex, options: { value: '(a+)+$' } },
              },
            ],
          },
          context
        )(of([frame]))
      )
    );
  });

  it('applies the regex value matcher itself within the budget', async () => {
    const frame = toDataFrame({
      fields: [{ name: 'line', type: FieldType.string, values: [OPEN_SUBJECT] }],
    });
    await expectMatchBounded(() => {
      const matcher = getValueMatcher({ id: ValueMatcherID.regex, options: { value: '(a+)+$' } });
      matcher(0, frame.fields[0], frame, [frame]);
    });
  });

  it('highlights text with a nested search pattern within the budget', async () => {
    await expectMatchBounded(() => {
      findMatchesInText(OPEN_SUBJECT, '(a+)+$');
    });
  });
});
