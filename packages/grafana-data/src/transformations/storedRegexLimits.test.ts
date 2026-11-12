import { firstValueFrom } from 'rxjs';

import { toDataFrame } from '../dataframe/processDataFrame';
import { FieldType, type DataFrame } from '../types/dataFrame';
import { type DataTransformerConfig } from '../types/transformations';
import { MappingType, type ValueMapping } from '../types/valueMapping';
import { mockTransformationsRegistry } from '../utils/tests/mockTransformationsRegistry';
import { getValueMappingResult } from '../utils/valueMappings';

import { getFieldMatcher, getFrameMatchers, getValueMatcher } from './matchers';
import { FieldMatcherID, FrameMatcherID, ValueMatcherID } from './matchers/ids';
import { transformDataFrame } from './transformDataFrame';
import { filterFieldsTransformer, filterFramesTransformer } from './transformers/filter';
import { filterFramesByRefIdTransformer } from './transformers/filterByRefId';
import {
  FilterByValueMatch,
  FilterByValueType,
  filterByValueTransformer,
  type FilterByValueTransformerOptions,
} from './transformers/filterByValue';
import { DataTransformerID } from './transformers/ids';
import { renameByRegexTransformer, type RenameByRegexTransformerOptions } from './transformers/renameByRegex';

/**
 * Stored dashboard regexes are compiled with the host RegExp engine and tested while a panel
 * query runs. A nested pattern such as `(a+)+$` is exponential in that engine: 30 `a` characters
 * followed by a non-match takes seconds and grows by about 4x for every two extra characters.
 * The contract under test is that every stored pattern is length-capped and that testing a
 * nested pattern returns or refuses inside the budget below.
 */
const MAX_STORED_REGEX_LENGTH = 1024;
const MATCH_BUDGET_MS = 250;
const NESTED_PATTERN = '(a+)+$';
const NESTED_INPUT = `${'a'.repeat(30)}!`;
const SLOW_TEST_TIMEOUT_MS = 180_000;

const maxLengthPattern = 'a'.repeat(MAX_STORED_REGEX_LENGTH);
const overLengthPattern = 'a'.repeat(MAX_STORED_REGEX_LENGTH + 1);

function messageFrame(values: string[], name = 'message'): DataFrame {
  return toDataFrame({
    name: 'A',
    refId: 'A',
    fields: [{ name, type: FieldType.string, values }],
  });
}

function namedFieldFrame(displayName: string): DataFrame {
  return toDataFrame({
    name: 'A',
    refId: 'A',
    fields: [
      {
        name: 'value',
        type: FieldType.string,
        values: ['1'],
        config: { displayName },
      },
    ],
  });
}

async function runTransformer<TOptions>(
  config: DataTransformerConfig<TOptions>,
  frames: DataFrame[],
  interpolate: (value: string) => string = (value) => value
): Promise<DataFrame[]> {
  return firstValueFrom(transformDataFrame([config], frames, { interpolate }));
}

function expectWithinBudget(startedAt: number) {
  expect(performance.now() - startedAt).toBeLessThan(MATCH_BUDGET_MS);
}

async function expectSettlesWithinBudget(run: () => Promise<unknown> | unknown) {
  const startedAt = performance.now();
  try {
    await run();
  } catch {
    // Refusing the pattern is inside the contract, as long as it happens inside the budget.
  }
  expectWithinBudget(startedAt);
}

describe('stored regular expressions', () => {
  beforeAll(() => {
    mockTransformationsRegistry([
      filterByValueTransformer,
      renameByRegexTransformer,
      filterFieldsTransformer,
      filterFramesTransformer,
      filterFramesByRefIdTransformer,
    ]);
  });

  describe('regex value matcher', () => {
    function match(pattern: string, value: string): boolean {
      const frame = messageFrame([value]);
      const matcher = getValueMatcher({
        id: ValueMatcherID.regex,
        options: { value: pattern },
      });
      return matcher(0, frame.fields[0], frame, [frame]);
    }

    it('matches a short pattern and rejects a non-match', () => {
      expect(match('^keep$', 'keep')).toBe(true);
      expect(match('^keep$', 'drop')).toBe(false);
    });

    it('still matches a stored pattern of exactly 1024 characters', () => {
      expect(match(maxLengthPattern, maxLengthPattern)).toBe(true);
      expect(match(maxLengthPattern, 'b')).toBe(false);
    });

    it('does not match a stored pattern longer than 1024 characters', () => {
      const startedAt = performance.now();
      let matched = true;
      try {
        matched = match(overLengthPattern, overLengthPattern);
      } catch {
        matched = false;
      }
      expectWithinBudget(startedAt);
      expect(matched).toBe(false);
    });

    it(
      'returns within 250ms for a nested pattern tested against 30 a characters and a non-match',
      () => expectSettlesWithinBudget(() => match(NESTED_PATTERN, NESTED_INPUT)),
      SLOW_TEST_TIMEOUT_MS
    );

    it(
      'returns within 250ms for an anchored nested pattern',
      () => expectSettlesWithinBudget(() => match(`^${NESTED_PATTERN}`, NESTED_INPUT)),
      SLOW_TEST_TIMEOUT_MS
    );
  });

  describe('filter-by-value transformation', () => {
    function config(pattern: string): DataTransformerConfig<FilterByValueTransformerOptions> {
      return {
        id: DataTransformerID.filterByValue,
        options: {
          type: FilterByValueType.include,
          match: FilterByValueMatch.all,
          filters: [
            {
              fieldName: 'message',
              config: {
                id: ValueMatcherID.regex,
                options: { value: pattern },
              },
            },
          ],
        },
      };
    }

    async function includedMessages(pattern: string, values: string[], scene = false): Promise<unknown[]> {
      const previousScene = window.__grafanaSceneContext;
      if (scene) {
        window.__grafanaSceneContext = {};
      } else {
        delete window.__grafanaSceneContext;
      }

      try {
        const frames = await runTransformer(config(pattern), [messageFrame(values)]);
        return frames[0]?.fields.find((field) => field.name === 'message')?.values ?? [];
      } finally {
        if (previousScene === undefined) {
          delete window.__grafanaSceneContext;
        } else {
          window.__grafanaSceneContext = previousScene;
        }
      }
    }

    it('keeps rows that match a short regex and drops the rest', async () => {
      await expect(includedMessages('^keep$', ['keep', 'drop'])).resolves.toEqual(['keep']);
    });

    it('keeps a row matched by a stored pattern of exactly 1024 characters', async () => {
      await expect(includedMessages(maxLengthPattern, [maxLengthPattern, 'b'])).resolves.toEqual([maxLengthPattern]);
    });

    it('does not keep a row matched only by a stored pattern longer than 1024 characters', async () => {
      const startedAt = performance.now();
      let values: unknown[] = [overLengthPattern];
      try {
        values = await includedMessages(overLengthPattern, [overLengthPattern]);
      } catch {
        values = [];
      }
      expectWithinBudget(startedAt);
      expect(values).toEqual([]);
    });

    it(
      'returns within 250ms when a scene dashboard runs a nested filter-by-value regex',
      async () => {
        // Scene dashboards set __grafanaSceneContext, and transformDataFrame then skips
        // variable interpolation and compiles the stored pattern as saved.
        await expectSettlesWithinBudget(() => includedMessages(NESTED_PATTERN, [NESTED_INPUT], true));
      },
      SLOW_TEST_TIMEOUT_MS
    );

    it(
      'returns within 250ms when variable interpolation leaves a nested filter-by-value regex unchanged',
      async () => {
        const previousScene = window.__grafanaSceneContext;
        delete window.__grafanaSceneContext;
        const interpolate = (value: string) => value;
        try {
          await expectSettlesWithinBudget(() =>
            runTransformer(config(NESTED_PATTERN), [messageFrame([NESTED_INPUT])], interpolate)
          );
        } finally {
          if (previousScene === undefined) {
            delete window.__grafanaSceneContext;
          } else {
            window.__grafanaSceneContext = previousScene;
          }
        }
      },
      SLOW_TEST_TIMEOUT_MS
    );
  });

  describe('rename-by-regex transformation', () => {
    function config(regex: string): DataTransformerConfig<RenameByRegexTransformerOptions> {
      return {
        id: DataTransformerID.renameByRegex,
        options: { regex, renamePattern: 'renamed' },
      };
    }

    async function renamed(regex: string, displayName: string): Promise<string | undefined> {
      const frames = await runTransformer(config(regex), [namedFieldFrame(displayName)]);
      return frames[0]?.fields[0]?.state?.displayName;
    }

    it('renames a field matched by a short pattern', async () => {
      await expect(renamed('keep', 'keep')).resolves.toBe('renamed');
    });

    it('renames a field matched by a stored pattern of exactly 1024 characters', async () => {
      await expect(renamed(maxLengthPattern, maxLengthPattern)).resolves.toBe('renamed');
    });

    it('does not apply a stored pattern longer than 1024 characters', async () => {
      const startedAt = performance.now();
      let displayName: string | undefined = 'renamed';
      try {
        displayName = await renamed(overLengthPattern, overLengthPattern);
      } catch {
        displayName = overLengthPattern;
      }
      expectWithinBudget(startedAt);
      expect(displayName).toBe(overLengthPattern);
    });

    it(
      'returns within 250ms for a nested rename pattern',
      async () => {
        await expectSettlesWithinBudget(() => renamed('(a+)+', NESTED_INPUT));
      },
      SLOW_TEST_TIMEOUT_MS
    );
  });

  describe('field-name regexp matchers', () => {
    function matchField(id: FieldMatcherID, pattern: string, displayName: string): boolean {
      const frame = namedFieldFrame(displayName);
      const matcher = getFieldMatcher({
        id,
        options: id === FieldMatcherID.byRegexp ? pattern : { pattern, names: [] },
      });
      return matcher(frame.fields[0], frame, [frame]);
    }

    it.each([FieldMatcherID.byRegexp, FieldMatcherID.byRegexpOrNames])(
      '%s matches a short pattern and a pattern of exactly 1024 characters',
      (id) => {
        expect(matchField(id, 'keep', 'keep')).toBe(true);
        expect(matchField(id, 'keep', 'drop')).toBe(false);
        expect(matchField(id, maxLengthPattern, maxLengthPattern)).toBe(true);
      }
    );

    it.each([FieldMatcherID.byRegexp, FieldMatcherID.byRegexpOrNames])(
      '%s does not match a stored pattern longer than 1024 characters',
      (id) => {
        const startedAt = performance.now();
        let matched = true;
        try {
          matched = matchField(id, overLengthPattern, overLengthPattern);
        } catch {
          matched = false;
        }
        expectWithinBudget(startedAt);
        expect(matched).toBe(false);
      }
    );

    it.each([FieldMatcherID.byRegexp, FieldMatcherID.byRegexpOrNames])(
      '%s returns within 250ms for a nested pattern',
      (id) => expectSettlesWithinBudget(() => matchField(id, '(a+)+', NESTED_INPUT)),
      SLOW_TEST_TIMEOUT_MS
    );

    it(
      'filter-fields returns within 250ms when its include matcher is a nested regexp',
      async () => {
        const config: DataTransformerConfig = {
          id: DataTransformerID.filterFields,
          options: {
            include: { id: FieldMatcherID.byRegexp, options: '(a+)+' },
          },
        };
        await expectSettlesWithinBudget(() => runTransformer(config, [namedFieldFrame(NESTED_INPUT)]));
      },
      SLOW_TEST_TIMEOUT_MS
    );
  });

  describe('frame-name matcher', () => {
    function matchFrame(pattern: string, name: string): boolean {
      const frame = toDataFrame({ name, refId: 'A', fields: [] });
      const matcher = getFrameMatchers({ id: FrameMatcherID.byName, options: pattern });
      return matcher(frame);
    }

    it('matches a short frame name and a pattern of exactly 1024 characters', () => {
      expect(matchFrame('Series A', 'Series A')).toBe(true);
      expect(matchFrame('Series A', 'Series B')).toBe(false);
      expect(matchFrame(maxLengthPattern, maxLengthPattern)).toBe(true);
    });

    it('does not match a stored pattern longer than 1024 characters', () => {
      const startedAt = performance.now();
      let matched = true;
      try {
        matched = matchFrame(overLengthPattern, overLengthPattern);
      } catch {
        matched = false;
      }
      expectWithinBudget(startedAt);
      expect(matched).toBe(false);
    });

    it(
      'returns within 250ms for a nested frame-name pattern',
      () => expectSettlesWithinBudget(() => matchFrame('(a+)+', NESTED_INPUT)),
      SLOW_TEST_TIMEOUT_MS
    );

    it(
      'filter-frames returns within 250ms when its include matcher is a nested frame name',
      async () => {
        const config: DataTransformerConfig = {
          id: DataTransformerID.filterFrames,
          options: {
            include: { id: FrameMatcherID.byName, options: '(a+)+' },
          },
        };
        const frame = toDataFrame({ name: NESTED_INPUT, refId: 'A', fields: [] });
        await expectSettlesWithinBudget(() => runTransformer(config, [frame]));
      },
      SLOW_TEST_TIMEOUT_MS
    );
  });

  describe('refId matcher', () => {
    function config(include: string): DataTransformerConfig {
      return {
        id: DataTransformerID.filterByRefId,
        options: { include },
      };
    }

    async function keptRefIds(include: string, refId: string): Promise<Array<string | undefined>> {
      const frame = toDataFrame({ name: 'A', refId, fields: [] });
      const frames = await runTransformer(config(include), [frame]);
      return frames.map((processed) => processed.refId);
    }

    it('keeps a frame whose refId matches a short slash-delimited pattern', async () => {
      await expect(keptRefIds('/^A$/', 'A')).resolves.toEqual(['A']);
    });

    it('keeps a frame matched by a stored pattern of exactly 1024 characters', async () => {
      const pattern = `/${'a'.repeat(MAX_STORED_REGEX_LENGTH - 2)}/`;
      const refId = 'a'.repeat(MAX_STORED_REGEX_LENGTH - 2);
      expect(pattern).toHaveLength(MAX_STORED_REGEX_LENGTH);
      await expect(keptRefIds(pattern, refId)).resolves.toEqual([refId]);
    });

    it('does not keep a frame matched only by a stored pattern longer than 1024 characters', async () => {
      const pattern = `/${'a'.repeat(MAX_STORED_REGEX_LENGTH - 1)}/`;
      const refId = 'a'.repeat(MAX_STORED_REGEX_LENGTH - 1);
      expect(pattern.length).toBeGreaterThan(MAX_STORED_REGEX_LENGTH);
      const startedAt = performance.now();
      let refIds: Array<string | undefined> = [refId];
      try {
        refIds = await keptRefIds(pattern, refId);
      } catch {
        refIds = [];
      }
      expectWithinBudget(startedAt);
      expect(refIds).toEqual([]);
    });

    it(
      'returns within 250ms for a nested slash-delimited refId pattern',
      async () => {
        await expectSettlesWithinBudget(() => keptRefIds(`/${NESTED_PATTERN}/`, NESTED_INPUT));
      },
      SLOW_TEST_TIMEOUT_MS
    );
  });

  describe('value-mapping regex', () => {
    function mapping(pattern: string): ValueMapping[] {
      return [
        {
          type: MappingType.RegexToText,
          options: { pattern, result: { text: 'mapped' } },
        },
      ];
    }

    it('maps a value matched by a short pattern', () => {
      expect(getValueMappingResult(mapping('keep'), 'keep')).toEqual({ text: 'mapped' });
      expect(getValueMappingResult(mapping('keep'), 'drop')).toBeNull();
    });

    it('maps a value matched by a stored pattern of exactly 1024 characters', () => {
      expect(getValueMappingResult(mapping(maxLengthPattern), maxLengthPattern)).toEqual({ text: 'mapped' });
    });

    it('does not map a value with a stored pattern longer than 1024 characters', () => {
      const startedAt = performance.now();
      let text: string | undefined = 'mapped';
      try {
        text = getValueMappingResult(mapping(overLengthPattern), overLengthPattern)?.text;
      } catch {
        text = undefined;
      }
      expectWithinBudget(startedAt);
      expect(text).toBeUndefined();
    });

    it(
      'returns within 250ms for a nested value-mapping pattern',
      () => expectSettlesWithinBudget(() => getValueMappingResult(mapping('(a+)+'), NESTED_INPUT)),
      SLOW_TEST_TIMEOUT_MS
    );
  });
});
