import { matchLabelsSet } from '@grafana/alerting/unstable';
import { type DataFrameJSON } from '@grafana/data';
import { config } from '@grafana/runtime';
import {
  AlertState,
  type AlertmanagerAlert,
  type AlertmanagerGroup,
  MatcherOperator,
  type RouteWithID,
} from 'app/plugins/datasource/alertmanager/types';

import { ruleHistoryToRecords } from './components/rules/central-state-history/useRuleHistoryRecords';
import { filterRules } from './hooks/useFilteredRules';
import { mockCombinedRule, mockCombinedRuleGroup, mockCombinedRuleNamespace, mockPromAlertingRule } from './mocks';
import { routeGroupsMatcher } from './routeGroupsMatcher';
import { getDatasourceFilter } from './rule-list/hooks/datasourceFilter';
import { getGrafanaFilter } from './rule-list/hooks/grafanaFilter';
import { getSearchFilterFromQuery } from './search/rulesSearchParser';
import { labelsMatchMatchers } from './utils/alertmanager';
import { parsePromQLStyleMatcherLooseSafe } from './utils/matchers';

// A few dozen repetitions. At this length a nested quantifier that fails to match
// takes seconds in the JavaScript RegExp engine and returns immediately once matching
// is bounded, rejected, or evaluated in linear time.
const REPEATED_LABEL = 'a'.repeat(30);
const ANCHORED_MISMATCH = `${'a'.repeat(28)}!`;
const NESTED_QUANTIFIER = '(a+)+b';
const NESTED_QUANTIFIER_ANCHORED = '(a+)+$';
const BUDGET_MS = 1000;

jest.setTimeout(60_000);

function elapsedNonMatch(run: () => boolean): boolean {
  const start = performance.now();
  let matched = true;
  try {
    matched = run();
  } catch {
    matched = false;
  }
  expect(performance.now() - start).toBeLessThan(BUDGET_MS);
  return matched;
}

function searchFilter(operator: string, pattern: string) {
  const matcher = `severity${operator}${pattern}`;
  const filter = getSearchFilterFromQuery(`label:${matcher}`);
  expect(filter.labels).toEqual([matcher]);
  return filter;
}

function promqlMatchers(operator: string, pattern: string) {
  const text = `severity${operator}${pattern}`;
  const matchers = parsePromQLStyleMatcherLooseSafe(text);
  expect(matchers).toEqual([
    {
      name: 'severity',
      value: pattern,
      isRegex: true,
      isEqual: operator === '=~',
    },
  ]);
  return matchers;
}

describe('alert label matcher backtracking', () => {
  describe('compiler', () => {
    it('finishes a nested regex match against a repeated label', () => {
      const matched = elapsedNonMatch(() =>
        matchLabelsSet([{ label: 'severity', type: '=~', value: NESTED_QUANTIFIER }], [['severity', REPEATED_LABEL]])
      );
      expect(matched).toBe(false);
    });

    it('finishes the anchored nested form against a repeated label that does not match', () => {
      const matched = elapsedNonMatch(() =>
        matchLabelsSet(
          [{ label: 'severity', type: '=~', value: NESTED_QUANTIFIER_ANCHORED }],
          [['severity', ANCHORED_MISMATCH]]
        )
      );
      expect(matched).toBe(false);
    });

    it('finishes a negative nested regex match against a repeated label', () => {
      const start = performance.now();
      let matched: boolean | undefined;
      try {
        matched = matchLabelsSet(
          [{ label: 'severity', type: '!~', value: NESTED_QUANTIFIER }],
          [['severity', REPEATED_LABEL]]
        );
      } catch {
        matched = undefined;
      }
      expect(performance.now() - start).toBeLessThan(BUDGET_MS);
      expect(matched === undefined || typeof matched === 'boolean').toBe(true);
    });

    it('still matches a Prometheus-style regex', () => {
      expect(matchLabelsSet([{ label: 'severity', type: '=~', value: 'crit.*' }], [['severity', 'critical']])).toBe(
        true
      );
      expect(matchLabelsSet([{ label: 'severity', type: '!~', value: 'crit.*' }], [['severity', 'critical']])).toBe(
        false
      );
    });
  });

  describe('alert list search query', () => {
    it('filters rules from the list search query without backtracking', () => {
      const filter = searchFilter('=~', NESTED_QUANTIFIER);
      const namespaces = [
        mockCombinedRuleNamespace({
          groups: [
            mockCombinedRuleGroup('group', [
              mockCombinedRule({ name: 'planted', labels: { severity: REPEATED_LABEL } }),
            ]),
          ],
        }),
      ];

      const matched = elapsedNonMatch(() => filterRules(namespaces, filter).length > 0);
      expect(matched).toBe(false);
    });

    it('filters datasource rules on the list without backtracking', () => {
      const filter = searchFilter('=~', NESTED_QUANTIFIER);
      const rule = mockPromAlertingRule({ name: 'planted', labels: { severity: REPEATED_LABEL } });
      const { ruleMatches } = getDatasourceFilter(filter);

      const matched = elapsedNonMatch(() => ruleMatches(rule));
      expect(matched).toBe(false);
    });

    it('filters Grafana rules on the client when backend label filters are off', () => {
      const previous = config.featureToggles.alertingUIUseBackendFilters;
      config.featureToggles.alertingUIUseBackendFilters = false;
      try {
        const filter = searchFilter('=~', NESTED_QUANTIFIER);
        const rule = mockPromAlertingRule({ name: 'planted', labels: { severity: REPEATED_LABEL } });
        const { frontendFilter } = getGrafanaFilter(filter);

        const matched = elapsedNonMatch(() => frontendFilter.ruleMatches(rule));
        expect(matched).toBe(false);
      } finally {
        config.featureToggles.alertingUIUseBackendFilters = previous;
      }
    });
  });

  describe('notification policy matching', () => {
    const repeatedAlert = (): AlertmanagerAlert => ({
      labels: { severity: REPEATED_LABEL },
      annotations: {},
      startsAt: '2024-01-01T00:00:00Z',
      endsAt: '2024-01-01T01:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      fingerprint: 'fp',
      receivers: [{ name: 'default' }],
      status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] },
    });

    it('matches stored policy matchers against alert groups without backtracking', () => {
      const root: RouteWithID = {
        id: 'root',
        receiver: 'default',
        matchers: [`severity=~${NESTED_QUANTIFIER}`],
        routes: [],
      };
      const groups: AlertmanagerGroup[] = [{ labels: {}, receiver: { name: 'default' }, alerts: [repeatedAlert()] }];

      const matched = elapsedNonMatch(() => {
        const grouped = routeGroupsMatcher.getRouteGroupsMap(root, groups);
        return (grouped.get('root') ?? []).some((group) => group.alerts.length > 0);
      });
      expect(matched).toBe(false);
    });

    it('matches routing-preview instances against a stored regex matcher without backtracking', () => {
      const root: RouteWithID = {
        id: 'root',
        receiver: 'default',
        object_matchers: [['severity', MatcherOperator.regex, NESTED_QUANTIFIER]],
        routes: [],
      };

      const matched = elapsedNonMatch(() => {
        const results = routeGroupsMatcher.matchInstancesToRoutes(root, [{ severity: REPEATED_LABEL }]);
        return results.some((result) => result.matchedRoutes.length > 0);
      });
      expect(matched).toBe(false);
    });
  });

  describe('label filters that parse a PromQL matcher string', () => {
    it('filters state history records without backtracking', () => {
      const stateHistory = {
        data: {
          values: [
            [1_700_000_000_000],
            [{ previous: 'Normal', current: 'Alerting', labels: { severity: REPEATED_LABEL } }],
          ],
        },
      } as DataFrameJSON;

      const matched = elapsedNonMatch(
        () => ruleHistoryToRecords(stateHistory, { labels: `severity=~${NESTED_QUANTIFIER}` }).historyRecords.length > 0
      );
      expect(matched).toBe(false);
    });

    it('filters rule labels from a PromQL matcher string without backtracking', () => {
      const matchers = promqlMatchers('=~', NESTED_QUANTIFIER);
      const matched = elapsedNonMatch(() => labelsMatchMatchers({ severity: REPEATED_LABEL }, matchers));
      expect(matched).toBe(false);
    });
  });
});
