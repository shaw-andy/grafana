import { render, screen } from 'test/test-utils';

import { type CreateNotificationsqueryalertsNotificationEntryAlert } from '@grafana/api-clients/rtkq/historian.alerting/v0alpha1';
import { config, setPluginLinksHook } from '@grafana/runtime';
import server from '@grafana/test-utils/server';
import { type AlertManagerDataSourceJsonData } from 'app/plugins/datasource/alertmanager/types';
import { AccessControlAction } from 'app/types/accessControl';
import { type Alert } from 'app/types/unified-alerting';
import { PromAlertingRuleState } from 'app/types/unified-alerting-dto';

import {
  GRAFANA_AM_VISIBILITY_PERMISSION,
  setupGrafanaAlertmanager,
} from '../../hooks/abilities/alertmanager/abilityTestUtils';
import { mockAlertRuleApi, setupMswServer } from '../../mockApi';
import {
  getGrafanaRule,
  grantUserPermissions,
  mockAlertWithState,
  mockAlertmanagerAlert,
  mockCombinedRule,
  mockDataSource,
  mockPromAlertingRule,
} from '../../mocks';
import { grafanaRulerRule } from '../../mocks/grafanaRulerApi';
import { AlertsListSection, OverviewSection } from '../../notifications/NotificationDetailAlerts';
import { AlertmanagerProvider } from '../../state/AlertmanagerContext';
import { grantPermissionsHelper } from '../../test/test-utils';
import { setupDataSources } from '../../testSetup/datasources';
import { Annotation } from '../../utils/constants';
import { DataSourceType } from '../../utils/datasource';
import * as ruleId from '../../utils/rule-id';
import { AnnotationDetailsField } from '../AnnotationDetailsField';
import { AlertDetails } from '../alert-groups/AlertDetails';
import { AlertInstanceDetails } from '../rules/AlertInstanceDetails';

import { AnnotationValue, Details } from './Details';
import { AlertRuleProvider } from './RuleContext';
import RuleViewer from './RuleViewer';

setupMswServer();

setPluginLinksHook(() => ({
  links: [],
  isLoading: false,
}));

// Paths Grafana's router serves as session actions. Match trims a trailing slash
// (pkg/web/tree.go Match) and the fast path compares the decoded URL.Path
// (pkg/web/router.go ServeHTTP), so percent-decoding is part of the request the
// browser actually makes.
const SESSION_PATH = /^\/(?:logout|profile\/switch-org\/\d+)$/;

function decodedRequestPath(pathname: string): string | undefined {
  let path = pathname;
  try {
    path = decodeURIComponent(path);
  } catch {
    return undefined;
  }
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }
  return path;
}

function resolvesToSessionAction(href: string): boolean {
  let url: URL;
  try {
    url = new URL(href, window.location.href);
  } catch {
    return false;
  }
  if (url.host !== window.location.host) {
    return false;
  }
  const path = decodedRequestPath(url.pathname);
  return path !== undefined && SESSION_PATH.test(path);
}

function sessionActionHrefs(): string[] {
  return screen
    .queryAllByRole('link')
    .map((anchor) => anchor.getAttribute('href') ?? '')
    .filter((href) => href !== '' && resolvesToSessionAction(href));
}

function expectVisibleWithoutSessionNavigation(text: string) {
  expect(screen.getAllByText(text).length).toBeGreaterThan(0);
  expect(sessionActionHrefs()).toEqual([]);
}

function sameServerUrls(): Record<string, string> {
  const origin = window.location.origin;
  const otherScheme = origin.startsWith('https:')
    ? origin.replace(/^https:/, 'http:')
    : origin.replace(/^http:/, 'https:');
  return {
    logout: `${origin}/logout`,
    logoutQuery: `${origin}/logout?next=%2Flogin`,
    logoutDots: `${origin}/profile/../logout`,
    logoutEncoded: `${origin}/%6cogout`,
    logoutSlash: `${origin}/logout/`,
    switchOrg: `${origin}/profile/switch-org/2`,
    switchOrgEncoded: `${origin}/profile/switch-org/%32`,
    switchOrgDots: `${origin}/foo/../profile/switch-org/9`,
    otherSchemeLogout: `${otherScheme}/logout`,
  };
}

describe('annotation text must not navigate to a session action on this server', () => {
  const urls = sameServerUrls();

  describe('AnnotationValue', () => {
    it.each(Object.entries(urls))('keeps %s annotation text from navigating (%s)', (_name, value) => {
      render(<AnnotationValue value={value} />);
      expectVisibleWithoutSessionNavigation(value);
    });
  });

  describe('rule viewer Details', () => {
    beforeAll(() => {
      setupDataSources();
    });

    it('does not link summary, description, runbook, or custom annotations at session paths', () => {
      const annotations = {
        [Annotation.summary]: urls.logout,
        [Annotation.description]: urls.logoutDots,
        [Annotation.runbookURL]: urls.switchOrg,
        custom_note: urls.logoutEncoded,
      };
      const rule = mockCombinedRule({
        promRule: mockPromAlertingRule({ annotations }),
      });

      render(<Details rule={rule} />);

      expectVisibleWithoutSessionNavigation(urls.logout);
      expectVisibleWithoutSessionNavigation(urls.logoutDots);
      expectVisibleWithoutSessionNavigation(urls.switchOrg);
      expectVisibleWithoutSessionNavigation(urls.logoutEncoded);
    });
  });

  describe('AnnotationDetailsField', () => {
    it('does not link summary, runbook, or custom annotation values at session paths', () => {
      render(
        <>
          <AnnotationDetailsField annotationKey={Annotation.summary} value={urls.logoutQuery} />
          <AnnotationDetailsField annotationKey={Annotation.description} value={urls.logout} />
          <AnnotationDetailsField annotationKey="message" value={urls.switchOrg} />
          <AnnotationDetailsField annotationKey={Annotation.runbookURL} value={urls.switchOrgEncoded} />
          <AnnotationDetailsField annotationKey="custom_note" value={urls.logoutEncoded} />
        </>
      );

      expectVisibleWithoutSessionNavigation(urls.logoutQuery);
      expectVisibleWithoutSessionNavigation(urls.logout);
      expectVisibleWithoutSessionNavigation(urls.switchOrg);
      expectVisibleWithoutSessionNavigation(urls.switchOrgEncoded);
      expectVisibleWithoutSessionNavigation(urls.logoutEncoded);
    });
  });

  describe('AlertInstanceDetails', () => {
    it('does not link instance annotations at session paths', () => {
      const instance: Alert = {
        ...mockAlertWithState(PromAlertingRuleState.Firing),
        annotations: {
          [Annotation.summary]: urls.logout,
          [Annotation.runbookURL]: urls.switchOrgDots,
          custom_note: urls.otherSchemeLogout,
        },
      };

      render(<AlertInstanceDetails instance={instance} />);

      expectVisibleWithoutSessionNavigation(urls.logout);
      expectVisibleWithoutSessionNavigation(urls.switchOrgDots);
      expectVisibleWithoutSessionNavigation(urls.otherSchemeLogout);
    });
  });

  describe('AlertDetails', () => {
    it('does not link alertmanager alert annotations at session paths', () => {
      const source = setupGrafanaAlertmanager();
      grantUserPermissions([GRAFANA_AM_VISIBILITY_PERMISSION]);
      const alert = mockAlertmanagerAlert({
        generatorURL: 'https://play.grafana.com/explore',
        annotations: {
          [Annotation.summary]: urls.logoutSlash,
          [Annotation.description]: urls.logout,
          custom_note: urls.switchOrg,
        },
      });

      render(
        <AlertmanagerProvider accessType="notification" alertmanagerSourceName={source}>
          <AlertDetails alert={alert} alertManagerSourceName={source} />
        </AlertmanagerProvider>
      );

      expectVisibleWithoutSessionNavigation(urls.logoutSlash);
      expectVisibleWithoutSessionNavigation(urls.logout);
      expectVisibleWithoutSessionNavigation(urls.switchOrg);
    });
  });

  describe('notification detail alerts', () => {
    function alertEntry(annotations: Record<string, string>): CreateNotificationsqueryalertsNotificationEntryAlert {
      return {
        annotations,
        labels: { alertname: 'cpu' },
        startsAt: '2021-06-21T17:25:28.562Z',
        endsAt: '2021-06-22T21:49:28.562Z',
        status: 'firing',
      };
    }

    it('does not link per-alert annotations at session paths', () => {
      render(
        <AlertsListSection
          isLoading={false}
          groupLabels={{}}
          alerts={[
            alertEntry({
              [Annotation.summary]: urls.logout,
              [Annotation.description]: urls.logoutDots,
              custom_note: urls.switchOrg,
            }),
          ]}
        />
      );

      expectVisibleWithoutSessionNavigation(urls.logout);
      expectVisibleWithoutSessionNavigation(urls.logoutDots);
      expectVisibleWithoutSessionNavigation(urls.switchOrg);
    });

    it('does not link common annotations at session paths', () => {
      const annotations = {
        [Annotation.summary]: urls.logoutEncoded,
        [Annotation.runbookURL]: urls.switchOrgEncoded,
      };
      render(
        <OverviewSection
          isLoading={false}
          groupLabels={{}}
          alerts={[alertEntry(annotations), alertEntry(annotations)]}
        />
      );

      expectVisibleWithoutSessionNavigation(urls.logoutEncoded);
      expectVisibleWithoutSessionNavigation(urls.switchOrgEncoded);
    });
  });

  describe('RuleViewer', () => {
    const dataSources = {
      am: mockDataSource<AlertManagerDataSourceJsonData>(
        {
          name: 'Alertmanager',
          type: DataSourceType.Alertmanager,
          jsonData: { handleGrafanaManagedAlerts: true },
        },
        { module: 'core:plugin/alertmanager' }
      ),
    };

    beforeAll(() => {
      mockAlertRuleApi(server);
    });

    beforeEach(() => {
      setupDataSources(dataSources.am);
      grantPermissionsHelper([AccessControlAction.AlertingRuleRead, AccessControlAction.AlertingRuleUpdate]);
    });

    it('does not link the runbook or sidebar annotations at session paths', async () => {
      const rule = getGrafanaRule(
        {
          name: 'Session link rule',
          uid: grafanaRulerRule.grafana_alert.uid,
          annotations: {
            [Annotation.summary]: urls.logout,
            [Annotation.description]: urls.logoutDots,
            [Annotation.runbookURL]: urls.switchOrg,
            custom_note: urls.logoutEncoded,
          },
          promRule: mockPromAlertingRule({
            annotations: {
              [Annotation.summary]: urls.logout,
              [Annotation.description]: urls.logoutDots,
              [Annotation.runbookURL]: urls.switchOrg,
              custom_note: urls.logoutEncoded,
            },
          }),
          group: { name: 'session-group', rules: [], totals: {} },
        },
        { uid: grafanaRulerRule.grafana_alert.uid }
      );
      const identifier = ruleId.fromCombinedRule('grafana', rule);

      render(
        <AlertRuleProvider identifier={identifier} rule={rule}>
          <RuleViewer />
        </AlertRuleProvider>,
        {
          historyOptions: {
            initialEntries: [`/alerting/grafana/${ruleId.stringifyIdentifier(identifier)}/view`],
          },
        }
      );

      expect(await screen.findByRole('heading', { name: 'Session link rule' })).toBeInTheDocument();
      expect(sessionActionHrefs()).toEqual([]);
      expect(screen.getAllByText(urls.switchOrg).length).toBeGreaterThan(0);
      // appSubUrl is empty in this test runtime; the linked path is the server root.
      expect(config.appSubUrl).toBe('');
    });
  });
});
