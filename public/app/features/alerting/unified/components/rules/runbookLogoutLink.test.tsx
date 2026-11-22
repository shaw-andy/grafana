import { render, screen } from 'test/test-utils';

import { config, setPluginLinksHook } from '@grafana/runtime';

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  useReturnToPrevious: jest.fn(),
}));

import server from '@grafana/test-utils/server';
import { AccessControlAction } from 'app/types/accessControl';
import { type CombinedRule } from 'app/types/unified-alerting';

import { mockAlertRuleApi, setupMswServer } from '../../mockApi';
import { getGrafanaRule, grantUserPermissions } from '../../mocks';
import { Annotation } from '../../utils/constants';
import { AnnotationDetailsField } from '../AnnotationDetailsField';
import { AnnotationValue } from '../rule-viewer/Details';

setPluginLinksHook(() => ({ links: [], isLoading: false }));

import RuleDetailsButtons from './RuleDetailsButtons';

const ROOT_APP_URL = 'http://grafana.example:3000/';
const SUBPATH_APP_URL = 'http://grafana.example:3000/grafana/';

function withAppUrl(appUrl: string, appSubUrl: string, run: () => void) {
  const previousAppUrl = config.appUrl;
  const previousAppSubUrl = config.appSubUrl;
  config.appUrl = appUrl;
  config.appSubUrl = appSubUrl;
  try {
    run();
  } finally {
    config.appUrl = previousAppUrl;
    config.appSubUrl = previousAppSubUrl;
  }
}

function logoutURL(appUrl: string): URL {
  const app = new URL(appUrl);
  const path = `${app.pathname.replace(/\/$/, '')}/logout`;
  return new URL(path, `${app.origin}/`);
}

function navigatesToLogout(href: string | null, appUrl: string): boolean {
  if (!href) {
    return false;
  }
  let resolved: URL;
  try {
    resolved = new URL(href, appUrl);
  } catch {
    return false;
  }
  const logout = logoutURL(appUrl);
  const path = decodeURIComponent(resolved.pathname).replace(/\/+$/, '') || '/';
  const logoutPath = decodeURIComponent(logout.pathname).replace(/\/+$/, '') || '/';
  return resolved.origin === logout.origin && path === logoutPath;
}

function expectNoLogoutAnchor(appUrl: string) {
  const hrefs = screen
    .queryAllByRole('link')
    .map((link) => link.getAttribute('href'))
    .filter((href): href is string => href !== null && navigatesToLogout(href, appUrl));
  expect(hrefs).toEqual([]);
}

function grafanaRule(runbook: string): CombinedRule {
  return getGrafanaRule({
    name: 'CPU high',
    annotations: { [Annotation.runbookURL]: runbook },
  });
}

describe('runbook links must not open this Grafana logout URL', () => {
  const previousAppUrl = config.appUrl;
  const previousAppSubUrl = config.appSubUrl;

  setupMswServer();
  mockAlertRuleApi(server);

  beforeEach(() => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    config.appUrl = ROOT_APP_URL;
    config.appSubUrl = '';
    grantUserPermissions([
      AccessControlAction.AlertingRuleRead,
      AccessControlAction.AlertingRuleUpdate,
      AccessControlAction.FoldersRead,
    ]);
  });

  afterEach(() => {
    config.appUrl = previousAppUrl;
    config.appSubUrl = previousAppSubUrl;
  });

  describe('rule list View runbook button', () => {
    const cases = [
      { source: 'grafana', rule: grafanaRule, runbook: '/logout' },
      { source: 'grafana', rule: grafanaRule, runbook: '//grafana.example:3000/logout' },
      { source: 'grafana', rule: grafanaRule, runbook: 'http://grafana.example:3000/logout' },
      { source: 'grafana', rule: grafanaRule, runbook: 'http://grafana.example:3000/logout?orgId=1' },
      { source: 'grafana', rule: grafanaRule, runbook: 'http://grafana.example:3000/log%6Fut' },
      { source: 'grafana', rule: grafanaRule, runbook: '&#47;logout' },
    ];

    it.each(cases)('$source rule does not link $runbook', ({ rule, runbook }) => {
      render(<RuleDetailsButtons rule={rule(runbook)} rulesSource={rule(runbook).namespace.rulesSource} />);
      expectNoLogoutAnchor(ROOT_APP_URL);
    });

    it('does not link the subpath logout URL', () => {
      withAppUrl(SUBPATH_APP_URL, '/grafana', () => {
        const rule = grafanaRule('http://grafana.example:3000/grafana/logout');
        render(<RuleDetailsButtons rule={rule} rulesSource={rule.namespace.rulesSource} />);
        expectNoLogoutAnchor(SUBPATH_APP_URL);
      });
    });

    it('does not link a site-relative subpath logout', () => {
      withAppUrl(SUBPATH_APP_URL, '/grafana', () => {
        const rule = grafanaRule('/grafana/logout');
        render(<RuleDetailsButtons rule={rule} rulesSource={rule.namespace.rulesSource} />);
        expectNoLogoutAnchor(SUBPATH_APP_URL);
      });
    });

    it('keeps an external https runbook on the View runbook button', () => {
      const runbook = 'https://runbooks.example/oncall';
      const rule = grafanaRule(runbook);
      render(<RuleDetailsButtons rule={rule} rulesSource={rule.namespace.rulesSource} />);
      expect(screen.getByRole('link', { name: /view runbook/i })).toHaveAttribute('href', runbook);
    });

    it('does not put a javascript runbook in the button', () => {
      const rule = grafanaRule('javascript:alert(1)');
      render(<RuleDetailsButtons rule={rule} rulesSource={rule.namespace.rulesSource} />);
      expect(screen.getByRole('link', { name: /view runbook/i })).toHaveAttribute('href', 'about:blank');
    });
  });

  describe('annotation text that is auto-linked', () => {
    it('does not link a same-origin logout runbook from the annotation list', () => {
      const runbook = 'http://grafana.example:3000/logout';
      render(<AnnotationDetailsField annotationKey={Annotation.runbookURL} value={runbook} />);
      expectNoLogoutAnchor(ROOT_APP_URL);
    });

    it('does not link a same-origin logout annotation from the rule viewer or state history', () => {
      const runbook = 'http://grafana.example:3000/logout';
      render(<AnnotationValue value={runbook} />);
      expectNoLogoutAnchor(ROOT_APP_URL);
    });

    it('keeps an external https annotation as a link', () => {
      const runbook = 'https://runbooks.example/oncall';
      render(<AnnotationValue value={runbook} />);
      expect(screen.getByRole('link', { name: runbook })).toHaveAttribute('href', runbook);
    });
  });
});
