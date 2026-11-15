import userEvent from '@testing-library/user-event';
import { render, screen } from 'test/test-utils';

import { AlertState } from 'app/plugins/datasource/alertmanager/types';
import { AccessControlAction } from 'app/types/accessControl';

import {
  EXTERNAL_AM_VISIBILITY_PERMISSION,
  GRAFANA_AM_VISIBILITY_PERMISSION,
  setupGrafanaAlertmanager,
  setupMimirAlertmanager,
} from '../../hooks/abilities/alertmanager/abilityTestUtils';
import { setupMswServer } from '../../mockApi';
import { grantUserPermissions, mockAlertmanagerAlert } from '../../mocks';
import { AlertmanagerProvider } from '../../state/AlertmanagerContext';

import { AlertDetails } from './AlertDetails';
import { AlertGroupAlertsTable } from './AlertGroupAlertsTable';

setupMswServer();

function renderAlertDetails(alert: ReturnType<typeof mockAlertmanagerAlert>, alertManagerSourceName: string) {
  return render(
    <AlertmanagerProvider accessType="notification" alertmanagerSourceName={alertManagerSourceName}>
      <AlertDetails alert={alert} alertManagerSourceName={alertManagerSourceName} />
    </AlertmanagerProvider>
  );
}

describe('AlertDetails', () => {
  describe('Silence button — Active alert', () => {
    it('shows Silence button when user can create silences', () => {
      const amSource = setupGrafanaAlertmanager();
      grantUserPermissions([GRAFANA_AM_VISIBILITY_PERMISSION, AccessControlAction.AlertingInstanceCreate]);
      const alert = mockAlertmanagerAlert({ status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] } });

      renderAlertDetails(alert, amSource);

      expect(screen.getByRole('link', { name: /silence/i })).toBeInTheDocument();
    });

    it('hides Silence button when user has no silence create permission', () => {
      const amSource = setupGrafanaAlertmanager();
      grantUserPermissions([GRAFANA_AM_VISIBILITY_PERMISSION]);
      const alert = mockAlertmanagerAlert({ status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] } });

      renderAlertDetails(alert, amSource);

      expect(screen.queryByRole('link', { name: /silence/i })).not.toBeInTheDocument();
    });
  });

  describe('Manage silences button — Suppressed alert', () => {
    it('shows Manage silences button when user can create silences', () => {
      const amSource = setupGrafanaAlertmanager();
      grantUserPermissions([GRAFANA_AM_VISIBILITY_PERMISSION, AccessControlAction.AlertingInstanceCreate]);
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Suppressed, silencedBy: ['abc123'], inhibitedBy: [] },
      });

      renderAlertDetails(alert, amSource);

      expect(screen.getByRole('link', { name: /manage silences/i })).toBeInTheDocument();
    });

    it('shows Manage silences button when user can update silences but not create', () => {
      const amSource = setupGrafanaAlertmanager();
      grantUserPermissions([GRAFANA_AM_VISIBILITY_PERMISSION, AccessControlAction.AlertingInstanceUpdate]);
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Suppressed, silencedBy: ['abc123'], inhibitedBy: [] },
      });

      renderAlertDetails(alert, amSource);

      expect(screen.getByRole('link', { name: /manage silences/i })).toBeInTheDocument();
    });

    it('hides Manage silences button when user has neither create nor update silence permission', () => {
      const amSource = setupGrafanaAlertmanager();
      grantUserPermissions([GRAFANA_AM_VISIBILITY_PERMISSION]);
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Suppressed, silencedBy: ['abc123'], inhibitedBy: [] },
      });

      renderAlertDetails(alert, amSource);

      expect(screen.queryByRole('link', { name: /manage silences/i })).not.toBeInTheDocument();
    });
  });

  describe('See alert rule button — Grafana source', () => {
    it('shows See alert rule button when user has rule read permission', () => {
      const amSource = setupGrafanaAlertmanager();
      grantUserPermissions([GRAFANA_AM_VISIBILITY_PERMISSION, AccessControlAction.AlertingRuleRead]);
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] },
        generatorURL: 'https://play.grafana.com/alerting/grafana/rule/123/view',
      });

      renderAlertDetails(alert, amSource);

      expect(screen.getByRole('link', { name: /see alert rule/i })).toHaveAttribute(
        'href',
        'https://play.grafana.com/alerting/grafana/rule/123/view'
      );
    });

    it('hides See alert rule button when user lacks rule read permission', () => {
      const amSource = setupGrafanaAlertmanager();
      grantUserPermissions([GRAFANA_AM_VISIBILITY_PERMISSION]);
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] },
        generatorURL: 'https://play.grafana.com/alerting/grafana/rule/123/view',
      });

      renderAlertDetails(alert, amSource);

      expect(screen.queryByRole('link', { name: /see alert rule/i })).not.toBeInTheDocument();
    });
  });

  describe('See source button — external source', () => {
    it('always shows See source button regardless of rule read permission', () => {
      const amSource = setupMimirAlertmanager();
      grantUserPermissions([EXTERNAL_AM_VISIBILITY_PERMISSION]);
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] },
        generatorURL: 'https://external-alertmanager.example.com',
      });

      renderAlertDetails(alert, amSource);

      expect(screen.getByRole('link', { name: /see source/i })).toBeInTheDocument();
    });

    it('keeps a generator URL on another host and names that host on the button', () => {
      const amSource = setupMimirAlertmanager();
      grantUserPermissions([EXTERNAL_AM_VISIBILITY_PERMISSION]);
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] },
        generatorURL: 'http://alertmanager.example:9093/graph?g0.expr=up',
      });

      renderAlertDetails(alert, amSource);

      const link = screen.getByRole('link', { name: /see source/i });
      expect(link).toHaveAttribute('href', 'http://alertmanager.example:9093/graph?g0.expr=up');
      expect(link).toHaveAccessibleName(/alertmanager\.example/i);
    });

    it.each([
      ['relative logout path', '/logout'],
      ['same-origin logout URL', `${window.location.origin}/logout`],
      ['same-origin org switch', `${window.location.origin}/profile/switch-org/2`],
      ['protocol-relative logout', `//${window.location.host}/logout`],
    ])('does not navigate a viewer to %s', async (_name, generatorURL) => {
      const amSource = setupMimirAlertmanager();
      grantUserPermissions([EXTERNAL_AM_VISIBILITY_PERMISSION]);
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] },
        generatorURL,
      });

      render(
        <AlertmanagerProvider accessType="notification" alertmanagerSourceName={amSource}>
          <AlertGroupAlertsTable alerts={[alert]} alertManagerSourceName={amSource} />
        </AlertmanagerProvider>
      );
      await userEvent.click(screen.getByRole('button', { name: /expand row/i }));

      const link = screen.queryByRole('link', { name: /see source/i });
      if (link) {
        const href = link.getAttribute('href') ?? '';
        const resolved = new URL(href, window.location.href);
        expect(resolved.origin).not.toBe(window.location.origin);
        expect(resolved.pathname).not.toBe('/logout');
        expect(resolved.pathname).not.toBe('/profile/switch-org/2');
      }
    });

    it('does not turn a same-origin annotation URL into a navigation', () => {
      const amSource = setupMimirAlertmanager();
      grantUserPermissions([EXTERNAL_AM_VISIBILITY_PERMISSION]);
      const logoutURL = `${window.location.origin}/logout`;
      const alert = mockAlertmanagerAlert({
        status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] },
        generatorURL: undefined,
        annotations: { summary: logoutURL },
      });

      renderAlertDetails(alert, amSource);

      const link = screen.queryByRole('link', { name: logoutURL });
      if (link) {
        const resolved = new URL(link.getAttribute('href') ?? '', window.location.href);
        expect(resolved.origin).not.toBe(window.location.origin);
      }
    });
  });

});
