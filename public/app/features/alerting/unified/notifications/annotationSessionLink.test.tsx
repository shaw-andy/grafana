import { screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom-v5-compat';
import { render } from 'test/test-utils';

import { type CreateNotificationqueryNotificationEntry } from '@grafana/api-clients/rtkq/historian.alerting/v0alpha1';

import { setupMswServer } from '../mockApi';
import { setHistorianAlerts, setHistorianNotifications } from '../mocks/server/handlers/historian';
import { sessionActionHrefs } from '../testSetup/sessionActionHref';

import { AlertsListSection, OverviewSection } from './NotificationDetailAlerts';
import NotificationDetailPage from './NotificationDetailPage';

setupMswServer();

function originUrl(pathAndQuery: string): string {
  return `${window.location.origin}${pathAndQuery}`;
}

const sessionAnnotationUrls = [
  originUrl('/logout'),
  originUrl('/logout?continue=1'),
  originUrl('/logout/'),
  originUrl('/%6Cogout'),
  originUrl('/profile/switch-org/2'),
  originUrl('/profile/switch-org/%32'),
  originUrl('/profile/switch-org/2/'),
  `HTTP://${window.location.host}/logout`,
  `http://viewer@${window.location.host}/logout`,
  `http://viewer@${window.location.host}/profile/switch-org/2`,
];

function alertWith(annotations: Record<string, string>) {
  return {
    labels: { alertname: 'HighCPU', __alert_rule_uid__: 'rule-1' },
    annotations,
    status: 'firing',
    startsAt: '2026-03-08T11:55:00Z',
    endsAt: '0001-01-01T00:00:00Z',
  };
}

describe('notification annotation session actions', () => {
  it.each(sessionAnnotationUrls)(
    'overview does not link a stored annotation to a session action: %s',
    (annotationUrl) => {
      const { container } = render(
        <OverviewSection
          alerts={[alertWith({ summary: annotationUrl, description: 'cpu is high' })]}
          groupLabels={{}}
          isLoading={false}
        />
      );

      expect(screen.getByText(annotationUrl)).toBeInTheDocument();
      expect(sessionActionHrefs(container)).toEqual([]);
    }
  );

  it.each(sessionAnnotationUrls)(
    'alert list does not link a stored annotation to a session action: %s',
    (annotationUrl) => {
      const { container } = render(
        <AlertsListSection alerts={[alertWith({ runbook_url: annotationUrl })]} groupLabels={{}} isLoading={false} />
      );

      expect(screen.getByText(annotationUrl)).toBeInTheDocument();
      expect(sessionActionHrefs(container)).toEqual([]);
    }
  );

  it('keeps an external annotation link from being treated as a session action', () => {
    const externalUrl = 'https://example.com/logout';
    const { container } = render(
      <AlertsListSection alerts={[alertWith({ summary: externalUrl })]} groupLabels={{}} isLoading={false} />
    );

    expect(screen.getByText(externalUrl)).toBeInTheDocument();
    expect(sessionActionHrefs(container)).toEqual([]);
  });

  it('notification detail page does not link historian alert annotations to logout or organization switch', async () => {
    const logoutUrl = originUrl('/logout');
    const switchOrgUrl = originUrl('/profile/switch-org/2');
    const notification: CreateNotificationqueryNotificationEntry = {
      uuid: 'uuid-session',
      ruleUIDs: ['rule-1'],
      receiver: 'slack-receiver',
      integration: 'slack',
      integrationIndex: 0,
      status: 'firing',
      outcome: 'success',
      duration: 150_000_000,
      alertCount: 1,
      alerts: [],
      groupKey: 'group-key-1',
      groupLabels: { alertname: 'HighCPU' },
      pipelineTime: '2026-03-08T12:00:00Z',
      retry: false,
      timestamp: '2026-03-08T12:00:01Z',
    };
    setHistorianNotifications([notification]);
    setHistorianAlerts([
      alertWith({
        summary: logoutUrl,
        runbook_url: switchOrgUrl,
      }),
    ]);

    const { container } = render(
      <Routes>
        <Route path="/alerting/notifications-history/view/:uuid" element={<NotificationDetailPage />} />
      </Routes>,
      {
        historyOptions: {
          initialEntries: [
            `/alerting/notifications-history/view/uuid-session?ts=${new Date(notification.timestamp).getTime()}`,
          ],
        },
      }
    );

    expect(await screen.findByText(logoutUrl)).toBeInTheDocument();
    expect(screen.getByText(switchOrgUrl)).toBeInTheDocument();
    expect(sessionActionHrefs(container)).toEqual([]);
  });
});
