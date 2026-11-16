import { type ReactElement } from 'react';
import { Route, Routes } from 'react-router-dom-v5-compat';
import { render, screen, waitFor } from 'test/test-utils';

import { setBackendSrv } from '@grafana/runtime';
import { backendSrv } from 'app/core/services/backend_srv';
import { AccessControlAction } from 'app/types/accessControl';

import { grantUserPermissions } from '../../mocks';
import NotificationTemplates from '../../Templates';
import PolicyPage from '../notification-policies/PolicyPage';

import EditContactPoint from './EditContactPoint';

// Eight parent segments clear
// /apis/<group>/<version>/namespaces/<namespace>/<resource>/ regardless of which of those resources is addressed.
const PARENT_SEGMENTS = '%252e%252e%252f'.repeat(8);

type RecordedRequest = {
  raw: string;
  path: string;
  method: string;
  credentials: RequestCredentials;
};

const recorded: RecordedRequest[] = [];

function requestTarget(input: RequestInfo | URL): { raw: string; path: string } {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  // Same resolution the browser applies to fetch() against <base href="/">.
  return { raw, path: new URL(raw, document.baseURI).pathname };
}

beforeAll(() => {
  setBackendSrv(backendSrv);
});

beforeEach(() => {
  recorded.length = 0;
  document.head.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.href = '/';
  document.head.appendChild(base);

  jest.spyOn(global, 'fetch').mockImplementation(async (input, init) => {
    const { raw, path } = requestTarget(input);
    const method = (
      init?.method ?? (typeof input !== 'string' && !(input instanceof URL) ? input.method : 'GET')
    ).toUpperCase();
    const credentials =
      init?.credentials ??
      (typeof input !== 'string' && !(input instanceof URL) ? input.credentials : undefined) ??
      'same-origin';
    recorded.push({ raw, path, method, credentials });
    // Answer in the test. Letting the relative URL reach jsdom's XHR logs a network error
    // before the browser would have resolved the parent segments.
    return new Response(JSON.stringify({ message: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  });
});

afterEach(() => {
  jest.mocked(global.fetch).mockRestore();
  document.head.querySelectorAll('base').forEach((node) => node.remove());
});

function escapedSessionRequests() {
  return recorded.filter((request) => request.path === '/logout' || request.path.startsWith('/profile/switch-org/'));
}

function expectSessionWasNotSentToAnotherRoute(resource: 'templategroups' | 'receivers' | 'routingtrees') {
  expect(escapedSessionRequests()).toEqual([]);

  const collection = `/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/${resource}/`;
  const reads = recorded.filter(
    (request) => request.raw.includes(`/${resource}/`) || request.path.includes(`/${resource}/`)
  );
  for (const request of reads) {
    expect(request.method).toBe('GET');
    expect(request.credentials).toBe('same-origin');
    // Parent segments must already have been resolved. A request that climbed out of the
    // collection no longer starts with it.
    expect(request.path.startsWith(collection)).toBe(true);
  }
}

async function open(ui: ReactElement, entry: string) {
  render(<Routes>{ui}</Routes>, { historyOptions: { initialEntries: [entry] } });
}

describe('notification name routes', () => {
  it('loads an ordinary template name inside the templategroups collection', async () => {
    grantUserPermissions([AccessControlAction.AlertingTemplatesRead]);

    await open(
      <Route path="/alerting/notifications/templates/*" element={<NotificationTemplates />} />,
      '/alerting/notifications/templates/slack-template/edit'
    );

    await waitFor(() => {
      expect(recorded.some((request) => request.path.includes('/templategroups/slack-template'))).toBe(true);
    });

    expectSessionWasNotSentToAnotherRoute('templategroups');
    expect(recorded.map((request) => request.path)).toContain(
      '/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/templategroups/slack-template'
    );
  });

  it.each([
    ['edit', 'logout', `${PARENT_SEGMENTS}logout`],
    ['edit', 'switch-org', `${PARENT_SEGMENTS}profile%252fswitch-org%252f2`],
    ['duplicate', 'logout', `${PARENT_SEGMENTS}logout`],
    ['duplicate', 'switch-org', `${PARENT_SEGMENTS}profile%252fswitch-org%252f2`],
  ])('template %s page does not follow a double-encoded name to %s', async (action, _target, name) => {
    grantUserPermissions([AccessControlAction.AlertingTemplatesRead]);

    await open(
      <Route path="/alerting/notifications/templates/*" element={<NotificationTemplates />} />,
      `/alerting/notifications/templates/${name}/${action}`
    );

    await waitFor(() => {
      const attempted =
        recorded.some((request) => request.raw.includes('/templategroups/')) ||
        screen.queryByText(/failed to fetch notification template/i) ||
        screen.queryByText(/error loading notification template/i) ||
        screen.queryByText(/invalid request path/i);
      expect(attempted).toBeTruthy();
    });

    expectSessionWasNotSentToAnotherRoute('templategroups');
  });

  it.each([
    ['logout', `${PARENT_SEGMENTS}logout`],
    ['switch-org', `${PARENT_SEGMENTS}profile%252fswitch-org%252f2`],
  ])('contact point edit does not follow a double-encoded name to %s', async (_target, name) => {
    grantUserPermissions([AccessControlAction.AlertingReceiversRead]);

    await open(
      <Route path="/alerting/notifications/receivers/:name/edit" element={<EditContactPoint />} />,
      `/alerting/notifications/receivers/${name}/edit`
    );

    await waitFor(() => {
      const attempted =
        recorded.some((request) => request.raw.includes('/receivers/')) ||
        screen.queryByText(/failed to fetch contact point/i) ||
        screen.queryByText(/invalid request path/i);
      expect(attempted).toBeTruthy();
    });

    expectSessionWasNotSentToAnotherRoute('receivers');
  });

  it.each([
    ['logout', `${PARENT_SEGMENTS}logout`],
    ['switch-org', `${PARENT_SEGMENTS}profile%252fswitch-org%252f2`],
  ])('notification policy edit does not follow a double-encoded name to %s', async (_target, name) => {
    grantUserPermissions([AccessControlAction.AlertingRoutesRead]);

    await open(
      <Route path="/alerting/routes/policy/:name/edit" element={<PolicyPage />} />,
      `/alerting/routes/policy/${name}/edit`
    );

    await waitFor(() => {
      const attempted =
        recorded.some((request) => request.raw.includes('/routingtrees/')) ||
        screen.queryByText(/routing tree not found/i) ||
        screen.queryByText(/invalid request path/i);
      expect(attempted).toBeTruthy();
    });

    expectSessionWasNotSentToAnotherRoute('routingtrees');
  });
});
