import { HttpResponse, http } from 'msw';
import { render, screen, userEvent, waitFor } from 'test/test-utils';

import { API_GROUP, API_VERSION, type TimeInterval } from '@grafana/api-clients/rtkq/notifications.alerting/v1beta1';
import server from '@grafana/test-utils/server';
import { AccessControlAction } from 'app/types/accessControl';

import { setupMswServer } from '../../mockApi';
import { grantUserPermissions } from '../../mocks';
import { listNamespacedTimeIntervalHandler } from '../../mocks/server/handlers/k8s/timeIntervals.k8s';
import { getK8sResponse } from '../../mocks/server/utils';
import { AlertmanagerProvider } from '../../state/AlertmanagerContext';
import { KnownProvenance } from '../../types/knownProvenance';
import { GRAFANA_RULES_SOURCE_NAME } from '../../utils/datasource';
import { K8sAnnotations } from '../../utils/k8s/constants';

import { TimeIntervalsTable } from './MuteTimingsTable';

// Five parent-directory segments climb out of api/v1/provisioning/mute-timings/ to the
// origin root for a base href of "/" or "/grafana/", and the "?" starts the query so the
// "/export/" suffix is not part of the path.
const TRAVERSAL_NAME = '../../../../../logout?';
const ENCODED_TRAVERSAL_SEGMENT = '..%2F..%2F..%2F..%2F..%2Flogout%3F';

const EXPORT_CASES = [
  {
    baseHref: '/',
    pathname: `/api/v1/provisioning/mute-timings/${ENCODED_TRAVERSAL_SEGMENT}/export/`,
  },
  {
    baseHref: '/grafana/',
    pathname: `/grafana/api/v1/provisioning/mute-timings/${ENCODED_TRAVERSAL_SEGMENT}/export/`,
  },
];

setupMswServer();

function setDocumentBase(href: string) {
  let base = document.querySelector('base');
  if (!base) {
    base = document.createElement('base');
    document.head.appendChild(base);
  }
  base.setAttribute('href', href);
}

function listedInterval(specName: string): TimeInterval {
  return {
    apiVersion: `${API_GROUP}/${API_VERSION}`,
    kind: 'TimeInterval',
    metadata: {
      annotations: {
        [K8sAnnotations.Provenance]: KnownProvenance.None,
        [K8sAnnotations.CanUse]: 'true',
      },
      name: 'safe-metadata-name',
      uid: 'interval-uid',
      namespace: 'default',
      resourceVersion: '1',
    },
    spec: { name: specName, time_intervals: [] },
  };
}

function renderTable() {
  return render(
    <AlertmanagerProvider accessType="notification" alertmanagerSourceName={GRAFANA_RULES_SOURCE_NAME}>
      <TimeIntervalsTable />
    </AlertmanagerProvider>
  );
}

describe('mute timing export path', () => {
  let calls: Array<{ url: string; credentials: RequestCredentials; method: string }>;

  beforeEach(() => {
    grantUserPermissions([
      AccessControlAction.AlertingNotificationsRead,
      AccessControlAction.AlertingNotificationsWrite,
    ]);
    server.use(
      http.get(listNamespacedTimeIntervalHandler().info.path, () =>
        HttpResponse.json(getK8sResponse<TimeInterval>('TimeIntervalList', [listedInterval(TRAVERSAL_NAME)]))
      ),
      // The export request is rewritten onto this route. Handle it so the test observes the
      // request instead of failing on an unmatched-request log.
      http.get('/logout', () => HttpResponse.text(''))
    );

    calls = [];
    const originalFetch = window.fetch.bind(window);
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(window, 'fetch').mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const raw = input instanceof Request ? input.url : input.toString();
      const request = new Request(raw, init);
      calls.push({ url: request.url, credentials: request.credentials, method: request.method });
      return originalFetch(input, init);
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
    document.querySelector('base')?.remove();
  });

  it.each(EXPORT_CASES)(
    'keeps the listed name in one export path segment when the document base is $baseHref',
    async ({ baseHref, pathname }) => {
      setDocumentBase(baseHref);
      const user = userEvent.setup();
      renderTable();

      expect(await screen.findByText(TRAVERSAL_NAME)).toBeInTheDocument();
      await user.click(await screen.findByTestId('export'));

      const parsed = (value: string) => new URL(value, document.baseURI);
      const isExportAttempt = (call: { url: string }) => {
        const path = parsed(call.url).pathname;
        return path.includes('/provisioning/mute-timings/') || path === '/logout';
      };

      await waitFor(() => {
        expect(calls.filter(isExportAttempt).map((call) => parsed(call.url).href)).not.toEqual([]);
      });

      const exportCall = calls.find(isExportAttempt);
      const url = parsed(exportCall!.url);

      expect({
        method: exportCall!.method,
        pathname: url.pathname,
        search: url.search,
        credentials: exportCall!.credentials,
      }).toEqual({
        method: 'GET',
        pathname,
        search: '?format=yaml',
        credentials: 'same-origin',
      });
    }
  );
});
