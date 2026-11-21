import { of } from 'rxjs';
import { render, screen, waitFor, within } from 'test/test-utils';

import { base64UrlEncode } from '@grafana/alerting';
import { setBackendSrv } from '@grafana/runtime';
import { BackendSrv, type BackendSrvDependencies } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';
import { setupMswServer } from 'app/features/alerting/unified/mockApi';
import { grantUserPermissions } from 'app/features/alerting/unified/mocks';
import { AlertmanagerProvider } from 'app/features/alerting/unified/state/AlertmanagerContext';
import { KnownProvenance } from 'app/features/alerting/unified/types/knownProvenance';
import { K8sAnnotations } from 'app/features/alerting/unified/utils/k8s/constants';
import { GRAFANA_RULES_SOURCE_NAME } from 'app/features/alerting/unified/utils/datasource';
import { AccessControlAction } from 'app/types/accessControl';

import { TimeIntervalsTable } from './MuteTimingsTable';

interface CapturedFetch {
  url: string;
  credentials?: RequestCredentials;
  method?: string;
}

setupMswServer();

// index.html sets <base href="[[.AppSubUrl]]/">. Fetch resolves the relative export URL against that base.
function setBaseHref(href: string) {
  document.head.querySelectorAll('base').forEach((node) => node.remove());
  const base = document.createElement('base');
  base.href = href;
  document.head.appendChild(base);
}

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function installCapturingBackend(displayName: string, captured: CapturedFetch[]) {
  const interval = {
    apiVersion: 'notifications.alerting.grafana.app/v1beta1',
    kind: 'TimeInterval',
    metadata: {
      annotations: {
        [K8sAnnotations.Provenance]: KnownProvenance.None,
        [K8sAnnotations.CanUse]: 'true',
      },
      name: base64UrlEncode(displayName),
      uid: 'interval-uid',
      namespace: 'default',
      resourceVersion: '1',
    },
    spec: { name: displayName, time_intervals: [] },
  };

  const backendSrv = new BackendSrv({
    fromFetch: (input, init) => {
      const url = typeof input === 'string' ? input : input.url;
      captured.push({ url, credentials: init?.credentials, method: init?.method });
      if (url.includes('/timeintervals')) {
        return of(jsonResponse({ items: [interval] }));
      }
      return of(new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }));
    },
    contextSrv,
  } as BackendSrvDependencies);
  setBackendSrv(backendSrv);
}

function exportRequests(captured: CapturedFetch[]) {
  return captured.filter((call) => call.url.includes('/provisioning/mute-timings/'));
}

function resolvedPath(url: string) {
  return new URL(url, document.baseURI);
}

const readerWhoCanExport = [
  AccessControlAction.AlertingNotificationsRead,
  AccessControlAction.AlertingTimeIntervalsWrite,
];

async function exportInterval(displayName: string, captured: CapturedFetch[]) {
  installCapturingBackend(displayName, captured);
  grantUserPermissions(readerWhoCanExport);

  const { user } = render(
    <AlertmanagerProvider accessType="notification" alertmanagerSourceName={GRAFANA_RULES_SOURCE_NAME}>
      <TimeIntervalsTable />
    </AlertmanagerProvider>
  );

  const table = await screen.findByTestId('dynamic-table');
  expect(within(table).getByText(displayName, { exact: false })).toBeInTheDocument();
  document.addEventListener(
    'click',
    (event) => {
      const target = event.target;
      if (target instanceof Element && target.closest('a')) {
        event.preventDefault();
      }
    },
    true
  );
  await user.click(within(table).getByTestId('export'));
  await screen.findByRole('dialog', { name: /export/i });
  await waitFor(() => {
    expect(screen.queryByText(/loading\.\.\.\./i)).not.toBeInTheDocument();
  });
}

describe('mute timing export', () => {
  afterEach(() => {
    document.head.querySelectorAll('base').forEach((node) => node.remove());
  });

  it.each([
    ['/', '../../../../logout?'],
    ['/grafana/', '../../../../../logout?'],
  ])(
    'does not send the viewer to /logout when the saved name escapes the export path (base %s)',
    async (baseHref, displayName) => {
      setBaseHref(baseHref);
      const captured: CapturedFetch[] = [];
      await exportInterval(displayName, captured);

      const exports = exportRequests(captured);
      for (const call of exports) {
        const resolved = resolvedPath(call.url);
        const segments = resolved.pathname.split('/').filter(Boolean);
        const nameIndex = segments.indexOf('mute-timings') + 1;
        expect(resolved.origin).toBe(new URL(document.baseURI).origin);
        expect(call.credentials).toBe('same-origin');
        expect(call.method ?? 'GET').toBe('GET');
        expect(resolved.pathname).not.toBe('/logout');
        expect(segments[nameIndex - 1]).toBe('mute-timings');
        expect(decodeURIComponent(segments[nameIndex])).toBe(displayName);
        expect(segments[nameIndex + 1]).toBe('export');
        expect(resolved.searchParams.get('format')).toBe('yaml');
      }
      expect(exports.filter((call) => resolvedPath(call.url).pathname === '/logout')).toHaveLength(0);
    }
  );

  it('exports a single-segment name on the provisioning path', async () => {
    setBaseHref('/');
    const captured: CapturedFetch[] = [];
    await exportInterval('weekends', captured);

    const exports = exportRequests(captured);
    expect(exports.length).toBeGreaterThan(0);
    for (const call of exports) {
      const resolved = resolvedPath(call.url);
      expect(resolved.pathname).toBe('/api/v1/provisioning/mute-timings/weekends/export/');
      expect(resolved.search).toBe('?format=yaml');
      expect(call.credentials).toBe('same-origin');
      expect(call.method ?? 'GET').toBe('GET');
    }
  });
});
