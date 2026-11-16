import { of } from 'rxjs';
import { Route, Routes } from 'react-router-dom-v5-compat';
import { render, waitFor } from 'test/test-utils';

import { OrgRole } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';
import { GrafanaRouteWrapper } from 'app/core/navigation/GrafanaRoute';
import { BackendSrv, backendSrv } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';
import { configureStore } from 'app/store/configureStore';
import { AccessControlAction } from 'app/types/accessControl';

import { getAlertingRoutes } from '../../routes';
import { alertSilencesApi } from './alertSilencesApi';

/**
 * Grafana serves index.html with <base href="[[.AppSubUrl]]/">. backend_srv then strips the
 * leading slash from local URLs, so the browser resolves them against that base.
 */
const APP_ROOT = '/';
const APP_SUBPATH = '/grafana/';

const LOGOUT_CLIMBS = [
  '..%2F..%2F..%2F..%2F..%2F..%2Flogout',
  '..%2f..%2f..%2f..%2f..%2f..%2flogout',
  '%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2F%2e%2e%2Flogout',
];

const SWITCH_ORG_CLIMB = '..%2F..%2F..%2F..%2F..%2F..%2Fprofile%2Fswitch-org%2F2';
const SAFE_SILENCE_ID = 'silence-id-1';

type CapturedRequest = {
  method: string;
  rawUrl: string;
  pathname: string;
  credentials: RequestCredentials | undefined;
};

const requests: CapturedRequest[] = [];

function installRecordingBackend() {
  const recordingBackend = new BackendSrv({
    fromFetch: (input, init) => {
      const rawUrl = typeof input === 'string' ? input : input.url;
      const resolved = new URL(rawUrl, document.baseURI);
      requests.push({
        method: (init?.method ?? 'GET').toUpperCase(),
        rawUrl,
        pathname: resolved.pathname,
        credentials: init?.credentials,
      });

      return of({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        headers: new Headers({ 'content-type': 'application/json' }),
        url: resolved.toString(),
        redirected: false,
        type: 'basic',
        text: () => Promise.resolve('{"message":"not found"}'),
      } as unknown as Response);
    },
  });
  setBackendSrv(recordingBackend);
}

function setDocumentBase(href: string) {
  let base = document.querySelector('base');
  if (!base) {
    base = document.createElement('base');
    document.head.appendChild(base);
  }
  base.setAttribute('href', href);
}

function rootFromBase(href: string): string {
  return href === APP_ROOT ? '' : href.replace(/\/$/, '');
}

function silencePrefix(href: string): string {
  return `${rootFromBase(href)}/api/alertmanager/grafana/api/v2/silence/`;
}

function traversalViolations(href: string): string[] {
  const root = rootFromBase(href);
  const prefix = silencePrefix(href);
  const violations: string[] = [];

  for (const request of requests) {
    const target = `${request.method} ${request.pathname} credentials=${request.credentials ?? 'omit'} <= ${request.rawUrl}`;
    if (request.pathname === `${root}/logout` || request.pathname === `${root}/profile/switch-org/2`) {
      violations.push(target);
      continue;
    }

    const isSilenceRequest =
      request.rawUrl.includes('/api/v2/silence/') || request.pathname.startsWith(prefix);
    if (!isSilenceRequest) {
      continue;
    }

    const idSegment = request.pathname.startsWith(prefix) ? request.pathname.slice(prefix.length) : '';
    if (!request.pathname.startsWith(prefix) || idSegment.includes('/') || idSegment.length === 0) {
      violations.push(target);
    }
  }

  return violations;
}

function renderSilenceRoute(path: '/alerting/silence/:id/view' | '/alerting/silence/:id/edit', idSegment: string) {
  const route = getAlertingRoutes().find((candidate) => candidate.path === path);
  if (!route) {
    throw new Error(`missing alerting route ${path}`);
  }

  const action = path.endsWith('/view') ? 'view' : 'edit';
  return render(
    <Routes>
      <Route path={path} element={<GrafanaRouteWrapper route={route} />} />
    </Routes>,
    {
      historyOptions: {
        initialEntries: [`/alerting/silence/${idSegment}/${action}?alertmanager=grafana`],
      },
    }
  );
}

async function settleSilencePage() {
  await waitFor(
    () => {
      const text = document.body.textContent ?? '';
      const fetchedSilence = requests.some((request) => request.rawUrl.includes('/api/v2/silence/'));
      const finished =
        /Silence not found|Error loading silence|Existing silence|not found|do not have permission/.test(text);
      expect(fetchedSilence || finished).toBe(true);
    },
    { timeout: 20000 }
  );
}

describe('silence link path traversal', () => {
  let baseElement: HTMLBaseElement | null;
  let alertingWasEnabled = false;

  beforeEach(() => {
    requests.length = 0;
    alertingWasEnabled = config.unifiedAlertingEnabled;
    config.unifiedAlertingEnabled = true;
    installRecordingBackend();
    setDocumentBase(APP_ROOT);
    contextSrv.user.isSignedIn = true;
    contextSrv.user.orgId = 1;
    contextSrv.user.orgRole = OrgRole.Viewer;
    contextSrv.isSignedIn = true;
    contextSrv.user.permissions = {
      [AccessControlAction.AlertingInstanceRead]: true,
      [AccessControlAction.AlertingSilenceRead]: true,
    };
  });

  afterEach(() => {
    config.unifiedAlertingEnabled = alertingWasEnabled;
    setBackendSrv(backendSrv);
    baseElement = document.querySelector('base');
    baseElement?.remove();
    contextSrv.user.permissions = {};
    contextSrv.user.isSignedIn = false;
    contextSrv.user.orgRole = '';
    contextSrv.isSignedIn = false;
  });

  it('loads an ordinary silence id from under the silence endpoint', async () => {
    const view = renderSilenceRoute('/alerting/silence/:id/view', SAFE_SILENCE_ID);
    await settleSilencePage();

    const silenceGets = requests.filter(
      (request) => request.method === 'GET' && request.pathname.startsWith(silencePrefix(APP_ROOT))
    );
    expect(silenceGets.map((request) => request.pathname)).toEqual([
      '/api/alertmanager/grafana/api/v2/silence/silence-id-1',
    ]);
    expect(silenceGets.map((request) => request.credentials)).toEqual(['same-origin']);
    expect(traversalViolations(APP_ROOT)).toEqual([]);
  });

  it.each(LOGOUT_CLIMBS)(
    'does not let a silence view link %s issue GET /logout',
    async (idSegment) => {
      renderSilenceRoute('/alerting/silence/:id/view', idSegment);
      await settleSilencePage();

      expect(requests.every((request) => request.credentials === 'same-origin')).toBe(true);
      expect(traversalViolations(APP_ROOT)).toEqual([]);
    }
  );

  it('does not let a silence view link switch the active organization', async () => {
    renderSilenceRoute('/alerting/silence/:id/view', SWITCH_ORG_CLIMB);
    await settleSilencePage();

    expect(traversalViolations(APP_ROOT)).toEqual([]);
  });

  it.each(LOGOUT_CLIMBS)(
    'does not let a silence edit link %s issue GET /logout',
    async (idSegment) => {
      renderSilenceRoute('/alerting/silence/:id/edit', idSegment);
      await settleSilencePage();

      expect(traversalViolations(APP_ROOT)).toEqual([]);
    }
  );

  it('does not let a silence edit link switch the active organization', async () => {
    renderSilenceRoute('/alerting/silence/:id/edit', SWITCH_ORG_CLIMB);
    await settleSilencePage();

    expect(traversalViolations(APP_ROOT)).toEqual([]);
  });

  it('keeps a silence view under the subpath base', async () => {
    setDocumentBase(APP_SUBPATH);
    expect(new URL(document.baseURI).pathname).toBe('/grafana/');

    renderSilenceRoute('/alerting/silence/:id/view', SAFE_SILENCE_ID);
    await settleSilencePage();

    expect(
      requests
        .filter((request) => request.method === 'GET' && request.pathname.includes('/api/v2/silence/'))
        .map((request) => request.pathname)
    ).toEqual(['/grafana/api/alertmanager/grafana/api/v2/silence/silence-id-1']);
  });

  it('does not let a subpath silence view link issue GET /grafana/logout', async () => {
    setDocumentBase(APP_SUBPATH);
    renderSilenceRoute('/alerting/silence/:id/view', LOGOUT_CLIMBS[0]);
    await settleSilencePage();

    expect(traversalViolations(APP_SUBPATH)).toEqual([]);
  });

  it('does not let a subpath silence view link switch the active organization', async () => {
    setDocumentBase(APP_SUBPATH);
    renderSilenceRoute('/alerting/silence/:id/view', SWITCH_ORG_CLIMB);
    await settleSilencePage();

    expect(traversalViolations(APP_SUBPATH)).toEqual([]);
  });

  it('deletes an ordinary silence id at the silence endpoint', async () => {
    const store = configureStore();
    await store.dispatch(
      alertSilencesApi.endpoints.expireSilence.initiate({
        datasourceUid: 'grafana',
        silenceId: SAFE_SILENCE_ID,
      })
    );

    expect(requests.map((request) => `${request.method} ${request.pathname}`)).toEqual([
      'DELETE /api/alertmanager/grafana/api/v2/silence/silence-id-1',
    ]);
    expect(requests.map((request) => request.credentials)).toEqual(['same-origin']);
  });

  it.each(['../../../../../../logout', '../../../../../../profile/switch-org/2'])(
    'does not let expireSilence send %s outside the silence endpoint',
    async (silenceId) => {
      const store = configureStore();
      await store.dispatch(
        alertSilencesApi.endpoints.expireSilence.initiate({
          datasourceUid: 'grafana',
          silenceId,
        })
      );

      expect(traversalViolations(APP_ROOT)).toEqual([]);
      const silenceDeletes = requests.filter((request) => request.method === 'DELETE');
      if (silenceDeletes.length === 0) {
        return;
      }
      expect(silenceDeletes.map((request) => request.pathname)).toEqual([
        silenceId === '../../../../../../logout'
          ? '/api/alertmanager/grafana/api/v2/silence/..%2F..%2F..%2F..%2F..%2F..%2Flogout'
          : '/api/alertmanager/grafana/api/v2/silence/..%2F..%2F..%2F..%2F..%2F..%2Fprofile%2Fswitch-org%2F2',
      ]);
    }
  );
});
