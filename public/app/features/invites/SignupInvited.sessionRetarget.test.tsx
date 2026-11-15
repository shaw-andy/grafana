import { Route, Routes, useParams } from 'react-router-dom-v5-compat';
import { of } from 'rxjs';
import { render, screen, waitFor } from 'test/test-utils';

import { setBackendSrv } from '@grafana/runtime';

import { BackendSrv } from '../../core/services/backend_srv';

import { SignupInvitedPage } from './SignupInvited';

// public/views/index.html sets <base href="/"> (AppSubUrl empty by default).
// fetch() resolves a relative URL against that document base. rxjs fromFetch
// passes the string it is given through to fetch().
const documentBase = 'http://grafana.example/';

interface CapturedRequest {
  url: string;
  credentials?: RequestCredentials;
}

function installBackend() {
  const requests: CapturedRequest[] = [];
  const backendSrv = new BackendSrv({
    fromFetch: (input, init) => {
      requests.push({ url: String(input), credentials: init?.credentials });
      return of(
        new Response(
          JSON.stringify({
            email: 'invitee@example.com',
            name: 'Invitee',
            username: 'invitee@example.com',
            invitedBy: 'Someone',
            orgName: 'Example Org',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        )
      );
    },
  });
  setBackendSrv(backendSrv);
  return requests;
}

function resolvedPath(url: string) {
  return new URL(url, documentBase).pathname;
}

function InviteRoute() {
  return (
    <Routes>
      <Route path="/invite/:code" element={<InvitePage />} />
    </Routes>
  );
}

function InvitePage() {
  const { code } = useParams();
  return (
    <>
      <div data-testid="invite-code-probe">{code}</div>
      <SignupInvitedPage />
    </>
  );
}

describe('SignupInvited invite code request', () => {
  it('requests a normal invite code as one encoded path segment', async () => {
    const requests = installBackend();

    render(<InviteRoute />, {
      historyOptions: { initialEntries: ['/invite/abcDEF123'] },
    });

    await waitFor(() => expect(requests).toHaveLength(1));
    expect(resolvedPath(requests[0].url)).toBe('/api/user/invite/abcDEF123');
    expect(requests[0].credentials).toBe('same-origin');
  });

  it.each([
    {
      name: 'logout',
      entry: '/invite/..%2F..%2F..%2F..%2Flogout',
      code: '../../../../logout',
      safePath: '/api/user/invite/..%2F..%2F..%2F..%2Flogout',
    },
    {
      name: 'organization switch',
      entry: '/invite/..%2F..%2F..%2F..%2Fprofile%2Fswitch-org%2F2',
      code: '../../../../profile/switch-org/2',
      safePath: '/api/user/invite/..%2F..%2F..%2F..%2Fprofile%2Fswitch-org%2F2',
    },
    {
      name: 'session rotation',
      entry: '/invite/..%2F..%2F..%2F..%2Fuser%2Fauth-tokens%2Frotate',
      code: '../../../../user/auth-tokens/rotate',
      safePath: '/api/user/invite/..%2F..%2F..%2F..%2Fuser%2Fauth-tokens%2Frotate',
    },
  ])('does not let an invite code for $name escape the invite API path', async ({ entry, code, safePath }) => {
    const requests = installBackend();

    render(<InviteRoute />, {
      historyOptions: { initialEntries: [entry] },
    });

    expect(await screen.findByTestId('invite-code-probe')).toHaveTextContent(code);

    await waitFor(() => expect(requests.length).toBeGreaterThan(0));
    for (const request of requests) {
      expect(resolvedPath(request.url)).toBe(safePath);
      expect(request.credentials).toBe('same-origin');
    }
  });
});
