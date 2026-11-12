import { act } from '@testing-library/react';
import { of } from 'rxjs';
import { render, screen } from 'test/test-utils';

import { setTestFlags } from '@grafana/test-utils/unstable';
import { backendSrv } from 'app/core/services/backend_srv';
import { contextSrv } from 'app/core/services/context_srv';

import { createFetchResponse } from '../../../test/helpers/createFetchResponse';

import { PlaylistPage } from './PlaylistPage';

jest.mock('@grafana/runtime', () => ({
  ...jest.requireActual('@grafana/runtime'),
  getBackendSrv: () => backendSrv,
}));

jest.mock('app/core/services/context_srv', () => ({
  contextSrv: {
    ...jest.requireActual('app/core/services/context_srv').contextSrv,
    hasPermission: jest.fn(),
    isEditor: false,
  },
}));

const ATTACKER_HOST = 'attacker.test';

/**
 * These tests specify the safe behavior and fail while query-string pull-request URLs are rendered.
 * A link is unsafe when its host is the attacker host, including a subdomain of that host.
 */
function attackerLinks(): Array<{ name: string; href: string }> {
  return screen.queryAllByRole('link').flatMap((link) => {
    const href = link.getAttribute('href');
    if (!href || !hrefPointsAtAttacker(href)) {
      return [];
    }
    return [{ name: link.textContent?.replace(/\s+/g, ' ').trim() ?? '', href }];
  });
}

function hrefPointsAtAttacker(href: string): boolean {
  try {
    const host = new URL(href, 'https://grafana.example').host;
    return host === ATTACKER_HOST || host.endsWith(`.${ATTACKER_HOST}`);
  } catch {
    return href.includes(ATTACKER_HOST);
  }
}

function renderPlaylists(search: string) {
  return render(<PlaylistPage />, {
    historyOptions: { initialEntries: [search.startsWith('/') ? search : `/playlists?${search}`] },
  });
}

describe('PlaylistPage untrusted pull-request query URLs', () => {
  beforeEach(() => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(backendSrv, 'fetch').mockImplementation(() => of(createFetchResponse({ items: [] })));
    jest.mocked(contextSrv.hasPermission).mockReturnValue(false);
    (contextSrv as jest.Mocked<typeof contextSrv>).isEditor = false;
    setTestFlags({ playlistsRBAC: false });
  });

  afterEach(async () => {
    // setTestFlags emits OpenFeature updates while the previous tree is still mounted.
    await act(async () => {
      setTestFlags({});
    });
  });

  it.each([
    {
      label: 'https address from the attack link',
      search: new URLSearchParams({
        new_pull_request_url: 'https://attacker.test/login',
        repo_type: 'github',
        action: 'create',
      }).toString(),
    },
    {
      label: 'http address',
      search: new URLSearchParams({
        new_pull_request_url: 'http://attacker.test/login',
        repo_type: 'github',
        action: 'create',
      }).toString(),
    },
    {
      label: 'protocol-relative address',
      search: new URLSearchParams({
        new_pull_request_url: '//attacker.test/login',
        repo_type: 'github',
        action: 'create',
      }).toString(),
    },
    {
      label: 'userinfo that makes the string start like a GitHub URL',
      search: new URLSearchParams({
        new_pull_request_url: 'https://github.com@attacker.test/login',
        repo_type: 'github',
        action: 'create',
      }).toString(),
    },
    {
      label: 'host that only begins with github.com',
      search: new URLSearchParams({
        new_pull_request_url: 'https://github.com.attacker.test/login',
        repo_type: 'github',
        action: 'create',
      }).toString(),
    },
    {
      label: 'GitHub-looking path on the attacker host',
      search: new URLSearchParams({
        new_pull_request_url: 'https://attacker.test/github.com/org/repo/pull/1',
        repo_type: 'github',
        action: 'create',
      }).toString(),
    },
    {
      label: 'HTML-entity dot that the sanitizer decodes into the attacker host',
      search: new URLSearchParams({
        new_pull_request_url: 'https://attacker&#46;test/login',
        repo_type: 'github',
        action: 'create',
      }).toString(),
    },
    {
      label: 'twice-encoded address',
      search: `new_pull_request_url=${encodeURIComponent(encodeURIComponent('https://attacker.test/login'))}&repo_type=github&action=create`,
    },
    {
      label: 'title query appended onto the attacker address',
      search: new URLSearchParams({
        new_pull_request_url: 'https://attacker.test/login',
        repo_type: 'github',
        action: 'create',
        pr_title: 'Review changes',
      }).toString(),
    },
    {
      label: 'delete action',
      search: new URLSearchParams({
        new_pull_request_url: 'https://attacker.test/login',
        repo_type: 'github',
        action: 'delete',
      }).toString(),
    },
    {
      label: 'update action',
      search: new URLSearchParams({
        new_pull_request_url: 'https://attacker.test/login',
        repo_type: 'github',
        action: 'update',
      }).toString(),
    },
    {
      label: 'GitLab label with an attacker address',
      search: new URLSearchParams({
        new_pull_request_url: 'https://attacker.test/login',
        repo_type: 'gitlab',
        action: 'create',
      }).toString(),
    },
    {
      label: 'Bitbucket label with an attacker address',
      search: new URLSearchParams({
        new_pull_request_url: 'https://attacker.test/login',
        repo_type: 'bitbucket',
        action: 'create',
      }).toString(),
    },
  ])('does not render $label as a pull-request link', async ({ search }) => {
    renderPlaylists(search);

    await screen.findByText(/open pull request|there are no playlists created yet/i);

    expect(attackerLinks()).toEqual([]);
  });

  it('does not turn repo_url into branch links or a fallback button when a new pull-request URL is also set', async () => {
    renderPlaylists(
      new URLSearchParams({
        new_pull_request_url: 'https://attacker.test/login',
        repo_url: 'https://attacker.test/org/repo',
        repo_type: 'github',
        action: 'create',
        ref: 'feature-branch',
        repo_branch: 'main',
      }).toString()
    );

    await screen.findByText(/open pull request|there are no playlists created yet/i);

    expect(attackerLinks()).toEqual([]);
  });
});
