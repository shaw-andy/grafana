import { HttpResponse, http } from 'msw';
import { type ReactElement } from 'react';
import { render, screen } from 'test/test-utils';

import { config } from '@grafana/runtime';
import { PROVISIONING_API_BASE as BASE } from '@grafana/test-utils/handlers';
import server from '@grafana/test-utils/server';
import { type RepositoryView } from 'app/api/clients/provisioning/v0alpha1';
import { type DashboardScene } from 'app/features/dashboard-scene/scene/DashboardScene';
import { DashboardPreviewBanner } from 'app/features/provisioning/components/Dashboards/DashboardPreviewBanner';
import { NewProvisionedFolderForm } from 'app/features/provisioning/components/Folders/NewProvisionedFolderForm';
import { ProvisionedFolderPreviewBanner } from 'app/features/provisioning/components/Folders/ProvisionedFolderPreviewBanner';
import { useProvisionedFolderFormData } from 'app/features/provisioning/hooks/useProvisionedFolderFormData';
import { DashboardRoutes } from 'app/types/dashboard';
import { type FolderDTO } from 'app/types/folders';

import { setupProvisioningMswServer } from '../../mocks/server';

jest.mock('app/features/manage-dashboards/services/ValidationSrv', () => ({
  validationSrv: {
    validateNewFolderName: jest.fn().mockResolvedValue(true),
  },
}));

jest.mock('../../hooks/usePRBranch', () => ({
  usePRBranch: jest.fn().mockReturnValue(undefined),
}));

jest.mock('../../hooks/useLastBranch', () => ({
  useLastBranch: jest.fn().mockReturnValue({
    getLastBranch: jest.fn().mockReturnValue(undefined),
    setLastBranch: jest.fn(),
  }),
}));

jest.mock('../../hooks/useGetRepositoryFolders', () => ({
  useGetRepositoryFolders: jest.fn().mockReturnValue({ options: [], loading: false, error: null }),
}));

jest.mock('../../hooks/useProvisionedFolderFormData', () => ({
  useProvisionedFolderFormData: jest.fn(),
}));

setupProvisioningMswServer();

const ATTACKER_HOST = 'attacker.test';
const SAVED_REPO_URL = 'https://github.com/org/repo';
const SAVED_PR_URL = 'https://github.com/org/repo/compare/main...feature-branch';

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

function linkHost(href: string | null): string {
  return new URL(href ?? '', 'https://grafana.example').host;
}

function renderAt(ui: ReactElement, search: string) {
  return render(ui, {
    historyOptions: { initialEntries: [search.startsWith('/') ? search : `/dashboards?${search}`] },
  });
}

const savedRepository: RepositoryView = {
  name: 'my-repo',
  title: 'Repo',
  type: 'github',
  target: 'folder',
  url: SAVED_REPO_URL,
  branch: 'main',
  workflows: ['branch'],
};

function savedFileResponse() {
  return HttpResponse.json({
    ref: 'feature-branch',
    path: 'dashboards/foo.json',
    repository: { name: 'my-repo', namespace: 'default', title: 'Repo', type: 'github' },
    resource: { action: 'create', type: { kind: 'Dashboard' } },
    urls: {
      repositoryURL: SAVED_REPO_URL,
      newPullRequestURL: SAVED_PR_URL,
      compareURL: SAVED_PR_URL,
    },
  });
}

describe('provisioning banners do not follow untrusted pull-request query URLs', () => {
  beforeEach(() => {
    config.provisioningEnabled = true;
    server.use(
      http.get(`${BASE}/settings`, () => HttpResponse.json({ items: [savedRepository] })),
      http.get(`${BASE}/repositories/:name/files/*`, () => savedFileResponse())
    );
  });

  describe('folder preview banner', () => {
    it.each([
      {
        label: 'pull_request_url',
        params: { pull_request_url: 'https://attacker.test/login', repo_type: 'github' },
      },
      {
        label: 'new_pull_request_url',
        params: { new_pull_request_url: 'https://attacker.test/login', repo_type: 'github', action: 'create' },
      },
      {
        label: 'new_pull_request_url for a delete',
        params: { new_pull_request_url: 'https://attacker.test/login', repo_type: 'github', action: 'delete' },
      },
      {
        label: 'repo_url on the behind-branch banner',
        params: { repo_url: 'https://attacker.test/org/repo', repo_type: 'github' },
      },
      {
        label: 'pull_request_url chosen ahead of a saved-looking new_pull_request_url',
        params: {
          pull_request_url: 'https://attacker.test/login',
          new_pull_request_url: SAVED_PR_URL,
          repo_type: 'github',
        },
      },
      {
        label: 'protocol-relative pull_request_url',
        params: { pull_request_url: '//attacker.test/login', repo_type: 'gitlab' },
      },
      {
        label: 'userinfo pull_request_url',
        params: { pull_request_url: 'https://gitlab.com@attacker.test/login', repo_type: 'gitlab' },
      },
    ])('does not render $label', ({ params }) => {
      renderAt(<ProvisionedFolderPreviewBanner queryParams={{}} />, new URLSearchParams(params).toString());

      expect(attackerLinks()).toEqual([]);
    });
  });

  describe('dashboard preview banner', () => {
    const dashboard = { state: { meta: { k8s: { annotations: {} } } } } as unknown as DashboardScene;

    function renderDashboard(search: string) {
      return renderAt(
        <DashboardPreviewBanner
          queryParams={{}}
          route={DashboardRoutes.Provisioning}
          slug="my-repo"
          path="dashboards/foo.json"
          dashboard={dashboard}
        />,
        search
      );
    }

    it('keeps the pull-request button on the repository host returned by the file API', async () => {
      renderDashboard(
        new URLSearchParams({
          pull_request_url: 'https://attacker.test/login',
          repo_type: 'github',
          pr_title: 'Review changes',
        }).toString()
      );

      const branch = await screen.findByRole('link', { name: 'feature-branch' });
      expect(linkHost(branch.getAttribute('href'))).toBe('github.com');

      const pullRequest = await screen.findByRole('link', { name: /pull request in github/i });
      expect(linkHost(pullRequest.getAttribute('href'))).toBe('github.com');
      expect(pullRequest.getAttribute('href')).not.toContain(ATTACKER_HOST);
      expect(attackerLinks()).toEqual([]);
    });

    it('does not use a userinfo pull_request_url when the file API returned a repository URL', async () => {
      renderDashboard(
        new URLSearchParams({
          pull_request_url: 'https://github.com@attacker.test/login',
          repo_type: 'github',
        }).toString()
      );

      const pullRequest = await screen.findByRole('link', { name: /pull request in github/i });
      expect(linkHost(pullRequest.getAttribute('href'))).toBe('github.com');
      expect(attackerLinks()).toEqual([]);
    });

    it('does not render a pull-request link from the query string when the file request fails', async () => {
      server.use(http.get(`${BASE}/repositories/:name/files/*`, () => new HttpResponse(null, { status: 404 })));

      renderDashboard(
        new URLSearchParams({
          pull_request_url: 'https://attacker.test/login',
          repo_type: 'github',
          action: 'create',
        }).toString()
      );

      // Loading returns null. Once the file query fails, the banner still renders and must not
      // keep the query-string address.
      await screen.findByRole('status');

      expect(attackerLinks()).toEqual([]);
    });
  });

  describe('new provisioned folder form', () => {
    beforeEach(() => {
      jest.mocked(useProvisionedFolderFormData).mockReturnValue({
        repository: {
          name: 'test-repo',
          title: 'Test Repository',
          type: 'github',
          workflows: ['write', 'branch'],
          target: 'folder',
        },
        isReadOnlyRepo: false,
        folder: {
          metadata: { annotations: { 'grafana.app/sourcePath': 'dashboards' } },
          spec: { title: '' },
        },
        canPushToConfiguredBranch: true,
        initialValues: {
          title: '',
          comment: '',
          ref: 'folder/test-timestamp',
          repo: 'test-repo',
          path: '/dashboards',
          workflow: 'write',
        },
        isLoading: false,
        isMissingRepo: false,
      });
    });

    it('does not render pull_request_url as the pull-request anchor', async () => {
      const parentFolder = {
        uid: 'folder-uid',
        title: 'Parent Folder',
        url: '/dashboards/f/folder-uid',
      } as FolderDTO;

      renderAt(
        <NewProvisionedFolderForm parentFolder={parentFolder} onDismiss={jest.fn()} />,
        new URLSearchParams({
          pull_request_url: 'https://attacker.test/login',
          repo_type: 'github',
        }).toString()
      );

      expect(await screen.findByRole('textbox', { name: /folder name/i })).toBeInTheDocument();
      expect(attackerLinks()).toEqual([]);
    });
  });
});
