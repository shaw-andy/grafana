import { config } from '@grafana/runtime';
import { type Repository } from 'app/api/clients/provisioning/v0alpha1';
import { contextSrv } from 'app/core/services/context_srv';
import { render, screen } from 'test/test-utils';

import { RepositoryActions } from './RepositoryActions';
import { RepositoryLink } from './RepositoryLink';
import { RepositoryListItem } from './RepositoryListItem';
import { RepositoryPullStatusCard } from './RepositoryPullStatusCard';

const mockUseGetRepositoryQuery = jest.fn();

jest.mock('app/api/clients/provisioning/v0alpha1', () => ({
  ...jest.requireActual('app/api/clients/provisioning/v0alpha1'),
  useCreateRepositoryJobsMutation: jest.fn().mockReturnValue([jest.fn(), { isLoading: false }]),
  useListJobQuery: jest.fn().mockReturnValue({ data: undefined }),
  useGetRepositoryQuery: (...args: unknown[]) => mockUseGetRepositoryQuery(...args),
}));

const thisInstance = 'https://grafana.example/';

function isSessionLogoutNavigation(href: string | null | undefined): boolean {
  if (!href) {
    return false;
  }
  const app = new URL(thisInstance);
  const target = new URL(href, app);
  if (target.origin !== app.origin) {
    return false;
  }
  const prefix = app.pathname.replace(/\/+$/, '');
  const path = target.pathname.length > 1 ? target.pathname.replace(/\/+$/, '') : target.pathname;
  return path === `${prefix}/logout`;
}

function expectNoLogoutLink(hrefs: Array<string | null | undefined>) {
  for (const href of hrefs) {
    expect(isSessionLogoutNavigation(href)).toBe(false);
  }
}

function repository(overrides: Partial<Repository> = {}): Repository {
  return {
    metadata: { name: 'test-repo' },
    spec: {
      title: 'Test Repository',
      type: 'git',
      sync: { target: 'folder', enabled: true },
      workflows: [],
      git: { url: 'https://grafana.example/logout', branch: 'main' },
    },
    status: {
      health: { healthy: true, checked: Date.now() },
      sync: { state: 'success', message: [], lastRef: 'abc1234def' },
      observedGeneration: 1,
      webhook: {},
    },
    ...overrides,
  };
}

describe('rendered repository links do not navigate to session logout', () => {
  const originalAppUrl = config.appUrl;
  const originalProvisioning = config.provisioningEnabled;
  const originalIsEditor = contextSrv.isEditor;

  beforeEach(() => {
    config.appUrl = thisInstance;
    config.provisioningEnabled = true;
    contextSrv.isEditor = true;
    jest.spyOn(contextSrv, 'hasPermission').mockReturnValue(false);
    mockUseGetRepositoryQuery.mockReturnValue({
      data: repository(),
      isLoading: false,
    });
  });

  afterEach(() => {
    config.appUrl = originalAppUrl;
    config.provisioningEnabled = originalProvisioning;
    contextSrv.isEditor = originalIsEditor;
    jest.restoreAllMocks();
  });

  it('does not point the repository list link at logout', () => {
    render(<RepositoryListItem repository={repository()} />);
    expectNoLogoutLink(screen.queryAllByRole('link').map((link) => link.getAttribute('href')));
  });

  it('does not point the pull status repository or commit link at logout', () => {
    const repo = repository({
      spec: {
        title: 'GitHub',
        type: 'github',
        sync: { target: 'folder', enabled: true },
        workflows: [],
        github: { url: 'https://grafana.example/foo/../logout?', branch: 'main' },
      },
    });
    render(<RepositoryPullStatusCard repo={repo} />);
    expectNoLogoutLink(screen.queryAllByRole('link').map((link) => link.getAttribute('href')));
  });

  it.each(['sync', 'delete'] as const)('does not point the %s job view-repository link at logout', (jobType) => {
    render(<RepositoryLink name="test-repo" jobType={jobType} />);
    expectNoLogoutLink(screen.queryAllByRole('link').map((link) => link.getAttribute('href')));
  });

  it('does not open logout from the repository actions source button', async () => {
    const open = jest.spyOn(window, 'open').mockImplementation(() => null);
    const { user } = render(<RepositoryActions repository={repository()} />);
    const source = screen.queryByRole('button', { name: /source code/i });
    if (source) {
      await user.click(source);
    }
    expectNoLogoutLink(open.mock.calls.map((call) => String(call[0])));
  });
});
