import { renderHook } from 'test/test-utils';

import { config } from '@grafana/runtime';
import { useGetFrontendSettingsQuery } from 'app/api/clients/provisioning/v0alpha1';
import { useUrlParams } from 'app/core/navigation/hooks';

import { usePullRequestParam } from './usePullRequestParam';

jest.mock('app/core/navigation/hooks');
jest.mock('app/api/clients/provisioning/v0alpha1', () => ({
  useGetFrontendSettingsQuery: jest.fn(),
}));

const mockUseUrlParams = useUrlParams as jest.MockedFunction<typeof useUrlParams>;
const mockSettingsQuery = useGetFrontendSettingsQuery as jest.Mock;

const savedRepositories = [
  { name: 'gh', title: 'GitHub repo', type: 'github', target: 'folder', url: 'https://github.com/org/repo' },
  { name: 'gl', title: 'GitLab repo', type: 'gitlab', target: 'folder', url: 'https://gitlab.com/group/proj.git' },
];

function setParams(params: Record<string, string>) {
  const searchParams = new URLSearchParams(params);
  mockUseUrlParams.mockReturnValue([searchParams, jest.fn()]);
}

describe('usePullRequestParam', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    config.provisioningEnabled = true;
    mockSettingsQuery.mockReturnValue({ data: { items: savedRepositories } });
    setParams({});
  });

  describe('repoType', () => {
    it('returns valid repo type', () => {
      setParams({ repo_type: 'github' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.repoType).toBe('github');
    });

    it('returns undefined for invalid repo type', () => {
      setParams({ repo_type: 'javascript:alert(1)' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.repoType).toBeUndefined();
    });

    it('returns undefined for empty repo type', () => {
      setParams({});
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.repoType).toBeUndefined();
    });
  });

  describe('resourcePushedTo', () => {
    it('returns valid k8s name', () => {
      setParams({ resource_pushed_to: 'my-repo-123' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.resourcePushedTo).toBe('my-repo-123');
    });

    it('rejects names with invalid characters', () => {
      setParams({ resource_pushed_to: 'INVALID_NAME' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.resourcePushedTo).toBeUndefined();
    });

    it('rejects names starting with hyphen', () => {
      setParams({ resource_pushed_to: '-bad-name' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.resourcePushedTo).toBeUndefined();
    });

    it('returns undefined when param is missing', () => {
      setParams({});
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.resourcePushedTo).toBeUndefined();
    });
  });

  describe('URL fields', () => {
    it('drops javascript: URLs', () => {
      setParams({
        pull_request_url: 'javascript:alert(1)',
        new_pull_request_url: 'javascript:alert(2)',
        repo_url: 'javascript:alert(3)',
      });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.prURL).toBeUndefined();
      expect(result.current.newPrURL).toBeUndefined();
      expect(result.current.repoURL).toBeUndefined();
    });

    it('keeps links inside a saved repository of the given type', () => {
      setParams({
        pull_request_url: 'https://github.com/org/repo/pull/1',
        new_pull_request_url: 'https://github.com/org/repo/compare/main...feature?quick_pull=1&labels=grafana',
        repo_url: 'https://github.com/org/repo',
        repo_type: 'github',
      });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.prURL).toBe('https://github.com/org/repo/pull/1');
      expect(result.current.newPrURL).toBe(
        'https://github.com/org/repo/compare/main...feature?quick_pull=1&labels=grafana'
      );
      expect(result.current.repoURL).toBe('https://github.com/org/repo');
    });

    it('decodes the extra escaping the backend applies to pull_request_url', () => {
      const prURL = 'https://github.com/org/repo/pull/1';
      mockUseUrlParams.mockReturnValue([
        new URLSearchParams(`pull_request_url=${encodeURIComponent(encodeURIComponent(prURL))}`),
        jest.fn(),
      ]);
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.prURL).toBe(prURL);
    });

    it('matches repository URLs saved with a .git suffix', () => {
      setParams({ new_pull_request_url: 'https://gitlab.com/group/proj/-/merge_requests/new', repo_type: 'gitlab' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.newPrURL).toBe('https://gitlab.com/group/proj/-/merge_requests/new');
    });

    it.each([
      'https://attacker.test/org/repo/pull/1',
      '//attacker.test/org/repo/pull/1',
      'https://github.com@attacker.test/org/repo/pull/1',
      'https://github.com.attacker.test/org/repo/pull/1',
      'https://github.com/org/repo/../../attacker/repo',
      'https://github.com/org/repository/pull/1',
      'https://github.com/other/repo/pull/1',
      'http://github.com/org/repo/pull/1',
      '/org/repo/pull/1',
    ])('drops %s', (url) => {
      setParams({ pull_request_url: url, new_pull_request_url: url, repo_url: url, repo_type: 'github' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.prURL).toBeUndefined();
      expect(result.current.newPrURL).toBeUndefined();
      expect(result.current.repoURL).toBeUndefined();
    });

    it('drops links whose repository does not match repo_type', () => {
      setParams({ pull_request_url: 'https://github.com/org/repo/pull/1', repo_type: 'gitlab' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.prURL).toBeUndefined();
    });

    it('returns the saved repository URL rather than the query value', () => {
      setParams({ repo_url: 'https://github.com/org/repo/tree/main', repo_type: 'github' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.repoURL).toBe('https://github.com/org/repo');
    });

    it('drops every link until the saved repositories have loaded', () => {
      mockSettingsQuery.mockReturnValue({ data: undefined });
      setParams({ pull_request_url: 'https://github.com/org/repo/pull/1', repo_type: 'github' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.prURL).toBeUndefined();
    });
  });

  describe('action', () => {
    it('accepts valid actions', () => {
      setParams({ action: 'create' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.action).toBe('create');
    });

    it('rejects invalid actions', () => {
      setParams({ action: 'malicious' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.action).toBeUndefined();
    });
  });

  describe('prTitle', () => {
    it('reads pr_title and collapses whitespace to single spaces', () => {
      setParams({ pr_title: 'update:  My   Dashboard' });
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.prTitle).toBe('update: My Dashboard');
    });

    it('returns undefined when pr_title is missing', () => {
      setParams({});
      const { result } = renderHook(() => usePullRequestParam());
      expect(result.current.prTitle).toBeUndefined();
    });
  });
});
