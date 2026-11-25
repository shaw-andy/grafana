import { config } from '@grafana/runtime';
import { type RepositorySpec } from 'app/api/clients/provisioning/v0alpha1';

import {
  getRepoCommitUrl,
  getRepoEditFileUrl,
  getRepoFileUrl,
  getRepoHrefForProvider,
  getRepoNewFileUrl,
  getRepoRawFileUrl,
} from './git';

// Partial specs for testing; getRepoHrefForProvider only reads type and provider url/branch/path.
function spec(s: Partial<RepositorySpec>): RepositorySpec {
  return s as RepositorySpec;
}

describe('buildRepoUrl', () => {
  describe('base URL normalization', () => {
    it('strips trailing .git from GitHub URL', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'github',
            github: { url: 'https://github.com/owner/repo.git', branch: 'main' },
          })
        )
      ).toBe('https://github.com/owner/repo/tree/main');
    });

    it('strips trailing .git/ from base URL', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'github',
            github: { url: 'https://github.com/owner/repo.git/', branch: 'main' },
          })
        )
      ).toBe('https://github.com/owner/repo/tree/main');
    });

    it('leaves URL unchanged when it does not end with .git', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'github',
            github: { url: 'https://github.com/owner/repo', branch: 'main' },
          })
        )
      ).toBe('https://github.com/owner/repo/tree/main');
    });

    it('trims whitespace from base URL', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'github',
            github: { url: '  https://github.com/owner/repo  ', branch: 'main' },
          })
        )
      ).toBe('https://github.com/owner/repo/tree/main');
    });
  });

  describe('branch and path', () => {
    it('builds URL with branch only', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'github',
            github: { url: 'https://github.com/owner/repo', branch: 'develop' },
          })
        )
      ).toBe('https://github.com/owner/repo/tree/develop');
    });

    it('builds URL with path segments encoded', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'github',
            github: {
              url: 'https://github.com/owner/repo',
              branch: 'main',
              path: 'src/utils/index.ts',
            },
          })
        )
      ).toBe('https://github.com/owner/repo/tree/main/src/utils/index.ts');
    });

    it('builds URL without branch when branch is missing', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'github',
            github: { url: 'https://github.com/owner/repo' } as RepositorySpec['github'],
          })
        )
      ).toBe('https://github.com/owner/repo/tree');
    });
  });

  describe('providers', () => {
    it('builds GitHub href with tree segment', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'github',
            github: { url: 'https://github.com/org/my-repo.git', branch: 'main' },
          })
        )
      ).toBe('https://github.com/org/my-repo/tree/main');
    });

    it('builds GitLab href with -/tree segments', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'gitlab',
            gitlab: { url: 'https://gitlab.com/group/project.git', branch: 'main' },
          })
        )
      ).toBe('https://gitlab.com/group/project/-/tree/main');
    });

    it('builds Bitbucket href with src segment', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'bitbucket',
            bitbucket: { url: 'https://bitbucket.org/workspace/repo.git', branch: 'main' },
          })
        )
      ).toBe('https://bitbucket.org/workspace/repo/src/main');
    });

    it('builds generic git href without tree segment', () => {
      expect(
        getRepoHrefForProvider(
          spec({
            type: 'git',
            git: { url: 'https://git.example.com/owner/repo.git', branch: 'main' },
          })
        )
      ).toBe('https://git.example.com/owner/repo');
    });
  });

  describe('edge cases', () => {
    it('returns undefined when spec is undefined', () => {
      expect(getRepoHrefForProvider(undefined)).toBeUndefined();
    });

    it('returns undefined when type is missing', () => {
      expect(getRepoHrefForProvider(spec({ type: undefined }))).toBeUndefined();
    });

    it('returns undefined when base URL is missing for provider', () => {
      expect(
        getRepoHrefForProvider(spec({ type: 'github', github: { url: undefined, branch: 'main' } }))
      ).toBeUndefined();
    });

    it('returns undefined for unknown provider type', () => {
      expect(getRepoHrefForProvider({ type: 'unknown' } as unknown as RepositorySpec)).toBeUndefined();
    });
  });
});

describe('getRepoFileUrl', () => {
  it('joins pathPrefix and filePath with a slash', () => {
    expect(
      getRepoFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        branch: 'main',
        filePath: 'dashboards/my-dashboard.json',
        pathPrefix: 'grafana',
      })
    ).toBe('https://github.com/owner/repo/blob/main/grafana/dashboards/my-dashboard.json');
  });

  it('handles pathPrefix with trailing slash', () => {
    expect(
      getRepoFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        branch: 'main',
        filePath: 'dashboards/my-dashboard.json',
        pathPrefix: 'grafana/',
      })
    ).toBe('https://github.com/owner/repo/blob/main/grafana/dashboards/my-dashboard.json');
  });

  it('uses filePath as-is when pathPrefix is not set', () => {
    expect(
      getRepoFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        branch: 'main',
        filePath: 'dashboards/my-dashboard.json',
      })
    ).toBe('https://github.com/owner/repo/blob/main/dashboards/my-dashboard.json');
  });

  it('returns undefined when url is missing', () => {
    expect(
      getRepoFileUrl({
        repoType: 'github',
        url: undefined,
        filePath: 'dashboards/my-dashboard.json',
      })
    ).toBeUndefined();
  });

  it('returns undefined when filePath is missing', () => {
    expect(
      getRepoFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        filePath: undefined,
      })
    ).toBeUndefined();
  });

  it('uses tree segment for GitHub directory paths (trailing slash)', () => {
    expect(
      getRepoFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        branch: 'main',
        filePath: 'dashboards/team-a/',
      })
    ).toBe('https://github.com/owner/repo/tree/main/dashboards/team-a');
  });

  it('uses tree segment for GitLab directory paths (trailing slash)', () => {
    expect(
      getRepoFileUrl({
        repoType: 'gitlab',
        url: 'https://gitlab.com/group/repo',
        branch: 'main',
        filePath: 'docs/',
      })
    ).toBe('https://gitlab.com/group/repo/-/tree/main/docs');
  });

  it('keeps the src segment for Bitbucket directory paths', () => {
    expect(
      getRepoFileUrl({
        repoType: 'bitbucket',
        url: 'https://bitbucket.org/workspace/repo',
        branch: 'main',
        filePath: 'docs/',
      })
    ).toBe('https://bitbucket.org/workspace/repo/src/main/docs');
  });

  it('treats githubEnterprise the same as github', () => {
    expect(
      getRepoFileUrl({
        repoType: 'githubEnterprise',
        url: 'https://ghe.example.com/owner/repo',
        branch: 'main',
        filePath: 'dashboards/team-a/',
      })
    ).toBe('https://ghe.example.com/owner/repo/tree/main/dashboards/team-a');
  });
});

describe('getRepoEditFileUrl', () => {
  it('builds a GitHub edit URL', () => {
    expect(
      getRepoEditFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        branch: 'main',
        filePath: 'README.md',
      })
    ).toBe('https://github.com/owner/repo/edit/main/README.md');
  });

  it('builds a GitLab edit URL', () => {
    expect(
      getRepoEditFileUrl({
        repoType: 'gitlab',
        url: 'https://gitlab.com/group/repo',
        branch: 'main',
        filePath: 'docs/README.md',
      })
    ).toBe('https://gitlab.com/group/repo/-/edit/main/docs/README.md');
  });

  it('falls back to the source view for Bitbucket', () => {
    expect(
      getRepoEditFileUrl({
        repoType: 'bitbucket',
        url: 'https://bitbucket.org/workspace/repo',
        branch: 'develop',
        filePath: 'README.md',
      })
    ).toBe('https://bitbucket.org/workspace/repo/src/develop/README.md');
  });

  it('joins the repository pathPrefix with the filePath', () => {
    expect(
      getRepoEditFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        branch: 'main',
        filePath: 'README.md',
        pathPrefix: 'dashboards/team-a',
      })
    ).toBe('https://github.com/owner/repo/edit/main/dashboards/team-a/README.md');
  });

  it('defaults to main when branch is missing', () => {
    expect(
      getRepoEditFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        branch: undefined,
        filePath: 'README.md',
      })
    ).toBe('https://github.com/owner/repo/edit/main/README.md');
  });

  it('returns undefined for repository types without a known edit URL', () => {
    expect(
      getRepoEditFileUrl({
        repoType: 'git',
        url: 'https://example.com/some/repo.git',
        filePath: 'README.md',
      })
    ).toBeUndefined();
    expect(
      getRepoEditFileUrl({
        repoType: 'local',
        url: '/data/repo',
        filePath: 'README.md',
      })
    ).toBeUndefined();
  });

  it('returns undefined when url or filePath is missing', () => {
    expect(
      getRepoEditFileUrl({
        repoType: 'github',
        url: undefined,
        filePath: 'README.md',
      })
    ).toBeUndefined();
    expect(
      getRepoEditFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        filePath: undefined,
      })
    ).toBeUndefined();
  });
});

describe('getRepoNewFileUrl', () => {
  it('builds a GitHub new-file URL with filename and prefilled template', () => {
    const url = getRepoNewFileUrl({
      repoType: 'github',
      url: 'https://github.com/owner/repo',
      branch: 'main',
      filePath: 'README.md',
      template: '# Hello',
    });

    expect(url).toBeDefined();
    const parsed = new URL(url!);
    expect(parsed.origin + parsed.pathname).toBe('https://github.com/owner/repo/new/main');
    expect(parsed.searchParams.get('filename')).toBe('README.md');
    expect(parsed.searchParams.get('value')).toBe('# Hello');
  });

  it('joins pathPrefix with filename in the GitHub new-file URL', () => {
    const url = getRepoNewFileUrl({
      repoType: 'github',
      url: 'https://github.com/owner/repo',
      branch: 'main',
      filePath: 'README.md',
      pathPrefix: 'dashboards/team-a',
    });

    expect(new URL(url!).searchParams.get('filename')).toBe('dashboards/team-a/README.md');
  });

  it('builds a GitLab new-file URL with file_name and content', () => {
    const url = getRepoNewFileUrl({
      repoType: 'gitlab',
      url: 'https://gitlab.com/group/repo',
      branch: 'main',
      filePath: 'docs/README.md',
      template: '# Hello',
    });

    const parsed = new URL(url!);
    expect(parsed.origin + parsed.pathname).toBe('https://gitlab.com/group/repo/-/new/main');
    expect(parsed.searchParams.get('file_name')).toBe('docs/README.md');
    expect(parsed.searchParams.get('content')).toBe('# Hello');
  });

  it('falls back to the parent directory source view for Bitbucket', () => {
    const url = getRepoNewFileUrl({
      repoType: 'bitbucket',
      url: 'https://bitbucket.org/workspace/repo',
      branch: 'develop',
      filePath: 'docs/README.md',
    });

    expect(url).toBe('https://bitbucket.org/workspace/repo/src/develop/docs');
  });

  it('returns undefined for repository types without a known new-file URL', () => {
    expect(
      getRepoNewFileUrl({
        repoType: 'git',
        url: 'https://example.com/some/repo.git',
        filePath: 'README.md',
      })
    ).toBeUndefined();
    expect(
      getRepoNewFileUrl({
        repoType: 'local',
        url: '/data/repo',
        filePath: 'README.md',
      })
    ).toBeUndefined();
  });

  it('returns undefined when url or filePath is missing', () => {
    expect(
      getRepoNewFileUrl({
        repoType: 'github',
        url: undefined,
        filePath: 'README.md',
      })
    ).toBeUndefined();
    expect(
      getRepoNewFileUrl({
        repoType: 'github',
        url: 'https://github.com/owner/repo',
        filePath: undefined,
      })
    ).toBeUndefined();
  });
});

// This Grafana instance, as bootstrapped into the frontend. Link builders must
// not send the browser here: GET /logout revokes the session cookie.
const thisInstance = 'https://grafana.example/';

function isSessionLogoutNavigation(href: string | undefined): boolean {
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

describe('repository links must not sign the viewer out', () => {
  const originalAppUrl = config.appUrl;

  beforeAll(() => {
    config.appUrl = thisInstance;
  });

  afterAll(() => {
    config.appUrl = originalAppUrl;
  });

  it.each([
    ['github', 'https://grafana.example/foo/../logout?'],
    ['githubEnterprise', 'https://grafana.example/foo/../logout?'],
    ['gitlab', 'https://grafana.example/foo/../logout?'],
    ['bitbucket', 'https://grafana.example/foo/../logout?'],
    ['git', 'https://grafana.example/logout'],
    ['git', 'https://grafana.example:443/logout'],
    ['git', 'https://Grafana.Example/logout'],
  ])('view-repository href for %s %s is not this instance logout', (type, url) => {
    const href = getRepoHrefForProvider(
      spec({
        type: type as RepositorySpec['type'],
        github: type === 'github' ? { url, branch: 'main' } : undefined,
        githubEnterprise: type === 'githubEnterprise' ? { url, branch: 'main' } : undefined,
        gitlab: type === 'gitlab' ? { url, branch: 'main' } : undefined,
        bitbucket: type === 'bitbucket' ? { url, branch: 'main' } : undefined,
        git: type === 'git' ? { url, branch: 'main' } : undefined,
      })
    );
    expect(isSessionLogoutNavigation(href)).toBe(false);
  });

  it.each(['github', 'githubEnterprise', 'gitlab', 'bitbucket'] as const)(
    '%s file, raw, edit, new-file, and commit URLs are not this instance logout',
    (repoType) => {
      const url = 'https://grafana.example/foo/../logout?';
      expect(
        isSessionLogoutNavigation(
          getRepoFileUrl({ repoType, url, branch: 'main', filePath: 'dashboards/a.json', pathPrefix: 'grafana' })
        )
      ).toBe(false);
      expect(isSessionLogoutNavigation(getRepoRawFileUrl({ repoType, url, branch: 'main', filePath: 'img.png' }))).toBe(
        false
      );
      expect(
        isSessionLogoutNavigation(getRepoEditFileUrl({ repoType, url, branch: 'main', filePath: 'dashboards/a.json' }))
      ).toBe(false);
      expect(
        isSessionLogoutNavigation(
          getRepoNewFileUrl({ repoType, url, branch: 'main', filePath: 'README.md', template: 'hello' })
        )
      ).toBe(false);
      const provider =
        repoType === 'github'
          ? { github: { url, branch: 'main' } }
          : repoType === 'githubEnterprise'
            ? { githubEnterprise: { url, branch: 'main' } }
            : repoType === 'gitlab'
              ? { gitlab: { url, branch: 'main' } }
              : { bitbucket: { url, branch: 'main' } };
      expect(isSessionLogoutNavigation(getRepoCommitUrl(spec({ type: repoType, ...provider }), 'abc1234').url)).toBe(
        false
      );
    }
  );

  it('keeps appended provider segments in the path when the saved URL contains a question mark', () => {
    const href = getRepoHrefForProvider(
      spec({
        type: 'github',
        github: { url: 'https://github.com/owner/repo?', branch: 'main' },
      })
    );
    const fileHref = getRepoFileUrl({
      repoType: 'github',
      url: 'https://github.com/owner/repo?',
      branch: 'main',
      filePath: 'dashboards/a.json',
    });
    const rawHref = getRepoRawFileUrl({
      repoType: 'github',
      url: 'https://github.com/owner/repo?',
      branch: 'main',
      filePath: 'img.png',
    });
    const editHref = getRepoEditFileUrl({
      repoType: 'github',
      url: 'https://github.com/owner/repo?',
      branch: 'main',
      filePath: 'dashboards/a.json',
    });
    const newHref = getRepoNewFileUrl({
      repoType: 'github',
      url: 'https://github.com/owner/repo?',
      branch: 'main',
      filePath: 'README.md',
    });
    const commitHref = getRepoCommitUrl(
      spec({ type: 'github', github: { url: 'https://github.com/owner/repo?', branch: 'main' } }),
      'abc1234'
    ).url;

    for (const built of [href, fileHref, rawHref, editHref, newHref, commitHref]) {
      expect(built).toEqual(expect.any(String));
      const parsed = new URL(built!);
      expect(parsed.search.startsWith('?/')).toBe(false);
      expect(parsed.pathname).toEqual(expect.stringMatching(/\/(tree|blob|raw|edit|new|commit)(\/|$)/));
    }
    expect(new URL(href!).pathname.endsWith('/tree/main')).toBe(true);
    expect(new URL(fileHref!).pathname).toContain('/blob/main/dashboards/a.json');
    expect(new URL(commitHref!).pathname).toContain('/commit/abc1234');
    // The new-file editor adds its own query. That query must not be the smuggled path.
    expect(new URL(newHref!).pathname).toContain('/new/main');
    expect(new URL(newHref!).search).toContain('filename=README.md');
  });
});
