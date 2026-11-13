import { render } from 'test/test-utils';

import { type GrafanaConfig, locationUtil } from '@grafana/data';
import { setTestFlags } from '@grafana/test-utils/unstable';
import { type RepositoryView } from 'app/api/clients/provisioning/v0alpha1';

import { type UseFolderDocsResult, useFolderDocs } from '../../hooks/useFolderDocs';
import { type UseFolderReadmeResult, useFolderReadme } from '../../hooks/useFolderReadme';

import { FolderReadmePanel } from './FolderReadmePanel';

jest.mock('../../hooks/useFolderDocs');
jest.mock('../../hooks/useFolderReadme');
jest.mock('mermaid', () => ({
  __esModule: true,
  default: { initialize: jest.fn(), parse: jest.fn().mockResolvedValue(true), render: jest.fn() },
}));

const mockUseFolderDocs = jest.mocked(useFolderDocs);
const mockUseFolderReadme = jest.mocked(useFolderReadme);

const repository: RepositoryView = {
  name: 'test-repo',
  target: 'folder',
  title: 'Test Repository',
  type: 'github',
  url: 'https://github.com/owner/repo',
  branch: 'main',
  workflows: [],
};

const readme = {
  key: 'readme' as const,
  path: 'dashboards/team-a/README.md',
  fileName: 'README.md',
};

/**
 * Media addresses the browser will fetch while painting the README.
 * Resolved the way the document resolves them, so a value that only looks
 * relative in the attribute is judged by the URL that is actually requested.
 */
function mediaRequestUrls(root: ParentNode): string[] {
  const urls: string[] = [];
  const push = (value: string | null | undefined) => {
    if (!value) {
      return;
    }
    const trimmed = value.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      return;
    }
    urls.push(new URL(trimmed, window.location.href).href);
  };

  root.querySelectorAll('img, audio, video, source, track, image').forEach((element) => {
    push(element.getAttribute('src'));
    push(element.getAttribute('poster'));
    const srcset = element.getAttribute('srcset');
    if (srcset) {
      for (const candidate of srcset.split(',')) {
        push(candidate.trim().split(/\s+/)[0]);
      }
    }
  });

  root.querySelectorAll<HTMLElement>('[style]').forEach((element) => {
    for (const match of element.getAttribute('style')?.matchAll(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi) ?? []) {
      push(match[2]);
    }
  });
  root.querySelectorAll('style').forEach((element) => {
    for (const match of element.textContent?.matchAll(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi) ?? []) {
      push(match[2]);
    }
  });

  return urls;
}

function renderReadme(markdown: string, repo: RepositoryView = repository, doc = readme) {
  mockUseFolderDocs.mockReturnValue({
    repository: repo,
    folder: { spec: { title: 'Test Folder' } },
    docs: [doc],
    isLoading: false,
  } as UseFolderDocsResult);
  mockUseFolderReadme.mockReturnValue({
    status: 'ok',
    markdownContent: markdown,
    refetch: jest.fn(),
    syncFinished: undefined,
  } satisfies UseFolderReadmeResult);

  return render(<FolderReadmePanel folderUID="folder-1" />);
}

function expectOnlyRepositoryMedia(container: HTMLElement, repoUrl: string) {
  const allowedHost = new URL(repoUrl).host;
  const urls = mediaRequestUrls(container);
  const offenders = urls.filter((url) => new URL(url).host !== allowedHost);
  expect(offenders).toEqual([]);
}

describe('provisioned folder README media requests', () => {
  beforeEach(() => {
    setTestFlags({ 'provisioning.readmes': true });
    locationUtil.initialize({
      config: { appSubUrl: '' } as GrafanaConfig,
      getTimeRangeForUrl: jest.fn(),
      getVariablesUrlParams: jest.fn(),
    });
  });

  it('keeps an image that resolves to the configured repository host', () => {
    const { container } = renderReadme(
      '![diagram](./diagram.png)\n\n![hosted](https://github.com/owner/repo/raw/main/diagram.png)'
    );
    const urls = mediaRequestUrls(container);

    expect(urls.map((url) => new URL(url).host)).toEqual(['github.com', 'github.com']);
    expect(urls.some((url) => url.includes('/diagram.png'))).toBe(true);
  });

  it('does not leave a root-relative image pointing at this Grafana server', () => {
    const { container } = renderReadme('![x](/logout)');

    expectOnlyRepositoryMedia(container, repository.url!);
  });

  it.each([
    ['markdown image of logout', (origin: string) => `![x](${origin}/logout)`],
    ['markdown image of organization switch', (origin: string) => `![x](${origin}/profile/switch-org/2)`],
    ['markdown image of token rotation', (origin: string) => `![x](${origin}/user/auth-tokens/rotate)`],
    ['raw image of logout', (origin: string) => `<img src="${origin}/logout" alt="">`],
    ['image with a query string', (origin: string) => `<img src="${origin}/logout?return=/">`],
    ['protocol-relative image', (_origin: string, host: string) => `<img src="//${host}/logout" alt="">`],
    [
      'image whose userinfo hides this server behind the repository host string',
      (_origin: string, host: string) => `<img src="https://github.com@${host}/logout" alt="">`,
    ],
    [
      'image on a host that only starts with the repository host',
      () => `<img src="https://github.com.attacker.example/logout" alt="">`,
    ],
    [
      'image srcset',
      (origin: string) =>
        `<img src="https://github.com/owner/repo/raw/main/ok.png" srcset="${origin}/logout 1x" alt="">`,
    ],
    ['audio element', (origin: string) => `<audio src="${origin}/logout"></audio>`],
    ['video element', (origin: string) => `<video src="${origin}/profile/switch-org/2"></video>`],
    ['video poster', (origin: string) => `<video poster="${origin}/logout"></video>`],
    ['video source element', (origin: string) => `<video><source src="${origin}/logout"></video>`],
    ['css background on an element', (origin: string) => `<div style="background-image:url(${origin}/logout)"></div>`],
    [
      'css background in a style element',
      (origin: string) => `<style>body{background-image:url(${origin}/logout)}</style>`,
    ],
    ['third-party image', () => `![x](https://cdn.example/pixel.png)`],
    ['data image', () => `<img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt="">`],
    ['image address with leading whitespace', (origin: string) => `<img src=" ${origin}/logout" alt="">`],
  ])('does not request %s from the rendered README', (_name, markdownFor) => {
    const origin = window.location.origin;
    const { container } = renderReadme(markdownFor(origin, window.location.host));

    expectOnlyRepositoryMedia(container, repository.url!);
  });

  it('applies the same media restriction to other folder markdown files', () => {
    const origin = window.location.origin;
    const { container } = renderReadme(`![x](${origin}/logout)`, repository, {
      key: 'contributing',
      path: 'dashboards/team-a/CONTRIBUTING.md',
      fileName: 'CONTRIBUTING.md',
    });

    expectOnlyRepositoryMedia(container, repository.url!);
  });

  it('drops same-origin media when the repository has no raw-file host', () => {
    const origin = window.location.origin;
    const { container } = renderReadme(`![x](${origin}/logout)`, {
      ...repository,
      type: 'local',
      url: '/data/repo',
    });

    expect(mediaRequestUrls(container)).toEqual([]);
  });
});
