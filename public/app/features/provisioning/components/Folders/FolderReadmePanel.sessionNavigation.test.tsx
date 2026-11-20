import { act, render, screen } from 'test/test-utils';

import { type GrafanaConfig, locationUtil } from '@grafana/data';
import { locationService } from '@grafana/runtime';
import { setTestFlags } from '@grafana/test-utils/unstable';
import { interceptLinkClicks } from 'app/core/navigation/patch/interceptLinkClicks';
import { contextSrv } from 'app/core/services/context_srv';

import { type UseFolderDocsResult, useFolderDocs } from '../../hooks/useFolderDocs';
import { type UseFolderReadmeResult, useFolderReadme } from '../../hooks/useFolderReadme';
import { setupProvisioningMswServer } from '../../mocks/server';
import { type FolderDoc } from '../../utils/folderDocConventions';

import { FolderReadmePanel } from './FolderReadmePanel';

jest.mock('../../hooks/useFolderDocs');
jest.mock('../../hooks/useFolderReadme');
jest.mock('mermaid', () => ({
  __esModule: true,
  default: { initialize: jest.fn(), parse: jest.fn().mockResolvedValue(true), render: jest.fn() },
}));

setupProvisioningMswServer();

const GRAFANA_ORIGIN = 'http://localhost:3000';
const GIT_HOST_README = 'https://github.com/owner/repo/blob/main/dashboards/team-a/README.md';
const GIT_HOST_GUIDE = 'https://github.com/owner/repo/blob/main/dashboards/team-a/guide.md';

/**
 * Markdown a repository committer can place in a folder README. The addresses
 * are the ones the folder page must not follow in this tab: the Grafana origin
 * logout URL, a query-only org switch, that logout URL with an org id, a
 * protocol-relative logout URL, and other non-git-host schemes. The last two
 * links are files on the connected git host and must stay.
 */
const attackerReadme = [
  '[Sign out](http://localhost:3000/logout)',
  '[Switch organization](?orgId=2)',
  '[Sign out there](http://localhost:3000/logout?orgId=2)',
  '[Protocol relative](//localhost:3000/logout)',
  '[Other site](https://example.com/phish)',
  '[Mail](mailto:someone@example.com)',
  '[Section](#section)',
  '[Sibling](./guide.md)',
  `[On the git host](${GIT_HOST_README})`,
].join('\n\n');

const mockUseFolderDocs = jest.mocked(useFolderDocs);
const mockUseFolderReadme = jest.mocked(useFolderReadme);

const readmeDoc: FolderDoc = {
  key: 'readme',
  path: 'dashboards/team-a/README.md',
  fileName: 'README.md',
};

function setFolder() {
  const docs: UseFolderDocsResult = {
    repository: {
      name: 'test-repo',
      target: 'folder',
      title: 'Test Repository',
      type: 'github',
      url: 'https://github.com/owner/repo',
      branch: 'main',
      workflows: [],
    },
    folder: {
      metadata: { name: 'test-folder' },
      spec: { title: 'Test Folder' },
      status: {},
    } as UseFolderDocsResult['folder'],
    docs: [readmeDoc],
    isLoading: false,
  };
  mockUseFolderDocs.mockReturnValue(docs);
}

function setReadme(markdownContent: string) {
  const result: UseFolderReadmeResult = {
    status: 'ok',
    markdownContent,
    refetch: jest.fn(),
    syncFinished: undefined,
  };
  mockUseFolderReadme.mockReturnValue(result);
}

interface LocationDouble {
  navigations: string[];
  restore: () => void;
}

function installLocationDouble(): LocationDouble {
  const navigations: string[] = [];
  let href = `${GRAFANA_ORIGIN}/dashboards/f/test-folder`;
  const location = {
    origin: GRAFANA_ORIGIN,
    protocol: 'http:',
    host: 'localhost:3000',
    hostname: 'localhost',
    pathname: '/dashboards/f/test-folder',
    search: '',
    hash: '',
    assign: (url: string) => {
      navigations.push(url);
    },
    replace: (url: string) => {
      navigations.push(url);
    },
    get href() {
      return href;
    },
    set href(value: string) {
      href = value;
      navigations.push(value);
    },
  };
  const original = Object.getOwnPropertyDescriptor(window, 'location');
  Object.defineProperty(window, 'location', { configurable: true, value: location });
  return {
    navigations,
    restore() {
      if (original) {
        Object.defineProperty(window, 'location', original);
      }
    },
  };
}

describe('FolderReadmePanel session navigation', () => {
  const originalOrgId = contextSrv.user.orgId;
  let locationDouble: LocationDouble;

  beforeEach(() => {
    setTestFlags({ 'provisioning.readmes': true });
    locationUtil.initialize({
      config: { appSubUrl: '' } as GrafanaConfig,
      getTimeRangeForUrl: jest.fn(),
      getVariablesUrlParams: jest.fn(),
    });
    contextSrv.user.orgId = 1;
    setFolder();
    setReadme(attackerReadme);
    locationDouble = installLocationDouble();
    document.addEventListener('click', interceptLinkClicks);
  });

  afterEach(() => {
    document.removeEventListener('click', interceptLinkClicks);
    locationDouble.restore();
    contextSrv.user.orgId = originalOrgId;
    act(() => {
      setTestFlags({});
    });
  });

  it('keeps a repository-relative file link on the git host and opens it in a new tab', () => {
    render(<FolderReadmePanel folderUID="test-folder" />);

    const link = screen.getByRole('link', { name: 'Sibling' });
    expect(link).toHaveAttribute('href', GIT_HOST_GUIDE);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link.getAttribute('rel')).toContain('noopener');
  });

  it('opens an absolute link on the configured git host in a new tab', async () => {
    const { user } = render(<FolderReadmePanel folderUID="test-folder" />);
    const pushSpy = jest.spyOn(locationService, 'push').mockImplementation(() => {});

    const link = screen.getByRole('link', { name: 'On the git host' });
    expect(link).toHaveAttribute('href', GIT_HOST_README);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link.getAttribute('rel')).toContain('noopener');

    await user.click(link);

    expect(locationDouble.navigations).toEqual([]);
    expect(pushSpy).not.toHaveBeenCalled();
  });

  it.each([
    ['Sign out', 'http://localhost:3000/logout'],
    ['Switch organization', '?orgId=2'],
    ['Sign out there', 'http://localhost:3000/logout?orgId=2'],
    ['Protocol relative', '//localhost:3000/logout'],
    ['Other site', 'https://example.com/phish'],
    ['Mail', 'mailto:someone@example.com'],
    ['Section', '#section'],
  ])('does not leave %s as a link that can navigate this Grafana tab', async (label) => {
    const { user } = render(<FolderReadmePanel folderUID="test-folder" />);
    const pushSpy = jest.spyOn(locationService, 'push').mockImplementation(() => {});

    const link = screen.queryByRole('link', { name: label });
    if (link) {
      await user.click(link);
    }

    expect({
      href: link?.getAttribute('href') ?? null,
      navigations: locationDouble.navigations,
      pushes: pushSpy.mock.calls,
    }).toEqual({ href: null, navigations: [], pushes: [] });
  });
});
