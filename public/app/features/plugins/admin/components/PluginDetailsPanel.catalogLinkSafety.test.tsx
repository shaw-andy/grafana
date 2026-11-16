import { render } from 'test/test-utils';

import { PluginSignatureStatus, PluginType } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';

import { getPluginDetails } from '../api';
import { addPlugins, fetchDetails } from '../state/actions';
import { reducer } from '../state/reducer';
import { type CatalogPlugin, type LocalPlugin, type RemotePlugin } from '../types';

import { PluginDetailsPanel } from './PluginDetailsPanel';

const PLUGIN_ID = 'catalog-publisher-plugin';

/**
 * A catalog navigation is unsafe when following it would send the signed-in
 * session cookie to this Grafana server, or when the address is not an
 * absolute http(s) URL on another host. sanitizeUrl only rewrites script
 * URLs, so these checks look at the href the browser actually receives.
 */
function isUnsafeCatalogHref(href: string | null): boolean {
  if (href == null) {
    return false;
  }

  const trimmed = href.trim();
  if (trimmed.startsWith('//')) {
    return true;
  }

  let url: URL;
  try {
    url = new URL(href, window.location.href);
  } catch {
    return true;
  }

  if (url.protocol === 'about:' && url.pathname === 'blank') {
    return false;
  }

  if (url.hostname.toLowerCase() === window.location.hostname.toLowerCase()) {
    return true;
  }

  return url.protocol !== 'http:' && url.protocol !== 'https:';
}

function unsafeHrefs(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll('a')).flatMap((anchor) => {
    const href = anchor.getAttribute('href');
    return isUnsafeCatalogHref(href) ? [href ?? ''] : [];
  });
}

function catalogPluginShell(): CatalogPlugin {
  return {
    description: 'Published by an external catalog author',
    downloads: 1,
    hasUpdate: false,
    id: PLUGIN_ID,
    info: {
      logos: { small: 'small', large: 'large' },
      keywords: [],
    },
    isDev: false,
    isCore: false,
    isEnterprise: false,
    isInstalled: false,
    isDisabled: false,
    isDeprecated: false,
    isPreinstalled: { found: false, withVersion: false },
    isPublished: true,
    name: 'Catalog publisher plugin',
    orgName: 'External publisher',
    signature: PluginSignatureStatus.valid,
    popularity: 0,
    publishedAt: '2024-01-01',
    type: PluginType.app,
    updatedAt: '2024-01-02',
    angularDetected: false,
    isFullyInstalled: false,
    accessControl: {},
    managed: { enabled: false },
  };
}

function installCatalogResponse(
  remote: Partial<RemotePlugin> | undefined,
  localLinks?: Array<{ name: string; url: string }>
) {
  const local: LocalPlugin[] =
    localLinks === undefined
      ? []
      : [
          {
            id: PLUGIN_ID,
            info: { links: localLinks },
          } as LocalPlugin,
        ];

  setBackendSrv({
    chunked: jest.fn(),
    delete: jest.fn(),
    fetch: jest.fn(),
    get: jest.fn(async (url: string) => {
      if (url === '/api/plugins') {
        return local;
      }
      if (url === `/api/gnet/plugins/${PLUGIN_ID}`) {
        if (remote === undefined) {
          throw new Error('catalog plugin is not published');
        }
        return remote;
      }
      if (url.startsWith(`/api/gnet/plugins/${PLUGIN_ID}/versions`)) {
        return { items: [] };
      }
      if (url.startsWith(`/api/plugins/${PLUGIN_ID}/markdown/`)) {
        return '';
      }
      throw new Error(`unexpected catalog request ${url}`);
    }),
    patch: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    request: jest.fn(),
    datasourceRequest: jest.fn(),
  });
}

async function renderCatalogPlugin(
  remote: Partial<RemotePlugin> | undefined,
  localLinks?: Array<{ name: string; url: string }>
) {
  installCatalogResponse(remote, localLinks);
  const details = await getPluginDetails(PLUGIN_ID);
  const loaded = reducer(undefined, { type: '@@INIT' });
  const withPlugin = reducer(loaded, addPlugins([catalogPluginShell()]));
  const withDetails = reducer(
    withPlugin,
    fetchDetails.fulfilled({ id: PLUGIN_ID, changes: { details } }, 'catalog-details', PLUGIN_ID)
  );
  const plugin = withDetails.items.entities[PLUGIN_ID];
  if (!plugin) {
    throw new Error('catalog plugin was not stored');
  }

  return render(<PluginDetailsPanel plugin={plugin} pluginExtentionsInfo={[]} />);
}

function remotePlugin(
  fields: Partial<RemotePlugin>,
  links: Array<{ name: string; url: string }> = []
): Partial<RemotePlugin> {
  return {
    slug: PLUGIN_ID,
    signatureType: '',
    json: {
      dependencies: {
        grafanaDependency: '>=10.0.0',
        plugins: [],
      },
      info: { links },
    },
    ...fields,
  };
}

describe('PluginDetailsPanel catalog links', () => {
  const previousAppUrl = config.appUrl;

  beforeEach(() => {
    config.appUrl = `${window.location.origin}/`;
    window.history.pushState({}, '', `/plugins/${PLUGIN_ID}/`);
  });

  afterEach(() => {
    config.appUrl = previousAppUrl;
  });

  it('keeps an external https repository link', async () => {
    const { container } = await renderCatalogPlugin(
      remotePlugin(
        {
          repositoryUrl: 'https://example.com/plugin-repo',
          documentationUrl: 'https://example.com/plugin-docs',
          licenseUrl: 'https://example.com/plugin-license',
          raiseAnIssueUrl: 'https://example.com/plugin-issues',
          sponsorshipUrl: 'https://example.com/plugin-sponsor',
        },
        [{ name: 'Website', url: 'https://example.com/plugin-site' }]
      )
    );

    expect(unsafeHrefs(container)).toEqual([]);
    expect(container.querySelector('[data-testid="plugin-details-repository-link"]')?.getAttribute('href')).toBe(
      'https://example.com/plugin-repo'
    );
    expect(container.querySelector('[data-testid="plugin-details-documentation-link"]')?.getAttribute('href')).toBe(
      'https://example.com/plugin-docs'
    );
    expect(container.querySelector('[data-testid="plugin-details-license-link"]')?.getAttribute('href')).toBe(
      'https://example.com/plugin-license'
    );
    expect(container.querySelector('[data-testid="plugin-details-raise-issue-link"]')?.getAttribute('href')).toBe(
      'https://example.com/plugin-issues'
    );
    expect(container.querySelector('[data-testid="plugin-details-sponsorship-link"]')?.getAttribute('href')).toBe(
      'https://example.com/plugin-sponsor'
    );
    expect(container.querySelector('[data-testid="plugin-details-custom-links"] a')?.getAttribute('href')).toBe(
      'https://example.com/plugin-site'
    );
  });

  it.each([
    ['repository', '/logout', { repositoryUrl: '/logout' }],
    ['documentation', '/profile/switch-org/2', { documentationUrl: '/profile/switch-org/2' }],
    ['license', `${window.location.origin}/logout`, { licenseUrl: `${window.location.origin}/logout` }],
    [
      'raise an issue',
      `${window.location.origin}/profile/switch-org/2`,
      { raiseAnIssueUrl: `${window.location.origin}/profile/switch-org/2` },
    ],
    ['sponsorship', `//${window.location.host}/logout`, { sponsorshipUrl: `//${window.location.host}/logout` }],
    ['repository with a trailing slash', '/logout/', { repositoryUrl: '/logout/' }],
    ['repository encoded as the logout path', '/%6Cogout', { repositoryUrl: '/%6Cogout' }],
    ['documentation with a leading space', ' /profile/switch-org/2', { documentationUrl: ' /profile/switch-org/2' }],
    ['license html-entity path', '&#47;logout', { licenseUrl: '&#47;logout' }],
    [
      'raise an issue html-entity org switch',
      '&#47;profile/switch-org/2',
      { raiseAnIssueUrl: '&#47;profile/switch-org/2' },
    ],
    ['sponsorship with a stripped control character', '/\u0009logout', { sponsorshipUrl: '/\tlogout' }],
    [
      'repository on this host with a different scheme',
      `https://${window.location.hostname}/logout`,
      { repositoryUrl: `https://${window.location.hostname}/logout` },
    ],
    ['documentation protocol-relative external host', '//example.com/docs', { documentationUrl: '//example.com/docs' }],
    ['license relative to the plugin page', '../logout', { licenseUrl: '../logout' }],
    [
      'raise an issue uppercase host',
      `http://${window.location.hostname.toUpperCase()}/logout`,
      { raiseAnIssueUrl: `http://${window.location.hostname.toUpperCase()}/logout` },
    ],
  ])('does not navigate the %s control to %s', async (_label, _url, fields) => {
    const { container } = await renderCatalogPlugin(remotePlugin(fields));
    expect(unsafeHrefs(container)).toEqual([]);
  });

  it.each([
    ['remote custom link', '/logout'],
    ['remote custom link org switch', '/profile/switch-org/2'],
    ['remote custom link absolute same host', `${window.location.origin}/logout`],
    ['remote custom link html entity', '&#47;logout'],
    ['remote custom link protocol-relative', `//${window.location.host}/profile/switch-org/2`],
  ])('does not navigate a %s', async (_name, url) => {
    const { container } = await renderCatalogPlugin(
      remotePlugin({}, [
        { name: 'Publisher notes', url },
        { name: 'Website', url: 'https://example.com/plugin-site' },
      ])
    );

    expect(unsafeHrefs(container)).toEqual([]);
    const hrefs = Array.from(container.querySelectorAll('[data-testid="plugin-details-custom-links"] a')).map(
      (anchor) => anchor.getAttribute('href')
    );
    expect(hrefs).toContain('https://example.com/plugin-site');
  });

  it('does not navigate a custom link taken from the installed plugin metadata', async () => {
    const { container } = await renderCatalogPlugin(
      remotePlugin({}, [{ name: 'Website', url: 'https://example.com/plugin-site' }]),
      [
        { name: 'Installed docs', url: '/logout' },
        { name: 'Installed site', url: 'https://example.com/installed-site' },
      ]
    );

    expect(unsafeHrefs(container)).toEqual([]);
    const hrefs = Array.from(container.querySelectorAll('[data-testid="plugin-details-custom-links"] a')).map(
      (anchor) => anchor.getAttribute('href')
    );
    expect(hrefs).toContain('https://example.com/installed-site');
    expect(hrefs).not.toContain('/logout');
  });
});
