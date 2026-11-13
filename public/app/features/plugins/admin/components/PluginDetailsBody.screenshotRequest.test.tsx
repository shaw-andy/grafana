import { OpenFeatureTestProvider } from '@openfeature/react-sdk';
import { render } from '@testing-library/react';
import type { JSX } from 'react';
import { Provider } from 'react-redux';

import { config, setBackendSrv } from '@grafana/runtime';
import { configureStore } from 'app/store/configureStore';

import { getPluginDetails } from '../api';
import { API_ROOT, GCOM_API_ROOT } from '../constants';
import { mapToCatalogPlugin } from '../helpers';
import { usePluginConfig } from '../hooks/usePluginConfig';
import { getLocalPluginMock, getRemotePluginMock } from '../mocks/mockHelpers';
import { PluginTabIds, type LocalPlugin, type RemotePlugin } from '../types';

import { PluginDetailsBody } from './PluginDetailsBody';

jest.mock('../hooks/usePluginConfig', () => ({
  usePluginConfig: jest.fn(),
}));

const usePluginConfigMock = jest.mocked(usePluginConfig);

const pluginId = 'catalog-plugin';
const pluginVersion = '1.2.3';
const safeScreenshot = 'img/overview-screenshot.png';

function renderWithStore(component: JSX.Element) {
  const store = configureStore();
  return render(
    <Provider store={store}>
      <OpenFeatureTestProvider>{component}</OpenFeatureTestProvider>
    </Provider>
  );
}

function installCatalogBackend(remote: RemotePlugin | 'missing', local: LocalPlugin[]) {
  const get = jest.fn(async (url: string) => {
    if (url.includes('/markdown/')) {
      return '';
    }
    if (url === API_ROOT) {
      return local;
    }
    if (url.startsWith(`${GCOM_API_ROOT}/plugins/`) && url.endsWith('/versions')) {
      return { items: [] };
    }
    if (url.startsWith(`${GCOM_API_ROOT}/plugins/`)) {
      if (remote === 'missing') {
        throw { status: 404, data: { message: 'not found' } };
      }
      return remote;
    }
    throw new Error(`unexpected catalog request ${url}`);
  });

  setBackendSrv({
    chunked: jest.fn(),
    delete: jest.fn(),
    fetch: jest.fn(),
    get,
    patch: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    request: jest.fn(),
    datasourceRequest: jest.fn(),
  });
}

/**
 * Same-origin image requests are safe only when the URL the browser will
 * request stays inside one plugin image directory. Dot segments are judged
 * after URL resolution, which is what the image element actually fetches.
 */
function isContainedScreenshotRequest(src: string, appSubUrl: string): boolean {
  const url = new URL(src, window.location.href);
  if (url.origin !== window.location.origin) {
    return true;
  }

  const prefix = `${appSubUrl}/api/gnet/plugins/`;
  if (!url.pathname.startsWith(prefix)) {
    return false;
  }

  const rest = url.pathname.slice(prefix.length);
  const match = /^([^/]+)\/versions\/([^/]+)\/images\/(.+)$/.exec(rest);
  if (!match) {
    return false;
  }

  const [, id, version, imagePath] = match;
  if (id === '.' || id === '..' || version === '.' || version === '..') {
    return false;
  }

  const segments = imagePath.split('/');
  return segments.length > 0 && segments.every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

describe('PluginDetailsBody screenshot requests', () => {
  const requested: string[] = [];
  let srcDescriptor: PropertyDescriptor | undefined;
  const originalAppSubUrl = config.appSubUrl;

  beforeEach(() => {
    requested.length = 0;
    config.appSubUrl = '';
    usePluginConfigMock.mockReturnValue({ value: null, loading: false });
    srcDescriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
    jest.spyOn(HTMLImageElement.prototype, 'src', 'set').mockImplementation(function (this: HTMLImageElement, value) {
      srcDescriptor?.set?.call(this, value);
      requested.push(this.src);
    });
  });

  afterEach(() => {
    config.appSubUrl = originalAppSubUrl;
    jest.restoreAllMocks();
  });

  async function showScreenshots(remote: RemotePlugin | 'missing', local: LocalPlugin[] = []) {
    const details = await getPluginDetails(typeof remote === 'string' ? pluginId : remote.slug);
    const catalog =
      remote === 'missing'
        ? mapToCatalogPlugin(local[0], undefined)
        : mapToCatalogPlugin(local[0], remote);
    catalog.details = details;

    renderWithStore(
      <PluginDetailsBody
        plugin={catalog}
        info={[]}
        queryParams={{}}
        pageId={PluginTabIds.SCREENSHOTS}
        showDetails={false}
      />
    );
  }

  function expectNoSameOriginEscape(appSubUrl = '') {
    expect(requested.length).toBeGreaterThan(0);
    for (const src of requested) {
      expect({ src, contained: isContainedScreenshotRequest(src, appSubUrl) }).toEqual({
        src,
        contained: true,
      });
    }
  }

  function expectSafeScreenshotKept() {
    expect(requested.some((src) => new URL(src).pathname.endsWith('/overview-screenshot.png'))).toBe(true);
  }

  it('requests a normal catalog screenshot inside the plugin image prefix', async () => {
    const remote = getRemotePluginMock({
      slug: pluginId,
      version: pluginVersion,
      json: {
        dependencies: { grafanaDependency: '>=8.0.0', plugins: [] },
        info: { links: [], screenshots: [{ name: 'Overview', path: safeScreenshot }] },
      },
    });
    installCatalogBackend(remote, []);

    await showScreenshots(remote);

    expect(requested.map((src) => new URL(src).pathname)).toEqual([
      '/api/gnet/plugins/catalog-plugin/versions/1.2.3/images/img/overview-screenshot.png',
    ]);
  });

  it.each([
    ['dot segments walk to logout', '../../../../../../../logout'],
    ['dot segments walk to switch org', '../../../../../../../profile/switch-org/2'],
    ['extra dot segments still walk to logout', '../../../../../../../../logout'],
    ['percent-encoded dot segments walk to logout', '%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/logout'],
    [
      'mixed encoded dot segments walk to logout',
      '.%2e/%2e./%2E%2E/%2e./.%2E/%2e%2e/%2E./logout',
    ],
    ['a query delimiter does not keep the walk inside the image prefix', '../../../../../../../logout?continue=1'],
    ['backslashes walk to logout', '..\\..\\..\\..\\..\\..\\..\\logout'],
    [
      'an absolute same-origin logout URL is not requested',
      `${window.location.origin}/logout`,
    ],
    [
      'an absolute same-origin switch-org URL is not requested',
      `${window.location.origin}/profile/switch-org/2`,
    ],
  ])('catalog screenshot path with %s stays inside the image prefix', async (_name, maliciousPath) => {
    const remote = getRemotePluginMock({
      slug: pluginId,
      version: pluginVersion,
      json: {
        dependencies: { grafanaDependency: '>=8.0.0', plugins: [] },
        info: {
          links: [],
          screenshots: [
            { name: 'Overview', path: safeScreenshot },
            { name: 'Walk', path: maliciousPath },
          ],
        },
      },
    });
    installCatalogBackend(remote, []);

    await showScreenshots(remote);

    expectNoSameOriginEscape();
    expectSafeScreenshotKept();
  });

  it('uses a local screenshot path when the catalog omits screenshots', async () => {
    const remote = getRemotePluginMock({
      slug: pluginId,
      version: pluginVersion,
      json: {
        dependencies: { grafanaDependency: '>=8.0.0', plugins: [] },
        info: { links: [] },
      },
    });
    const local = getLocalPluginMock({
      id: pluginId,
      info: {
        ...getLocalPluginMock().info,
        screenshots: [
          { name: 'Overview', path: safeScreenshot },
          // path.Join("public/plugins", id, ten "../" segments) still returns seven "../" segments.
          { name: 'Walk', path: '../../../../../../../logout' },
        ],
      },
    });
    installCatalogBackend(remote, [local]);

    await showScreenshots(remote, [local]);

    expectNoSameOriginEscape();
    expectSafeScreenshotKept();
  });

  it('uses a local screenshot path when the catalog cannot be loaded', async () => {
    const local = getLocalPluginMock({
      id: pluginId,
      latestVersion: pluginVersion,
      info: {
        ...getLocalPluginMock().info,
        version: pluginVersion,
        screenshots: [
          { name: 'Overview', path: safeScreenshot },
          {
            name: 'Encoded walk',
            path: 'public/plugins/catalog-plugin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/logout',
          },
        ],
      },
    });
    installCatalogBackend('missing', [local]);

    await showScreenshots('missing', [local]);

    expectNoSameOriginEscape();
    expectSafeScreenshotKept();
  });

  it('does not let the published version walk out of the image prefix', async () => {
    const remote = getRemotePluginMock({
      slug: pluginId,
      version: '1.2.3/../../../../../../logout?',
      json: {
        dependencies: { grafanaDependency: '>=8.0.0', plugins: [] },
        info: { links: [], screenshots: [{ name: 'Overview', path: safeScreenshot }] },
      },
    });
    installCatalogBackend(remote, []);

    await showScreenshots(remote);

    expectNoSameOriginEscape();
  });

  it('does not let the plugin id walk out of the image prefix', async () => {
    const remote = getRemotePluginMock({
      slug: 'catalog-plugin/../../../../logout?',
      version: pluginVersion,
      json: {
        dependencies: { grafanaDependency: '>=8.0.0', plugins: [] },
        info: { links: [], screenshots: [{ name: 'Overview', path: safeScreenshot }] },
      },
    });
    installCatalogBackend(remote, []);

    await showScreenshots(remote);

    expectNoSameOriginEscape();
  });

  it('keeps screenshot requests inside the image prefix when appSubUrl is set', async () => {
    config.appSubUrl = '/grafana';
    const remote = getRemotePluginMock({
      slug: pluginId,
      version: pluginVersion,
      json: {
        dependencies: { grafanaDependency: '>=8.0.0', plugins: [] },
        info: {
          links: [],
          screenshots: [
            { name: 'Overview', path: safeScreenshot },
            { name: 'Root logout', path: '../../../../../../../../logout' },
            { name: 'Subpath logout', path: '../../../../../../../logout' },
            { name: 'Subpath org', path: '../../../../../../../profile/switch-org/2' },
          ],
        },
      },
    });
    installCatalogBackend(remote, []);

    await showScreenshots(remote);

    expectNoSameOriginEscape('/grafana');
    expect(requested.some((src) => new URL(src).pathname.endsWith('/overview-screenshot.png'))).toBe(true);
    expect(
      requested.some(
        (src) => new URL(src).pathname === '/grafana/api/gnet/plugins/catalog-plugin/versions/1.2.3/images/img/overview-screenshot.png'
      )
    ).toBe(true);
  });
});
