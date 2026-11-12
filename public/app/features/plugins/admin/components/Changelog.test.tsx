import { render, screen } from '@testing-library/react';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type JSX } from 'react';
import { Provider } from 'react-redux';

import { setBackendSrv, type BackendSrv } from '@grafana/runtime';
import { configureStore } from 'app/store/configureStore';

import { getPluginDetails } from '../api';
import { API_ROOT, GCOM_API_ROOT } from '../constants';
import { usePluginConfig } from '../hooks/usePluginConfig';
import { getCatalogPluginMock, getLocalPluginMock, getRemotePluginMock } from '../mocks/mockHelpers';
import { PluginTabIds, type CatalogPluginDetails } from '../types';

import { PluginDetailsBody } from './PluginDetailsBody';

jest.mock('../hooks/usePluginConfig', () => ({
  usePluginConfig: jest.fn(),
}));

const usePluginConfigMock = jest.mocked(usePluginConfig);

const PLUGIN_ID = 'publisher-notes-app';
const INSTALLED_VERSION = '1.2.3';
const CATALOG_CHANGELOG_TEXT = 'Catalog release note';
const LOCAL_CHANGELOG_TEXT = 'This build is installed locally.';
const CATALOG_README_TEXT = 'Catalog overview note';

// Event-handler markup in the shape the catalog already returns for changelog and readme (HTML, not markdown).
const CATALOG_CHANGELOG_HTML = [
  `<h2>${CATALOG_CHANGELOG_TEXT}</h2>`,
  `<img src="x" alt="catalog-figure" onerror="document.documentElement.setAttribute('data-catalog-handler','ran')">`,
  `<img src=x alt=catalog-unquoted onerror=document.documentElement.setAttribute('data-catalog-unquoted','ran')>`,
  `<a href="#notes" onclick="document.documentElement.setAttribute('data-catalog-click','ran')">notes</a>`,
  `<svg xmlns="http://www.w3.org/2000/svg" onload="document.documentElement.setAttribute('data-catalog-load','ran')"></svg>`,
  `<img src="x" alt="catalog-case" OnError="document.documentElement.setAttribute('data-catalog-case','ran')">`,
  "<script>document.documentElement.setAttribute('data-catalog-script','ran')</script>",
].join('\n');

const CATALOG_README_HTML = `<h2>${CATALOG_README_TEXT}</h2><img src="x" alt="readme-figure" onerror="document.documentElement.setAttribute('data-readme-handler','ran')">`;

const LOCAL_CHANGELOG_MARKDOWN = `# Local release note\n\n${LOCAL_CHANGELOG_TEXT}`;

// Markers set by handlers that fire on parse (img onerror, svg onload). Click handlers are
// checked as attributes below; a script inserted with innerHTML does not run, so it is not listed.
const CHANGELOG_HANDLER_MARKERS = [
  'data-catalog-handler="ran"',
  'data-catalog-unquoted="ran"',
  'data-catalog-load="ran"',
  'data-catalog-case="ran"',
];

function renderWithStore(component: JSX.Element) {
  const store = configureStore();
  return render(<Provider store={store}>{component}</Provider>);
}

function parsedHandlerAttributes(html: string): string[] {
  return handlerAttributes(new DOMParser().parseFromString(html, 'text/html'));
}

function handlerAttributes(root: ParentNode): string[] {
  const found: string[] = [];
  root.querySelectorAll('*').forEach((element) => {
    for (const name of element.getAttributeNames()) {
      if (name.toLowerCase().startsWith('on')) {
        found.push(`${element.tagName.toLowerCase()}[${name}]`);
      }
    }
  });
  return found;
}

// Re-assigns the HTML string with innerHTML, which is what the changelog and readme tabs do.
// Chrome parses the resulting event-handler attributes and runs them; jsdom does not.
function browserInnerHtml(html: string): string {
  const directory = mkdtempSync(join(tmpdir(), 'catalog-html-'));
  const pagePath = join(directory, 'page.html');
  const payload = Buffer.from(html, 'utf8').toString('base64');
  writeFileSync(
    pagePath,
    `<!doctype html><html><body><div id="out"></div><script>
      document.getElementById('out').innerHTML = atob(${JSON.stringify(payload)});
    </script></body></html>`
  );

  // Chrome prints the DOM and then keeps the headless process alive, so timeout stops it after the dump.
  const result = spawnSync(
    'timeout',
    [
      '20s',
      'google-chrome',
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--virtual-time-budget=2000',
      '--dump-dom',
      `file://${pagePath}`,
    ],
    { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
  );
  if (!result.stdout.includes('<html')) {
    throw new Error(`Chrome did not dump the page (status ${result.status}): ${result.stderr}`);
  }
  return result.stdout;
}

function mockCatalogApis({
  remoteChangelog,
  remoteReadme,
  localChangelog,
  localReadme,
}: {
  remoteChangelog: string;
  remoteReadme: string;
  localChangelog?: string;
  localReadme?: string;
}) {
  const remote = getRemotePluginMock({
    slug: PLUGIN_ID,
    name: 'Publisher notes',
    changelog: remoteChangelog,
    readme: remoteReadme,
    version: INSTALLED_VERSION,
  });
  const local = getLocalPluginMock({
    id: PLUGIN_ID,
    name: 'Publisher notes',
    info: {
      ...getLocalPluginMock().info,
      version: INSTALLED_VERSION,
    },
  });

  const get = jest.fn(async (path: string) => {
    if (path === `${GCOM_API_ROOT}/plugins/${PLUGIN_ID}`) {
      return remote;
    }
    if (path === `${GCOM_API_ROOT}/plugins/${PLUGIN_ID}/versions`) {
      return {
        items: [
          {
            version: INSTALLED_VERSION,
            createdAt: '2024-01-01T00:00:00.000Z',
            isCompatible: true,
            grafanaDependency: '>=10.0.0',
            angularDetected: false,
            status: 'active',
          },
        ],
      };
    }
    if (path === API_ROOT) {
      return [local];
    }
    if (path === `${API_ROOT}/${PLUGIN_ID}/markdown/CHANGELOG`) {
      if (localChangelog === undefined) {
        throw new Error('changelog missing');
      }
      return localChangelog;
    }
    if (path === `${API_ROOT}/${PLUGIN_ID}/markdown/README`) {
      if (localReadme === undefined) {
        throw new Error('readme missing');
      }
      return localReadme;
    }
    throw new Error(`unexpected plugin request: ${path}`);
  });

  setBackendSrv({ get } as unknown as BackendSrv);
  return get;
}

async function loadDetails(): Promise<CatalogPluginDetails> {
  return getPluginDetails(PLUGIN_ID);
}

describe('catalog changelog and readme HTML', () => {
  jest.setTimeout(45000);

  beforeEach(() => {
    usePluginConfigMock.mockReturnValue({ value: null, loading: false, error: undefined });
  });

  it('does not run a catalog changelog event handler on the changelog tab when a sanitized local changelog also exists', async () => {
    mockCatalogApis({
      remoteChangelog: CATALOG_CHANGELOG_HTML,
      remoteReadme: '<p>Remote readme</p>',
      localChangelog: LOCAL_CHANGELOG_MARKDOWN,
      localReadme: '# Local readme\n\nLocal overview.',
    });

    const details = await loadDetails();
    const plugin = getCatalogPluginMock({
      id: PLUGIN_ID,
      name: 'Publisher notes',
      isPublished: true,
      isCore: false,
      isInstalled: false,
      details,
    });

    const { container } = renderWithStore(
      <PluginDetailsBody
        plugin={plugin}
        info={[]}
        queryParams={{}}
        pageId={PluginTabIds.CHANGELOG}
        showDetails={false}
      />
    );

    expect(screen.getByRole('heading', { name: CATALOG_CHANGELOG_TEXT })).toBeInTheDocument();
    expect(screen.queryByText(LOCAL_CHANGELOG_TEXT)).not.toBeInTheDocument();
    expect(handlerAttributes(container)).toEqual([]);
    expect(container.querySelector('script')).toBeNull();
    expect(parsedHandlerAttributes(details.changelog ?? '')).toEqual([]);

    const rendered = browserInnerHtml(container.innerHTML);
    expect(rendered).toContain(CATALOG_CHANGELOG_TEXT);
    for (const marker of CHANGELOG_HANDLER_MARKERS) {
      expect(rendered).not.toContain(marker);
    }
  });

  it('does not run a catalog readme event handler on the overview tab when the installed plugin has no readme', async () => {
    mockCatalogApis({
      remoteChangelog: '',
      remoteReadme: CATALOG_README_HTML,
      localChangelog: LOCAL_CHANGELOG_MARKDOWN,
      localReadme: undefined,
    });

    const details = await loadDetails();
    const plugin = getCatalogPluginMock({
      id: PLUGIN_ID,
      name: 'Publisher notes',
      isPublished: true,
      isCore: false,
      isInstalled: false,
      details,
    });

    const { container } = renderWithStore(
      <PluginDetailsBody
        plugin={plugin}
        info={[]}
        queryParams={{}}
        pageId={PluginTabIds.OVERVIEW}
        showDetails={false}
      />
    );

    expect(screen.getByRole('heading', { name: CATALOG_README_TEXT })).toBeInTheDocument();
    expect(handlerAttributes(container)).toEqual([]);
    expect(container.querySelector('script')).toBeNull();
    expect(parsedHandlerAttributes(details.readme ?? '')).toEqual([]);

    const rendered = browserInnerHtml(container.innerHTML);
    expect(rendered).toContain(CATALOG_README_TEXT);
    expect(rendered).not.toContain('data-readme-handler="ran"');
  });
});
