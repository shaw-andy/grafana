import { OpenFeatureTestProvider } from '@openfeature/react-sdk';
import { act, render, type RenderResult } from '@testing-library/react';
import { Provider } from 'react-redux';

import { getBackendSrv, setBackendSrv, type BackendSrv } from '@grafana/runtime';
import { configureStore } from 'app/store/configureStore';

import { getPluginDetails } from './api';
import { PluginDetailsBody } from './components/PluginDetailsBody';
import { getCatalogPluginMock } from './mocks/mockHelpers';
import { type CatalogPluginDetails, PluginTabIds } from './types';

const PLUGIN_ID = 'catalog-html-fixture';

// Event-handler markup in the shape the catalog mock already stores for readme and changelog:
// HTML, not markdown. The overview and changelog tabs assign that string with innerHTML.
const CATALOG_EVENT_HTML = [
  '<h1>Catalog copy</h1>',
  '<img src="x" onerror="window.catalogHandler = 1">',
  '<img src="x" OnError="window.catalogHandler = 2">',
  '<svg onload="window.catalogHandler = 3"></svg>',
  '<button onclick="window.catalogHandler = 4">x</button>',
].join('');

function eventHandlerAttributes(root: ParentNode): string[] {
  const found: string[] = [];
  root.querySelectorAll('*').forEach((element) => {
    for (const attribute of Array.from(element.attributes)) {
      if (attribute.name.toLowerCase().startsWith('on')) {
        found.push(`${element.tagName.toLowerCase()} ${attribute.name}`);
      }
    }
  });
  return found;
}

function respond(body: string | number): Promise<unknown> {
  if (typeof body === 'number') {
    return Promise.reject({ status: body, data: { message: 'not found' } });
  }
  return Promise.resolve(body);
}

function installCatalogBackend({
  localPlugins,
  readme,
  changelog,
}: {
  localPlugins: unknown[];
  readme: string | number;
  changelog: string | number;
}) {
  const current = getBackendSrv();
  setBackendSrv({
    ...current,
    get: (path: string) => {
      if (path === `/api/gnet/plugins/${PLUGIN_ID}`) {
        return Promise.resolve({
          slug: PLUGIN_ID,
          readme: CATALOG_EVENT_HTML,
          changelog: CATALOG_EVENT_HTML,
          signatureType: '',
          json: { info: { links: [] }, dependencies: { plugins: [] } },
        });
      }
      if (path === '/api/plugins') {
        return Promise.resolve(localPlugins);
      }
      if (path === `/api/gnet/plugins/${PLUGIN_ID}/versions`) {
        return Promise.resolve({
          items: [
            {
              version: '1.0.0',
              createdAt: '2020-01-01T00:00:00.000Z',
              isCompatible: true,
              grafanaDependency: '',
              angularDetected: false,
              status: 'active',
            },
          ],
        });
      }
      if (path === `/api/plugins/${PLUGIN_ID}/markdown/README`) {
        return respond(readme);
      }
      if (path === `/api/plugins/${PLUGIN_ID}/markdown/CHANGELOG`) {
        return respond(changelog);
      }
      return Promise.reject(new Error(`unexpected catalog request ${path}`));
    },
  } as BackendSrv);
}

async function renderCatalogTab(pageId: PluginTabIds, details: CatalogPluginDetails): Promise<RenderResult> {
  const store = configureStore();
  const plugin = getCatalogPluginMock({
    id: PLUGIN_ID,
    isInstalled: false,
    isDeprecated: false,
    details,
  });

  let rendered: RenderResult;
  await act(async () => {
    rendered = render(
      <Provider store={store}>
        <OpenFeatureTestProvider>
          <PluginDetailsBody plugin={plugin} info={[]} queryParams={{}} pageId={pageId} showDetails={false} />
        </OpenFeatureTestProvider>
      </Provider>
    );
  });
  return rendered!;
}

describe('catalog HTML on the plugin admin page', () => {
  const originalBackend = getBackendSrv();

  afterEach(() => {
    setBackendSrv(originalBackend);
  });

  it('does not render catalog readme event handlers when the plugin is not installed', async () => {
    installCatalogBackend({ localPlugins: [], readme: 404, changelog: 404 });

    const details = await getPluginDetails(PLUGIN_ID);
    const rendered = await renderCatalogTab(PluginTabIds.OVERVIEW, details);

    expect(eventHandlerAttributes(rendered.container)).toEqual([]);
  });

  it('does not render catalog readme event handlers when the installed README is empty', async () => {
    installCatalogBackend({
      localPlugins: [{ id: PLUGIN_ID, info: { version: '1.0.0', links: [] } }],
      readme: '',
      changelog: 404,
    });

    const details = await getPluginDetails(PLUGIN_ID);
    const rendered = await renderCatalogTab(PluginTabIds.OVERVIEW, details);

    expect(eventHandlerAttributes(rendered.container)).toEqual([]);
  });

  it('does not render catalog changelog event handlers when there is no local changelog', async () => {
    installCatalogBackend({ localPlugins: [], readme: 404, changelog: 404 });

    const details = await getPluginDetails(PLUGIN_ID);
    const rendered = await renderCatalogTab(PluginTabIds.CHANGELOG, details);

    expect(eventHandlerAttributes(rendered.container)).toEqual([]);
  });

  it('does not render catalog changelog event handlers when a local changelog exists', async () => {
    installCatalogBackend({
      localPlugins: [{ id: PLUGIN_ID, info: { version: '1.0.0', links: [] } }],
      readme: '# Local readme',
      changelog: '# Local changelog',
    });

    const details = await getPluginDetails(PLUGIN_ID);
    const rendered = await renderCatalogTab(PluginTabIds.CHANGELOG, details);

    expect(eventHandlerAttributes(rendered.container)).toEqual([]);
  });
});
