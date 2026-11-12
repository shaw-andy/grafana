import { PluginType, type DataSourcePluginMeta } from '@grafana/data';
import { setDatasourcePluginMetas } from '@grafana/runtime/internal';
import { setLogger } from '@grafana/runtime/unstable';

import { importPluginModuleInSandbox } from './sandboxPluginLoader';

/**
 * Spec for the frontend plugin sandbox: plugin code must not be able to run
 * script in the Grafana page by assigning a javascript URL to the location
 * object the sandbox exposes. These tests fail while that assignment still
 * reaches the host page Location.
 */
const MARKER = '__sandboxLocationMarker';

function marker(): string | undefined {
  return (window as unknown as Record<string, string | undefined>)[MARKER];
}

function setMarker(value: string | undefined) {
  (window as unknown as Record<string, string | undefined>)[MARKER] = value;
}

describe('sandboxed plugin location', () => {
  beforeAll(() => {
    setLogger('sandbox', {
      logDebug: jest.fn(),
      logError: jest.fn(),
      logInfo: jest.fn(),
      logMeasurement: jest.fn(),
      logWarning: jest.fn(),
    });
  });

  afterEach(() => {
    setMarker(undefined);
    setDatasourcePluginMetas({});
    jest.restoreAllMocks();
  });

  async function loadPlugin(pluginId: string, statement: string) {
    const meta = {
      id: pluginId,
      name: pluginId,
      type: PluginType.datasource,
      module: `public/plugins/${pluginId}/module.js`,
    } as DataSourcePluginMeta;

    setDatasourcePluginMetas({ [pluginId]: meta });

    const source = `define([], function () { ${statement}; return { plugin: {} }; });`;
    jest.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      text: async () => source,
    } as Response);

    await importPluginModuleInSandbox({ pluginId });
    // javascript: navigations apply asynchronously in browsers.
    await new Promise((resolve) => setTimeout(resolve, 300));
  }

  it.each([
    {
      id: 'sandbox-loc-href',
      label: 'href setter',
      statement: `window.location.href = 'javascript:void(window.${MARKER}="href")'`,
      expected: 'href',
    },
    {
      id: 'sandbox-loc-assign',
      label: 'assign',
      statement: `window.location.assign('javascript:void(window.${MARKER}="assign")')`,
      expected: 'assign',
    },
    {
      id: 'sandbox-loc-replace',
      label: 'replace',
      statement: `window.location.replace('javascript:void(window.${MARKER}="replace")')`,
      expected: 'replace',
    },
    {
      id: 'sandbox-loc-href-case',
      label: 'href setter with a mixed-case javascript scheme',
      statement: `window.location.href = 'JavaScript:void(window.${MARKER}="case")'`,
      expected: 'case',
    },
    {
      id: 'sandbox-loc-href-space',
      label: 'href setter with a leading space',
      statement: `window.location.href = ' javascript:void(window.${MARKER}="space")'`,
      expected: 'space',
    },
    {
      id: 'sandbox-loc-href-tab',
      label: 'href setter with a leading tab',
      statement: `window.location.href = '\\tjavascript:void(window.${MARKER}="tab")'`,
      expected: 'tab',
    },
    {
      id: 'sandbox-loc-href-newline',
      label: 'href setter with a leading newline',
      statement: `window.location.href = '\\njavascript:void(window.${MARKER}="newline")'`,
      expected: 'newline',
    },
  ])('$label does not run script in the host page', async ({ id, statement, expected }) => {
    await loadPlugin(id, statement);

    // Vulnerable behavior sets the marker to `expected`. The sandbox must not.
    expect(marker()).not.toBe(expected);
    expect(marker()).toBeUndefined();
  });
});
