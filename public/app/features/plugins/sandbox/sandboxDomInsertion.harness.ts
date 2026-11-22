import { type BackendSrv, config, setBackendSrv } from '@grafana/runtime';

import { importPluginModuleInSandbox } from './sandboxPluginLoader';
import { shouldLoadPluginInFrontendSandbox } from './sandboxPluginLoaderRegistry';

const pluginSources = new Map<string, string>();

const originalFetch = window.fetch.bind(window);
window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  for (const [pluginId, source] of pluginSources) {
    if (url.includes(`/public/plugins/${pluginId}/`)) {
      return Promise.resolve(
        new Response(source, {
          status: 200,
          headers: { 'content-type': 'application/javascript' },
        })
      );
    }
  }
  return originalFetch(input, init);
};

function unsupportedBackendMethod(name: string): never {
  throw new Error(`unexpected backend ${name}`);
}

const backend: BackendSrv = {
  async get(url: string) {
    const match = String(url).match(/\/api\/plugins\/([^/]+)\/settings/);
    if (!match) {
      throw new Error(`unexpected backend request ${url}`);
    }
    const pluginId = decodeURIComponent(match[1]);
    return {
      id: pluginId,
      name: pluginId,
      type: 'datasource',
      signatureType: 'community',
      signature: 'valid',
      module: `/public/plugins/${pluginId}/module.js`,
    };
  },
  delete: () => unsupportedBackendMethod('delete'),
  post: () => unsupportedBackendMethod('post'),
  patch: () => unsupportedBackendMethod('patch'),
  put: () => unsupportedBackendMethod('put'),
  request: () => unsupportedBackendMethod('request'),
  datasourceRequest: () => unsupportedBackendMethod('datasourceRequest'),
  fetch: () => unsupportedBackendMethod('fetch'),
  chunked: () => unsupportedBackendMethod('chunked'),
};

setBackendSrv(backend);

type LoadResult = {
  sandboxed: boolean;
  ok: boolean;
  error?: string;
};

async function loadListedSandboxPlugin(pluginId: string, pluginSource: string): Promise<LoadResult> {
  pluginSources.set(pluginId, pluginSource);
  const listed = config.enableFrontendSandboxForPlugins ?? [];
  if (!listed.includes(pluginId)) {
    config.enableFrontendSandboxForPlugins = [...listed, pluginId];
  }

  const sandboxed = await shouldLoadPluginInFrontendSandbox({ pluginId });
  if (!sandboxed) {
    return { sandboxed: false, ok: false, error: 'sandbox gate declined the plugin' };
  }

  try {
    await importPluginModuleInSandbox({ pluginId });
    return { sandboxed: true, ok: true };
  } catch (error) {
    return {
      sandboxed: true,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

Reflect.set(window, '__loadListedSandboxPlugin', loadListedSandboxPlugin);
