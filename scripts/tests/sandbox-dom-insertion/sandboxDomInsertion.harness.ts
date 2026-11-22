import { type AppPluginConfig, PluginLoadingStrategy } from '@grafana/data';
import { config } from '@grafana/runtime';

import { importPluginModuleInSandbox } from '../../../public/app/features/plugins/sandbox/sandboxPluginLoader';

declare global {
  interface Window {
    __sandboxProbeDone?: boolean;
  }
}

/**
 * Browser entry for the sandbox insertion spec.
 * The page URL names a plugin id. That id is listed in
 * enableFrontendSandboxForPlugins and loaded through the production sandbox
 * loader, which is the path taken for a plugin the operator asked the sandbox
 * to contain.
 */
export async function runSandboxInsertionProbe(): Promise<void> {
  const pluginId = new URLSearchParams(window.location.search).get('pluginId') ?? '';
  const app: AppPluginConfig = {
    id: pluginId,
    path: `/public/plugins/${pluginId}/module.js`,
    version: '1.0.0',
    preload: false,
    angular: { detected: false, hideDeprecation: true },
    loadingStrategy: PluginLoadingStrategy.script,
    dependencies: {
      grafanaDependency: '>=10.0.0',
      grafanaVersion: '*',
      plugins: [],
      extensions: { exposedComponents: [] },
    },
    extensions: {
      addedLinks: [],
      addedComponents: [],
      exposedComponents: [],
      extensionPoints: [],
      addedFunctions: [],
    },
  };

  config.enableFrontendSandboxForPlugins = pluginId ? [pluginId] : [];
  config.apps[pluginId] = app;

  try {
    await importPluginModuleInSandbox({ pluginId });
  } catch (error) {
    document.documentElement.setAttribute('data-load-error', error instanceof Error ? error.message : String(error));
  } finally {
    window.__sandboxProbeDone = true;
  }
}

void runSandboxInsertionProbe();
