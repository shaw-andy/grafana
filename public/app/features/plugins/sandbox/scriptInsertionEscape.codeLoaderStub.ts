import { type SandboxEnvironment, type SandboxPluginMeta } from './types';

/**
 * Replaces plugin fetching for the insertion tests. loadScriptIntoSandbox follows
 * the real codeLoader same-origin check: an empty script URL fails URL parsing
 * before any fetch, which is the appendChild path for an inline script.
 */
export async function getPluginLoadData(pluginId: string): Promise<SandboxPluginMeta> {
  return {
    id: pluginId,
    type: 'panel',
    module: 'public/plugins/sandbox-script-insertion/module.js',
  } as SandboxPluginMeta;
}

export async function getPluginCode(): Promise<string> {
  const code = (globalThis as { __SANDBOX_PLUGIN_CODE?: string }).__SANDBOX_PLUGIN_CODE;
  if (!code) {
    throw new Error('sandbox script insertion test did not set plugin code');
  }
  return code;
}

export function patchSandboxEnvironmentPrototype(): void {}

function isSameDomainAsHost(url: string): boolean {
  const locationUrl = new URL(window.location.href);
  const paramUrl = new URL(url);
  return locationUrl.host === paramUrl.host;
}

export async function loadScriptIntoSandbox(url: string, sandboxEnv: SandboxEnvironment): Promise<void> {
  let scriptCode = '';

  if (isSameDomainAsHost(url)) {
    const response = await fetch(url);
    scriptCode = await response.text();
  }

  if (scriptCode.length === 0) {
    throw new Error('Only same domain scripts are allowed in sandboxed plugins');
  }

  sandboxEnv.evaluate(scriptCode);
}
