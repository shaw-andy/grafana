import { config } from '@grafana/runtime';
import { PluginLoadingStrategy } from '@grafana/data';

import { importPluginModule } from '../importer/importPluginModule';
import { shouldLoadPluginInFrontendSandbox } from './sandboxPluginLoaderRegistry';

declare global {
  interface Window {
    __SANDBOX_CASE__?: SandboxCase;
    __SANDBOX_RESULT__?: SandboxResult;
  }
}

export type SandboxCase = {
  pluginId: string;
  modulePath: string;
  // When set, the page itself starts the worker. This is the unsandboxed browser baseline.
  control?: boolean;
};

export type SandboxResult = {
  eligible: boolean | null;
  reached: boolean;
  rejected: boolean;
  error: string | null;
  pageOrigin: string;
  documentWriteThrew: boolean | null;
};

async function runControl(): Promise<SandboxResult> {
  // Blob workers resolve relative URLs against the blob URL, which fails to parse.
  // The page origin is absolute, so the worker can still call the page.
  const canary = JSON.stringify(location.origin + '/canary');
  const body = `fetch(${canary},{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({kind:"control-shared-worker-blob",scope:self.constructor&&self.constructor.name,origin:location.origin})})`;
  const url = URL.createObjectURL(new Blob([body], { type: 'text/javascript' }));
  const worker = new SharedWorker(url);
  worker.port.start();
  return {
    eligible: null,
    reached: true,
    rejected: false,
    error: null,
    pageOrigin: location.origin,
    documentWriteThrew: null,
  };
}

async function runSandboxed(spec: SandboxCase): Promise<SandboxResult> {
  config.enableFrontendSandboxForPlugins = [spec.pluginId];
  config.buildInfo = { env: 'production' };
  const eligible = await shouldLoadPluginInFrontendSandbox({ pluginId: spec.pluginId });
  let rejected = false;
  let error: string | null = null;
  let documentWriteThrew: boolean | null = null;
  try {
    const exported = await importPluginModule({
      path: spec.modulePath,
      pluginId: spec.pluginId,
      loadingStrategy: PluginLoadingStrategy.script,
      pluginName: spec.pluginId,
    });
    const plugin = exported && typeof exported === 'object' ? (exported as { plugin?: { documentWriteThrew?: boolean } }).plugin : undefined;
    if (plugin && typeof plugin.documentWriteThrew === 'boolean') {
      documentWriteThrew = plugin.documentWriteThrew;
    }
  } catch (err) {
    rejected = true;
    error = err instanceof Error ? err.message : String(err);
  }
  return {
    eligible,
    reached: true,
    rejected,
    error,
    pageOrigin: location.origin,
    documentWriteThrew,
  };
}

async function main() {
  const spec = window.__SANDBOX_CASE__;
  try {
    if (!spec) {
      throw new Error('missing sandbox case');
    }
    window.__SANDBOX_RESULT__ = spec.control ? await runControl() : await runSandboxed(spec);
  } catch (err) {
    window.__SANDBOX_RESULT__ = {
      eligible: null,
      reached: false,
      rejected: true,
      error: err instanceof Error ? `${err.message}\n${err.stack ?? ''}` : String(err),
      pageOrigin: location.origin,
      documentWriteThrew: null,
    };
  }
}

void main();
