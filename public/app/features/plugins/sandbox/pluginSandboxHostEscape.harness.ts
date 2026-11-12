import { importPluginModuleInSandbox } from './sandboxPluginLoader';

declare global {
  interface Window {
    __probeSource?: string;
    __runSandboxProbe?: () => Promise<{ fetched: boolean; error: string | null }>;
  }
}

/**
 * Browser entry for the host-escape tests.
 *
 * The page boot data registers escape-probe as a datasource plugin. This fetch
 * wrapper only supplies that plugin's module source so getPluginCode runs the
 * real loader path. Every other request uses the page's fetch.
 */
const pageFetch = window.fetch.bind(window);
let fetchedProbe = false;

window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  if (url.includes('/public/plugins/escape-probe/')) {
    fetchedProbe = true;
    const source = window.__probeSource ?? '';
    return Promise.resolve(
      new Response(source, {
        status: 200,
        headers: { 'Content-Type': 'text/javascript' },
      })
    );
  }
  return pageFetch(input, init);
};

window.__runSandboxProbe = async () => {
  fetchedProbe = false;
  try {
    await importPluginModuleInSandbox({ pluginId: 'escape-probe' });
    return { fetched: fetchedProbe, error: null };
  } catch (error) {
    return { fetched: fetchedProbe, error: error instanceof Error ? error.message : String(error) };
  }
};
