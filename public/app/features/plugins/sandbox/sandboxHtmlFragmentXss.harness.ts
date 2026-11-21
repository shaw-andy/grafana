import { config } from '@grafana/runtime';

import { importPluginModuleInSandbox } from './sandboxPluginLoader';

const PLUGIN_ID = 'xss-plugin';

// The product looks the plugin up from boot-data datasources, then fetches
// public/plugins/<id>/module.js. The test server serves that URL.
(config.datasources as Record<string, unknown>)[PLUGIN_ID] = {
  type: PLUGIN_ID,
  meta: {
    id: PLUGIN_ID,
    name: 'XSS',
    type: 'datasource',
    module: 'public/plugins/xss-plugin/module.js',
  },
};

const host = window as unknown as { __xss: string[]; __done: boolean; __error: string };

async function main() {
  host.__xss = [];
  try {
    await importPluginModuleInSandbox({ pluginId: PLUGIN_ID });
    host.__error = '';
  } catch (e) {
    host.__error = String(e);
  }
  host.__done = true;
}

void main();
