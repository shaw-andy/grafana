import { type DataSourceInstanceSettings, type DataSourcePluginMeta, PluginType } from '@grafana/data';
import { config } from '@grafana/runtime';

import { importPluginModuleInSandbox } from './sandboxPluginLoader';

type InstalledPlugin = {
  id: string;
  module: string;
};

// Test entry. The runner serves each plugin module and this bundle, then asks
// the real sandbox loader to evaluate them.
const installPlugins = (plugins: InstalledPlugin[]) => {
  const datasources: Record<string, DataSourceInstanceSettings> = {};
  for (const plugin of plugins) {
    datasources[plugin.id] = {
      uid: plugin.id,
      type: plugin.id,
      name: plugin.id,
      access: 'proxy',
      readOnly: true,
      jsonData: {},
      meta: {
        id: plugin.id,
        name: plugin.id,
        type: PluginType.datasource,
        module: plugin.module,
        baseUrl: '',
        info: {
          author: { name: 'probe' },
          description: 'probe',
          links: [],
          logos: { large: '', small: '' },
          screenshots: [],
          updated: '',
          version: '0.0.0',
        },
      } as DataSourcePluginMeta,
    };
  }
  config.datasources = datasources;
  config.pluginsCDNBaseURL = '';
  config.featureToggles = {
    ...config.featureToggles,
    pluginsSriChecks: false,
  };
  config.buildInfo = {
    ...config.buildInfo,
    env: 'production',
  };
};

const loadPlugin = (pluginId: string) => importPluginModuleInSandbox({ pluginId });

Object.assign(window, { __installPlugins: installPlugins, __loadPlugin: loadPlugin });
