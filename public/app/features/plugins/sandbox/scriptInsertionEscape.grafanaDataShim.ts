/**
 * Narrow stand-in for @grafana/data symbols the sandbox modules import.
 * Script insertion does not use these classes; they only need to load.
 */
export enum PluginType {
  panel = 'panel',
  datasource = 'datasource',
  app = 'app',
  renderer = 'renderer',
}

export class DataSourceApi {}

export class CustomVariableSupport {}

export const textUtil = {
  sanitizeUrl: (url: string) => url,
};
