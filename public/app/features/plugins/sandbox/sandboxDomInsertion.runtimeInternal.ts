/* eslint-disable no-barrel-files/no-barrel-files -- test bundle seam, not a production barrel */
// Test bundle seam. Production code imports the @grafana/runtime/internal barrel, which also
// pulls the app shell. This module re-exports only the functions that module reaches on the
// sandbox load path, from their real source files.
export { getDatasourcePluginMeta } from '../../../../../packages/grafana-runtime/src/services/pluginMeta/datasources';
export { getPanelPluginMetas } from '../../../../../packages/grafana-runtime/src/services/pluginMeta/panels';
export { getAppPluginMetas } from '../../../../../packages/grafana-runtime/src/services/pluginMeta/apps';
export { invalidatePluginSettingsCache } from '../../../../../packages/grafana-runtime/src/services/pluginSettings/invalidatePluginSettingsCache';
export { getFeatureFlagClient } from '../../../../../packages/grafana-runtime/src/internal/openFeature';
export { FlagKeys } from '../../../../../packages/grafana-runtime/src/internal/openFeature/openfeature.gen';
export {
  installPluginMeta,
  uninstallPluginMeta,
} from '../../../../../packages/grafana-runtime/src/services/pluginMeta/plugins';
export { logPluginMetaError } from '../../../../../packages/grafana-runtime/src/services/pluginMeta/logging';
