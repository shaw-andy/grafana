export {
  PluginLoadingStrategy,
  PluginSignatureStatus,
  PluginSignatureType,
  PluginType,
} from '../../../../../../packages/grafana-data/src/types/plugin';
export { patchArrayVectorProrotypeMethods } from '../../../../../../packages/grafana-data/src/types/vector';
export { textUtil } from '../../../../../../packages/grafana-data/src/text/sanitize';

// Live-target marking only cares about the prototype chain of these classes.
export class DataSourceApi {}
export class CustomVariableSupport {}
