import defaultConfig from '@grafana/plugin-configs/jest/jest.config.js';
import { grafanaESModules, nodeModulesToTransform } from '@grafana/plugin-configs/jest/utils.js';

// d3-random@3 is ESM-only. The shared plugin Jest list matches the package
// "d3" but not "d3-random", so node graph tests cannot load the generator.
export default {
  ...defaultConfig,
  transformIgnorePatterns: [nodeModulesToTransform([...grafanaESModules, 'd3-random'])],
};
