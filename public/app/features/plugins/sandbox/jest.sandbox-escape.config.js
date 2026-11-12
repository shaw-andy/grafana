const path = require('path');

// Jest's default setup replaces TextEncoder and always loads a DOM shim, which
// breaks esbuild and a node-only Playwright driver. This config runs only the
// host-page sandbox escape tests.
module.exports = {
  rootDir: path.resolve(__dirname, '../../../../..'),
  testEnvironment: 'node',
  testMatch: ['<rootDir>/public/app/features/plugins/sandbox/pluginSandboxHostEscape.test.ts'],
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        isolatedModules: true,
        diagnostics: false,
      },
    ],
  },
  testTimeout: 60000,
};
