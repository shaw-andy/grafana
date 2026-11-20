const path = require('path');

const base = require('../../jest.config');

// The default mapper replaces react-inlinesvg with a stub that never calls fetch.
// These tests have to load the published package so the request the browser makes is real.
const moduleNameMapper = { ...base.moduleNameMapper };
delete moduleNameMapper['react-inlinesvg'];

const transformIgnorePatterns = base.transformIgnorePatterns.map((pattern) =>
  pattern.replace('pkce-challenge', 'pkce-challenge|react-inlinesvg|react-from-dom')
);

module.exports = {
  ...base,
  rootDir: path.resolve(__dirname, '../..'),
  moduleNameMapper,
  transformIgnorePatterns,
  testRegex: 'iconPathTraversal\\.test\\.tsx$',
  setupFiles: [...base.setupFiles, '<rootDir>/public/test/icon-path-traversal-setup.ts'],
};
