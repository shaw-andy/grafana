import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: __dirname,
  testMatch: 'sandboxDomInsertion.browser.spec.ts',
  outputDir: '/tmp/sandbox-insertion-playwright',
  timeout: 180_000,
  expect: { timeout: 30_000 },
  retries: 0,
  workers: 1,
  reporter: 'line',
  use: {
    channel: 'chrome',
    headless: true,
  },
});
