import { defineConfig, devices } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

export default defineConfig({
  testDir: './tests/smoke',
  outputDir: './test-results-smoke',
  timeout: 30000,
  expect: {
    timeout: 10000,
  },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: './playwright-report-smoke' }],
    ['junit', { outputFile: './test-results-smoke/junit.xml' }],
  ],
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 15000,
    navigationTimeout: 30000,
    ...devices['Desktop Chrome'],
  },
  webServer: [
    {
      command: 'npm run dev',
      url: BASE_URL,
      reuseExistingServer: false,
      timeout: 120000,
    },
  ],
});
