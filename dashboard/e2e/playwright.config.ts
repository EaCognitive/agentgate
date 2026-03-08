/**
 * Playwright E2E Test Configuration
 * AgentGate Dashboard - Enterprise Engineering Protocols (2026 Platinum)
 *
 * @author Erick | Founding Principal AI Architect
 */

import { defineConfig, devices } from '@playwright/test';
import path from 'path';

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const API_URL = process.env.API_URL || 'http://localhost:8000';

export default defineConfig({
  testDir: './tests',
  outputDir: './test-results',
  timeout: 30000,
  expect: {
    timeout: 10000,
  },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: './playwright-report' }],
    ['json', { outputFile: './test-results/results.json' }],
    ['junit', { outputFile: './test-results/junit.xml' }],
  ],
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 15000,
    navigationTimeout: 30000,
    extraHTTPHeaders: {
      'Accept-Language': 'en-US,en;q=0.9',
    },
  },
  projects: [
    // Setup project for authentication state
    {
      name: 'setup',
      testMatch: /.*\.setup\.ts/,
    },
    // Desktop browsers
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        storageState: './e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
    {
      name: 'firefox',
      use: {
        ...devices['Desktop Firefox'],
        storageState: './e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
    {
      name: 'webkit',
      use: {
        ...devices['Desktop Safari'],
        storageState: './e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
    // Mobile viewports
    {
      name: 'mobile-chrome',
      use: {
        ...devices['Pixel 5'],
        storageState: './e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
    {
      name: 'mobile-safari',
      use: {
        ...devices['iPhone 12'],
        storageState: './e2e/.auth/user.json',
      },
      dependencies: ['setup'],
    },
    // Unauthenticated tests (login, signup)
    {
      name: 'auth-tests',
      testMatch: /.*\/auth\/.*\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],
  webServer: [
    {
      command: 'npm run dev',
      url: BASE_URL,
      reuseExistingServer: !process.env.CI,
      timeout: 120000,
    },
  ],
  // Global setup/teardown
  globalSetup: path.join(__dirname, 'fixtures', 'global-setup.ts'),
  globalTeardown: path.join(__dirname, 'fixtures', 'global-teardown.ts'),
});
