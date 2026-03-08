/**
 * Authentication Fixtures for E2E Tests
 * Provides authenticated page contexts for different user roles
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test as base, Page, BrowserContext } from '@playwright/test';

// User credentials for different roles
export const TEST_USERS = {
  admin: {
    email: 'admin@agentgate.io',
    password: 'AdminPassword123!',
    role: 'admin',
  },
  approver: {
    email: 'approver@agentgate.io',
    password: 'ApproverPassword123!',
    role: 'approver',
  },
  auditor: {
    email: 'auditor@agentgate.io',
    password: 'AuditorPassword123!',
    role: 'auditor',
  },
  developer: {
    email: 'developer@agentgate.io',
    password: 'DeveloperPassword123!',
    role: 'developer',
  },
  viewer: {
    email: 'viewer@agentgate.io',
    password: 'ViewerPassword123!',
    role: 'viewer',
  },
} as const;

export type UserRole = keyof typeof TEST_USERS;

interface AuthFixtures {
  authenticatedPage: Page;
  adminPage: Page;
  approverPage: Page;
  auditorPage: Page;
  developerPage: Page;
  viewerPage: Page;
  loginAs: (role: UserRole) => Promise<Page>;
}

async function loginAsUser(
  context: BrowserContext,
  baseURL: string,
  email: string,
  password: string
): Promise<Page> {
  const page = await context.newPage();
  await page.goto(`${baseURL}/login`);

  await page.fill('[data-testid="email-input"]', email);
  await page.fill('[data-testid="password-input"]', password);
  await page.click('[data-testid="login-button"]');

  // Wait for successful login
  await page.waitForURL('**/');

  return page;
}

export const test = base.extend<AuthFixtures>({
  authenticatedPage: async ({ page }, use) => {
    // Uses pre-authenticated state from global setup
    await use(page);
  },

  adminPage: async ({ context, baseURL }, use) => {
    const { email, password } = TEST_USERS.admin;
    const page = await loginAsUser(context, baseURL!, email, password);
    await use(page);
    await page.close();
  },

  approverPage: async ({ context, baseURL }, use) => {
    const { email, password } = TEST_USERS.approver;
    const page = await loginAsUser(context, baseURL!, email, password);
    await use(page);
    await page.close();
  },

  auditorPage: async ({ context, baseURL }, use) => {
    const { email, password } = TEST_USERS.auditor;
    const page = await loginAsUser(context, baseURL!, email, password);
    await use(page);
    await page.close();
  },

  developerPage: async ({ context, baseURL }, use) => {
    const { email, password } = TEST_USERS.developer;
    const page = await loginAsUser(context, baseURL!, email, password);
    await use(page);
    await page.close();
  },

  viewerPage: async ({ context, baseURL }, use) => {
    const { email, password } = TEST_USERS.viewer;
    const page = await loginAsUser(context, baseURL!, email, password);
    await use(page);
    await page.close();
  },

  loginAs: async ({ context, baseURL }, use) => {
    const createdPages: Page[] = [];

    const loginFn = async (role: UserRole): Promise<Page> => {
      const { email, password } = TEST_USERS[role];
      const page = await loginAsUser(context, baseURL!, email, password);
      createdPages.push(page);
      return page;
    };

    await use(loginFn);

    // Cleanup all created pages
    for (const page of createdPages) {
      await page.close();
    }
  },
});

export { expect } from '@playwright/test';
