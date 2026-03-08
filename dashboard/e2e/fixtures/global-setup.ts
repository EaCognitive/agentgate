/**
 * Global Setup for Playwright E2E Tests
 * Runs once before all test suites
 *
 * @author Erick | Founding Principal AI Architect
 */

import { chromium, FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';

const AUTH_FILE = path.join(__dirname, '..', '.auth', 'user.json');
const API_URL = process.env.API_URL || 'http://localhost:8000';

async function globalSetup(config: FullConfig) {
  // Ensure auth directory exists
  const authDir = path.dirname(AUTH_FILE);
  if (!fs.existsSync(authDir)) {
    fs.mkdirSync(authDir, { recursive: true });
  }

  // Seed test data via API
  try {
    const response = await fetch(`${API_URL}/api/test/seed`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      console.warn('Warning: Could not seed test data. Tests may use existing data.');
    } else {
      console.log('Test data seeded successfully');
    }
  } catch (error) {
    console.warn('Warning: API not reachable for test data seeding:', error);
  }

  // Create authenticated browser state
  const browser = await chromium.launch();
  const page = await browser.newPage();

  try {
    // Navigate to login page
    const baseURL = config.projects[0].use?.baseURL || 'http://localhost:3000';
    await page.goto(`${baseURL}/login`);

    // Perform login with test credentials
    await page.fill('[data-testid="email-input"]', 'test@agentgate.io');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');
    await page.click('[data-testid="login-button"]');

    // Wait for successful login redirect
    await page.waitForURL('**/');

    // Save authenticated state
    await page.context().storageState({ path: AUTH_FILE });
    console.log('Authentication state saved');
  } catch (error) {
    console.warn('Warning: Could not create authenticated state:', error);
    // Create empty auth file to prevent test failures
    fs.writeFileSync(AUTH_FILE, JSON.stringify({ cookies: [], origins: [] }));
  } finally {
    await browser.close();
  }
}

export default globalSetup;
