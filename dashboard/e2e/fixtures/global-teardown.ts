/**
 * Global Teardown for Playwright E2E Tests
 * Runs once after all test suites complete
 *
 * @author Erick | Founding Principal AI Architect
 */

import { FullConfig } from '@playwright/test';

const API_URL = process.env.API_URL || 'http://localhost:8000';

async function globalTeardown(config: FullConfig) {
  // Clean up test data if in CI environment
  if (process.env.CI) {
    try {
      const response = await fetch(`${API_URL}/api/test/clear`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.ok) {
        console.log('Test data cleared successfully');
      }
    } catch (error) {
      console.warn('Warning: Could not clear test data:', error);
    }
  }
}

export default globalTeardown;
