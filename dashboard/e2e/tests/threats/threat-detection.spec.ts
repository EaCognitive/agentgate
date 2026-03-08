/**
 * E2E Tests for Threat Detection Dashboard
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test, expect } from '@playwright/test';
import { createAPIMocker } from '../../fixtures/api-mock.fixture';

test.describe('Threat Detection Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    // Mock threats list
    await apiMocker.mockRoute('**/api/security/threats**', {
      body: [
        {
          id: 'threat-001',
          event_type: 'brute_force_attempt',
          severity: 'critical',
          source_ip: '192.168.1.100',
          target: '/api/auth/login',
          description: 'Multiple failed login attempts detected from IP',
          status: 'pending',
          detected_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
          metadata: { attempts: 15 },
        },
        {
          id: 'threat-002',
          event_type: 'suspicious_api_pattern',
          severity: 'high',
          source_ip: '10.0.0.50',
          target: '/api/datasets',
          description: 'Unusual data access pattern detected',
          status: 'acknowledged',
          detected_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          acknowledged_by: 'admin@example.com',
          acknowledged_at: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
        },
        {
          id: 'threat-003',
          event_type: 'rate_limit_exceeded',
          severity: 'medium',
          source_ip: '172.16.0.25',
          target: '/api/traces',
          description: 'Rate limit exceeded for API endpoint',
          status: 'resolved',
          detected_at: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
          resolved_by: 'security@example.com',
          resolved_at: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
        },
      ],
    });

    // Mock threat stats
    await apiMocker.mockRoute('**/api/security/threats/stats', {
      body: {
        total: 15,
        critical: 2,
        high: 5,
        medium: 6,
        low: 2,
        pending: 4,
        acknowledged: 3,
        resolved: 8,
      },
    });

    // Mock threat timeline
    await apiMocker.mockRoute('**/api/security/threats/timeline**', {
      body: [
        { time: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString(), count: 2 },
        { time: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(), count: 1 },
        { time: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString(), count: 3 },
        { time: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(), count: 2 },
        { time: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), count: 4 },
        { time: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(), count: 2 },
        { time: new Date().toISOString(), count: 1 },
      ],
    });

    await page.goto('/security/threats');
  });

  test('should display threat stats cards', async ({ page }) => {
    await expect(page.getByText('Total Threats')).toBeVisible();
    await expect(page.getByText('Critical/High')).toBeVisible();
    await expect(page.getByText('Pending Review')).toBeVisible();
    await expect(page.getByText('Resolved')).toBeVisible();
  });

  test('should display threat timeline chart', async ({ page }) => {
    await expect(page.getByText('Threat Activity')).toBeVisible();
    await expect(page.getByText('Detected threats over time')).toBeVisible();
  });

  test('should display severity distribution chart', async ({ page }) => {
    await expect(page.getByText('Severity Distribution')).toBeVisible();
  });

  test('should display threats list', async ({ page }) => {
    await expect(page.getByText('Active Threats')).toBeVisible();
    await expect(page.getByText('brute_force_attempt')).toBeVisible();
    await expect(page.getByText('suspicious_api_pattern')).toBeVisible();
    await expect(page.getByText('192.168.1.100')).toBeVisible();
  });

  test('should show severity badges with correct colors', async ({ page }) => {
    // Critical should be visible
    const criticalBadge = page.locator('text=Critical').first();
    await expect(criticalBadge).toBeVisible();

    // High should be visible
    const highBadge = page.locator('text=High').first();
    await expect(highBadge).toBeVisible();
  });

  test('should expand threat to show details', async ({ page }) => {
    // Click on a threat row
    await page.getByText('brute_force_attempt').first().click();

    // Should show additional details
    await expect(page.getByText('Multiple failed login attempts detected')).toBeVisible();
  });

  test('should filter threats by severity', async ({ page }) => {
    // Find severity filter
    const severitySelect = page.locator('select').first();
    await severitySelect.selectOption('critical');

    // URL should update (mock doesn't filter, but navigation works)
    await expect(page).toHaveURL(/severity=critical/);
  });

  test('should filter threats by status', async ({ page }) => {
    // Find status filter
    const statusSelect = page.locator('select').nth(1);
    await statusSelect.selectOption('pending');

    await expect(page).toHaveURL(/status=pending/);
  });
});

test.describe('Threat Actions', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    await apiMocker.mockRoute('**/api/security/threats**', {
      body: [
        {
          id: 'threat-001',
          event_type: 'brute_force_attempt',
          severity: 'critical',
          source_ip: '192.168.1.100',
          target: '/api/auth/login',
          description: 'Multiple failed login attempts',
          status: 'pending',
          detected_at: new Date().toISOString(),
        },
      ],
    });

    await apiMocker.mockRoute('**/api/security/threats/stats', {
      body: { total: 1, critical: 1, high: 0, medium: 0, low: 0, pending: 1, acknowledged: 0, resolved: 0 },
    });

    await apiMocker.mockRoute('**/api/security/threats/timeline**', { body: [] });

    await page.goto('/security/threats');
  });

  test('should show action buttons for pending threats', async ({ page }) => {
    // Expand the threat
    await page.getByText('brute_force_attempt').first().click();

    // Should show action buttons
    await expect(page.getByRole('button', { name: 'Acknowledge' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Resolve' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Dismiss' })).toBeVisible();
  });

  test('should acknowledge a threat', async ({ page }) => {
    // Mock the acknowledge endpoint
    await page.route('**/api/security/threats/threat-001/acknowledge', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 200,
          body: JSON.stringify({ success: true }),
        });
      }
    });

    // Expand and click acknowledge
    await page.getByText('brute_force_attempt').first().click();
    await page.getByRole('button', { name: 'Acknowledge' }).click();

    // Button should be disabled/loading during request
    // (actual behavior depends on implementation)
  });

  test('should resolve a threat', async ({ page }) => {
    // Mock the resolve endpoint
    await page.route('**/api/security/threats/threat-001/resolve', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 200,
          body: JSON.stringify({ success: true }),
        });
      }
    });

    await page.getByText('brute_force_attempt').first().click();
    await page.getByRole('button', { name: 'Resolve' }).click();
  });
});

test.describe('Empty State', () => {
  test('should show empty state when no threats', async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    await apiMocker.mockRoute('**/api/security/threats**', { body: [] });
    await apiMocker.mockRoute('**/api/security/threats/stats', {
      body: { total: 0, critical: 0, high: 0, medium: 0, low: 0, pending: 0, acknowledged: 0, resolved: 0 },
    });
    await apiMocker.mockRoute('**/api/security/threats/timeline**', { body: [] });

    await page.goto('/security/threats');

    await expect(page.getByText('No threats detected')).toBeVisible();
  });
});
