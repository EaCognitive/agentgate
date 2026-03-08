/**
 * E2E Tests for PII Vault
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test, expect } from '@playwright/test';
import { createAPIMocker } from '../../fixtures/api-mock.fixture';

test.describe('PII Vault Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    // Mock PII stats
    await apiMocker.mockRoute('**/api/pii/stats', {
      body: {
        total_entries: 1500,
        active_sessions: 25,
        entities_detected: 3200,
        entities_redacted: 3150,
        detection_rate: 98.44,
        last_key_rotation: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        compliance_status: 'compliant',
      },
    });

    // Mock PII entries
    await apiMocker.mockRoute('**/api/pii/entries**', {
      body: [
        {
          id: 'pii-001',
          session_id: 'session-abc123',
          entity_type: 'EMAIL_ADDRESS',
          original_value_preview: 'j***@example.com',
          replacement_token: '[EMAIL_1]',
          detected_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
          status: 'active',
        },
        {
          id: 'pii-002',
          session_id: 'session-abc123',
          entity_type: 'PHONE_NUMBER',
          original_value_preview: '+1-***-***-1234',
          replacement_token: '[PHONE_1]',
          detected_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          status: 'active',
        },
        {
          id: 'pii-003',
          session_id: 'session-def456',
          entity_type: 'CREDIT_CARD',
          original_value_preview: '****-****-****-4242',
          replacement_token: '[CARD_1]',
          detected_at: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
          status: 'redacted',
        },
      ],
    });

    // Mock entity types
    await apiMocker.mockRoute('**/api/pii/entity-types', {
      body: [
        { type: 'EMAIL_ADDRESS', count: 450 },
        { type: 'PHONE_NUMBER', count: 380 },
        { type: 'CREDIT_CARD', count: 120 },
        { type: 'SSN', count: 85 },
        { type: 'ADDRESS', count: 215 },
      ],
    });

    await page.goto('/pii');
  });

  test('should display PII stats cards', async ({ page }) => {
    await expect(page.getByText('Total Entries')).toBeVisible();
    await expect(page.getByText('Active Sessions')).toBeVisible();
    await expect(page.getByText('Detection Rate')).toBeVisible();
    await expect(page.getByText('Compliance')).toBeVisible();
  });

  test('should display PII entries table', async ({ page }) => {
    await expect(page.getByText('j***@example.com')).toBeVisible();
    await expect(page.getByText('[EMAIL_1]')).toBeVisible();
    await expect(page.getByText('EMAIL_ADDRESS')).toBeVisible();
  });

  test('should show entity type badges', async ({ page }) => {
    await expect(page.getByText('EMAIL_ADDRESS')).toBeVisible();
    await expect(page.getByText('PHONE_NUMBER')).toBeVisible();
    await expect(page.getByText('CREDIT_CARD')).toBeVisible();
  });

  test('should filter by entity type', async ({ page }) => {
    // Find entity type filter
    const filterSelect = page.getByRole('combobox').first();
    await filterSelect.selectOption('EMAIL_ADDRESS');

    await expect(page).toHaveURL(/entity_type=EMAIL_ADDRESS/);
  });

  test('should show compliance status badge', async ({ page }) => {
    await expect(page.getByText('Compliant')).toBeVisible();
  });
});

test.describe('PII Detection Tab', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    await apiMocker.mockRoute('**/api/pii/stats', {
      body: {
        total_entries: 1500,
        active_sessions: 25,
        entities_detected: 3200,
        entities_redacted: 3150,
        detection_rate: 98.44,
        last_key_rotation: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        compliance_status: 'compliant',
      },
    });

    await apiMocker.mockRoute('**/api/pii/entries**', { body: [] });
    await apiMocker.mockRoute('**/api/pii/entity-types', { body: [] });

    await page.goto('/pii');
  });

  test('should switch to detection tab', async ({ page }) => {
    await page.getByRole('tab', { name: 'Detection' }).click();

    await expect(page.getByText('Detect PII')).toBeVisible();
    await expect(page.getByPlaceholder(/Enter text to scan/)).toBeVisible();
  });

  test('should detect PII in text', async ({ page }) => {
    // Mock detect endpoint
    await page.route('**/api/pii/detect', async (route) => {
      await route.fulfill({
        status: 200,
        body: JSON.stringify({
          entities: [
            { type: 'EMAIL_ADDRESS', value: 'test@example.com', start: 10, end: 26 },
            { type: 'PHONE_NUMBER', value: '555-123-4567', start: 50, end: 62 },
          ],
        }),
      });
    });

    await page.getByRole('tab', { name: 'Detection' }).click();

    const textarea = page.getByPlaceholder(/Enter text to scan/);
    await textarea.fill('Contact me at test@example.com or call 555-123-4567');

    await page.getByRole('button', { name: 'Scan for PII' }).click();

    // Should show detected entities
    await expect(page.getByText('EMAIL_ADDRESS')).toBeVisible();
  });
});

test.describe('PII Key Rotation', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    await apiMocker.mockRoute('**/api/pii/stats', {
      body: {
        total_entries: 1500,
        active_sessions: 25,
        entities_detected: 3200,
        entities_redacted: 3150,
        detection_rate: 98.44,
        last_key_rotation: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
        compliance_status: 'warning',
      },
    });

    await apiMocker.mockRoute('**/api/pii/entries**', { body: [] });
    await apiMocker.mockRoute('**/api/pii/entity-types', { body: [] });

    await page.goto('/pii');
  });

  test('should show key rotation warning', async ({ page }) => {
    // Key rotation warning should appear after 30+ days
    await expect(page.getByText(/Key rotation recommended/)).toBeVisible();
  });

  test('should open key rotation modal', async ({ page }) => {
    await page.getByRole('button', { name: 'Rotate Key' }).click();

    await expect(page.getByText('Rotate Encryption Key')).toBeVisible();
    await expect(page.getByText(/This will re-encrypt all PII/)).toBeVisible();
  });

  test('should rotate encryption key', async ({ page }) => {
    // Mock rotate endpoint
    await page.route('**/api/pii/rotate-key', async (route) => {
      await route.fulfill({
        status: 200,
        body: JSON.stringify({ success: true, entries_rotated: 1500 }),
      });
    });

    await page.getByRole('button', { name: 'Rotate Key' }).click();
    await page.getByRole('button', { name: 'Confirm Rotation' }).click();

    // Modal should close on success
    await expect(page.getByText('Rotate Encryption Key')).not.toBeVisible();
  });
});

test.describe('PII Export', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    await apiMocker.mockRoute('**/api/pii/stats', {
      body: {
        total_entries: 1500,
        active_sessions: 25,
        entities_detected: 3200,
        entities_redacted: 3150,
        detection_rate: 98.44,
        last_key_rotation: new Date().toISOString(),
        compliance_status: 'compliant',
      },
    });

    await apiMocker.mockRoute('**/api/pii/entries**', { body: [] });
    await apiMocker.mockRoute('**/api/pii/entity-types', { body: [] });

    await page.goto('/pii');
  });

  test('should open export modal', async ({ page }) => {
    await page.getByRole('button', { name: 'Export Audit' }).click();

    await expect(page.getByText('Export PII Audit Report')).toBeVisible();
    await expect(page.getByText('CSV')).toBeVisible();
    await expect(page.getByText('JSON')).toBeVisible();
  });

  test('should export audit report', async ({ page }) => {
    // Mock export endpoint
    const downloadPromise = page.waitForEvent('download');

    await page.route('**/api/pii/export**', async (route) => {
      await route.fulfill({
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': 'attachment; filename=pii_audit.csv',
        },
        body: 'id,entity_type,detected_at\n1,EMAIL_ADDRESS,2024-01-01',
      });
    });

    await page.getByRole('button', { name: 'Export Audit' }).click();
    await page.getByRole('button', { name: 'Download CSV' }).click();

    // Should trigger download
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('pii_audit.csv');
  });
});
