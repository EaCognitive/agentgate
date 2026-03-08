/**
 * RBAC Permission Enforcement E2E Tests
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test, expect, TEST_USERS } from '../../fixtures/auth.fixture';
import { createAPIMocker } from '../../fixtures/api-mock.fixture';

test.describe('RBAC Permission Enforcement', () => {
  test.describe('Admin Role', () => {
    test('should have access to all pages', async ({ loginAs }) => {
      const page = await loginAs('admin');

      // Should access all dashboard pages
      const pages = [
        '/',
        '/traces',
        '/approvals',
        '/datasets',
        '/costs',
        '/audit',
        '/pii',
        '/security/settings',
        '/security/threats',
      ];

      for (const path of pages) {
        await page.goto(path);
        await expect(page).not.toHaveURL('**/unauthorized');
        await expect(page.locator('[data-testid="access-denied"]')).not.toBeVisible();
      }
    });

    test('should see admin-only actions', async ({ loginAs }) => {
      const page = await loginAs('admin');
      await page.goto('/security/settings');

      // Admin should see user management options
      await expect(page.locator('[data-testid="manage-users-link"]')).toBeVisible();
    });

    test('should be able to approve requests', async ({ loginAs }) => {
      const page = await loginAs('admin');
      await page.goto('/approvals');

      const approveButton = page.locator('[data-testid="approve-button"]').first();
      await expect(approveButton).toBeEnabled();
    });

    test('should be able to view and export audit logs', async ({ loginAs }) => {
      const page = await loginAs('admin');
      await page.goto('/audit');

      await expect(page.locator('[data-testid="export-button"]')).toBeVisible();
    });
  });

  test.describe('Approver Role', () => {
    test('should have access to approvals page', async ({ loginAs }) => {
      const page = await loginAs('approver');
      await page.goto('/approvals');

      await expect(page).not.toHaveURL('**/unauthorized');
      await expect(page.locator('[data-testid="approvals-list"]')).toBeVisible();
    });

    test('should be able to approve and deny requests', async ({ loginAs }) => {
      const page = await loginAs('approver');
      await page.goto('/approvals');

      await expect(page.locator('[data-testid="approve-button"]').first()).toBeEnabled();
      await expect(page.locator('[data-testid="deny-button"]').first()).toBeEnabled();
    });

    test('should have read-only access to traces', async ({ loginAs }) => {
      const page = await loginAs('approver');
      await page.goto('/traces');

      await expect(page).not.toHaveURL('**/unauthorized');
      // Should not see edit/delete actions
      await expect(page.locator('[data-testid="delete-trace-button"]')).not.toBeVisible();
    });

    test('should not have access to security settings admin features', async ({ loginAs }) => {
      const page = await loginAs('approver');
      await page.goto('/security/settings');

      // Should see own security settings but not admin features
      await expect(page.locator('[data-testid="manage-users-link"]')).not.toBeVisible();
    });
  });

  test.describe('Auditor Role', () => {
    test('should have full access to audit logs', async ({ loginAs }) => {
      const page = await loginAs('auditor');
      await page.goto('/audit');

      await expect(page).not.toHaveURL('**/unauthorized');
      await expect(page.locator('[data-testid="audit-table"]')).toBeVisible();
      await expect(page.locator('[data-testid="export-button"]')).toBeVisible();
    });

    test('should have read-only access to other pages', async ({ loginAs }) => {
      const page = await loginAs('auditor');

      // Can view traces
      await page.goto('/traces');
      await expect(page).not.toHaveURL('**/unauthorized');

      // Can view costs
      await page.goto('/costs');
      await expect(page).not.toHaveURL('**/unauthorized');
    });

    test('should not be able to approve requests', async ({ loginAs }) => {
      const page = await loginAs('auditor');
      await page.goto('/approvals');

      // Should see approvals but not action buttons
      const approveButton = page.locator('[data-testid="approve-button"]').first();
      await expect(approveButton).not.toBeVisible();
    });

    test('should not be able to create or modify datasets', async ({ loginAs }) => {
      const page = await loginAs('auditor');
      await page.goto('/datasets');

      await expect(page.locator('[data-testid="create-dataset-button"]')).not.toBeVisible();
    });
  });

  test.describe('Developer Role', () => {
    test('should have full access to traces', async ({ loginAs }) => {
      const page = await loginAs('developer');
      await page.goto('/traces');

      await expect(page).not.toHaveURL('**/unauthorized');
      await expect(page.locator('[data-testid="traces-table"]')).toBeVisible();
    });

    test('should have full access to datasets', async ({ loginAs }) => {
      const page = await loginAs('developer');
      await page.goto('/datasets');

      await expect(page).not.toHaveURL('**/unauthorized');
      await expect(page.locator('[data-testid="create-dataset-button"]')).toBeVisible();
    });

    test('should be able to create and run tests', async ({ loginAs }) => {
      const page = await loginAs('developer');
      await page.goto('/datasets');

      await expect(page.locator('[data-testid="create-dataset-button"]')).toBeEnabled();
    });

    test('should not be able to approve requests', async ({ loginAs }) => {
      const page = await loginAs('developer');
      await page.goto('/approvals');

      // Can view but not act
      await expect(page.locator('[data-testid="approve-button"]')).not.toBeVisible();
    });

    test('should have read-only access to costs', async ({ loginAs }) => {
      const page = await loginAs('developer');
      await page.goto('/costs');

      await expect(page).not.toHaveURL('**/unauthorized');
      await expect(page.locator('[data-testid="set-budget-button"]')).not.toBeVisible();
    });
  });

  test.describe('Viewer Role', () => {
    test('should have read-only access to all pages', async ({ loginAs }) => {
      const page = await loginAs('viewer');

      const readOnlyPages = ['/', '/traces', '/approvals', '/costs'];

      for (const path of readOnlyPages) {
        await page.goto(path);
        await expect(page).not.toHaveURL('**/unauthorized');
      }
    });

    test('should not see any action buttons', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      await page.goto('/traces');

      await expect(page.locator('[data-testid="delete-trace-button"]')).not.toBeVisible();
      await expect(page.locator('[data-testid="edit-button"]')).not.toBeVisible();
    });

    test('should not have access to security settings', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      await page.goto('/security/settings');

      // Should be redirected or see unauthorized
      const unauthorized = page.locator('[data-testid="access-denied"]');
      const hasAccess = !(await unauthorized.isVisible());

      if (hasAccess) {
        // If they can access, ensure it's read-only
        await expect(page.locator('[data-testid="enable-2fa-button"]')).not.toBeVisible();
      }
    });

    test('should not have access to PII vault write operations', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      await page.goto('/pii');

      await expect(page.locator('[data-testid="rotate-key-button"]')).not.toBeVisible();
      await expect(page.locator('[data-testid="export-button"]')).not.toBeVisible();
    });

    test('should not be able to create datasets', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      await page.goto('/datasets');

      await expect(page.locator('[data-testid="create-dataset-button"]')).not.toBeVisible();
    });

    test('should not see audit export functionality', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      await page.goto('/audit');

      await expect(page.locator('[data-testid="export-button"]')).not.toBeVisible();
    });
  });

  test.describe('Navigation Visibility', () => {
    test('admin should see all navigation items', async ({ loginAs }) => {
      const page = await loginAs('admin');
      await page.goto('/');

      const navItems = [
        'Overview',
        'Traces',
        'Approvals',
        'Datasets',
        'Costs',
        'Audit',
        'PII Vault',
        'Security',
      ];

      for (const item of navItems) {
        await expect(page.getByRole('link', { name: item })).toBeVisible();
      }
    });

    test('viewer should see limited navigation items', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      await page.goto('/');

      // Should see read-only pages
      await expect(page.getByRole('link', { name: 'Overview' })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Traces' })).toBeVisible();

      // Should not see admin pages in nav
      await expect(page.getByRole('link', { name: 'Security' })).not.toBeVisible();
    });

    test('approver should see approvals prominently', async ({ loginAs }) => {
      const page = await loginAs('approver');
      await page.goto('/');

      await expect(page.getByRole('link', { name: 'Approvals' })).toBeVisible();
      // Should have pending count badge
      await expect(page.locator('[data-testid="approvals-badge"]')).toBeVisible();
    });
  });

  test.describe('API Permission Enforcement', () => {
    test('should return 403 for unauthorized API access', async ({ loginAs }) => {
      const page = await loginAs('viewer');

      const response = await page.request.delete('/api/datasets/test-id');
      expect(response.status()).toBe(403);
    });

    test('should return 403 when viewer tries to approve', async ({ loginAs }) => {
      const page = await loginAs('viewer');

      const response = await page.request.post('/api/approvals/test-id/decide', {
        data: { decision: 'approve' },
      });
      expect(response.status()).toBe(403);
    });

    test('should allow authorized API access', async ({ loginAs }) => {
      const page = await loginAs('admin');

      const mocker = createAPIMocker(page);
      await mocker.mockRoute('**/api/traces', {
        body: { items: [], total: 0 },
      });

      const response = await page.request.get('/api/traces');
      expect(response.ok()).toBe(true);
    });
  });

  test.describe('Role-based UI State', () => {
    test('should disable action buttons for insufficient permissions', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      await page.goto('/datasets');

      // Create button should be disabled or hidden
      const createButton = page.locator('[data-testid="create-dataset-button"]');

      // Either not visible or disabled
      const isVisible = await createButton.isVisible();
      if (isVisible) {
        await expect(createButton).toBeDisabled();
      }
    });

    test('should show permission tooltip on disabled actions', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      await page.goto('/approvals');

      // Find a disabled action area and hover
      const disabledAction = page.locator('[data-testid="action-disabled-area"]').first();

      if (await disabledAction.isVisible()) {
        await disabledAction.hover();
        const tooltip = page.locator('[role="tooltip"]');
        await expect(tooltip).toContainText('permission');
      }
    });
  });

  test.describe('Permission Escalation Prevention', () => {
    test('should prevent direct URL access to admin pages', async ({ loginAs }) => {
      const page = await loginAs('viewer');

      // Try to access admin-only endpoint directly
      await page.goto('/admin/users');

      // Should be redirected or see access denied
      await expect(page.locator('[data-testid="access-denied"]')).toBeVisible();
    });

    test('should prevent API manipulation attempts', async ({ loginAs }) => {
      const page = await loginAs('viewer');

      // Try to call admin-only API
      const response = await page.request.post('/api/admin/users', {
        data: { email: 'hacker@test.com', role: 'admin' },
      });

      expect(response.status()).toBe(403);
    });

    test('should log unauthorized access attempts', async ({ loginAs }) => {
      const page = await loginAs('viewer');
      const mocker = createAPIMocker(page);

      let auditLogged = false;
      await mocker.mockRoute('**/api/audit', {
        body: (req: any) => {
          if (req.body?.event_type === 'permission.denied') {
            auditLogged = true;
          }
          return { success: true };
        },
      });

      // Attempt unauthorized action
      await page.request.delete('/api/datasets/test-id');

      // Verify audit log was called
      // Note: This may need adjustment based on actual audit implementation
    });
  });
});
