/**
 * Security Settings E2E Tests
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test, expect } from '../../fixtures/auth.fixture';
import { SecuritySettingsPage } from '../../pages/security-settings.page';
import { createAPIMocker, mockFactories } from '../../fixtures/api-mock.fixture';

test.describe('Security Settings', () => {
  let securityPage: SecuritySettingsPage;

  test.beforeEach(async ({ authenticatedPage }) => {
    securityPage = new SecuritySettingsPage(authenticatedPage);
    await securityPage.goto();
  });

  test.describe('Page Load', () => {
    test('should display all security sections', async () => {
      await securityPage.expectPageLoaded();
      await expect(securityPage.passwordSection).toBeVisible();
      await expect(securityPage.activityLog).toBeVisible();
    });

    test('should show current 2FA status', async () => {
      await expect(securityPage.twoFactorStatus).toBeVisible();
    });
  });

  test.describe('Two-Factor Authentication', () => {
    test.describe('Enable 2FA Flow', () => {
      test('should display QR code when enabling 2FA', async ({ authenticatedPage }) => {
        const mocker = createAPIMocker(authenticatedPage);
        await mocker.mockRoute('**/api/auth/2fa/enable', {
          body: {
            qr_code: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...',
            secret: 'JBSWY3DPEHPK3PXP',
          },
        });

        await securityPage.enable2FA();
        await expect(securityPage.qrCode).toBeVisible();
        await expect(securityPage.secretKey).toBeVisible();
      });

      test('should show secret key for manual entry', async ({ authenticatedPage }) => {
        const mocker = createAPIMocker(authenticatedPage);
        await mocker.mockRoute('**/api/auth/2fa/enable', {
          body: {
            qr_code: 'data:image/png;base64,...',
            secret: 'JBSWY3DPEHPK3PXP',
          },
        });

        await securityPage.enable2FA();
        await expect(securityPage.secretKey).toContainText('JBSWY3DPEHPK3PXP');
      });

      test('should verify and enable 2FA with valid code', async ({ authenticatedPage }) => {
        const mocker = createAPIMocker(authenticatedPage);

        await mocker.mockRoute('**/api/auth/2fa/enable', {
          body: { qr_code: 'data:...', secret: 'SECRET' },
        });
        await mocker.mockRoute('**/api/auth/2fa/verify', {
          body: { success: true, backup_codes: ['CODE1', 'CODE2'] },
        });

        await securityPage.enable2FA();
        await securityPage.verify2FA('123456');
        await securityPage.expect2FAEnabled();
      });

      test('should show error for invalid verification code', async ({ authenticatedPage }) => {
        const mocker = createAPIMocker(authenticatedPage);

        await mocker.mockRoute('**/api/auth/2fa/enable', {
          body: { qr_code: 'data:...', secret: 'SECRET' },
        });
        await mocker.mockError('**/api/auth/2fa/verify', 401, 'Invalid verification code');

        await securityPage.enable2FA();
        await securityPage.verify2FA('000000');
        await securityPage.expectToastError('Invalid verification code');
      });
    });

    test.describe('Disable 2FA Flow', () => {
      test.beforeEach(async ({ authenticatedPage }) => {
        // Mock 2FA as currently enabled
        const mocker = createAPIMocker(authenticatedPage);
        await mocker.mockRoute('**/api/auth/mfa/status', {
          body: { enabled: true, last_verified: new Date().toISOString() },
        });
        await securityPage.goto();
      });

      test('should require verification code to disable 2FA', async ({ authenticatedPage }) => {
        const mocker = createAPIMocker(authenticatedPage);
        await mocker.mockRoute('**/api/auth/2fa/disable', {
          body: { success: true },
        });

        await securityPage.disable2FA('123456');
        await securityPage.expect2FADisabled();
      });

      test('should show confirmation modal before disabling', async () => {
        await securityPage.disable2FAButton.click();
        const modal = await securityPage.waitForModal('Disable Two-Factor Authentication');
        await expect(modal).toContainText('This will make your account less secure');
      });
    });

    test.describe('Backup Codes', () => {
      test('should generate new backup codes', async ({ authenticatedPage }) => {
        const mocker = createAPIMocker(authenticatedPage);
        const codes = Array.from({ length: 10 }, (_, i) => `BACKUP-${i.toString().padStart(4, '0')}`);

        await mocker.mockRoute('**/api/auth/2fa/backup-codes', {
          body: { codes },
        });

        await securityPage.generateBackupCodes();
        await securityPage.expectBackupCodesGenerated(10);
      });

      test('should allow downloading backup codes', async ({ authenticatedPage }) => {
        const mocker = createAPIMocker(authenticatedPage);
        await mocker.mockRoute('**/api/auth/2fa/backup-codes', {
          body: { codes: ['CODE1', 'CODE2'] },
        });

        await securityPage.generateBackupCodes();

        // Verify download button is visible
        await expect(securityPage.downloadBackupCodesButton).toBeVisible();
      });

      test('should allow copying backup codes to clipboard', async ({ authenticatedPage }) => {
        const mocker = createAPIMocker(authenticatedPage);
        await mocker.mockRoute('**/api/auth/2fa/backup-codes', {
          body: { codes: ['CODE1', 'CODE2'] },
        });

        await securityPage.generateBackupCodes();
        await securityPage.copyBackupCodesButton.click();

        await securityPage.expectToastSuccess('Copied to clipboard');
      });
    });
  });

  test.describe('WebAuthn Passkeys', () => {
    test('should display registered passkeys list', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/webauthn/credentials', {
        body: [
          { id: 'key-1', name: 'MacBook Pro', created_at: new Date().toISOString() },
          { id: 'key-2', name: 'iPhone 14', created_at: new Date().toISOString() },
        ],
      });

      await securityPage.goto();
      const count = await securityPage.getPasskeyCount();
      expect(count).toBe(2);
    });

    test('should show register passkey button', async () => {
      await expect(securityPage.registerPasskeyButton).toBeVisible();
    });

    test('should open registration modal when clicking register', async () => {
      await securityPage.registerPasskeyButton.click();
      const modal = await securityPage.waitForModal('Register Passkey');
      await expect(modal).toBeVisible();
    });

    test('should allow naming the passkey', async () => {
      await securityPage.registerPasskeyButton.click();
      await securityPage.waitForModal('Register Passkey');
      await expect(securityPage.passkeyNameInput).toBeVisible();
    });

    test('should revoke passkey with confirmation', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/webauthn/credentials', {
        body: [{ id: 'key-1', name: 'Old Device', created_at: new Date().toISOString() }],
      });
      await mocker.mockRoute('**/api/auth/webauthn/credentials/key-1', {
        status: 204,
      });

      await securityPage.goto();
      await securityPage.revokePasskey('Old Device');

      await securityPage.expectToastSuccess('Passkey revoked');
    });
  });

  test.describe('Active Sessions', () => {
    test('should display all active sessions', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      const sessions = [
        mockFactories.session({ id: 'session-1', is_current: true }),
        mockFactories.session({ id: 'session-2', is_current: false }),
        mockFactories.session({ id: 'session-3', is_current: false }),
      ];

      await mocker.mockRoute('**/api/auth/sessions', { body: sessions });

      await securityPage.goto();
      const count = await securityPage.getSessionCount();
      expect(count).toBe(3);
    });

    test('should mark current session', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/sessions', {
        body: [mockFactories.session({ is_current: true })],
      });

      await securityPage.goto();
      await securityPage.expectCurrentSessionMarked();
    });

    test('should not allow terminating current session', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/sessions', {
        body: [mockFactories.session({ id: 'current', is_current: true })],
      });

      await securityPage.goto();

      // Current session should not have terminate button
      const currentSession = securityPage.sessionsList.locator('[data-session-id="current"]');
      const terminateButton = currentSession.locator('[data-testid="terminate-session-button"]');
      await expect(terminateButton).not.toBeVisible();
    });

    test('should terminate other sessions', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/sessions', {
        body: [
          mockFactories.session({ id: 'current', is_current: true }),
          mockFactories.session({ id: 'other-1', is_current: false }),
        ],
      });
      await mocker.mockRoute('**/api/auth/sessions/other-1', { status: 204 });

      await securityPage.goto();
      await securityPage.terminateSession('other-1');

      await securityPage.expectToastSuccess('Session terminated');
    });

    test('should terminate all other sessions', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/sessions', {
        body: [
          mockFactories.session({ id: 'current', is_current: true }),
          mockFactories.session({ id: 'other-1', is_current: false }),
          mockFactories.session({ id: 'other-2', is_current: false }),
        ],
      });
      await mocker.mockRoute('**/api/auth/sessions', {
        method: 'DELETE',
        body: { terminated: 2 },
      });

      await securityPage.goto();
      await securityPage.terminateAllOtherSessions();

      await securityPage.expectToastSuccess('sessions terminated');
    });

    test('should show session details', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/sessions', {
        body: [
          mockFactories.session({
            device: 'Chrome on macOS',
            ip_address: '192.168.1.50',
            location: 'San Francisco, CA',
          }),
        ],
      });

      await securityPage.goto();

      const session = securityPage.sessionsList.locator('[data-testid="session-item"]').first();
      await expect(session).toContainText('Chrome on macOS');
      await expect(session).toContainText('192.168.1.50');
      await expect(session).toContainText('San Francisco');
    });
  });

  test.describe('Password Change', () => {
    test('should validate current password is required', async () => {
      await securityPage.newPasswordInput.fill('NewPassword123!');
      await securityPage.confirmPasswordInput.fill('NewPassword123!');
      await securityPage.changePasswordButton.click();

      const error = securityPage.page.locator('[data-testid="current-password-error"]');
      await expect(error).toBeVisible();
    });

    test('should validate password confirmation matches', async () => {
      await securityPage.currentPasswordInput.fill('OldPassword123!');
      await securityPage.newPasswordInput.fill('NewPassword123!');
      await securityPage.confirmPasswordInput.fill('DifferentPassword123!');
      await securityPage.changePasswordButton.click();

      const error = securityPage.page.locator('[data-testid="confirm-password-error"]');
      await expect(error).toContainText('Passwords do not match');
    });

    test('should validate password strength', async () => {
      await securityPage.currentPasswordInput.fill('OldPassword123!');
      await securityPage.newPasswordInput.fill('weak');
      await securityPage.confirmPasswordInput.fill('weak');
      await securityPage.changePasswordButton.click();

      const error = securityPage.page.locator('[data-testid="new-password-error"]');
      await expect(error).toBeVisible();
    });

    test('should change password successfully', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/password', {
        body: { success: true },
      });

      await securityPage.changePassword('OldPassword123!', 'NewSecurePassword456!');
      await securityPage.expectPasswordChangeSuccess();
    });

    test('should show error for incorrect current password', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockError('**/api/auth/password', 401, 'Current password is incorrect');

      await securityPage.changePassword('WrongPassword!', 'NewPassword123!');
      await securityPage.expectPasswordChangeError('Current password is incorrect');
    });
  });

  test.describe('Security Activity Log', () => {
    test('should display recent security events', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/audit?category=security*', {
        body: {
          items: [
            mockFactories.auditEntry({ event_type: 'auth.login', action: 'login' }),
            mockFactories.auditEntry({ event_type: 'auth.password_change', action: 'password_change' }),
          ],
          total: 2,
        },
      });

      await securityPage.goto();
      await expect(securityPage.activityLog).toBeVisible();

      const entries = securityPage.activityLog.locator('[data-testid="activity-entry"]');
      await expect(entries).toHaveCount(2);
    });

    test('should show login event details', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/audit?category=security*', {
        body: {
          items: [
            mockFactories.auditEntry({
              event_type: 'auth.login',
              ip_address: '192.168.1.100',
              timestamp: new Date().toISOString(),
            }),
          ],
          total: 1,
        },
      });

      await securityPage.goto();

      const entry = securityPage.activityLog.locator('[data-testid="activity-entry"]').first();
      await expect(entry).toContainText('Login');
      await expect(entry).toContainText('192.168.1.100');
    });
  });

  test.describe('Accessibility', () => {
    test('should be keyboard navigable', async ({ authenticatedPage }) => {
      // Tab through main sections
      await authenticatedPage.keyboard.press('Tab');

      // Verify focus is visible and sections are navigable
      const focusedElement = await authenticatedPage.evaluate(() =>
        document.activeElement?.getAttribute('data-testid')
      );
      expect(focusedElement).toBeTruthy();
    });

    test('should have proper ARIA labels', async () => {
      const twoFactorSection = securityPage.twoFactorSection;
      await expect(twoFactorSection).toHaveAttribute('aria-label');
    });

    test('should announce status changes to screen readers', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/auth/2fa/enable', {
        body: { qr_code: 'data:...', secret: 'SECRET' },
      });

      await securityPage.enable2FA();

      // Verify live region exists for announcements
      const liveRegion = authenticatedPage.locator('[aria-live="polite"]');
      await expect(liveRegion).toBeVisible();
    });
  });
});
