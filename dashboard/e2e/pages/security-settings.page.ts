/**
 * Security Settings Page Object Model
 *
 * @author Erick | Founding Principal AI Architect
 */

import { Page, Locator, Download, expect } from '@playwright/test';
import { BasePage } from './base.page';

export class SecuritySettingsPage extends BasePage {
  constructor(page: Page) {
    super(page);
  }

  getPath(): string {
    return '/security/settings';
  }

  // Two-Factor Authentication Section
  get twoFactorSection(): Locator {
    return this.page.locator('[data-testid="2fa-section"]');
  }

  get enable2FAButton(): Locator {
    return this.page.locator('[data-testid="enable-2fa-button"]');
  }

  get disable2FAButton(): Locator {
    return this.page.locator('[data-testid="disable-2fa-button"]');
  }

  get qrCode(): Locator {
    return this.page.locator('[data-testid="2fa-qr-code"]');
  }

  get secretKey(): Locator {
    return this.page.locator('[data-testid="2fa-secret-key"]');
  }

  get verificationCodeInput(): Locator {
    return this.page.locator('[data-testid="2fa-verification-code"]');
  }

  get verify2FAButton(): Locator {
    return this.page.locator('[data-testid="verify-2fa-button"]');
  }

  get twoFactorStatus(): Locator {
    return this.page.locator('[data-testid="2fa-status"]');
  }

  // Backup Codes Section
  get backupCodesSection(): Locator {
    return this.page.locator('[data-testid="backup-codes-section"]');
  }

  get generateBackupCodesButton(): Locator {
    return this.page.locator('[data-testid="generate-backup-codes-button"]');
  }

  get backupCodesList(): Locator {
    return this.page.locator('[data-testid="backup-codes-list"]');
  }

  get downloadBackupCodesButton(): Locator {
    return this.page.locator('[data-testid="download-backup-codes-button"]');
  }

  get copyBackupCodesButton(): Locator {
    return this.page.locator('[data-testid="copy-backup-codes-button"]');
  }

  // WebAuthn Passkeys Section
  get passkeysSection(): Locator {
    return this.page.locator('[data-testid="passkeys-section"]');
  }

  get registerPasskeyButton(): Locator {
    return this.page.locator('[data-testid="register-passkey-button"]');
  }

  get passkeysList(): Locator {
    return this.page.locator('[data-testid="passkeys-list"]');
  }

  get passkeyNameInput(): Locator {
    return this.page.locator('[data-testid="passkey-name-input"]');
  }

  // Active Sessions Section
  get sessionsSection(): Locator {
    return this.page.locator('[data-testid="sessions-section"]');
  }

  get sessionsList(): Locator {
    return this.page.locator('[data-testid="sessions-list"]');
  }

  get terminateAllSessionsButton(): Locator {
    return this.page.locator('[data-testid="terminate-all-sessions-button"]');
  }

  get currentSessionBadge(): Locator {
    return this.page.locator('[data-testid="current-session-badge"]');
  }

  // Password Change Section
  get passwordSection(): Locator {
    return this.page.locator('[data-testid="password-section"]');
  }

  get currentPasswordInput(): Locator {
    return this.page.locator('[data-testid="current-password-input"]');
  }

  get newPasswordInput(): Locator {
    return this.page.locator('[data-testid="new-password-input"]');
  }

  get confirmPasswordInput(): Locator {
    return this.page.locator('[data-testid="confirm-password-input"]');
  }

  get changePasswordButton(): Locator {
    return this.page.locator('[data-testid="change-password-button"]');
  }

  // Security Activity Log
  get activityLog(): Locator {
    return this.page.locator('[data-testid="security-activity-log"]');
  }

  // 2FA Actions
  async enable2FA(): Promise<void> {
    await this.enable2FAButton.click();
    await this.waitForModal('Enable Two-Factor Authentication');
    await expect(this.qrCode).toBeVisible();
  }

  async verify2FA(code: string): Promise<void> {
    await this.verificationCodeInput.fill(code);
    await this.verify2FAButton.click();
    await this.waitForLoading();
  }

  async disable2FA(code: string): Promise<void> {
    await this.disable2FAButton.click();
    await this.waitForModal('Disable Two-Factor Authentication');
    await this.verificationCodeInput.fill(code);
    await this.confirmModal();
    await this.waitForLoading();
  }

  async generateBackupCodes(): Promise<void> {
    await this.generateBackupCodesButton.click();
    await this.waitForModal('Backup Codes');
    await expect(this.backupCodesList).toBeVisible();
  }

  async downloadBackupCodes(): Promise<Download> {
    const [download] = await Promise.all([
      this.page.waitForEvent('download'),
      this.downloadBackupCodesButton.click(),
    ]);
    return download;
  }

  // Passkey Actions
  async registerPasskey(name: string): Promise<void> {
    await this.registerPasskeyButton.click();
    await this.waitForModal('Register Passkey');
    await this.passkeyNameInput.fill(name);
    // Note: Actual WebAuthn registration requires browser support
    // In tests, we'll mock this or use virtual authenticators
  }

  async revokePasskey(name: string): Promise<void> {
    const passkeyRow = this.passkeysList.locator(`[data-passkey-name="${name}"]`);
    await passkeyRow.locator('[data-testid="revoke-passkey-button"]').click();
    await this.waitForModal('Revoke Passkey');
    await this.confirmModal();
    await this.waitForLoading();
  }

  async getPasskeyCount(): Promise<number> {
    return this.passkeysList.locator('[data-testid="passkey-item"]').count();
  }

  // Session Actions
  async terminateSession(sessionId: string): Promise<void> {
    const sessionRow = this.sessionsList.locator(`[data-session-id="${sessionId}"]`);
    await sessionRow.locator('[data-testid="terminate-session-button"]').click();
    await this.waitForModal('Terminate Session');
    await this.confirmModal();
    await this.waitForLoading();
  }

  async terminateAllOtherSessions(): Promise<void> {
    await this.terminateAllSessionsButton.click();
    await this.waitForModal('Terminate All Sessions');
    await this.confirmModal();
    await this.waitForLoading();
  }

  async getSessionCount(): Promise<number> {
    return this.sessionsList.locator('[data-testid="session-item"]').count();
  }

  // Password Actions
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.currentPasswordInput.fill(currentPassword);
    await this.newPasswordInput.fill(newPassword);
    await this.confirmPasswordInput.fill(newPassword);
    await this.changePasswordButton.click();
    await this.waitForLoading();
  }

  // Assertions
  async expectPageLoaded(): Promise<void> {
    await expect(this.twoFactorSection).toBeVisible();
    await expect(this.passkeysSection).toBeVisible();
    await expect(this.sessionsSection).toBeVisible();
  }

  async expect2FAEnabled(): Promise<void> {
    await expect(this.twoFactorStatus).toContainText('Enabled');
    await expect(this.disable2FAButton).toBeVisible();
    await expect(this.enable2FAButton).not.toBeVisible();
  }

  async expect2FADisabled(): Promise<void> {
    await expect(this.twoFactorStatus).toContainText('Disabled');
    await expect(this.enable2FAButton).toBeVisible();
    await expect(this.disable2FAButton).not.toBeVisible();
  }

  async expectBackupCodesGenerated(count: number = 10): Promise<void> {
    const codes = this.backupCodesList.locator('[data-testid="backup-code"]');
    await expect(codes).toHaveCount(count);
  }

  async expectPasskeyRegistered(name: string): Promise<void> {
    const passkey = this.passkeysList.locator(`[data-passkey-name="${name}"]`);
    await expect(passkey).toBeVisible();
  }

  async expectCurrentSessionMarked(): Promise<void> {
    await expect(this.currentSessionBadge).toBeVisible();
    await expect(this.currentSessionBadge).toContainText('Current');
  }

  async expectPasswordChangeSuccess(): Promise<void> {
    await this.expectToastSuccess('Password changed successfully');
  }

  async expectPasswordChangeError(message: string): Promise<void> {
    await this.expectToastError(message);
  }
}
