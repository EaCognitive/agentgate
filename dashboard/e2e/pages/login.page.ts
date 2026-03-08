/**
 * Login Page Object Model
 *
 * @author Erick | Founding Principal AI Architect
 */

import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';

export class LoginPage extends BasePage {
  constructor(page: Page) {
    super(page);
  }

  getPath(): string {
    return '/login';
  }

  // Locators
  get emailInput(): Locator {
    return this.page.locator('[data-testid="email-input"]');
  }

  get passwordInput(): Locator {
    return this.page.locator('[data-testid="password-input"]');
  }

  get loginButton(): Locator {
    return this.page.locator('[data-testid="login-button"]');
  }

  get rememberMeCheckbox(): Locator {
    return this.page.locator('[data-testid="remember-me"]');
  }

  get forgotPasswordLink(): Locator {
    return this.page.getByRole('link', { name: /forgot password/i });
  }

  get signUpLink(): Locator {
    return this.page.getByRole('link', { name: /sign up/i });
  }

  get googleLoginButton(): Locator {
    return this.page.locator('[data-testid="google-login"]');
  }

  get githubLoginButton(): Locator {
    return this.page.locator('[data-testid="github-login"]');
  }

  get errorMessage(): Locator {
    return this.page.locator('[data-testid="error-message"]');
  }

  get mfaCodeInput(): Locator {
    return this.page.locator('[data-testid="mfa-code-input"]');
  }

  get mfaVerifyButton(): Locator {
    return this.page.locator('[data-testid="mfa-verify-button"]');
  }

  get useBackupCodeLink(): Locator {
    return this.page.getByRole('link', { name: /use backup code/i });
  }

  get backupCodeInput(): Locator {
    return this.page.locator('[data-testid="backup-code-input"]');
  }

  // Actions
  async login(email: string, password: string): Promise<void> {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.loginButton.click();
  }

  async loginWithRememberMe(email: string, password: string): Promise<void> {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.rememberMeCheckbox.check();
    await this.loginButton.click();
  }

  async verifyMFA(code: string): Promise<void> {
    await this.mfaCodeInput.fill(code);
    await this.mfaVerifyButton.click();
  }

  async useBackupCode(code: string): Promise<void> {
    await this.useBackupCodeLink.click();
    await this.backupCodeInput.fill(code);
    await this.mfaVerifyButton.click();
  }

  async clickGoogleLogin(): Promise<void> {
    await this.googleLoginButton.click();
  }

  async clickGithubLogin(): Promise<void> {
    await this.githubLoginButton.click();
  }

  async navigateToSignUp(): Promise<void> {
    await this.signUpLink.click();
    await this.page.waitForURL('**/signup');
  }

  async navigateToForgotPassword(): Promise<void> {
    await this.forgotPasswordLink.click();
    await this.page.waitForURL('**/forgot-password');
  }

  // Assertions
  async expectLoginSuccess(): Promise<void> {
    await this.page.waitForURL('/');
    await expect(this.page).toHaveURL('/');
  }

  async expectLoginError(message?: string): Promise<void> {
    await expect(this.errorMessage).toBeVisible();
    if (message) {
      await expect(this.errorMessage).toContainText(message);
    }
  }

  async expectMFARequired(): Promise<void> {
    await expect(this.mfaCodeInput).toBeVisible();
    await expect(this.mfaVerifyButton).toBeVisible();
  }

  async expectFormValidationError(field: string): Promise<void> {
    const fieldError = this.page.locator(`[data-testid="${field}-error"]`);
    await expect(fieldError).toBeVisible();
  }

  async expectPageLoaded(): Promise<void> {
    await expect(this.emailInput).toBeVisible();
    await expect(this.passwordInput).toBeVisible();
    await expect(this.loginButton).toBeVisible();
  }
}
