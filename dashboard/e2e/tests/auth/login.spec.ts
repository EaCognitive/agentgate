/**
 * Login Page E2E Tests
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test, expect } from '@playwright/test';
import { LoginPage } from '../../pages/login.page';
import { createAPIMocker } from '../../fixtures/api-mock.fixture';

test.describe('Login Page', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    await loginPage.goto();
  });

  test.describe('Page Load', () => {
    test('should display login form elements', async () => {
      await loginPage.expectPageLoaded();
      await expect(loginPage.forgotPasswordLink).toBeVisible();
      await expect(loginPage.signUpLink).toBeVisible();
    });

    test('should display social login buttons', async () => {
      await expect(loginPage.googleLoginButton).toBeVisible();
      await expect(loginPage.githubLoginButton).toBeVisible();
    });
  });

  test.describe('Form Validation', () => {
    test('should show error for empty email', async () => {
      await loginPage.passwordInput.fill('password123');
      await loginPage.loginButton.click();
      await loginPage.expectFormValidationError('email');
    });

    test('should show error for invalid email format', async () => {
      await loginPage.emailInput.fill('invalid-email');
      await loginPage.passwordInput.fill('password123');
      await loginPage.loginButton.click();
      await loginPage.expectFormValidationError('email');
    });

    test('should show error for empty password', async () => {
      await loginPage.emailInput.fill('test@example.com');
      await loginPage.loginButton.click();
      await loginPage.expectFormValidationError('password');
    });

    test('should show error for short password', async () => {
      await loginPage.emailInput.fill('test@example.com');
      await loginPage.passwordInput.fill('short');
      await loginPage.loginButton.click();
      await loginPage.expectFormValidationError('password');
    });
  });

  test.describe('Authentication', () => {
    test('should login successfully with valid credentials', async ({ page }) => {
      const mocker = createAPIMocker(page);
      await mocker.mockRoute('**/api/auth/login', {
        body: {
          access_token: 'test-token',
          token_type: 'bearer',
          user: { id: '1', email: 'test@example.com', role: 'admin' },
        },
      });

      await loginPage.login('test@example.com', 'ValidPassword123!');
      await loginPage.expectLoginSuccess();
    });

    test('should show error for invalid credentials', async ({ page }) => {
      const mocker = createAPIMocker(page);
      await mocker.mockError('**/api/auth/login', 401, 'Invalid email or password');

      await loginPage.login('test@example.com', 'WrongPassword');
      await loginPage.expectLoginError('Invalid email or password');
    });

    test('should show error for locked account', async ({ page }) => {
      const mocker = createAPIMocker(page);
      await mocker.mockError('**/api/auth/login', 423, 'Account locked due to too many failed attempts');

      await loginPage.login('test@example.com', 'password');
      await loginPage.expectLoginError('Account locked');
    });

    test('should handle network error gracefully', async ({ page }) => {
      const mocker = createAPIMocker(page);
      await mocker.mockNetworkError('**/api/auth/login');

      await loginPage.login('test@example.com', 'password');
      await loginPage.expectLoginError();
    });
  });

  test.describe('MFA Flow', () => {
    test('should prompt for MFA code when 2FA is enabled', async ({ page }) => {
      const mocker = createAPIMocker(page);
      await mocker.mockRoute('**/api/auth/login', {
        status: 200,
        body: { mfa_required: true, session_token: 'temp-session' },
      });

      await loginPage.login('test@example.com', 'ValidPassword123!');
      await loginPage.expectMFARequired();
    });

    test('should verify MFA code successfully', async ({ page }) => {
      const mocker = createAPIMocker(page);

      // First request returns MFA required
      await mocker.mockRoute('**/api/auth/login', {
        body: { mfa_required: true, session_token: 'temp-session' },
      });

      await loginPage.login('test@example.com', 'ValidPassword123!');
      await loginPage.expectMFARequired();

      // Clear the mock and set up for MFA verification
      await mocker.clearMocks();
      await mocker.mockRoute('**/api/auth/2fa/verify', {
        body: {
          access_token: 'test-token',
          user: { id: '1', email: 'test@example.com', role: 'admin' },
        },
      });

      await loginPage.verifyMFA('123456');
      await loginPage.expectLoginSuccess();
    });

    test('should show error for invalid MFA code', async ({ page }) => {
      const mocker = createAPIMocker(page);

      await mocker.mockRoute('**/api/auth/login', {
        body: { mfa_required: true, session_token: 'temp-session' },
      });

      await loginPage.login('test@example.com', 'ValidPassword123!');
      await loginPage.expectMFARequired();

      await mocker.clearMocks();
      await mocker.mockError('**/api/auth/2fa/verify', 401, 'Invalid verification code');

      await loginPage.verifyMFA('000000');
      await loginPage.expectLoginError('Invalid verification code');
    });

    test('should allow using backup code', async ({ page }) => {
      const mocker = createAPIMocker(page);

      await mocker.mockRoute('**/api/auth/login', {
        body: { mfa_required: true, session_token: 'temp-session' },
      });

      await loginPage.login('test@example.com', 'ValidPassword123!');
      await loginPage.expectMFARequired();

      await mocker.clearMocks();
      await mocker.mockRoute('**/api/auth/2fa/verify', {
        body: {
          access_token: 'test-token',
          user: { id: '1', email: 'test@example.com', role: 'admin' },
        },
      });

      await loginPage.useBackupCode('ABCD-EFGH-1234');
      await loginPage.expectLoginSuccess();
    });
  });

  test.describe('Remember Me', () => {
    test('should persist session when remember me is checked', async ({ page }) => {
      const mocker = createAPIMocker(page);
      await mocker.mockRoute('**/api/auth/login', {
        body: {
          access_token: 'test-token',
          refresh_token: 'refresh-token',
          user: { id: '1', email: 'test@example.com', role: 'admin' },
        },
      });

      await loginPage.loginWithRememberMe('test@example.com', 'ValidPassword123!');
      await loginPage.expectLoginSuccess();

      // Verify refresh token is stored
      const cookies = await page.context().cookies();
      const refreshCookie = cookies.find((c) => c.name === 'refresh_token');
      expect(refreshCookie).toBeTruthy();
    });
  });

  test.describe('Navigation', () => {
    test('should navigate to sign up page', async () => {
      await loginPage.navigateToSignUp();
    });

    test('should navigate to forgot password page', async () => {
      await loginPage.navigateToForgotPassword();
    });
  });

  test.describe('Accessibility', () => {
    test('should be keyboard navigable', async ({ page }) => {
      await page.keyboard.press('Tab');
      await expect(loginPage.emailInput).toBeFocused();

      await page.keyboard.press('Tab');
      await expect(loginPage.passwordInput).toBeFocused();

      await page.keyboard.press('Tab');
      await expect(loginPage.rememberMeCheckbox).toBeFocused();

      await page.keyboard.press('Tab');
      await expect(loginPage.loginButton).toBeFocused();
    });

    test('should have proper form labels', async ({ page }) => {
      const emailLabel = page.locator('label[for="email"]');
      const passwordLabel = page.locator('label[for="password"]');

      await expect(emailLabel).toBeVisible();
      await expect(passwordLabel).toBeVisible();
    });

    test('should announce errors to screen readers', async ({ page }) => {
      await loginPage.loginButton.click();

      const errorRegion = page.locator('[role="alert"]');
      await expect(errorRegion).toBeVisible();
    });
  });

  test.describe('Rate Limiting', () => {
    test('should show rate limit message after too many attempts', async ({ page }) => {
      const mocker = createAPIMocker(page);
      await mocker.mockError('**/api/auth/login', 429, 'Too many login attempts. Please try again later.');

      await loginPage.login('test@example.com', 'WrongPassword');
      await loginPage.expectLoginError('Too many login attempts');
    });
  });
});
