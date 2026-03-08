import { expect, test } from '@playwright/test';

async function mockLoginPageBootstrap(page: import('@playwright/test').Page): Promise<void> {
  await page.route('**/api/setup/status', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ setup_required: false }),
    });
  });

  await page.route('**/api/identity/providers', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        mode: 'local',
        local_password_auth_allowed: true,
      }),
    });
  });
}

test.describe('Login Smoke', () => {
  test('renders login form controls', async ({ page }) => {
    await mockLoginPageBootstrap(page);
    await page.goto('/login');

    await expect(page.getByRole('heading', { name: /welcome back/i })).toBeVisible();
    await expect(page.getByPlaceholder('you@example.com')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /sign up/i })).toBeVisible();
  });

  test('shows provider fallback mode when local auth is disabled', async ({ page }) => {
    await page.route('**/api/setup/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ setup_required: false }),
      });
    });

    await page.route('**/api/identity/providers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mode: 'descope',
          local_password_auth_allowed: false,
        }),
      });
    });

    await page.goto('/login');

    await expect(page.getByText(/local password login is disabled/i)).toBeVisible();
    await expect(page.getByRole('link', { name: /continue with descope/i })).toBeVisible();
  });
});
