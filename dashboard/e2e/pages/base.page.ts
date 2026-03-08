/**
 * Base Page Object Model
 * Provides common functionality for all page objects
 *
 * @author Erick | Founding Principal AI Architect
 */

import { Page, Locator, expect } from '@playwright/test';

export abstract class BasePage {
  readonly page: Page;
  protected readonly baseURL: string;

  constructor(page: Page) {
    this.page = page;
    this.baseURL = page.context().pages()[0]?.url() || 'http://localhost:3000';
  }

  // Common navigation elements
  get sidebar(): Locator {
    return this.page.locator('[data-testid="sidebar"]');
  }

  get header(): Locator {
    return this.page.locator('[data-testid="header"]');
  }

  get userMenu(): Locator {
    return this.page.locator('[data-testid="user-menu"]');
  }

  get loadingSpinner(): Locator {
    return this.page.locator('[data-testid="loading-spinner"]');
  }

  get toastNotification(): Locator {
    return this.page.locator('[data-testid="toast-notification"]');
  }

  // Common actions
  async goto(): Promise<void> {
    await this.page.goto(this.getPath());
    await this.waitForPageLoad();
  }

  abstract getPath(): string;

  async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
  }

  async waitForLoading(): Promise<void> {
    const spinner = this.loadingSpinner;
    if (await spinner.isVisible()) {
      await spinner.waitFor({ state: 'hidden', timeout: 30000 });
    }
  }

  async expectToastSuccess(message?: string): Promise<void> {
    const toast = this.toastNotification.filter({ hasText: message || '' });
    await expect(toast).toBeVisible();
    await expect(toast).toHaveAttribute('data-type', 'success');
  }

  async expectToastError(message?: string): Promise<void> {
    const toast = this.toastNotification.filter({ hasText: message || '' });
    await expect(toast).toBeVisible();
    await expect(toast).toHaveAttribute('data-type', 'error');
  }

  async navigateTo(path: string): Promise<void> {
    await this.page.goto(path);
    await this.waitForPageLoad();
  }

  async clickNavItem(name: string): Promise<void> {
    await this.sidebar.getByRole('link', { name }).click();
    await this.waitForPageLoad();
  }

  async logout(): Promise<void> {
    await this.userMenu.click();
    await this.page.getByRole('button', { name: /logout/i }).click();
    await this.page.waitForURL('**/login');
  }

  async takeScreenshot(name: string): Promise<void> {
    await this.page.screenshot({
      path: `./e2e/screenshots/${name}.png`,
      fullPage: true,
    });
  }

  // Table helpers
  async getTableRowCount(tableSelector: string): Promise<number> {
    const rows = this.page.locator(`${tableSelector} tbody tr`);
    return rows.count();
  }

  async getTableRow(tableSelector: string, index: number): Promise<Locator> {
    return this.page.locator(`${tableSelector} tbody tr`).nth(index);
  }

  async sortTableBy(columnName: string): Promise<void> {
    await this.page.getByRole('columnheader', { name: columnName }).click();
  }

  // Modal helpers
  async waitForModal(title?: string): Promise<Locator> {
    const modal = this.page.locator('[role="dialog"]');
    await modal.waitFor({ state: 'visible' });
    if (title) {
      await expect(modal.getByRole('heading', { name: title })).toBeVisible();
    }
    return modal;
  }

  async closeModal(): Promise<void> {
    await this.page.locator('[role="dialog"] [data-testid="close-modal"]').click();
    await this.page.locator('[role="dialog"]').waitFor({ state: 'hidden' });
  }

  async confirmModal(): Promise<void> {
    await this.page.locator('[role="dialog"]').getByRole('button', { name: /confirm|yes|ok/i }).click();
  }

  async cancelModal(): Promise<void> {
    await this.page.locator('[role="dialog"]').getByRole('button', { name: /cancel|no/i }).click();
  }

  // Form helpers
  async fillInput(testId: string, value: string): Promise<void> {
    await this.page.locator(`[data-testid="${testId}"]`).fill(value);
  }

  async selectOption(testId: string, value: string): Promise<void> {
    await this.page.locator(`[data-testid="${testId}"]`).selectOption(value);
  }

  async toggleSwitch(testId: string): Promise<void> {
    await this.page.locator(`[data-testid="${testId}"]`).click();
  }

  async clickButton(testId: string): Promise<void> {
    await this.page.locator(`[data-testid="${testId}"]`).click();
  }

  // Pagination helpers
  async goToNextPage(): Promise<void> {
    await this.page.getByRole('button', { name: /next/i }).click();
    await this.waitForLoading();
  }

  async goToPreviousPage(): Promise<void> {
    await this.page.getByRole('button', { name: /previous/i }).click();
    await this.waitForLoading();
  }

  async goToPage(pageNumber: number): Promise<void> {
    await this.page.getByRole('button', { name: String(pageNumber), exact: true }).click();
    await this.waitForLoading();
  }

  // Filter helpers
  async applyFilter(filterName: string, value: string): Promise<void> {
    await this.page.locator(`[data-testid="filter-${filterName}"]`).selectOption(value);
    await this.waitForLoading();
  }

  async clearFilters(): Promise<void> {
    await this.page.getByRole('button', { name: /clear filters/i }).click();
    await this.waitForLoading();
  }

  // Search helpers
  async search(query: string): Promise<void> {
    await this.page.locator('[data-testid="search-input"]').fill(query);
    await this.page.keyboard.press('Enter');
    await this.waitForLoading();
  }

  async clearSearch(): Promise<void> {
    await this.page.locator('[data-testid="search-input"]').clear();
    await this.page.keyboard.press('Enter');
    await this.waitForLoading();
  }
}
