/**
 * Overview/Dashboard Page Object Model
 *
 * @author Erick | Founding Principal AI Architect
 */

import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';

export class OverviewPage extends BasePage {
  constructor(page: Page) {
    super(page);
  }

  getPath(): string {
    return '/';
  }

  // Stat Cards
  get totalTracesCard(): Locator {
    return this.page.locator('[data-testid="stat-total-traces"]');
  }

  get successRateCard(): Locator {
    return this.page.locator('[data-testid="stat-success-rate"]');
  }

  get pendingApprovalsCard(): Locator {
    return this.page.locator('[data-testid="stat-pending-approvals"]');
  }

  get totalCostCard(): Locator {
    return this.page.locator('[data-testid="stat-total-cost"]');
  }

  // Charts
  get tracesTimelineChart(): Locator {
    return this.page.locator('[data-testid="traces-timeline-chart"]');
  }

  get statusDistributionChart(): Locator {
    return this.page.locator('[data-testid="status-distribution-chart"]');
  }

  get toolUsageChart(): Locator {
    return this.page.locator('[data-testid="tool-usage-chart"]');
  }

  // Recent Activity
  get recentTracesTable(): Locator {
    return this.page.locator('[data-testid="recent-traces-table"]');
  }

  get recentApprovalsTable(): Locator {
    return this.page.locator('[data-testid="recent-approvals-table"]');
  }

  // Time Range Selector
  get timeRangeSelector(): Locator {
    return this.page.locator('[data-testid="time-range-selector"]');
  }

  // Actions
  async selectTimeRange(range: '24h' | '7d' | '30d' | 'custom'): Promise<void> {
    await this.timeRangeSelector.click();
    await this.page.getByRole('option', { name: range }).click();
    await this.waitForLoading();
  }

  async viewAllTraces(): Promise<void> {
    await this.page.getByRole('link', { name: /view all traces/i }).click();
    await this.page.waitForURL('**/traces');
  }

  async viewAllApprovals(): Promise<void> {
    await this.page.getByRole('link', { name: /view all approvals/i }).click();
    await this.page.waitForURL('**/approvals');
  }

  async clickRecentTrace(index: number = 0): Promise<void> {
    await this.recentTracesTable.locator('tbody tr').nth(index).click();
  }

  async clickRecentApproval(index: number = 0): Promise<void> {
    await this.recentApprovalsTable.locator('tbody tr').nth(index).click();
  }

  // Assertions
  async expectPageLoaded(): Promise<void> {
    await expect(this.totalTracesCard).toBeVisible();
    await expect(this.successRateCard).toBeVisible();
    await expect(this.pendingApprovalsCard).toBeVisible();
    await expect(this.totalCostCard).toBeVisible();
  }

  async expectChartsRendered(): Promise<void> {
    await expect(this.tracesTimelineChart).toBeVisible();
    await expect(this.statusDistributionChart).toBeVisible();
  }

  async expectStatCardValue(card: 'total-traces' | 'success-rate' | 'pending-approvals' | 'total-cost', value: string): Promise<void> {
    const cardLocator = this.page.locator(`[data-testid="stat-${card}"]`);
    await expect(cardLocator.locator('[data-testid="stat-value"]')).toContainText(value);
  }

  async expectRecentTracesCount(count: number): Promise<void> {
    const rows = this.recentTracesTable.locator('tbody tr');
    await expect(rows).toHaveCount(count);
  }

  async expectRecentApprovalsCount(count: number): Promise<void> {
    const rows = this.recentApprovalsTable.locator('tbody tr');
    await expect(rows).toHaveCount(count);
  }

  async getStatCardValue(card: 'total-traces' | 'success-rate' | 'pending-approvals' | 'total-cost'): Promise<string> {
    const cardLocator = this.page.locator(`[data-testid="stat-${card}"]`);
    return await cardLocator.locator('[data-testid="stat-value"]').textContent() || '';
  }
}
