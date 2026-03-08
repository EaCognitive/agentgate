/**
 * Page Object Model for Threat Detection Page
 *
 * @author Erick | Founding Principal AI Architect
 */

import { Page, Locator, expect } from '@playwright/test';

export class ThreatsPage {
  readonly page: Page;

  // Locators
  readonly pageTitle: Locator;
  readonly totalThreatsCard: Locator;
  readonly criticalHighCard: Locator;
  readonly pendingCard: Locator;
  readonly resolvedCard: Locator;
  readonly timelineChart: Locator;
  readonly severityChart: Locator;
  readonly threatsTable: Locator;
  readonly severityFilter: Locator;
  readonly statusFilter: Locator;
  readonly refreshButton: Locator;

  constructor(page: Page) {
    this.page = page;

    this.pageTitle = page.getByRole('heading', { name: 'Threat Detection' });
    this.totalThreatsCard = page.getByText('Total Threats').locator('..');
    this.criticalHighCard = page.getByText('Critical/High').locator('..');
    this.pendingCard = page.getByText('Pending Review').locator('..');
    this.resolvedCard = page.getByText('Resolved').locator('..');
    this.timelineChart = page.getByText('Threat Activity').locator('..');
    this.severityChart = page.getByText('Severity Distribution').locator('..');
    this.threatsTable = page.getByText('Active Threats').locator('..');
    this.severityFilter = page.locator('select').first();
    this.statusFilter = page.locator('select').nth(1);
    this.refreshButton = page.getByRole('button', { name: 'Refresh' });
  }

  async goto() {
    await this.page.goto('/security/threats');
  }

  async waitForLoad() {
    await expect(this.pageTitle).toBeVisible({ timeout: 10000 });
  }

  async getThreatCount(): Promise<string> {
    const text = await this.totalThreatsCard.textContent();
    const match = text?.match(/\d+/);
    return match ? match[0] : '0';
  }

  async filterBySeverity(severity: 'all' | 'critical' | 'high' | 'medium' | 'low') {
    await this.severityFilter.selectOption(severity);
  }

  async filterByStatus(status: 'all' | 'pending' | 'acknowledged' | 'resolved' | 'dismissed') {
    await this.statusFilter.selectOption(status);
  }

  async expandThreat(threatType: string) {
    await this.page.getByText(threatType).first().click();
  }

  async acknowledgeThreat() {
    await this.page.getByRole('button', { name: 'Acknowledge' }).click();
  }

  async resolveThreat() {
    await this.page.getByRole('button', { name: 'Resolve' }).click();
  }

  async dismissThreat() {
    await this.page.getByRole('button', { name: 'Dismiss' }).click();
  }

  async getThreatRow(index: number): Promise<Locator> {
    return this.threatsTable.locator('tr').nth(index + 1); // +1 to skip header
  }

  async refresh() {
    await this.refreshButton.click();
  }
}
