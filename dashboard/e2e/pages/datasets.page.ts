/**
 * Page Object Model for Datasets Page
 *
 * @author Erick | Founding Principal AI Architect
 */

import { Page, Locator, expect } from '@playwright/test';

export class DatasetsPage {
  readonly page: Page;

  // Locators
  readonly pageTitle: Locator;
  readonly newDatasetButton: Locator;
  readonly datasetsList: Locator;
  readonly testCasesSection: Locator;
  readonly runTestsButton: Locator;
  readonly historyButton: Locator;
  readonly exportButton: Locator;
  readonly createModal: Locator;
  readonly testRunsHistory: Locator;

  constructor(page: Page) {
    this.page = page;

    this.pageTitle = page.getByRole('heading', { name: 'Datasets' });
    this.newDatasetButton = page.getByRole('button', { name: 'New Dataset' });
    this.datasetsList = page.getByText('Datasets').locator('..').locator('..');
    this.testCasesSection = page.getByText('Test Cases').locator('..').locator('..');
    this.runTestsButton = page.getByTestId('run-tests-button');
    this.historyButton = page.getByTestId('test-history-button');
    this.exportButton = page.getByRole('button', { name: 'Export Pytest' });
    this.createModal = page.getByText('Create New Dataset').locator('..');
    this.testRunsHistory = page.getByTestId('test-runs-history');
  }

  async goto() {
    await this.page.goto('/datasets');
  }

  async waitForLoad() {
    await expect(this.pageTitle).toBeVisible({ timeout: 10000 });
  }

  async selectDataset(name: string) {
    await this.page.getByText(name).click();
  }

  async createDataset(name: string, description?: string) {
    await this.newDatasetButton.click();
    await this.page.getByPlaceholder('e.g., API Integration Tests').fill(name);
    if (description) {
      await this.page.getByPlaceholder('Describe the purpose of this dataset...').fill(description);
    }
    await this.page.getByRole('button', { name: 'Create Dataset' }).click();
  }

  async runTests() {
    await this.runTestsButton.click();
  }

  async toggleHistory() {
    await this.historyButton.click();
  }

  async exportPytest() {
    await this.exportButton.click();
  }

  async expandTestCase(name: string) {
    await this.page.getByText(name).click();
  }

  async deleteTestCase(name: string) {
    const row = this.page.getByText(name).locator('..');
    await row.getByRole('button', { name: 'Delete' }).click();
  }

  async getDatasetCard(name: string): Promise<Locator> {
    return this.page.getByText(name).locator('..');
  }

  async getTestCaseRow(name: string): Promise<Locator> {
    return this.page.getByText(name).locator('..');
  }

  async getDatasetStats(): Promise<{ total: string; passRate: string; lastRun: string }> {
    const totalText = await this.page.getByText('Total Tests').locator('..').textContent();
    const passRateText = await this.page.getByText('Pass Rate').locator('..').textContent();
    const lastRunText = await this.page.getByText('Last Run').locator('..').textContent();

    return {
      total: totalText?.match(/\d+/)?.[0] || '0',
      passRate: passRateText?.match(/[\d.]+%/)?.[0] || '—',
      lastRun: lastRunText || '—',
    };
  }
}
