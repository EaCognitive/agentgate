/**
 * E2E Tests for Dataset Test Execution
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test, expect } from '@playwright/test';
import { createAPIMocker, mockFactories } from '../../fixtures/api-mock.fixture';

test.describe('Dataset Test Execution', () => {
  test.beforeEach(async ({ page }) => {
    // Mock API responses
    const apiMocker = createAPIMocker(page);

    // Mock datasets list
    await apiMocker.mockRoute('**/api/datasets', {
      body: [
        {
          id: 1,
          name: 'Integration Tests',
          description: 'Core integration test suite',
          test_count: 15,
          last_run_pass_rate: 93.3,
          last_run_at: new Date().toISOString(),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          tags: ['integration', 'core'],
        },
        {
          id: 2,
          name: 'API Tests',
          description: 'API endpoint tests',
          test_count: 8,
          last_run_pass_rate: 100,
          last_run_at: new Date().toISOString(),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          tags: ['api'],
        },
      ],
    });

    // Mock test cases for dataset 1
    await apiMocker.mockRoute('**/api/datasets/1/tests**', {
      body: [
        {
          id: 1,
          dataset_id: 1,
          name: 'Test Web Search',
          tool: 'web_search',
          inputs: { query: 'test query' },
          expected_output: { results: [] },
          status: 'active',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
        {
          id: 2,
          dataset_id: 1,
          name: 'Test File Write',
          tool: 'file_write',
          inputs: { path: '/tmp/test.txt', content: 'hello' },
          expected_output: { success: true },
          status: 'active',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ],
    });

    // Mock test runs
    await apiMocker.mockRoute('**/api/datasets/1/runs', {
      body: [
        {
          id: 1,
          dataset_id: 1,
          status: 'completed',
          passed_count: 14,
          failed_count: 1,
          total_tests: 15,
          duration_ms: 5432,
          started_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          completed_at: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
        },
      ],
    });

    await page.goto('/datasets');
  });

  test('should display datasets list', async ({ page }) => {
    await expect(page.getByText('Integration Tests')).toBeVisible();
    await expect(page.getByText('API Tests')).toBeVisible();
    await expect(page.getByText('15 tests')).toBeVisible();
  });

  test('should select a dataset and show test cases', async ({ page }) => {
    await page.getByText('Integration Tests').click();

    await expect(page.getByText('Test Web Search')).toBeVisible();
    await expect(page.getByText('Test File Write')).toBeVisible();
  });

  test('should show run tests button when dataset selected', async ({ page }) => {
    await page.getByText('Integration Tests').click();

    const runButton = page.getByTestId('run-tests-button');
    await expect(runButton).toBeVisible();
    await expect(runButton).toContainText('Run Tests');
  });

  test('should toggle test run history', async ({ page }) => {
    await page.getByText('Integration Tests').click();

    // Click history button
    const historyButton = page.getByTestId('test-history-button');
    await historyButton.click();

    // History panel should appear
    const historyPanel = page.getByTestId('test-runs-history');
    await expect(historyPanel).toBeVisible();
    await expect(page.getByText('Test Run History')).toBeVisible();

    // Click again to hide
    await historyButton.click();
    await expect(historyPanel).not.toBeVisible();
  });

  test('should expand test case to show details', async ({ page }) => {
    await page.getByText('Integration Tests').click();

    // Click on a test case row
    await page.getByText('Test Web Search').click();

    // Should show inputs and expected output
    await expect(page.getByText('Inputs')).toBeVisible();
    await expect(page.getByText('Expected Output')).toBeVisible();
  });

  test('should show dataset statistics', async ({ page }) => {
    await page.getByText('Integration Tests').click();

    // Check stats cards
    await expect(page.getByText('Total Tests')).toBeVisible();
    await expect(page.getByText('Pass Rate')).toBeVisible();
    await expect(page.getByText('Last Run')).toBeVisible();
    await expect(page.getByText('Created')).toBeVisible();
  });
});

test.describe('Dataset Creation', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    await apiMocker.mockRoute('**/api/datasets', {
      body: [],
    });

    await page.goto('/datasets');
  });

  test('should show create dataset modal', async ({ page }) => {
    await page.getByRole('button', { name: 'New Dataset' }).click();

    await expect(page.getByText('Create New Dataset')).toBeVisible();
    await expect(page.getByPlaceholder('e.g., API Integration Tests')).toBeVisible();
  });

  test('should create a new dataset', async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    // Mock the create endpoint
    await page.route('**/api/datasets', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 200,
          body: JSON.stringify({
            id: 1,
            name: 'New Test Dataset',
            description: 'Test description',
            test_count: 0,
            created_at: new Date().toISOString(),
          }),
        });
      } else {
        await route.fulfill({
          status: 200,
          body: JSON.stringify([]),
        });
      }
    });

    await page.getByRole('button', { name: 'New Dataset' }).click();

    await page.getByPlaceholder('e.g., API Integration Tests').fill('New Test Dataset');
    await page.getByPlaceholder('Describe the purpose of this dataset...').fill('Test description');

    await page.getByRole('button', { name: 'Create Dataset' }).click();

    // Modal should close
    await expect(page.getByText('Create New Dataset')).not.toBeVisible();
  });
});
