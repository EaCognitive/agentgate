/**
 * E2E Tests for Cost Analytics
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test, expect } from '@playwright/test';
import { createAPIMocker } from '../../fixtures/api-mock.fixture';

test.describe('Cost Analytics - By Tool View', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    // Mock cost summary
    await apiMocker.mockRoute('**/api/costs/summary', {
      body: {
        period_cost: 125.50,
        all_time_cost: 450.75,
        budget_limit: 1000,
        budget_remaining: 549.25,
        budget_used_percent: 45.08,
      },
    });

    // Mock cost breakdown by tool
    await apiMocker.mockRoute('**/api/costs/breakdown', {
      body: [
        { tool: 'web_search', total_cost: 85.25, call_count: 1234 },
        { tool: 'file_write', total_cost: 45.50, call_count: 567 },
        { tool: 'code_execute', total_cost: 30.00, call_count: 890 },
      ],
    });

    // Mock cost timeline
    await apiMocker.mockRoute('**/api/costs/timeline**', {
      body: [
        { time: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString(), cumulative_cost: 100 },
        { time: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(), cumulative_cost: 150 },
        { time: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString(), cumulative_cost: 200 },
        { time: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(), cumulative_cost: 280 },
        { time: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), cumulative_cost: 350 },
        { time: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(), cumulative_cost: 400 },
        { time: new Date().toISOString(), cumulative_cost: 450.75 },
      ],
    });

    // Mock cost by agent
    await apiMocker.mockRoute('**/api/costs/by-agent**', {
      body: [
        {
          agent_id: 'agent-research-001',
          agent_name: 'Research Agent',
          total_cost: 45.67,
          call_count: 234,
          tools_used: ['web_search', 'document_read', 'summarize'],
          last_active: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
        },
        {
          agent_id: 'agent-code-002',
          agent_name: 'Code Assistant',
          total_cost: 32.45,
          call_count: 178,
          tools_used: ['code_execute', 'file_write', 'terminal'],
          last_active: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
        },
      ],
    });

    await page.goto('/costs');
  });

  test('should display cost summary cards', async ({ page }) => {
    await expect(page.getByText('Total Cost')).toBeVisible();
    await expect(page.getByText('Avg Cost per Call')).toBeVisible();
    await expect(page.getByText('Total Calls')).toBeVisible();
  });

  test('should display budget status', async ({ page }) => {
    await expect(page.getByText('Budget Status')).toBeVisible();
    await expect(page.getByText('Edit Budget')).toBeVisible();
  });

  test('should display cost over time chart', async ({ page }) => {
    await expect(page.getByText('Cost Over Time')).toBeVisible();
    await expect(page.getByText('Cumulative cost trend (7 days)')).toBeVisible();
  });

  test('should display cost breakdown by tool', async ({ page }) => {
    await expect(page.getByText('Cost Breakdown by Tool')).toBeVisible();
    await expect(page.getByText('web_search')).toBeVisible();
    await expect(page.getByText('file_write')).toBeVisible();
  });

  test('should have tab navigation', async ({ page }) => {
    const byToolTab = page.getByTestId('cost-by-tool-tab');
    const byAgentTab = page.getByTestId('cost-by-agent-tab');

    await expect(byToolTab).toBeVisible();
    await expect(byAgentTab).toBeVisible();
  });
});

test.describe('Cost Analytics - By Agent View', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    // Mock all endpoints
    await apiMocker.mockRoute('**/api/costs/summary', {
      body: {
        period_cost: 125.50,
        all_time_cost: 450.75,
        budget_limit: 1000,
        budget_remaining: 549.25,
      },
    });

    await apiMocker.mockRoute('**/api/costs/breakdown', {
      body: [
        { tool: 'web_search', total_cost: 85.25, call_count: 1234 },
      ],
    });

    await apiMocker.mockRoute('**/api/costs/timeline**', {
      body: [],
    });

    await apiMocker.mockRoute('**/api/costs/by-agent**', {
      body: [
        {
          agent_id: 'agent-research-001',
          agent_name: 'Research Agent',
          total_cost: 45.67,
          call_count: 234,
          tools_used: ['web_search', 'document_read', 'summarize'],
          last_active: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
        },
        {
          agent_id: 'agent-code-002',
          agent_name: 'Code Assistant',
          total_cost: 32.45,
          call_count: 178,
          tools_used: ['code_execute', 'file_write', 'terminal'],
          last_active: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
        },
      ],
    });

    await page.goto('/costs');
  });

  test('should switch to agent view', async ({ page }) => {
    await page.getByTestId('cost-by-agent-tab').click();

    await expect(page.getByText('Total Agent Cost')).toBeVisible();
    await expect(page.getByText('Active Agents')).toBeVisible();
    await expect(page.getByText('Total Agent Calls')).toBeVisible();
  });

  test('should display agent cost distribution chart', async ({ page }) => {
    await page.getByTestId('cost-by-agent-tab').click();

    await expect(page.getByText('Cost Distribution by Agent')).toBeVisible();
  });

  test('should display top agents by cost', async ({ page }) => {
    await page.getByTestId('cost-by-agent-tab').click();

    await expect(page.getByText('Top Agents by Cost')).toBeVisible();
    await expect(page.getByText('Research Agent')).toBeVisible();
    await expect(page.getByText('Code Assistant')).toBeVisible();
  });

  test('should display agent cost details table', async ({ page }) => {
    await page.getByTestId('cost-by-agent-tab').click();

    const table = page.getByTestId('agent-cost-table');
    await expect(table).toBeVisible();
    await expect(page.getByText('Agent Cost Details')).toBeVisible();
  });

  test('should expand agent row to show tools used', async ({ page }) => {
    await page.getByTestId('cost-by-agent-tab').click();

    // Click on an agent row
    await page.getByText('Research Agent').click();

    // Should show tools used
    await expect(page.getByText('Tools Used')).toBeVisible();
    await expect(page.getByText('web_search')).toBeVisible();
    await expect(page.getByText('document_read')).toBeVisible();
  });
});

test.describe('Budget Management', () => {
  test.beforeEach(async ({ page }) => {
    const apiMocker = createAPIMocker(page);

    await apiMocker.mockRoute('**/api/costs/summary', {
      body: {
        period_cost: 125.50,
        all_time_cost: 850.00,
        budget_limit: 1000,
        budget_remaining: 150,
      },
    });

    await apiMocker.mockRoute('**/api/costs/breakdown', { body: [] });
    await apiMocker.mockRoute('**/api/costs/timeline**', { body: [] });
    await apiMocker.mockRoute('**/api/costs/by-agent**', { body: [] });

    await page.goto('/costs');
  });

  test('should show budget warning when above 80%', async ({ page }) => {
    await expect(page.getByText(/Budget usage is above 80%/)).toBeVisible();
  });

  test('should open budget edit modal', async ({ page }) => {
    await page.getByRole('button', { name: 'Edit Budget' }).click();

    await expect(page.getByText('Monthly Budget Limit ($)')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save Budget' })).toBeVisible();
  });

  test('should save new budget', async ({ page }) => {
    await page.getByRole('button', { name: 'Edit Budget' }).click();

    const input = page.getByPlaceholder('1000');
    await input.clear();
    await input.fill('2000');

    await page.getByRole('button', { name: 'Save Budget' }).click();

    // Modal should close
    await expect(page.getByText('Monthly Budget Limit ($)')).not.toBeVisible();
  });
});
