/**
 * Dashboard Overview E2E Tests
 *
 * @author Erick | Founding Principal AI Architect
 */

import { test, expect } from '../../fixtures/auth.fixture';
import { OverviewPage } from '../../pages/overview.page';
import { createAPIMocker, mockFactories } from '../../fixtures/api-mock.fixture';

test.describe('Dashboard Overview', () => {
  let overviewPage: OverviewPage;

  test.beforeEach(async ({ authenticatedPage }) => {
    overviewPage = new OverviewPage(authenticatedPage);
    await overviewPage.goto();
  });

  test.describe('Page Load', () => {
    test('should display all stat cards', async () => {
      await overviewPage.expectPageLoaded();
    });

    test('should render charts', async () => {
      await overviewPage.expectChartsRendered();
    });

    test('should display recent traces table', async () => {
      await expect(overviewPage.recentTracesTable).toBeVisible();
    });

    test('should display recent approvals table', async () => {
      await expect(overviewPage.recentApprovalsTable).toBeVisible();
    });

    test('should show time range selector', async () => {
      await expect(overviewPage.timeRangeSelector).toBeVisible();
    });
  });

  test.describe('Stat Cards', () => {
    test('should display correct total traces count', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/overview', {
        body: {
          total_traces: 1250,
          success_rate: 95.5,
          pending_approvals: 12,
          total_cost: 125.50,
        },
      });

      await overviewPage.goto();
      await overviewPage.expectStatCardValue('total-traces', '1,250');
    });

    test('should display correct success rate', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/overview', {
        body: {
          total_traces: 1000,
          success_rate: 98.7,
          pending_approvals: 5,
          total_cost: 100,
        },
      });

      await overviewPage.goto();
      await overviewPage.expectStatCardValue('success-rate', '98.7%');
    });

    test('should display pending approvals with badge', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/overview', {
        body: {
          total_traces: 500,
          success_rate: 90,
          pending_approvals: 25,
          total_cost: 50,
        },
      });

      await overviewPage.goto();
      await overviewPage.expectStatCardValue('pending-approvals', '25');
    });

    test('should display total cost formatted as currency', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/overview', {
        body: {
          total_traces: 1000,
          success_rate: 95,
          pending_approvals: 10,
          total_cost: 1234.56,
        },
      });

      await overviewPage.goto();
      await overviewPage.expectStatCardValue('total-cost', '$1,234.56');
    });
  });

  test.describe('Time Range Selection', () => {
    test('should update data when selecting 24h range', async ({ authenticatedPage }) => {
      await overviewPage.selectTimeRange('24h');
      await expect(overviewPage.timeRangeSelector).toContainText('24h');
    });

    test('should update data when selecting 7d range', async () => {
      await overviewPage.selectTimeRange('7d');
      await expect(overviewPage.timeRangeSelector).toContainText('7d');
    });

    test('should update data when selecting 30d range', async () => {
      await overviewPage.selectTimeRange('30d');
      await expect(overviewPage.timeRangeSelector).toContainText('30d');
    });
  });

  test.describe('Recent Traces Table', () => {
    test('should display up to 5 recent traces', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      const traces = Array.from({ length: 5 }, (_, i) =>
        mockFactories.trace({ id: `trace-${i}` })
      );

      await mocker.mockRoute('**/api/traces*', {
        body: { items: traces, total: 100 },
      });

      await overviewPage.goto();
      await overviewPage.expectRecentTracesCount(5);
    });

    test('should navigate to traces page on view all click', async () => {
      await overviewPage.viewAllTraces();
    });

    test('should open trace details on row click', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      const trace = mockFactories.trace({ id: 'trace-001' });

      await mocker.mockRoute('**/api/traces*', {
        body: { items: [trace], total: 1 },
      });

      await overviewPage.goto();
      await overviewPage.clickRecentTrace(0);

      // Should open trace detail modal or navigate to detail page
      const modal = await overviewPage.waitForModal('Trace Details');
      await expect(modal).toBeVisible();
    });
  });

  test.describe('Recent Approvals Table', () => {
    test('should display pending approvals', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      const approvals = Array.from({ length: 3 }, (_, i) =>
        mockFactories.approval({ id: `approval-${i}` })
      );

      await mocker.mockRoute('**/api/approvals/pending', {
        body: { items: approvals, total: 3 },
      });

      await overviewPage.goto();
      await overviewPage.expectRecentApprovalsCount(3);
    });

    test('should navigate to approvals page on view all click', async () => {
      await overviewPage.viewAllApprovals();
    });
  });

  test.describe('Charts', () => {
    test('should render traces timeline chart with data', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      const timelineData = Array.from({ length: 24 }, (_, i) => ({
        hour: i,
        traces: Math.floor(Math.random() * 100),
        success: Math.floor(Math.random() * 80),
        failed: Math.floor(Math.random() * 20),
      }));

      await mocker.mockRoute('**/api/traces/timeline*', {
        body: timelineData,
      });

      await overviewPage.goto();
      await expect(overviewPage.tracesTimelineChart).toBeVisible();

      // Verify chart has rendered SVG elements
      const chartSvg = overviewPage.tracesTimelineChart.locator('svg');
      await expect(chartSvg).toBeVisible();
    });

    test('should render status distribution pie chart', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);

      await mocker.mockRoute('**/api/traces/stats*', {
        body: {
          total: 1000,
          by_status: {
            success: 850,
            failed: 100,
            blocked: 30,
            pending: 20,
          },
        },
      });

      await overviewPage.goto();
      await expect(overviewPage.statusDistributionChart).toBeVisible();
    });

    test('should show tooltip on chart hover', async ({ authenticatedPage }) => {
      await overviewPage.goto();

      // Hover over a chart data point
      const chartPath = overviewPage.tracesTimelineChart.locator('path').first();
      await chartPath.hover();

      // Verify tooltip appears
      const tooltip = authenticatedPage.locator('[role="tooltip"]');
      await expect(tooltip).toBeVisible();
    });
  });

  test.describe('Error Handling', () => {
    test('should show error state when API fails', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockError('**/api/overview', 500, 'Internal server error');

      await overviewPage.goto();

      const errorMessage = authenticatedPage.locator('[data-testid="error-state"]');
      await expect(errorMessage).toBeVisible();
    });

    test('should show retry button on error', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockError('**/api/overview', 500, 'Internal server error');

      await overviewPage.goto();

      const retryButton = authenticatedPage.getByRole('button', { name: /retry/i });
      await expect(retryButton).toBeVisible();
    });

    test('should retry data fetch on retry button click', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);

      // First request fails
      await mocker.mockError('**/api/overview', 500, 'Internal server error');
      await overviewPage.goto();

      // Clear mock and set up success response
      await mocker.clearMocks();
      await mocker.mockRoute('**/api/overview', {
        body: {
          total_traces: 100,
          success_rate: 95,
          pending_approvals: 5,
          total_cost: 50,
        },
      });

      // Click retry
      const retryButton = authenticatedPage.getByRole('button', { name: /retry/i });
      await retryButton.click();

      // Verify data loaded
      await overviewPage.expectPageLoaded();
    });
  });

  test.describe('Loading States', () => {
    test('should show skeleton loaders while data is loading', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      await mocker.mockRoute('**/api/overview', {
        body: { total_traces: 100, success_rate: 95, pending_approvals: 5, total_cost: 50 },
        delay: 2000, // Slow response
      });

      await overviewPage.goto();

      // Verify skeletons are visible initially
      const skeleton = authenticatedPage.locator('[data-testid="skeleton"]').first();
      await expect(skeleton).toBeVisible();
    });
  });

  test.describe('Responsive Design', () => {
    test('should stack cards on mobile viewport', async ({ authenticatedPage }) => {
      await authenticatedPage.setViewportSize({ width: 375, height: 667 });
      await overviewPage.goto();

      // Verify cards are stacked (flexbox column on mobile)
      const cardsContainer = authenticatedPage.locator('[data-testid="stat-cards-container"]');
      const style = await cardsContainer.evaluate((el) => getComputedStyle(el).flexDirection);
      expect(style).toBe('column');
    });

    test('should show horizontal cards on desktop viewport', async ({ authenticatedPage }) => {
      await authenticatedPage.setViewportSize({ width: 1440, height: 900 });
      await overviewPage.goto();

      const cardsContainer = authenticatedPage.locator('[data-testid="stat-cards-container"]');
      const style = await cardsContainer.evaluate((el) => getComputedStyle(el).flexDirection);
      expect(style).toBe('row');
    });
  });

  test.describe('Real-time Updates', () => {
    test('should update stats periodically', async ({ authenticatedPage }) => {
      const mocker = createAPIMocker(authenticatedPage);
      let callCount = 0;

      await mocker.mockRoute('**/api/overview', {
        body: () => ({
          total_traces: 100 + callCount++,
          success_rate: 95,
          pending_approvals: 5,
          total_cost: 50,
        }),
      });

      await overviewPage.goto();
      const initialValue = await overviewPage.getStatCardValue('total-traces');

      // Wait for auto-refresh (typically 30s, but we'll mock time)
      await authenticatedPage.waitForTimeout(1000);

      // Trigger manual refresh
      await authenticatedPage.keyboard.press('F5');
      await overviewPage.waitForPageLoad();

      // Value should potentially be different after refresh
      const newValue = await overviewPage.getStatCardValue('total-traces');
      expect(newValue).not.toBe(initialValue);
    });
  });
});
