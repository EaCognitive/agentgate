/**
 * API Mock Fixtures for E2E Tests
 * Provides utilities for mocking API responses in tests
 *
 * @author Erick | Founding Principal AI Architect
 */

import { Page, Route } from '@playwright/test';

export interface MockResponse {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
  delay?: number;
  method?: string;
}

export interface APIMocker {
  mockRoute: (pattern: string | RegExp, response: MockResponse) => Promise<void>;
  mockError: (pattern: string | RegExp, status: number, message: string) => Promise<void>;
  mockNetworkError: (pattern: string | RegExp) => Promise<void>;
  clearMocks: () => Promise<void>;
}

export function createAPIMocker(page: Page): APIMocker {
  const mockedRoutes: Array<{ pattern: string | RegExp; handler: (route: Route) => void }> = [];

  return {
    async mockRoute(pattern: string | RegExp, response: MockResponse) {
      const handler = async (route: Route) => {
        if (response.method && route.request().method() !== response.method) {
          await route.fallback();
          return;
        }

        if (response.delay) {
          await new Promise((resolve) => setTimeout(resolve, response.delay));
        }

        await route.fulfill({
          status: response.status || 200,
          contentType: 'application/json',
          headers: response.headers || {},
          body: JSON.stringify(response.body || {}),
        });
      };

      await page.route(pattern, handler);
      mockedRoutes.push({ pattern, handler });
    },

    async mockError(pattern: string | RegExp, status: number, message: string) {
      const handler = async (route: Route) => {
        await route.fulfill({
          status,
          contentType: 'application/json',
          body: JSON.stringify({ error: message, detail: message }),
        });
      };

      await page.route(pattern, handler);
      mockedRoutes.push({ pattern, handler });
    },

    async mockNetworkError(pattern: string | RegExp) {
      const handler = async (route: Route) => {
        await route.abort('failed');
      };

      await page.route(pattern, handler);
      mockedRoutes.push({ pattern, handler });
    },

    async clearMocks() {
      for (const { pattern } of mockedRoutes) {
        await page.unroute(pattern);
      }
      mockedRoutes.length = 0;
    },
  };
}

// Common mock data factories
export const mockFactories = {
  trace: (overrides = {}) => ({
    id: `trace-${Date.now()}`,
    agent_id: 'agent-001',
    tool_name: 'web_search',
    status: 'success',
    input: { query: 'test query' },
    output: { results: [] },
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    duration_ms: 150,
    cost: 0.001,
    ...overrides,
  }),

  approval: (overrides = {}) => ({
    id: `approval-${Date.now()}`,
    trace_id: `trace-${Date.now()}`,
    agent_id: 'agent-001',
    tool_name: 'file_write',
    input: { path: '/tmp/test.txt', content: 'test' },
    status: 'pending',
    requested_at: new Date().toISOString(),
    ...overrides,
  }),

  dataset: (overrides = {}) => ({
    id: `dataset-${Date.now()}`,
    name: 'Test Dataset',
    description: 'A test dataset',
    test_count: 5,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  }),

  testCase: (overrides = {}) => ({
    id: `test-${Date.now()}`,
    name: 'Test Case',
    input: { query: 'test' },
    expected_output: { response: 'expected' },
    assertion_type: 'equals',
    status: 'pending',
    ...overrides,
  }),

  auditEntry: (overrides = {}) => ({
    id: `audit-${Date.now()}`,
    event_type: 'auth.login',
    actor_id: 'user-001',
    actor_email: 'user@example.com',
    resource_type: 'session',
    resource_id: 'session-001',
    action: 'create',
    outcome: 'success',
    ip_address: '127.0.0.1',
    timestamp: new Date().toISOString(),
    ...overrides,
  }),

  threat: (overrides = {}) => ({
    id: `threat-${Date.now()}`,
    event_type: 'brute_force_attempt',
    severity: 'high',
    source_ip: '192.168.1.100',
    target: '/api/auth/login',
    description: 'Multiple failed login attempts detected',
    status: 'pending',
    detected_at: new Date().toISOString(),
    ...overrides,
  }),

  costSummary: (overrides = {}) => ({
    total_cost: 125.50,
    total_requests: 5000,
    period_start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    period_end: new Date().toISOString(),
    budget: 500,
    budget_remaining: 374.50,
    budget_utilization: 0.251,
    ...overrides,
  }),

  piiStats: (overrides = {}) => ({
    total_entries: 1500,
    active_sessions: 25,
    entities_detected: 3200,
    entities_redacted: 3150,
    last_key_rotation: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    compliance_status: 'compliant',
    ...overrides,
  }),

  session: (overrides = {}) => ({
    id: `session-${Date.now()}`,
    user_id: 'user-001',
    device: 'Chrome on macOS',
    ip_address: '192.168.1.50',
    location: 'San Francisco, CA',
    created_at: new Date().toISOString(),
    last_active: new Date().toISOString(),
    is_current: false,
    ...overrides,
  }),
};
