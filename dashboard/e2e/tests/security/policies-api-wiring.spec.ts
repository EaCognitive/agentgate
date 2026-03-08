/**
 * Dashboard policy API wiring smoke coverage.
 *
 * Validates that dashboard BFF routes forward to backend policy endpoints with
 * correct status propagation and RBAC behavior.
 */

import { APIRequestContext, expect, request as playwrightRequest, test } from '@playwright/test';

const DEFAULT_DASHBOARD_BASE_URL = 'http://localhost:3000';
const DEFAULT_BACKEND_BASE_URL = 'http://localhost:8000';
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL || 'admin@agentgate.io';
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'AdminPassword123!';
const VIEWER_EMAIL = process.env.E2E_VIEWER_EMAIL || 'viewer@agentgate.io';
const VIEWER_PASSWORD = process.env.E2E_VIEWER_PASSWORD || 'ViewerPassword123!';

function normalizeBaseUrl(url: string): string {
  return url.trim().replace(/\/+$/, '').replace(/\/api$/, '');
}

function dashboardBaseUrl(baseURL: string | undefined): string {
  return normalizeBaseUrl(baseURL || process.env.BASE_URL || DEFAULT_DASHBOARD_BASE_URL);
}

function backendBaseUrl(): string {
  return normalizeBaseUrl(process.env.API_URL || DEFAULT_BACKEND_BASE_URL);
}

function makePolicyPayload(policySetId: string) {
  return {
    policy_json: {
      policy_set_id: policySetId,
      version: '1.0.0',
      description: 'Dashboard policy API wiring smoke test policy',
      default_effect: 'allow',
      rules: [
        {
          rule_id: 'deny-delete-file',
          effect: 'deny',
          description: 'Deny delete_file requests',
          priority: 100,
          conditions: [
            {
              field: 'request.tool',
              operator: 'eq',
              value: 'delete_file',
            },
          ],
        },
      ],
    },
    origin: 'manual',
    locked: false,
  };
}

function makeEvaluatePayload(policySetId: string) {
  return {
    policy_set_id: policySetId,
    request_context: {
      request: {
        tool: 'delete_file',
        inputs: {
          path: '/tmp/smoke.txt',
        },
      },
      actor: {
        role: 'developer',
      },
    },
  };
}

async function parseJsonSafe(response: {
  json: () => Promise<unknown>;
}): Promise<Record<string, unknown>> {
  try {
    const body = await response.json();
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      return body as Record<string, unknown>;
    }
    return {};
  } catch {
    return {};
  }
}

async function loginForToken(
  backendContext: APIRequestContext,
  email: string,
  password: string
): Promise<{ status: number; token?: string; body: Record<string, unknown> }> {
  const loginResponse = await backendContext.post('/api/auth/login', {
    data: { email, password },
  });
  const body = await parseJsonSafe(loginResponse);
  if (loginResponse.status() !== 200) {
    return { status: loginResponse.status(), body };
  }

  const token = body.access_token;
  if (typeof token !== 'string' || !token) {
    return { status: loginResponse.status(), body };
  }
  return { status: loginResponse.status(), token, body };
}

async function ensureAdminToken(
  dashboardContext: APIRequestContext,
  backendContext: APIRequestContext
): Promise<string> {
  const firstAttempt = await loginForToken(backendContext, ADMIN_EMAIL, ADMIN_PASSWORD);
  if (firstAttempt.status === 200 && firstAttempt.token) {
    return firstAttempt.token;
  }

  const setupStatus = await dashboardContext.get('/api/setup/status');
  expect(setupStatus.status()).toBe(200);
  const setupStatusBody = await parseJsonSafe(setupStatus);

  const setupRequired = setupStatusBody.setup_required === true;
  if (setupRequired) {
    const completeSetupResponse = await dashboardContext.post('/api/setup/complete', {
      data: {
        email: ADMIN_EMAIL,
        password: ADMIN_PASSWORD,
        name: 'E2E Admin',
        generate_api_key: false,
        api_key_name: 'e2e-policy-wiring',
      },
    });
    expect(completeSetupResponse.status()).toBe(200);
  }

  const secondAttempt = await loginForToken(backendContext, ADMIN_EMAIL, ADMIN_PASSWORD);
  if (secondAttempt.status !== 200 || !secondAttempt.token) {
    const detail = JSON.stringify(secondAttempt.body);
    throw new Error(
      `Unable to authenticate admin user. status=${secondAttempt.status} body=${detail}`
    );
  }
  return secondAttempt.token;
}

async function ensureViewerUser(
  backendContext: APIRequestContext,
  adminToken: string
): Promise<void> {
  const authHeaders = {
    Authorization: `Bearer ${adminToken}`,
  };
  const listResponse = await backendContext.get('/api/users?limit=500', {
    headers: authHeaders,
  });
  expect(listResponse.status()).toBe(200);
  const users = (await listResponse.json()) as Array<Record<string, unknown>>;
  const existing = users.find((entry) => entry.email === VIEWER_EMAIL);

  if (existing && typeof existing.id === 'number') {
    const updateResponse = await backendContext.patch(`/api/users/${existing.id}`, {
      headers: authHeaders,
      data: {
        name: 'E2E Viewer',
        role: 'viewer',
        is_active: true,
        password: VIEWER_PASSWORD,
      },
    });
    expect(updateResponse.status()).toBe(200);
    return;
  }

  const createResponse = await backendContext.post('/api/users', {
    headers: authHeaders,
    data: {
      email: VIEWER_EMAIL,
      password: VIEWER_PASSWORD,
      name: 'E2E Viewer',
      role: 'viewer',
    },
  });
  expect(createResponse.status()).toBe(200);
}

function withBearer(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
  };
}

async function newApiContext(
  baseURL: string,
  token?: string
): Promise<APIRequestContext> {
  return playwrightRequest.newContext({
    baseURL,
    extraHTTPHeaders: token ? withBearer(token) : undefined,
  });
}

test.describe('Policy API wiring', () => {
  test('returns 401 without authentication', async ({ baseURL }) => {
    const dashboardContext = await newApiContext(dashboardBaseUrl(baseURL));
    try {
      const response = await dashboardContext.get('/api/policies');
      expect(response.status()).toBe(401);
    } finally {
      await dashboardContext.dispose();
    }
  });

  test('admin CRUD + utility endpoints are wired', async ({ baseURL }) => {
    const backendContext = await newApiContext(backendBaseUrl());
    const dashboardContext = await newApiContext(dashboardBaseUrl(baseURL));
    const trackedPolicyIds: string[] = [];

    try {
      const adminToken = await ensureAdminToken(dashboardContext, backendContext);
      const adminHeaders = withBearer(adminToken);

      const listResponse = await dashboardContext.get('/api/policies', {
        headers: adminHeaders,
      });
      expect(listResponse.status()).toBe(200);
      const listBody = await listResponse.json();
      expect(Array.isArray(listBody.loaded_policies)).toBeTruthy();
      expect(Array.isArray(listBody.db_policies)).toBeTruthy();

      const policySetId = `dashboard-wiring-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
      const createResponse = await dashboardContext.post('/api/policies', {
        headers: adminHeaders,
        data: makePolicyPayload(policySetId),
      });
      expect(createResponse.status()).toBe(201);
      const createdPolicy = await createResponse.json();
      expect(createdPolicy.policy_set_id).toBe(policySetId);
      expect(typeof createdPolicy.db_id).toBe('number');
      trackedPolicyIds.push(policySetId);

      const evaluateResponse = await dashboardContext.post('/api/policies/evaluate', {
        headers: adminHeaders,
        data: makeEvaluatePayload(policySetId),
      });
      expect(evaluateResponse.status()).toBe(200);
      const evaluated = await evaluateResponse.json();
      expect(typeof evaluated.allowed).toBe('boolean');
      expect(Array.isArray(evaluated.matched_rules)).toBeTruthy();
      expect(evaluated.policy_set_id).toBe(policySetId);

      const loadResponse = await dashboardContext.post(
        `/api/policies/${createdPolicy.db_id}/load`,
        { headers: adminHeaders }
      );
      expect(loadResponse.status()).toBe(200);
      const loaded = await loadResponse.json();
      expect(loaded.policy_set_id).toBe(policySetId);

      const lockResponse = await dashboardContext.patch(`/api/policies/${policySetId}`, {
        headers: adminHeaders,
        data: { locked: true },
      });
      expect(lockResponse.status()).toBe(200);
      const locked = await lockResponse.json();
      expect(locked.locked).toBe(true);

      const deleteLockedResponse = await dashboardContext.delete(
        `/api/policies/${policySetId}`,
        { headers: adminHeaders }
      );
      expect(deleteLockedResponse.status()).toBe(403);
      const deleteLockedBody = await deleteLockedResponse.json();
      expect(String(deleteLockedBody.detail || deleteLockedBody.error || '')).toContain('locked');

      const unlockResponse = await dashboardContext.patch(`/api/policies/${policySetId}`, {
        headers: adminHeaders,
        data: { locked: false },
      });
      expect(unlockResponse.status()).toBe(200);
      const unlocked = await unlockResponse.json();
      expect(unlocked.locked).toBe(false);

      const deleteResponse = await dashboardContext.delete(`/api/policies/${policySetId}`, {
        headers: adminHeaders,
      });
      expect(deleteResponse.status()).toBe(204);
      trackedPolicyIds.length = 0;
    } finally {
      for (const policySetId of trackedPolicyIds) {
        try {
          const adminToken = await ensureAdminToken(dashboardContext, backendContext);
          const adminHeaders = withBearer(adminToken);
          await dashboardContext.patch(`/api/policies/${policySetId}`, {
            headers: adminHeaders,
            data: { locked: false },
          });
          await dashboardContext.delete(`/api/policies/${policySetId}`, {
            headers: adminHeaders,
          });
        } catch {
          // Best-effort cleanup; no additional action required.
        }
      }
      await dashboardContext.dispose();
      await backendContext.dispose();
    }
  });

  test('non-admin mutating policy endpoints are forbidden', async ({ baseURL }) => {
    const backendContext = await newApiContext(backendBaseUrl());
    const dashboardContext = await newApiContext(dashboardBaseUrl(baseURL));

    const policySetId = `dashboard-rbac-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
    const createdPolicyIds: string[] = [];
    let createdPolicyDbId: number | null = null;

    try {
      const adminToken = await ensureAdminToken(dashboardContext, backendContext);
      await ensureViewerUser(backendContext, adminToken);

      const viewerLogin = await loginForToken(backendContext, VIEWER_EMAIL, VIEWER_PASSWORD);
      expect(viewerLogin.status).toBe(200);
      if (!viewerLogin.token) {
        throw new Error('Viewer authentication did not return an access token');
      }

      const adminHeaders = withBearer(adminToken);
      const viewerHeaders = withBearer(viewerLogin.token);

      const createResponse = await dashboardContext.post('/api/policies', {
        headers: adminHeaders,
        data: makePolicyPayload(policySetId),
      });
      expect(createResponse.status()).toBe(201);
      const createdPolicy = await createResponse.json();
      createdPolicyDbId = Number(createdPolicy.db_id);
      createdPolicyIds.push(policySetId);

      const viewerCreateResponse = await dashboardContext.post('/api/policies', {
        headers: viewerHeaders,
        data: makePolicyPayload(`${policySetId}-viewer-attempt`),
      });
      expect(viewerCreateResponse.status()).toBe(403);

      const viewerPatchResponse = await dashboardContext.patch(`/api/policies/${policySetId}`, {
        headers: viewerHeaders,
        data: { locked: true },
      });
      expect(viewerPatchResponse.status()).toBe(403);

      const viewerDeleteResponse = await dashboardContext.delete(`/api/policies/${policySetId}`, {
        headers: viewerHeaders,
      });
      expect(viewerDeleteResponse.status()).toBe(403);

      const viewerLoadResponse = await dashboardContext.post(
        `/api/policies/${createdPolicyDbId}/load`,
        { headers: viewerHeaders }
      );
      expect(viewerLoadResponse.status()).toBe(403);
    } finally {
      for (const trackedPolicyId of createdPolicyIds) {
        try {
          const adminToken = await ensureAdminToken(dashboardContext, backendContext);
          const adminHeaders = withBearer(adminToken);
          await dashboardContext.patch(`/api/policies/${trackedPolicyId}`, {
            headers: adminHeaders,
            data: { locked: false },
          });
          await dashboardContext.delete(`/api/policies/${trackedPolicyId}`, {
            headers: adminHeaders,
          });
        } catch {
          // Best-effort cleanup; no additional action required.
        }
      }
      await dashboardContext.dispose();
      await backendContext.dispose();
    }
  });
});
