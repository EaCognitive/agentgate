# AgentGate Dashboard Production Readiness Plan

**Version:** 1.0.0
**Date:** January 28, 2026
**Author:** Erick | Founding Principal AI Architect
**Standard:** Enterprise Engineering Protocols (2026 Platinum)

---

## Executive Summary

This document outlines the comprehensive plan to bring the AgentGate Dashboard to production readiness with full test automation. The plan addresses gaps identified in the audit while leveraging TailAdmin React components for a polished, enterprise-grade UI.

---

## Current State Analysis

### Working Pages (7)
| Page | Status | Components |
|------|--------|------------|
| Overview | ✅ Complete | Stat cards, area chart, pie chart, recent traces |
| Traces | ✅ Complete | Filtering, expandable rows, pagination |
| Datasets | ✅ Complete | CRUD, test cases, export pytest, stats |
| Approvals | ✅ Complete | Pending/history tabs, approve/deny flow |
| Costs | ✅ Complete | Summary cards, budget tracking, timeline chart |
| Audit | ✅ Complete | Search, filters, CSV/JSON export, pagination |
| PII Vault | ⚠️ Partial | Stats/audit/sessions read-only, export & rotate are stubs |

### Backend Capabilities Not Exposed in Dashboard
| Feature | Server Support | Dashboard Status | Priority |
|---------|----------------|------------------|----------|
| 2FA/MFA Management | ✅ Full | ❌ Missing | **HIGH** |
| WebAuthn Passkeys | ✅ Full | ❌ Missing | **HIGH** |
| Session Management | ✅ Full | ❌ Missing | **HIGH** |
| PII Key Rotation | ✅ Full | ⚠️ Stub only | **HIGH** |
| PII Detection Tools | ✅ Full | ❌ Missing | **HIGH** |
| Threat Detection | ✅ Full | ❌ Missing | **HIGH** |
| Test Execution | ✅ Full | ❌ Missing | **MEDIUM** |
| Cost by Agent | ✅ Full | ❌ Missing | **MEDIUM** |
| RBAC Enforcement | ✅ Full | ❌ Missing | **MEDIUM** |
| Social Login | ⚠️ Partial | ⚠️ Non-functional | **LOW** |

---

## Implementation Phases

### Phase 1: Testing Infrastructure (Days 1-2)

#### 1.1 Install E2E Testing Framework
```bash
# Playwright for E2E testing (recommended for enterprise)
cd dashboard
npm install -D @playwright/test playwright
npx playwright install
```

#### 1.2 Test Configuration Structure
```
dashboard/
├── e2e/
│   ├── playwright.config.ts
│   ├── fixtures/
│   │   ├── auth.fixture.ts        # Authentication fixtures
│   │   ├── api-mock.fixture.ts    # API mocking utilities
│   │   └── test-data.fixture.ts   # Test data generators
│   ├── pages/                     # Page Object Models
│   │   ├── login.page.ts
│   │   ├── overview.page.ts
│   │   ├── traces.page.ts
│   │   ├── datasets.page.ts
│   │   ├── approvals.page.ts
│   │   ├── costs.page.ts
│   │   ├── audit.page.ts
│   │   ├── pii-vault.page.ts
│   │   ├── security-settings.page.ts
│   │   └── threat-detection.page.ts
│   └── tests/
│       ├── auth/
│       │   ├── login.spec.ts
│       │   ├── mfa.spec.ts
│       │   └── webauthn.spec.ts
│       ├── dashboard/
│       │   ├── overview.spec.ts
│       │   ├── traces.spec.ts
│       │   └── ...
│       └── security/
│           ├── rbac.spec.ts
│           └── threat-detection.spec.ts
├── src/
│   └── __tests__/                 # Unit tests (existing)
└── vitest.config.ts               # Unit test config
```

#### 1.3 Playwright Configuration
```typescript
// e2e/playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 30000,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['html', { open: 'never' }],
    ['json', { outputFile: 'test-results/results.json' }],
    ['junit', { outputFile: 'test-results/junit.xml' }],
  ],
  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:3000',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
  webServer: {
    command: 'npm run dev',
    port: 3000,
    reuseExistingServer: !process.env.CI,
  },
});
```

---

### Phase 2: Security Settings Page (Days 3-5)

#### 2.1 New Page: `/security/settings`

**Features:**
- Two-Factor Authentication (TOTP)
  - Enable/disable 2FA
  - QR code display for authenticator apps
  - Backup codes generation and download
- WebAuthn Passkeys
  - Register new passkey
  - List registered passkeys
  - Revoke passkeys
- Active Sessions
  - View all active sessions (device, IP, last active)
  - Terminate individual sessions
  - Terminate all other sessions
- Account Security
  - Password change
  - Security activity log

#### 2.2 TailAdmin Components to Use
- **React Two-Step Verification** - 2FA setup flow
- **React Form Elements** - Input fields, toggles
- **React Cards Components** - Section containers
- **React Modals Components** - Confirmation dialogs
- **React Alerts Components** - Success/error notifications
- **React Data Tables** - Sessions list
- **React Buttons Components** - Actions

#### 2.3 API Endpoints to Connect
```typescript
// Security Settings API
POST   /api/auth/enable-2fa                 // Enable 2FA, returns QR code
POST   /api/auth/verify-2fa                 // Verify TOTP setup
POST   /api/auth/disable-2fa                // Disable 2FA
POST   /api/auth/regenerate-backup-codes    // Generate backup codes
POST   /api/auth/passkey/register-start     // Start passkey registration
POST   /api/auth/passkey/register-finish    // Complete passkey registration
GET    /api/auth/passkey/list               // List registered passkeys
DELETE /api/auth/passkey/{credential_id}    // Revoke passkey
GET    /api/auth/sessions          // List active sessions
DELETE /api/auth/sessions/{session_id} // Terminate session
DELETE /api/auth/sessions          // Terminate all other sessions
```

#### 2.4 Component Structure
```
src/app/(dashboard)/security/
├── page.tsx                       # Main security settings page
├── components/
│   ├── TwoFactorSection.tsx       # 2FA management
│   ├── QRCodeDisplay.tsx          # QR code for authenticator
│   ├── BackupCodesModal.tsx       # Backup codes display
│   ├── WebAuthnSection.tsx        # Passkey management
│   ├── PasskeyCard.tsx            # Individual passkey display
│   ├── RegisterPasskeyModal.tsx   # Passkey registration flow
│   ├── SessionsSection.tsx        # Active sessions management
│   ├── SessionRow.tsx             # Session list item
│   └── SecurityActivityLog.tsx    # Recent security events
```

---

### Phase 3: Complete PII Vault Operations (Days 6-7)

#### 3.1 Features to Implement
- **Key Management**
  - View encryption key metadata (not actual keys)
  - Rotate encryption keys
  - Key rotation history
- **PII Permissions**
  - Grant/revoke access to PII data
  - Permission audit trail
- **PII Detection Tools**
  - Test text for PII detection
  - View detected entity types
  - Redaction preview

#### 3.2 TailAdmin Components
- **React Form Layout** - Detection tool input
- **React Progressbar Components** - Key rotation progress
- **React Tabs Components** - Section organization
- **React Badge Components** - Entity type labels
- **React Notifications Components** - Operation feedback

#### 3.3 API Endpoints
```typescript
// PII Vault Write Operations
POST   /api/pii/keys/rotate           // Rotate encryption key
GET    /api/pii/keys                  // Key metadata/history
POST   /api/pii/permissions           // Grant PII access
DELETE /api/pii/permissions/{permission_id} // Revoke PII access
POST   /api/pii/detect                // Detect PII in text
POST   /api/pii/redact                // Redact PII from text
GET    /api/pii/audit/export          // Export PII audit data
```

---

### Phase 4: Threat Detection Dashboard (Days 8-9)

#### 4.1 New Page: `/security/threats`

**Features:**
- Real-time threat alerts dashboard
- Threat event timeline
- Threat type breakdown (pie chart)
- Alert severity levels (Critical, High, Medium, Low)
- Alert details modal
- Acknowledge/resolve workflow
- Threat statistics cards

#### 4.2 TailAdmin Components
- **React Line Charts** - Threat timeline
- **React Pie Charts** - Threat type distribution
- **React Alerts Components** - Threat alert cards
- **React Badge Components** - Severity indicators
- **React Data Tables** - Event list
- **React Modals Components** - Alert details
- **React Pagination Components** - Event pagination

#### 4.3 API Endpoints
```typescript
// Threat Detection API
GET    /api/audit                      // Security-relevant audit events
GET    /api/audit/stats                // Aggregated event statistics
GET    /api/pii/audit                  // PII access and restore audit stream
```

#### 4.4 Component Structure
```
src/app/(dashboard)/security/threats/
├── page.tsx                       # Main threat detection page
├── components/
│   ├── ThreatStatsCards.tsx       # Summary statistics
│   ├── ThreatTimeline.tsx         # Line chart of threats over time
│   ├── ThreatTypeBreakdown.tsx    # Pie chart by threat type
│   ├── ThreatAlertsList.tsx       # List of recent threats
│   ├── ThreatAlertCard.tsx        # Individual threat alert
│   ├── ThreatDetailsModal.tsx     # Detailed threat view
│   ├── SeverityBadge.tsx          # Severity indicator
│   └── ThreatFilters.tsx          # Filter controls
```

---

### Phase 5: Test Execution Feature (Days 10-11)

#### 5.1 Enhance Datasets Page

**New Features:**
- Run test cases button
- Test run history
- Test results viewer
- Pass/fail statistics
- Assertion details
- Re-run failed tests

#### 5.2 TailAdmin Components
- **React Progressbar Components** - Test execution progress
- **React Badge Components** - Test status (pass/fail/running)
- **React Spinners Components** - Loading states
- **React Data Tables** - Test results
- **React Tabs Components** - Test history vs results

#### 5.3 API Endpoints
```typescript
// Test Execution API
POST   /api/datasets/{dataset_id}/runs                 // Start test run
GET    /api/datasets/{dataset_id}/runs                 // List test runs
GET    /api/datasets/{dataset_id}/runs/{run_id}        // Get test run details
GET    /api/datasets/{dataset_id}/runs/{run_id}/results // Get test results
```

#### 5.4 Component Structure
```
src/app/(dashboard)/datasets/[id]/
├── page.tsx                       # Dataset detail page
├── components/
│   ├── TestCasesList.tsx          # List of test cases
│   ├── RunTestsButton.tsx         # Execute tests action
│   ├── TestRunProgress.tsx        # Execution progress
│   ├── TestRunHistory.tsx         # Historical runs
│   ├── TestResultsView.tsx        # Results display
│   ├── AssertionDetails.tsx       # Assertion breakdown
│   └── TestStatusBadge.tsx        # Pass/fail indicator
```

---

### Phase 6: Cost by Agent Analytics (Day 12)

#### 6.1 Enhance Costs Page

**New Features:**
- Per-agent cost breakdown
- Agent cost trends chart
- Top spending agents table
- Agent cost comparison

#### 6.2 TailAdmin Components
- **React Bar Charts** - Agent cost comparison
- **React Line Charts** - Agent cost trends
- **React Data Tables** - Agent cost details
- **React Dropdowns Components** - Agent selector

#### 6.3 API Endpoint
```typescript
GET /api/overview        // Runtime summary metrics
GET /api/audit/stats     // Aggregated event stats for dashboard charts
```

---

### Phase 7: Frontend RBAC Enforcement (Days 13-14)

#### 7.1 Permission System Implementation

**Role Definitions:**
```typescript
enum UserRole {
  Admin = 'admin',       // Full access
  Approver = 'approver', // Approvals + read access
  Auditor = 'auditor',   // Audit + read access
  Developer = 'developer', // Traces + Datasets + read access
  Viewer = 'viewer'      // Read-only access
}

const ROLE_PERMISSIONS = {
  admin: ['*'],
  approver: ['approvals:*', 'read:*'],
  auditor: ['audit:*', 'read:*'],
  developer: ['traces:*', 'datasets:*', 'read:*'],
  viewer: ['read:*'],
};
```

#### 7.2 Components to Create
```typescript
// Permission guard component
<RequirePermission permission="approvals:write">
  <ApproveButton />
</RequirePermission>

// Navigation filtering
<ProtectedNavItem permission="security:read" href="/security/settings">
  Security Settings
</ProtectedNavItem>

// Conditional rendering hook
const canApprove = usePermission('approvals:write');
```

#### 7.3 Implementation Files
```
src/lib/
├── permissions.ts             # Permission definitions
├── hooks/
│   ├── usePermission.ts       # Permission check hook
│   └── useRole.ts             # Role access hook
src/components/
├── auth/
│   ├── RequirePermission.tsx  # Permission guard
│   ├── ProtectedNavItem.tsx   # Nav item with permission check
│   └── RoleGate.tsx           # Role-based visibility
```

---

### Phase 8: UI Polish with TailAdmin (Days 15-16)

#### 8.1 Component Upgrades

| Current Component | TailAdmin Upgrade |
|-------------------|-------------------|
| Basic tables | React Data Tables with sorting, filtering |
| Simple buttons | React Buttons Components with variants |
| Plain modals | React Modals Components with animations |
| Basic forms | React Form Elements with validation states |
| Static alerts | React Notifications Components with auto-dismiss |
| Simple dropdowns | React Dropdowns Components with search |
| Basic pagination | React Pagination Components |
| Plain cards | React Cards Components with hover effects |

#### 8.2 Dashboard Enhancements
- Add React Carousel for overview metrics
- Implement React Tooltips on all action buttons
- Add React Popovers for detailed info displays
- Use React Ribbons for status indicators
- Implement React Spinners for all loading states
- Add React Breadcrumbs for navigation context

---

### Phase 9: E2E Test Suite (Days 17-19)

#### 9.1 Test Coverage Matrix

| Page | Test Cases | Priority |
|------|------------|----------|
| Login | Valid/invalid login, remember me, social login | HIGH |
| 2FA | Setup flow, verify code, backup codes | HIGH |
| WebAuthn | Register passkey, authenticate, revoke | HIGH |
| Overview | Stats display, chart rendering, navigation | MEDIUM |
| Traces | Filtering, pagination, detail view | MEDIUM |
| Approvals | Pending list, approve/deny flow | HIGH |
| Datasets | CRUD operations, test execution | MEDIUM |
| Costs | Data display, agent breakdown | LOW |
| Audit | Search, filters, export | MEDIUM |
| PII Vault | Stats, detection, key rotation | HIGH |
| Threats | Alert display, acknowledge, resolve | HIGH |
| RBAC | Permission enforcement per role | HIGH |

#### 9.2 Test File Structure
```
e2e/tests/
├── auth/
│   ├── login.spec.ts
│   ├── logout.spec.ts
│   ├── mfa-setup.spec.ts
│   ├── mfa-login.spec.ts
│   ├── webauthn-registration.spec.ts
│   └── webauthn-login.spec.ts
├── dashboard/
│   ├── overview.spec.ts
│   ├── traces.spec.ts
│   ├── approvals.spec.ts
│   ├── datasets.spec.ts
│   ├── test-execution.spec.ts
│   ├── costs.spec.ts
│   ├── costs-by-agent.spec.ts
│   ├── audit.spec.ts
│   └── audit-export.spec.ts
├── security/
│   ├── security-settings.spec.ts
│   ├── pii-vault.spec.ts
│   ├── pii-detection.spec.ts
│   ├── key-rotation.spec.ts
│   ├── threat-detection.spec.ts
│   └── threat-workflow.spec.ts
├── rbac/
│   ├── admin-access.spec.ts
│   ├── approver-access.spec.ts
│   ├── auditor-access.spec.ts
│   ├── developer-access.spec.ts
│   └── viewer-access.spec.ts
└── accessibility/
    ├── keyboard-navigation.spec.ts
    └── screen-reader.spec.ts
```

---

### Phase 10: Documentation & Verification (Day 20)

#### 10.1 Documentation Updates
- Update README with new features
- API documentation for new endpoints
- Component storybook entries
- Test coverage report

#### 10.2 Enterprise Compliance Checklist

##### Code Quality
- [ ] All function signatures include TypeScript types
- [ ] No `any` types without explicit justification
- [ ] ESLint passes with zero errors
- [ ] Prettier formatting applied
- [ ] Test coverage > 80% for business logic

##### Security
- [ ] RBAC enforced on all protected routes
- [ ] CSRF protection on all forms
- [ ] XSS prevention (sanitized inputs)
- [ ] Secure headers configured
- [ ] No sensitive data in localStorage

##### Observability
- [ ] Error boundary components
- [ ] Sentry integration for error tracking
- [ ] Console logging in development only
- [ ] Performance metrics collection

##### Accessibility
- [ ] ARIA labels on interactive elements
- [ ] Keyboard navigation support
- [ ] Color contrast compliance
- [ ] Screen reader compatibility

##### Resilience
- [ ] Loading states for all async operations
- [ ] Error states with retry options
- [ ] Offline detection and handling
- [ ] Graceful degradation for failed API calls

---

## Implementation Timeline

```
Week 1: Foundation
├── Day 1-2:  Testing Infrastructure (Playwright setup)
├── Day 3-5:  Security Settings Page (2FA, WebAuthn, Sessions)

Week 2: Security & Testing Features
├── Day 6-7:  PII Vault Operations (Key rotation, detection)
├── Day 8-9:  Threat Detection Dashboard
├── Day 10-11: Test Execution Feature

Week 3: Analytics & Polish
├── Day 12:   Cost by Agent Analytics
├── Day 13-14: Frontend RBAC Enforcement
├── Day 15-16: UI Polish with TailAdmin

Week 4: Testing & Documentation
├── Day 17-19: E2E Test Suite
├── Day 20:    Documentation & Verification
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| E2E Test Coverage | > 80% of user flows |
| Page Load Time | < 2s for all pages |
| Lighthouse Performance | > 90 |
| Accessibility Score | > 95 |
| Security Audit | Zero critical/high findings |
| Backend Feature Parity | 100% of server features exposed |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| WebAuthn browser compatibility | Feature detection + fallback to TOTP |
| Complex RBAC edge cases | Comprehensive test suite + deny by default |
| Performance with large datasets | Virtual scrolling + pagination |
| API breaking changes | API versioning + contract tests |

---

## Next Steps

1. **Immediate**: Set up Playwright E2E testing framework
2. **This Week**: Implement Security Settings page (highest priority gap)
3. **Ongoing**: Add E2E tests for each new feature as implemented

---

**Authored By:** Erick | Founding Principal AI Architect
**Standard:** Enterprise Engineering Protocols (2026 Platinum)
