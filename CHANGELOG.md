# Changelog

All notable changes to AgentGate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-02-05

### Added

- **Core Security Gateway**: Enterprise-grade middleware for AI agent tool execution
- **Authentication System**: JWT tokens, TOTP MFA, WebAuthn/Passkeys support
- **Role-Based Access Control**: Admin, Approver, Auditor, Developer, Viewer roles
- **Approval Workflows**: Human-in-the-loop controls for sensitive operations
- **PII Protection**: Presidio-based detection with AES-256-GCM encrypted vault
- **Audit Logging**: Immutable trails with HMAC-SHA256 chain verification
- **Compliance Features**: HIPAA, SOC 2, and GDPR compliance controls
- **Threat Detection**: Real-time detection of SQLi, XSS, path traversal attacks
- **Rate Limiting**: Configurable per-endpoint limits with Redis or in-memory storage
- **Observability**: Prometheus metrics, structured logging, OpenTelemetry support
- **Cost Tracking**: Per-agent and per-tool cost analytics
- **CLI**: `ea-agentgate serve` command for easy server startup
- **Dashboard API**: Full REST API for dashboard integration

### Security

- Vendored Scalar API docs with nonce-based CSP (eliminates CDN supply-chain risk)
- Production database validation (fails fast if SQLite used in production)
- Strict Content-Security-Policy headers without unsafe-inline/unsafe-eval
- Test routes (`/api/test/*`) excluded from production builds

### Changed

- Base `pip install ea-agentgate` now includes minimal runtime dependencies for CLI
- Full server features available via `pip install ea-agentgate[server]`

## [Unreleased]

### Added

- **Async Audit Event Pipeline**: Optional Redis Streams backend for audit
  event processing (`AUDIT_PIPELINE=redis_stream`). Decouples audit persistence
  from request latency via microsecond `XADD` publishes and batched background
  DB writes. Includes dead-letter queue, pending message recovery, and
  fail-open design. Default behavior (`sync`) is unchanged.
- `server/audit/` package: `EventBus` protocol, `SyncEventBus`,
  `RedisStreamEventBus`, `StreamConsumer`, and `emit_audit_event()` helper
- 21 new tests for the audit pipeline and consumer (fakeredis-based)

### Changed

- All 28 audit `session.add(AuditEntry(...))` callsites across 10 router files
  migrated to `await emit_audit_event(session, ...)` for bus-agnostic dispatch
- Migrated production secret management from Google Cloud Secret Manager to
  Azure Key Vault with `DefaultAzureCredential` authentication

### Planned

- GraphQL API support
- Additional LLM provider integrations
- Enhanced multi-region support
- Kubernetes Helm charts

---

**Erick Aleman | AI Architect | AI Engineer | erick@eacognitive.com**
