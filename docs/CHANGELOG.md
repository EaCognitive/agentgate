# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Google Cloud Secret Manager support for production secrets with fail-closed startup.
- NLP warmup hook to preload spaCy/Presidio models during server lifespan.
- Lua-based Redis rate limiting for atomic increments (sync + async backends).

### Changed
- Documented semantic cache scalability caveat; recommend Redis Vector Search/RediSearch for large caches.
- Logging setup now preserves pytest handlers during tests while keeping handler count consistent.

## [1.0.0] - 2026-03-07

### Added
- Public PyPI distribution under the collision-free namespace `ea-agentgate`.
- Formal verification helpers, evidence-path validation, and live SDK coverage for
  admissibility, certificate verification, and PII restore flows.
- Production-ready public docs surface with a simplified guide layout and native
  Scalar API reference integration.

### Changed
- Renamed the published package, import surface, and CLI to `ea-agentgate`,
  `ea_agentgate`, and `ea-agentgate` to avoid conflicts with the existing
  `agentgate` project on PyPI.
- Aligned README, docs, package metadata, and public links to the
  `github.com/eacognitive/agentgate` and `www.eacognitive.com` branding surface.
- Tightened release gates across typing, docs governance, packaging, security
  scans, and repo-wide lint validation.

### Fixed
- Resolved production typecheck blockers, docs drift, and stale docs claims that
  were failing the release matrix.
- Fixed live deployment issues across API reference rendering, dashboard docs
  navigation, runtime auth validation, and dropdown layering.
- Stabilized test infrastructure and teardown behavior for router, audit, PII,
  WebAuthn, and formal verification suites.

## [0.4.0] - 2025-01-27

### Added
- **PII Vault**: Bi-directional anonymization for protecting sensitive data
  - Automatic PII detection (PERSON, EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS, DOB)
  - Placeholder generation and rehydration
  - `MemoryPIIVaultBackend` for local development
  - `RedisPIIVaultBackend` for distributed deployments
  - `CompliantPIIVaultBackend` with SOC 2 / HIPAA compliance
    - AES-256-GCM encryption at rest
    - HMAC-SHA256 integrity verification
    - Role-based access control (RBAC)
    - Tamper-evident audit logging
    - Secure deletion with memory overwrite
  - Dashboard integration for compliance monitoring

- **Save to Dataset**: One-click evaluation testing
  - `DatasetRecorder` middleware for automatic trace capture
  - Dataset and TestCase management API
  - Trace-to-TestCase conversion
  - Pytest code generation and export
  - Test run tracking with pass/fail statistics
  - Dashboard UI for dataset management

- **Model Routing & Fallbacks**: Universal LLM client
  - `UniversalClient` with multi-provider support
  - `ProviderRegistry` for provider configuration
  - `HealthTracker` with circuit breaker pattern
  - Routing strategies: Fallback, RoundRobin, CostOptimized, LatencyOptimized, Random
  - `AgentGate.Client()` factory for quick setup
  - `GoogleProvider` for Gemini 3 models

### Changed
- Updated model references: gpt-5.2, opus-4.5, gemini-3-pro/gemini-3-flash
- Improved README with engineering-focused documentation
- Enhanced test data seeding for all features

## [0.3.0] - 2025-01-26

### Added
- Full async/await support across the entire stack
  - `agent.acall()` for async tool execution
  - `agent.atransaction()` for async transactions
  - `MiddlewareChain.aexecute()` for async middleware
  - Native async `abefore()` and `aafter()` middleware hooks
- Async Redis backends for distributed rate limiting and caching
  - `AsyncRedisRateLimitBackend` with pipeline operations
  - `AsyncRedisCacheBackend` with batched MGET (fixes N+1 queries)
  - `AsyncRedisCostBackend` for cost tracking
- Async LLM providers
  - `AsyncOpenAIProvider` for non-blocking API calls
  - `AsyncAnthropicProvider` with embedding provider delegation
- Async-aware middleware
  - `is_async_native()` method for middleware introspection
  - `RateLimiter` with `async_backend` support
  - `SemanticCache` with `async_provider` and `async_backend` support
  - `SemanticValidator` with `async_provider` support
- Comprehensive async test suite (29 new tests)
- `aiofiles` optional dependency for async file I/O

### Changed
- Default middleware async hooks now use `asyncio.to_thread()` for non-blocking fallback
- Improved documentation with async usage examples

## [0.2.0] - 2025-01-26

### Added
- Human-in-the-loop approval middleware
- Cost tracking middleware with budget limits
- Rate limiting middleware with configurable scopes
- Audit logging middleware with redaction support
- Transaction support with automatic rollback (saga pattern)
- OpenAI SDK integration
- Anthropic SDK integration
- Comprehensive validation middleware with path safety

### Changed
- Restructured to middleware-based architecture
- Improved trace lifecycle with more status states

## [0.1.0] - 2025-01-15

### Added
- Initial release
- Core Agent class with tool registration
- Basic tracing infrastructure
- Validation middleware prototype
- Exception hierarchy

[1.0.0]: https://github.com/EaCognitive/agentgate/releases/tag/v1.0.0
[0.4.0]: https://github.com/EaCognitive/agentgate/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/EaCognitive/agentgate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EaCognitive/agentgate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EaCognitive/agentgate/releases/tag/v0.1.0
