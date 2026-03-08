# Test Suite Documentation

This document describes the AgentGate test suite structure, coverage, and execution.

## Overview

| File | Tests | Coverage Area |
|------|-------|---------------|
| `test_agent.py` | 21 | Core Agent class, tool registration, transactions |
| `test_async.py` | 29 | Async/await support, async middleware, async backends |
| `test_backends.py` | 21 | Memory backends for rate limiting, cost tracking, caching |
| `test_enterprise.py` | 17 | SemanticCache, SemanticValidator, OTelExporter, LLM providers |
| `test_middleware.py` | 11 | RateLimiter, CostTracker, AuditLog, HumanApproval |
| `test_trace.py` | 9 | Trace lifecycle, status transitions, serialization |
| **Total** | **116** | |

## Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_async.py

# Run specific test class
pytest tests/test_agent.py::TestAgentTransactions

# Run specific test
pytest tests/test_agent.py::TestAgentBasics::test_call_tool

# Run with coverage
pytest --cov=ea_agentgate --cov-report=html
```

## Test Files

### test_agent.py

Core Agent functionality tests.

**TestAgentBasics**
| Test | Description |
|------|-------------|
| `test_create_agent` | Agent instantiation with default configuration |
| `test_register_tool` | Tool registration via `agent.register()` method |
| `test_register_tool_decorator` | Tool registration via `@agent.tool` decorator |
| `test_register_tool_with_options` | Tool registration with custom options |
| `test_call_tool` | Basic tool execution via `agent.call()` |
| `test_call_tool_with_args` | Tool execution with arguments |
| `test_call_unregistered_tool` | Error handling for unknown tools |
| `test_traces_recorded` | Trace creation on tool execution |
| `test_traces_property` | Access to trace history |
| `test_failed_tool_traces` | Trace status on tool failure |
| `test_clear_traces` | Trace history clearing |

**TestAgentTransactions**
| Test | Description |
|------|-------------|
| `test_begin_transaction` | Transaction initialization |
| `test_commit_transaction` | Successful transaction commit |
| `test_rollback_clears_transaction_traces` | Rollback clears transaction-scoped traces |
| `test_transaction_context_manager` | `with agent.transaction()` context manager |
| `test_transaction_rollback_on_failure` | Automatic rollback on exception (saga pattern) |

**TestAgentMiddleware**
| Test | Description |
|------|-------------|
| `test_add_middleware` | Dynamic middleware addition |
| `test_middleware_blocks_execution` | Middleware can block tool execution |
| `test_middleware_in_constructor` | Middleware passed to Agent constructor |

**TestAgentIdentifiers**
| Test | Description |
|------|-------------|
| `test_auto_generated_agent_id` | Automatic agent ID generation |
| `test_custom_identifiers` | Custom agent_id, session_id, user_id |

---

### test_async.py

Async/await support tests.

**TestAgentAcall**
| Test | Description |
|------|-------------|
| `test_acall_sync_tool` | Async execution of sync tools (thread pool) |
| `test_acall_async_tool` | Native async tool execution |
| `test_acall_with_positional_args` | Async call with positional arguments |
| `test_acall_creates_trace` | Trace creation in async context |
| `test_acall_unknown_tool` | Error handling for unknown tools in async |
| `test_acall_parallel_execution` | Parallel tool execution with `asyncio.gather()` |

**TestAgentAtransaction**
| Test | Description |
|------|-------------|
| `test_atransaction_success` | Async transaction commit |
| `test_atransaction_rollback_on_failure` | Async rollback on exception |
| `test_atransaction_async_compensation` | Async compensation functions |

**TestSyncCallWithAsyncTool**
| Test | Description |
|------|-------------|
| `test_sync_call_async_tool_no_loop` | Sync call of async tool when no event loop running |

**TestMiddlewareChainAexecute**
| Test | Description |
|------|-------------|
| `test_aexecute_sync_tool` | Middleware chain with sync tool in async context |
| `test_aexecute_async_tool` | Middleware chain with async tool |
| `test_aexecute_runs_abefore_hooks` | `abefore()` hooks execute in order |
| `test_aexecute_runs_aafter_hooks` | `aafter()` hooks execute in reverse order |
| `test_aexecute_cache_hit` | Cache hit short-circuits tool execution |

**TestMiddlewareDefaultAsync**
| Test | Description |
|------|-------------|
| `test_default_abefore_calls_before` | Default `abefore()` wraps `before()` in thread |
| `test_default_aafter_calls_after` | Default `aafter()` wraps `after()` in thread |
| `test_is_async_native_default` | `is_async_native()` returns False by default |

**TestAsyncRateLimiter**
| Test | Description |
|------|-------------|
| `test_rate_limiter_sync_fallback` | Rate limiter uses thread pool without async backend |
| `test_rate_limiter_async_backend` | Rate limiter uses async backend when provided |
| `test_rate_limiter_async_exceeds_limit` | Rate limit enforcement in async context |

**TestAsyncRedisRateLimitBackend**
| Test | Description |
|------|-------------|
| `test_arecord_call_returns_count` | Async Redis rate limit recording |

**TestAsyncRedisCacheBackend**
| Test | Description |
|------|-------------|
| `test_aget_returns_value` | Async cache retrieval |
| `test_aget_returns_none_for_missing` | Async cache miss handling |
| `test_asearch_similar_uses_mget` | Batched MGET for similarity search (N+1 fix) |

**TestAsyncOpenAIProvider**
| Test | Description |
|------|-------------|
| `test_acomplete_returns_response` | Async LLM completion |
| `test_aembed_returns_vector` | Async embedding generation |

**TestAsyncIntegration**
| Test | Description |
|------|-------------|
| `test_full_async_pipeline` | End-to-end async middleware + tool execution |
| `test_async_error_handling` | Error propagation in async context |

---

### test_backends.py

Backend implementation tests.

**TestMemoryRateLimitBackend**
| Test | Description |
|------|-------------|
| `test_record_call_returns_count` | Call recording returns current count |
| `test_multiple_calls_increment_count` | Count increments with calls |
| `test_old_calls_removed_from_window` | Sliding window removes expired entries |
| `test_separate_keys_tracked_independently` | Scope isolation |
| `test_get_count_without_recording` | Read-only count check |
| `test_reset_specific_key` | Reset single scope |
| `test_reset_all_keys` | Reset all scopes |

**TestMemoryCostBackend**
| Test | Description |
|------|-------------|
| `test_add_cost_returns_new_total` | Cost addition returns updated total |
| `test_costs_accumulate` | Costs accumulate correctly |
| `test_get_total_for_unknown_key` | Unknown key returns zero |
| `test_separate_keys_tracked_independently` | Scope isolation |
| `test_reset_specific_key` | Reset single scope |
| `test_reset_all_keys` | Reset all scopes |

**TestMemoryCacheBackend**
| Test | Description |
|------|-------------|
| `test_set_and_get` | Basic cache set/get |
| `test_get_nonexistent_key` | Cache miss returns None |
| `test_delete` | Cache entry deletion |
| `test_delete_nonexistent` | Delete nonexistent key returns False |
| `test_clear` | Clear all entries |
| `test_ttl_expiration` | TTL-based expiration |
| `test_search_similar_finds_matching` | Embedding similarity search |
| `test_search_similar_respects_threshold` | Similarity threshold enforcement |
| `test_search_similar_respects_limit` | Result limit enforcement |
| `test_search_similar_sorted_by_similarity` | Results sorted by similarity descending |
| `test_search_similar_skips_entries_without_embedding` | Skip entries without embeddings |

**TestRateLimiterWithBackend**
| Test | Description |
|------|-------------|
| `test_rate_limiter_uses_custom_backend` | RateLimiter accepts custom backend |

---

### test_enterprise.py

Enterprise feature tests.

**TestSemanticCache**
| Test | Description |
|------|-------------|
| `test_cache_miss_executes_tool` | Tool executes on cache miss |
| `test_cache_stores_result` | Result stored after execution |
| `test_cache_hit_skips_tool` | Tool skipped on cache hit |
| `test_exclude_tools` | Excluded tools bypass cache |
| `test_cache_tools_filter` | Only specified tools cached |
| `test_cache_stats` | Hit/miss statistics tracking |

**TestSemanticValidator**
| Test | Description |
|------|-------------|
| `test_prompt_injection_blocked` | Prompt injection detection and blocking |
| `test_clean_input_passes` | Clean input passes validation |
| `test_pii_detection` | PII detection (SSN, email, etc.) |
| `test_non_blocking_check` | Non-blocking checks log but don't block |
| `test_fail_open_on_error` | `fail_open=True` allows on LLM error |
| `test_fail_closed_on_error` | `fail_open=False` blocks on LLM error |
| `test_topic_relevance_check` | Off-topic content detection |

**TestOTelExporter**
| Test | Description |
|------|-------------|
| `test_graceful_degradation_without_otel` | Works when OTel not installed |
| `test_span_attributes_set` | Span attributes correctly set |

**TestLLMProviders**
| Test | Description |
|------|-------------|
| `test_llm_response_properties` | LLMResponse dataclass properties |
| `test_llm_response_alternative_keys` | Alternative key handling in usage dict |
| `test_provider_protocol` | Provider protocol compliance |

**TestMiddlewareChainCacheSupport**
| Test | Description |
|------|-------------|
| `test_cache_hit_skips_execution` | Cache hit short-circuits tool execution |
| `test_no_cache_hit_executes_tool` | Cache miss executes tool normally |

---

### test_middleware.py

Core middleware tests.

**TestRateLimiter**
| Test | Description |
|------|-------------|
| `test_allows_within_limit` | Requests within limit allowed |
| `test_blocks_over_limit` | Requests over limit blocked with `RateLimitError` |
| `test_per_tool_limiting` | Per-tool rate limit scope |

**TestCostTracker**
| Test | Description |
|------|-------------|
| `test_tracks_costs` | Cost accumulation tracking |
| `test_blocks_over_budget` | Budget exceeded raises `BudgetExceededError` |

**TestAuditLog**
| Test | Description |
|------|-------------|
| `test_logs_to_stream` | Log output to stream |
| `test_redacts_sensitive_keys` | Sensitive key redaction |
| `test_context_manager` | Context manager cleanup |
| `test_get_entries` | Access to log entries |

**TestHumanApproval**
| Test | Description |
|------|-------------|
| `test_no_approval_for_unlisted_tools` | Unlisted tools execute without approval |
| `test_requires_approval_for_specified_tools` | Specified tools require approval |
| `test_approval_granted` | Approved tools execute |

---

### test_trace.py

Trace lifecycle tests.

**TestTrace**
| Test | Description |
|------|-------------|
| `test_create_trace` | Trace instantiation |
| `test_trace_start` | Trace start timestamp and status |
| `test_trace_succeed` | Success status transition |
| `test_trace_fail` | Failure status with error message |
| `test_trace_block` | Blocked status with middleware name |
| `test_trace_to_dict` | Serialization to dictionary |
| `test_trace_metadata` | Custom metadata attachment |
| `test_trace_cost` | Cost tracking on trace |
| `test_trace_parent_id` | Parent trace ID for hierarchical tracing |

---

## Test Fixtures

Defined in `conftest.py`:

| Fixture | Scope | Description |
|---------|-------|-------------|
| `agent` | function | Fresh Agent instance for each test |
| `mock_llm_provider` | function | Mock LLM provider for semantic tests |

## Mocking Strategy

- **LLM Providers**: Mocked to avoid API calls and costs
- **Redis Clients**: Mocked using `unittest.mock.AsyncMock`
- **Time-dependent tests**: Use `time.sleep()` for TTL testing

## Known Warnings

The test suite produces 4 warnings related to `AsyncMockMixin` coroutines in Redis pipeline tests. These are false positives caused by mock behavior differences from real `redis.asyncio` - the production code is correct.

## Coverage Goals

- Core functionality: 100% coverage
- Error paths: All exception types tested
- Edge cases: Empty inputs, None values, boundary conditions
- Async/sync interop: Both directions tested
