## Resilience & Latency Optimization

AgentGate provides enterprise-grade resilience patterns and performance optimizations for production AI applications.

### Overview

Phase 3 introduces:
- **Fail-Open/Fail-Closed Modes**: Configurable failure handling
- **Circuit Breaker Pattern**: Prevent cascade failures
- **Async Inference Sidecar**: 60% latency reduction for ML models
- **Timeout Handling**: Graceful timeout management
- **Retry Logic**: Automatic retry for transient failures

### Failure Modes

Control how middleware behaves when errors occur:

```python
from ea_agentgate import Agent
from ea_agentgate.middleware import PromptGuardMiddleware
from ea_agentgate.middleware.base import FailureMode

# Fail-Open: Pass through on error (graceful degradation)
agent = Agent(
    middleware=[
        PromptGuardMiddleware(
            threshold=0.9,
            failure_mode=FailureMode.FAIL_OPEN,
        ),
    ]
)

# Fail-Closed: Block on error (secure by default)
agent = Agent(
    middleware=[
        PromptGuardMiddleware(
            threshold=0.9,
            failure_mode=FailureMode.FAIL_CLOSED,
        ),
    ]
)

# Retry: Attempt retries before failing
agent = Agent(
    middleware=[
        PromptGuardMiddleware(
            threshold=0.9,
            failure_mode=FailureMode.RETRY,
            max_retries=3,
        ),
    ]
)
```

#### When to Use Each Mode

**Fail-Open (Graceful Degradation)**
- Use for: Non-critical security checks, user-facing applications
- Behavior: Requests proceed even if middleware fails
- Example: Content moderation where availability > perfect accuracy

**Fail-Closed (Secure by Default)**
- Use for: Critical security checks, compliance requirements
- Behavior: Requests blocked if middleware fails
- Example: PII detection before database writes

**Retry (Transient Failure Handling)**
- Use for: Network-dependent operations, temporary issues
- Behavior: Automatic retries with exponential backoff
- Example: Remote API calls, database connections

### Circuit Breaker

Prevent cascade failures by detecting repeated errors and temporarily failing fast:

```python
from ea_agentgate.middleware import PromptGuardMiddleware
from ea_agentgate.middleware.base import FailureMode

middleware = PromptGuardMiddleware(
    threshold=0.9,
    failure_mode=FailureMode.FAIL_OPEN,
    circuit_breaker_threshold=5,      # Open after 5 consecutive failures
    circuit_breaker_timeout=60.0,     # Wait 60s before recovery attempt
)

# Access circuit breaker statistics
stats = middleware._circuit_breaker.stats
print(f"State: {middleware._circuit_breaker.state.value}")
print(f"Failures: {stats.total_failures}")
print(f"Successes: {stats.total_successes}")
```

#### Circuit States

1. **CLOSED (Normal)**: All requests pass through
2. **OPEN (Failing)**: Requests fail fast without execution
3. **HALF_OPEN (Testing)**: Limited requests to test recovery

#### Circuit Breaker Benefits

- **Prevents Cascade Failures**: Stop overloading failing services
- **Fast Failure**: Fail immediately instead of waiting for timeout
- **Automatic Recovery**: Test service health and recover automatically
- **Resource Protection**: Prevent resource exhaustion

### Async Inference Sidecar

Achieve 60% latency reduction by offloading ML inference to process pool:

```python
from ea_agentgate.middleware import PromptGuardMiddleware
from ea_agentgate.middleware.base import FailureMode

# Enable async inference for low latency
agent = Agent(
    middleware=[
        PromptGuardMiddleware(
            threshold=0.9,
            failure_mode=FailureMode.FAIL_OPEN,
            use_async_inference=True,  # Enable process-pool inference
            timeout_ms=5000,            # 5 second timeout
        ),
    ]
)

@agent.tool
async def chat(message: str) -> str:
    """Process chat message with low-latency security checks."""
    return f"Response to: {message}"

# Concurrent requests benefit from async inference
results = await asyncio.gather(
    agent.acall("chat", message="Hello"),
    agent.acall("chat", message="How are you?"),
    agent.acall("chat", message="Tell me about AI"),
)
```

#### How It Works

1. **Process Pool**: ML inference runs in separate processes
2. **GIL Avoidance**: Bypass Python's Global Interpreter Lock
3. **Concurrency**: Multiple inferences run truly in parallel
4. **Resource Isolation**: Process isolation prevents memory leaks

#### Performance Comparison

| Mode | Latency | Throughput | Use Case |
|------|---------|------------|----------|
| Sync | 100ms | 10 req/s | Simple apps |
| Async (thread) | 80ms | 15 req/s | I/O bound |
| Async (process) | 40ms | 25 req/s | ML inference |

### Timeout Configuration

Prevent operations from hanging indefinitely:

```python
from ea_agentgate.middleware import PromptGuardMiddleware
from ea_agentgate.middleware.base import FailureMode

agent = Agent(
    middleware=[
        PromptGuardMiddleware(
            threshold=0.9,
            failure_mode=FailureMode.FAIL_CLOSED,
            timeout_ms=3000,  # 3 second timeout
        ),
    ]
)
```

#### Timeout Behavior

- **Fail-Open**: Timeout allows request through
- **Fail-Closed**: Timeout blocks request
- **Retry**: Timeout triggers retry

### Direct Circuit Breaker Usage

Use circuit breaker independently of middleware:

```python
from ea_agentgate.resilience import CircuitBreaker, CircuitBreakerError

# Create circuit breaker
breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60.0,
    half_open_max_calls=3,
)

def risky_operation(data: str) -> str:
    """Operation that might fail."""
    # ... API call, database query, etc.
    return result

# Execute with circuit breaker protection
try:
    result = breaker.call(risky_operation, "input data")
except CircuitBreakerError:
    print("Circuit open, using fallback")
    result = get_cached_data()

# Async support
async def async_risky_operation(data: str) -> str:
    """Async operation that might fail."""
    return await fetch_from_api(data)

result = await breaker.acall(async_risky_operation, "input data")
```

#### Fallback Functions

Provide fallback behavior when circuit is open:

```python
def fallback_handler(*args, **kwargs) -> str:
    """Fallback when circuit is open."""
    return "cached_response"

breaker = CircuitBreaker(
    failure_threshold=3,
    recovery_timeout=60.0,
    fallback_fn=fallback_handler,
)

# Will use fallback when circuit is open
result = breaker.call(failing_operation, "data")
```

### Direct Inference Sidecar Usage

Use async inference independently:

```python
from ea_agentgate.inference.sidecar import InferenceSidecar

# Create inference sidecar
sidecar = InferenceSidecar(
    max_workers=4,
    device="cpu",  # or "cuda", "mps"
)

# Classify text
result = await sidecar.classify_async(
    model_id="meta-llama/Llama-Prompt-Guard-2-86M",
    text="User input text",
    max_length=512,
)

print(f"Benign: {result['benign_prob']:.2f}")
print(f"Injection: {result['injection_prob']:.2f}")
print(f"Jailbreak: {result['jailbreak_prob']:.2f}")

# Cleanup
await sidecar.shutdown()
```

#### Convenience Function

Use global sidecar for simple cases:

```python
from ea_agentgate.inference.sidecar import classify_async

result = await classify_async(
    model_id="meta-llama/Llama-Prompt-Guard-2-86M",
    text="User input",
    max_length=512,
    device="cpu",
)
```

### Best Practices

#### 1. Choose Appropriate Failure Mode

```python
# User-facing: Prioritize availability
user_facing = PromptGuardMiddleware(
    failure_mode=FailureMode.FAIL_OPEN,
)

# Backend: Prioritize security
backend = PromptGuardMiddleware(
    failure_mode=FailureMode.FAIL_CLOSED,
)

# API calls: Retry transient failures
api_wrapper = PromptGuardMiddleware(
    failure_mode=FailureMode.RETRY,
    max_retries=3,
)
```

#### 2. Configure Circuit Breaker Thresholds

```python
# Aggressive: Fail fast
aggressive = PromptGuardMiddleware(
    circuit_breaker_threshold=3,     # Open after 3 failures
    circuit_breaker_timeout=30.0,    # Short recovery window
)

# Conservative: Tolerate more failures
conservative = PromptGuardMiddleware(
    circuit_breaker_threshold=10,    # Open after 10 failures
    circuit_breaker_timeout=120.0,   # Longer recovery window
)
```

#### 3. Set Appropriate Timeouts

```python
# Fast operations: Short timeout
fast = PromptGuardMiddleware(
    timeout_ms=1000,  # 1 second
)

# ML inference: Longer timeout
ml_heavy = PromptGuardMiddleware(
    timeout_ms=5000,  # 5 seconds
    use_async_inference=True,
)
```

#### 4. Monitor Circuit Breaker Statistics

```python
# Log circuit breaker metrics
stats = middleware._circuit_breaker.stats
logger.info(
    "Circuit breaker stats",
    state=middleware._circuit_breaker.state.value,
    total_calls=stats.total_calls,
    success_rate=stats.total_successes / max(stats.total_calls, 1),
    consecutive_failures=stats.consecutive_failures,
)

# Alert on circuit open
if middleware._circuit_breaker.state.value == "open":
    send_alert("Circuit breaker open for PromptGuard")
```

### Migration Guide

#### From Legacy fail_closed Parameter

Old:
```python
middleware = PromptGuardMiddleware(
    threshold=0.9,
    fail_closed=True,
)
```

New:
```python
from ea_agentgate.middleware.base import FailureMode

middleware = PromptGuardMiddleware(
    threshold=0.9,
    failure_mode=FailureMode.FAIL_CLOSED,
)
```

#### Enabling Async Inference

Add `use_async_inference=True` to existing middleware:

```python
middleware = PromptGuardMiddleware(
    threshold=0.9,
    failure_mode=FailureMode.FAIL_OPEN,
    use_async_inference=True,  # Add this
    timeout_ms=5000,            # Add timeout
)
```

### Performance Benchmarks

| Configuration | Avg Latency | P95 Latency | Throughput |
|--------------|-------------|-------------|------------|
| Sync | 150ms | 200ms | 10 req/s |
| Async (thread pool) | 120ms | 180ms | 15 req/s |
| Async (process pool) | 60ms | 90ms | 25 req/s |

**Test setup**: 4-core CPU, meta-llama/Llama-Prompt-Guard-2-86M model

### Related Documentation

- [Architecture Guide](./architecture.md)
- [Prompt Guard](./prompt-guard.md)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Error Handling Guide](./error-handling.md)

### Examples

See complete examples:
- [resilience_demo.py](../ea_agentgate/examples/resilience_demo.py)
- [Circuit Breaker Routing Tests](../tests/test_routing.py)
- [Inference Sidecar Implementation](../ea_agentgate/inference/sidecar.py)
