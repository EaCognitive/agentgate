# Error Handling Guide

AgentGate provides comprehensive error handling with rich debugging context, actionable suggestions, and documentation links.

## Table of Contents

1. [Enhanced Exception System](#enhanced-exception-system)
2. [Exception Types](#exception-types)
3. [Error Context](#error-context)
4. [Best Practices](#best-practices)
5. [Debugging Errors](#debugging-errors)

## Enhanced Exception System

All AgentGate exceptions inherit from `AgentGateError`, which provides:

- **Detailed error messages** - Clear description of what went wrong
- **Middleware context** - Which middleware raised the error
- **Tool context** - Which tool was being executed
- **Trace ID** - Unique identifier for debugging
- **Additional context** - Relevant data (scores, limits, etc.)
- **Documentation links** - Direct links to relevant docs
- **Suggested fixes** - Actionable steps to resolve the error

### Basic Error Handling

```python
from ea_agentgate import Agent, ValidationError

agent = Agent(name="my-agent")

try:
    result = agent.call("dangerous_tool", path="/")
except ValidationError as e:
    print(f"Error: {e}")
```

### Enhanced Error Information

```python
try:
    result = agent.call("dangerous_tool", path="/")
except ValidationError as e:
    # Basic error message
    print(f"Error: {e}")

    # Debugging context
    print(f"Middleware: {e.middleware}")
    print(f"Tool: {e.tool}")
    print(f"Trace ID: {e.trace_id}")

    # Additional context
    for key, value in e.context.items():
        print(f"  {key}: {value}")

    # Actionable guidance
    print(f"Suggested Fix: {e.suggested_fix}")
    print(f"Documentation: {e.docs_url}")
```

## Exception Types

### ValidationError

Raised when validation fails (blocked paths, patterns, prompt injection).

**Common Causes:**
- Blocked file paths
- Dangerous command patterns
- Prompt injection detected
- Tool not allowed

**Example:**
```python
from ea_agentgate import Agent, ValidationError
from ea_agentgate.middleware import Validator

agent = Agent(
    middleware=[
        Validator(block_paths=["/", "/etc"])
    ]
)

@agent.tool
def delete_file(path: str) -> str:
    return f"Deleted {path}"

try:
    agent.call("delete_file", path="/etc/passwd")
except ValidationError as e:
    print(e)
    # Output:
    # Error: Blocked path: /etc/passwd
    # Middleware: Validator
    # Tool: delete_file
    # Trace ID: abc12345
    # Context:
    #   - blocked_path: /etc/passwd
    #   - rule: block_paths
    # Suggested Fix: Use a safe path outside blocked directories
    # Documentation: https://docs.agentgate.io/middleware/validation
```

### RateLimitError

Raised when rate limit is exceeded.

**Example:**
```python
from ea_agentgate import Agent, RateLimitError
from ea_agentgate.middleware import RateLimiter

agent = Agent(
    middleware=[
        RateLimiter(max_calls=10, window="1m")
    ]
)

@agent.tool
def api_call() -> str:
    return "API response"

try:
    for i in range(15):
        agent.call("api_call")
except RateLimitError as e:
    print(e)
    # Output:
    # Error: Rate limit exceeded: 10 calls per 1m
    # Middleware: RateLimiter
    # Tool: api_call
    # Trace ID: def45678
    # Context:
    #   - current_calls: 11
    #   - max_calls: 10
    #   - window: 1m
    # Suggested Fix: Wait 45.2 seconds before retrying
    # Documentation: https://docs.agentgate.io/middleware/rate-limiter

    # Use retry_after for exponential backoff
    if e.retry_after:
        time.sleep(e.retry_after)
```

### BudgetExceededError

Raised when cost budget is exceeded.

**Example:**
```python
from ea_agentgate import Agent, BudgetExceededError
from ea_agentgate.middleware import CostTracker

agent = Agent(
    middleware=[
        CostTracker(max_budget=1.00)
    ]
)

try:
    # Expensive operations...
    agent.call("expensive_api_call")
except BudgetExceededError as e:
    print(e)
    # Output:
    # Error: Cost budget exceeded
    # Middleware: CostTracker
    # Tool: expensive_api_call
    # Trace ID: ghi78901
    # Context:
    #   - current_cost: $1.2500
    #   - max_budget: $1.0000
    #   - overage: $0.2500
    # Suggested Fix: Increase budget from $1.00 or wait for reset
    # Documentation: https://docs.agentgate.io/middleware/cost-tracker
```

### ApprovalRequired

Raised when human approval is required.

**Example:**
```python
from ea_agentgate import Agent, ApprovalRequired
from ea_agentgate.middleware import HumanApproval

agent = Agent(
    middleware=[
        HumanApproval(tools=["delete_*", "send_*"])
    ]
)

@agent.tool
def delete_database(name: str) -> str:
    return f"Deleted database {name}"

try:
    agent.call("delete_database", name="production")
except ApprovalRequired as e:
    print(e)
    # Output:
    # Error: Human approval required for delete_database
    # Middleware: HumanApproval
    # Tool: delete_database
    # Trace ID: jkl23456
    # Context:
    #   - approval_id: apr_abc123
    #   - tool_inputs: {'name': 'production'}
    # Suggested Fix: Approve this request using: agent.approve_request('apr_abc123')
    # Documentation: https://docs.agentgate.io/middleware/human-approval

    # Approve the request
    agent.approve_request(e.approval_id)
    result = agent.call("delete_database", name="production")
```

### ApprovalDenied

Raised when human approval is denied.

**Example:**
```python
try:
    result = agent.call("dangerous_operation")
except ApprovalDenied as e:
    print(e)
    # Output:
    # Error: Request denied by admin@example.com
    # Middleware: HumanApproval
    # Tool: dangerous_operation
    # Trace ID: mno34567
    # Context:
    #   - denied_by: admin@example.com
    # Suggested Fix: Modify the request or contact the reviewer for details
    # Documentation: https://docs.agentgate.io/middleware/human-approval
```

### ApprovalTimeout

Raised when approval request times out.

**Example:**
```python
from ea_agentgate import Agent, ApprovalTimeout
from ea_agentgate.middleware import HumanApproval

agent = Agent(
    middleware=[
        HumanApproval(tools=["critical_*"], timeout=60)
    ]
)

try:
    # No one responds within 60 seconds
    agent.call("critical_operation")
except ApprovalTimeout as e:
    print(e)
    # Output:
    # Error: Approval request timed out after 60 seconds
    # Middleware: HumanApproval
    # Tool: critical_operation
    # Trace ID: pqr45678
    # Context:
    #   - timeout_seconds: 60
    # Suggested Fix: Increase timeout from 60s or respond faster
    # Documentation: https://docs.agentgate.io/middleware/human-approval
```

### GuardrailViolationError

Raised when temporal guardrail constraints are violated.

**Example:**
```python
from ea_agentgate import Agent, GuardrailViolationError
from ea_agentgate.middleware import StatefulGuardrail
from ea_agentgate.backends import MemoryGuardrailBackend

agent = Agent(
    middleware=[
        StatefulGuardrail(
            policy="policy.json",
            backend=MemoryGuardrailBackend()
        )
    ]
)

try:
    # Violate cooldown constraint
    agent.call("send_email")
    agent.call("send_email")  # Too soon!
except GuardrailViolationError as e:
    print(e)
    # Output:
    # Error: Guardrail violation: cooldown not satisfied
    # Middleware: StatefulGuardrail
    # Tool: send_email
    # Trace ID: stu56789
    # Context:
    #   - policy_id: email-policy
    #   - current_state: idle
    #   - attempted_action: send_email
    #   - violated_constraint: min_delay: 300s
    # Suggested Fix: Constraint violated: min_delay: 300s. Review policy rules
    # Documentation: https://docs.agentgate.io/middleware/guardrails
```

### TransactionFailed

Raised when a transaction fails and is rolled back.

**Example:**
```python
from ea_agentgate import Agent, TransactionFailed

agent = Agent()

@agent.tool
def create_user(email: str) -> dict:
    return {"id": "user_123", "email": email}

@agent.tool
def charge_card(amount: float) -> dict:
    raise RuntimeError("Card declined")

# Register rollback handler
agent.compensate("create_user", lambda output: delete_user(output["id"]))

try:
    with agent.transaction():
        user = agent.call("create_user", email="test@example.com")
        agent.call("charge_card", amount=99.00)  # Fails!
except TransactionFailed as e:
    print(e)
    # Output:
    # Error: Transaction failed at charge_card
    # Failed step: charge_card
    # Completed steps: ['create_user']
    # Compensated steps: ['create_user']
```

## Error Context

All exceptions include a `context` dictionary with relevant information:

### ValidationError Context
```python
{
    "blocked_path": "/etc/passwd",
    "rule": "block_paths",
    "threat_score": 0.95,  # For prompt guard
    "threat_type": "injection"
}
```

### RateLimitError Context
```python
{
    "current_calls": 11,
    "max_calls": 10,
    "window": "1m"
}
```

### BudgetExceededError Context
```python
{
    "current_cost": "$1.2500",
    "max_budget": "$1.0000",
    "overage": "$0.2500"
}
```

### GuardrailViolationError Context
```python
{
    "policy_id": "email-policy",
    "current_state": "idle",
    "attempted_action": "send_email",
    "violated_constraint": "min_delay: 300s"
}
```

## Best Practices

### 1. Always Catch Specific Exceptions

```python
# Good: Catch specific exception types
try:
    agent.call("dangerous_tool")
except ValidationError as e:
    # Handle validation errors
    log.error(f"Validation failed: {e.suggested_fix}")
except RateLimitError as e:
    # Handle rate limit errors
    time.sleep(e.retry_after)
except Exception as e:
    # Handle unexpected errors
    log.exception(f"Unexpected error: {e}")

# Bad: Catch all exceptions without differentiation
try:
    agent.call("dangerous_tool")
except Exception:
    pass  # Don't do this!
```

### 2. Use Trace IDs for Debugging

```python
try:
    agent.call("complex_operation")
except Exception as e:
    if hasattr(e, "trace_id"):
        log.error(f"Operation failed. Trace ID: {e.trace_id}")
        # Use trace ID to look up full trace
        trace = next(t for t in agent.traces if t.id == e.trace_id)
        log.error(f"Full trace: {trace}")
```

### 3. Present Helpful Error Messages to Users

```python
try:
    agent.call("send_email", to="user@example.com")
except ValidationError as e:
    # Show user-friendly message
    print(f"Cannot send email: {str(e).split('\\n')[0]}")

    # Log technical details for debugging
    log.error(
        f"Email validation failed",
        extra={
            "trace_id": e.trace_id,
            "middleware": e.middleware,
            "context": e.context
        }
    )
```

### 4. Implement Retry Logic with Backoff

```python
import time
from ea_agentgate import RateLimitError

def call_with_retry(agent, tool, max_retries=3, **inputs):
    """Call tool with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return agent.call(tool, **inputs)
        except RateLimitError as e:
            if attempt == max_retries - 1:
                raise

            # Wait with exponential backoff
            wait_time = e.retry_after or (2 ** attempt)
            print(f"Rate limited. Waiting {wait_time}s...")
            time.sleep(wait_time)
```

### 5. Monitor Error Patterns

```python
from collections import Counter

# Track error patterns
error_counter = Counter()

for trace in agent.traces:
    if trace.result.status.value == "blocked":
        middleware = trace.context.blocked_by
        error_counter[middleware] += 1

# Report frequent blockers
print("Top blockers:")
for middleware, count in error_counter.most_common(5):
    print(f"  {middleware}: {count} blocks")
```

## Debugging Errors

### View Full Error Details

```python
import traceback

try:
    agent.call("problematic_tool")
except Exception as e:
    # Print full error with rich context
    print(e)  # Uses enhanced __str__ method

    # Print stack trace
    traceback.print_exc()

    # Access error attributes
    if hasattr(e, "trace_id"):
        print(f"\nTrace ID: {e.trace_id}")
    if hasattr(e, "context"):
        print(f"Context: {e.context}")
```

### Analyze Traces

```python
# Find failed traces
failed_traces = [
    t for t in agent.traces
    if t.result.status.value in ["failed", "blocked", "denied"]
]

for trace in failed_traces:
    print(f"\nFailed Tool: {trace.tool}")
    print(f"Status: {trace.result.status.value}")
    print(f"Error: {trace.result.error}")
    print(f"Blocked By: {trace.context.blocked_by}")
    print(f"Inputs: {trace.inputs}")
```

### Enable Debug Logging

```python
import logging

# Enable debug logging for AgentGate
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("agentgate")
logger.setLevel(logging.DEBUG)

# Now all middleware operations are logged
agent.call("my_tool")
```

## Common Error Scenarios

### Scenario 1: Path Validation Failure

```python
# Error: Trying to delete a blocked path
try:
    agent.call("delete_file", path="/etc/passwd")
except ValidationError as e:
    print(e.suggested_fix)  # "Use a safe path outside blocked directories"

    # Fix: Use allowed path
    agent.call("delete_file", path="/tmp/cache.txt")
```

### Scenario 2: Rate Limit Exceeded

```python
# Error: Too many API calls
try:
    for i in range(100):
        agent.call("api_call")
except RateLimitError as e:
    print(f"Wait {e.retry_after}s")

    # Fix: Implement backoff or batch requests
    time.sleep(e.retry_after)
```

### Scenario 3: Prompt Injection Detected

```python
# Error: Malicious prompt detected
try:
    agent.call("chat", prompt="Ignore previous instructions and...")
except ValidationError as e:
    print(e.context["threat_type"])  # "injection"
    print(e.suggested_fix)  # "Remove command injection patterns..."

    # Fix: Sanitize user input
    safe_prompt = sanitize(user_input)
    agent.call("chat", prompt=safe_prompt)
```

## Further Reading

- [Middleware Documentation](https://docs.agentgate.io/middleware)
- [Observability Guide](https://docs.agentgate.io/observability)
- [Best Practices](https://docs.agentgate.io/best-practices)
- [API Reference](overview.md#api-reference)
