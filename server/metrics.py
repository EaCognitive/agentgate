"""Prometheus metrics for AgentGate."""

import time
from typing import Any

from prometheus_client import Counter, Histogram, Gauge, Info

# Request metrics
http_requests_total = Counter(
    "agentgate_http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)

http_request_duration_seconds = Histogram(
    "agentgate_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Tool execution metrics
tool_executions_total = Counter(
    "agentgate_tool_executions_total", "Total tool executions", ["tool", "status"]
)

tool_execution_duration_seconds = Histogram(
    "agentgate_tool_execution_duration_seconds",
    "Tool execution duration in seconds",
    ["tool"],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

tool_execution_cost = Histogram(
    "agentgate_tool_execution_cost",
    "Tool execution cost in dollars",
    ["tool"],
    buckets=(0.0001, 0.001, 0.01, 0.1, 1.0, 10.0),
)

# Approval metrics
approvals_pending = Gauge("agentgate_approvals_pending", "Number of pending approvals")

approvals_total = Counter("agentgate_approvals_total", "Total approval requests", ["status"])

# Rate limiting metrics
rate_limit_exceeded_total = Counter(
    "agentgate_rate_limit_exceeded_total", "Total rate limit exceeded events", ["endpoint"]
)

# PII metrics
pii_operations_total = Counter(
    "agentgate_pii_operations_total",
    "Total PII operations",
    ["operation"],  # store, retrieve, delete
)

pii_detections_total = Counter(
    "agentgate_pii_detections_total",
    "Total PII detections",
    ["pii_type"],  # email, phone, ssn, etc.
)

pii_redact_calls_total = Counter(
    "agentgate_pii_redact_calls_total",
    "Total permission-scoped PII redact calls",
)

pii_restore_calls_total = Counter(
    "agentgate_pii_restore_calls_total",
    "Total permission-scoped PII restore calls",
)

pii_restore_denied_total = Counter(
    "agentgate_pii_restore_denied_total",
    "Total denied PII restore attempts",
)

pii_restore_integrity_fail_total = Counter(
    "agentgate_pii_restore_integrity_fail_total",
    "Total PII restore integrity failures",
)

z3_eval_total = Counter(
    "agentgate_z3_eval_total",
    "Total runtime Z3 admissibility evaluations",
    ["mode", "result"],  # mode: off/shadow/enforce, result: admissible/inadmissible
)

z3_eval_failures_total = Counter(
    "agentgate_z3_eval_failures_total",
    "Total runtime Z3 evaluation failures",
    ["mode"],  # mode: shadow/enforce
)

z3_drift_total = Counter(
    "agentgate_z3_drift_total",
    "Total runtime decision drifts between python and Z3 evaluators",
    ["mode"],  # mode: shadow/enforce
)

mcp_auth_validation_failures_total = Counter(
    "agentgate_mcp_auth_validation_failures_total",
    "Total MCP remote auth validation failures",
)

mcp_guardrail_denials_total = Counter(
    "agentgate_mcp_guardrail_denials_total",
    "Total MCP execution-policy denials",
    ["reason"],  # approval_required, blocked, error
)

mcp_policy_missing_fail_closed_total = Counter(
    "agentgate_mcp_policy_missing_fail_closed_total",
    "Total MCP fail-closed denials due to missing active policy",
)

mcp_async_job_failures_total = Counter(
    "agentgate_mcp_async_job_failures_total",
    "Total failed MCP async jobs",
    ["operation"],
)

mcp_formal_missing_runtime_solver_total = Counter(
    "agentgate_mcp_formal_missing_runtime_solver_total",
    "Total MCP formal responses missing runtime_solver metadata",
    ["operation"],
)

health_monitor_probe_total = Counter(
    "agentgate_health_monitor_probe_total",
    "Total distributed health monitor probes",
    ["target", "result"],  # result: healthy|failed
)

health_monitor_target_status = Gauge(
    "agentgate_health_monitor_target_status",
    "Current distributed health monitor status per target (1=healthy, 0=failed)",
    ["target"],
)

# Error metrics
errors_total = Counter("agentgate_errors_total", "Total errors", ["error_type"])

# Database metrics
db_query_duration_seconds = Histogram(
    "agentgate_db_query_duration_seconds",
    "Database query duration in seconds",
    ["query_type"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

db_connections_active = Gauge(
    "agentgate_db_connections_active", "Number of active database connections"
)

# System info
system_info = Info("agentgate_system", "AgentGate system information")


# Helper functions for recording metrics
def record_request(method: str, endpoint: str, status: int, duration: float):
    """Record HTTP request metrics."""
    http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
    http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)


def record_tool_execution(tool: str, status: str, duration: float, cost: float = 0.0):
    """Record tool execution metrics."""
    tool_executions_total.labels(tool=tool, status=status).inc()
    tool_execution_duration_seconds.labels(tool=tool).observe(duration)
    if cost > 0:
        tool_execution_cost.labels(tool=tool).observe(cost)


def record_approval(status: str):
    """Record approval metrics."""
    approvals_total.labels(status=status).inc()


def record_pii_operation(operation: str):
    """Record PII operation metrics."""
    pii_operations_total.labels(operation=operation).inc()


def record_pii_detection(pii_type: str):
    """Record PII detection metrics."""
    pii_detections_total.labels(pii_type=pii_type).inc()


def record_pii_redact_call() -> None:
    """Record a permission-scoped PII redact call."""
    pii_redact_calls_total.inc()


def record_pii_restore_call() -> None:
    """Record a permission-scoped PII restore call."""
    pii_restore_calls_total.inc()


def record_pii_restore_denied() -> None:
    """Record a denied PII restore attempt."""
    pii_restore_denied_total.inc()


def record_pii_restore_integrity_fail() -> None:
    """Record a PII restore integrity failure."""
    pii_restore_integrity_fail_total.inc()


def record_z3_eval(mode: str, admissible: bool) -> None:
    """Record a runtime Z3 evaluation result."""
    result = "admissible" if admissible else "inadmissible"
    z3_eval_total.labels(mode=mode, result=result).inc()


def record_z3_eval_failure(mode: str) -> None:
    """Record a runtime Z3 evaluation failure."""
    z3_eval_failures_total.labels(mode=mode).inc()


def record_z3_drift(mode: str) -> None:
    """Record a runtime decision drift between python and Z3 evaluators."""
    z3_drift_total.labels(mode=mode).inc()


def record_mcp_auth_validation_failure() -> None:
    """Record a failed MCP remote-auth validation event."""
    mcp_auth_validation_failures_total.inc()


def record_mcp_guardrail_denial(reason: str) -> None:
    """Record an MCP execution-policy denial."""
    mcp_guardrail_denials_total.labels(reason=reason).inc()


def record_mcp_policy_missing_fail_closed() -> None:
    """Record MCP fail-closed enforcement due to missing policy."""
    mcp_policy_missing_fail_closed_total.inc()


def record_mcp_async_job_failure(operation: str) -> None:
    """Record an MCP async-job failure."""
    mcp_async_job_failures_total.labels(operation=operation).inc()


def record_mcp_formal_missing_runtime_solver(operation: str) -> None:
    """Record a missing runtime_solver payload for formal MCP responses."""
    mcp_formal_missing_runtime_solver_total.labels(operation=operation).inc()


def record_health_monitor_probe(target: str, *, result: str) -> None:
    """Record a distributed health monitor probe result."""
    health_monitor_probe_total.labels(target=target, result=result).inc()


def set_health_monitor_target_status(target: str, *, is_healthy: bool) -> None:
    """Set current target health status (1 healthy, 0 failed)."""
    health_monitor_target_status.labels(target=target).set(1 if is_healthy else 0)


def record_error(error_type: str):
    """Record error metrics."""
    errors_total.labels(error_type=error_type).inc()


def record_rate_limit_exceeded(endpoint: str):
    """Record rate limit exceeded event."""
    rate_limit_exceeded_total.labels(endpoint=endpoint).inc()


# Middleware for automatic request metrics
class MetricsMiddleware:
    """Middleware to automatically record request metrics."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self._request_count: int = 0

    def get_request_count(self) -> int:
        """
        Get the total number of requests processed by this middleware instance.

        Returns:
            The total number of HTTP requests processed.
        """
        return self._request_count

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        self._request_count += 1
        method = scope["method"]
        path = scope["path"]
        start_time = time.time()
        status_code = 500  # Default to error

        async def send_wrapper(message: dict[str, Any]) -> None:
            """Intercept response start to capture the HTTP status code."""
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.time() - start_time
            record_request(method, path, status_code, duration)
