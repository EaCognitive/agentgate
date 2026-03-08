"""
Dataset recording middleware for one-click eval test case generation.

Allows automatic recording of successful tool calls to datasets for
building evaluation test suites from production traffic.
"""

from __future__ import annotations

import asyncio
import json
import random
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING
from collections.abc import Callable
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from .base import Middleware, MiddlewareContext

if TYPE_CHECKING:
    pass


@dataclass
class RecordingFilterConfig:
    """Filtering configuration for dataset recording."""

    # Filter by tool names (empty = all tools)
    tool_filter: list[str] = field(default_factory=list)

    # Sample rate (0.0-1.0, 1.0 = record all)
    sample_rate: float = 1.0

    # Only record successful calls
    only_success: bool = True

    # Maximum number of test cases per session
    max_per_session: int | None = None


@dataclass
class RecordingConfig:
    """Configuration for dataset recording."""

    # Dataset to record to (required)
    dataset_id: int

    # Dashboard API URL for recording
    dashboard_url: str = "http://localhost:8000"

    # Auto-generate assertions from output
    auto_assertions: bool = True

    # Tags to apply to recorded test cases
    tags: list[str] = field(default_factory=list)

    # Custom name generator for test cases
    name_generator: Callable[[str, dict], str] | None = None

    # Filtering configuration
    filter: RecordingFilterConfig = field(default_factory=RecordingFilterConfig)


class DatasetRecorder(Middleware):
    """
    Middleware that records tool calls to datasets for evaluation.

    Records successful tool executions as test cases, enabling
    one-click conversion of production traffic to eval datasets.

    Example:
        # Basic usage - record all calls to dataset
        recorder = DatasetRecorder(
            dataset_id=1,
            dashboard_url="http://localhost:8000"
        )
        agent = Agent(middlewares=[recorder])

        # With filtering - only record certain tools
        recorder = DatasetRecorder(
            dataset_id=1,
            tool_filter=["search_database", "process_payment"],
            sample_rate=0.1,  # Record 10% of calls
        )

        # With custom name generator
        recorder = DatasetRecorder(
            dataset_id=1,
            name_generator=lambda tool, inputs: f"{tool}_{inputs.get('query', 'unknown')}"
        )

    The recorded test cases can then be:
    - Viewed in the dashboard
    - Exported as pytest files
    - Run as regression tests
    """

    def __init__(
        self,
        dataset_id: int,
        *,
        config: RecordingConfig | None = None,
    ):
        """
        Initialize dataset recorder.

        Args:
            dataset_id: ID of the dataset to record to
            config: Optional RecordingConfig with dashboard settings and filters.
                    If not provided, uses defaults.
        """
        if config is None:
            config = RecordingConfig(
                dataset_id=dataset_id,
            )
        else:
            # Override dataset_id from parameter
            config.dataset_id = dataset_id

        # Ensure dashboard_url doesn't have trailing slash
        super().__init__()
        self.config = config
        self.config.dashboard_url = self.config.dashboard_url.rstrip("/")

        # Session counters
        self._session_counts: dict[str, int] = {}
        self._http_client = None

    @property
    def name(self) -> str:
        """Return the middleware identifier."""
        return "DatasetRecorder"

    def _should_record(self, ctx: MiddlewareContext, error: Exception | None) -> bool:
        """Check if this call should be recorded."""
        # Only record success if configured
        if self.config.filter.only_success and error is not None:
            return False

        # Check tool filter
        if self.config.filter.tool_filter and ctx.tool not in self.config.filter.tool_filter:
            return False

        # Check sample rate
        if self.config.filter.sample_rate < 1.0:
            if random.random() > self.config.filter.sample_rate:
                return False

        # Check session limit
        if self.config.filter.max_per_session is not None:
            session_key = ctx.session_id or "default"
            count = self._session_counts.get(session_key, 0)
            if count >= self.config.filter.max_per_session:
                return False

        return True

    def should_record(self, ctx: MiddlewareContext, error: Exception | None = None) -> bool:
        """Public wrapper around the record-filter decision."""
        return self._should_record(ctx, error)

    def _generate_name(self, ctx: MiddlewareContext) -> str:
        """Generate a name for the test case."""
        if self.config.name_generator:
            return self.config.name_generator(ctx.tool, ctx.inputs)

        # Default: tool_timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"{ctx.tool}_{timestamp}"

    def _generate_assertions(self, result: Any) -> list[dict]:
        """Generate assertions from the result."""
        if not self.config.auto_assertions:
            return []

        assertions: list[dict[str, Any]] = []

        if result is None:
            assertions.append(
                {"type": "equals", "expected": None, "description": "Result should be None"}
            )
        elif isinstance(result, bool):
            assertions.append(
                {"type": "equals", "expected": result, "description": f"Result should be {result}"}
            )
        elif isinstance(result, (int, float)):
            assertions.append(
                {
                    "type": "type_check",
                    "expected_type": "number",
                    "description": "Result should be a number",
                }
            )
        elif isinstance(result, str):
            assertions.append(
                {
                    "type": "type_check",
                    "expected_type": "string",
                    "description": "Result should be a string",
                }
            )
            if len(result) < 100:
                assertions.append(
                    {
                        "type": "contains",
                        "expected": result[:50] if len(result) > 50 else result,
                        "description": "Result should contain expected content",
                    }
                )
        elif isinstance(result, dict):
            assertions.append(
                {
                    "type": "type_check",
                    "expected_type": "object",
                    "description": "Result should be an object",
                }
            )
            # Add assertions for top-level keys
            for key in list(result.keys())[:5]:  # Max 5 key assertions
                assertions.append(
                    {
                        "type": "json_path",
                        "path": f"$.{key}",
                        "description": f"Result should have '{key}' field",
                    }
                )
        elif isinstance(result, list):
            assertions.append(
                {
                    "type": "type_check",
                    "expected_type": "array",
                    "description": "Result should be an array",
                }
            )

        return assertions

    def generate_assertions(self, result: Any) -> list[dict]:
        """Public wrapper around automatic assertion generation."""
        return self._generate_assertions(result)

    def _serialize_result(self, result: Any) -> dict | None:
        """Serialize result for storage."""
        try:
            # Try direct JSON serialization
            json.dumps(result)
            return {"value": result}
        except (TypeError, ValueError):
            # Fall back to string representation
            return {"value": str(result), "_serialized": True}

    def serialize_result(self, result: Any) -> dict | None:
        """Public wrapper around result serialization."""
        return self._serialize_result(result)

    def after(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """Record successful calls to the dataset (sync version)."""
        if not self._should_record(ctx, error):
            return

        # Run async recording in a new event loop if needed
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Schedule as task (fire-and-forget)
                asyncio.create_task(self._record_test_case(ctx, result))
            else:
                loop.run_until_complete(self._record_test_case(ctx, result))
        except RuntimeError:
            # No event loop - create one
            asyncio.run(self._record_test_case(ctx, result))

    async def aafter(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """Record successful calls to the dataset (async version)."""
        if not self._should_record(ctx, error):
            return

        await self._record_test_case(ctx, result)

    async def _record_test_case(self, ctx: MiddlewareContext, result: Any) -> None:
        """Send test case to dashboard API."""
        try:
            # Capture PII metadata for before/after view in dashboard
            pii_metadata = {}
            if "pii_original_inputs" in ctx.metadata:
                pii_metadata["original_inputs"] = ctx.metadata["pii_original_inputs"]
            if "pii_redacted" in ctx.metadata:
                pii_metadata["redacted"] = ctx.metadata["pii_redacted"]
            if "pii_rehydrated" in ctx.metadata:
                pii_metadata["rehydrated"] = ctx.metadata["pii_rehydrated"]

            # Prepare test case data
            test_case_data = {
                "name": self._generate_name(ctx),
                "inputs": ctx.inputs,
                "expected_output": self._serialize_result(result),
                "assertions": self._generate_assertions(result),
                "tags": self.config.tags,
            }

            # Add PII metadata if present (enables before/after view in dashboard)
            if pii_metadata:
                test_case_data["pii_metadata"] = pii_metadata

            # Add source trace if available
            if ctx.trace and hasattr(ctx.trace, "id"):
                test_case_data["source_trace_id"] = ctx.trace.id

            # Send to dashboard
            if httpx is None:
                return
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.config.dashboard_url}/api/datasets/{self.config.dataset_id}/tests",
                    json=test_case_data,
                    timeout=10.0,
                )

                if response.status_code == 201:
                    # Update session counter
                    session_key = ctx.session_id or "default"
                    self._session_counts[session_key] = self._session_counts.get(session_key, 0) + 1

        except (OSError, RuntimeError, ValueError, KeyError):
            # Don't fail the main request if recording fails
            pass

    def is_async_native(self) -> bool:
        """This middleware has native async support."""
        return True

    def reset_session_counts(self) -> None:
        """Reset session counters."""
        self._session_counts.clear()


class DatasetRecorderContext:
    """
    Context manager for scoped dataset recording.

    Temporarily enables recording for a specific scope,
    useful for capturing specific interactions.

    Example:
        recorder = DatasetRecorder(dataset_id=1)
        agent = Agent(middlewares=[recorder])

        # Normal calls - recorded per config
        agent.run("search", query="test")

        # Scoped recording - record everything in this block
        with DatasetRecorderContext(recorder, sample_rate=1.0, tool_filter=[]):
            agent.run("process", data="important")
            agent.run("validate", result=result)
    """

    def __init__(
        self,
        recorder: DatasetRecorder,
        sample_rate: float | None = None,
        tool_filter: list[str] | None = None,
        only_success: bool | None = None,
    ):
        self.recorder = recorder
        self._original_config: dict = {}

        # Store overrides
        if sample_rate is not None:
            self._original_config["sample_rate"] = recorder.config.filter.sample_rate
            recorder.config.filter.sample_rate = sample_rate

        if tool_filter is not None:
            self._original_config["tool_filter"] = recorder.config.filter.tool_filter
            recorder.config.filter.tool_filter = tool_filter

        if only_success is not None:
            self._original_config["only_success"] = recorder.config.filter.only_success
            recorder.config.filter.only_success = only_success

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original config
        for key, value in self._original_config.items():
            setattr(self.recorder.config.filter, key, value)
        return False


__all__ = [
    "RecordingConfig",
    "RecordingFilterConfig",
    "DatasetRecorder",
    "DatasetRecorderContext",
]
