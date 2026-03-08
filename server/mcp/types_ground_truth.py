"""Ground-truth schema contracts for MCP synchronous and asynchronous responses."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """Lifecycle status for asynchronous MCP operations."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REQUIRES_INPUT = "requires_input"


class JobResponse(BaseModel):
    """Serialized job state returned to MCP callers for async workflows."""

    job_id: str = Field(min_length=1)
    status: JobStatus
    progress_pct: int = Field(ge=0, le=100)
    message: str = Field(default="")
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    requires_input_payload: dict[str, Any] | None = None
    started_at: datetime
    updated_at: datetime
    operation: str = Field(min_length=1)
    request_id: str = Field(min_length=1)


class ToolEnvelope(BaseModel):
    """Unified MCP response envelope for synchronous and async-capable tools."""

    success: bool
    operation: str = Field(min_length=1)
    mode: Literal["sync", "async"]
    request_id: str = Field(min_length=1)
    job: JobResponse | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
