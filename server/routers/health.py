"""Health and readiness endpoints for runtime probe orchestration."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ea_agentgate import __version__ as AGENTGATE_VERSION
from server.db.readiness import evaluate_readiness
from server.policy_governance.kernel.distributed_health_monitor import (
    get_distributed_health_monitor_snapshot,
)

router = APIRouter(tags=["health"])


@router.get("/health/liveness")
async def health_liveness() -> dict[str, Any]:
    """Liveness probe with zero dependency checks."""
    return {
        "status": "alive",
        "version": AGENTGATE_VERSION,
    }


async def _build_readiness_response() -> JSONResponse:
    report = await evaluate_readiness()
    payload = {
        "status": "healthy" if report.ready else "unhealthy",
        "readiness": "ready" if report.ready else "not_ready",
        "version": AGENTGATE_VERSION,
        "profile": report.profile,
        "checks": report.checks,
        "distributed_health_monitor": get_distributed_health_monitor_snapshot(),
    }
    status_code = 200 if report.ready else 503
    return JSONResponse(status_code=status_code, content=payload)


@router.get("/health/readiness")
async def health_readiness() -> JSONResponse:
    """Readiness probe with dependency and schema checks."""
    return await _build_readiness_response()


@router.get("/api/health")
async def health_readiness_alias() -> JSONResponse:
    """Backward-compatible readiness alias."""
    return await _build_readiness_response()


@router.get("/api/health/distributed")
async def distributed_health_status() -> dict[str, Any]:
    """Distributed health monitor status endpoint."""
    return get_distributed_health_monitor_snapshot()
