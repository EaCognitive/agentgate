"""Tests for route access-mode metadata validation helpers."""

from __future__ import annotations

import pytest
from fastapi import APIRouter, FastAPI

from server.routers.access_mode import route_access_mode, validate_route_access_modes


def _build_app_with_single_route(path: str, method: str = "get") -> FastAPI:
    app = FastAPI()
    router = APIRouter()

    if method == "get":

        @router.get(path)
        async def _handler() -> dict[str, str]:
            return {"status": "ok"}

    elif method == "post":

        @router.post(path)
        async def _handler() -> dict[str, str]:
            return {"status": "ok"}

    else:
        raise ValueError(f"Unsupported method: {method}")

    app.include_router(router)
    return app


def test_route_access_mode_sets_metadata_on_function() -> None:
    """Decorator should attach explicit mode metadata to endpoint callables."""

    @route_access_mode("read_only")
    async def endpoint() -> None:
        return None

    assert getattr(endpoint, "__agentgate_access_mode__") == "read_only"


def test_route_access_mode_rejects_unknown_mode() -> None:
    """Decorator factory must reject unsupported mode values."""
    with pytest.raises(ValueError, match="Unsupported route access mode"):
        route_access_mode("read")


def test_validate_route_access_modes_accepts_annotated_protected_routes() -> None:
    """Protected routes with compatible method contracts should pass validation."""
    app = FastAPI()
    router = APIRouter()

    @router.get("/api/audit")
    @route_access_mode("read_only")
    async def list_audit() -> dict[str, str]:
        return {"status": "ok"}

    @router.post("/api/approvals")
    @route_access_mode("write_only")
    async def create_approval() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(router)

    validate_route_access_modes(app)


def test_validate_route_access_modes_fails_for_missing_annotations() -> None:
    """Protected routes without access-mode annotations must fail startup checks."""
    app = _build_app_with_single_route("/api/audit", method="get")

    with pytest.raises(RuntimeError, match="Missing access mode annotations"):
        validate_route_access_modes(app)


def test_validate_route_access_modes_fails_for_incompatible_contract() -> None:
    """Route method and declared mode must remain contract-compatible."""
    app = FastAPI()
    router = APIRouter()

    @router.get("/api/audit")
    @route_access_mode("write_only")
    async def list_audit() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(router)

    with pytest.raises(RuntimeError, match="Invalid access mode contracts"):
        validate_route_access_modes(app)
