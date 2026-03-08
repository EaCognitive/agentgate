"""Database utility helpers for sync/async session compatibility."""

from __future__ import annotations

import inspect
from typing import Any


async def _maybe_await(result: Any) -> Any:
    """Await result if it's awaitable, otherwise return directly."""
    if inspect.isawaitable(result):
        return await result
    return result


async def execute(session: Any, statement: Any) -> Any:
    """Execute a SQL statement on sync or async sessions."""
    if hasattr(session, "execute"):
        return await _maybe_await(session.execute(statement))
    if hasattr(type(session), "exec"):
        return await _maybe_await(session.exec(statement))
    if hasattr(session, "exec"):
        return await _maybe_await(session.exec(statement))
    raise TypeError("Session does not support execute/exec")


async def get(session: Any, model: Any, identity: Any) -> Any:
    """Fetch a single entity by primary key on sync or async sessions."""
    if not hasattr(session, "get"):
        raise TypeError("Session does not support get")
    return await _maybe_await(session.get(model, identity))


async def commit(session: Any) -> None:
    """Commit transaction on sync or async sessions."""
    if not hasattr(session, "commit"):
        raise TypeError("Session does not support commit")
    await _maybe_await(session.commit())


async def flush(session: Any) -> None:
    """Flush pending changes on sync or async sessions."""
    if not hasattr(session, "flush"):
        raise TypeError("Session does not support flush")
    await _maybe_await(session.flush())


async def delete(session: Any, instance: Any) -> None:
    """Delete instance on sync or async sessions."""
    if not hasattr(session, "delete"):
        raise TypeError("Session does not support delete")
    await _maybe_await(session.delete(instance))


async def refresh(session: Any, instance: Any) -> None:
    """Refresh instance state on sync or async sessions."""
    if not hasattr(session, "refresh"):
        raise TypeError("Session does not support refresh")
    await _maybe_await(session.refresh(instance))


async def rollback(session: Any) -> None:
    """Rollback transaction on sync or async sessions."""
    if not hasattr(session, "rollback"):
        raise TypeError("Session does not support rollback")
    await _maybe_await(session.rollback())
