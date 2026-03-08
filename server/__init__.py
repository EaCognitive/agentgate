"""AgentGate Dashboard Server."""

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .main import app


def __getattr__(name: str):
    """Lazy import to avoid circular imports."""
    if name == "app":
        main_module = importlib.import_module(".main", __name__)
        return main_module.app
    if name == "main":
        return importlib.import_module(".main", __name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["app"]  # pylint: disable=undefined-all-variable
