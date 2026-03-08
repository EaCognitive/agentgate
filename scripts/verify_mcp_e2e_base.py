"""AgentGate MCP E2E -- base classes, constants, and utilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

BASE_URL = "http://127.0.0.1:8000"
TEST_EMAIL = "admin@admin.com"
TEST_PASSWORD = "password"
TEST_NAME = "Admin"
BLOCK_IP = "198.51.100.99"
TIMEOUT = 30.0
TOOL_COUNT = 49
RES_COUNT = 6
DENIED = frozenset({403})
HANDLED_ERRORS = (
    AttributeError,
    ImportError,
    KeyError,
    RuntimeError,
    TypeError,
    ValueError,
    httpx.HTTPError,
)


class V(str, Enum):
    """Check verdict."""

    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class CR:
    """Single check result."""

    phase: int
    domain: str
    name: str
    verdict: V
    detail: str = ""


@dataclass
class PR:
    """Phase report."""

    phase: int
    domain: str
    results: list[CR] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Total checks."""
        return len(self.results)

    @property
    def passed(self) -> int:
        """Passed checks."""
        return sum(1 for r in self.results if r.verdict == V.PASS)

    @property
    def failed(self) -> int:
        """Failed checks."""
        return sum(1 for r in self.results if r.verdict == V.FAIL)

    @property
    def ok(self) -> bool:
        """True when zero failures."""
        return self.failed == 0


def _dots(label: str, w: int = 52) -> str:
    """Pad label with dots for aligned output."""
    return label + " " + "." * max(1, w - len(label))


def _emit(r: CR) -> None:
    """Print one check result."""
    tag = f"[Phase {r.phase}] {r.domain}: {r.name}"
    line = f"  {_dots(tag)} {r.verdict.value}"
    if r.detail:
        line += f" ({r.detail})"
    print(line)


class Agent:
    """Base domain verification agent."""

    phase: int = 0
    domain: str = "Base"

    def __init__(
        self,
        c: httpx.AsyncClient,
        ctx: dict[str, Any],
    ) -> None:
        self._c = c
        self._ctx = ctx
        self._rs: list[CR] = []

    def _r(self, n: str, v: V, d: str = "") -> None:
        """Record and print a check."""
        cr = CR(self.phase, self.domain, n, v, d)
        self._rs.append(cr)
        _emit(cr)

    def _ok(self, n: str, d: str = "") -> None:
        """Record a passing check."""
        self._r(n, V.PASS, d)

    def _fl(self, n: str, d: str = "") -> None:
        """Record a failing check."""
        self._r(n, V.FAIL, d)

    def _sk(self, n: str, d: str = "") -> None:
        """Record a skipped check."""
        self._r(n, V.SKIP, d)

    def results(self) -> list[CR]:
        """Return a snapshot of accumulated check results."""
        return list(self._rs)

    def _h(self) -> dict[str, str]:
        """Auth headers."""
        return {
            "Authorization": (f"Bearer {self._ctx.get('access_token', '')}"),
        }

    async def _get(
        self,
        p: str,
        params: dict | None = None,
    ) -> httpx.Response:
        """Perform authenticated GET request."""
        return await self._c.get(
            p,
            headers=self._h(),
            params=params,
        )

    async def _post(
        self,
        p: str,
        body: dict | None = None,
    ) -> httpx.Response:
        """Perform authenticated POST request."""
        return await self._c.post(
            p,
            headers=self._h(),
            json=body,
        )

    async def _del(self, p: str) -> httpx.Response:
        """Perform authenticated DELETE request."""
        return await self._c.delete(p, headers=self._h())

    async def _pat(
        self,
        p: str,
        body: dict | None = None,
    ) -> httpx.Response:
        """Perform authenticated PATCH request."""
        return await self._c.patch(
            p,
            headers=self._h(),
            json=body,
        )

    async def _cg(
        self,
        name: str,
        path: str,
        *,
        params: dict | None = None,
        key: str | None = None,
        lst: bool = False,
    ) -> httpx.Response | None:
        """Standard GET check."""
        try:
            resp = await self._get(path, params=params)
        except HANDLED_ERRORS as exc:
            self._fl(name, str(exc))
            return None
        if resp.status_code in DENIED:
            self._sk(name, "insufficient permissions")
            return resp
        if resp.status_code >= 400:
            self._fl(name, f"HTTP {resp.status_code}")
            return resp
        data = resp.json()
        if lst and not isinstance(data, list):
            self._fl(name, "expected list")
            return resp
        if key and key not in data:
            self._fl(name, f"missing key: {key}")
            return resp
        self._ok(name)
        return resp

    async def run(self) -> PR:
        """Execute checks and return report."""
        await self._execute()
        return PR(self.phase, self.domain, list(self._rs))

    async def _execute(self) -> None:
        """Override in subclasses."""
