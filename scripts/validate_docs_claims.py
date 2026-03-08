#!/usr/bin/env python3
"""Validate docs endpoint and code-path claims against the current repository."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = REPO_ROOT / "docs"
LOCAL_PREFIX = str(REPO_ROOT) + "/"

ENDPOINT_PATTERN = re.compile(
    r"/api(?:/[A-Za-z0-9._{}\-/]+)+|/health/(?:liveness|readiness)|/metrics"
)
FILE_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"((?:ea_agentgate|server|dashboard|scripts|tests|docs|deploy|docker|alembic)"
    r"/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+)"
)
ABS_FILE_PATH_PATTERN = re.compile(r"(/Users/[^\\s`\"')]+)")
TRAILING_PUNCTUATION = ".,);]`\"'"
PATH_SUFFIX_ALLOWLIST = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".md",
        ".yaml",
        ".yml",
        ".toml",
        ".sh",
        ".sql",
    }
)
ENDPOINT_SKIP_MARKERS = (
    "not currently exposed",
    "not mounted",
    "not present in the current api",
    "historical",
)


@dataclass(frozen=True)
class DocFinding:
    """A single docs validation finding."""

    file_path: str
    line_no: int
    kind: str
    value: str


def _dashboard_route_to_api_path(route_file: Path) -> str:
    """Map a Next.js `route.ts` file path to a concrete `/api/...` route."""
    relative = route_file.relative_to(REPO_ROOT / "dashboard" / "src" / "app" / "api")
    parts: list[str] = []
    for part in relative.parts[:-1]:
        if part.startswith("[[...") and part.endswith("]]"):
            parts.append("{" + part[5:-2] + "*}")
            continue
        if part.startswith("[...") and part.endswith("]"):
            parts.append("{" + part[4:-1] + "+}")
            continue
        if part.startswith("[") and part.endswith("]"):
            parts.append("{" + part[1:-1] + "}")
            continue
        parts.append(part)
    return "/api/" + "/".join(parts)


def load_known_routes() -> tuple[set[str], list[re.Pattern[str]]]:
    """Load backend + dashboard API routes and precompiled matchers."""
    app = import_module("server.main").app

    routes: set[str] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        if path:
            routes.add(path)

    api_routes_root = REPO_ROOT / "dashboard" / "src" / "app" / "api"
    for route_file in api_routes_root.rglob("route.ts"):
        routes.add(_dashboard_route_to_api_path(route_file))

    route_matchers: list[re.Pattern[str]] = []
    for route in routes:
        pattern = "^" + re.escape(route) + "$"
        pattern = re.sub(r"\\\{[A-Za-z0-9_]+\*\\\}", r".+", pattern)
        pattern = re.sub(r"\\\{[A-Za-z0-9_]+\+\\\}", r"[^/]+(?:/[^/]+)*", pattern)
        pattern = re.sub(r"\\\{[A-Za-z0-9_]+\\\}", r"[^/]+", pattern)
        route_matchers.append(re.compile(pattern))
    return routes, route_matchers


def _line_has_skip_marker(line_text: str) -> bool:
    """Return True when endpoint validation should be skipped for this line."""
    lowered = line_text.lower()
    if any(marker in lowered for marker in ENDPOINT_SKIP_MARKERS):
        return True
    if "not" in lowered and "mounted" in lowered:
        return True
    if "not" in lowered and "exposed" in lowered:
        return True
    return False


def _endpoint_is_known(
    endpoint: str,
    line_text: str,
    routes: set[str],
    route_matchers: list[re.Pattern[str]],
) -> bool:
    """Return True when an endpoint claim maps to a known route."""
    if endpoint in routes:
        return True

    # Allow mounted prefix claims (for example: `/api/pii` in router-mount docs).
    prefix = endpoint.rstrip("/")
    if prefix.endswith(("/api", "/auth", "/security", "/datasets", "/pii", "/policies")):
        if any(route.startswith(prefix + "/") for route in routes):
            return True
    if "/*" in line_text and any(route.startswith(prefix + "/") for route in routes):
        return True

    return any(matcher.match(endpoint) for matcher in route_matchers)


def _normalize_doc_path(raw_path: str) -> str:
    """Normalize file-path claims to repo-relative values when possible."""
    path = raw_path.rstrip(TRAILING_PUNCTUATION)
    if path.startswith(LOCAL_PREFIX):
        return path[len(LOCAL_PREFIX) :]
    return path


def _should_validate_file_path(path_claim: str) -> bool:
    """Return True when a file-path claim should be existence-validated."""
    suffix = Path(path_claim).suffix.lower()
    if suffix not in PATH_SUFFIX_ALLOWLIST:
        return False
    if path_claim.startswith("tests/artifacts/"):
        return False
    if any(token in path_claim for token in ("<", ">", "$", "...", "{", "}", "*")):
        return False
    return True


def validate_docs() -> list[DocFinding]:
    """Validate all markdown docs and return any findings."""
    routes, route_matchers = load_known_routes()
    findings: list[DocFinding] = []

    for doc_file in sorted(DOCS_ROOT.rglob("*.md")):
        lines = doc_file.read_text(encoding="utf-8").splitlines()
        for line_no, line_text in enumerate(lines, start=1):
            if not _line_has_skip_marker(line_text):
                for endpoint_match in ENDPOINT_PATTERN.finditer(line_text):
                    endpoint = endpoint_match.group(0).rstrip(TRAILING_PUNCTUATION)
                    if _endpoint_is_known(endpoint, line_text, routes, route_matchers):
                        continue
                    findings.append(
                        DocFinding(
                            file_path=str(doc_file.relative_to(REPO_ROOT)),
                            line_no=line_no,
                            kind="endpoint",
                            value=endpoint,
                        )
                    )

            path_matches = list(FILE_PATH_PATTERN.finditer(line_text))
            path_matches.extend(ABS_FILE_PATH_PATTERN.finditer(line_text))
            for path_match in path_matches:
                normalized = _normalize_doc_path(path_match.group(1))
                if not _should_validate_file_path(normalized):
                    continue
                if (REPO_ROOT / normalized).exists():
                    continue
                findings.append(
                    DocFinding(
                        file_path=str(doc_file.relative_to(REPO_ROOT)),
                        line_no=line_no,
                        kind="path",
                        value=normalized,
                    )
                )
    return findings


def main() -> int:
    """CLI entrypoint."""
    docs_count = len(list(DOCS_ROOT.rglob("*.md")))
    findings = validate_docs()
    if not findings:
        print(
            "Docs claims validation passed: "
            f"no endpoint/path drift detected across {docs_count} docs files."
        )
        return 0

    print(
        f"Docs claims validation failed: {len(findings)} findings across {docs_count} docs files."
    )
    for finding in findings:
        print(f"- {finding.file_path}:{finding.line_no} [{finding.kind}] {finding.value}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
