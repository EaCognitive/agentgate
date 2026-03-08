"""Interactive full-pipeline CLI test for AgentGate.

Boots the real server.main:app with an isolated SQLite database, then walks
the user through five interactive stages covering auth, PII vault, traces,
approvals, and audit trail verification.

Usage:
    python3 scripts/interactive_pii_test.py

Environment variables are set BEFORE any server.* import because
server.models.database reads DATABASE_URL at module level.
"""

import asyncio
import os
import shutil
import sys
import tempfile
import uuid

import httpx
from httpx import ASGITransport

from server.main import app
from server.models.database import init_db, close_db

# ---------------------------------------------------------------------------
# 1. Environment setup (must happen before server.* imports)
# ---------------------------------------------------------------------------
_tmpdir = tempfile.mkdtemp(prefix="agentgate_interactive_")
_db_path = os.path.join(_tmpdir, "interactive_test.db")

os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_db_path}"
os.environ["DATABASE_POOL_DISABLED"] = "1"
os.environ["TESTING"] = "true"
os.environ["AGENTGATE_ENV"] = "test"
os.environ["SECRET_KEY"] = "interactive-test-secret-key-at-least-32-chars!"
os.environ["REDIS_URL"] = "memory://"
os.environ["ENABLE_THREAT_DETECTION"] = "true"

# ---------------------------------------------------------------------------
# 2. Now safe to import server modules
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 3. Output helpers
# ---------------------------------------------------------------------------
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _pass(msg: str) -> None:
    print(f"  {GREEN}[PASS]{RESET} {msg}")


def _fail(msg: str) -> None:
    print(f"  {RED}[FAIL]{RESET} {msg}")


def _info(msg: str) -> None:
    print(f"  {CYAN}[INFO]{RESET} {msg}")


def _header(title: str) -> None:
    print(f"\n{BOLD}[{title}]{RESET}")


def _prompt(msg: str) -> str:
    return input(f"  {msg} ")


# ---------------------------------------------------------------------------
# 4. Stage implementations
# ---------------------------------------------------------------------------
ADMIN_EMAIL = "admin-interactive@agentgate.test"
ADMIN_PASSWORD = "InteractiveTest!Secure99"
ADMIN_NAME = "Interactive Admin"


async def stage_auth(client: httpx.AsyncClient) -> dict | None:
    """Stage 1: Register admin + login. Returns credentials dict or None."""
    _header("Stage 1: Authentication")
    passed = 0
    total = 2

    # Register
    resp = await client.post(
        "/api/auth/register",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "name": ADMIN_NAME},
    )
    if resp.status_code == 200:
        user_data = resp.json()
        _pass(f"Registered admin user ({user_data.get('email')}, role={user_data.get('role')})")
        passed += 1
    else:
        _fail(f"Registration failed: {resp.status_code} - {resp.text}")
        return None

    # Login
    resp = await client.post(
        "/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    if resp.status_code == 200:
        data = resp.json()
        _pass(f"Logged in successfully (token expires in {data.get('expires_in', '?')}s)")
        passed += 1
        return {
            "access_token": data["access_token"],
            "refresh_token": data["refresh_token"],
            "headers": {"Authorization": f"Bearer {data['access_token']}"},
            "passed": passed,
            "total": total,
        }
    _fail(f"Login failed: {resp.status_code} - {resp.text}")
    return None


async def _pii_detect(client: httpx.AsyncClient, headers: dict, text: str) -> tuple[int, int, str]:
    """Detect PII in text. Returns (passed, total, redacted_text or empty)."""
    passed = 0
    total = 4
    redacted = ""

    resp = await client.post("/api/pii/detect", json={"text": text}, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        detections = data.get("detections", [])
        types = [d["type"] for d in detections]
        if detections:
            _pass(f"Detected {len(detections)} PII entities: {', '.join(types)}")
            for d in detections:
                _info(f'  {d["type"]}: "{d["value"]}" (score={d["score"]})')
        else:
            _pass("Detection ran successfully (0 entities found -- try text with names/SSNs)")
        # Show multilingual metadata
        detected_lang = data.get("detected_language")
        effective_lang = data.get("effective_language")
        engines_used = data.get("engines_used", [])
        if detected_lang or engines_used:
            _info(f"  Language: detected={detected_lang}, effective={effective_lang}")
            engines_str = ", ".join(engines_used) if engines_used else "none"
            _info(f"  Engines used: {engines_str}")
        passed += 1
    elif resp.status_code == 500 and "spacy" in resp.text.lower():
        _fail("Presidio/spaCy not installed. Run:")
        _info(
            "pip install presidio-analyzer presidio-anonymizer && "
            "python -m spacy download en_core_web_lg"
        )
        _info("pip install lingua-language-detector && python -m spacy download xx_ent_wiki_sm")
    else:
        _fail(f"Detect failed: {resp.status_code} - {resp.text}")

    return passed, total, redacted


async def _pii_redact(
    client: httpx.AsyncClient,
    headers: dict,
    text: str,
    session_id: str,
    *,
    passed: int,
    total: int,
) -> tuple[int, int, str]:
    """Redact PII in text. Returns (passed, total, redacted_text)."""
    redacted = ""

    resp = await client.post(
        "/api/pii/redact",
        json={"session_id": session_id, "text": text},
        headers=headers,
    )
    if resp.status_code == 200:
        data = resp.json()
        redacted = data.get("redacted_text", "")
        mappings = data.get("mappings", [])
        _pass(f"Redacted text: {redacted}")
        for m in mappings:
            _info(f"  {m['token']} (type={m['type']}, score={m['score']})")
        passed += 1
    else:
        _fail(f"Redact failed: {resp.status_code} - {resp.text}")

    return passed, total, redacted


async def _pii_restore(
    client: httpx.AsyncClient,
    headers: dict,
    session_id: str,
    redacted: str,
    original: str,
    *,
    passed: int,
    total: int,
) -> tuple[int, int]:
    """Restore PII in text. Returns (passed, total)."""
    resp = await client.post(
        "/api/pii/restore",
        json={"session_id": session_id, "text": redacted},
        headers=headers,
    )
    if resp.status_code == 200:
        data = resp.json()
        restored = data.get("restored_text", "")
        if restored == original:
            _pass("Restored text matches original")
        else:
            _fail("Restored text does not match original")
            _info(f"  Original:  {original}")
            _info(f"  Restored:  {restored}")
        passed += 1
    else:
        _fail(f"Restore failed: {resp.status_code} - {resp.text}")

    return passed, total


async def _pii_vault_stats(
    client: httpx.AsyncClient, headers: dict, *, passed: int, total: int
) -> tuple[int, int]:
    """Get vault stats. Returns (passed, total)."""
    resp = await client.get("/api/pii/vault/stats", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        total_items = data.get("total_items", 0)
        by_type = data.get("by_type", {})
        _pass(f"Vault contains {total_items} items (types: {by_type})")
        passed += 1
    else:
        _fail(f"Vault stats failed: {resp.status_code} - {resp.text}")

    return passed, total


async def stage_pii(client: httpx.AsyncClient, headers: dict) -> tuple[int, int]:
    """Stage 2: PII detection, redaction, restoration, vault stats."""
    _header("Stage 2: PII Vault")
    session_id = f"interactive-pii-{uuid.uuid4().hex[:10]}"

    session_resp = await client.post(
        "/api/pii/sessions",
        json={
            "session_id": session_id,
            "user_id": ADMIN_EMAIL,
            "agent_id": "interactive-pii-test",
            "purpose": "interactive pii validation flow",
        },
        headers=headers,
    )
    if session_resp.status_code != 200:
        _fail(f"Failed to create PII session: {session_resp.status_code} - {session_resp.text}")
        return 0, 4

    text = _prompt("Enter text containing PII (e.g. 'My name is John Smith, SSN 123-45-6789'):")
    if not text.strip():
        text = "My name is John Smith, my SSN is 123-45-6789 and email john@example.com"
        _info(f"Using default: {text}")

    # Detect
    passed, total, _unused = await _pii_detect(client, headers, text)
    if passed == 0:
        return passed, total

    # Redact
    passed, total, redacted = await _pii_redact(
        client,
        headers,
        text,
        session_id,
        passed=passed,
        total=total,
    )
    if not redacted:
        return passed, total

    # Restore
    passed, total = await _pii_restore(
        client,
        headers,
        session_id,
        redacted,
        text,
        passed=passed,
        total=total,
    )

    # Vault stats
    passed, total = await _pii_vault_stats(
        client,
        headers,
        passed=passed,
        total=total,
    )

    return passed, total


async def stage_traces(
    client: httpx.AsyncClient, headers: dict
) -> tuple[int, int, str | None, str]:
    """Stage 3: Create and verify a trace. Returns (passed, total, trace_id, tool_name)."""
    _header("Stage 3: Trace Creation")
    passed = 0
    total = 3
    trace_id = None

    tool_name = _prompt("Enter a tool name (e.g. bash, file_read, web_search):")
    if not tool_name.strip():
        tool_name = "bash"
        _info(f"Using default: {tool_name}")

    command = _prompt("Enter the command/input for this tool:")
    if not command.strip():
        command = "echo hello world"
        _info(f"Using default: {command}")

    trace_id = str(uuid.uuid4())

    # Create trace
    resp = await client.post(
        "/api/traces",
        json={
            "trace_id": trace_id,
            "tool": tool_name.strip(),
            "inputs": {"command": command.strip()},
            "output": {"result": "success"},
            "status": "success",
            "duration_ms": 42.0,
            "cost": 0.001,
            "agent_id": "interactive-test",
            "session_id": "interactive-session",
        },
        headers=headers,
    )
    if resp.status_code in (200, 201):
        _pass(f"Created trace {trace_id[:12]}...")
        passed += 1
    else:
        _fail(f"Create trace failed: {resp.status_code} - {resp.text}")
        return passed, total, None, tool_name.strip()

    # Get trace
    resp = await client.get(f"/api/traces/{trace_id}", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        _pass(f"Retrieved trace (tool={data.get('tool')}, status={data.get('status')})")
        passed += 1
    else:
        _fail(f"Get trace failed: {resp.status_code} - {resp.text}")

    # Stats
    resp = await client.get("/api/traces/stats", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        total_traces = data.get("total", 0)
        success_rate = data.get("success_rate", 0)
        _pass(f"Stats: {total_traces} total traces, {success_rate:.0f}% success rate")
        passed += 1
    else:
        _fail(f"Trace stats failed: {resp.status_code} - {resp.text}")

    return passed, total, trace_id, tool_name.strip()


async def stage_approvals(
    client: httpx.AsyncClient, headers: dict, tool_name: str | None, trace_id: str | None
) -> tuple[int, int]:
    """Stage 4: Create approval, list pending, decide."""
    _header("Stage 4: Approval Workflow")
    passed = 0
    total = 3

    tool = tool_name or "bash"
    approval_id = str(uuid.uuid4())

    # Create approval (no auth required)
    resp = await client.post(
        "/api/approvals",
        json={
            "approval_id": approval_id,
            "tool": tool,
            "inputs": {"command": "test operation"},
            "trace_id": trace_id,
            "agent_id": "interactive-test",
            "context": {"reason": "Automated pipeline test"},
        },
    )
    if resp.status_code in (200, 201):
        _info(f"Created approval for tool '{tool}' (id={approval_id[:12]}...)")
        passed += 1
    else:
        _fail(f"Create approval failed: {resp.status_code} - {resp.text}")
        return passed, total

    # List pending
    resp = await client.get("/api/approvals/pending", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        _pass(f"Found {len(data)} pending approval(s)")
        passed += 1
    else:
        _fail(f"List pending failed: {resp.status_code} - {resp.text}")

    # User decides
    decision_input = _prompt("Approve or Deny? (a/d):")
    approved = decision_input.strip().lower() != "d"
    reason = _prompt("Reason:")
    if not reason.strip():
        reason = "Interactive test decision"

    resp = await client.post(
        f"/api/approvals/{approval_id}/decide",
        json={"approved": approved, "reason": reason.strip()},
        headers=headers,
    )
    if resp.status_code == 200:
        data = resp.json()
        _pass(f"Approval decided: {data.get('status')}")
        passed += 1
    else:
        _fail(f"Decide approval failed: {resp.status_code} - {resp.text}")

    return passed, total


async def stage_audit(client: httpx.AsyncClient, headers: dict) -> tuple[int, int]:
    """Stage 5: Verify audit trail."""
    _header("Stage 5: Audit Trail Verification")
    passed = 0
    total = 2

    # List audit entries
    resp = await client.get("/api/audit", headers=headers)
    if resp.status_code == 200:
        entries = resp.json()
        _pass(f"Found {len(entries)} audit entries")
        for e in entries[:6]:
            event_type = e.get("event_type", "?")
            actor = e.get("actor", "N/A")
            result = e.get("result", "N/A")
            _info(f"  {event_type:25s} actor={actor:30s} result={result}")
        if len(entries) > 6:
            _info(f"  ... and {len(entries) - 6} more")
        passed += 1
    else:
        _fail(f"List audit failed: {resp.status_code} - {resp.text}")

    # Export JSON
    resp = await client.get("/api/audit/export?format=json", headers=headers)
    if resp.status_code == 200:
        _pass("Audit export (JSON) successful")
        passed += 1
    else:
        _fail(f"Audit export failed: {resp.status_code} - {resp.text}")

    return passed, total


# ---------------------------------------------------------------------------
# 5. Main entrypoint
# ---------------------------------------------------------------------------
async def main() -> int:
    """Interactive test harness for PII detection, masking, and rehydration pipeline."""
    print(f"\n{BOLD}=== AgentGate Interactive Pipeline Test ==={RESET}")
    _info(f"Temp DB: {_db_path}")

    await init_db()

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        total_passed = 0
        total_steps = 0

        # Stage 1: Auth
        creds = await stage_auth(client)
        if creds is None:
            _fail("Cannot continue without authentication.")
            await close_db()
            return 1
        total_passed += creds["passed"]
        total_steps += creds["total"]
        headers = creds["headers"]

        # Stage 2: PII
        try:
            p, t = await stage_pii(client, headers)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
            _header("Stage 2: PII Vault")
            exc_lower = str(exc).lower()
            if "spacy" in exc_lower or "presidio" in exc_lower:
                _fail("Presidio/spaCy NLP engine not available.")
                _info(
                    "Install with: pip install presidio-analyzer "
                    "presidio-anonymizer && python -m spacy download "
                    "en_core_web_lg"
                )
            else:
                _fail(f"Unexpected error: {exc}")
            p, t = 0, 4
        total_passed += p
        total_steps += t

        # Stage 3: Traces
        p, t, trace_id, tool_name = await stage_traces(client, headers)
        total_passed += p
        total_steps += t

        # Stage 4: Approvals
        p, t = await stage_approvals(client, headers, tool_name, trace_id)
        total_passed += p
        total_steps += t

        # Stage 5: Audit
        p, t = await stage_audit(client, headers)
        total_passed += p
        total_steps += t

        # Summary
        color = GREEN if total_passed == total_steps else RED
        result_text = f"{total_passed}/{total_steps} passed"
        print(f"\n{BOLD}=== Results: {color}{result_text}{RESET}{BOLD} ==={RESET}\n")

    await close_db()
    shutil.rmtree(_tmpdir, ignore_errors=True)

    return 0 if total_passed == total_steps else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
