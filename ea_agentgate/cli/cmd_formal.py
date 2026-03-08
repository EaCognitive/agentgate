"""Formal verification CLI commands.

Usage::

    ea-agentgate formal check --principal agent:ops --action delete --resource /api/users
    ea-agentgate formal verify --decision-id abc123
    ea-agentgate formal plan --principal agent:pipeline --steps '[...]'
    ea-agentgate formal evidence --chain-id global
"""

import json
from argparse import ArgumentParser, Namespace, _SubParsersAction
from importlib import import_module
from typing import Any, cast

from ..api_client import ApiError, DashboardClient
from ..formal.helpers import extract_certificate_payload
from .formatters import print_error, print_json, print_kv, print_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register formal verification subcommands."""
    formal = subparsers.add_parser(
        "formal",
        help="Formal verification and proof operations",
    )
    sub = formal.add_subparsers(dest="formal_action")

    # check — admissibility evaluation
    p = sub.add_parser(
        "check",
        parents=[parent],
        help="Check admissibility of a principal/action/resource tuple",
    )
    p.add_argument("--principal", required=True, help="Principal identity (e.g. agent:ops)")
    p.add_argument("--action", required=True, help="Action to evaluate (e.g. delete)")
    p.add_argument("--resource", required=True, help="Resource path (e.g. /api/users)")
    p.add_argument(
        "--policies",
        default=None,
        help="JSON policies array (or omit to use server-side policies)",
    )
    p.add_argument("--tenant-id", default=None, help="Tenant ID for scoped evaluation")
    p.add_argument(
        "--provider",
        choices=["remote", "local"],
        default="remote",
        help="Formal verification provider (default: remote)",
    )
    p.set_defaults(func=cmd_check)

    # verify — certificate verification
    p = sub.add_parser(
        "verify",
        parents=[parent],
        help="Verify a decision certificate by ID",
    )
    p.add_argument("decision_id", help="Decision certificate ID to verify")
    p.set_defaults(func=cmd_verify)

    # plan — multi-step plan verification
    p = sub.add_parser(
        "plan",
        parents=[parent],
        help="Pre-flight verification of a multi-step plan",
    )
    p.add_argument("--principal", required=True, help="Principal identity")
    p.add_argument(
        "--steps",
        required=True,
        help='JSON array of steps, e.g. \'[{"action":"read","resource":"/api/data"}]\'',
    )
    p.add_argument(
        "--policies",
        default=None,
        help="JSON policies array (or omit to use server-side policies)",
    )
    p.add_argument(
        "--provider",
        choices=["remote", "local"],
        default="remote",
        help="Plan verification provider (default: remote)",
    )
    p.add_argument(
        "--risk-tier",
        default="high",
        choices=["low", "medium", "high", "critical"],
        help="Risk tier for remote counterfactual verification",
    )
    p.add_argument("--tenant-id", default=None, help="Tenant ID for remote verification")
    p.add_argument(
        "--verification-grant-token",
        default=None,
        help="Verification grant token for staging/production remote verification",
    )
    p.set_defaults(func=cmd_plan)

    # evidence — evidence chain verification
    p = sub.add_parser(
        "evidence",
        parents=[parent],
        help="Verify evidence chain integrity",
    )
    p.add_argument("--chain-id", default="global", help="Chain ID (default: global)")
    p.set_defaults(func=cmd_evidence)

    formal.add_argument("--json", action="store_true", dest="json", default=False)
    formal.add_argument("--url", default=None)
    formal.set_defaults(func=cmd_help, _parser=formal)


def cmd_help(args: Namespace, _client: DashboardClient) -> None:
    """Show formal subcommand help."""
    parser = getattr(args, "_parser", None)
    if parser is not None:
        parser.print_help()


def cmd_check(args: Namespace, client: DashboardClient) -> None:
    """Run admissibility check using remote or local formal provider."""
    if args.provider == "remote":
        _cmd_check_remote(args, client)
        return
    _cmd_check_local(args)


def _cmd_check_local(args: Namespace) -> None:
    """Run admissibility check via local/offline solver path."""
    verification = import_module("ea_agentgate.verification")
    check_admissibility = getattr(verification, "check_admissibility")

    policies = None
    if args.policies:
        try:
            policies = json.loads(args.policies)
        except json.JSONDecodeError as exc:
            print_error(f"Invalid --policies JSON: {exc}")
            return

    result = check_admissibility(
        principal=args.principal,
        action=args.action,
        resource=args.resource,
        policies=policies or [],
        tenant_id=getattr(args, "tenant_id", None),
    )

    if getattr(args, "json", False):
        print_json(
            {
                "decision": result.decision,
                "decision_id": result.decision_id,
                "proof_type": result.proof_type,
                "theorem_hash": result.theorem_hash,
            }
        )
        return

    symbol = "[PASS]" if result.decision == "ADMISSIBLE" else "[FAIL]"
    print(f"\n  {symbol} {result.decision}")
    print_kv(
        [
            ("Decision ID", result.decision_id),
            ("Proof Type", result.proof_type),
            ("Theorem Hash", result.theorem_hash[:24] + "..." if result.theorem_hash else "-"),
        ]
    )


def _cmd_check_remote(args: Namespace, client: DashboardClient) -> None:
    """Run admissibility check via canonical remote API path."""
    if args.policies:
        print_error(
            "--policies is only supported with --provider local. "
            "Remote mode uses server-side policy state."
        )
        return

    certificate: dict[str, Any] | None = None
    runtime_solver: dict[str, object] = {}

    try:
        data = client.formal_evaluate_admissibility(
            principal=args.principal,
            action=args.action,
            resource=args.resource,
            runtime_context={},
            tenant_id=getattr(args, "tenant_id", None),
        )
        certificate = cast(dict[str, Any] | None, data.get("certificate"))
        runtime_solver = cast(dict[str, object], data.get("runtime_solver", {}))
    except ApiError as exc:
        certificate = extract_certificate_payload(exc.detail)
        if certificate is None:
            print_error(str(exc))
            return
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        detail_payload = detail.get("detail", detail)
        if isinstance(detail_payload, dict):
            runtime_solver = detail_payload.get("runtime_solver", {})

    if not isinstance(certificate, dict):
        print_error("Remote verification did not return a certificate payload")
        return

    if getattr(args, "json", False):
        print_json(
            {
                "decision": certificate.get("result"),
                "decision_id": certificate.get("decision_id"),
                "proof_type": certificate.get("proof_type"),
                "theorem_hash": certificate.get("theorem_hash"),
                "runtime_solver": runtime_solver,
            }
        )
        return

    decision = str(certificate.get("result", "UNKNOWN"))
    symbol = "[PASS]" if decision == "ADMISSIBLE" else "[FAIL]"
    theorem_hash = str(certificate.get("theorem_hash", ""))
    print(f"\n  {symbol} {decision}")
    print_kv(
        [
            ("Decision ID", str(certificate.get("decision_id", "-"))),
            ("Proof Type", str(certificate.get("proof_type", "-"))),
            ("Theorem Hash", theorem_hash[:24] + "..." if theorem_hash else "-"),
            ("Solver Mode", str(runtime_solver.get("solver_mode", "-"))),
            ("Solver Backend", str(runtime_solver.get("solver_backend", "-"))),
        ]
    )


def cmd_verify(args: Namespace, client: DashboardClient) -> None:
    """Verify a decision certificate by ID (via server API)."""
    data = client.formal_verify_certificate(args.decision_id)

    if getattr(args, "json", False):
        print_json(data)
        return

    valid = bool(
        data.get(
            "valid",
            data.get("verification_run", {}).get("verification_result", False),
        )
    )
    symbol = "[PASS]" if valid else "[FAIL]"
    reason = data.get("reason", "")
    print(f"\n  {symbol} Certificate {args.decision_id}")
    if reason:
        print(f"  Reason: {reason}")


def cmd_plan(args: Namespace, client: DashboardClient) -> None:
    """Pre-flight plan verification using remote or local provider."""
    if args.provider == "remote":
        _cmd_plan_remote(args, client)
        return
    _cmd_plan_local(args)


def _cmd_plan_local(args: Namespace) -> None:
    """Pre-flight plan verification (offline via SDK)."""
    verification = import_module("ea_agentgate.verification")
    verify_plan = getattr(verification, "verify_plan")

    try:
        steps = json.loads(args.steps)
    except json.JSONDecodeError as exc:
        print_error(f"Invalid --steps JSON: {exc}")
        return

    policies = None
    if args.policies:
        try:
            policies = json.loads(args.policies)
        except json.JSONDecodeError as exc:
            print_error(f"Invalid --policies JSON: {exc}")
            return

    result = verify_plan(
        principal=args.principal,
        steps=steps,
        policies=policies or [],
    )

    if getattr(args, "json", False):
        print_json(
            {
                "safe": result.safe,
                "total_steps": result.total_steps,
                "blocked_step_index": result.blocked_step_index,
                "blocked_reason": result.blocked_reason,
            }
        )
        return

    if result.safe:
        print(f"\n  [PASS] Plan SAFE - all {result.total_steps} steps admissible")
    else:
        print(f"\n  [FAIL] Plan BLOCKED at step {result.blocked_step_index}")
        print(f"  Reason: {result.blocked_reason}")

    if result.step_results:
        rows = []
        for i, step_res in enumerate(result.step_results):
            rows.append(
                [
                    str(i),
                    step_res.decision,
                    step_res.decision_id[:12] + "..." if step_res.decision_id else "-",
                ]
            )
        print()
        print_table(["STEP", "RESULT", "DECISION ID"], rows)


def _cmd_plan_remote(args: Namespace, client: DashboardClient) -> None:
    """Pre-flight plan verification through canonical remote counterfactual endpoint."""
    if args.policies:
        print_error(
            "--policies is only supported with --provider local. "
            "Remote mode uses server-side policy state."
        )
        return
    try:
        steps = json.loads(args.steps)
    except json.JSONDecodeError as exc:
        print_error(f"Invalid --steps JSON: {exc}")
        return

    if not isinstance(steps, list):
        print_error("--steps must decode to a JSON array")
        return

    try:
        data = client.post(
            "/api/security/counterfactual/verify",
            body={
                "principal": args.principal,
                "steps": steps,
                "risk_tier": args.risk_tier,
                "tenant_id": args.tenant_id,
                "verification_grant_token": args.verification_grant_token,
            },
        )
    except ApiError as exc:
        print_error(str(exc))
        return

    if getattr(args, "json", False):
        print_json(data)
        return

    safe = bool(data.get("safe", False))
    symbol = "[PASS]" if safe else "[FAIL]"
    if safe:
        print(f"\n  {symbol} Plan SAFE - all {data.get('evaluated_steps', 0)} steps admissible")
    else:
        print(f"\n  {symbol} Plan BLOCKED at step {data.get('blocked_step_index')}")
        print(f"  Reason: {data.get('counterexample') or data.get('trace') or '-'}")


def cmd_evidence(args: Namespace, client: DashboardClient) -> None:
    """Verify evidence chain integrity (via server API)."""
    chain_id = getattr(args, "chain_id", "global")
    data = client.formal_verify_evidence_chain(chain_id)

    if getattr(args, "json", False):
        print_json(data)
        return

    valid = data.get("valid", data.get("integrity_verified", False))
    count = data.get("entries_verified", data.get("total_entries", 0))
    symbol = "[PASS]" if valid else "[FAIL]"
    print(f"\n  {symbol} Evidence chain '{chain_id}'")
    print_kv(
        [
            ("Entries verified", count),
            ("Integrity", "INTACT" if valid else "BROKEN"),
        ]
    )
