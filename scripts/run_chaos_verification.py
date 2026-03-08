#!/usr/bin/env python3
"""Run chaos verification campaigns with explicit execution modes.

Modes:
- single: deterministic quick campaign for local validation.
- parallel: full regulated-scale campaign.
- custom: caller-provided campaign profile and counts.
"""

from __future__ import annotations

import argparse
import os

from scripts.chaos_primitives import (
    resolve_chaos_campaign_configuration,
)
from scripts.chaos_runner import run_chaos_verification

_TRUE_VALUES = {"1", "true", "yes", "on"}


def _parse_count(raw_value: str | None, *, label: str) -> int | None:
    """Parse positive integer values with optional k suffix."""
    if raw_value is None:
        return None

    value = raw_value.strip().lower().replace("_", "")
    if not value:
        return None

    multiplier = 1
    if value.endswith("k"):
        multiplier = 1000
        value = value[:-1]

    if not value.isdigit():
        raise ValueError(f"{label} must be a positive integer (supports k suffix)")

    parsed = int(value) * multiplier
    if parsed <= 0:
        raise ValueError(f"{label} must be > 0")
    return parsed


def _is_truthy(value: str | None) -> bool:
    """Interpret truthy environment toggle values."""
    if value is None:
        return False
    return value.strip().lower() in _TRUE_VALUES


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run PGK chaos verification with explicit mode selection.",
    )
    parser.add_argument(
        "--mode",
        choices=["single", "parallel", "custom"],
        default="single",
        help="Execution mode. single=quick, parallel=full, custom=caller-defined.",
    )
    parser.add_argument(
        "--count",
        default=None,
        help="Iteration count (supports suffix: 10k, 100k, 500k).",
    )
    parser.add_argument(
        "--workers",
        default=None,
        help="Worker count override.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed.",
    )
    parser.add_argument(
        "--compliance-profile",
        default=None,
        help="Compliance profile override (development|soc2|soc3|hipaa|regulated).",
    )
    parser.add_argument(
        "--identity-profile",
        default=None,
        help="Identity profile override (local|hybrid_migration|descope|custom_oidc).",
    )
    parser.add_argument(
        "--allow-identity-mismatch",
        action="store_true",
        help="Bypass identity/compliance compatibility checks explicitly.",
    )

    enforce_group = parser.add_mutually_exclusive_group()
    enforce_group.add_argument(
        "--enforce-runtime",
        dest="enforce_runtime",
        action="store_true",
        help="Require runtime solver mode=enforce with z3 backend checks (default).",
    )
    enforce_group.add_argument(
        "--no-enforce-runtime",
        dest="enforce_runtime",
        action="store_false",
        help="Disable enforce-mode runtime requirement.",
    )
    parser.set_defaults(enforce_runtime=True)

    parser.add_argument(
        "--no-fail-fast",
        action="store_true",
        help="Collect all violations instead of terminating on first violation.",
    )
    return parser


def _resolve_mode_defaults(args: argparse.Namespace) -> tuple[int | None, int | None, str, str]:
    """Resolve mode-specific defaults while allowing explicit overrides."""
    if args.mode == "single":
        default_count = "10k"
        default_workers = "4"
        default_compliance = "development"
        default_identity = "local"
    elif args.mode == "parallel":
        default_count = None
        default_workers = None
        default_compliance = "regulated"
        default_identity = "descope"
    else:
        default_count = None
        default_workers = None
        default_compliance = "development"
        default_identity = "local"

    count = _parse_count(args.count or default_count, label="--count")
    workers = _parse_count(args.workers or default_workers, label="--workers")

    compliance_profile = (
        args.compliance_profile or os.getenv("CHAOS_COMPLIANCE_PROFILE") or default_compliance
    )
    identity_profile = (
        args.identity_profile
        or os.getenv("CHAOS_IDENTITY_PROFILE")
        or os.getenv("IDENTITY_PROVIDER_MODE")
        or default_identity
    )
    return count, workers, compliance_profile, identity_profile


def main(argv: list[str] | None = None) -> int:
    """Execute the configured chaos verification campaign."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.allow_identity_mismatch or _is_truthy(
        os.getenv("CHAOS_ALLOW_IDENTITY_PROFILE_MISMATCH")
    ):
        os.environ["CHAOS_ALLOW_IDENTITY_PROFILE_MISMATCH"] = "true"

    count, workers, compliance_profile, identity_profile = _resolve_mode_defaults(args)

    configuration = resolve_chaos_campaign_configuration(
        iterations=count,
        workers=workers,
        seed=args.seed,
        compliance_profile=compliance_profile,
        identity_profile=identity_profile,
    )

    print("=" * 72)
    print("CHAOS VERIFICATION MODE")
    print("=" * 72)
    print(f"Mode:               {args.mode}")
    print(f"Iterations:         {configuration.iterations:,}")
    print(f"Workers:            {configuration.workers}")
    print(f"Seed:               {configuration.seed}")
    print(f"Compliance profile: {configuration.compliance_profile}")
    print(f"Identity profile:   {configuration.identity_profile}")
    print(f"Require enforce:    {args.enforce_runtime}")
    print(f"Fail fast:          {not args.no_fail_fast}")
    print("=" * 72)

    report = run_chaos_verification(
        iterations=configuration.iterations,
        workers=configuration.workers,
        seed=configuration.seed,
        require_enforce_runtime=args.enforce_runtime,
        compliance_profile=configuration.compliance_profile,
        identity_profile=configuration.identity_profile,
        fail_fast_on_violation=not args.no_fail_fast,
    )

    if int(report.get("invariant_violations", 0)) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
