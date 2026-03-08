"""Compatibility shim for renamed policy governance script."""

import sys

from scripts.validate_policy_governance_adapter import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
