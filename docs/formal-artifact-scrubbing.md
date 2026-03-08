# Formal Artifact Scrubbing

Last updated: 2026-02-12

## Purpose

This document defines the mandatory pre-share sanitization workflow for formal verification artifacts.

Objective:
- remove sensitive values from exported evidence bundles
- verify that scrubbed output is free of known leak patterns
- provide traceable scrub manifests and summaries for audit review

## Canonical Command

```bash
./run verify formal scrub
```

Default behavior:
1. Selects the latest runtime forensic run directory from `tests/artifacts/formal_runtime_forensic_run_*`.
2. Creates a scrubbed bundle under `tests/artifacts/share/`.
3. Verifies scrubbed files against sensitive-pattern checks.
4. Fails non-zero if any sensitive pattern remains.

## Source Selection

Use these options when the default source is not appropriate:

```bash
# Scrub canonical latest chaos snapshot
./run verify formal scrub --source-profile latest-canonical

# Scrub a specific run directory
./run verify formal scrub --source-dir /absolute/path/to/tests/artifacts/formal_runtime_forensic_run_...
```

## Output Artifacts

Each scrub execution writes:

- `SCRUB_REPORT.json`:
  structured run metadata, counters, and verification findings.
- `MANIFEST.json`:
  file-level source/output SHA-256 records and scrub mode per file.
- `SHARE_SUMMARY.txt`:
  human-readable summary for release notes and audit attachments.

## Redaction Rules

The scrubber applies recursive value sanitization for structured files (`.json`, `.jsonl`) and pattern sanitization for text files.

Redaction categories:
- email addresses
- bearer tokens
- local user path segments:
  - `/Users/<username>/...`
  - `/home/<username>/...`
  - `C:\Users\<username>\...`
- secret-like fields in structured payloads:
  - `access_token`
  - `refresh_token`
  - `authorization`
  - `api_key`
  - `password`
  - `secret`
  - `secret_key`
  - `private_key`

## Verification Rules

After scrubbing, the tool scans output for unsanitized patterns.

Fail conditions:
- source directory resolves but contains no artifact files
- any sensitive pattern match remains
- output path collision without explicit `--overwrite`
- source directory cannot be resolved

Verification-only mode:

```bash
./run verify formal scrub --verify-only --source-dir /absolute/path/to/artifacts
```

This mode scans for leaks without creating a scrubbed copy.

## Operational Workflow

Recommended release workflow:

1. Run formal runtime campaign:
   `./run verify formal run --count 100k --workers 6 --enforce-runtime`
2. Run scrub + verify:
   `./run verify formal scrub`
3. Share only files from the scrub output directory under `tests/artifacts/share/`.

## CI and Release Integration

For release pipelines, enforce:

1. `verify formal run` success (runtime evidence completeness)
2. `verify formal scrub` success (privacy-safe share bundle)
3. artifact publication from scrub output only

This prevents direct publication of raw runtime artifacts.

## Implementation References

- CLI entrypoint:
  `run`
- Scrub/verify implementation:
  `scripts/scrub_formal_artifacts.py`
- Shared sanitization rules:
  `scripts/privacy_sanitizer.py`
- Forensic runtime runner:
  `scripts/run_chaos_verification.py` (invoked via `./run verify formal run ...`)
