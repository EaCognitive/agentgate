"""Move non-endpoint test files to .backup/tests/ preserving directory structure.

This script reuses the same classification logic as classify_tests.py to decide
which files to archive, then performs the actual move.

Usage:
    python scripts/archive_tests.py           # dry-run (prints moves, no changes)
    python scripts/archive_tests.py --execute # moves files for real
"""

import argparse
import shutil
import sys
from pathlib import Path

from scripts.classify_tests import classify


def archive_tests(tests_root: Path, backup_root: Path, execute: bool) -> int:
    """Move archived test files from tests_root into backup_root.

    Args:
        tests_root: Absolute path to the tests/ directory.
        backup_root: Absolute path to .backup/tests/.
        execute: When False, only print the planned moves (dry-run).

    Returns:
        Exit code (0 on success).
    """
    _keep, to_archive = classify(tests_root)

    if not to_archive:
        print("Nothing to archive.")
        return 0

    print(f"{'DRY-RUN — ' if not execute else ''}Archiving {len(to_archive)} files")
    print(f"  Source:      {tests_root}")
    print(f"  Destination: {backup_root}")
    print()

    moved = 0
    skipped = 0

    for rel in to_archive:
        src = tests_root / rel
        dst = backup_root / rel

        if not src.exists():
            print(f"  SKIP (missing) {rel}")
            skipped += 1
            continue

        if execute:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            print(f"  MOVED  {rel}")
        else:
            print(f"  WOULD MOVE  {rel}")

        moved += 1

    print()
    if execute:
        print(f"Done. Moved {moved} files, skipped {skipped}.")
        _copy_support_files(tests_root, backup_root, execute=True)
    else:
        print(f"Dry-run complete. Would move {moved} files, skip {skipped}.")
        _copy_support_files(tests_root, backup_root, execute=False)

    return 0


def _copy_support_files(tests_root: Path, backup_root: Path, execute: bool) -> None:
    """Copy conftest.py and __init__.py files into backup dirs that need them.

    Args:
        tests_root: Absolute path to the tests/ directory.
        backup_root: Absolute path to .backup/tests/.
        execute: When False, only print what would be copied.
    """
    support_files = ["conftest.py", "__init__.py"]
    archived_dirs: set[Path] = set()

    if backup_root.exists():
        for path in backup_root.rglob("*.py"):
            archived_dirs.add(path.parent)
    else:
        # In dry-run mode, infer destination dirs from the classification.
        _keep, to_archive = classify(tests_root)
        for rel in to_archive:
            archived_dirs.add(backup_root / rel.parent)

    for archived_dir in archived_dirs:
        rel_dir = archived_dir.relative_to(backup_root)
        src_dir = tests_root / rel_dir

        for name in support_files:
            src_file = src_dir / name
            dst_file = archived_dir / name

            if not src_file.exists():
                continue
            if dst_file.exists():
                continue

            if execute:
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src_file), str(dst_file))
                print(f"  COPIED support {rel_dir / name}")
            else:
                print(f"  WOULD COPY support {rel_dir / name}")


def main() -> int:
    """Entry point for the archive script."""
    parser = argparse.ArgumentParser(description="Move non-endpoint tests to .backup/tests/.")
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Actually move the files (default: dry-run)",
    )
    parser.add_argument(
        "--tests-dir",
        default="tests",
        help="Path to the tests directory (default: tests)",
    )
    parser.add_argument(
        "--backup-dir",
        default=".backup/tests",
        help="Path to the backup destination (default: .backup/tests)",
    )
    args = parser.parse_args()

    tests_root = Path(args.tests_dir).resolve()
    backup_root = Path(args.backup_dir).resolve()

    if not tests_root.is_dir():
        print(f"ERROR: tests directory not found: {tests_root}", file=sys.stderr)
        return 1

    return archive_tests(tests_root, backup_root, execute=args.execute)


if __name__ == "__main__":
    sys.exit(main())
