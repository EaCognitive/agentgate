#!/usr/bin/env python3
"""
Bundle codebase into a single plain text file for LLM context.

Excludes sensitive files, binaries, and large generated content.
Outputs directory tree, file contents, and token count.

Usage:
    python scripts/bundle_codebase.py > codebase.txt
    python scripts/bundle_codebase.py --output codebase.txt
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from collections import defaultdict
from pathlib import Path

try:
    import tiktoken as _tiktoken
except ImportError:
    _tiktoken = None

# Directories to exclude entirely
EXCLUDED_DIRS = {
    ".git",
    ".archive",
    "data",
    "venv",
    ".env",
    "node_modules",
    "__pycache__",
    "scripts",
    ".mypy_cache",
    "dist",
    "build",
    "*.egg-info",
    ".eggs",
    "htmlcov",
    ".coverage",
    ".tox",
    ".nox",
    "site-packages",
    ".idea",
    ".vscode",
    "logos",
    "allure-report",
    "allure-results",
    "logs",
    "log",
    ".next",
    "out",
    ".turbo",
    ".cache",
    ".uv",
    ".agent",
    ".allure-results",
    ".venv",
    ".allure-history",
    ".vercel",
    ".nuxt",
    "coverage",
    ".nyc_output",
}

# File patterns to exclude
EXCLUDED_PATTERNS = {
    # Sensitive files
    "uv.config.js",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.*",
    "*.pem",
    "*.key",
    "*.crt",
    "*.p12",
    "*.pfx",
    "credentials.json",
    "secrets.json",
    "service-account.json",
    ".npmrc",
    ".pypirc",
    # Lock files (large, generated)
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    # Binary and compiled files
    "*.pyc",
    "*.pyo",
    "*.so",
    "*.dylib",
    "*.dll",
    "*.exe",
    "*.bin",
    "*.o",
    "*.a",
    "*.class",
    "*.jar",
    "*.war",
    # Images and media
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "agentgate.db",
    "*.svg",
    "*.webp",
    "*.mp3",
    "*.mp4",
    "*.wav",
    "*.avi",
    "*.mov",
    "*.pdf",
    # Archives
    "*.zip",
    "*.tar",
    "*.gz",
    "*.bz2",
    "*.xz",
    "*.rar",
    "*.7z",
    # Database files
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    # Log files
    "*.log",
    "*.logs",
    # Large data files
    "*.csv",
    "*.parquet",
    "*.arrow",
    "*.feather",
    # IDE and editor files
    "*.swp",
    "*.swo",
    "*~",
    ".DS_Store",
    "Thumbs.db",
    # Source maps
    "*.map",
    "*.js.map",
    "*.css.map",
    # Minified files
    "*.min.js",
    "*.min.css",
}

# Files to exclude by exact name
EXCLUDED_FILES = {
    ".gitignore",
    ".gitattributes",
    ".dockerignore",
    ".eslintcache",
    ".prettierignore",
    "CODEOWNERS",
    "renovate.json",
    "dependabot.yml",
    "CLAUDE.md",
    "claude.md",
    "SKILL.md",
    "skill.md",
}

# Maximum file size to include (bytes)
MAX_FILE_SIZE = 100_000  # 100KB


def matches_pattern(filename: str, patterns: set[str]) -> bool:
    """Check if filename matches any pattern."""
    filename_lower = filename.lower()
    for pattern in patterns:
        pattern_lower = pattern.lower()
        if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(filename_lower, pattern_lower):
            return True
    return False


def should_exclude_dir(dirname: str) -> bool:
    """Check if directory should be excluded."""
    if dirname.startswith("."):
        return True
    return matches_pattern(dirname, EXCLUDED_DIRS)


def should_exclude_file(filepath: Path, max_size: int = MAX_FILE_SIZE) -> bool:
    """Check if file should be excluded."""
    filename = filepath.name

    # Check exact name matches (case-insensitive)
    filename_lower = filename.lower()
    if any(filename_lower == f.lower() for f in EXCLUDED_FILES):
        return True

    # Check patterns
    if matches_pattern(filename, EXCLUDED_PATTERNS):
        return True

    # Check file size
    try:
        if filepath.stat().st_size > max_size:
            return True
    except OSError:
        return True

    # Check if binary
    if is_binary(filepath):
        return True

    return False


def is_binary(filepath: Path) -> bool:
    """Check if file is binary."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
            if b"\x00" in chunk:
                return True
            # Check for high ratio of non-text bytes
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
            non_text = sum(1 for byte in chunk if byte not in text_chars)
            if len(chunk) > 0 and non_text / len(chunk) > 0.30:
                return True
    except (OSError, IOError):
        return True
    return False


def get_file_extension(filepath: Path) -> str:
    """Get file extension for language detection."""
    return filepath.suffix.lower()


def generate_tree(root: Path, prefix: str = "") -> list[str]:
    """Generate directory tree structure."""
    lines = []
    entries = []

    try:
        for entry in sorted(root.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            if entry.is_dir():
                if not should_exclude_dir(entry.name):
                    entries.append(entry)
            else:
                if not should_exclude_file(entry):
                    entries.append(entry)
    except PermissionError:
        return lines

    for i, entry in enumerate(entries):
        is_last = i == len(entries) - 1
        connector = "└── " if is_last else "├── "
        lines.append(f"{prefix}{connector}{entry.name}")

        if entry.is_dir():
            extension = "    " if is_last else "│   "
            lines.extend(generate_tree(entry, prefix + extension))

    return lines


def collect_files(root: Path, max_size: int = MAX_FILE_SIZE) -> list[Path]:
    """Collect all files to include."""
    files = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out excluded directories
        dirnames[:] = [d for d in dirnames if not should_exclude_dir(d)]

        for filename in filenames:
            filepath = Path(dirpath) / filename
            if not should_exclude_file(filepath, max_size):
                files.append(filepath)

    return sorted(files)


def read_file_content(filepath: Path) -> str | None:
    """Read file content, handling encoding issues."""
    encodings = ["utf-8", "cp1252", "latin-1"]

    for encoding in encodings:
        try:
            with open(filepath, "r", encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
        except (OSError, IOError):
            return None

    return None


def estimate_tokens(text: str) -> int:
    """
    Estimate token count.

    Uses tiktoken if available, otherwise approximates with word count.
    GPT-4/Claude tokenizers average ~4 characters per token for code.
    """
    if _tiktoken is not None:
        try:
            enc = _tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except (AttributeError, KeyError, ValueError):
            pass

    # Fallback: approximate 1 token per 4 characters for code
    return len(text) // 4


def bundle_codebase(
    root: Path, max_size: int = MAX_FILE_SIZE
) -> tuple[str, int, int, list[tuple[str, int]]]:
    """
    Bundle codebase into plain text.

    Returns:
        tuple: (content, file_count, token_count, dir_tokens)
            dir_tokens is a list of (directory_path, token_count)
            sorted descending by token count.
    """
    lines = []
    dir_token_map: dict[str, int] = defaultdict(int)

    # Header
    lines.append("=" * 80)
    lines.append(f"CODEBASE: {root.name}")
    lines.append("=" * 80)
    lines.append("")

    # Directory tree
    lines.append("DIRECTORY STRUCTURE")
    lines.append("-" * 40)
    lines.append(root.name + "/")
    tree = generate_tree(root)
    lines.extend(tree)
    lines.append("")
    lines.append("")

    # File contents
    lines.append("FILE CONTENTS")
    lines.append("-" * 40)
    lines.append("")

    files = collect_files(root, max_size)
    file_count = 0

    for filepath in files:
        relative_path = filepath.relative_to(root)
        content = read_file_content(filepath)

        if content is None:
            continue

        file_count += 1
        file_tokens = estimate_tokens(content)

        # Accumulate tokens into every ancestor directory
        parts = relative_path.parts
        for depth in range(1, len(parts)):
            dir_key = str(Path(*parts[:depth]))
            dir_token_map[dir_key] += file_tokens
        # Also count the root itself
        dir_token_map["."] += file_tokens

        # File header
        lines.append("=" * 80)
        lines.append(f"FILE: {relative_path}")
        lines.append("=" * 80)
        lines.append("")
        lines.append(content)
        if not content.endswith("\n"):
            lines.append("")
        lines.append("")

    # Join all content
    full_content = "\n".join(lines)
    token_count = estimate_tokens(full_content)

    dir_tokens = sorted(dir_token_map.items(), key=lambda x: x[1], reverse=True)

    return full_content, file_count, token_count, dir_tokens


def find_project_root(start_path: Path) -> Path:
    """Find the project root by looking for marker files."""
    markers = {"pyproject.toml", ".git", "package.json", "Makefile"}
    current = start_path.resolve()

    for _ in range(10):  # Go up at most 10 levels
        if any((current / marker).exists() for marker in markers):
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent

    return start_path


def main():
    """Main entry point for bundle codebase script."""
    # Print script path for confirmation (similar to other tools)
    print(f"{Path(__file__).resolve()}", file=sys.stderr)

    parser = argparse.ArgumentParser(description="Bundle codebase into plain text for LLM context")
    parser.add_argument(
        "path",
        nargs="?",
        default=None,  # Change default to None to detect when user didn't specify
        help="Root directory to bundle (default: auto-detect project root or current directory)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--no-tree",
        action="store_true",
        help="Exclude directory tree",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=100000,
        help="Maximum file size in bytes (default: 100000)",
    )

    args = parser.parse_args()
    max_file_size = args.max_size

    if args.path:
        root = Path(args.path).resolve()
    else:
        # Auto-detect root if not specified
        root = find_project_root(Path.cwd())

    if not root.exists():
        print(f"Error: Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    if not root.is_dir():
        print(f"Error: Path is not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    # Bundle codebase
    content, file_count, token_count, dir_tokens = bundle_codebase(root, max_file_size)

    # Output content
    output_path = Path(args.output) if args.output else root / "codebase.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Bundled to: {output_path}", file=sys.stderr)

    # Print stats to stderr
    print("", file=sys.stderr)
    print("=" * 40, file=sys.stderr)
    print("BUNDLE STATISTICS", file=sys.stderr)
    print("=" * 40, file=sys.stderr)
    print(f"Files included:    {file_count:,}", file=sys.stderr)
    print(f"Total characters:  {len(content):,}", file=sys.stderr)
    print(f"Estimated tokens:  {token_count:,}", file=sys.stderr)
    print("=" * 40, file=sys.stderr)

    # Print top 10 directories by token count
    top_dirs = dir_tokens[:10]
    if top_dirs:
        print("", file=sys.stderr)
        print("TOP 10 DIRECTORIES BY TOKEN COUNT", file=sys.stderr)
        print("-" * 40, file=sys.stderr)
        for rank, (dir_path, tokens) in enumerate(top_dirs, 1):
            print(
                f"  {rank:>2}. {tokens:>8,} tokens  {dir_path}/",
                file=sys.stderr,
            )
        print("=" * 40, file=sys.stderr)


if __name__ == "__main__":
    main()
