"""
Import professional datasets from HuggingFace into AgentGate.

Downloads curated, production-ready datasets and converts them to AgentGate format.

Popular datasets:
- databricks/databricks-dolly-15k - Instruction following
- Open-Orca/OpenOrca - Complex reasoning
- tatsu-lab/alpaca - Instruction tuning
- HuggingFaceH4/helpful-base - Helpful AI assistant
- yahma/alpaca-cleaned - High-quality instructions

Usage:
    python scripts/import_huggingface_datasets.py \
        --dataset "databricks/databricks-dolly-15k" \
        --revision "<commit-or-tag>" --limit 100
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent

try:
    from datasets import load_dataset_builder
except ImportError as exc:
    print("Error: 'datasets' library not installed")
    print("Install with: pip install datasets")
    raise SystemExit(1) from exc


def _load_runtime_symbols():
    """Load runtime dependencies while keeping this script directly executable."""
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    models = importlib.import_module("server.models")
    sqlmodel_module = importlib.import_module("sqlmodel")
    return (
        models.Dataset,
        models.TestCase,
        models.TestCaseStatus,
        models.get_session,
        sqlmodel_module.select,
    )


(
    DATASET_MODEL,
    TEST_CASE_MODEL,
    TEST_CASE_STATUS,
    get_session,
    select,
) = _load_runtime_symbols()

# Mapping of popular HuggingFace datasets to AgentGate format
DATASET_CONFIGS = {
    "databricks/databricks-dolly-15k": {
        "name": "Databricks Dolly 15k - Instruction Following",
        "description": (
            "High-quality human-generated instruction-following dataset from "
            "Databricks. Covers brainstorming, classification, QA, generation, and more."
        ),
        "input_field": "instruction",
        "output_field": "response",
        "context_field": "context",
        "tool": "instruction_following",
    },
    "Open-Orca/OpenOrca": {
        "name": "OpenOrca - Advanced Reasoning",
        "description": (
            "Large-scale dataset for training reasoning capabilities. Contains GPT-4 "
            "and GPT-3.5 completions on diverse tasks."
        ),
        "input_field": "question",
        "output_field": "response",
        "tool": "reasoning",
    },
    "tatsu-lab/alpaca": {
        "name": "Stanford Alpaca - Instruction Tuning",
        "description": (
            "Stanford's Alpaca dataset for instruction-tuned models. "
            "52K instruction-following examples."
        ),
        "input_field": "instruction",
        "output_field": "output",
        "context_field": "input",
        "tool": "instruction",
    },
    "HuggingFaceH4/helpful-base": {
        "name": "HuggingFace Helpful - AI Assistant",
        "description": (
            "Dataset for training helpful AI assistants. "
            "Covers common assistant tasks and conversations."
        ),
        "input_field": "prompt",
        "output_field": "completion",
        "tool": "assistant",
    },
    "yahma/alpaca-cleaned": {
        "name": "Alpaca Cleaned - High Quality Instructions",
        "description": (
            "Cleaned version of Stanford Alpaca dataset with improved quality. "
            "Duplicate and low-quality examples removed."
        ),
        "input_field": "instruction",
        "output_field": "output",
        "context_field": "input",
        "tool": "instruction",
    },
}


def convert_to_agentgate_format(
    example: dict[str, Any],
    config: dict[str, str],
    index: int,
) -> dict[str, Any]:
    """Convert a HuggingFace example to AgentGate test case format."""
    input_text = example.get(config["input_field"], "")

    context_field = config.get("context_field")
    if context_field and context_field in example:
        context = example.get(context_field, "")
        if context:
            input_text = f"{context}\n\n{input_text}"

    output_text = example.get(config["output_field"], "")
    return {
        "name": f"example_{index}",
        "tool": config["tool"],
        "inputs": {"message": input_text.strip()},
        "expected_output": {"response": output_text.strip()},
        "status": TEST_CASE_STATUS.ACTIVE,
        "tags": ["imported", "huggingface", config["tool"]],
    }


def _resolve_config(dataset_id: str) -> dict[str, str]:
    """Resolve dataset config or exit with available options."""
    config = DATASET_CONFIGS.get(dataset_id)
    if config is not None:
        return config

    print(f"Unknown dataset: {dataset_id}")
    print("\nAvailable datasets:")
    for available_id in DATASET_CONFIGS:
        print(f"  - {available_id}")
    raise SystemExit(1)


def _download_examples(
    dataset_id: str,
    split: str,
    limit: int,
    revision: str,
) -> list[dict[str, Any]]:
    """Download dataset samples from HuggingFace."""
    print("Downloading from HuggingFace...")
    try:
        builder = load_dataset_builder(
            dataset_id,
            revision=revision,
        )
        dataset = builder.as_streaming_dataset(split=split)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"Failed to initialize dataset: {exc}")
        raise SystemExit(1) from exc

    examples = list(dataset.take(limit))
    print(f"Downloaded {len(examples)} examples")
    print()
    return examples


async def _get_or_create_dataset(session, config: dict[str, str]) -> Any:
    """Get existing dataset or create a new one."""
    stmt = select(DATASET_MODEL).where(DATASET_MODEL.name == config["name"])
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing:
        print(f"Dataset '{config['name']}' already exists")
        response = input("Overwrite? (y/N): ")
        if response.lower() != "y":
            print("Aborted")
            return None
        return existing

    dataset_obj = DATASET_MODEL(name=config["name"], description=config["description"])
    session.add(dataset_obj)
    await session.flush()
    return dataset_obj


def _create_test_case(tc_data: dict[str, Any], dataset_id: int) -> Any:
    """Create a test case instance from converted dataset data."""
    return TEST_CASE_MODEL(dataset_id=dataset_id, **tc_data)


async def _save_examples(session, dataset_obj, examples, config: dict[str, str]) -> int:
    """Convert and persist examples as test cases."""
    print("Converting examples...")
    imported_count = 0
    for index, example in enumerate(examples):
        tc_data = convert_to_agentgate_format(example, config, index)
        if not tc_data["inputs"]["message"] or not tc_data["expected_output"]["response"]:
            continue

        session.add(_create_test_case(tc_data, dataset_obj.id))
        imported_count += 1

        if (index + 1) % 10 == 0:
            print(f"  Processed {index + 1}/{len(examples)} examples...")

    await session.commit()
    return imported_count


async def import_dataset(
    dataset_id: str,
    revision: str,
    limit: int = 100,
    split: str = "train",
) -> None:
    """Import dataset from HuggingFace into AgentGate."""
    print(f"Importing dataset: {dataset_id}")
    print(f"  Revision: {revision}")
    print(f"  Limit: {limit} examples")
    print(f"  Split: {split}")
    print()

    config = _resolve_config(dataset_id)
    examples = _download_examples(dataset_id, split, limit, revision)

    async for session in get_session():
        try:
            dataset_obj = await _get_or_create_dataset(session, config)
            if dataset_obj is None:
                return

            print(f"Created dataset: {dataset_obj.name}")
            print()
            imported_count = await _save_examples(session, dataset_obj, examples, config)

            print()
            print(f"Successfully imported {imported_count} examples!")
            print()
            print(f"Dataset ID: {dataset_obj.id}")
            print(f"View in dashboard: http://localhost:3000/datasets/{dataset_obj.id}")
            print()
            print("Next steps:")
            print("  1. Review examples in dashboard")
            print("  2. Export for fine-tuning:")
            print(
                "     curl "
                f"'http://localhost:8000/api/datasets/{dataset_obj.id}/"
                "export/finetune?format=openai' "
                "> training.jsonl"
            )
        except (ValueError, TypeError, KeyError, RuntimeError) as exc:
            await session.rollback()
            print(f"Error importing dataset: {exc}")
            raise
        return


def main() -> None:
    """Parse CLI args and run the HuggingFace dataset import."""
    parser = argparse.ArgumentParser(
        description="Import professional datasets from HuggingFace",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Available datasets:\n"
            "  databricks/databricks-dolly-15k  - Instruction following (15k examples)\n"
            "  Open-Orca/OpenOrca               - Advanced reasoning (large)\n"
            "  tatsu-lab/alpaca                 - Instruction tuning (52k examples)\n"
            "  HuggingFaceH4/helpful-base       - AI assistant conversations\n"
            "  yahma/alpaca-cleaned             - High-quality instructions (cleaned)\n\n"
            "Examples:\n"
            "  # Import 100 examples from Dolly\n"
            "  python scripts/import_huggingface_datasets.py "
            '--dataset "databricks/databricks-dolly-15k" '
            '--revision "<commit-or-tag>" --limit 100\n\n'
            "  # Import 50 examples from Alpaca (cleaned)\n"
            "  python scripts/import_huggingface_datasets.py "
            '--dataset "yahma/alpaca-cleaned" --revision "<commit-or-tag>" --limit 50\n\n'
            "  # Import full dataset (use with caution!)\n"
            "  python scripts/import_huggingface_datasets.py "
            '--dataset "tatsu-lab/alpaca" --revision "<commit-or-tag>" --limit 1000'
        ),
    )

    parser.add_argument("--dataset", "-d", required=True, help="HuggingFace dataset ID")
    parser.add_argument(
        "--revision",
        "-r",
        required=True,
        help="Pinned dataset revision (commit hash or immutable tag)",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=100,
        help="Number of examples to import (default: 100)",
    )
    parser.add_argument(
        "--split",
        "-s",
        default="train",
        help="Dataset split to use (default: train)",
    )

    args = parser.parse_args()

    print()
    print("=" * 80)
    print("AgentGate HuggingFace Dataset Importer")
    print("=" * 80)
    print()

    try:
        asyncio.run(import_dataset(args.dataset, args.revision, args.limit, args.split))
    except KeyboardInterrupt:
        print("\n\nImport interrupted by user")
    except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
        print(f"\n\nError: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
