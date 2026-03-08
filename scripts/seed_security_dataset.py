"""
Seed bootstrap security dataset for Prompt Guard.

Loads the 500-example security dataset into AgentGate:
- 350 benign business/technical queries (anchor)
- 75 injection attacks
- 75 jailbreak attacks

Usage:
    python scripts/seed_security_dataset.py
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
DATASET_NAME = "Security Bootstrap v0.1"
DATA_PATH = PROJECT_ROOT / "ea_agentgate" / "data" / "seed_security_dataset.json"


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


def _print_banner() -> None:
    print("=" * 80)
    print("AgentGate Security Dataset Seeder")
    print("=" * 80)
    print()


def _load_examples() -> list[dict[str, Any]]:
    if not DATA_PATH.exists():
        print(f"Error: Dataset file not found at {DATA_PATH}")
        print("\nPlease run: python scripts/generate_security_dataset.py")
        raise SystemExit(1)

    print(f"Loading dataset from: {DATA_PATH}")
    with DATA_PATH.open(encoding="utf-8") as file_obj:
        examples = json.load(file_obj)

    print(f"Loaded {len(examples)} examples")
    print()
    return examples


def _print_dataset_composition(examples: list[dict[str, Any]]) -> None:
    benign_count = sum(1 for ex in examples if ex["label"] == 0)
    injection_count = sum(1 for ex in examples if ex["label"] == 1)
    jailbreak_count = sum(1 for ex in examples if ex["label"] == 2)

    print("Dataset composition:")
    print(f"  Benign:    {benign_count} examples")
    print(f"  Injection: {injection_count} examples")
    print(f"  Jailbreak: {jailbreak_count} examples")
    print()


async def _get_or_create_dataset(session, overwrite: bool) -> Any:
    stmt = select(DATASET_MODEL).where(DATASET_MODEL.name == DATASET_NAME)
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing:
        print(f"Dataset '{DATASET_NAME}' already exists")
        if not overwrite:
            response = input("Overwrite? (y/N): ")
            if response.lower() != "y":
                print("Aborted")
                return None
        return existing

    dataset_obj = DATASET_MODEL(
        name=DATASET_NAME,
        description=(
            "Bootstrap security dataset for Prompt Guard middleware. "
            "Contains 500 examples covering benign queries, injection attacks, "
            "and jailbreak attempts. Aligned with "
            "meta-llama/Llama-Prompt-Guard-2-86M for immediate threat "
            "detection calibration."
        ),
    )
    session.add(dataset_obj)
    await session.flush()
    return dataset_obj


def _build_test_case(example: dict[str, Any], index: int, dataset_id: int) -> Any:
    difficulty = example["metadata"].get("difficulty", "N/A")
    return TEST_CASE_MODEL(
        dataset_id=dataset_id,
        name=f"security_ex_{index}",
        tool="prompt_guard",
        inputs={"prompt": example["text"]},
        expected_output={
            "label": example["label"],
            "label_text": example["label_text"],
        },
        tags=[
            example["label_text"].lower(),
            example["metadata"]["category"],
            example["source"],
        ],
        status=TEST_CASE_STATUS.ACTIVE,
        description=(f"Source: {example['source']}, Difficulty: {difficulty}"),
    )


async def _add_test_cases(session, examples: list[dict[str, Any]], dataset_id: int) -> None:
    print("Converting examples to test cases...")
    for index, example in enumerate(examples):
        test_case = _build_test_case(example, index, dataset_id)
        session.add(test_case)
        if (index + 1) % 50 == 0:
            print(f"  Processed {index + 1}/{len(examples)} examples...")


def _print_success(dataset_id: int, total_examples: int) -> None:
    print()
    print("=" * 80)
    print("Success! Security dataset seeded")
    print("=" * 80)
    print()
    print(f"Dataset ID: {dataset_id}")
    print(f"Total examples: {total_examples}")
    print()
    print("What you can do now:")
    print("  1. View dataset:      http://localhost:3000/datasets")
    print(f"  2. Run test suite:    POST /api/datasets/{dataset_id}/test-runs")
    print(f"  3. Export for tuning: GET /api/datasets/{dataset_id}/export/finetune?format=openai")
    print()
    print("Prompt Guard Middleware:")
    print("  - This dataset provides immediate calibration for threat detection")
    print("  - Use for validating Prompt Guard accuracy")
    print("  - Export and fine-tune for domain-specific improvements")


async def seed_security_dataset() -> None:
    """Load security dataset from JSON file into database."""
    _print_banner()
    examples = _load_examples()
    _print_dataset_composition(examples)

    async for session in get_session():
        dataset_obj = await _get_or_create_dataset(session, overwrite=False)
        if dataset_obj is None:
            return

        if dataset_obj.id is None:
            raise ValueError("Dataset ID is None after creation")

        try:
            print(f"Created dataset: {dataset_obj.name}")
            print()
            await _add_test_cases(session, examples, dataset_obj.id)
            await session.commit()
            _print_success(dataset_obj.id, len(examples))
        except (ValueError, TypeError, KeyError, RuntimeError) as exc:
            await session.rollback()
            print(f"Error seeding dataset: {exc}")
            raise
        return


if __name__ == "__main__":
    try:
        asyncio.run(seed_security_dataset())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
        print(f"\n\nError: {exc}")
        sys.exit(1)
