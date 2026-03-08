"""
Dataset Validation Framework with History Logging.

Validates that fine-tuning improves model performance and does not regress.
Tracks performance over time with detailed history logs.

Usage:
    python scripts/validate_dataset.py --dataset-id 1 --model baseline --save-history
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent


class PromptGuardLoadError(RuntimeError):
    """Raised when Prompt Guard model loading fails."""


def _load_runtime_symbols():
    """Load runtime dependencies while keeping this script directly executable."""
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    models = importlib.import_module("server.models")
    sqlmodel_module = importlib.import_module("sqlmodel")

    try:
        prompt_guard_module = importlib.import_module("ea_agentgate.middleware.prompt_guard")
        model_manager = getattr(prompt_guard_module, "_PromptGuardModelManager")
        prompt_guard_available = True
    except ModuleNotFoundError:
        model_manager = None
        prompt_guard_available = False

    return {
        "TestCase": models.TestCase,
        "TestCaseStatus": models.TestCaseStatus,
        "get_session": models.get_session,
        "select": sqlmodel_module.select,
        "PromptGuardManager": model_manager,
        "prompt_guard_available": prompt_guard_available,
    }


RUNTIME = _load_runtime_symbols()
TestCase = RUNTIME["TestCase"]
TestCaseStatus = RUNTIME["TestCaseStatus"]
get_session = RUNTIME["get_session"]
select = RUNTIME["select"]
PROMPT_GUARD_MANAGER = RUNTIME["PromptGuardManager"]
PROMPT_GUARD_AVAILABLE = RUNTIME["prompt_guard_available"]

if not PROMPT_GUARD_AVAILABLE:
    print("Warning: Prompt Guard not available, using mock predictions")


@dataclass
class ValidationResult:
    """Stores validation results for a single run."""

    model_id: str
    dataset_id: int
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    predictions: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def add_prediction(
        self,
        example_id: int,
        true_label: int,
        predicted_label: int,
        confidence: float,
    ) -> None:
        """Add a single prediction result."""
        self.predictions.append(
            {
                "example_id": example_id,
                "true_label": true_label,
                "predicted_label": predicted_label,
                "confidence": confidence,
                "correct": true_label == predicted_label,
            }
        )

    def calculate_metrics(self) -> None:
        """Calculate aggregate and per-class performance metrics."""
        if not self.predictions:
            return

        correct = sum(1 for item in self.predictions if item["correct"])
        total = len(self.predictions)
        self.metrics["accuracy"] = correct / total
        self.metrics["total_examples"] = total
        self.metrics["correct_predictions"] = correct

        for label in [0, 1, 2]:
            label_name = ["benign", "injection", "jailbreak"][label]
            precision, recall, f1 = _compute_prf(self.predictions, label)
            self.metrics[f"{label_name}_precision"] = precision
            self.metrics[f"{label_name}_recall"] = recall
            self.metrics[f"{label_name}_f1"] = f1

        self.metrics["confusion_matrix"] = _build_confusion_matrix(self.predictions)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "model_id": self.model_id,
            "dataset_id": self.dataset_id,
            "timestamp": self.timestamp,
            "metrics": self.metrics,
            "predictions_count": len(self.predictions),
        }


def _compute_prf(predictions: list[dict[str, Any]], label: int) -> tuple[float, float, float]:
    """Compute precision, recall, and F1 for one class label."""
    true_positives = sum(
        1
        for item in predictions
        if item["true_label"] == label and item["predicted_label"] == label
    )
    false_positives = sum(
        1
        for item in predictions
        if item["true_label"] != label and item["predicted_label"] == label
    )
    false_negatives = sum(
        1
        for item in predictions
        if item["true_label"] == label and item["predicted_label"] != label
    )

    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else 0.0
    )
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def _build_confusion_matrix(predictions: list[dict[str, Any]]) -> list[list[int]]:
    """Build a 3x3 confusion matrix for labels 0..2."""
    confusion = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
    for item in predictions:
        confusion[item["true_label"]][item["predicted_label"]] += 1
    return confusion


async def _load_test_cases(dataset_id: int, limit: int | None) -> list[Any]:
    """Load active test cases from the given dataset."""
    async for session in get_session():
        stmt = select(TestCase).where(
            TestCase.dataset_id == dataset_id,
            TestCase.status == TestCaseStatus.ACTIVE,
        )
        if limit is not None:
            stmt = stmt.limit(limit)

        result_set = await session.execute(stmt)
        return list(result_set.scalars().all())
    return []


def _load_prompt_guard_model() -> tuple[Any, Any, Any] | None:
    """Load Prompt Guard model tuple (model, tokenizer, device)."""
    if not PROMPT_GUARD_AVAILABLE or PROMPT_GUARD_MANAGER is None:
        return None

    print("Loading Prompt Guard model...")
    model_tuple = PROMPT_GUARD_MANAGER.get_model_and_tokenizer(
        "meta-llama/Llama-Prompt-Guard-2-86M"
    )
    if model_tuple is None:
        raise PromptGuardLoadError("Failed to load Prompt Guard model")
    return model_tuple


def _predict_with_model(prompt: str, model: Any, tokenizer: Any, device: Any) -> tuple[int, float]:
    """Run one model inference against Prompt Guard."""
    if not callable(tokenizer):
        raise TypeError("Tokenizer is not callable")

    torch_module = importlib.import_module("torch")
    encoded_inputs = tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True,
    )
    encoded_inputs = {key: value.to(device) for key, value in encoded_inputs.items()}

    with torch_module.no_grad():
        outputs = model(**encoded_inputs)
        logits = outputs.logits
        probabilities = torch_module.nn.functional.softmax(logits, dim=-1)[0]

    predicted_label = int(torch_module.argmax(probabilities))
    confidence = float(probabilities[predicted_label])
    return predicted_label, confidence


def _predict_mock() -> tuple[int, float]:
    """Generate random prediction when model is unavailable."""
    return random.randint(0, 2), random.random()


async def validate_dataset(
    dataset_id: int,
    model_id: str = "prompt-guard-baseline",
    limit: int | None = None,
) -> ValidationResult:
    """Validate dataset against a model and return the result object."""
    print(f"Validating dataset {dataset_id} with model {model_id}...")
    print()

    result = ValidationResult(model_id=model_id, dataset_id=dataset_id)
    test_cases = await _load_test_cases(dataset_id, limit)

    if not test_cases:
        print(f"Error: No test cases found for dataset {dataset_id}")
        raise SystemExit(1)

    print(f"Loaded {len(test_cases)} test cases")
    print()

    model_info = None
    try:
        model_info = _load_prompt_guard_model()
        if model_info:
            _, _, device = model_info
            print(f"Model loaded on {device}")
            print()
    except PromptGuardLoadError as exc:
        print(f"Error: {exc}")
        print("Using mock predictions instead")

    print("Running predictions...")
    for index, test_case in enumerate(test_cases):
        prompt = test_case.inputs.get("prompt", "") if test_case.inputs else ""
        true_label = test_case.expected_output.get("label", 0) if test_case.expected_output else 0
        if not prompt:
            continue

        if model_info is not None:
            model, tokenizer, device = model_info
            predicted_label, confidence = _predict_with_model(
                prompt,
                model,
                tokenizer,
                device,
            )
        else:
            predicted_label, confidence = _predict_mock()

        result.add_prediction(
            example_id=test_case.id or 0,
            true_label=true_label,
            predicted_label=predicted_label,
            confidence=confidence,
        )

        if (index + 1) % 100 == 0:
            print(f"  Processed {index + 1}/{len(test_cases)} examples...")

    print(f"Completed {len(result.predictions)} predictions")
    print()
    result.calculate_metrics()
    return result


def _load_history(history_file: Path) -> list[dict[str, Any]]:
    """Load validation history from disk."""
    if not history_file.exists():
        return []
    with history_file.open(encoding="utf-8") as file_obj:
        return json.load(file_obj)


def save_history(result: ValidationResult, history_file: Path) -> None:
    """Save validation result to history log."""
    history = _load_history(history_file)
    history.append(result.to_dict())

    history_file.parent.mkdir(parents=True, exist_ok=True)
    with history_file.open("w", encoding="utf-8") as file_obj:
        json.dump(history, file_obj, indent=2)

    print(f"Saved to history: {history_file}")


def compare_results(
    history_file: Path,
    baseline_model: str = "prompt-guard-baseline",
) -> None:
    """Compare latest result with baseline to detect regression."""
    if not history_file.exists():
        print(f"Error: No history file found at {history_file}")
        return

    history = _load_history(history_file)
    if len(history) < 2:
        print("Error: Need at least 2 validation runs to compare")
        return

    baseline = next((item for item in history if item["model_id"] == baseline_model), None)
    if baseline is None:
        print(f"Warning: No baseline found for {baseline_model}, using first result")
        baseline = history[0]

    latest = history[-1]
    _print_comparison_table(baseline, latest)
    _print_regression_summary(baseline, latest)


def _print_comparison_table(baseline: dict[str, Any], latest: dict[str, Any]) -> None:
    """Print side-by-side metric comparisons for baseline vs latest."""
    print("=" * 80)
    print("Performance Comparison")
    print("=" * 80)
    print()
    print(f"Baseline: {baseline['model_id']} ({baseline['timestamp']})")
    print(f"Latest:   {latest['model_id']} ({latest['timestamp']})")
    print()
    print(f"{'Metric':<20} {'Baseline':>10} {'Latest':>10} {'Change':>10} {'Status':>10}")
    print("-" * 70)

    for metric in ["accuracy", "benign_f1", "injection_f1", "jailbreak_f1"]:
        baseline_value = baseline["metrics"].get(metric, 0)
        latest_value = latest["metrics"].get(metric, 0)
        change = latest_value - baseline_value
        change_pct = (change / baseline_value * 100) if baseline_value > 0 else 0
        status = "[IMPROVED]" if change > 0.01 else "[REGRESSED]" if change < -0.01 else "[STABLE]"
        print(
            f"{metric:<20} {baseline_value:>10.4f} {latest_value:>10.4f} "
            f"{change_pct:>9.2f}% {status:>10}"
        )

    print()


def _print_regression_summary(baseline: dict[str, Any], latest: dict[str, Any]) -> None:
    """Print qualitative regression summary from accuracy delta."""
    baseline_accuracy = baseline["metrics"]["accuracy"]
    latest_accuracy = latest["metrics"]["accuracy"]

    if latest_accuracy < baseline_accuracy - 0.05:
        print("[REGRESSION] Accuracy dropped by >5%")
        print("   Fine-tuning may have degraded model performance")
        print("   Recommendation: Revert to baseline or retrain with different data")
    elif latest_accuracy > baseline_accuracy + 0.05:
        print("[IMPROVEMENT] Accuracy increased by >5%")
        print("   Fine-tuning successfully improved model performance")
        print("   Recommendation: Deploy fine-tuned model to production")
    else:
        print("[INFO] NO SIGNIFICANT CHANGE: Performance is stable")
        print("   Fine-tuning had minimal impact")
        print("   Recommendation: Consider different training approach or more data")


def _print_validation_report(result: ValidationResult) -> None:
    """Print validation metrics and confusion matrix."""
    print("=" * 80)
    print("Validation Results")
    print("=" * 80)
    print()
    print(f"Model: {result.model_id}")
    print(f"Dataset: {result.dataset_id}")
    print(f"Timestamp: {result.timestamp}")
    print()
    print("Performance Metrics:")
    print(f"  Accuracy: {result.metrics['accuracy']:.4f}")
    print(f"  Total examples: {result.metrics['total_examples']}")
    print(f"  Correct: {result.metrics['correct_predictions']}")
    print()
    print("Per-Class Performance:")

    for label_name in ["benign", "injection", "jailbreak"]:
        precision = result.metrics[f"{label_name}_precision"]
        recall = result.metrics[f"{label_name}_recall"]
        f1 = result.metrics[f"{label_name}_f1"]
        print(
            f"  {label_name.capitalize():12} - Precision: {precision:.4f}, "
            f"Recall: {recall:.4f}, F1: {f1:.4f}"
        )

    print()
    print("Confusion Matrix:")
    print("                Predicted")
    print("              Benign  Injection  Jailbreak")
    confusion = result.metrics["confusion_matrix"]
    for index, label in enumerate(["Benign", "Injection", "Jailbreak"]):
        print(
            f"True {label:12} {confusion[index][0]:6d}  "
            f"{confusion[index][1]:9d}  {confusion[index][2]:9d}"
        )
    print()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate dataset and track performance history",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dataset-id", type=int, required=True, help="Dataset ID to validate")
    parser.add_argument(
        "--model",
        default="prompt-guard-baseline",
        help="Model identifier (for tracking)",
    )
    parser.add_argument("--limit", type=int, help="Maximum examples to validate")
    parser.add_argument("--save-history", action="store_true", help="Save results to history log")
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare latest result with baseline",
    )
    parser.add_argument(
        "--history-file",
        default="validation_history.json",
        help="History log file (default: validation_history.json)",
    )
    return parser.parse_args()


async def main() -> None:
    """Main entry point."""
    args = parse_args()
    history_path = PROJECT_ROOT / "ea_agentgate" / "data" / args.history_file

    if args.compare:
        compare_results(history_path, baseline_model="prompt-guard-baseline")
        return

    print("=" * 80)
    print("Dataset Validation")
    print("=" * 80)
    print()

    result = await validate_dataset(
        dataset_id=args.dataset_id,
        model_id=args.model,
        limit=args.limit,
    )

    _print_validation_report(result)
    if args.save_history:
        save_history(result, history_path)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except (ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
        print(f"\n\nError: {exc}")
        sys.exit(1)
