"""Dataset, test case, and test run schemas and models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar

from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive (for TIMESTAMP WITHOUT TIME ZONE columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============== Datasets & Test Cases (One-Click Evals) ==============


class TestCaseStatus(str, Enum):
    """Status of a test case."""

    __test__ = False
    ACTIVE = "active"
    DISABLED = "disabled"
    DRAFT = "draft"


class AssertionType(str, Enum):
    """Types of assertions for test cases.

    SECURITY NOTE: CUSTOM assertion type is deprecated and disabled for
    security reasons. It previously allowed arbitrary Python code execution,
    which is a critical security vulnerability. Use the safe assertion types
    instead.
    """

    EQUALS = "equals"  # Exact match
    CONTAINS = "contains"  # Output contains substring
    NOT_CONTAINS = "not_contains"  # Output does not contain
    MATCHES_REGEX = "matches_regex"  # Regex pattern match
    JSON_PATH = "json_path"  # JSONPath assertion
    TYPE_CHECK = "type_check"  # Type validation


class Dataset(SQLModel, table=True):
    """
    Collection of test cases for evaluation.

    Datasets can be used for:
    - Regression testing
    - Model evaluation/comparison
    - Continuous integration
    """

    __tablename__: ClassVar[str] = "datasets"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    description: str | None = None

    # Ownership
    created_by: int | None = Field(default=None, foreign_key="users.id")

    # Metadata
    tags: list[str] | None = Field(default=None, sa_column=Column(JSON))
    metadata_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))

    # Stats (denormalized for performance)
    test_count: int = Field(default=0)
    last_run_at: datetime | None = None
    last_run_pass_rate: float | None = None

    # Timestamps
    created_at: datetime = Field(default_factory=utc_now, index=True)
    updated_at: datetime = Field(default_factory=utc_now)


class DatasetCreate(SQLModel):
    """Schema for creating a dataset."""

    name: str
    description: str | None = None
    tags: list[str] | None = None
    metadata_json: dict[str, Any] | None = None


class DatasetRead(SQLModel):
    """Schema for reading a dataset."""

    id: int
    name: str
    description: str | None
    tags: list[str] | None
    test_count: int
    last_run_at: datetime | None
    last_run_pass_rate: float | None
    created_at: datetime
    updated_at: datetime
    created_by: int | None = None  # User ID of the owner


class DatasetUpdate(SQLModel):
    """Schema for updating a dataset."""

    name: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class TestCase(SQLModel, table=True):
    """
    Individual test case within a dataset.

    Captures input/output pairs from real traces with optional assertions.
    """

    __test__ = False
    __tablename__: ClassVar[str] = "test_cases"

    id: int | None = Field(default=None, primary_key=True)
    dataset_id: int = Field(foreign_key="datasets.id", index=True)

    # Test identification
    name: str
    description: str | None = None

    # Tool execution
    tool: str = Field(index=True)
    inputs: dict[str, Any] = Field(sa_column=Column(JSON))

    # Expected output (golden output from trace)
    expected_output: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))

    # Assertions (multiple assertions can be defined)
    assertions: list[dict[str, Any]] | None = Field(default=None, sa_column=Column(JSON))

    # Source trace (for provenance)
    source_trace_id: str | None = Field(default=None, index=True)

    # Status
    status: TestCaseStatus = Field(default=TestCaseStatus.ACTIVE)

    # Metadata
    tags: list[str] | None = Field(default=None, sa_column=Column(JSON))
    metadata_json: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))

    # Timestamps
    created_at: datetime = Field(default_factory=utc_now, index=True)
    updated_at: datetime = Field(default_factory=utc_now)


class TestCaseCreate(SQLModel):
    """Schema for creating a test case."""

    __test__ = False
    dataset_id: int
    name: str
    description: str | None = None
    tool: str
    inputs: dict[str, Any]
    expected_output: dict[str, Any] | None = None
    assertions: list[dict[str, Any]] | None = None
    source_trace_id: str | None = None
    tags: list[str] | None = None


class TestCaseRead(SQLModel):
    """Schema for reading a test case."""

    __test__ = False
    id: int
    dataset_id: int
    name: str
    description: str | None
    tool: str
    inputs: dict[str, Any]
    expected_output: dict[str, Any] | None
    assertions: list[dict[str, Any]] | None
    source_trace_id: str | None
    status: TestCaseStatus
    tags: list[str] | None
    created_at: datetime


class TestCaseUpdate(SQLModel):
    """Schema for updating a test case."""

    __test__ = False
    name: str | None = None
    description: str | None = None
    inputs: dict[str, Any] | None = None
    expected_output: dict[str, Any] | None = None
    assertions: list[dict[str, Any]] | None = None
    status: TestCaseStatus | None = None
    tags: list[str] | None = None


class TestCaseFromTrace(SQLModel):
    """Schema for creating a test case from a trace."""

    __test__ = False
    trace_id: str
    dataset_id: int
    name: str | None = None
    description: str | None = None
    assertions: list[dict[str, Any]] | None = None
    tags: list[str] | None = None


class Assertion(SQLModel):
    """Individual assertion definition."""

    type: AssertionType
    field: str | None = None  # For JSON path or specific field
    expected: Any | None = None  # Expected value
    pattern: str | None = None  # For regex
    expression: str | None = None  # For custom Python expression
    message: str | None = None  # Custom failure message


# ============== Test Run Results ==============


class TestRunStatus(str, Enum):
    """Status of a test run."""

    __test__ = False
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestResultStatus(str, Enum):
    """Status of individual test result."""

    __test__ = False
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class TestRun(SQLModel, table=True):
    """
    Execution of a dataset's test cases.

    Tracks overall run status and aggregated results.
    """

    __test__ = False
    __tablename__: ClassVar[str] = "test_runs"

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(unique=True, index=True)
    dataset_id: int = Field(foreign_key="datasets.id", index=True)

    # Run metadata
    name: str | None = None
    triggered_by: int | None = Field(default=None, foreign_key="users.id")

    # Status
    status: TestRunStatus = Field(default=TestRunStatus.PENDING)

    # Results (denormalized for quick access)
    total_tests: int = Field(default=0)
    passed_count: int = Field(default=0)
    failed_count: int = Field(default=0)
    error_count: int = Field(default=0)
    skipped_count: int = Field(default=0)

    # Timing
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: float | None = None

    # Configuration
    config: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))

    # Timestamps
    created_at: datetime = Field(default_factory=utc_now, index=True)


class TestRunCreate(SQLModel):
    """Schema for creating a test run."""

    __test__ = False
    dataset_id: int
    name: str | None = None
    config: dict[str, Any] | None = None


class TestRunRead(SQLModel):
    """Schema for reading a test run."""

    __test__ = False
    id: int
    run_id: str
    dataset_id: int
    name: str | None
    status: TestRunStatus
    total_tests: int
    passed_count: int
    failed_count: int
    error_count: int
    skipped_count: int
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: float | None
    created_at: datetime


class TestResult(SQLModel, table=True):
    """
    Individual test case result within a run.
    """

    __test__ = False
    __tablename__: ClassVar[str] = "test_results"

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(foreign_key="test_runs.run_id", index=True)
    test_case_id: int = Field(foreign_key="test_cases.id", index=True)

    # Result
    status: TestResultStatus

    # Actual output
    actual_output: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))

    # Assertion results
    assertion_results: list[dict[str, Any]] | None = Field(default=None, sa_column=Column(JSON))

    # Error details
    error_message: str | None = None
    error_traceback: str | None = None

    # Timing
    duration_ms: float | None = None

    # Timestamps
    executed_at: datetime = Field(default_factory=utc_now)


class TestResultRead(SQLModel):
    """Schema for reading a test result."""

    __test__ = False
    id: int
    run_id: str
    test_case_id: int
    status: TestResultStatus
    actual_output: dict[str, Any] | None
    assertion_results: list[dict[str, Any]] | None
    error_message: str | None
    duration_ms: float | None
    executed_at: datetime


# ============== Pytest Export ==============


class PytestExportConfig(SQLModel):
    """Configuration for pytest export."""

    dataset_id: int
    output_dir: str = "tests/generated"
    file_prefix: str = "test_"
    include_assertions: bool = True
    include_comments: bool = True
    async_tests: bool = False


class PytestExportResult(SQLModel):
    """Result of pytest export."""

    file_path: str
    test_count: int
    content: str
