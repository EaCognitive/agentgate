"""Configuration constants for the audit event pipeline."""

from enum import Enum


class AuditPipelineMode(str, Enum):
    """Selects how audit events are persisted."""

    SYNC = "sync"
    REDIS_STREAM = "redis_stream"


STREAM_KEY = "agentgate:audit:events"
DLQ_STREAM_KEY = "agentgate:audit:dlq"
CONSUMER_GROUP = "audit-writers"
MAX_RETRIES = 5
BATCH_SIZE = 50
BLOCK_MS = 2000
CLAIM_IDLE_MS = 60_000
