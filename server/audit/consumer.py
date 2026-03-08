"""Background consumer that reads audit events from Redis Stream and writes to DB.

Uses XREADGROUP for reliable delivery with consumer groups, automatic
dead-letter queue (DLQ) for messages exceeding retry limits, and
atomic batch writes to PostgreSQL.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from server.models.audit_schemas import AuditEntry
from server.models.database import get_session_context

from .config import (
    BATCH_SIZE,
    BLOCK_MS,
    CLAIM_IDLE_MS,
    CONSUMER_GROUP,
    DLQ_STREAM_KEY,
    MAX_RETRIES,
    STREAM_KEY,
)

logger = logging.getLogger(__name__)
CONSUMER_ERRORS = (
    AttributeError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
    json.JSONDecodeError,
)


class StreamConsumer:
    """Reads audit events from a Redis Stream and persists them to the DB."""

    def __init__(
        self,
        redis_client: Any,
        consumer_name: str = "worker-0",
    ) -> None:
        self._redis = redis_client
        self._consumer_name = consumer_name
        self._running = False
        self._task: asyncio.Task[None] | None = None

    async def setup(self) -> None:
        """Create the consumer group (idempotent)."""
        try:
            await self._redis.xgroup_create(
                STREAM_KEY,
                CONSUMER_GROUP,
                id="0",
                mkstream=True,
            )
            logger.info(
                "Created consumer group %s on %s",
                CONSUMER_GROUP,
                STREAM_KEY,
            )
        except CONSUMER_ERRORS as exc:
            # BUSYGROUP means group already exists -- safe to ignore
            if "BUSYGROUP" in str(exc):
                logger.debug("Consumer group %s already exists", CONSUMER_GROUP)
            else:
                raise

    async def start(self) -> None:
        """Spawn the background consume loop."""
        await self.setup()
        self._running = True
        self._task = asyncio.create_task(self._consume_loop())
        logger.info("Audit StreamConsumer started (%s)", self._consumer_name)

    async def stop(self, timeout: float = 10.0) -> None:
        """Signal the loop to stop and wait for clean shutdown."""
        self._running = False
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning("Consumer did not stop in time; cancelling")
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None
        logger.info("Audit StreamConsumer stopped")

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    async def _consume_loop(self) -> None:
        """Main loop: reclaim pending, then read new messages."""
        while self._running:
            try:
                await self._reclaim_pending()

                # Read new messages
                response = await self._redis.xreadgroup(
                    CONSUMER_GROUP,
                    self._consumer_name,
                    {STREAM_KEY: ">"},
                    count=BATCH_SIZE,
                    block=BLOCK_MS,
                )
                if response:
                    for _stream_name, messages in response:
                        if messages:
                            await self._process_batch(messages)
            except asyncio.CancelledError:
                break
            except CONSUMER_ERRORS:
                logger.exception("Error in audit consume loop")
                await asyncio.sleep(1)

    async def _process_batch(
        self,
        entries: list[tuple[bytes | str, dict[bytes | str, bytes | str]]],
    ) -> None:
        """Deserialize messages, write to DB, ACK on success."""
        audit_entries: list[AuditEntry] = []
        msg_ids: list[bytes | str] = []

        for msg_id, data in entries:
            try:
                entry = self._deserialize(data)
                audit_entries.append(entry)
                msg_ids.append(msg_id)
            except CONSUMER_ERRORS:
                logger.warning(
                    "Malformed audit message %s; sending to DLQ",
                    msg_id,
                )
                await self._send_to_dlq(msg_id, data, "deserialization_error")
                await self._redis.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)

        if not audit_entries:
            return

        try:
            async with get_session_context() as session:
                for entry in audit_entries:
                    session.add(entry)
            # Session commits on successful exit of the context manager
            await self._redis.xack(STREAM_KEY, CONSUMER_GROUP, *msg_ids)
        except CONSUMER_ERRORS:
            logger.exception(
                "DB write failed for batch of %d; messages remain pending",
                len(audit_entries),
            )

    async def _reclaim_pending(self) -> None:
        """Reclaim idle messages from crashed consumers via XPENDING + XCLAIM."""
        try:
            pending = await self._redis.xpending_range(
                STREAM_KEY,
                CONSUMER_GROUP,
                min="-",
                max="+",
                count=BATCH_SIZE,
            )
            if not pending:
                return

            for entry in pending:
                msg_id = entry["message_id"]
                delivery_count = entry["times_delivered"]
                idle_time = entry["time_since_delivered"]

                if idle_time < CLAIM_IDLE_MS:
                    continue

                if delivery_count > MAX_RETRIES:
                    # Exceeded retries -- move to DLQ
                    claimed = await self._redis.xclaim(
                        STREAM_KEY,
                        CONSUMER_GROUP,
                        self._consumer_name,
                        min_idle_time=0,
                        message_ids=[msg_id],
                    )
                    for claimed_id, data in claimed:
                        await self._send_to_dlq(claimed_id, data, "max_retries_exceeded")
                        await self._redis.xack(STREAM_KEY, CONSUMER_GROUP, claimed_id)
                    continue

                # Reclaim for reprocessing
                await self._redis.xclaim(
                    STREAM_KEY,
                    CONSUMER_GROUP,
                    self._consumer_name,
                    min_idle_time=CLAIM_IDLE_MS,
                    message_ids=[msg_id],
                )
        except CONSUMER_ERRORS:
            logger.exception("Error reclaiming pending audit messages")

    async def _send_to_dlq(
        self,
        msg_id: bytes | str,
        data: dict[bytes | str, bytes | str],
        reason: str,
    ) -> None:
        """Write a failed message to the dead-letter queue stream."""
        try:
            dlq_fields: dict[str, str] = {
                "original_id": (msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)),
                "reason": reason,
            }
            for key, value in data.items():
                str_key = key.decode() if isinstance(key, bytes) else str(key)
                str_val = value.decode() if isinstance(value, bytes) else str(value)
                dlq_fields[f"orig_{str_key}"] = str_val
            await self._redis.xadd(DLQ_STREAM_KEY, dlq_fields)
        except CONSUMER_ERRORS:
            logger.exception("Failed to write to DLQ for message %s", msg_id)

    @staticmethod
    def _deserialize(
        data: dict[bytes | str, bytes | str],
    ) -> AuditEntry:
        """Convert a Redis Stream message dict to an AuditEntry model."""

        def _str(val: bytes | str | None) -> str | None:
            if val is None:
                return None
            return val.decode() if isinstance(val, bytes) else str(val)

        def _get(key: str) -> str | None:
            return _str(data.get(key) or data.get(key.encode()))

        event_type = _get("event_type")
        if not event_type:
            raise ValueError("Missing required field: event_type")

        timestamp_str = _get("timestamp")
        timestamp = datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.utcnow()

        inputs_raw = _get("inputs")
        inputs = json.loads(inputs_raw) if inputs_raw else None

        details_raw = _get("details")
        details = json.loads(details_raw) if details_raw else None

        return AuditEntry(
            event_type=event_type,
            actor=_get("actor"),
            tool=_get("tool"),
            inputs=inputs,
            result=_get("result"),
            details=details,
            ip_address=_get("ip_address"),
            timestamp=timestamp,
        )
