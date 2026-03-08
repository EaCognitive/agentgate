"""Tests for miscellaneous utilities."""

from datetime import datetime, timezone

from server.models.schemas import utc_now


def test_utc_now() -> None:
    """utc_now returns a naive UTC datetime suitable for SQL timestamps."""
    now = utc_now()
    assert isinstance(now, datetime)
    assert now.tzinfo is None

    current = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs((now - current).total_seconds()) < 1
