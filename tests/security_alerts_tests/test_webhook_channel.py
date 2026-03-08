"""Tests for WebhookAlertChannel."""

import logging
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server.policy_governance.kernel.alerts import (
    AlertContentInfo,
    AlertEventInfo,
    AlertPriority,
    SecurityAlert,
    WebhookAlertChannel,
)


class TestWebhookAlertChannel:
    """Tests for WebhookAlertChannel."""

    def test_initialization(self) -> None:
        """Test webhook channel initialization."""
        channel = WebhookAlertChannel(
            url="https://example.com/webhook",
            headers={"Authorization": "Bearer token"},
            timeout=5.0,
            min_priority=AlertPriority.HIGH,
        )

        assert "webhook:https://example.com/webhook" in channel.name
        assert channel.supports_async is True

    def test_name_property(self) -> None:
        """Test webhook channel name property."""
        channel = WebhookAlertChannel(url="https://example.com/webhook")
        assert channel.name == "webhook:https://example.com/webhook"

    def test_name_truncated_for_long_urls(self) -> None:
        """Test that long URLs are truncated in channel name."""
        long_url = "https://example.com/" + "a" * 100
        channel = WebhookAlertChannel(url=long_url)
        assert len(channel.name) <= 58  # "webhook:" + 50 chars

    def test_supports_async_property(self) -> None:
        """Test supports_async property."""
        channel = WebhookAlertChannel(url="https://example.com/webhook")
        assert channel.supports_async is True

    def test_should_send_checks_priority(self) -> None:
        """Test _should_send respects minimum priority."""
        channel = WebhookAlertChannel(
            url="https://example.com/webhook",
            min_priority=AlertPriority.HIGH,
        )

        low_alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.LOW,
            ),
            content_info=AlertContentInfo(
                title="Test",
                description="Test",
                source="test",
                category="test",
            ),
        )

        high_alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test",
                description="Test",
                source="test",
                category="test",
            ),
        )

        # Low priority should not be sent
        with patch("httpx.Client") as mock_client:
            result = channel.send(low_alert)
            assert result is True
            mock_client.assert_not_called()

        # High priority should be sent
        with patch("httpx.Client") as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__enter__.return_value.post.return_value = mock_response

            result = channel.send(high_alert)
            assert result is True

    def test_send_success(self) -> None:
        """Test successful webhook delivery."""
        channel = WebhookAlertChannel(url="https://example.com/webhook")
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test Alert",
                description="Test",
                source="test",
                category="test",
            ),
        )

        with patch("httpx.Client") as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__enter__.return_value.post.return_value = mock_response

            result = channel.send(alert)

        assert result is True
        mock_client.return_value.__enter__.return_value.post.assert_called_once()

    def test_send_with_custom_headers(self) -> None:
        """Test webhook with custom headers."""
        channel = WebhookAlertChannel(
            url="https://example.com/webhook",
            headers={"X-Custom-Header": "value"},
        )
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test",
                description="Test",
                source="test",
                category="test",
            ),
        )

        with patch("httpx.Client") as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__enter__.return_value.post.return_value = mock_response

            channel.send(alert)

            call_args = mock_client.return_value.__enter__.return_value.post.call_args
            headers = call_args.kwargs["headers"]
            assert headers["X-Custom-Header"] == "value"
            assert headers["Content-Type"] == "application/json"

    def test_send_with_transform(self) -> None:
        """Test webhook with custom payload transform."""

        def custom_transform(alert: SecurityAlert) -> dict[str, Any]:
            return {
                "custom_field": "custom_value",
                "alert_title": alert.title,
            }

        channel = WebhookAlertChannel(
            url="https://example.com/webhook",
            transform=custom_transform,
        )
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test Alert",
                description="Test",
                source="test",
                category="test",
            ),
        )

        with patch("httpx.Client") as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__enter__.return_value.post.return_value = mock_response

            channel.send(alert)

            call_args = mock_client.return_value.__enter__.return_value.post.call_args
            payload = call_args.kwargs["json"]
            assert payload["custom_field"] == "custom_value"
            assert payload["alert_title"] == "Test Alert"

    def test_send_httpx_not_installed(self, caplog) -> None:
        """Test webhook when httpx is not installed."""
        channel = WebhookAlertChannel(url="https://example.com/webhook")
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test",
                description="Test",
                source="test",
                category="test",
            ),
        )

        with patch("builtins.__import__", side_effect=ImportError("No module named 'httpx'")):
            with caplog.at_level(logging.WARNING):
                result = channel.send(alert)

        assert result is False
        assert "httpx not installed" in caplog.text

    def test_send_http_error(self, caplog) -> None:
        """Test webhook with HTTP error."""
        channel = WebhookAlertChannel(url="https://example.com/webhook")
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test",
                description="Test",
                source="test",
                category="test",
            ),
        )

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.post.side_effect = Exception(
                "Connection error"
            )

            with caplog.at_level(logging.ERROR):
                result = channel.send(alert)

        assert result is False
        assert "Failed to send webhook alert" in caplog.text

    @pytest.mark.asyncio
    async def test_send_async_success(self) -> None:
        """Test successful async webhook delivery."""
        channel = WebhookAlertChannel(url="https://example.com/webhook")
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test Alert",
                description="Test",
                source="test",
                category="test",
            ),
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await channel.send_async(alert)

        assert result is True

    @pytest.mark.asyncio
    async def test_send_async_below_min_priority(self) -> None:
        """Test async send with alert below minimum priority."""
        channel = WebhookAlertChannel(
            url="https://example.com/webhook",
            min_priority=AlertPriority.CRITICAL,
        )
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.LOW,
            ),
            content_info=AlertContentInfo(
                title="Test",
                description="Test",
                source="test",
                category="test",
            ),
        )

        result = await channel.send_async(alert)
        assert result is True  # Returns True without sending

    @pytest.mark.asyncio
    async def test_send_async_httpx_not_installed(self, caplog) -> None:
        """Test async webhook when httpx is not installed."""
        channel = WebhookAlertChannel(url="https://example.com/webhook")
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test",
                description="Test",
                source="test",
                category="test",
            ),
        )

        with patch("builtins.__import__", side_effect=ImportError("No module named 'httpx'")):
            with caplog.at_level(logging.WARNING):
                result = await channel.send_async(alert)

        assert result is False
        assert "httpx not installed" in caplog.text

    @pytest.mark.asyncio
    async def test_send_async_http_error(self, caplog) -> None:
        """Test async webhook with HTTP error."""
        channel = WebhookAlertChannel(url="https://example.com/webhook")
        alert = SecurityAlert(
            event_info=AlertEventInfo(
                alert_id="test",
                timestamp=time.time(),
                priority=AlertPriority.HIGH,
            ),
            content_info=AlertContentInfo(
                title="Test",
                description="Test",
                source="test",
                category="test",
            ),
        )

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=Exception("Connection error")
            )

            with caplog.at_level(logging.ERROR):
                result = await channel.send_async(alert)

        assert result is False
        assert "Failed to send async webhook alert" in caplog.text
