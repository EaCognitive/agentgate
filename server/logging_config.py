"""Structured logging configuration for AgentGate server."""

import logging
import os
import sys
from pythonjsonlogger.json import JsonFormatter  # type: ignore[import]


class CustomJsonFormatter(JsonFormatter):  # type: ignore[misc]
    """Custom JSON formatter with standard fields."""

    def add_fields(self, log_data, record, message_dict):  # type: ignore[override]
        """Add custom fields to log records."""
        super().add_fields(log_data, record, message_dict)

        # Add standard fields
        log_data["level"] = record.levelname
        log_data["logger"] = record.name
        log_data["timestamp"] = self.formatTime(record, self.datefmt)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)


def setup_logging(log_level: str = "INFO", use_json: bool = True):
    """Configure structured logging.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        use_json: Whether to use JSON format (True) or plain text (False)
    """
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    # Remove existing handlers to reset configuration
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, log_level.upper()))

    formatter: logging.Formatter

    if use_json:
        # JSON formatter for production
        formatter = CustomJsonFormatter(
            "%(timestamp)s %(level)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    else:
        # Plain text formatter for development
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Set library log levels
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    presidio_level_name = os.getenv("PRESIDIO_LOG_LEVEL", "ERROR").upper()
    presidio_level = getattr(logging, presidio_level_name, logging.ERROR)
    logging.getLogger("presidio-analyzer").setLevel(presidio_level)
    logging.getLogger("presidio_analyzer").setLevel(presidio_level)

    return root_logger
