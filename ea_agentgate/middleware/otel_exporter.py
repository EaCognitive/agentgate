"""OpenTelemetry span export middleware."""

from __future__ import annotations

import logging
from types import ModuleType
from importlib import import_module
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

from .base import Middleware, MiddlewareContext

OTEL_TRACE: ModuleType | None
try:
    OTEL_TRACE = import_module("opentelemetry.trace")
    OTEL_SPAN_KIND = getattr(OTEL_TRACE, "SpanKind")
    OTEL_STATUS_CODE = getattr(OTEL_TRACE, "StatusCode")
except ImportError:
    OTEL_TRACE = None
    OTEL_SPAN_KIND = None
    OTEL_STATUS_CODE = None

if TYPE_CHECKING:
    from opentelemetry.trace import Tracer, Span

logger = logging.getLogger(__name__)


@dataclass
class OTelConfig:
    """Configuration for OpenTelemetry exporter."""

    service_name: str = "agentgate"
    propagate_context: bool = True
    record_inputs: bool = True
    record_outputs: bool = False
    max_attribute_length: int = 1024


class OTelExporter(Middleware):
    """
    OpenTelemetry span exporter for observability.

    Maps AgentGate Trace objects to OTel spans for integration with
    Datadog, Jaeger, Honeycomb, and other observability platforms.

    Example:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        # Setup OTel
        provider = TracerProvider()
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)

        # Use with AgentGate
        exporter = OTelExporter(service_name="my-agent")

        # Or with custom tracer
        tracer = trace.get_tracer("custom-tracer")
        exporter = OTelExporter(tracer=tracer)
    """

    def __init__(
        self,
        *,
        service_name: str = "agentgate",
        tracer: "Tracer | None" = None,
        propagate_context: bool = True,
        record_inputs: bool = True,
        record_outputs: bool = False,
        max_attribute_length: int = 1024,
    ) -> None:
        """
        Initialize OTel exporter.

        Args:
            service_name: Service name for spans
            tracer: Optional pre-configured OTel tracer
            propagate_context: Whether to propagate trace context
            record_inputs: Whether to record tool inputs as attributes
            record_outputs: Whether to record outputs (may contain sensitive data)
            max_attribute_length: Maximum length for attribute values
        """
        super().__init__()
        self.config = OTelConfig(
            service_name=service_name,
            propagate_context=propagate_context,
            record_inputs=record_inputs,
            record_outputs=record_outputs,
            max_attribute_length=max_attribute_length,
        )

        self._tracer = tracer
        self._spans: dict[str, "Span"] = {}
        self._otel_available = self._check_otel_available()

    def _check_otel_available(self) -> bool:
        """Check if OpenTelemetry is available as an optional dependency."""
        return (
            OTEL_TRACE is not None and OTEL_SPAN_KIND is not None and OTEL_STATUS_CODE is not None
        )

    def _get_tracer(self) -> "Tracer | None":
        """Get or create OTel tracer (optional dependency)."""
        if self._tracer:
            return self._tracer

        if not self._otel_available:
            return None

        try:
            trace_module = OTEL_TRACE
            if trace_module is None:
                return None
            self._tracer = trace_module.get_tracer(self.config.service_name)
            return self._tracer
        except (ImportError, AttributeError):
            # OpenTelemetry not installed or unavailable
            logger.debug("OpenTelemetry initialization failed; tracing disabled")
            return None
        except (RuntimeError, ValueError, KeyError) as exc:
            # OTel initialization errors should not crash the application
            logger.debug("Failed to initialize OpenTelemetry tracer: %s", exc)
            return None

    def before(self, ctx: MiddlewareContext) -> None:
        """Start OTel span before tool execution."""
        tracer = self._get_tracer()
        if not tracer or OTEL_SPAN_KIND is None:
            return

        try:
            span_name = f"tool.{ctx.tool}"
            span = tracer.start_span(
                span_name,
                kind=OTEL_SPAN_KIND.INTERNAL,
            )

            span.set_attribute("ea_agentgate.trace_id", ctx.trace.id)
            span.set_attribute("ea_agentgate.tool", ctx.tool)
            span.set_attribute("ea_agentgate.service", self.config.service_name)

            if ctx.agent_id:
                span.set_attribute("ea_agentgate.agent_id", ctx.agent_id)
            if ctx.session_id:
                span.set_attribute("ea_agentgate.session_id", ctx.session_id)
            if ctx.user_id:
                span.set_attribute("ea_agentgate.user_id", ctx.user_id)

            if ctx.trace.context.parent_id:
                span.set_attribute("ea_agentgate.parent_trace_id", ctx.trace.context.parent_id)

            if self.config.record_inputs:
                for key, value in ctx.inputs.items():
                    attr_value = self._truncate_value(value)
                    span.set_attribute(f"ea_agentgate.input.{key}", attr_value)

            self._spans[ctx.trace.id] = span

        except (ImportError, AttributeError):
            # OpenTelemetry span API unavailable
            logger.debug("Failed to create OpenTelemetry span")
        except (RuntimeError, ValueError, KeyError) as exc:
            # Telemetry errors should never crash the application
            logger.debug("Error recording span: %s", exc)

    def _build_span_attributes(
        self,
        span: "Span",
        ctx: MiddlewareContext,
        result: Any,
        error: Exception | None,
    ) -> None:
        """Populate span attributes, status, and events from execution context."""
        if ctx.trace.timing.duration_ms is not None:
            span.set_attribute("ea_agentgate.duration_ms", ctx.trace.timing.duration_ms)

        span.set_attribute("ea_agentgate.status", ctx.trace.status.value)

        if ctx.cost:
            span.set_attribute("ea_agentgate.cost", ctx.cost)

        if ctx.trace.context.blocked_by:
            span.add_event(
                "blocked",
                {
                    "middleware": ctx.trace.context.blocked_by,
                    "reason": ctx.trace.result.error or "",
                },
            )
            if OTEL_STATUS_CODE is not None:
                span.set_status(OTEL_STATUS_CODE.ERROR, ctx.trace.result.error or "Blocked")
        elif error:
            if OTEL_STATUS_CODE is not None:
                span.set_status(OTEL_STATUS_CODE.ERROR, str(error))
            span.record_exception(error)
        else:
            if OTEL_STATUS_CODE is not None:
                span.set_status(OTEL_STATUS_CODE.OK)
            if self.config.record_outputs and result is not None:
                output_value = self._truncate_value(result)
                span.set_attribute("ea_agentgate.output", output_value)

        for key, value in ctx.metadata.items():
            if key.startswith("semantic_"):
                span.set_attribute(f"ea_agentgate.{key}", str(value))

    def after(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """End OTel span after tool execution."""
        span = self._spans.pop(ctx.trace.id, None)
        if not span:
            return

        try:
            self._build_span_attributes(span, ctx, result, error)
            span.end()
        except (ImportError, AttributeError):
            logger.debug("Failed to update OpenTelemetry span attributes")
            self._safe_close_span(span)
        except (RuntimeError, ValueError, KeyError) as exc:
            logger.debug("Error closing span: %s", exc)
            self._safe_close_span(span)

    def _safe_close_span(self, span: "Span") -> None:
        """Safely close a span, logging any errors."""
        try:
            span.end()
        except (RuntimeError, ValueError, KeyError) as exc:
            logger.debug("Error closing span: %s", exc)

    def _truncate_value(self, value: Any) -> str:
        """Truncate value to max attribute length."""
        str_value = str(value)
        max_len = self.config.max_attribute_length
        if len(str_value) > max_len:
            return str_value[: max_len - 3] + "..."
        return str_value


__all__ = ["OTelExporter"]
