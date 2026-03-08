"""Placeholder management for PII Vault middleware."""

from .pii_vault_models import PIIEntity, RedactionResult


class PlaceholderManager:
    """Manages placeholder generation and text redaction/rehydration.

    Ensures consistent placeholder assignment for the same PII value
    within a session.
    """

    def __init__(self, placeholder_format: str = "<{type}_{id}>"):
        self.placeholder_format = placeholder_format
        self.mappings: dict[str, str] = {}  # original -> placeholder
        self.reverse_mappings: dict[str, str] = {}  # placeholder -> original
        self.counters: dict[str, int] = {}  # type -> counter

    def get_or_create(self, original: str, pii_type: str) -> str:
        """Get existing placeholder or create a new one."""
        if original in self.mappings:
            return self.mappings[original]

        count = self.counters.get(pii_type, 0) + 1
        self.counters[pii_type] = count

        placeholder = self.placeholder_format.format(type=pii_type, id=count)
        self.mappings[original] = placeholder
        self.reverse_mappings[placeholder] = original

        return placeholder

    def get_original(self, placeholder: str) -> str | None:
        """Get the original value for a placeholder."""
        return self.reverse_mappings.get(placeholder)

    def get_all_mappings(self) -> dict[str, str]:
        """Get all placeholder mappings."""
        return self.reverse_mappings.copy()

    def redact_text(self, text: str, entities: list[PIIEntity]) -> RedactionResult:
        """Redact PII entities from text in reverse order."""
        if not entities:
            return RedactionResult(text, [], {})

        # Sort entities by start position descending
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

        redacted_text = text
        current_mappings = {}

        for entity in sorted_entities:
            placeholder = self.get_or_create(entity.text, entity.pii_type)
            redacted_text = (
                redacted_text[: entity.start] + placeholder + redacted_text[entity.end :]
            )
            current_mappings[placeholder] = entity.text

        return RedactionResult(redacted_text, entities, current_mappings)

    def rehydrate_text(self, text: str, mappings: dict[str, str] | None = None) -> str:
        """Rehydrate placeholders in text."""
        active_mappings = mappings if mappings is not None else self.reverse_mappings

        # Sort placeholders by length descending to avoid partial replacements
        sorted_placeholders = sorted(active_mappings.keys(), key=len, reverse=True)

        result = text
        for placeholder in sorted_placeholders:
            result = result.replace(placeholder, active_mappings[placeholder])

        return result

    def clear(self) -> None:
        """Clear all mappings and counters."""
        self.mappings.clear()
        self.reverse_mappings.clear()
        self.counters.clear()
