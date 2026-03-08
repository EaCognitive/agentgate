"""Data models for PII Vault middleware."""

from dataclasses import dataclass


@dataclass
class PIIEntity:
    """A detected PII entity in text.

    Attributes:
        text: The detected PII text (e.g., "Erick Aleman")
        pii_type: Type of PII (e.g., "PERSON", "EMAIL", "SSN")
        start: Start index in the original text
        end: End index in the original text
        confidence: Detection confidence score (0.0 - 1.0)
    """

    text: str
    pii_type: str
    start: int
    end: int
    confidence: float = 1.0


@dataclass
class RedactionResult:
    """Result of redacting PII from text."""

    redacted_text: str
    entities: list[PIIEntity]
    mappings: dict[str, str]
