"""PII Detection logic for PII Vault middleware."""

import asyncio
import concurrent.futures
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TYPE_CHECKING, cast

try:
    import spacy
except ImportError:
    spacy = None  # type: ignore

from ..prompts import get_pii_detection_prompt
from .pii_vault_models import PIIEntity

if TYPE_CHECKING:
    from ..providers.base import LLMProvider

logger = logging.getLogger(__name__)


class _WarmupState:
    """Module-level state for spaCy model preloading completion.

    This avoids cold-start delay on first request and allows the warmup()
    function to run once per application lifetime.
    """

    _complete = False

    @classmethod
    def set_complete(cls, value: bool) -> None:
        """Set the warmup completion flag."""
        cls._complete = value

    @classmethod
    def is_complete(cls) -> bool:
        """Get the warmup completion flag."""
        return cls._complete


def _get_warmup_complete() -> bool:
    """Get the warmup completion flag."""
    return _WarmupState.is_complete()


def _set_warmup_complete(value: bool) -> None:
    """Set the warmup completion flag."""
    _WarmupState.set_complete(value)


def _collect_spacy_models() -> set[str]:
    """Collect spaCy model names from configuration/environment."""
    models: set[str] = set()

    raw_models = os.getenv("PII_LANGUAGE_MODELS")
    if raw_models:
        for pair in raw_models.split(","):
            pair = pair.strip()
            if ":" in pair:
                _, model = pair.split(":", 1)
                if model.strip():
                    models.add(model.strip())
            elif pair:
                models.add(pair)
    else:
        models.add("en_core_web_lg")

    multilingual_model = os.getenv("PII_MULTILINGUAL_MODEL", "xx_ent_wiki_sm").strip()
    if multilingual_model:
        models.add(multilingual_model)

    return models


async def warmup() -> None:
    """
    Preload spaCy NLP pipelines so the first request does not pay the cold-start cost.

    Best-effort: skips silently if spaCy/models are not available.
    """
    if _get_warmup_complete():
        return

    models = _collect_spacy_models()
    if not models:
        _set_warmup_complete(True)
        return

    try:
        if spacy is None:
            raise ImportError("spacy not imported")
        spacy_module = spacy
    except ImportError:
        logger.info("PIIVault warmup skipped: spaCy not installed")
        _set_warmup_complete(True)
        return

    async def _load_model(model_name: str) -> None:
        try:
            await asyncio.to_thread(spacy_module.load, model_name)
            logger.info("PIIVault warmup loaded spaCy model %s", model_name)
        except OSError as exc:
            logger.warning("PIIVault warmup missing spaCy model %s: %s", model_name, exc)
        except (RuntimeError, ValueError, AttributeError) as exc:
            # Defensive logging for expected errors during model loading
            logger.warning("PIIVault warmup failed for %s: %s", model_name, exc)

    await asyncio.gather(*(_load_model(model) for model in models))
    _set_warmup_complete(True)


class PIIPatterns:
    """Compiled regex patterns for common PII types.

    A utility class containing compiled regex patterns for detecting
    common PII types. This class provides methods to check patterns
    against text and list available patterns.
    """

    EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", re.IGNORECASE)
    SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    PHONE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
    CREDIT_CARD = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
    IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    DATE = re.compile(r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b")
    ZIP_CODE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
    DRIVERS_LICENSE = re.compile(r"\b(?=.*\d)(?=.*[A-Z])[A-Z0-9]{7,20}\b", re.IGNORECASE)
    PASSPORT = re.compile(r"\b(?=.*\d)(?=.*[A-Z])[A-Z0-9]{9,12}\b", re.IGNORECASE)
    BANK_ACCOUNT = re.compile(r"\b\d{8,12}\b")

    ALL = {
        "EMAIL": EMAIL,
        "SSN": SSN,
        "PHONE": PHONE,
        "CREDIT_CARD": CREDIT_CARD,
        "IP_ADDRESS": IP_ADDRESS,
        "DATE": DATE,
        "ZIP_CODE": ZIP_CODE,
        "DRIVERS_LICENSE": DRIVERS_LICENSE,
        "PASSPORT": PASSPORT,
        "BANK_ACCOUNT": BANK_ACCOUNT,
    }

    @classmethod
    def get_patterns(cls) -> dict[str, re.Pattern[str]]:
        """Get all available PII patterns.

        Returns:
            Dictionary mapping pattern names to compiled regex patterns
        """
        return cls.ALL.copy()

    @classmethod
    def get_pattern_names(cls) -> list[str]:
        """Get list of all available pattern names.

        Returns:
            List of pattern names in the ALL dictionary
        """
        return list(cls.ALL.keys())


class PIIDetector:
    """Detects PII in text using regex patterns, spaCy, and optional LLM validation."""

    LLM_DETECTION_PROMPT = get_pii_detection_prompt()

    def __init__(
        self,
        *,
        pii_types: list[str] | None = None,
        use_regex: bool = True,
        use_spacy: bool = True,
        use_llm: bool = False,
        provider: "LLMProvider | None" = None,
        min_confidence: float = 0.5,
    ):
        if use_llm and not provider:
            raise ValueError("use_llm=True requires a provider")

        self.pii_types = pii_types
        # Combine detection flags to reduce instance attribute count
        self.config = {
            "use_regex": use_regex,
            "use_spacy": use_spacy,
            "use_llm": use_llm,
        }
        self.provider = provider
        self.min_confidence = min_confidence
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._nlp_pipelines = {}

        if self.config["use_spacy"]:
            try:
                if spacy is None:
                    raise ImportError("spacy not imported")
                spacy_module = spacy
                models = _collect_spacy_models()
                for model in models:
                    try:
                        self._nlp_pipelines[model] = spacy_module.load(model)
                    except OSError as exc:
                        logger.warning(
                            "Failed to load spaCy model %s (not downloaded): %s",
                            model,
                            exc,
                        )
                    except (RuntimeError, ValueError, AttributeError) as exc:
                        # Expected errors during model loading (e.g., corrupted model files)
                        logger.warning("Unexpected error loading spaCy model %s: %s", model, exc)
            except ImportError:
                logger.info("spaCy not installed, skipping MLP detection")
                self.config["use_spacy"] = False

    @property
    def use_llm(self) -> bool:
        """Whether LLM detection is enabled."""
        return self.config["use_llm"]

    def detect(self, text: str) -> list[PIIEntity]:
        """Detect PII entities in text (sync)."""
        entities: list[PIIEntity] = []
        if self.config["use_regex"]:
            entities.extend(self._detect_with_regex(text))
        if self.config["use_spacy"]:
            entities.extend(self._detect_with_spacy(text))
        if self.config["use_llm"] and self.provider:
            entities.extend(self._detect_with_llm(text))

        # Filter by pii_types if specified
        if self.pii_types:
            entities = [e for e in entities if e.pii_type in self.pii_types]

        return self._deduplicate_entities(entities)

    async def adetect(self, text: str) -> list[PIIEntity]:
        """Detect PII entities in text (async)."""
        entities: list[PIIEntity] = []
        tasks = []
        if self.config["use_regex"]:
            entities.extend(self._detect_with_regex(text))
        if self.config["use_spacy"]:
            # spaCy is CPU bound, run in thread pool
            tasks.append(asyncio.to_thread(self._detect_with_spacy, text))
        if self.config["use_llm"] and self.provider:
            tasks.append(self._adetect_with_llm(text))

        if tasks:
            results = await asyncio.gather(*tasks)
            for res in results:
                entities.extend(res)

        # Filter by pii_types if specified
        if self.pii_types:
            entities = [e for e in entities if e.pii_type in self.pii_types]

        return self._deduplicate_entities(entities)

    def _detect_with_regex(self, text: str) -> list[PIIEntity]:
        entities = []
        for pii_type, pattern in PIIPatterns.ALL.items():
            for match in pattern.finditer(text):
                entities.append(
                    PIIEntity(
                        text=match.group(),
                        pii_type=pii_type,
                        start=match.start(),
                        end=match.end(),
                        confidence=1.0,
                    )
                )
        return entities

    def _detect_with_spacy(self, text: str) -> list[PIIEntity]:
        """Detect PII using spaCy NER pipelines."""
        entities: list[PIIEntity] = []

        # Map spaCy entity labels to PII types
        label_map = {
            "PERSON": "PERSON",
            "GPE": "LOCATION",
            "LOC": "LOCATION",
            "ORG": "ORGANIZATION",
            "FAC": "LOCATION",
        }

        for model_name, nlp in self._nlp_pipelines.items():
            try:
                doc = nlp(text)
                for ent in doc.ents:
                    if ent.label_ in label_map:
                        pii_type = label_map[ent.label_]
                        entities.append(
                            PIIEntity(
                                text=ent.text,
                                pii_type=pii_type,
                                start=ent.start_char,
                                end=ent.end_char,
                                confidence=0.9,
                            )
                        )
            except (AttributeError, ValueError) as exc:
                # Expected errors: text encoding issues, invalid model state
                logger.debug("spaCy detection error for model %s: %s", model_name, exc)
            except (RuntimeError, KeyError, IndexError) as exc:
                # Expected errors during detection
                logger.error(
                    "Error during spaCy detection for model %s: %s",
                    model_name,
                    exc,
                )

        return entities

    def _detect_with_llm(self, text: str) -> list[PIIEntity]:
        """Detect PII using LLM (sync), offloading to a thread when necessary."""
        if not self.provider:
            return []

        prompt = self.LLM_DETECTION_PROMPT.format(text=text)

        try:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            if loop.is_running():
                # Event loop is already running (e.g. inside FastAPI handler).
                # Run the sync provider call in a thread via the executor so
                # we don't block and don't silently skip detection.
                future = self._executor.submit(self.provider.complete, prompt)
                response = future.result(timeout=30)
            else:
                response = loop.run_until_complete(
                    asyncio.to_thread(self.provider.complete, prompt)
                )

            return self._parse_llm_response(text, response.content)
        except RuntimeError as exc:
            logger.debug("Cannot run LLM detection in current event loop: %s", exc)
            return []
        except AttributeError as exc:
            logger.debug("LLM provider missing required method: %s", exc)
            return []
        except concurrent.futures.TimeoutError:
            logger.debug("LLM PII detection timed out")
            return []
        except (OSError, ValueError, KeyError) as exc:
            logger.debug("LLM PII detection failed: %s", type(exc).__name__)
            return []

    async def _adetect_with_llm(self, text: str) -> list[PIIEntity]:
        """Detect PII using LLM (async)."""
        if not self.provider:
            return []

        prompt = self.LLM_DETECTION_PROMPT.format(text=text)

        try:
            if hasattr(self.provider, "acomplete"):
                response = await cast(Any, self.provider).acomplete(prompt)
            else:
                response = await asyncio.to_thread(self.provider.complete, prompt)
            return self._parse_llm_response(text, response.content)
        except AttributeError as exc:
            # Provider missing required methods or response missing content attribute
            logger.debug("LLM provider missing required method/attribute: %s", exc)
            return []
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            # Network, API, or other provider errors should not crash PII detection
            logger.debug("Async LLM PII detection failed: %s", type(exc).__name__)
            return []

    def _parse_llm_response(self, original_text: str, response: str) -> list[PIIEntity]:
        """Parse LLM response and create PIIEntity objects."""
        entities: list[PIIEntity] = []

        try:
            json_str = response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]

            data = json.loads(json_str.strip())

            for item in data.get("entities", []):
                entity_text = item.get("text", "")
                entity_type = item.get("type", "OTHER")

                start = original_text.find(entity_text)
                if start == -1:
                    continue

                if self.pii_types and entity_type not in self.pii_types:
                    continue

                entities.append(
                    PIIEntity(
                        text=entity_text,
                        pii_type=entity_type,
                        start=start,
                        end=start + len(entity_text),
                        confidence=0.8,
                    )
                )

        except (json.JSONDecodeError, KeyError, TypeError):
            pass

        return entities

    def _deduplicate_entities(self, entities: list[PIIEntity]) -> list[PIIEntity]:
        """Remove duplicate and overlapping entities."""
        if not entities:
            return []

        sorted_entities = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))

        result: list[PIIEntity] = []
        for entity in sorted_entities:
            overlaps = False
            for existing in result:
                if not (entity.end <= existing.start or entity.start >= existing.end):
                    overlaps = True
                    break

            if not overlaps:
                result.append(entity)

        return result
