"""PII Detection & Redaction NLP Engine for AgentGate.

Supports multilingual PII detection using Microsoft Presidio and spaCy.
Implements O-01: Lazy initialization of NLP models to avoid blocking startup.
"""

import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from starlette.concurrency import run_in_threadpool

_presidio_level_name = os.getenv("PRESIDIO_LOG_LEVEL", "ERROR").upper()
_presidio_level = getattr(logging, _presidio_level_name, logging.ERROR)
for _logger_name in ("presidio-analyzer", "presidio_analyzer"):
    logging.getLogger(_logger_name).setLevel(_presidio_level)

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
except ImportError:
    AnalyzerEngine = None
    NlpEngineProvider = None

try:
    from lingua import LanguageDetectorBuilder
except ImportError:
    LanguageDetectorBuilder = None

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine as PresidioAnalyzerEngine
    from presidio_analyzer import RecognizerResult as PresidioRecognizerResult
else:
    PresidioAnalyzerEngine = Any
    PresidioRecognizerResult = Any

_logger = logging.getLogger(__name__)


@dataclass
class _RegexDetection:
    """Minimal RecognizerResult-like detection for regex fallback mode."""

    entity_type: str
    start: int
    end: int
    score: float


_REGEX_FALLBACK_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "EMAIL_ADDRESS",
        re.compile(r"(?<!\S)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?!\S)"),
        0.97,
    ),
    (
        "PHONE_NUMBER",
        re.compile(r"(?<!\S)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}(?!\S)"),
        0.92,
    ),
    ("US_SSN", re.compile(r"(?<!\S)\d{3}-\d{2}-\d{4}(?!\S)"), 0.98),
    ("CREDIT_CARD", re.compile(r"(?<!\S)(?:\d[ -]*?){13,19}(?!\S)"), 0.90),
    ("IP_ADDRESS", re.compile(r"(?<!\S)(?:\d{1,3}\.){3}\d{1,3}(?!\S)"), 0.86),
)


def _regex_fallback_detections(
    text: str,
    *,
    score_threshold: float,
) -> list[_RegexDetection]:
    """Detect common high-signal PII patterns when NLP engines are unavailable."""
    detections: list[_RegexDetection] = []
    for entity_type, pattern, score in _REGEX_FALLBACK_PATTERNS:
        if score < score_threshold:
            continue
        for match in pattern.finditer(text):
            detections.append(
                _RegexDetection(
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    score=score,
                )
            )
    return detections


class _MultilingualAnalyzerManager:
    """
    Thread-safe lazy manager for multiple Presidio AnalyzerEngine instances.

    Implements O-01: Defers model loading until first use.
    Supports multilingual detection by managing engines for different languages.
    """

    _engines: dict[str, PresidioAnalyzerEngine] = {}
    _engine_errors: dict[str, str] = {}
    _lock = threading.Lock()
    _language_detector: object | None = None
    _language_detector_loaded: bool = False
    _config_loaded: bool = False

    # Configuration (populated from env vars on first use)
    _multilingual_model: str = ""
    _language_models: dict[str, str] = {}
    _auto_detect_language: bool = True
    _default_language: str = "en"

    @classmethod
    def _load_config(cls) -> None:
        """Load configuration from environment variables (once)."""
        if cls._config_loaded:
            return
        cls._multilingual_model = os.environ.get("PII_MULTILINGUAL_MODEL", "xx_ent_wiki_sm")
        raw_models = os.environ.get("PII_LANGUAGE_MODELS", "en:en_core_web_lg")
        cls._language_models = {}
        for pair in raw_models.split(","):
            pair = pair.strip()
            if ":" in pair:
                lang, model = pair.split(":", 1)
                cls._language_models[lang.strip()] = model.strip()
        cls._auto_detect_language = os.environ.get("PII_AUTO_DETECT_LANGUAGE", "true").lower() in (
            "true",
            "1",
            "yes",
        )
        cls._default_language = os.environ.get("PII_DEFAULT_LANGUAGE", "en")
        cls._config_loaded = True

    @classmethod
    def _create_engine(
        cls,
        lang_code: str,
        model_name: str,
    ) -> PresidioAnalyzerEngine | None:
        """Create an AnalyzerEngine for a specific language/model. Returns None on failure."""
        try:
            if AnalyzerEngine is None or NlpEngineProvider is None:
                raise ImportError("Presidio libraries not installed")

            nlp_provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": lang_code, "model_name": model_name}],
                }
            )
            engine = AnalyzerEngine(nlp_engine=nlp_provider.create_engine())
            _logger.info("Presidio engine initialized: lang=%s model=%s", lang_code, model_name)
            return engine
        except (ImportError, OSError, ValueError, RuntimeError, SystemExit) as exc:
            cls._engine_errors[lang_code] = str(exc)
            _logger.warning(
                "Failed to initialize Presidio engine for lang=%s model=%s: %s",
                lang_code,
                model_name,
                exc,
            )
            return None

    @classmethod
    def _resolve_model_name(cls, lang_code: str) -> str | None:
        if lang_code == "xx":
            model_name = cls._multilingual_model
            if not model_name:
                _logger.info("Multilingual model disabled (PII_MULTILINGUAL_MODEL empty)")
                cls._engine_errors["xx"] = "disabled"
                return None
            return model_name

        if lang_code in cls._language_models:
            return cls._language_models[lang_code]

        cls._engine_errors[lang_code] = "no model configured"
        return None

    @classmethod
    def _get_engine_locked(cls, lang_code: str) -> PresidioAnalyzerEngine | None:
        with cls._lock:
            # Double-check
            if lang_code in cls._engines:
                return cls._engines[lang_code]
            if lang_code in cls._engine_errors:
                return None

            model_name = cls._resolve_model_name(lang_code)
            if not model_name:
                return None

            engine = cls._create_engine(lang_code, model_name)
            if engine is not None:
                cls._engines[lang_code] = engine
            return engine

    @classmethod
    def get_engine(cls, lang_code: str) -> PresidioAnalyzerEngine | None:
        """Get or create the AnalyzerEngine for a given language code."""
        cls._load_config()
        if lang_code in cls._engines:
            return cls._engines[lang_code]
        if lang_code in cls._engine_errors:
            return None
        return cls._get_engine_locked(lang_code)

    @classmethod
    def detect_language(cls, text: str) -> str | None:
        """Auto-detect input language via lingua. Returns ISO 639-1 code or None."""
        cls._load_config()
        if not cls._auto_detect_language:
            return None
        detector: Any = cls._get_language_detector()
        if detector is None:
            return None
        try:
            result = detector.detect_language_of(text)
            if result is not None:
                return str(result.iso_code_639_1.name.lower())
        except (AttributeError, ValueError, TypeError) as exc:
            _logger.warning("Language detection failed: %s", exc)
        return None

    @classmethod
    def _get_language_detector(cls) -> object | None:
        """Lazy-load the lingua LanguageDetector.

        Uses low-accuracy mode by default to reduce memory footprint.
        The full model set (~700 MB) causes OOM kills in memory-constrained
        containers. Low-accuracy mode loads a small subset of language models
        and is sufficient for texts longer than 120 characters.

        Set PII_LINGUA_HIGH_ACCURACY=true to use the full model set
        (requires increasing the container memory limit above 2 GiB).
        """
        if cls._language_detector_loaded:
            return cls._language_detector

        with cls._lock:
            if cls._language_detector_loaded:
                return cls._language_detector

            try:
                if LanguageDetectorBuilder is None:
                    raise ImportError("lingua-language-detector not installed")

                high_accuracy = os.environ.get("PII_LINGUA_HIGH_ACCURACY", "false").lower() in (
                    "true",
                    "1",
                    "yes",
                )

                builder = (
                    LanguageDetectorBuilder.from_all_languages().with_minimum_relative_distance(
                        0.25
                    )
                )
                if not high_accuracy:
                    builder = builder.with_low_accuracy_mode()
                cls._language_detector = builder.build()
                mode = "high-accuracy" if high_accuracy else "low-accuracy"
                _logger.info(
                    "Lingua language detector initialized (mode=%s)",
                    mode,
                )
            except ImportError:
                _logger.warning("lingua-language-detector not installed; auto-detection disabled")
                cls._language_detector = None
            except (OSError, ValueError, RuntimeError) as exc:
                _logger.warning("Failed to initialize lingua detector: %s", exc)
                cls._language_detector = None

            cls._language_detector_loaded = True

        return cls._language_detector

    @classmethod
    def get_default_language(cls) -> str:
        """Get the default language code."""
        cls._load_config()
        return cls._default_language or "en"

    @classmethod
    def get_status(cls) -> dict:
        """Diagnostic status of loaded engines and configuration."""
        cls._load_config()
        return {
            "multilingual_model": cls._multilingual_model,
            "language_models": dict(cls._language_models),
            "auto_detect_language": cls._auto_detect_language,
            "default_language": cls._default_language,
            "loaded_engines": list(cls._engines.keys()),
            "engine_errors": dict(cls._engine_errors),
            "language_detector_available": cls._language_detector is not None,
        }

    @classmethod
    def is_initialized(cls) -> bool:
        """Check if any analyzer engine has been initialized (backwards compat)."""
        return len(cls._engines) > 0

    @classmethod
    def _reset_for_testing(cls) -> None:
        """Reset all state (for test fixtures only)."""
        cls._engines = {}
        cls._engine_errors = {}
        cls._language_detector = None
        cls._language_detector_loaded = False
        cls._config_loaded = False
        cls._multilingual_model = ""
        cls._language_models = {}
        cls._auto_detect_language = True
        cls._default_language = "en"


# Supported PII entity types
SUPPORTED_ENTITIES = [
    "PERSON",  # NLP: "John Smith", "O'Brien", "Kim Jong Un"
    "EMAIL_ADDRESS",  # Regex: all standard email formats
    "PHONE_NUMBER",  # Regex+context: US, UK, international formats
    "US_SSN",  # Regex+checksum: XXX-XX-XXXX
    "CREDIT_CARD",  # Regex+Luhn: Visa, MC, Amex, Discover, etc.
    "IP_ADDRESS",  # Regex: IPv4 and IPv6
    "LOCATION",  # NLP: cities, countries, addresses
    "DATE_TIME",  # NLP+regex: dates, times
    "US_DRIVER_LICENSE",
    "US_PASSPORT",
    "US_BANK_NUMBER",
    "IBAN_CODE",
    "URL",
    "MEDICAL_LICENSE",
    "NRP",  # NLP: nationality, religion, political group
]


def _merge_detections(
    all_results: list[PresidioRecognizerResult],
) -> list[PresidioRecognizerResult]:
    """
    Merge and deduplicate overlapping PII detections from multiple engines.

    Uses a sweep-line algorithm:
    1. Sort by start position, then by score descending
    2. Sweep through; for overlapping spans, keep the detection with highest score
       (ties broken by longest span)

    Time complexity: O(n log n)
    """
    if not all_results:
        return []

    # Sort: primary by start ascending, secondary by score descending,
    # tertiary by span length descending
    sorted_results = sorted(
        all_results,
        key=lambda r: (r.start, -r.score, -(r.end - r.start)),
    )

    merged: list[PresidioRecognizerResult] = []
    current = sorted_results[0]

    for candidate in sorted_results[1:]:
        if candidate.start < current.end:
            # Overlapping: keep higher score, break ties with longer span
            if candidate.score > current.score or (
                candidate.score == current.score
                and (candidate.end - candidate.start) > (current.end - current.start)
            ):
                current = candidate
        else:
            merged.append(current)
            current = candidate

    merged.append(current)
    return merged


def _run_presidio_analysis(
    engine: PresidioAnalyzerEngine | None,
    text: str,
    language: str,
    *,
    score_threshold: float = 0.4,
    all_results: list | None = None,
    meta_engines: list | None = None,
) -> None:
    """Run a single Presidio engine analysis and append results."""
    if engine is None:
        return

    try:
        results = engine.analyze(
            text=text,
            entities=SUPPORTED_ENTITIES,
            language=language,
            score_threshold=score_threshold,
        )
        if all_results is not None:
            all_results.extend(results)
        if meta_engines is not None:
            meta_engines.append(language)
    except (AttributeError, ValueError, TypeError, OSError, RuntimeError) as exc:
        _logger.warning("Engine (%s) analysis failed: %s", language, exc)


def _analyze_text_sync(
    text: str,
    *,
    score_threshold: float = 0.4,
    language: str | None = None,
) -> tuple[list, dict]:
    """
    Synchronous multilingual Presidio analysis (CPU-bound).

    Pipeline:
      1. Detect language (lingua, if enabled and no explicit language)
      2. Run multilingual engine (xx) -- NLP entities in any language
      3. Run default language engine (en) -- regex recognizers + English NLP
      4. If detected language differs from default and a model exists, run it too
      5. Merge/deduplicate all results

    Returns (results, metadata) tuple.
    """
    mgr = _MultilingualAnalyzerManager
    meta: dict = {"engines_used": [], "detected_language": None, "effective_language": None}

    # Step 1: Detect language
    detected_lang: str | None
    if language:
        detected_lang = language
    else:
        detected_lang = mgr.detect_language(text)
    meta["detected_language"] = detected_lang

    default_lang = mgr.get_default_language()
    effective_lang = str(detected_lang) if detected_lang else default_lang  # type: ignore
    meta["effective_language"] = effective_lang

    all_results: list = []

    # Step 2: Run multilingual engine (xx)
    _run_presidio_analysis(
        mgr.get_engine("xx"),
        text,
        "xx",
        score_threshold=score_threshold,
        all_results=all_results,
        meta_engines=meta["engines_used"],
    )

    # Step 3: Run default language engine (en)
    _run_presidio_analysis(
        mgr.get_engine(default_lang),
        text,
        default_lang,
        score_threshold=score_threshold,
        all_results=all_results,
        meta_engines=meta["engines_used"],
    )

    # Step 4: If detected language differs from default, run language-specific engine
    if effective_lang not in (default_lang, "xx"):
        _run_presidio_analysis(
            mgr.get_engine(effective_lang),
            text,
            effective_lang,
            score_threshold=score_threshold,
            all_results=all_results,
            meta_engines=meta["engines_used"],
        )

    # Step 5: Merge and deduplicate
    merged = _merge_detections(all_results)
    if not merged:
        fallback = _regex_fallback_detections(
            text,
            score_threshold=score_threshold,
        )
        if fallback:
            meta["engines_used"].append("regex-fallback")
            merged = fallback
    return merged, meta


async def _analyze_text(
    text: str,
    score_threshold: float = 0.4,
    language: str | None = None,
) -> tuple[list, dict]:
    """
    Async wrapper for multilingual Presidio analysis (C-04).

    Offloads CPU-bound NLP processing to a threadpool worker to prevent
    blocking the async event loop.
    """
    return await run_in_threadpool(
        lambda: _analyze_text_sync(
            text,
            score_threshold=score_threshold,
            language=language,
        )
    )
