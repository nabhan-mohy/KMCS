"""
kmcs.core.models
================

The **domain model vocabulary** for the Keyless Memory-Corruption Scanner.

This module contains *no orchestration logic*: it defines the shared language
that every other subsystem (targets, fuzzers, sanitizers, analysis, campaigns,
reproduction, reporting, CLI, GUI) speaks.  Getting this vocabulary right and
stable is what makes the later phases composable.

Contents
--------

* :class:`StrEnum` / :class:`IntEnumMixin` — string/int enumerations that are
  database- and JSON-friendly, tolerant of unknown values and case-insensitive.
* The core enums: :class:`Severity`, :class:`CrashClass`,
  :class:`MemoryAccessType`, :class:`SanitizerKind`, :class:`EngineKind`,
  :class:`InstrumentationKind`, :class:`TargetKind`, :class:`Language`, …
* Value objects (mostly frozen dataclasses): :class:`StackFrame`,
  :class:`StackTrace`, :class:`SanitizerReport`, :class:`Fingerprint`,
  :class:`Crash`, :class:`Finding`, :class:`ReproductionResult`, …
* Registries & helpers: :data:`MODEL_REGISTRY`, :func:`register_model`,
  :func:`build_default_registry`, :func:`compute_fingerprint`,
  :func:`derive_severity`, ID generation, hashing, size parsing, path safety,
  authorisation gating, capability guarding and a fully offline toolchain probe.

Design principles
-----------------

1. **Explicit over implicit.**  Every enum member carries a machine token and a
   human label; nothing relies on positional magic numbers.
2. **Immutable where sensible.**  Value objects use ``frozen=True`` so they can
   be shared across threads and used as dictionary keys.
3. **Lossless round-trip.**  ``to_dict()``/``from_dict()`` pairs let records be
   stored in SQLite/JSON and rebuilt exactly, including provenance.
4. **No fabricated data.**  Metrics objects treat ``None`` as *"not measured"*.
   A number only exists when a real engine/tool produced it.
5. **Defensive use only.**  Models describe *findings*, never weapons.  There is
   no representation for payloads, shellcode or exploit primitives, and requests
   for such things raise :class:`~kmcs.core.exceptions.ProhibitedCapabilityError`.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import threading
import uuid
from collections import OrderedDict, defaultdict
from dataclasses import MISSING, asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import (
    Any, Callable, ClassVar, Dict, Iterable, Iterator, List, Mapping, Optional,
    Sequence, Set, Tuple, Type, TypeVar, Union, get_args, get_origin,
)

from kmcs.core.exceptions import (
    AuthorizationError,
    ConsentRequiredError,
    CrashClassificationError,
    ErrorCode,
    InstrumentationError,
    InvalidValueError,
    ProhibitedCapabilityError,
    ScopeExceededError,
    SeverityAssessmentError,
    ToolNotFoundError,
)

__all__: List[str] = [
    # foundations
    "CoercibleEnum", "StrEnum", "IntEnumMixin", "ModelProtocol",
    "TypedModelRegistry", "MODEL_REGISTRY", "register_model", "model_for",
    "model_names", "instantiate", "build_default_registry", "describe_models",
    "describe_class", "serialise", "deserialise", "record_to_row", "row_to_record",
    "deep_merge", "merge_dicts", "walk_type", "type_hint_of",
    # enums
    "Severity", "Confidence", "Priority", "CrashClass", "MemoryAccessType",
    "TriggerCondition", "EngineKind", "SanitizerKind", "InstrumentationKind",
    "CompilerFamily", "LinkageKind", "OptimizationLevel", "TargetKind",
    "Language", "Architecture", "OperatingSystem", "InputClass", "RunStatus",
    "CampaignStatus", "JobStateName", "CrashState", "FindingState",
    "ReproductionOutcome", "DedupDecision", "ReportFormat", "ProcessRole",
    "SymbolizerKind", "CoverageMetric", "OperationMode",
    # constants
    "SEVERITY_CVSS_BANDS", "DEFAULT_SEVERITY_WEIGHTS", "CRASH_CLASS_FAMILIES",
    "CRASH_CLASS_SANITIZER_ORIGIN", "CRASH_CLASS_LABELS", "ENGINE_BINARIES",
    "SANITIZER_FLAGS", "INSTRUMENTATION_TOOLS", "KNOWN_TOOLS",
    # value objects
    "TimestampRange", "ByteRange", "ResourceUsage", "ToolAvailability",
    "ToolchainProbe", "EngineCapabilities", "StackFrame", "StackTrace",
    "SignalInfo", "MemoryAccess", "CrashLocation", "SanitizerReport",
    "Fingerprint", "CorpusEntry", "CorpusStats", "Corpus", "Scope",
    "Authorisation", "BuildRecipe", "HarnessSpec", "Target", "Crash",
    "RunMetrics", "CampaignMetrics", "Campaign", "ReproductionResult",
    "MinimizationResult", "Evidence", "RootCauseHint", "Reproducer", "Finding",
    "RegressionTest", "ReportRequest", "ReportArtifact", "EventEnvelope",
    "JobRecord", "TaskSpec", "SourceLayout", "ProductIdentity", "Vote",
    "DedupDecisionDetail", "TelemetrySample", "HealthSnapshot",
    # functions
    "now_utc", "utc_string", "parse_timestamp", "humanize_duration",
    "generate_prefixed_id", "sha256_bytes", "sha256_file", "md5_bytes",
    "stable_digest", "short_hash", "b64encode_bytes", "b64decode_str",
    "parse_size", "format_size", "normalize_path", "safe_filename",
    "guess_language", "is_source_file", "is_binary_likely",
    "probe_toolchain", "probe_engine_availability", "require_authorization",
    "make_authorisation", "guard_capability", "is_prohibited_capability",
    "compute_fingerprint", "fingerprint_of", "derive_severity",
    "severity_from_crash_class", "crash_class_for_sanitizer",
    "confidence_from_votes", "input_class_for", "taxonomy_overview",
    "model_registration_summary", "dump_json", "load_json",
]

T = TypeVar("T")


# ===========================================================================
# time / id / hash / path utilities
# ===========================================================================


def now_utc() -> datetime:
    """Timezone-aware current time in UTC."""
    return datetime.now(timezone.utc)


def utc_string(value: Optional[datetime] = None) -> str:
    """ISO-8601 UTC string with millisecond precision."""
    moment = value if value is not None else now_utc()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


#: Alias kept for readability at call sites that want a plain default timestamp.
default_timestamp = utc_string


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Best-effort parser returning an aware UTC datetime (or ``None``)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        for candidate in (text, text.replace("Z", "+00:00")):
            try:
                parsed = datetime.fromisoformat(candidate)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, fmt)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def humanize_duration(seconds: Optional[float]) -> str:
    """Render a duration compactly, e.g. ``1d 2h 3m 4s``."""
    if seconds is None:
        return "n/a"
    total = float(seconds)
    if total < 0:
        return f"-{humanize_duration(-total)}"
    if total < 1e-3:
        return f"{total * 1e6:.0f}us"
    if total < 1.0:
        return f"{total * 1e3:.1f}ms"
    parts: List[str] = []
    days, remainder = divmod(int(total), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    for unit, amount in (("d", days), ("h", hours), ("m", minutes), ("s", secs)):
        if amount:
            parts.append(f"{amount}{unit}")
    return " ".join(parts) or "0s"


def generate_prefixed_id(prefix: str = "kmcs", entropy_bits: int = 96) -> str:
    """Generate a sortable, collision-resistant identifier.

    Format ``<prefix>-<yyyymmddhhmmss>-<hex>``.  Time-sortable (handy for listing
    findings chronologically) and requires no external coordination service —
    no network, no API keys.
    """
    width = max(4, int(entropy_bits) // 8)
    random_part = uuid.uuid4().hex[: 2 * width]
    stamp = now_utc().strftime("%Y%m%d%H%M%S")
    clean = re.sub(r"[^a-z0-9]", "", str(prefix or "").lower()) or "kmcs"
    return f"{clean}-{stamp}-{random_part}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def sha256_file(path: Union[str, "os.PathLike[str]"], chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(os.fspath(path), "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def md5_bytes(data: bytes) -> str:
    """MD5 used purely as a *change detector* for corpus de-duplication.

    It provides **no** security property and must never be relied upon as one.
    """
    return hashlib.md5(bytes(data)).hexdigest()


def stable_digest(payload: Any, length: int = 16) -> str:
    """Deterministic digest of arbitrary JSON-able data (keys sorted)."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=_json_default)
    return hashlib.sha256(encoded.encode("utf-8", "replace")).hexdigest()[: max(4, int(length))]


def short_hash(text: Any, length: int = 12) -> str:
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()[: max(4, int(length))]


def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def b64decode_str(text: Any) -> bytes:
    payload = str(text or "")
    padding = "=" * (-len(payload) % 4)
    return base64.b64decode(payload + padding)


_SIZE_UNITS: Dict[str, int] = {
    "": 1, "b": 1, "byte": 1, "bytes": 1,
    "k": 1024, "kb": 1024, "ki": 1024, "kib": 1024,
    "m": 1024 ** 2, "mb": 1024 ** 2, "mi": 1024 ** 2, "mib": 1024 ** 2,
    "g": 1024 ** 3, "gb": 1024 ** 3, "gi": 1024 ** 3, "gib": 1024 ** 3,
    "t": 1024 ** 4, "tb": 1024 ** 4, "ti": 1024 ** 4, "tib": 1024 ** 4,
    "p": 1024 ** 5, "pb": 1024 ** 5, "pi": 1024 ** 5, "pib": 1024 ** 5,
}


def parse_size(value: Any, default: Optional[int] = None) -> int:
    """Parse ``"16 MiB"``, ``"1024"`` or ``4096`` into a byte count."""
    if value is None:
        if default is None:
            raise InvalidValueError("size value is required")
        return int(default)
    if isinstance(value, bool):
        raise InvalidValueError("boolean is not a valid size")
    if isinstance(value, (int, float)):
        if value < 0:
            raise InvalidValueError(f"size cannot be negative ({value})")
        return int(value)
    text = str(value).strip().lower().replace(",", "").replace("_", "")
    match = re.fullmatch(r"([0-9]*\.?[0-9]+)\s*([a-z]{0,4})?", text)
    if not match:
        raise InvalidValueError(f"cannot parse size '{value}'", details={"value": str(value)})
    number = float(match.group(1))
    unit = (match.group(2) or "").strip()
    if unit not in _SIZE_UNITS:
        raise InvalidValueError(
            f"unknown size unit '{unit}'", details={"value": str(value), "known": sorted(_SIZE_UNITS)},
        )
    result = int(round(number * _SIZE_UNITS[unit]))
    if result < 0:
        raise InvalidValueError(f"size cannot be negative ({value})")
    return result


def format_size(num_bytes: Optional[int]) -> str:
    """Human-readable byte count using binary prefixes."""
    if num_bytes is None:
        return "n/a"
    value = float(num_bytes)
    negative = value < 0
    value = abs(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(value) < 1024.0 or unit == "PiB":
            rendered = f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
            return f"-{rendered}" if negative else rendered
        value /= 1024.0
    return f"{value:.2f} PiB"


def normalize_path(path: Any, *, expand: bool = True, resolve: bool = False) -> str:
    """Portable path normalisation (``~``/env expansion, ``..`` collapse, slashes)."""
    raw = os.fspath(path) if not isinstance(path, str) else path
    if expand:
        raw = os.path.expandvars(os.path.expanduser(raw))
    normalized = os.path.normpath(raw)
    if resolve:
        try:
            normalized = str(Path(normalized).resolve())
        except OSError:
            pass
    return normalized.replace("\\", "/")


_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"}


def safe_filename(name: Any, default: str = "unnamed", max_length: int = 128) -> str:
    """Reduce arbitrary text to a filesystem-safe token (no traversal risk)."""
    text = str(name or "").strip()
    cleaned = _UNSAFE_FILENAME.sub("_", text).strip("._-") or default
    upper = cleaned.upper()
    if upper in _RESERVED_NAMES or re.match(r"^(COM|LPT)[0-9]$", upper):
        cleaned = f"_{cleaned}"
    if len(cleaned) > max_length:
        cleaned = cleaned[: max(8, max_length - 10)] + "-" + short_hash(text, 8)
    return cleaned


_LANGUAGE_BY_SUFFIX = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cp": "cpp", ".cxx": "cpp", ".cpp": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp", ".inl": "cpp", ".ipp": "cpp", ".C": "cpp",
    ".rs": "rust", ".go": "go", ".py": "python", ".java": "java", ".js": "javascript",
    ".ts": "typescript", ".cs": "csharp", ".m": "objective-c", ".swift": "swift",
    ".vala": "vala", ".zig": "zig", ".f90": "fortran", ".for": "fortran",
    ".asm": "assembly", ".s": "assembly",
}


def guess_language(path: Any, default: str = "unknown") -> str:
    """Infer a source language from a file extension."""
    suffix = os.path.splitext(os.fspath(path))[1].lower()
    return _LANGUAGE_BY_SUFFIX.get(suffix, default)


_SOURCE_SUFFIXES = set(_LANGUAGE_BY_SUFFIX) | {
    ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".cmake", ".mk", ".sh", ".patch", ".diff",
}


def is_source_file(path: Any) -> bool:
    return os.path.splitext(os.fspath(path))[1].lower() in _SOURCE_SUFFIXES


def is_binary_likely(path: Any, sample_bytes: int = 8192) -> bool:
    """Heuristic ELF/Mach-O/PE detection used by target auto-discovery."""
    try:
        with open(os.fspath(path), "rb") as handle:
            head = handle.read(sample_bytes)
    except OSError:
        return False
    if not head:
        return False
    magic_hits = (
        head.startswith(b"\x7fELF"),
        head[:2] == b"MZ",
        head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                     b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xfe\xed\xfa\xbf", b"\xbf\xfa\xed\xfe"),
    )
    if any(magic_hits):
        return True
    return head.count(0) > len(head) // 20


def dump_json(obj: Any, *, pretty: bool = False, sort_keys: bool = True) -> str:
    """Serialise any model/graph to a JSON string with sane defaults."""
    plain = serialise(obj, pretty=False)
    if isinstance(plain, str):
        return plain
    return json.dumps(plain, indent=2 if pretty else None, sort_keys=sort_keys, ensure_ascii=False)


def load_json(text: Any, *, registry: Optional["TypedModelRegistry"] = None, default_model: Optional[str] = None) -> Any:
    """Parse JSON and rebuild registered models when ``__type__`` is present."""
    data = json.loads(text) if isinstance(text, (str, bytes)) else text
    if isinstance(data, (dict, list)):
        return deserialise(data, registry=registry, default_model=default_model)
    return data


# ===========================================================================
# enumeration foundations
# ===========================================================================


class CoercibleEnum(Enum):
    """Common behaviour for KMCS enumerations.

    Subclasses gain case-insensitive parsing, a tolerant :meth:`try_parse`,
    listing helpers and a human readable :meth:`label`.
    """

    @classmethod
    def coerce(cls, value: Any, default: Any = None) -> Any:
        """Return the matching member, raising :class:`InvalidValueError` otherwise."""
        if isinstance(value, cls):
            return value
        if value is None:
            if default is not None:
                return cls.coerce(default)
            raise InvalidValueError(
                f"{cls.__name__}: value required", details={"allowed": cls.tokens()},
            )
        text = str(value).strip()
        lowered = text.lower().replace("-", "_").replace(" ", "_")
        for member in cls:
            if str(member.value).lower() == lowered or member.name.lower() == lowered:
                return member
        for member in cls:
            aliases = getattr(member, "aliases", ()) or ()
            if any(str(alias).lower() == lowered for alias in aliases):
                return member
        if re.fullmatch(r"-?\d+", text):
            try:
                return cls(int(text))
            except (ValueError, KeyError, TypeError):
                pass
        raise InvalidValueError(
            f"{cls.__name__}: '{value}' is not one of {', '.join(cls.tokens())}",
            details={"provided": text, "allowed": cls.tokens()},
        )

    @classmethod
    def try_parse(cls, value: Any, default: Optional[Any] = None) -> Optional[Any]:
        try:
            return cls.coerce(value)
        except Exception:
            return default

    @classmethod
    def tokens(cls) -> List[str]:
        return [str(member.value) for member in cls]

    @classmethod
    def names(cls) -> List[str]:
        return [member.name for member in cls]

    @classmethod
    def from_name(cls, name: Any) -> Any:
        key = str(name).strip().upper()
        if key not in cls.__members__:
            raise InvalidValueError(f"{cls.__name__} has no member named '{name}'", details={"known": cls.names()})
        return cls.__members__[key]

    @classmethod
    def mapping(cls) -> Dict[str, Any]:
        return {member.name: member.value for member in cls}

    def next(self, steps: int = 1) -> Any:
        members = list(type(self))
        index = (members.index(self) + int(steps)) % len(members)
        return members[index]

    def label(self) -> str:
        doc = (self.__doc__ or "").strip()
        if doc:
            return doc.splitlines()[0].split("—")[0].strip()
        return str(self.value).replace("_", " ").replace("-", " ").title()

    def __str__(self) -> str:
        return str(self.value)


class StrEnum(str, CoercibleEnum):
    """String-valued enum usable anywhere a ``str`` is expected (DB/JSON friendly)."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__}.{self.name}: {self.value!r}>"

    def __hash__(self) -> int:
        return hash(str(self.value))

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, StrEnum):
            return str(self.value) == str(other.value)
        if isinstance(other, str):
            return str(self.value) == other
        return NotImplemented

    def __ne__(self, other: Any) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    @property
    def key(self) -> str:
        return self.name.lower()


class IntEnumMixin(IntEnum):
    """Integer enum with the same tolerant parsing as :class:`CoercibleEnum`."""

    @classmethod
    def coerce(cls, value: Any, default: Any = None) -> Any:
        if isinstance(value, cls):
            return value
        if value is None:
            if default is not None:
                return cls.coerce(default)
            raise InvalidValueError(f"{cls.__name__}: value required", details={"allowed": cls.tokens()})
        if isinstance(value, str):
            text = value.strip().lower().replace("-", "_").replace(" ", "_")
            for member in cls:
                if member.name.lower() == text or str(int(member)) == text:
                    return member
            try:
                value = int(text)
            except ValueError as exc:
                raise InvalidValueError(f"{cls.__name__}: cannot parse '{value}'") from exc
        try:
            return cls(int(value))
        except (ValueError, TypeError) as exc:
            raise InvalidValueError(
                f"{cls.__name__}: '{value}' is out of range", details={"allowed": cls.tokens()},
            ) from exc

    @classmethod
    def try_parse(cls, value: Any, default: Optional[Any] = None) -> Optional[Any]:
        try:
            return cls.coerce(value)
        except Exception:
            return default

    @classmethod
    def tokens(cls) -> List[str]:
        return [f"{member.name.lower()}({int(member)})" for member in cls]

    def label(self) -> str:
        return self.name.replace("_", " ").title()


# ===========================================================================
# severity / confidence / priority
# ===========================================================================


class Severity(StrEnum):
    """Severity ladder used for crashes and findings.

    Vocabulary deliberately matches common industry wording so exported reports
    read naturally to reviewers.
    """

    NONE = "none"
    INFORMATIONAL = "informational"
    LOW = "low"
    MODERATE = "moderate"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def rank(cls, value: Any) -> int:
        order = {
            "none": 0, "informational": 1, "low": 2, "moderate": 3,
            "medium": 3, "high": 4, "critical": 5,
        }
        try:
            token = str(cls.coerce(value).value)
        except Exception:
            return 0
        return order.get(token, 0)

    @classmethod
    def most_severe(cls, values: Iterable[Any]) -> "Severity":
        best = cls.NONE
        for candidate in values:
            try:
                resolved = cls.coerce(candidate)
            except Exception:
                continue
            if cls.rank(resolved) > cls.rank(best):
                best = resolved
        return best

    def at_least(self, other: Any) -> bool:
        return Severity.rank(self) >= Severity.rank(other)

    def cvss_band(self) -> str:
        return SEVERITY_CVSS_BANDS.get(str(self.value), "unspecified")

    def escalate(self, steps: int = 1) -> "Severity":
        ladder = [Severity.NONE, Severity.INFORMATIONAL, Severity.LOW, Severity.MODERATE, Severity.HIGH, Severity.CRITICAL]
        anchor = Severity.MODERATE if self is Severity.MEDIUM else self
        index = ladder.index(anchor)
        return ladder[max(0, min(len(ladder) - 1, index + int(steps)))]

    def weight(self) -> int:
        return DEFAULT_SEVERITY_WEIGHTS.get(str(self.value), 0)


SEVERITY_CVSS_BANDS: Dict[str, str] = {
    "none": "None (0.0)",
    "informational": "Informational (0.1-3.9)",
    "low": "Low (0.1-3.9)",
    "moderate": "Medium (4.0-6.9)",
    "medium": "Medium (4.0-6.9)",
    "high": "High (7.0-8.9)",
    "critical": "Critical (9.0-10.0)",
}

DEFAULT_SEVERITY_WEIGHTS: Dict[str, int] = {
    "none": 0, "informational": 1, "low": 2, "moderate": 3, "medium": 3, "high": 4, "critical": 5,
}


class Confidence(StrEnum):
    """Analyst/engine confidence in a classification or fingerprint match."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

    @classmethod
    def from_score(cls, score: float) -> "Confidence":
        value = float(score)
        if not 0.0 <= value <= 1.0:
            raise InvalidValueError(f"confidence score must be within [0, 1]; got {score}")
        if value >= 0.95:
            return cls.CONFIRMED
        if value >= 0.75:
            return cls.HIGH
        if value >= 0.45:
            return cls.MEDIUM
        if value > 0.0:
            return cls.LOW
        return cls.UNKNOWN

    def score(self) -> float:
        return {"unknown": 0.0, "low": 0.3, "medium": 0.6, "high": 0.85, "confirmed": 0.98}[str(self.value)]


class Priority(IntEnumMixin):
    """Scheduler priority; higher runs first."""

    IDLE = 0
    LOWEST = 10
    LOW = 25
    NORMAL = 50
    HIGH = 75
    URGENT = 90
    CRITICAL = 100

    @classmethod
    def from_severity(cls, severity: Any) -> "Priority":
        mapping = {
            Severity.NONE: cls.IDLE, Severity.INFORMATIONAL: cls.LOWEST, Severity.LOW: cls.LOW,
            Severity.MODERATE: cls.NORMAL, Severity.MEDIUM: cls.NORMAL,
            Severity.HIGH: cls.HIGH, Severity.CRITICAL: cls.URGENT,
        }
        try:
            return mapping.get(Severity.coerce(severity), cls.NORMAL)
        except Exception:
            return cls.NORMAL


# ===========================================================================
# crash taxonomy
# ===========================================================================


class CrashClass(StrEnum):
    """High-level memory-safety crash category.

    These categories drive classification, de-duplication and severity
    derivation.  They describe *what the sanitizer observed*, never how one
    might abuse it.
    """

    UNKNOWN = "unknown"
    HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
    HEAP_BUFFER_UNDERFLOW = "heap-buffer-underflow"
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    STACK_BUFFER_UNDERFLOW = "stack-buffer-underflow"
    GLOBAL_BUFFER_OVERFLOW = "global-buffer-overflow"
    GLOBAL_BUFFER_UNDERFLOW = "global-buffer-underflow"
    USE_AFTER_FREE = "use-after-free"
    USE_AFTER_RETURN = "use-after-return"
    USE_AFTER_SCOPE = "use-after-scope"
    DOUBLE_FREE = "double-free"
    INVALID_FREE = "invalid-free"
    ALLOCATOR_MISUSE = "allocator-misuse"
    OVERFLOW_ALLOC = "overflow-alloc"
    MEMORY_LEAK = "memory-leak"
    INDIRECT_LEAK = "indirect-leak"
    UNINITIALIZED_USE = "uninitialized-use"
    INTEGER_OVERFLOW = "integer-overflow"
    SIGNED_SHIFT_OVERFLOW = "signed-shift-overflow"
    DIVIDE_BY_ZERO = "divide-by-zero"
    MISALIGNED_ACCESS = "misaligned-access"
    OBJECT_SIZE_VIOLATION = "object-size-violation"
    ENUM_OUT_OF_RANGE = "enum-out-of-range"
    UNREACHABLE_CODE = "unreachable-code"
    TYPE_MISSMATCH = "type-mismatch"
    NULL_ARGUMENT = "null-argument"
    FUNCTION_TYPE_MISMATCH = "function-type-mismatch"
    VLA_BOUND_CHANGE = "vla-bound-change"
    SEGMENTATION_FAULT = "segmentation-fault"
    BUS_ERROR = "bus-error"
    ABORT = "abort"
    ILLEGAL_INSTRUCTION = "illegal-instruction"
    STACK_OVERFLOW = "stack-overflow"
    NULL_DEREFERENCE = "null-dereference"
    TIMEOUT = "timeout"
    OUT_OF_MEMORY = "out-of-memory"
    HANG = "hang"
    SHUTDOWN_TIMEOUT = "shutdown-timeout"
    SIGNAL = "signal"
    ASSERTION_FAILURE = "assertion-failure"
    DATA_RACE = "data-race"
    LOCK_ORDER_INVERSION = "lock-order-inversion"
    BAD_CAST = "bad-cast"
    GENERIC_GCC_ERROR = "generic-gcc-error"

    @property
    def family(self) -> str:
        return CRASH_CLASS_FAMILIES.get(str(self.value), "other")

    @property
    def sanitizer_origin(self) -> str:
        return CRASH_CLASS_SANITIZER_ORIGIN.get(str(self.value), "unknown")

    @property
    def is_memory_safety(self) -> bool:
        return self.family in {"heap", "stack", "global", "lifetime", "allocator", "initialization"}

    @property
    def is_undefined_behaviour(self) -> bool:
        return self.family == "undefined-behaviour"

    @property
    def is_resource(self) -> bool:
        return self.family in {"resource", "availability"}

    def typical_severity(self) -> "Severity":
        return severity_from_crash_class(self)


CRASH_CLASS_FAMILIES: Dict[str, str] = {
    "heap-buffer-overflow": "heap", "heap-buffer-underflow": "heap",
    "stack-buffer-overflow": "stack", "stack-buffer-underflow": "stack",
    "global-buffer-overflow": "global", "global-buffer-underflow": "global",
    "use-after-free": "lifetime", "use-after-return": "lifetime", "use-after-scope": "lifetime",
    "double-free": "allocator", "invalid-free": "allocator", "allocator-misuse": "allocator",
    "overflow-alloc": "allocator", "memory-leak": "leak", "indirect-leak": "leak",
    "uninitialized-use": "initialization",
    "integer-overflow": "undefined-behaviour", "signed-shift-overflow": "undefined-behaviour",
    "divide-by-zero": "undefined-behaviour", "misaligned-access": "undefined-behaviour",
    "object-size-violation": "undefined-behaviour", "enum-out-of-range": "undefined-behaviour",
    "unreachable-code": "undefined-behaviour", "type-mismatch": "undefined-behaviour",
    "null-argument": "undefined-behaviour", "function-type-mismatch": "undefined-behaviour",
    "vla-bound-change": "undefined-behaviour", "bad-cast": "undefined-behaviour",
    "segmentation-fault": "signal", "bus-error": "signal", "illegal-instruction": "signal",
    "abort": "signal", "assertion-failure": "signal", "signal": "signal",
    "stack-overflow": "availability", "null-dereference": "availability",
    "timeout": "availability", "out-of-memory": "availability", "hang": "availability",
    "shutdown-timeout": "availability",
    "data-race": "concurrency", "lock-order-inversion": "concurrency",
    "generic-gcc-error": "other", "unknown": "other",
}

CRASH_CLASS_SANITIZER_ORIGIN: Dict[str, str] = {
    "heap-buffer-overflow": "asan", "heap-buffer-underflow": "asan",
    "stack-buffer-overflow": "asan", "stack-buffer-underflow": "asan",
    "global-buffer-overflow": "asan", "global-buffer-underflow": "asan",
    "use-after-free": "asan", "use-after-return": "asan", "use-after-scope": "asan",
    "double-free": "asan", "invalid-free": "asan", "allocator-misuse": "asan",
    "overflow-alloc": "asan", "memory-leak": "lsan", "indirect-leak": "lsan",
    "uninitialized-use": "msan",
    "integer-overflow": "ubsan", "signed-shift-overflow": "ubsan", "divide-by-zero": "ubsan",
    "misaligned-access": "ubsan", "object-size-violation": "ubsan", "enum-out-of-range": "ubsan",
    "unreachable-code": "ubsan", "type-mismatch": "ubsan", "null-argument": "ubsan",
    "function-type-mismatch": "ubsan", "vla-bound-change": "ubsan", "bad-cast": "ubsan",
    "data-race": "tsan", "lock-order-inversion": "tsan",
    "generic-gcc-error": "compiler",
}

CRASH_CLASS_LABELS: Dict[str, str] = {
    "heap-buffer-overflow": "Heap buffer overflow",
    "stack-buffer-overflow": "Stack buffer overflow",
    "global-buffer-overflow": "Global buffer overflow",
    "use-after-free": "Use after free",
    "use-after-return": "Use after return",
    "double-free": "Double free",
    "memory-leak": "Memory leak",
    "integer-overflow": "Signed integer overflow",
    "divide-by-zero": "Division by zero",
    "uninitialized-use": "Use of uninitialised value",
    "segmentation-fault": "Segmentation fault",
    "null-dereference": "Null pointer dereference",
    "stack-overflow": "Stack exhaustion",
    "timeout": "Timeout (potential hang)",
    "data-race": "Data race",
    "assertion-failure": "Assertion failure",
}

_CRASH_CLASS_SEVERITY: Dict[str, Severity] = {
    CrashClass.HEAP_BUFFER_OVERFLOW: Severity.HIGH,
    CrashClass.HEAP_BUFFER_UNDERFLOW: Severity.HIGH,
    CrashClass.STACK_BUFFER_OVERFLOW: Severity.HIGH,
    CrashClass.STACK_BUFFER_UNDERFLOW: Severity.HIGH,
    CrashClass.GLOBAL_BUFFER_OVERFLOW: Severity.HIGH,
    CrashClass.GLOBAL_BUFFER_UNDERFLOW: Severity.MODERATE,
    CrashClass.USE_AFTER_FREE: Severity.HIGH,
    CrashClass.USE_AFTER_RETURN: Severity.HIGH,
    CrashClass.USE_AFTER_SCOPE: Severity.MODERATE,
    CrashClass.DOUBLE_FREE: Severity.HIGH,
    CrashClass.INVALID_FREE: Severity.MODERATE,
    CrashClass.ALLOCATOR_MISUSE: Severity.MODERATE,
    CrashClass.OVERFLOW_ALLOC: Severity.MODERATE,
    CrashClass.MEMORY_LEAK: Severity.LOW,
    CrashClass.INDIRECT_LEAK: Severity.LOW,
    CrashClass.UNINITIALIZED_USE: Severity.MODERATE,
    CrashClass.INTEGER_OVERFLOW: Severity.MODERATE,
    CrashClass.SIGNED_SHIFT_OVERFLOW: Severity.MODERATE,
    CrashClass.DIVIDE_BY_ZERO: Severity.MODERATE,
    CrashClass.MISALIGNED_ACCESS: Severity.LOW,
    CrashClass.OBJECT_SIZE_VIOLATION: Severity.HIGH,
    CrashClass.ENUM_OUT_OF_RANGE: Severity.LOW,
    CrashClass.UNREACHABLE_CODE: Severity.INFORMATIONAL,
    CrashClass.TYPE_MISSMATCH: Severity.MODERATE,
    CrashClass.NULL_ARGUMENT: Severity.MODERATE,
    CrashClass.FUNCTION_TYPE_MISMATCH: Severity.MODERATE,
    CrashClass.VLA_BOUND_CHANGE: Severity.LOW,
    CrashClass.BAD_CAST: Severity.MODERATE,
    CrashClass.SEGMENTATION_FAULT: Severity.MODERATE,
    CrashClass.BUS_ERROR: Severity.MODERATE,
    CrashClass.ABORT: Severity.MODERATE,
    CrashClass.ILLEGAL_INSTRUCTION: Severity.HIGH,
    CrashClass.STACK_OVERFLOW: Severity.MODERATE,
    CrashClass.NULL_DEREFERENCE: Severity.MODERATE,
    CrashClass.TIMEOUT: Severity.LOW,
    CrashClass.OUT_OF_MEMORY: Severity.LOW,
    CrashClass.HANG: Severity.LOW,
    CrashClass.SHUTDOWN_TIMEOUT: Severity.INFORMATIONAL,
    CrashClass.SIGNAL: Severity.MODERATE,
    CrashClass.ASSERTION_FAILURE: Severity.LOW,
    CrashClass.DATA_RACE: Severity.MODERATE,
    CrashClass.LOCK_ORDER_INVERSION: Severity.LOW,
    CrashClass.GENERIC_GCC_ERROR: Severity.INFORMATIONAL,
    CrashClass.UNKNOWN: Severity.MODERATE,
}


def severity_from_crash_class(crash_class: Any) -> Severity:
    """Default severity mapping for a crash class."""
    try:
        resolved = CrashClass.coerce(crash_class)
    except Exception:
        return Severity.MODERATE
    return _CRASH_CLASS_SEVERITY.get(resolved, Severity.MODERATE)


class MemoryAccessType(StrEnum):
    READ = "read"
    WRITE = "write"
    FREE = "free"
    ALLOC = "alloc"
    EXECUTE = "execute"
    UNKNOWN = "unknown"


class TriggerCondition(StrEnum):
    """What the input must do for the defect to manifest."""

    ANY_INPUT = "any-input"
    SPECIFIC_INPUT = "specific-input"
    LARGE_INPUT = "large-input"
    DEEP_NESTING = "deep-nesting"
    SPECIFIC_SEQUENCE = "specific-sequence"
    RESOURCE_PRESSURE = "resource-pressure"
    CONCURRENT_EXECUTION = "concurrent-execution"
    ENVIRONMENT_DEPENDENT = "environment-dependent"
    UNKNOWN = "unknown"


# ===========================================================================
# engines / toolchain
# ===========================================================================


class EngineKind(StrEnum):
    """Supported fuzzing engines.  KMCS orchestrates them; it does not replace them."""

    AFLPP = "aflpp"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"
    CUSTOM = "custom"

    @property
    def primary_binary(self) -> str:
        binaries = ENGINE_BINARIES[str(self.value)]
        return binaries[0] if binaries else ""

    @property
    def binaries(self) -> List[str]:
        return list(ENGINE_BINARIES[str(self.value)])

    @property
    def display_name(self) -> str:
        return {"aflpp": "AFL++", "libfuzzer": "libFuzzer", "honggfuzz": "Honggfuzz",
                "custom": "Custom engine"}[str(self.value)]

    @property
    def in_process(self) -> bool:
        """Whether the engine drives the target inside its own process."""
        return str(self.value) == "libfuzzer"

    @property
    def requires_instrumentation(self) -> bool:
        return str(self.value) in {"aflpp", "honggfuzz"}

    @property
    def supports_parallel_workers(self) -> bool:
        return str(self.value) in {"aflpp", "honggfuzz", "custom"}


ENGINE_BINARIES: Dict[str, List[str]] = {
    "aflpp": ["afl-fuzz", "afl-clang-fast", "afl-clang-fast++", "afl-showmap", "afl-cmin", "afl-tmin", "afl-analyze"],
    "libfuzzer": ["clang", "clang++"],
    "honggfuzz": ["honggfuzz"],
    "custom": [],
}


class SanitizerKind(StrEnum):
    ASAN = "address"
    UBSAN = "undefined"
    LSAN = "leak"
    MSAN = "memory"
    TSAN = "thread"
    HWASAN = "hwaddress"
    SAFESTACK = "safestack"
    NONE = "none"

    @property
    def flag(self) -> str:
        return SANITIZER_FLAGS[str(self.value)]

    @property
    def env_var(self) -> Optional[str]:
        return {
            "address": "ASAN_OPTIONS", "undefined": "UBSAN_OPTIONS", "leak": "LSAN_OPTIONS",
            "memory": "MSAN_OPTIONS", "thread": "TSAN_OPTIONS", "hwaddress": "ASAN_OPTIONS",
            "safestack": None, "none": None,
        }.get(str(self.value))

    @property
    def available_phase(self) -> int:
        """First delivery phase in which this sanitizer is wired up."""
        return {
            "address": 5, "leak": 5, "undefined": 5, "memory": 5,
            "thread": 6, "hwaddress": 6, "safestack": 6, "none": 1,
        }[str(self.value)]

    @property
    def incompatible_with(self) -> List[str]:
        return {
            "address": ["memory", "thread"],
            "memory": ["address", "thread", "leak"],
            "thread": ["address", "memory", "leak", "hwaddress"],
            "hwaddress": ["address", "thread"],
            "leak": ["memory", "thread"],
            "undefined": [], "safestack": ["hwaddress"], "none": [],
        }[str(self.value)]


SANITIZER_FLAGS: Dict[str, str] = {
    "address": "-fsanitize=address",
    "undefined": "-fsanitize=undefined",
    "leak": "-fsanitize=leak",
    "memory": "-fsanitize=memory",
    "thread": "-fsanitize=thread",
    "hwaddress": "-fsanitize=hwaddress",
    "safestack": "-fsanitize=safe-stack",
    "none": "",
}


class InstrumentationKind(StrEnum):
    NONE = "none"
    AFL_CLANG_FAST = "afl-clang-fast"
    AFL_CLANG_LTO = "afl-clang-lto"
    AFL_GCC_PLUGIN = "afl-gcc-plugin"
    LLVM_PROFILE = "llvm-profile"
    PCGUARD = "sancov-pcguard"
    TRACE_PC = "trace-pc-guard"
    QEMU_MODE = "qemu-mode"
    FRIDA_MODE = "frida-mode"

    @property
    def supports_edge_coverage(self) -> bool:
        return str(self.value) in {
            "afl-clang-fast", "afl-clang-lto", "afl-gcc-plugin", "trace-pc-guard", "sancov-pcguard",
        }

    @property
    def requires_recompile(self) -> bool:
        return str(self.value) not in {"qemu-mode", "frida-mode", "none"}


INSTRUMENTATION_TOOLS: Dict[str, List[str]] = {
    "afl-clang-fast": ["afl-clang-fast", "afl-clang-fast++"],
    "afl-clang-lto": ["afl-clang-lto", "afl-clang-lto++", "afl-lto"],
    "afl-gcc-plugin": ["afl-gcc", "afl-g++"],
    "llvm-profile": ["clang", "llvm-profdata", "llvm-cov"],
    "sancov-pcguard": ["clang"],
    "trace-pc-guard": ["clang"],
    "qemu-mode": ["afl-qemu-trace"],
    "frida-mode": ["afl-frida-trace"],
    "none": [],
}


class CompilerFamily(StrEnum):
    CLANG = "clang"
    GCC = "gcc"
    AFL_CLANG_FAST = "afl-clang-fast"
    AFL_CLANG_LTO = "afl-clang-lto"
    AFL_GCC = "afl-gcc"
    UNKNOWN = "unknown"

    @property
    def cxx_counterpart(self) -> str:
        return {
            "clang": "clang++", "gcc": "g++", "afl-clang-fast": "afl-clang-fast++",
            "afl-clang-lto": "afl-clang-lto++", "afl-gcc": "afl-g++", "unknown": "",
        }[str(self.value)]

    @property
    def supports_sanitizers(self) -> bool:
        return str(self.value) in {"clang", "afl-clang-fast", "afl-clang-lto", "gcc"}

    @property
    def flags_executable(self) -> str:
        return {"clang": "clang", "gcc": "gcc", "afl-clang-fast": "afl-clang-fast",
                "afl-clang-lto": "afl-clang-lto", "afl-gcc": "afl-gcc", "unknown": "cc"}[str(self.value)]


class LinkageKind(StrEnum):
    STATIC = "static"
    SHARED = "shared"
    DYNAMIC = "dynamic"
    UNKNOWN = "unknown"


class OptimizationLevel(StrEnum):
    O0 = "O0"
    O1 = "O1"
    O2 = "O2"
    O3 = "O3"
    OS = "Os"
    OG = "Og"
    OFAST = "Ofast"

    @property
    def flag(self) -> str:
        return f"-{self.value}"

    @property
    def recommended_for_fuzzing(self) -> bool:
        return str(self.value) in {"O0", "O1", "Og"}


class TargetKind(StrEnum):
    BINARY = "binary"
    LIBRARY = "library"
    HARNESS = "harness"
    SOURCE_TREE = "source-tree"
    PACKAGE = "package"
    CONTAINER = "container"
    UNKNOWN = "unknown"


class Language(StrEnum):
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    GO = "go"
    PYTHON = "python"
    JAVA = "java"
    MIXED = "mixed"
    UNKNOWN = "unknown"

    @classmethod
    def detect(cls, paths: Iterable[Any]) -> "Language":
        found: Set[str] = set()
        for path in paths:
            token = guess_language(path, default="")
            if token:
                found.add(token)
        if not found:
            return cls.UNKNOWN
        if len(found) == 1:
            try:
                return cls.coerce(next(iter(found)))
            except Exception:
                return cls.UNKNOWN
        if found <= {"c", "cpp"}:
            return cls.CPP if "cpp" in found else cls.C
        return cls.MIXED


class Architecture(StrEnum):
    X86_64 = "x86_64"
    X86 = "x86"
    AARCH64 = "aarch64"
    ARM = "arm"
    RISCV64 = "riscv64"
    PPC64 = "ppc64"
    S390X = "s390x"
    WASM = "wasm"
    UNKNOWN = "unknown"

    @classmethod
    def host(cls) -> "Architecture":
        machine = platform.machine().lower()
        table = {
            "amd64": cls.X86_64, "x86_64": cls.X86_64, "i386": cls.X86, "i686": cls.X86,
            "i586": cls.X86, "aarch64": cls.AARCH64, "arm64": cls.AARCH64,
            "armv7l": cls.ARM, "armv6l": cls.ARM, "arm": cls.ARM, "riscv64": cls.RISCV64,
            "ppc64le": cls.PPC64, "ppc64": cls.PPC64, "s390x": cls.S390X,
            "wasm32": cls.WASM, "wasm64": cls.WASM,
        }
        return table.get(machine, cls.UNKNOWN)

    @property
    def bitness(self) -> int:
        return {"x86": 32, "wasm": 32}.get(str(self.value), 64 if self is not Architecture.UNKNOWN else 0)


class OperatingSystem(StrEnum):
    LINUX = "linux"
    DARWIN = "darwin"
    WINDOWS = "windows"
    FREEBSD = "freebsd"
    OPENBSD = "openbsd"
    ANDROID = "android"
    UNKNOWN = "unknown"

    @classmethod
    def host(cls) -> "OperatingSystem":
        return {
            "linux": cls.LINUX, "darwin": cls.DARWIN, "windows": cls.WINDOWS,
            "freebsd": cls.FREEBSD, "openbsd": cls.OPENBSD, "android": cls.ANDROID,
        }.get(platform.system().lower(), cls.UNKNOWN)


class InputClass(StrEnum):
    """Classification of a corpus / test-case input file."""

    VALID = "valid"
    MALFORMED = "malformed"
    TRUNCATED = "truncated"
    FUZZER_DISCOVERED = "fuzzer-discovered"
    CRASH_TRIGGERING = "crash-triggering"
    HANG_TRIGGERING = "hang-triggering"
    MINIMISED = "minimised"
    SYNTHETIC = "synthetic"
    REGRESSION = "regression"
    UNKNOWN = "unknown"


def input_class_for(path: Any, default: InputClass = InputClass.UNKNOWN) -> InputClass:
    """Infer an input's class from conventional fuzzer directory names."""
    text = str(os.fspath(path)).replace("\\", "/").lower()
    table = (
        ("crash", InputClass.CRASH_TRIGGERING), ("oom", InputClass.CRASH_TRIGGERING),
        ("timeout", InputClass.HANG_TRIGGERING), ("hang", InputClass.HANG_TRIGGERING),
        ("queue", InputClass.FUZZER_DISCOVERED), ("minimized", InputClass.MINIMISED),
        ("minimised", InputClass.MINIMISED), ("regression", InputClass.REGRESSION),
        ("seeds", InputClass.VALID), ("corpus", InputClass.VALID), ("valid", InputClass.VALID),
        ("malformed", InputClass.MALFORMED), ("truncat", InputClass.TRUNCATED),
    )
    for needle, kind in table:
        if needle in text:
            return kind
    return default


class RunStatus(StrEnum):
    """Lifecycle status of a run/campaign/worker."""

    PENDING = "pending"
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    CRASHED = "crashed"
    TIMED_OUT = "timed-out"
    ABORTED = "aborted"
    UNKNOWN = "unknown"

    @property
    def terminal(self) -> bool:
        return str(self.value) in {"completed", "failed", "cancelled", "crashed", "timed-out", "aborted"}

    @property
    def active(self) -> bool:
        return str(self.value) in {"preparing", "running", "paused", "stopping"}

    @property
    def successful(self) -> bool:
        return str(self.value) == "completed"


class CampaignStatus(RunStatus):
    """Alias namespace with an extra warm-up state for campaign code paths."""

    WARMUP = "warmup"


class JobStateName(StrEnum):
    """Canonical job states mirrored by :mod:`kmcs.core.jobs`."""

    CREATED = "created"
    WAITING = "waiting"
    READY = "ready"
    LEASED = "leased"
    RUNNING = "running"
    PAUSED = "paused"
    RETRYING = "retrying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    ORPHANED = "orphaned"


class CrashState(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    CLASSIFIED = "classified"
    DUPLICATE = "duplicate"
    REPRODUCED = "reproduced"
    NOT_REPRODUCIBLE = "not-reproducible"
    MINIMIZED = "minimized"
    REPORTED = "reported"
    FIXED_UPSTREAM = "fixed-upstream"
    WONTFIX = "wontfix"
    FALSE_POSITIVE = "false-positive"
    UNKNOWN = "unknown"


class FindingState(StrEnum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    ANALYZED = "analyzed"
    DOCUMENTED = "documented"
    DISCLOSED = "disclosed"
    PATCHED = "patched"
    VERIFIED_FIXED = "verified-fixed"
    REJECTED = "rejected"
    DUPLICATED = "duplicated"
    ARCHIVED = "archived"

    @property
    def actionable(self) -> bool:
        return str(self.value) in {"candidate", "confirmed", "analyzed"}

    @property
    def closed(self) -> bool:
        return str(self.value) in {"patched", "verified-fixed", "rejected", "archived"}


class ReproductionOutcome(StrEnum):
    REPRODUCED = "reproduced"
    INTERMITTENT = "intermittent"
    NOT_REPRODUCED = "not-reproduced"
    ERROR = "error"
    SKIPPED = "skipped"
    PENDING = "pending"

    @property
    def rate_label(self) -> str:
        return {
            "reproduced": "always", "intermittent": "sometimes", "not-reproduced": "never",
            "error": "unknown (tool error)", "skipped": "not attempted", "pending": "queued",
        }[str(self.value)]


class DedupDecision(StrEnum):
    UNIQUE = "unique"
    DUPLICATE = "duplicate"
    PROBABLE_DUPLICATE = "probable-duplicate"
    RELATED = "related"
    UNCERTAIN = "uncertain"


class ReportFormat(StrEnum):
    HTML = "html"
    JSON = "json"
    MARKDOWN = "markdown"
    CSV = "csv"
    SARIF = "sarif"
    TXT = "txt"

    @property
    def extension(self) -> str:
        return {"html": ".html", "json": ".json", "markdown": ".md", "csv": ".csv",
                "sarif": ".sarif", "txt": ".txt"}[str(self.value)]

    @property
    def mime_type(self) -> str:
        return {"html": "text/html", "json": "application/json", "markdown": "text/markdown",
                "csv": "text/csv", "sarif": "application/json+sarif", "txt": "text/plain"}[str(self.value)]


class ProcessRole(StrEnum):
    SUPERVISOR = "supervisor"
    WORKER = "worker"
    FUZZER = "fuzzer"
    TARGET = "target"
    ANALYZER = "analyzer"
    REPORTER = "reporter"
    MONITOR = "monitor"


class SymbolizerKind(StrEnum):
    ASAN_SYMBOLIZER = "llvm-symbolizer"
    ADDR2LINE = "addr2line"
    GDB = "gdb"
    LLDB = "lldb"
    NATIVE = "native"
    NONE = "none"


class CoverageMetric(StrEnum):
    EDGES = "edges"
    FEATURES = "features"
    BRANCHES = "branches"
    LINES = "lines"
    FUNCTIONS = "functions"
    PATHS = "paths"


class OperationMode(StrEnum):
    """How KMCS should behave operationally."""

    RESEARCH = "research"
    CI = "ci"
    OFFLINE = "offline"
    DEMO = "demo"

    @property
    def allows_network(self) -> bool:
        """KMCS never requires the network; every mode forbids it."""
        return False


# ===========================================================================
# protocol & registry
# ===========================================================================


class ModelProtocol:
    """Structural interface implemented by KMCS models."""

    __slots__ = ()

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Any:
        raise NotImplementedError


def _slug_token(text: Any) -> str:
    token = re.sub(r"[^a-z0-9]+", "_", str(text or "").strip().lower()).strip("_")
    return token or "model"


class TypedModelRegistry:
    """Registry mapping logical model names → classes.

    Lets generic persistence/reporting code in later phases rebuild the right
    Python object from a stored row without importing every module.
    """

    def __init__(self) -> None:
        self._models: "OrderedDict[str, Type[Any]]" = OrderedDict()
        self._by_class: Dict[Type[Any], str] = {}
        self._lock = threading.RLock()

    def register(self, name: Any, klass: Type[Any], *, override: bool = False) -> str:
        key = _slug_token(name)
        with self._lock:
            existing = self._models.get(key)
            if existing is not None and existing is not klass and not override:
                raise InvalidValueError(
                    f"model name '{key}' already bound to {existing.__name__}; pass override=True to rebind",
                    details={"existing": existing.__name__, "requested": klass.__name__},
                )
            self._models[key] = klass
            self._by_class[klass] = key
            return key

    def unregister(self, name: Any) -> bool:
        key = _slug_token(name)
        with self._lock:
            klass = self._models.pop(key, None)
            if klass is None:
                return False
            if self._by_class.get(klass) == key:
                self._by_class.pop(klass, None)
            return True

    def get(self, name: Any) -> Optional[Type[Any]]:
        if isinstance(name, type):
            return name
        with self._lock:
            return self._models.get(_slug_token(name))

    def name_of(self, klass: Type[Any]) -> Optional[str]:
        with self._lock:
            return self._by_class.get(klass)

    def names(self) -> List[str]:
        with self._lock:
            return list(self._models.keys())

    def classes(self) -> List[Type[Any]]:
        with self._lock:
            return list(dict.fromkeys(self._models.values()))

    def items(self) -> List[Tuple[str, Type[Any]]]:
        with self._lock:
            unique: "OrderedDict[str, Type[Any]]" = OrderedDict()
            for key, klass in self._models.items():
                unique.setdefault(self._by_class.get(klass, key), klass)
            return list(unique.items())

    def instantiate(self, name: Any, payload: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Any:
        klass = self.get(name)
        if klass is None:
            raise InvalidValueError(f"no model registered under '{name}'", details={"known": self.names()})
        return _instantiate(klass, payload or {}, kwargs)

    def schema(self, name: Any) -> Dict[str, Any]:
        klass = self.get(name)
        if klass is None:
            raise InvalidValueError(f"no model registered under '{name}'", details={"known": self.names()})
        return describe_class(klass)

    def schemas(self) -> Dict[str, Dict[str, Any]]:
        return {key: describe_class(klass) for key, klass in self.items()}

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, type):
            with self._lock:
                return item in self._by_class
        return self.get(item) is not None

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_class)

    def __iter__(self) -> Iterator[str]:
        return iter(self.names())

    def __repr__(self) -> str:
        return f"<TypedModelRegistry models={len(self)}>"


MODEL_REGISTRY = TypedModelRegistry()


def _default_model_name(klass: type) -> str:
    return _slug_token(klass.__name__)


def register_model(name: Optional[str] = None, *, override: bool = True) -> Callable[[Type[T]], Type[T]]:
    """Decorator registering a model class in :data:`MODEL_REGISTRY`."""

    def decorator(klass: Type[T]) -> Type[T]:
        key = name or _default_model_name(klass)
        MODEL_REGISTRY.register(key, klass, override=override)
        setattr(klass, "__kmcs_model_name__", key)
        return klass

    return decorator


def model_for(name: Any) -> Optional[Type[Any]]:
    return MODEL_REGISTRY.get(name)


def model_names() -> List[str]:
    return MODEL_REGISTRY.names()


def instantiate(name: Any, payload: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Any:
    return MODEL_REGISTRY.instantiate(name, payload, **kwargs)


def build_default_registry(populate: bool = True) -> TypedModelRegistry:
    """Return the registry pre-populated with every model/enum in this module."""
    if populate:
        for klass in _ALL_MODEL_CLASSES:
            MODEL_REGISTRY.register(_default_model_name(klass), klass, override=True)
        for enum_cls in _ENUM_CLASSES:
            MODEL_REGISTRY.register(f"enum_{_slug_token(enum_cls.__name__)}", enum_cls, override=True)
    return MODEL_REGISTRY


def describe_class(klass: Type[Any]) -> Dict[str, Any]:
    """Structural description of a dataclass/enum (used for docs and DB mapping)."""
    info: Dict[str, Any] = {
        "class": klass.__name__,
        "module": klass.__module__,
        "kind": "other",
        "fields": {},
        "doc": (klass.__doc__ or "").strip().splitlines()[0] if klass.__doc__ else "",
    }
    if issubclass(klass, Enum):
        info["kind"] = "enum"
        info["members"] = {member.name: member.value for member in klass}
        return info
    if is_dataclass(klass):
        info["kind"] = "dataclass"
        params = getattr(klass, "__dataclass_params__", None)
        for f in fields(klass):
            info["fields"][f.name] = {
                "type": _type_name(f.type),
                "default": _safe_default(f.default, f.default_factory),
                "required": f.default is MISSING and f.default_factory is MISSING,
                "frozen": bool(getattr(params, "frozen", False)),
            }
        return info
    return info


def describe_models() -> Dict[str, Dict[str, Any]]:
    return dict(MODEL_REGISTRY.schemas())


def _type_name(annotation: Any) -> str:
    if isinstance(annotation, str):
        return annotation
    origin = get_origin(annotation)
    if origin is None:
        return getattr(annotation, "__name__", str(annotation))
    args = ", ".join(_type_name(arg) for arg in get_args(annotation))
    return f"{getattr(origin, '__name__', str(origin))}[{args}]"


def _safe_default(default: Any, factory: Any) -> Any:
    if default is not MISSING:
        if isinstance(default, (datetime, Path)):
            return str(default)
        if isinstance(default, (list, set, dict)):
            return None
        return default
    if factory is not MISSING:
        try:
            value = factory()
        except Exception:
            return None
        if isinstance(value, (list, tuple, set, dict)) and len(value) > 8:
            return None
        if isinstance(value, (datetime, Path)):
            return str(value)
        return value
    return None


def _instantiate(klass: Type[T], payload: Mapping[str, Any], extra: Mapping[str, Any]) -> T:
    """Construct *klass* from a mapping, ignoring unknown keys defensively."""
    merged: Dict[str, Any] = dict(payload)
    merged.update({k: v for k, v in (extra or {}).items() if v is not None or k in merged})
    if is_dataclass(klass):
        allowed = {f.name for f in fields(klass)}
        unknown = [k for k in merged if k not in allowed]
        filtered = {k: v for k, v in merged.items() if k in allowed}
        instance = klass(**filtered)  # type: ignore[arg-type]
        if unknown:
            try:
                setattr(instance, "__kmcs_unknown_keys__", unknown)
            except Exception:
                pass
        return instance
    try:
        return klass(**merged)  # type: ignore[call-arg]
    except TypeError as exc:
        raise InvalidValueError(
            f"cannot construct {klass.__name__}: {exc}", details={"payload_keys": sorted(merged)},
        ) from exc


# ===========================================================================
# serialisation helpers
# ===========================================================================


def _json_default(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return utc_string(obj)
    if isinstance(obj, (bytes, bytearray)):
        return b64encode_bytes(bytes(obj))
    if isinstance(obj, Path):
        return str(obj)
    if is_dataclass(obj):
        return serialise(obj, pretty=False)
    if isinstance(obj, Mapping):
        return dict(obj)
    if isinstance(obj, (set, frozenset, tuple)):
        return list(obj)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def _to_plain(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return utc_string(obj)
    if isinstance(obj, (bytes, bytearray)):
        return b64encode_bytes(bytes(obj))
    if isinstance(obj, Path):
        return str(obj)
    if is_dataclass(obj):
        payload = {f.name: _to_plain(getattr(obj, f.name)) for f in fields(obj)}
        payload["__type__"] = type(obj).__name__
        return payload
    if isinstance(obj, Mapping):
        return {str(k): _to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_to_plain(item) for item in obj]
    if hasattr(obj, "to_dict"):
        return _to_plain(obj.to_dict())
    return str(obj)


def serialise(obj: Any, *, pretty: bool = False) -> Any:
    """Convert models/dicts/lists into JSON-safe structures (or a JSON string)."""
    converted = _to_plain(obj)
    if pretty:
        return json.dumps(converted, indent=2, sort_keys=True, default=_json_default, ensure_ascii=False)
    return converted


def deserialise(text_or_obj: Any, *, registry: Optional[TypedModelRegistry] = None, default_model: Optional[str] = None) -> Any:
    """Inverse of :func:`serialise`; uses ``__type__`` plus registry when present."""
    data = json.loads(text_or_obj) if isinstance(text_or_obj, (str, bytes)) else copy.deepcopy(text_or_obj)
    reg = registry or MODEL_REGISTRY
    if isinstance(data, list):
        return [deserialise(item, registry=reg) for item in data]
    if not isinstance(data, dict):
        return data
    type_name = data.get("__type__") or default_model
    if type_name and reg.get(type_name) is not None:
        payload = {k: v for k, v in data.items() if k != "__type__"}
        return reg.instantiate(type_name, payload)
    return {k: deserialise(v, registry=reg) if isinstance(v, (dict, list)) else v for k, v in data.items()}


_JSON_HINTS = ("List", "Dict", "Set", "Tuple", "list", "dict", "set", "tuple")


def record_to_row(record: Any) -> Dict[str, Any]:
    """Flatten a model into SQLite-friendly scalar columns (+ JSON blobs)."""
    payload = record.to_dict() if hasattr(record, "to_dict") else _to_plain(record)
    if not isinstance(payload, Mapping):
        raise InvalidValueError(f"cannot flatten {type(record).__name__} into a row")
    row: Dict[str, Any] = {}
    for key, value in payload.items():
        if value is None or isinstance(value, (str, int, float, bool)):
            row[key] = value
        elif isinstance(value, Enum):
            row[key] = value.value
        else:
            row[key] = json.dumps(_to_plain(value), default=_json_default, sort_keys=True)
    return row


def row_to_record(row: Mapping[str, Any], klass: Type[T], *, json_fields: Optional[Sequence[str]] = None) -> T:
    """Rebuild a model from a flat row, decoding declared JSON columns."""
    payload: Dict[str, Any] = dict(row)
    declared: Set[str] = set(json_fields or ())
    if is_dataclass(klass):
        for f in fields(klass):
            name = _type_name(f.type)
            if any(hint in name for hint in _JSON_HINTS):
                declared.add(f.name)
    for key in declared:
        value = payload.get(key)
        if isinstance(value, str) and value[:1] in "[{":
            try:
                payload[key] = json.loads(value)
            except json.JSONDecodeError:
                pass
    return _instantiate(klass, payload, {})


def deep_merge(base: Optional[Mapping[str, Any]], overlay: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Recursively merge mappings; lists are replaced rather than concatenated."""
    result: Dict[str, Any] = {}
    for key, value in (base or {}).items():
        result[key] = copy.deepcopy(value)
    for key, value in (overlay or {}).items():
        if key in result and isinstance(result[key], Mapping) and isinstance(value, Mapping):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


merge_dicts = deep_merge


def walk_type(annotation: Any) -> List[str]:
    """Collect leaf type names inside a (possibly nested) type hint."""
    origin = get_origin(annotation)
    if origin is None:
        return [getattr(annotation, "__name__", None) or str(annotation)]
    leaves: List[str] = [getattr(origin, "__name__", str(origin))]
    for arg in get_args(annotation):
        leaves.extend(walk_type(arg))
    return leaves


def type_hint_of(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, (bytes, bytearray)):
        return "bytes"
    if isinstance(value, Mapping):
        inner = ", ".join(sorted({type_hint_of(key) for key in value})) or "Any"
        return f"Dict[{inner}]"
    if isinstance(value, (list, tuple, set, frozenset)):
        inner = ", ".join(sorted({type_hint_of(item) for item in value})) or "Any"
        return f"List[{inner}]"
    return type(value).__name__


# ===========================================================================
# small value objects
# ===========================================================================


@dataclass(frozen=True)
class TimestampRange:
    """Closed interval between two aware timestamps."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        begin = parse_timestamp(self.start) or now_utc()
        finish = parse_timestamp(self.end) or begin
        object.__setattr__(self, "start", begin)
        object.__setattr__(self, "end", finish if finish >= begin else begin)

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    def contains(self, moment: Any) -> bool:
        stamp = parse_timestamp(moment)
        return bool(stamp) and self.start <= stamp <= self.end

    def overlaps(self, other: "TimestampRange") -> bool:
        return self.start <= other.end and other.start <= self.end

    def human(self) -> str:
        return humanize_duration(self.duration_seconds)

    def to_dict(self) -> Dict[str, Any]:
        return {"start": utc_string(self.start), "end": utc_string(self.end), "seconds": round(self.duration_seconds, 3)}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "TimestampRange":
        return cls(parse_timestamp(payload.get("start")) or now_utc(), parse_timestamp(payload.get("end")) or now_utc())


@dataclass(frozen=True)
class ByteRange:
    offset: int
    length: int

    def __post_init__(self) -> None:
        if int(self.offset) < 0:
            raise InvalidValueError(f"byte offset cannot be negative ({self.offset})")
        if int(self.length) < 0:
            raise InvalidValueError(f"byte length cannot be negative ({self.length})")

    @property
    def end(self) -> int:
        return int(self.offset) + int(self.length)

    def contains(self, position: int) -> bool:
        return self.offset <= int(position) < self.end

    def overlaps(self, other: "ByteRange") -> bool:
        return self.offset < other.end and other.offset < self.end

    def to_dict(self) -> Dict[str, Any]:
        return {"offset": self.offset, "length": self.length, "end": self.end}


@dataclass
class ResourceUsage:
    cpu_percent: Optional[float] = None
    rss_bytes: Optional[int] = None
    vms_bytes: Optional[int] = None
    peak_rss_bytes: Optional[int] = None
    disk_read_bytes: Optional[int] = None
    disk_write_bytes: Optional[int] = None
    open_files: Optional[int] = None
    threads: Optional[int] = None
    sampled_at: str = field(default_factory=lambda: utc_string())

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ToolAvailability:
    """Result of probing one external tool.  Never fabricates a version."""

    name: str
    executable: Optional[str] = None
    present: bool = False
    version: Optional[str] = None
    version_parsed: Optional[Tuple[int, ...]] = None
    min_version: Optional[str] = None
    sufficient: Optional[bool] = None
    path_searched: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    probed_at: str = field(default_factory=lambda: utc_string())
    probe_error: Optional[str] = None

    @property
    def status(self) -> str:
        if not self.present:
            return "missing"
        if self.sufficient is False:
            return "too-old"
        if self.sufficient is None:
            return "present-unverified"
        return "ok"

    @property
    def usable(self) -> bool:
        return bool(self.present and self.sufficient is not False)

    def summary(self) -> str:
        if not self.present:
            return f"{self.name}: not found"
        return f"{self.name}: {self.version or 'unknown version'} [{self.status}]"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["version_parsed"] = list(self.version_parsed) if self.version_parsed else None
        return data


_VERSION_PATTERNS = (
    re.compile(r"version\s+([0-9]+(?:\.[0-9]+){1,3})"),
    re.compile(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
)


def _extract_version(text: Any) -> Optional[str]:
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(str(text or ""))
        if match:
            return match.group(1)
    return None


def _compare_versions(left: Optional[str], right: Optional[str]) -> int:
    def parts(value: Optional[str]) -> List[int]:
        if not value:
            return [0, 0, 0, 0]
        cleaned = re.sub(r"[^0-9.].*$", "", str(value).strip())
        chunks = [int(x) for x in cleaned.split(".") if x.isdigit()]
        return (chunks + [0, 0, 0, 0])[:4]

    pa, pb = parts(left), parts(right)
    return (pa > pb) - (pa < pb)


KNOWN_TOOLS: Dict[str, Dict[str, Any]] = {
    "afl-fuzz": {"engine": "aflpp", "role": "fuzzer", "min_version": "4.00"},
    "afl-clang-fast": {"engine": "aflpp", "role": "instrumentation", "min_version": "4.00"},
    "afl-clang-fast++": {"engine": "aflpp", "role": "instrumentation", "min_version": "4.00"},
    "afl-showmap": {"engine": "aflpp", "role": "coverage"},
    "afl-cmin": {"engine": "aflpp", "role": "corpus-minimization"},
    "afl-tmin": {"engine": "aflpp", "role": "testcase-minimization"},
    "afl-analyze": {"engine": "aflpp", "role": "analysis"},
    "clang": {"engine": "libfuzzer", "role": "compiler", "min_version": "11"},
    "clang++": {"engine": "libfuzzer", "role": "compiler", "min_version": "11"},
    "honggfuzz": {"engine": "honggfuzz", "role": "fuzzer"},
    "gcc": {"role": "compiler"},
    "g++": {"role": "compiler"},
    "llvm-symbolizer": {"role": "symbolizer"},
    "addr2line": {"role": "symbolizer"},
    "objdump": {"role": "binary-utils"},
    "nm": {"role": "binary-utils"},
    "file": {"role": "detector"},
    "gdb": {"role": "debugger"},
    "lldb": {"role": "debugger"},
    "perf": {"role": "profiler"},
    "strace": {"role": "tracer"},
    "ltrace": {"role": "tracer"},
    "ccache": {"role": "build-cache"},
    "cmake": {"role": "build-system"},
    "make": {"role": "build-system"},
    "ninja": {"role": "build-system"},
    "meson": {"role": "build-system"},
    "autoconf": {"role": "build-system"},
    "pkg-config": {"role": "build-system"},
}


def _run_version_probe(executable: str, timeout: float = 5.0) -> Tuple[Optional[str], Optional[str]]:
    """Execute ``<tool> --version`` for real; return ``(version, error)``."""
    for args in (("--version",), ("-version",), ("--help",)):
        try:
            proc = subprocess.run([executable, *args], capture_output=True, text=True, timeout=timeout, check=False)
        except FileNotFoundError:
            return None, "not-found"
        except subprocess.TimeoutExpired:
            return None, "probe-timeout"
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        version = _extract_version(text)
        if version:
            return version, None
        if proc.returncode == 0:
            first = text.strip().splitlines()[0] if text.strip() else ""
            return _extract_version(first), None
    return None, "no-version-output"


class ToolchainProbe:
    """Aggregate view of a toolchain probe with attribute-style access."""

    def __init__(self, search_paths: Optional[Sequence[str]] = None) -> None:
        self.search_paths: List[str] = list(search_paths or [])
        self.tools: Dict[str, ToolAvailability] = {}
        self.missing_required: List[str] = []
        self.probed_at: str = utc_string()
        self.complete: bool = False

    def get(self, name: str) -> Optional[ToolAvailability]:
        return self.tools.get(name)

    def has(self, name: str) -> bool:
        tool = self.tools.get(name)
        return bool(tool and tool.present)

    def usable(self, name: str) -> bool:
        tool = self.tools.get(name)
        return bool(tool and tool.usable)

    def require(self, *names: str) -> None:
        missing = [name for name in names if not self.usable(name)]
        if missing:
            raise ToolNotFoundError(missing[0], searched=self.search_paths, details={"missing": missing})

    def available_roles(self, role: str) -> List[str]:
        marker = f"role={role}"
        return [name for name, tool in self.tools.items() if tool.present and marker in (tool.notes or [])]

    def summary(self) -> Dict[str, Any]:
        return {
            "probed_at": self.probed_at,
            "tools_total": len(self.tools),
            "tools_present": sum(1 for t in self.tools.values() if t.present),
            "tools_ok": sum(1 for t in self.tools.values() if t.status == "ok"),
            "missing_required": list(self.missing_required),
            "complete": self.complete,
            "search_paths": self.search_paths[:10],
            "tools": {name: tool.to_dict() for name, tool in sorted(self.tools.items())},
        }

    def report_lines(self) -> List[str]:
        lines = [f"toolchain probe @ {self.probed_at}", f"search paths: {len(self.search_paths)}"]
        for name, tool in sorted(self.tools.items()):
            lines.append(f"  {'+' if tool.present else '-'} {tool.summary()}")
        if self.missing_required:
            lines.append("MISSING REQUIRED: " + ", ".join(self.missing_required))
        return lines

    def to_dict(self) -> Dict[str, Any]:
        return self.summary()


def probe_toolchain(
    tools: Optional[Iterable[str]] = None,
    *,
    search_paths: Optional[Sequence[Any]] = None,
    timeout: float = 5.0,
    require: Optional[Sequence[str]] = None,
) -> ToolchainProbe:
    """Probe the local toolchain honestly.

    Missing tools are reported as missing; no version numbers are invented and
    no fuzzing activity is simulated.
    """
    wanted = list(tools or KNOWN_TOOLS.keys())
    required_set = set(require or ())
    default_paths = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    probe = ToolchainProbe(search_paths=[normalize_path(p) for p in (search_paths or default_paths)])
    joined_path = os.pathsep.join(probe.search_paths) or None
    for name in wanted:
        meta = KNOWN_TOOLS.get(name, {})
        located = shutil.which(name, path=joined_path)
        availability = ToolAvailability(
            name=name,
            executable=located,
            present=bool(located),
            min_version=meta.get("min_version"),
            path_searched=probe.search_paths[:12],
            notes=[f"role={meta['role']}"] if meta.get("role") else [],
        )
        if located:
            version, error = _run_version_probe(located, timeout=timeout)
            availability.version = version
            if version:
                availability.version_parsed = tuple(int(x) for x in re.findall(r"\d+", version)[:4])
            if error:
                availability.notes.append(f"version-probe:{error}")
            if availability.min_version and version:
                availability.sufficient = _compare_versions(version, availability.min_version) >= 0
        probe.tools[name] = availability
        if name in required_set and not availability.usable:
            probe.missing_required.append(name)
    probe.probed_at = utc_string()
    probe.complete = not probe.missing_required
    return probe


@dataclass
class EngineCapabilities:
    """What a specific engine can actually do on this host (derived from probes)."""

    engine: str
    available: bool = False
    binaries: List[str] = field(default_factory=list)
    usable_binaries: List[str] = field(default_factory=list)
    supports_corpus: bool = True
    supports_parallel: bool = True
    supports_dictionary: bool = True
    supports_tokens: bool = False
    in_process: bool = False
    requires_instrumentation: bool = True
    notes: List[str] = field(default_factory=list)
    probed_at: str = field(default_factory=lambda: utc_string())

    def __post_init__(self) -> None:
        try:
            kind = EngineKind.coerce(self.engine)
        except Exception:
            kind = EngineKind.CUSTOM
        self.engine = str(kind.value)
        self.in_process = kind.in_process
        self.requires_instrumentation = kind.requires_instrumentation
        self.supports_tokens = kind is EngineKind.AFLPP
        self.supports_parallel = kind.supports_parallel_workers

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def probe_engine_availability(engine: Any, probe: Optional[ToolchainProbe] = None) -> EngineCapabilities:
    kind = EngineKind.coerce(engine)
    tool_probe = probe or probe_toolchain(list(dict.fromkeys(kind.binaries)) or None)
    present = [binary for binary in kind.binaries if tool_probe.has(binary)]
    usable = [binary for binary in kind.binaries if tool_probe.usable(binary)]
    available = bool(usable) if kind.binaries else kind is EngineKind.CUSTOM
    notes: List[str] = []
    if kind is EngineKind.LIBFUZZER and not tool_probe.has("clang"):
        available = False
        notes.append("libFuzzer requires clang with -fsanitize=fuzzer support")
    if kind is EngineKind.AFLPP and not tool_probe.has("afl-fuzz"):
        available = False
        notes.append("afl-fuzz binary not found on PATH")
    if not notes:
        notes.append(f"found {len(present)}/{len(kind.binaries)} components" if present else "no components found")
    return EngineCapabilities(
        engine=str(kind.value), available=available, binaries=present, usable_binaries=usable,
        notes=notes, probed_at=tool_probe.probed_at,
    )


# ===========================================================================
# stack traces / sanitizer reports
# ===========================================================================


@dataclass(frozen=True)
class StackFrame:
    """One resolved frame of a crash backtrace."""

    index: int = 0
    address: Optional[str] = None
    module: Optional[str] = None
    function: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    offset: Optional[str] = None
    is_instrumented: bool = False
    is_system_library: bool = False
    raw: str = ""

    SYSTEM_MODULE_PATTERNS: ClassVar[Tuple[str, ...]] = (
        "libc.so", "libc-", "ld-linux", "ld-musl", "libstdc++", "libgcc_s", "ld64.",
        "libpthread", "libdl", "libm.so", "ntdll.dll", "kernel32.dll", "libc++.so",
    )

    def __post_init__(self) -> None:
        if self.module and any(pattern in self.module for pattern in self.SYSTEM_MODULE_PATTERNS):
            object.__setattr__(self, "is_system_library", True)

    @property
    def location(self) -> str:
        if self.function and self.file:
            return f"{self.function} at {self.file}:{self.line or '?'}"
        if self.function:
            return f"{self.function} ({self.module or self.address or '?'})"
        if self.module:
            return f"{self.module}+{self.offset or self.address or '0'}"
        return self.raw or self.address or "<unknown frame>"

    @property
    def identity(self) -> str:
        """Stable identity used for fingerprinting (deliberately excludes addresses)."""
        function = _normalise_function(self.function) if self.function else ""
        module = os.path.basename(self.module) if self.module else ""
        if function:
            return f"{module}:{function}" if module else function
        if module:
            return f"{module}:{self.line if self.line is not None else ''}"
        return (self.raw or "").strip() or "?"

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", False) or k == "index"}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "StackFrame":
        simple = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]

    @classmethod
    def parse_asan_line(cls, line: Any, index: int = 0) -> Optional["StackFrame"]:
        """Parse an ASan/LSan style frame: ``#0 0xabc in func file.cpp:12:3``."""
        text = str(line or "").strip()
        match = re.match(
            r"^#(\d+)\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(.+?)\s+(/.+?|<[^>]+>)(?::(\d+)(?::(\d+))?)?$", text,
        )
        if match:
            return cls(
                index=int(match.group(1)), function=match.group(2).strip(),
                file=None if match.group(3).startswith("<") else match.group(3),
                line=int(match.group(4)) if match.group(4) else None,
                column=int(match.group(5)) if match.group(5) else None, raw=text,
            )
        match = re.match(r"^#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)\s+\(([^)]*)\)$", text)
        if match:
            module_part = match.group(4)
            offset_match = re.search(r"\+(0x[0-9a-fA-F]+)", module_part)
            return cls(
                index=int(match.group(1)), address=match.group(2), function=match.group(3),
                module=(module_part.split("+")[0].strip() or None),
                offset=offset_match.group(1) if offset_match else None, raw=text,
            )
        match = re.match(r"^#(\d+)\s+(0x[0-9a-fA-F]+):\s*(\S+)?\s*(.*)$", text)
        if match:
            return cls(index=int(match.group(1)), address=match.group(2), module=match.group(3), raw=text)
        return None

    @classmethod
    def parse_gdb_line(cls, line: Any, index: int = 0) -> Optional["StackFrame"]:
        text = str(line or "").strip()
        match = re.match(r"^#(\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?([\w:~<>$]+)\s*\((.*?)\)\s*(?:at\s+(.*?):(\d+))?", text)
        if match:
            return cls(
                index=int(match.group(1)), function=match.group(2), raw=text,
                file=match.group(4), line=int(match.group(5)) if match.group(5) else None,
            )
        return None


def _normalise_function(name: Any) -> str:
    """Strip template arguments, parameter lists and addresses from a symbol."""
    if not name:
        return ""
    text = str(name).strip()
    text = re.sub(r"\s*\{[^}]*\}", "", text)
    for _ in range(4):
        text = re.sub(r"<[^<>]*>", "<>", text)
    text = re.sub(r"\(.*\)$", "", text)
    return re.sub(r"\s+", "", text)


@dataclass
class StackTrace:
    frames: List[StackFrame] = field(default_factory=list)
    truncated: bool = False
    source: str = "sanitizer"
    thread_id: Optional[int] = None
    raw: str = ""

    def __post_init__(self) -> None:
        self.frames.sort(key=lambda frame: frame.index)

    def __len__(self) -> int:
        return len(self.frames)

    def __iter__(self) -> Iterator[StackFrame]:
        return iter(self.frames)

    @property
    def top(self) -> Optional[StackFrame]:
        return self.frames[0] if self.frames else None

    def significant_frames(self, limit: int = 5, skip_system: bool = True) -> List[StackFrame]:
        chosen = [frame for frame in self.frames if not (skip_system and frame.is_system_library)] or list(self.frames)
        return chosen[: max(1, int(limit))]

    def signature(self, depth: int = 4, skip_system: bool = True) -> str:
        identities = [frame.identity for frame in self.significant_frames(limit=depth, skip_system=skip_system)]
        return "|".join(identities) if identities else "??"

    def to_text(self) -> str:
        return "\n".join(f"#{frame.index:>2} {frame.location}" for frame in self.frames)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frames": [frame.to_dict() for frame in self.frames],
            "truncated": self.truncated, "source": self.source,
            "thread_id": self.thread_id, "signature": self.signature(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "StackTrace":
        frames = [StackFrame.from_dict(item) for item in payload.get("frames", []) if isinstance(item, Mapping)]
        return cls(
            frames=frames, truncated=bool(payload.get("truncated")),
            source=str(payload.get("source", "sanitizer")), thread_id=payload.get("thread_id"),
            raw=str(payload.get("raw", "")),
        )

    @classmethod
    def parse(cls, text: Any, *, source: str = "auto") -> "StackTrace":
        frames: List[StackFrame] = []
        for line in str(text or "").splitlines():
            if not line.strip().startswith("#"):
                continue
            frame = StackFrame.parse_asan_line(line, len(frames)) or StackFrame.parse_gdb_line(line, len(frames))
            if frame is not None:
                frames.append(frame)
        detected = source
        if source == "auto":
            body = str(text or "")
            detected = "gdb" if re.search(r"^#\d+\s+0x[0-9a-fA-F]+\s+in\s", body, re.MULTILINE) else "sanitizer"
        return cls(frames=frames, source=detected, raw=str(text or ""))


@dataclass
class SignalInfo:
    signal_number: Optional[int] = None
    name: Optional[str] = None
    si_code: Optional[int] = None
    fault_address: Optional[str] = None
    description: str = ""

    COMMON_SIGNALS: ClassVar[Dict[int, str]] = {
        1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT",
        7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE", 14: "SIGALRM",
        15: "SIGTERM", 23: "SIGSYS", 24: "SIGXCPU", 25: "SIGXFSZ",
    }

    def __post_init__(self) -> None:
        if self.signal_number is not None:
            self.signal_number = int(self.signal_number)
            if not self.name:
                self.name = self.COMMON_SIGNALS.get(self.signal_number)
        if not self.description and self.signal_number in self.COMMON_SIGNALS:
            self.description = {
                11: "Invalid memory reference (segmentation fault)",
                6: "Process aborted (assertion or explicit abort)",
                8: "Arithmetic operation error (e.g. division by zero)",
                4: "Illegal instruction executed",
                7: "Bus error (misaligned or non-existent physical address)",
            }.get(self.signal_number, "")

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass
class MemoryAccess:
    """Description of the offending access recorded by a sanitizer."""

    access_type: str = MemoryAccessType.UNKNOWN.value
    access_size: Optional[int] = None
    access_address: Optional[str] = None
    allocation_size: Optional[int] = None
    allocation_address: Optional[str] = None
    offset_from_allocation: Optional[int] = None
    freed_by_frame: Optional[str] = None
    allocated_by_frame: Optional[str] = None
    thread_id: Optional[int] = None

    def __post_init__(self) -> None:
        try:
            self.access_type = str(MemoryAccessType.coerce(self.access_type).value)
        except Exception:
            self.access_type = MemoryAccessType.UNKNOWN.value
        for name in ("access_size", "allocation_size", "offset_from_allocation"):
            value = getattr(self, name)
            if value is not None and int(value) < 0 and name != "offset_from_allocation":
                raise InvalidValueError(f"{name} cannot be negative ({value})")
        if self.access_address and self.allocation_address and self.offset_from_allocation is None:
            try:
                self.offset_from_allocation = int(str(self.access_address), 16) - int(str(self.allocation_address), 16)
            except (TypeError, ValueError):
                pass

    @property
    def direction(self) -> str:
        if self.offset_from_allocation is None:
            return "unknown"
        if self.offset_from_allocation < 0:
            return "underflow"
        if self.allocation_size is not None and self.offset_from_allocation >= self.allocation_size:
            return "overflow"
        if 0 <= self.offset_from_allocation < (self.allocation_size or 0):
            return "in-bounds"
        return "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class CrashLocation:
    """Where in the target the fault was observed."""

    module: Optional[str] = None
    function: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    address: Optional[str] = None
    instruction_offset: Optional[str] = None

    @property
    def display(self) -> str:
        if self.file and self.function:
            return f"{os.path.basename(self.file)}:{self.line or '?'} in {self.function}"
        if self.function:
            return self.function
        if self.module:
            return f"{os.path.basename(self.module)}+{self.instruction_offset or self.address or '0'}"
        return self.address or "unknown location"

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass
class SanitizerReport:
    """Structured view of one sanitizer output block.

    Only *observed* fields are populated; anything absent stays ``None`` so the
    analysis layer can distinguish "not reported" from "zero".
    """

    sanitizer: str = SanitizerKind.ASAN.value
    headline: Optional[str] = None
    crash_class: str = CrashClass.UNKNOWN.value
    thread: Optional[str] = None
    pid: Optional[int] = None
    exit_code: Optional[int] = None
    shadow_bytes: Optional[str] = None
    memory_access: Optional[MemoryAccess] = None
    stack_trace: StackTrace = field(default_factory=StackTrace)
    allocation_trace: Optional[StackTrace] = None
    free_trace: Optional[StackTrace] = None
    thread_list: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    raw_output: str = ""
    parsed_from: str = "raw"
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        try:
            self.sanitizer = str(SanitizerKind.coerce(self.sanitizer).value)
        except Exception:
            self.sanitizer = SanitizerKind.NONE.value
        try:
            self.crash_class = str(CrashClass.coerce(self.crash_class).value)
        except Exception:
            self.crash_class = CrashClass.UNKNOWN.value
        if not self.headline and self.raw_output:
            for line in str(self.raw_output).splitlines():
                if "ERROR:" in line or "runtime error" in line or "SUMMARY:" in line:
                    self.headline = line.strip()
                    break

    @property
    def summary_line(self) -> str:
        return self.headline or f"{self.sanitizer}: {self.crash_class}"

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "sanitizer": self.sanitizer, "headline": self.headline, "crash_class": self.crash_class,
            "thread": self.thread, "pid": self.pid, "exit_code": self.exit_code,
            "shadow_bytes": self.shadow_bytes,
            "memory_access": self.memory_access.to_dict() if self.memory_access else None,
            "stack_trace": self.stack_trace.to_dict(),
            "allocation_trace": self.allocation_trace.to_dict() if self.allocation_trace else None,
            "free_trace": self.free_trace.to_dict() if self.free_trace else None,
            "threads": list(self.thread_list), "modules": list(self.modules),
            "stats": dict(self.stats), "warnings": list(self.warnings),
            "parsed_from": self.parsed_from, "raw_output": self.raw_output,
        }
        return {k: v for k, v in payload.items() if v not in (None, [], {}, "")}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SanitizerReport":
        trace = payload.get("stack_trace")
        alloc = payload.get("allocation_trace")
        free = payload.get("free_trace")
        access = payload.get("memory_access")
        simple = {f.name for f in fields(cls)} - {
            "stack_trace", "allocation_trace", "free_trace", "memory_access", "thread_list",
            "modules", "stats", "warnings",
        }
        return cls(
            **{k: v for k, v in payload.items() if k in simple},  # type: ignore[arg-type]
            stack_trace=StackTrace.from_dict(trace) if isinstance(trace, Mapping) else StackTrace(),
            allocation_trace=StackTrace.from_dict(alloc) if isinstance(alloc, Mapping) else None,
            free_trace=StackTrace.from_dict(free) if isinstance(free, Mapping) else None,
            memory_access=MemoryAccess(**{k: v for k, v in access.items() if k in {f.name for f in fields(MemoryAccess)}}) if isinstance(access, Mapping) else None,
            thread_list=list(payload.get("threads") or payload.get("thread_list") or []),
            modules=list(payload.get("modules") or []),
            stats=dict(payload.get("stats") or {}),
            warnings=list(payload.get("warnings") or []),
        )


# ===========================================================================
# fingerprints
# ===========================================================================


@dataclass(frozen=True)
class Fingerprint:
    """De-duplication key for a crash.

    Computed from the *semantic* crash identity (target, sanitizer, crash class,
    top stack frames, faulting location) — never from volatile values such as
    PIDs, timestamps or absolute addresses, which would defeat de-duplication.
    """

    algorithm: str = "kmcs-crash-v1"
    digest: str = ""
    components: Tuple[Tuple[str, str], ...] = ()
    collision_group: Optional[str] = None

    @property
    def short(self) -> str:
        return self.digest[:12] if self.digest else "0" * 12

    def matches(self, other: Any) -> bool:
        if isinstance(other, Fingerprint):
            return bool(self.digest) and self.digest == other.digest
        return bool(self.digest) and str(self.digest) == str(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"algorithm": self.algorithm, "digest": self.digest, "short": self.short,
                "components": dict(self.components)}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Fingerprint":
        comps = payload.get("components") or {}
        items = comps.items() if isinstance(comps, Mapping) else comps
        return cls(
            algorithm=str(payload.get("algorithm", "kmcs-crash-v1")),
            digest=str(payload.get("digest", "")),
            components=tuple(sorted((str(k), str(v)) for k, v in items)),
            collision_group=payload.get("collision_group"),
        )


def compute_fingerprint(
    *,
    target: Any = "",
    sanitizer: Any = "",
    crash_class: Any = "",
    stack_signature: str = "",
    location: str = "",
    extra: Optional[Mapping[str, Any]] = None,
    algorithm: str = "kmcs-crash-v1",
    depth: int = 4,
) -> Fingerprint:
    """Compute a deterministic crash fingerprint from semantic attributes."""
    sig_frames = [part.strip() for part in str(stack_signature or "").split("|") if part.strip()]
    components: Dict[str, str] = {
        "target": _slug_token(target) if target else "",
        "sanitizer": str(sanitizer or "").lower(),
        "crash_class": str(crash_class or "").lower(),
        "frames": "|".join(sig_frames[: max(1, int(depth))]),
        "location": os.path.basename(str(location or "")).strip(),
    }
    for key, value in (extra or {}).items():
        if value is not None:
            components[f"x-{key}"] = str(value)
    payload = json.dumps(components, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(f"{algorithm}\n{payload}".encode("utf-8", "replace")).hexdigest()
    return Fingerprint(algorithm=algorithm, digest=digest, components=tuple(sorted(components.items())))


def fingerprint_of(record: Any, *, depth: int = 4) -> Fingerprint:
    """Derive a fingerprint from a :class:`Crash` instance or a plain mapping."""
    if isinstance(record, Crash):
        return compute_fingerprint(
            target=record.target_id or record.executable,
            sanitizer=record.sanitizer, crash_class=record.crash_class,
            stack_signature=record.stack_signature(depth=depth),
            location=record.location.display if record.location else "",
            extra={"access_type": record.memory_access.access_type if record.memory_access else ""},
            depth=depth,
        )
    if isinstance(record, Mapping):
        access = record.get("memory_access")
        return compute_fingerprint(
            target=record.get("target_id") or record.get("executable") or "",
            sanitizer=record.get("sanitizer") or "", crash_class=record.get("crash_class") or "",
            stack_signature=record.get("stack_signature") or "",
            location=str(record.get("location") or ""),
            extra={"access_type": (access or {}).get("access_type") if isinstance(access, Mapping) else ""},
            depth=depth,
        )
    raise InvalidValueError(f"cannot fingerprint object of type {type(record).__name__}")


# ===========================================================================
# corpus models
# ===========================================================================


@dataclass
class CorpusEntry:
    id: str = field(default_factory=lambda: generate_prefixed_id("seed"))
    path: str = ""
    content_hash: str = ""
    size_bytes: int = 0
    input_class: str = InputClass.UNKNOWN.value
    label: str = ""
    origin: str = "manual"
    tags: List[str] = field(default_factory=list)
    added_at: str = field(default_factory=lambda: utc_string())
    last_seen_at: Optional[str] = None
    executions: int = 0
    favours: int = 0
    coverage_edges: Optional[int] = None
    quarantine: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if self.path:
            self.path = normalize_path(self.path)
            if not self.label:
                self.label = os.path.basename(self.path)
        try:
            self.input_class = str(InputClass.coerce(self.input_class).value)
        except Exception:
            self.input_class = InputClass.UNKNOWN.value
        if int(self.size_bytes) < 0:
            raise InvalidValueError(f"corpus entry size cannot be negative ({self.size_bytes})")
        self.size_bytes = int(self.size_bytes)
        self.tags = [tag for tag in dict.fromkeys(_slug_token(t) for t in self.tags if str(t).strip()) if tag and tag != "tag"]

    @property
    def is_crash_trigger(self) -> bool:
        return self.input_class == InputClass.CRASH_TRIGGERING.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CorpusEntry":
        simple = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]

    @classmethod
    def from_file(cls, path: Any, *, input_class: Any = None, origin: str = "import", hash_content: bool = True) -> "CorpusEntry":
        real = normalize_path(path, resolve=True)
        info = os.stat(real)
        if not stat.S_ISREG(info.st_mode):
            raise InvalidValueError(f"corpus seed must be a regular file: {real}")
        return cls(
            path=real,
            content_hash=sha256_file(real) if hash_content else "",
            size_bytes=info.st_size,
            input_class=str(input_class or input_class_for(real)),
            label=os.path.basename(real),
            origin=origin,
            added_at=utc_string(datetime.fromtimestamp(info.st_mtime, tz=timezone.utc)),
        )


@dataclass
class CorpusStats:
    entries: int = 0
    total_bytes: int = 0
    unique_hashes: int = 0
    duplicates: int = 0
    invalid: int = 0
    quarantined: int = 0
    mean_size: float = 0.0
    median_size: float = 0.0
    largest: int = 0
    smallest: Optional[int] = None
    by_class: Dict[str, int] = field(default_factory=dict)
    computed_at: str = field(default_factory=lambda: utc_string())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_entries(cls, entries: Sequence["CorpusEntry"]) -> "CorpusStats":
        sizes = sorted(int(entry.size_bytes or 0) for entry in entries)
        hashes = {entry.content_hash for entry in entries if entry.content_hash}
        by_class: Dict[str, int] = defaultdict(int)
        for entry in entries:
            by_class[entry.input_class] += 1
        return cls(
            entries=len(entries),
            total_bytes=sum(sizes),
            unique_hashes=len(hashes) or len(entries),
            duplicates=max(0, len(entries) - len(hashes)),
            invalid=sum(1 for entry in entries if entry.input_class == InputClass.UNKNOWN.value),
            quarantined=sum(1 for entry in entries if entry.quarantine),
            mean_size=round(sum(sizes) / len(sizes), 2) if sizes else 0.0,
            median_size=float(sizes[len(sizes) // 2]) if sizes else 0.0,
            largest=sizes[-1] if sizes else 0,
            smallest=sizes[0] if sizes else None,
            by_class=dict(by_class),
        )


@dataclass
class Corpus:
    id: str = field(default_factory=lambda: generate_prefixed_id("corpus"))
    name: str = ""
    root: str = ""
    description: str = ""
    target_id: Optional[str] = None
    format_hint: Optional[str] = None
    entries: List[CorpusEntry] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: utc_string())
    updated_at: str = field(default_factory=lambda: utc_string())
    max_input_bytes: int = 1 << 20
    validate_on_add: bool = True

    def __post_init__(self) -> None:
        self.root = normalize_path(self.root) if self.root else ""
        if not self.name and self.root:
            self.name = os.path.basename(self.root.rstrip("/"))
        if int(self.max_input_bytes) <= 0:
            raise InvalidValueError("max_input_bytes must be positive")

    def add(self, entry: CorpusEntry) -> CorpusEntry:
        if entry.size_bytes > self.max_input_bytes:
            raise InvalidValueError(
                f"seed '{entry.label}' is {entry.size_bytes} bytes, exceeding the corpus limit of {self.max_input_bytes}",
                code=ErrorCode.INPUT_TOO_LARGE,
                details={"path": entry.path, "size_bytes": entry.size_bytes, "limit_bytes": self.max_input_bytes},
            )
        for existing in self.entries:
            if existing.content_hash and existing.content_hash == entry.content_hash:
                existing.last_seen_at = utc_string()
                existing.executions += 1
                return existing
        self.entries.append(entry)
        self.updated_at = utc_string()
        return entry

    def remove(self, entry_id: str) -> bool:
        before = len(self.entries)
        self.entries = [entry for entry in self.entries if entry.id != entry_id]
        self.updated_at = utc_string()
        return len(self.entries) != before

    def find_by_hash(self, content_hash: str) -> Optional[CorpusEntry]:
        for entry in self.entries:
            if entry.content_hash == content_hash:
                return entry
        return None

    def statistics(self) -> CorpusStats:
        return CorpusStats.from_entries(self.entries)

    def is_empty(self) -> bool:
        return not self.entries

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "root": self.root, "description": self.description,
            "target_id": self.target_id, "format_hint": self.format_hint,
            "entries": [entry.to_dict() for entry in self.entries], "tags": list(self.tags),
            "created_at": self.created_at, "updated_at": self.updated_at,
            "max_input_bytes": self.max_input_bytes, "validate_on_add": self.validate_on_add,
            "statistics": self.statistics().to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Corpus":
        entries = [CorpusEntry.from_dict(item) for item in payload.get("entries", []) if isinstance(item, Mapping)]
        simple = {f.name for f in fields(cls)} - {"entries"}
        return cls(entries=entries, **{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]


# ===========================================================================
# authorisation / scope / targets
# ===========================================================================


@dataclass(frozen=True)
class Scope:
    """Declared boundary of an authorised engagement.

    Anything outside the listed paths/assets is refused with
    :class:`~kmcs.core.exceptions.ScopeExceededError`.  This is what keeps KMCS
    honest about being a *consented research* tool rather than a scanning
    utility.
    """

    assets: Tuple[str, ...] = ()
    paths: Tuple[str, ...] = ()
    source_roots: Tuple[str, ...] = ()
    notes: str = ""
    expires_at: Optional[str] = None

    def contains_path(self, candidate: Any) -> bool:
        if not self.paths:
            return False
        target_path = os.path.realpath(normalize_path(candidate))
        for allowed in self.paths:
            allowed_path = os.path.realpath(normalize_path(allowed))
            if target_path == allowed_path or target_path.startswith(allowed_path.rstrip("/") + "/"):
                return True
        return False

    def contains_asset(self, asset: Any) -> bool:
        if not self.assets:
            return False
        token = str(asset or "").strip().lower()
        return any(fnmatchcase(str(item).strip().lower(), token) or str(item).strip().lower() == token for item in self.assets)

    def expired(self, at: Optional[datetime] = None) -> bool:
        if not self.expires_at:
            return False
        expiry = parse_timestamp(self.expires_at)
        return bool(expiry and (at or now_utc()) > expiry)

    def to_dict(self) -> Dict[str, Any]:
        return {"assets": list(self.assets), "paths": list(self.paths),
                "source_roots": list(self.source_roots), "notes": self.notes, "expires_at": self.expires_at}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Scope":
        return cls(
            assets=tuple(payload.get("assets") or ()), paths=tuple(payload.get("paths") or ()),
            source_roots=tuple(payload.get("source_roots") or ()), notes=str(payload.get("notes", "")),
            expires_at=payload.get("expires_at"),
        )


@dataclass
class Authorisation:
    """Written permission record attached to a target.

    KMCS refuses to fuzz a target whose authorisation is missing, revoked or
    expired.  The record stores *who granted it, when and for what scope* — it
    never stores secrets or credentials.
    """

    granted_by: str = ""
    relationship: str = "owner"
    statement: str = ""
    evidence_ref: str = ""
    granted_at: str = field(default_factory=lambda: utc_string())
    expires_at: Optional[str] = None
    revoked: bool = False
    scope: Scope = field(default_factory=Scope)

    RELATIONSHIPS: ClassVar[Tuple[str, ...]] = (
        "owner", "maintainer", "contracted_tester", "bug_bounty_program", "internal_team", "research_permit",
    )

    def __post_init__(self) -> None:
        if self.relationship not in self.RELATIONSHIPS:
            raise InvalidValueError(
                f"unknown authorisation relationship '{self.relationship}'",
                details={"allowed": list(self.RELATIONSHIPS)},
            )
        if not str(self.statement or "").strip():
            raise AuthorizationError(
                "authorisation requires an explicit statement of permission", component="core.models",
            )

    @property
    def valid(self) -> bool:
        if self.revoked or not str(self.statement or "").strip():
            return False
        if self.scope.expired():
            return False
        expiry = parse_timestamp(self.expires_at)
        return not (expiry and now_utc() > expiry)

    def validate_for(self, path: Any) -> None:
        """Raise unless *path* is covered by a live authorisation."""
        if self.revoked:
            raise AuthorizationError("authorisation has been revoked", component="core.models", input_path=str(path))
        if not self.valid:
            raise AuthorizationError("authorisation is missing or expired", component="core.models", input_path=str(path))
        if self.scope.paths and not self.scope.contains_path(path):
            raise ScopeExceededError(requested=str(path), allowed=list(self.scope.paths))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "granted_by": self.granted_by, "relationship": self.relationship, "statement": self.statement,
            "evidence_ref": self.evidence_ref, "granted_at": self.granted_at, "expires_at": self.expires_at,
            "revoked": self.revoked, "scope": self.scope.to_dict(), "valid": self.valid,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Authorisation":
        simple = {f.name for f in fields(cls)} - {"scope"}
        return cls(scope=Scope.from_dict(payload.get("scope") or {}),
                   **{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]


def make_authorisation(
    granted_by: str,
    statement: str,
    *,
    paths: Sequence[Any] = (),
    assets: Sequence[str] = (),
    relationship: str = "owner",
    evidence_ref: str = "",
    days: Optional[int] = None,
) -> Authorisation:
    """Ergonomic constructor for a properly scoped authorisation record."""
    expiry = utc_string(now_utc() + timedelta(days=int(days))) if days else None
    return Authorisation(
        granted_by=granted_by, relationship=relationship, statement=statement, evidence_ref=evidence_ref,
        expires_at=expiry,
        scope=Scope(paths=tuple(normalize_path(p) for p in paths), assets=tuple(assets)),
    )


def require_authorization(target: Any, *, operation: str = "fuzz") -> Authorisation:
    """Gate an operation on a valid authorisation; raise otherwise.

    Called by every execution path in later phases *before* any process spawns.
    """
    authorisation = getattr(target, "authorisation", None)
    if authorisation is None:
        raise ConsentRequiredError(
            f"refusing to {operation}: target '{getattr(target, 'name', target)}' has no authorisation record",
            component="core.models", operation=operation, target=getattr(target, "name", str(target)),
        )
    if not authorisation.valid:
        raise AuthorizationError(
            f"refusing to {operation}: authorisation for target '{getattr(target, 'name', target)}' is revoked or expired",
            component="core.models", operation=operation,
        )
    candidate = getattr(target, "binary_path", None) or getattr(target, "source_root", None)
    if candidate:
        authorisation.validate_for(candidate)
    return authorisation


_PROHIBITED_TERMS: Dict[str, str] = {
    "shellcode": "Shellcode generation is prohibited: KMCS analyses defects, it does not create payloads.",
    "exploit": "Exploit generation is prohibited by the KMCS defensive-use charter.",
    "weaponize": "Weaponisation is prohibited; findings are documented, not armed.",
    "weaponise": "Weaponisation is prohibited; findings are documented, not armed.",
    "rop chain": "ROP-chain construction is exploitation, which KMCS refuses to provide.",
    "gadget": "Gadget discovery belongs to offensive tooling and is not implemented here.",
    "privilege escalation": "Privilege-escalation tooling is prohibited.",
    "persistence": "Persistence mechanisms are prohibited.",
    "credential theft": "Credential theft is prohibited.",
    "keylogger": "Keylogging is prohibited.",
    "remote access trojan": "Remote-access trojans are prohibited.",
    "rootkit": "Rootkits are prohibited.",
    "evasion": "Detection evasion / stealth is prohibited.",
    "stealth": "Stealth operation is prohibited; KMCS is transparent about its activity.",
    "bypass av": "Security-control bypass is prohibited.",
    "unauthorized scan": "Unauthorised scanning is prohibited; consent is mandatory.",
    "brute force cred": "Credential brute-forcing is prohibited.",
    "polymorphic": "Polymorphic/metamorphic code generation is prohibited.",
}


def is_prohibited_capability(request: Any) -> bool:
    token = str(request or "").lower()
    return any(term in token for term in _PROHIBITED_TERMS)


def guard_capability(request: Any, *, context: Optional[Mapping[str, Any]] = None) -> None:
    """Raise :class:`ProhibitedCapabilityError` for offensive requests.

    Called by CLI/GUI handlers so that even a *prompt* asking for offensive
    behaviour produces a clear refusal instead of silence.
    """
    token = str(request or "").lower()
    for term, reason in _PROHIBITED_TERMS.items():
        if term in token:
            raise ProhibitedCapabilityError(
                reason, component="core.models", operation=str(request)[:120],
                details={"matched_term": term, "context": dict(context or {})},
            )


_DANGEROUS_FLAG_PATTERNS = (
    re.compile(r"^-fsanitize=(address|undefined|leak|memory|thread|hwaddress|safe-stack|fuzzer.*)$"),
    re.compile(r"^-fno-omit-frame-pointer$"),
    re.compile(r"^-g[a-z0-9]*$"),
    re.compile(r"^-O[0-3szg]$"),
    re.compile(r"^-W[a-z-]*$"),
    re.compile(r"^-D[A-Za-z_][A-Za-z0-9_]*(=.*)?$"),
    re.compile(r"^-I\S+$"),
    re.compile(r"^-l\S+$"),
    re.compile(r"^-L\S+$"),
    re.compile(r"^-(std|arch|march|mtune|target)=?"),
    re.compile(r"^-f(pic|PIE|no-pie|visibility=\S+|stack-protector\S*|bounds-checking|trapv|unsigned-char)$"),
    re.compile(r"^-(pthread|static|shared|r)$"),
    re.compile(r"^-Xclang\S*"),
    re.compile(r"^--?include=\S+"),
)


def _flag_is_dangerous(flag: Any) -> bool:
    """Reject malformed/hostile compiler flags while allowing the standard set."""
    text = str(flag).strip()
    if not text:
        return False
    if not text.startswith("-"):
        return True
    if "\n" in text or "\x00" in text or ";" in text or "|" in text or "&" in text or "$(" in text:
        return True
    return not any(pattern.match(text) for pattern in _DANGEROUS_FLAG_PATTERNS)


@dataclass
class BuildRecipe:
    """How to (re)build a target with instrumentation + sanitizers."""

    system: str = "autodetect"
    source_root: str = ""
    configure_command: Optional[str] = None
    build_command: Optional[str] = None
    cmake_args: List[str] = field(default_factory=list)
    make_targets: List[str] = field(default_factory=list)
    cc: Optional[str] = None
    cxx: Optional[str] = None
    cflags: List[str] = field(default_factory=list)
    cxxflags: List[str] = field(default_factory=list)
    ldflags: List[str] = field(default_factory=list)
    definitions: Dict[str, str] = field(default_factory=dict)
    sanitizers: List[str] = field(default_factory=list)
    instrumentation: str = InstrumentationKind.NONE.value
    optimization: str = OptimizationLevel.O1.value
    keep_symbols: bool = True
    build_dir: str = "build-kmcs"
    artifacts: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    notes: str = ""

    def __post_init__(self) -> None:
        self.source_root = normalize_path(self.source_root) if self.source_root else ""
        self.build_dir = normalize_path(self.build_dir)
        try:
            self.instrumentation = str(InstrumentationKind.coerce(self.instrumentation).value)
        except Exception:
            self.instrumentation = InstrumentationKind.NONE.value
        try:
            self.optimization = str(OptimizationLevel.coerce(self.optimization).value)
        except Exception:
            self.optimization = OptimizationLevel.O1.value
        cleaned: List[str] = []
        for sanitizer in self.sanitizers:
            try:
                cleaned.append(str(SanitizerKind.coerce(sanitizer).value))
            except Exception:
                raise InvalidValueError(f"unknown sanitizer '{sanitizer}'", details={"allowed": SanitizerKind.tokens()})
        self.sanitizers = list(dict.fromkeys(cleaned))
        for flag_list in (self.cflags, self.cxxflags, self.ldflags):
            for flag in list(flag_list):
                if _flag_is_dangerous(flag):
                    raise InstrumentationError(
                        f"refusing unsafe compiler flag '{flag}' in build recipe",
                        component="core.models", details={"flag": str(flag)},
                    )

    def compile_flags(self, for_cxx: bool = False) -> List[str]:
        flags: List[str] = [OptimizationLevel.coerce(self.optimization).flag]
        if self.keep_symbols:
            flags.append("-g")
        flags.append("-fno-omit-frame-pointer")
        for sanitizer in self.sanitizers:
            flag = SANITIZER_FLAGS.get(str(sanitizer), "")
            if flag:
                flags.append(flag)
        flags.extend(self.cxxflags if for_cxx else self.cflags)
        for name, value in self.definitions.items():
            flags.append(f"-D{name}={value}" if value else f"-D{name}")
        return list(dict.fromkeys(flags))

    def effective_cc(self) -> str:
        if self.cc:
            return self.cc
        if self.instrumentation in {InstrumentationKind.AFL_CLANG_FAST.value, InstrumentationKind.AFL_CLANG_LTO.value}:
            return self.instrumentation
        return "clang"

    def effective_cxx(self) -> str:
        if self.cxx:
            return self.cxx
        if self.instrumentation in {InstrumentationKind.AFL_CLANG_FAST.value, InstrumentationKind.AFL_CLANG_LTO.value}:
            return f"{self.instrumentation}++"
        return "clang++"

    def conflicts(self) -> List[str]:
        issues: List[str] = []
        for sanitizer in self.sanitizers:
            try:
                kind = SanitizerKind.coerce(sanitizer)
            except Exception:
                continue
            for other in kind.incompatible_with:
                if other in self.sanitizers:
                    issues.append(f"{sanitizer} is incompatible with {other}")
        if self.instrumentation in {InstrumentationKind.QEMU_MODE.value, InstrumentationKind.FRIDA_MODE.value} and self.sanitizers:
            issues.append("qemu/frida mode cannot combine with compiled sanitizers")
        return issues

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BuildRecipe":
        simple = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]


@dataclass
class HarnessSpec:
    """Description of how the target consumes input during fuzzing."""

    mode: str = "stdin"
    argv_template: List[str] = field(default_factory=list)
    file_argument_index: Optional[int] = None
    workdir: str = ""
    env: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 10.0
    memory_limit_mb: Optional[int] = None
    startup_pattern: Optional[str] = None
    accept_patterns: List[str] = field(default_factory=list)
    dictionary_path: Optional[str] = None
    tokens_path: Optional[str] = None
    queue_seed_dir: Optional[str] = None
    notes: str = ""

    MODES: ClassVar[Tuple[str, ...]] = ("stdin", "file", "argv", "persistent", "in-process", "socket")

    def __post_init__(self) -> None:
        if self.mode not in self.MODES:
            raise InvalidValueError(f"unsupported harness mode '{self.mode}'", details={"allowed": list(self.MODES)})
        if float(self.timeout_seconds) <= 0:
            raise InvalidValueError("harness timeout must be positive")
        self.workdir = normalize_path(self.workdir) if self.workdir else ""
        for optional in ("dictionary_path", "tokens_path", "queue_seed_dir"):
            value = getattr(self, optional)
            setattr(self, optional, normalize_path(value) if value else None)

    def render_argv(self, input_path: Any) -> List[str]:
        if not self.argv_template:
            raise InvalidValueError("argv_template is empty; cannot render command line")
        target = normalize_path(input_path)
        rendered = [part.replace("@@", target) if "@@" in part else part for part in self.argv_template]
        if self.mode == "argv" and self.file_argument_index is not None and not any("@@" in part for part in self.argv_template):
            index = max(0, min(int(self.file_argument_index), len(rendered)))
            rendered.insert(index, target)
        return rendered

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "HarnessSpec":
        simple = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]


@dataclass
class SourceLayout:
    """Where the sources/headers/build files of a target live."""

    root: str = ""
    include_dirs: List[str] = field(default_factory=list)
    source_dirs: List[str] = field(default_factory=list)
    build_files: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    line_count_estimate: Optional[int] = None
    scanned_at: str = field(default_factory=lambda: utc_string())

    def __post_init__(self) -> None:
        self.root = normalize_path(self.root) if self.root else ""
        self.include_dirs = [normalize_path(p) for p in self.include_dirs]
        self.source_dirs = [normalize_path(p) for p in self.source_dirs]
        self.build_files = [normalize_path(p) for p in self.build_files]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProductIdentity:
    """Upstream product identification for a target (for accurate reporting)."""

    name: str = ""
    vendor: str = ""
    version: str = ""
    distribution: str = ""
    repository_url: str = ""
    bug_tracker_url: str = ""
    license: str = ""
    cpe: str = ""
    purl: str = ""
    commit: str = ""
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class Target:
    """An authorised C/C++ artefact that KMCS may analyse."""

    id: str = field(default_factory=lambda: generate_prefixed_id("tgt"))
    name: str = ""
    binary_path: str = ""
    source_root: str = ""
    kind: str = TargetKind.BINARY.value
    language: str = Language.UNKNOWN.value
    architecture: str = Architecture.UNKNOWN.value
    operating_system: str = OperatingSystem.UNKNOWN.value
    upstream_project: str = ""
    upstream_url: str = ""
    version: str = ""
    build_recipe: BuildRecipe = field(default_factory=BuildRecipe)
    harness: HarnessSpec = field(default_factory=HarnessSpec)
    authorisation: Optional[Authorisation] = None
    corpus_ids: List[str] = field(default_factory=list)
    instrumented: bool = False
    instrumentation: str = InstrumentationKind.NONE.value
    sanitizers_enabled: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: utc_string())
    updated_at: str = field(default_factory=lambda: utc_string())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.binary_path = normalize_path(self.binary_path) if self.binary_path else ""
        self.source_root = normalize_path(self.source_root) if self.source_root else ""
        if not self.name:
            self.name = os.path.basename(self.binary_path or self.source_root) or self.id
        for attribute, enum_cls in (
            ("kind", TargetKind), ("language", Language), ("architecture", Architecture),
            ("operating_system", OperatingSystem), ("instrumentation", InstrumentationKind),
        ):
            try:
                setattr(self, attribute, str(enum_cls.coerce(getattr(self, attribute)).value))
            except Exception:
                pass
        cleaned: List[str] = []
        for sanitizer in self.sanitizers_enabled:
            try:
                cleaned.append(str(SanitizerKind.coerce(sanitizer).value))
            except Exception:
                raise InvalidValueError(f"unknown sanitizer '{sanitizer}'", details={"allowed": SanitizerKind.tokens()})
        self.sanitizers_enabled = list(dict.fromkeys(cleaned))
        self.tags = list(dict.fromkeys(_slug_token(t) for t in self.tags if str(t).strip()))

    @property
    def authorized(self) -> bool:
        return bool(self.authorisation and self.authorisation.valid)

    def require_authorization(self, operation: str = "fuzz") -> Authorisation:
        return require_authorization(self, operation=operation)

    @property
    def exists(self) -> bool:
        path = self.binary_path or self.source_root
        return bool(path) and os.path.exists(path)

    def refresh_identity(self) -> None:
        """Re-derive language/architecture facts from the filesystem (best effort)."""
        if self.source_root and os.path.isdir(self.source_root):
            sources: List[str] = []
            for dirpath, _dirs, filenames in os.walk(self.source_root):
                for filename in filenames:
                    if is_source_file(filename):
                        sources.append(os.path.join(dirpath, filename))
                if len(sources) > 4000:
                    break
            if sources:
                self.language = str(Language.detect(sources).value)
        if self.binary_path and os.path.isfile(self.binary_path):
            if self.architecture == Architecture.UNKNOWN.value:
                self.architecture = str(Architecture.host().value)
            if self.operating_system == OperatingSystem.UNKNOWN.value:
                self.operating_system = str(OperatingSystem.host().value)
        self.updated_at = utc_string()

    def summary(self) -> str:
        flags = ",".join(self.sanitizers_enabled) or "no-sanitizers"
        return (
            f"{self.name} [{self.kind}] arch={self.architecture} lang={self.language} "
            f"instr={self.instrumentation} sanitizers={flags} "
            f"authorized={'yes' if self.authorized else 'NO'}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "binary_path": self.binary_path,
            "source_root": self.source_root, "kind": self.kind, "language": self.language,
            "architecture": self.architecture, "operating_system": self.operating_system,
            "upstream_project": self.upstream_project, "upstream_url": self.upstream_url,
            "version": self.version,
            "build_recipe": self.build_recipe.to_dict(), "harness": self.harness.to_dict(),
            "authorisation": self.authorisation.to_dict() if self.authorisation else None,
            "corpus_ids": list(self.corpus_ids), "instrumented": self.instrumented,
            "instrumentation": self.instrumentation, "sanitizers_enabled": list(self.sanitizers_enabled),
            "tags": list(self.tags), "created_at": self.created_at, "updated_at": self.updated_at,
            "metadata": dict(self.metadata), "exists": self.exists, "authorized": self.authorized,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Target":
        simple = {f.name for f in fields(cls)} - {"build_recipe", "harness", "authorisation"}
        recipe = payload.get("build_recipe")
        harness = payload.get("harness")
        auth = payload.get("authorisation")
        return cls(
            build_recipe=BuildRecipe.from_dict(recipe) if isinstance(recipe, Mapping) else BuildRecipe(),
            harness=HarnessSpec.from_dict(harness) if isinstance(harness, Mapping) else HarnessSpec(),
            authorisation=Authorisation.from_dict(auth) if isinstance(auth, Mapping) else None,
            **{k: v for k, v in payload.items() if k in simple},  # type: ignore[arg-type]
        )


# ===========================================================================
# crashes
# ===========================================================================


@dataclass
class Crash:
    """A single observed crash instance plus its analysis state."""

    id: str = field(default_factory=lambda: generate_prefixed_id("crash"))
    campaign_id: Optional[str] = None
    target_id: Optional[str] = None
    target_name: str = ""
    executable: str = ""
    engine: str = ""
    sanitizer: str = SanitizerKind.NONE.value
    crash_class: str = CrashClass.UNKNOWN.value
    state: str = CrashState.NEW.value
    severity: str = Severity.MODERATE.value
    confidence: str = Confidence.UNKNOWN.value
    input_path: str = ""
    input_hash: str = ""
    input_size: int = 0
    signal: Optional[SignalInfo] = None
    memory_access: Optional[MemoryAccess] = None
    location: CrashLocation = field(default_factory=CrashLocation)
    stack_trace: StackTrace = field(default_factory=StackTrace)
    sanitizer_report: Optional[SanitizerReport] = None
    fingerprint: Optional[Fingerprint] = None
    duplicate_of: Optional[str] = None
    occurrence_count: int = 1
    first_seen_at: str = field(default_factory=lambda: utc_string())
    last_seen_at: str = field(default_factory=lambda: utc_string())
    exit_code: Optional[int] = None
    runtime_ms: Optional[float] = None
    reproducer_path: Optional[str] = None
    minimized_path: Optional[str] = None
    finding_id: Optional[str] = None
    triaged_by: str = ""
    notes: str = ""
    labels: List[str] = field(default_factory=list)
    raw_log_path: Optional[str] = None

    def __post_init__(self) -> None:
        self.input_path = normalize_path(self.input_path) if self.input_path else ""
        self.executable = normalize_path(self.executable) if self.executable else ""
        self.reproducer_path = normalize_path(self.reproducer_path) if self.reproducer_path else None
        self.minimized_path = normalize_path(self.minimized_path) if self.minimized_path else None
        self.raw_log_path = normalize_path(self.raw_log_path) if self.raw_log_path else None
        try:
            self.crash_class = str(CrashClass.coerce(self.crash_class).value)
        except Exception:
            self.crash_class = CrashClass.UNKNOWN.value
        try:
            self.sanitizer = str(SanitizerKind.coerce(self.sanitizer).value)
        except Exception:
            self.sanitizer = SanitizerKind.NONE.value
        try:
            self.state = str(CrashState.coerce(self.state).value)
        except Exception:
            self.state = CrashState.NEW.value
        try:
            self.severity = str(Severity.coerce(self.severity).value)
        except Exception:
            self.severity = severity_from_crash_class(self.crash_class).value
        try:
            self.confidence = str(Confidence.coerce(self.confidence).value)
        except Exception:
            self.confidence = Confidence.UNKNOWN.value
        if int(self.input_size) < 0:
            raise InvalidValueError("crash input size cannot be negative")
        if int(self.occurrence_count) < 1:
            object.__setattr__(self, "occurrence_count", 1)
        self.labels = list(dict.fromkeys(_slug_token(t) for t in self.labels if str(t).strip()))

    def stack_signature(self, depth: int = 4) -> str:
        return self.stack_trace.signature(depth=depth)

    def compute_fingerprint(self, *, depth: int = 4) -> Fingerprint:
        self.fingerprint = fingerprint_of(self, depth=depth)
        return self.fingerprint

    @property
    def fingerprint_digest(self) -> str:
        if self.fingerprint is None:
            self.compute_fingerprint()
        return self.fingerprint.digest if self.fingerprint else ""

    def classify(self, crash_class: Any, *, confidence: Any = None, note: str = "") -> "Crash":
        try:
            resolved = CrashClass.coerce(crash_class)
        except Exception as exc:
            raise CrashClassificationError(f"cannot classify crash as '{crash_class}'", component="core.models") from exc
        self.crash_class = str(resolved.value)
        if confidence is not None:
            self.confidence = str(Confidence.coerce(confidence).value)
        elif self.confidence == Confidence.UNKNOWN.value:
            self.confidence = Confidence.MEDIUM.value
        self.severity = str(resolved.typical_severity().value)
        if note:
            self.notes = (self.notes + " | " if self.notes else "") + note
        if self.state == CrashState.NEW.value:
            self.state = CrashState.CLASSIFIED.value
        return self

    def mark_duplicate(self, other: "Crash") -> "Crash":
        if other.id == self.id:
            raise InvalidValueError("a crash cannot be its own duplicate")
        self.duplicate_of = other.id
        self.state = CrashState.DUPLICATE.value
        other.occurrence_count = max(1, int(other.occurrence_count)) + 1
        other.last_seen_at = utc_string()
        return self

    def touch(self) -> "Crash":
        self.last_seen_at = utc_string()
        self.occurrence_count = int(self.occurrence_count) + 1
        return self

    def derive_severity(self, *, factors: Optional[Mapping[str, Any]] = None) -> Severity:
        try:
            self.severity = str(derive_severity(self, factors=factors).value)
        except SeverityAssessmentError:
            raise
        return Severity.coerce(self.severity)

    def headline(self) -> str:
        report = self.sanitizer_report
        if report and report.headline:
            return report.headline
        label = CRASH_CLASS_LABELS.get(self.crash_class, str(self.crash_class).replace("-", " ").title())
        subject = self.target_name or os.path.basename(self.executable) or "target"
        return f"{label} in {subject}"

    def timeline(self) -> TimestampRange:
        return TimestampRange(parse_timestamp(self.first_seen_at) or now_utc(),
                              parse_timestamp(self.last_seen_at) or now_utc())

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id, "campaign_id": self.campaign_id, "target_id": self.target_id,
            "target_name": self.target_name, "executable": self.executable, "engine": self.engine,
            "sanitizer": self.sanitizer, "crash_class": self.crash_class, "state": self.state,
            "severity": self.severity, "confidence": self.confidence, "input_path": self.input_path,
            "input_hash": self.input_hash, "input_size": self.input_size,
            "signal": self.signal.to_dict() if self.signal else None,
            "memory_access": self.memory_access.to_dict() if self.memory_access else None,
            "location": self.location.to_dict(), "stack_trace": self.stack_trace.to_dict(),
            "sanitizer_report": self.sanitizer_report.to_dict() if self.sanitizer_report else None,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "duplicate_of": self.duplicate_of, "occurrence_count": self.occurrence_count,
            "first_seen_at": self.first_seen_at, "last_seen_at": self.last_seen_at,
            "exit_code": self.exit_code, "runtime_ms": self.runtime_ms,
            "reproducer_path": self.reproducer_path, "minimized_path": self.minimized_path,
            "finding_id": self.finding_id, "triaged_by": self.triaged_by, "notes": self.notes,
            "labels": list(self.labels), "raw_log_path": self.raw_log_path,
            "headline": self.headline(), "stack_signature": self.stack_signature(),
        }
        return {k: v for k, v in payload.items() if v not in (None, "", [], {})}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Crash":
        simple = {f.name for f in fields(cls)} - {
            "signal", "memory_access", "location", "stack_trace", "sanitizer_report", "fingerprint",
        }
        signal = payload.get("signal")
        access = payload.get("memory_access")
        location = payload.get("location")
        trace = payload.get("stack_trace")
        report = payload.get("sanitizer_report")
        finger = payload.get("fingerprint")
        return cls(
            **{k: v for k, v in payload.items() if k in simple},  # type: ignore[arg-type]
            signal=SignalInfo(**{kk: vv for kk, vv in signal.items() if kk in {f.name for f in fields(SignalInfo)}}) if isinstance(signal, Mapping) else None,
            memory_access=MemoryAccess(**{kk: vv for kk, vv in access.items() if kk in {f.name for f in fields(MemoryAccess)}}) if isinstance(access, Mapping) else None,
            location=CrashLocation(**{kk: vv for kk, vv in location.items() if kk in {f.name for f in fields(CrashLocation)}}) if isinstance(location, Mapping) else CrashLocation(),
            stack_trace=StackTrace.from_dict(trace) if isinstance(trace, Mapping) else StackTrace(),
            sanitizer_report=SanitizerReport.from_dict(report) if isinstance(report, Mapping) else None,
            fingerprint=Fingerprint.from_dict(finger) if isinstance(finger, Mapping) else None,
        )


def derive_severity(crash: Any, *, factors: Optional[Mapping[str, Any]] = None) -> Severity:
    """Derive a severity from crash semantics.

    Inputs are limited to *defensive* signals: crash class, access direction,
    reproducibility rate and sanitizer origin.  No exploitability scoring is
    performed — that would cross the project's security boundary.
    """
    if isinstance(crash, Mapping):
        crash_class = crash.get("crash_class", CrashClass.UNKNOWN.value)
        access = crash.get("memory_access")
        access_type = access.get("access_type") if isinstance(access, Mapping) else crash.get("access_type")
        reproducible = crash.get("reproducible")
        sanitizer = crash.get("sanitizer", "")
    elif isinstance(crash, Crash):
        crash_class = crash.crash_class
        access_type = crash.memory_access.access_type if crash.memory_access else None
        reproducible = bool(crash.reproducer_path) or None
        sanitizer = crash.sanitizer
    else:
        raise SeverityAssessmentError(f"cannot derive severity from {type(crash).__name__}", component="core.models")

    try:
        resolved_class = CrashClass.coerce(crash_class)
    except Exception:
        resolved_class = CrashClass.UNKNOWN
    base = severity_from_crash_class(resolved_class)
    score = Severity.rank(base)
    extra: Dict[str, Any] = dict(factors or {})

    if access_type == MemoryAccessType.WRITE.value and Severity.rank(base) <= Severity.MODERATE.rank():
        score += 1
    if str(sanitizer) == SanitizerKind.TSAN.value and score > Severity.MODERATE.rank():
        score -= 1
    if reproducible is False:
        score -= 1
    if extra.get("wide_controlled_region") and score < 5:
        score += 1
    if extra.get("affects_service_boundary") and score < 5:
        score += 1
    if extra.get("memory_corruption") is False:
        score -= 1
    rate = extra.get("reproducibility")
    if isinstance(rate, (int, float)):
        if rate >= 0.9 and score < 5:
            score += 1
        elif rate <= 0.1:
            score -= 1

    ladder = [Severity.NONE, Severity.INFORMATIONAL, Severity.LOW, Severity.MODERATE, Severity.HIGH, Severity.CRITICAL]
    index = max(0, min(len(ladder) - 1, int(score)))
    return ladder[index]


def confidence_from_votes(votes: Sequence[Tuple[Any, float]]) -> Confidence:
    """Weighted vote aggregation used by classification/de-duplication layers."""
    if not votes:
        return Confidence.UNKNOWN
    tally: Dict[Any, float] = defaultdict(float)
    total = 0.0
    for option, weight in votes:
        value = float(weight)
        if value < 0:
            raise InvalidValueError("vote weights must be non-negative")
        tally[option] += value
        total += value
    if total <= 0:
        return Confidence.UNKNOWN
    best = max(tally.items(), key=lambda pair: pair[1])
    return Confidence.from_score(best[1] / total)


@dataclass
class Vote:
    """A single weighted opinion, used by classifiers and de-duplicators."""

    option: Any
    weight: float = 1.0
    rationale: str = ""

    def __post_init__(self) -> None:
        if float(self.weight) < 0:
            raise InvalidValueError("vote weight must be non-negative")

    def to_tuple(self) -> Tuple[Any, float]:
        return (self.option, float(self.weight))


@dataclass
class DedupDecisionDetail:
    """Explanation of why two crashes were (or were not) merged."""

    decision: str = DedupDecision.UNCERTAIN.value
    canonical_id: Optional[str] = None
    similarity: float = 0.0
    matched_components: List[str] = field(default_factory=list)
    differing_components: List[str] = field(default_factory=list)
    method: str = "fingerprint-exact"
    explained_at: str = field(default_factory=lambda: utc_string())

    def __post_init__(self) -> None:
        try:
            self.decision = str(DedupDecision.coerce(self.decision).value)
        except Exception:
            self.decision = DedupDecision.UNCERTAIN.value
        if not 0.0 <= float(self.similarity) <= 1.0:
            raise InvalidValueError("similarity must be within [0, 1]")

    @property
    def is_merge(self) -> bool:
        return self.decision in {DedupDecision.DUPLICATE.value, DedupDecision.PROBABLE_DUPLICATE.value}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ===========================================================================
# metrics / campaigns
# ===========================================================================


@dataclass
class RunMetrics:
    """Execution counters.

    Every field defaults to ``None`` meaning *"not measured"*.  Values must come
    from a real engine/tool output — KMCS never invents statistics.
    """

    executions: Optional[int] = None
    execs_per_second: Optional[float] = None
    unique_crashes: Optional[int] = None
    saved_crashes: Optional[int] = None
    hangs: Optional[int] = None
    coverage_edges: Optional[int] = None
    coverage_percent: Optional[float] = None
    corpus_size: Optional[int] = None
    queue_items: Optional[int] = None
    cpu_affinity: Optional[str] = None
    uptime_seconds: Optional[float] = None
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    source: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for name in ("executions", "unique_crashes", "saved_crashes", "hangs", "coverage_edges", "corpus_size", "queue_items"):
            value = getattr(self, name)
            if value is not None and int(value) < 0:
                raise InvalidValueError(f"metric '{name}' cannot be negative (got {value})")
        for name in ("execs_per_second", "coverage_percent", "uptime_seconds"):
            value = getattr(self, name)
            if value is not None and float(value) < 0:
                raise InvalidValueError(f"metric '{name}' cannot be negative (got {value})")
        if self.coverage_percent is not None and not 0.0 <= float(self.coverage_percent) <= 100.0:
            raise InvalidValueError(f"coverage_percent must be within [0, 100] (got {self.coverage_percent})")

    @property
    def measured(self) -> bool:
        return any(
            getattr(self, name) is not None
            for name in ("executions", "execs_per_second", "coverage_edges", "unique_crashes", "corpus_size")
        )

    def merge(self, other: "RunMetrics") -> "RunMetrics":
        """Overlay newer measurements onto this snapshot (only non-``None`` values)."""
        for f in fields(self):
            value = getattr(other, f.name)
            if value is None:
                continue
            if f.name == "warnings":
                self.warnings = list(dict.fromkeys([*self.warnings, *(value or [])]))
            else:
                setattr(self, f.name, value)
        self.updated_at = utc_string()
        return self

    def delta_since(self, previous: "RunMetrics") -> Dict[str, float]:
        out: Dict[str, float] = {}
        for name in ("executions", "unique_crashes", "hangs", "coverage_edges", "corpus_size", "queue_items"):
            mine, theirs = getattr(self, name), getattr(previous, name)
            if mine is not None and theirs is not None:
                out[name] = float(mine) - float(theirs)
        return out

    def rate_estimate(self, window_seconds: Optional[float]) -> Optional[float]:
        if not window_seconds or self.executions is None:
            return None
        return round(float(self.executions) / float(window_seconds), 2)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], "")}


@dataclass
class TelemetrySample:
    """One telemetry tick emitted by a running campaign."""

    campaign_id: str = ""
    worker_id: str = ""
    sequence: int = 0
    captured_at: str = field(default_factory=lambda: utc_string())
    metrics: RunMetrics = field(default_factory=RunMetrics)
    resource: ResourceUsage = field(default_factory=ResourceUsage)
    engine_state: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id, "worker_id": self.worker_id, "sequence": self.sequence,
            "captured_at": self.captured_at, "metrics": self.metrics.to_dict(),
            "resource": self.resource.to_dict(), "engine_state": self.engine_state, "notes": self.notes,
        }


@dataclass
class HealthSnapshot:
    """Overall health of the KMCS installation (honest about what is missing)."""

    ok: bool = True
    checked_at: str = field(default_factory=lambda: utc_string())
    checks: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    disk_free_bytes: Optional[int] = None
    python_version: str = platform.python_version()
    platform: str = f"{platform.system()}-{platform.release()}"

    def add(self, name: str, passed: bool, detail: str = "", *, fatal: bool = False) -> None:
        self.checks.append({"name": name, "passed": bool(passed), "detail": detail, "fatal": bool(fatal)})
        if not passed:
            (self.errors if fatal else self.warnings).append(f"{name}: {detail or 'failed'}")
            if fatal:
                self.ok = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CampaignMetrics:
    runs: int = 0
    total_executions: Optional[int] = None
    total_execs_per_second: Optional[float] = None
    crashes_found: int = 0
    unique_crashes: int = 0
    duplicates: int = 0
    hangs: int = 0
    findings_open: int = 0
    findings_closed: int = 0
    coverage_edges: Optional[int] = None
    corpus_grew_by: Optional[int] = None
    wall_clock_seconds: float = 0.0
    cpu_seconds: Optional[float] = None
    peak_memory_bytes: Optional[int] = None
    disk_bytes_used: Optional[int] = None
    samples: int = 0
    last_sample_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, 0, "", [], {})}

    def record_sample(self, metrics: RunMetrics, *, wall_clock_seconds: float = 0.0) -> "CampaignMetrics":
        """Fold one telemetry sample in.  Unmeasured fields stay unmeasured."""
        self.samples += 1
        self.last_sample_at = utc_string()
        if metrics.executions is not None:
            self.total_executions = (self.total_executions or 0) + int(metrics.executions)
        if metrics.execs_per_second is not None:
            self.total_execs_per_second = round((self.total_execs_per_second or 0.0) + float(metrics.execs_per_second), 2)
        if metrics.unique_crashes is not None:
            self.crashes_found = max(self.crashes_found, int(metrics.unique_crashes))
        if metrics.hangs is not None:
            self.hangs = max(self.hangs, int(metrics.hangs))
        if metrics.coverage_edges is not None:
            self.coverage_edges = max(self.coverage_edges or 0, int(metrics.coverage_edges))
        if metrics.corpus_size is not None:
            self.corpus_grew_by = int(metrics.corpus_size)
        self.wall_clock_seconds = round(max(self.wall_clock_seconds, float(wall_clock_seconds)), 3)
        return self


@dataclass
class Campaign:
    """A managed fuzzing session against one authorised target."""

    id: str = field(default_factory=lambda: generate_prefixed_id("camp"))
    name: str = ""
    target_id: str = ""
    target_name: str = ""
    engine: str = EngineKind.AFLPP.value
    status: str = RunStatus.PENDING.value
    corpus_ids: List[str] = field(default_factory=list)
    worker_count: int = 1
    cpu_affinity: List[int] = field(default_factory=list)
    max_runtime_seconds: Optional[float] = None
    max_input_bytes: int = 1 << 20
    sanitizers: List[str] = field(default_factory=list)
    crash_dir: str = ""
    work_dir: str = ""
    log_path: str = ""
    metrics: CampaignMetrics = field(default_factory=CampaignMetrics)
    created_at: str = field(default_factory=lambda: utc_string())
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    owner: str = ""
    notes: str = ""
    labels: List[str] = field(default_factory=list)
    engine_session_id: Optional[str] = None

    def __post_init__(self) -> None:
        self.name = self.name or f"campaign-{self.id[-6:]}"
        for attribute, enum_cls in (("engine", EngineKind), ("status", RunStatus)):
            try:
                setattr(self, attribute, str(enum_cls.coerce(getattr(self, attribute)).value))
            except Exception:
                pass
        if int(self.worker_count) < 1:
            raise InvalidValueError(f"worker_count must be >= 1 (got {self.worker_count})")
        if self.max_runtime_seconds is not None and float(self.max_runtime_seconds) <= 0:
            raise InvalidValueError("max_runtime_seconds must be positive when provided")
        self.crash_dir = normalize_path(self.crash_dir) if self.crash_dir else ""
        self.work_dir = normalize_path(self.work_dir) if self.work_dir else ""
        self.log_path = normalize_path(self.log_path) if self.log_path else ""
        self.labels = list(dict.fromkeys(_slug_token(t) for t in self.labels if str(t).strip()))

    @property
    def running(self) -> bool:
        return self.status in {RunStatus.RUNNING.value, RunStatus.PREPARING.value, RunStatus.STOPPING.value}

    @property
    def finished(self) -> bool:
        try:
            return RunStatus.coerce(self.status).terminal
        except Exception:
            return False

    def elapsed_seconds(self) -> float:
        start = parse_timestamp(self.started_at)
        if not start:
            return 0.0
        end = parse_timestamp(self.finished_at) or now_utc()
        return max(0.0, (end - start).total_seconds())

    def duration_range(self) -> Optional[TimestampRange]:
        start = parse_timestamp(self.started_at)
        if not start:
            return None
        return TimestampRange(start, parse_timestamp(self.finished_at) or now_utc())

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["metrics"] = self.metrics.to_dict()
        payload["elapsed_seconds"] = round(self.elapsed_seconds(), 3)
        payload["running"] = self.running
        payload["finished"] = self.finished
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Campaign":
        simple = {f.name for f in fields(cls)} - {"metrics"}
        metrics_payload = payload.get("metrics")
        metrics = (
            CampaignMetrics(**{k: v for k, v in metrics_payload.items() if k in {f.name for f in fields(CampaignMetrics)}})
            if isinstance(metrics_payload, Mapping) else CampaignMetrics()
        )
        return cls(metrics=metrics, **{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]


# ===========================================================================
# reproduction / minimization / findings
# ===========================================================================


@dataclass
class ReproductionResult:
    """Outcome of replaying a crash input against the target."""

    attempt: int = 1
    outcome: str = ReproductionOutcome.PENDING.value
    reproduced_count: int = 0
    total_attempts: int = 0
    exit_codes: List[int] = field(default_factory=list)
    signals: List[int] = field(default_factory=list)
    runtime_ms: List[float] = field(default_factory=list)
    crash_class_observed: Optional[str] = None
    fingerprint_observed: Optional[str] = None
    environment_hash: Optional[str] = None
    command: List[str] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    started_at: str = field(default_factory=lambda: utc_string())
    finished_at: Optional[str] = None
    error: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
        try:
            self.outcome = str(ReproductionOutcome.coerce(self.outcome).value)
        except Exception:
            self.outcome = ReproductionOutcome.PENDING.value
        if int(self.total_attempts) < 0:
            raise InvalidValueError("total_attempts cannot be negative")
        if int(self.reproduced_count) > int(self.total_attempts):
            raise InvalidValueError(
                f"reproduced_count ({self.reproduced_count}) exceeds total_attempts ({self.total_attempts})",
                details={"hint": "counters must reflect real executions only"},
            )

    @property
    def rate(self) -> float:
        if not self.total_attempts:
            return 0.0
        return round(self.reproduced_count / self.total_attempts, 4)

    @property
    def consistent(self) -> bool:
        return self.total_attempts > 0 and self.reproduced_count == self.total_attempts

    def observe(
        self, *, crashed: bool, exit_code: Optional[int] = None, signal_number: Optional[int] = None,
        runtime_ms: Optional[float] = None,
    ) -> "ReproductionResult":
        """Record one *actual* execution result."""
        self.total_attempts += 1
        if crashed:
            self.reproduced_count += 1
        if exit_code is not None:
            self.exit_codes.append(int(exit_code))
        if signal_number is not None:
            self.signals.append(int(signal_number))
        if runtime_ms is not None:
            self.runtime_ms.append(float(runtime_ms))
        self.outcome = self._infer_outcome()
        return self

    def _infer_outcome(self) -> str:
        if self.error:
            return ReproductionOutcome.ERROR.value
        if self.total_attempts == 0:
            return ReproductionOutcome.PENDING.value
        rate = self.rate
        if rate >= 0.999:
            return ReproductionOutcome.REPRODUCED.value
        if rate == 0.0:
            return ReproductionOutcome.NOT_REPRODUCED.value
        return ReproductionOutcome.INTERMITTENT.value

    def finalize(self) -> "ReproductionResult":
        self.finished_at = utc_string()
        self.outcome = self._infer_outcome()
        return self

    def mean_runtime_ms(self) -> Optional[float]:
        return round(sum(self.runtime_ms) / len(self.runtime_ms), 2) if self.runtime_ms else None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["rate"] = self.rate
        payload["consistent"] = self.consistent
        payload["mean_runtime_ms"] = self.mean_runtime_ms()
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ReproductionResult":
        simple = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]


@dataclass
class MinimizationResult:
    original_bytes: int = 0
    minimized_bytes: Optional[int] = None
    original_path: str = ""
    minimized_path: str = ""
    iterations: int = 0
    reduction_ratio: Optional[float] = None
    still_crashes: Optional[bool] = None
    same_fingerprint: Optional[bool] = None
    tool: str = ""
    started_at: str = field(default_factory=lambda: utc_string())
    finished_at: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
        if int(self.original_bytes) < 0:
            raise InvalidValueError("original_bytes cannot be negative")
        self.original_path = normalize_path(self.original_path) if self.original_path else ""
        self.minimized_path = normalize_path(self.minimized_path) if self.minimized_path else ""
        if self.minimized_bytes is not None:
            if int(self.minimized_bytes) < 0:
                raise InvalidValueError("minimized_bytes cannot be negative")
            if self.original_bytes and self.minimized_bytes > self.original_bytes:
                raise InvalidValueError("minimized size cannot exceed original size")
            self.reduction_ratio = round(1.0 - (float(self.minimized_bytes) / float(self.original_bytes)), 4) if self.original_bytes else None

    def finalize(self) -> "MinimizationResult":
        self.finished_at = utc_string()
        return self

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    """One piece of supporting material for a finding (log excerpt, hash, …)."""

    id: str = field(default_factory=lambda: generate_prefixed_id("ev"))
    kind: str = "artifact"
    summary: str = ""
    path: Optional[str] = None
    content: Optional[str] = None
    content_hash: Optional[str] = None
    produced_by: str = ""
    captured_at: str = field(default_factory=lambda: utc_string())
    redacted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    KINDS: ClassVar[Tuple[str, ...]] = (
        "sanitizer-log", "stack-trace", "input-file", "minimized-input", "reproducer-run",
        "coverage-report", "build-log", "fuzzer-stats", "command-line", "environment",
        "diff", "note", "artifact",
    )

    def __post_init__(self) -> None:
        if self.kind not in self.KINDS:
            raise InvalidValueError(f"unknown evidence kind '{self.kind}'", details={"allowed": list(self.KINDS)})
        self.path = normalize_path(self.path) if self.path else None
        if self.content is not None and not self.content_hash:
            self.content_hash = sha256_bytes(str(self.content).encode("utf-8", "replace"))

    def excerpt(self, limit: int = 2000) -> str:
        text = self.content or ""
        if not text and self.path and os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
                    text = handle.read(max(0, int(limit)) * 2)
            except OSError:
                text = ""
        return text[: max(0, int(limit))]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["excerpt"] = self.excerpt(600)
        return {k: v for k, v in payload.items() if v not in (None, "", {}, [])}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Evidence":
        simple = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]


@dataclass
class RootCauseHint:
    """Non-exploitative guidance towards *fixing* the defect."""

    title: str = ""
    detail: str = ""
    suggested_action: str = ""
    references: List[str] = field(default_factory=list)
    confidence: str = Confidence.MEDIUM.value
    code_location: Optional[str] = None

    def __post_init__(self) -> None:
        try:
            self.confidence = str(Confidence.coerce(self.confidence).value)
        except Exception:
            self.confidence = Confidence.MEDIUM.value

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", [])}


@dataclass
class Reproducer:
    """Self-contained *reproduction* instructions for a finding."""

    input_path: str = ""
    input_hash: str = ""
    minimized_path: Optional[str] = None
    command: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    sanitizer_options: Dict[str, str] = field(default_factory=dict)
    expected_exit_code: Optional[int] = None
    expected_signal: Optional[int] = None
    expected_output_pattern: Optional[str] = None
    attempts_required: int = 1
    success_rate: Optional[float] = None
    last_result: Optional[ReproductionResult] = None
    regression_test_id: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
        self.input_path = normalize_path(self.input_path) if self.input_path else ""
        self.minimized_path = normalize_path(self.minimized_path) if self.minimized_path else None
        if int(self.attempts_required) < 1:
            raise InvalidValueError("attempts_required must be >= 1")
        if self.success_rate is not None and not 0.0 <= float(self.success_rate) <= 1.0:
            raise InvalidValueError("success_rate must be within [0, 1]")

    @property
    def best_input(self) -> str:
        return self.minimized_path or self.input_path

    def render_command(self, input_path: Optional[Any] = None) -> str:
        target = normalize_path(input_path or self.best_input)
        parts = [part.replace("@@", target) if "@@" in part else part for part in self.command]
        if self.command and not any("@@" in part for part in self.command):
            parts = parts + [target]
        return " ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["last_result"] = self.last_result.to_dict() if self.last_result else None
        payload["rendered_command"] = self.render_command()
        return {k: v for k, v in payload.items() if v not in (None, "", [], {})}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Reproducer":
        simple = {f.name for f in fields(cls)} - {"last_result"}
        last = payload.get("last_result")
        return cls(
            last_result=ReproductionResult.from_dict(last) if isinstance(last, Mapping) else None,
            **{k: v for k, v in payload.items() if k in simple},  # type: ignore[arg-type]
        )


_FINDING_TRANSITIONS: Dict[FindingState, Set[FindingState]] = {
    FindingState.CANDIDATE: {FindingState.CONFIRMED, FindingState.REJECTED, FindingState.DUPLICATED, FindingState.ARCHIVED},
    FindingState.CONFIRMED: {FindingState.ANALYZED, FindingState.REJECTED, FindingState.DUPLICATED, FindingState.ARCHIVED},
    FindingState.ANALYZED: {FindingState.DOCUMENTED, FindingState.REJECTED, FindingState.ARCHIVED},
    FindingState.DOCUMENTED: {FindingState.DISCLOSED, FindingState.PATCHED, FindingState.ARCHIVED},
    FindingState.DISCLOSED: {FindingState.PATCHED, FindingState.VERIFIED_FIXED, FindingState.ARCHIVED},
    FindingState.PATCHED: {FindingState.VERIFIED_FIXED, FindingState.REJECTED, FindingState.ARCHIVED},
    FindingState.VERIFIED_FIXED: {FindingState.ARCHIVED},
    FindingState.REJECTED: {FindingState.CANDIDATE, FindingState.ARCHIVED},
    FindingState.DUPLICATED: {FindingState.ARCHIVED, FindingState.CANDIDATE},
    FindingState.ARCHIVED: {FindingState.CANDIDATE},
}


@dataclass
class Finding:
    """The structured security finding produced from one or more crashes."""

    id: str = field(default_factory=lambda: generate_prefixed_id("find"))
    title: str = ""
    summary: str = ""
    description: str = ""
    target_id: str = ""
    target_name: str = ""
    campaign_ids: List[str] = field(default_factory=list)
    crash_ids: List[str] = field(default_factory=list)
    canonical_crash_id: Optional[str] = None
    crash_class: str = CrashClass.UNKNOWN.value
    severity: str = Severity.MODERATE.value
    confidence: str = Confidence.MEDIUM.value
    state: str = FindingState.CANDIDATE.value
    fingerprint: Optional[Fingerprint] = None
    location: CrashLocation = field(default_factory=CrashLocation)
    stack_signature: str = ""
    root_cause_hints: List[RootCauseHint] = field(default_factory=list)
    trigger_conditions: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_in: Optional[str] = None
    reproducer: Optional[Reproducer] = None
    minimization: Optional[MinimizationResult] = None
    evidence: List[Evidence] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    assignee: str = ""
    discovered_at: str = field(default_factory=lambda: utc_string())
    confirmed_at: Optional[str] = None
    reported_at: Optional[str] = None
    closed_at: Optional[str] = None
    updated_at: str = field(default_factory=lambda: utc_string())
    disclosure_notes: str = ""
    cvss_vector_hint: Optional[str] = None
    analyst: str = ""

    def __post_init__(self) -> None:
        try:
            self.crash_class = str(CrashClass.coerce(self.crash_class).value)
        except Exception:
            self.crash_class = CrashClass.UNKNOWN.value
        for attribute, enum_cls in (("severity", Severity), ("confidence", Confidence), ("state", FindingState)):
            try:
                setattr(self, attribute, str(enum_cls.coerce(getattr(self, attribute)).value))
            except Exception:
                pass
        self.title = self.title or f"{CRASH_CLASS_LABELS.get(self.crash_class, str(self.crash_class).replace('-', ' ').title())} in {self.target_name or 'target'}"
        resolved_triggers: List[str] = []
        for item in self.trigger_conditions:
            try:
                resolved_triggers.append(str(TriggerCondition.coerce(item).value))
            except Exception:
                resolved_triggers.append(TriggerCondition.UNKNOWN.value)
        self.trigger_conditions = list(dict.fromkeys(resolved_triggers))
        self.labels = list(dict.fromkeys(_slug_token(t) for t in self.labels if str(t).strip()))

    def transition(self, new_state: Any, *, actor: str = "", note: str = "") -> "Finding":
        """Move through the finding lifecycle, enforcing legal transitions."""
        target_state = FindingState.coerce(new_state)
        allowed = _FINDING_TRANSITIONS.get(FindingState.coerce(self.state), set())
        if target_state not in allowed:
            raise InvalidValueError(
                f"illegal finding transition {self.state} -> {target_state.value}",
                details={"allowed": sorted(state.value for state in allowed)},
            )
        self.state = str(target_state.value)
        self.updated_at = utc_string()
        moment = utc_string()
        if target_state is FindingState.CONFIRMED and not self.confirmed_at:
            self.confirmed_at = moment
        if target_state is FindingState.DOCUMENTED and not self.reported_at:
            self.reported_at = moment
        if target_state in {FindingState.PATCHED, FindingState.VERIFIED_FIXED, FindingState.REJECTED, FindingState.ARCHIVED}:
            self.closed_at = moment
        if actor:
            self.assignee = actor
        if note:
            self.disclosure_notes = (self.disclosure_notes + "\n" if self.disclosure_notes else "") + f"[{moment}] {note}"
        return self

    def add_evidence(self, evidence: Evidence) -> Evidence:
        self.evidence.append(evidence)
        self.updated_at = utc_string()
        return evidence

    def attach_crash(self, crash: Crash, *, canonical: bool = False) -> "Finding":
        if crash.id not in self.crash_ids:
            self.crash_ids.append(crash.id)
        if crash.campaign_id and crash.campaign_id not in self.campaign_ids:
            self.campaign_ids.append(crash.campaign_id)
        if canonical or self.canonical_crash_id is None:
            self.canonical_crash_id = crash.id
            self.crash_class = crash.crash_class
            self.location = crash.location
            self.stack_signature = crash.stack_signature()
            if crash.fingerprint is not None:
                self.fingerprint = crash.fingerprint
        self.target_id = self.target_id or (crash.target_id or "")
        self.target_name = self.target_name or (crash.target_name or os.path.basename(crash.executable))
        self.updated_at = utc_string()
        return self

    def recompute_severity(self, *, factors: Optional[Mapping[str, Any]] = None) -> Severity:
        synthetic = Crash(
            crash_class=self.crash_class,
            sanitizer=SanitizerKind.ASAN.value,
            reproducer_path=self.reproducer.best_input if self.reproducer else None,
        )
        merged: Dict[str, Any] = dict(factors or {})
        if self.reproducer is not None:
            merged.setdefault("reproducibility", self.reproducer.success_rate)
        try:
            severity = derive_severity(synthetic, factors=merged)
        except SeverityAssessmentError as exc:
            raise SeverityAssessmentError(f"cannot assess finding {self.id}: {exc}", component="core.models") from exc
        self.severity = str(severity.value)
        self.updated_at = utc_string()
        return severity

    @property
    def reproducible(self) -> Optional[bool]:
        if self.reproducer is None or self.reproducer.success_rate is None:
            return None
        return self.reproducer.success_rate > 0.0

    def headline(self) -> str:
        return f"[{Severity.coerce(self.severity).value.upper()}] {self.title}"

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id, "title": self.title, "summary": self.summary, "description": self.description,
            "target_id": self.target_id, "target_name": self.target_name,
            "campaign_ids": list(self.campaign_ids), "crash_ids": list(self.crash_ids),
            "canonical_crash_id": self.canonical_crash_id, "crash_class": self.crash_class,
            "severity": self.severity, "confidence": self.confidence, "state": self.state,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "location": self.location.to_dict(), "stack_signature": self.stack_signature,
            "root_cause_hints": [hint.to_dict() for hint in self.root_cause_hints],
            "trigger_conditions": list(self.trigger_conditions),
            "affected_versions": list(self.affected_versions), "fixed_in": self.fixed_in,
            "reproducer": self.reproducer.to_dict() if self.reproducer else None,
            "minimization": self.minimization.to_dict() if self.minimization else None,
            "evidence": [item.to_dict() for item in self.evidence],
            "references": list(self.references), "labels": list(self.labels),
            "assignee": self.assignee, "discovered_at": self.discovered_at,
            "confirmed_at": self.confirmed_at, "reported_at": self.reported_at,
            "closed_at": self.closed_at, "updated_at": self.updated_at,
            "disclosure_notes": self.disclosure_notes, "cvss_vector_hint": self.cvss_vector_hint,
            "analyst": self.analyst, "reproducible": self.reproducible, "headline": self.headline(),
        }
        return {k: v for k, v in payload.items() if v not in (None, "", [], {})}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Finding":
        simple = {f.name for f in fields(cls)} - {
            "fingerprint", "location", "root_cause_hints", "reproducer", "minimization", "evidence",
        }
        hints = [
            RootCauseHint(**{k: v for k, v in item.items() if k in {f.name for f in fields(RootCauseHint)}})
            for item in payload.get("root_cause_hints", []) if isinstance(item, Mapping)
        ]
        evidence = [Evidence.from_dict(item) for item in payload.get("evidence", []) if isinstance(item, Mapping)]
        reproducer = payload.get("reproducer")
        minimization = payload.get("minimization")
        fingerprint = payload.get("fingerprint")
        location = payload.get("location")
        return cls(
            root_cause_hints=hints, evidence=evidence,
            reproducer=Reproducer.from_dict(reproducer) if isinstance(reproducer, Mapping) else None,
            minimization=MinimizationResult(**{k: v for k, v in minimization.items() if k in {f.name for f in fields(MinimizationResult)}}) if isinstance(minimization, Mapping) else None,
            fingerprint=Fingerprint.from_dict(fingerprint) if isinstance(fingerprint, Mapping) else None,
            location=CrashLocation(**{k: v for k, v in location.items() if k in {f.name for f in fields(CrashLocation)}}) if isinstance(location, Mapping) else CrashLocation(),
            **{k: v for k, v in payload.items() if k in simple},  # type: ignore[arg-type]
        )


@dataclass
class RegressionTest:
    """A durable test guarding against reintroduction of a fixed defect."""

    id: str = field(default_factory=lambda: generate_prefixed_id("reg"))
    finding_id: str = ""
    name: str = ""
    input_path: str = ""
    input_hash: str = ""
    command: List[str] = field(default_factory=list)
    expected_signal: Optional[int] = None
    expected_exit_code: Optional[int] = None
    sanitizer: str = SanitizerKind.ASAN.value
    enabled: bool = True
    last_run_at: Optional[str] = None
    last_result: Optional[ReproductionResult] = None
    passes: int = 0
    failures: int = 0
    notes: str = ""

    def __post_init__(self) -> None:
        self.input_path = normalize_path(self.input_path) if self.input_path else ""
        self.name = self.name or f"regression-{(self.finding_id or self.id)[-8:]}"
        try:
            self.sanitizer = str(SanitizerKind.coerce(self.sanitizer).value)
        except Exception:
            self.sanitizer = SanitizerKind.ASAN.value

    @property
    def pass_rate(self) -> Optional[float]:
        total = self.passes + self.failures
        return round(self.passes / total, 4) if total else None

    def record(self, result: ReproductionResult) -> "RegressionTest":
        self.last_run_at = utc_string()
        self.last_result = result
        if result.outcome == ReproductionOutcome.NOT_REPRODUCED.value:
            self.passes += 1
        elif result.outcome in {ReproductionOutcome.REPRODUCED.value, ReproductionOutcome.INTERMITTENT.value}:
            self.failures += 1
        return self

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["last_result"] = self.last_result.to_dict() if self.last_result else None
        payload["pass_rate"] = self.pass_rate
        return {k: v for k, v in payload.items() if v not in (None, "", {}, [])}


@dataclass
class ReportRequest:
    """Parameters describing a report to be generated (implemented in phase 6)."""

    id: str = field(default_factory=lambda: generate_prefixed_id("rep"))
    title: str = "KMCS security report"
    formats: List[str] = field(default_factory=lambda: [ReportFormat.JSON.value, ReportFormat.MARKDOWN.value])
    finding_ids: List[str] = field(default_factory=list)
    campaign_ids: List[str] = field(default_factory=list)
    include_raw_logs: bool = False
    include_stack_traces: bool = True
    include_inputs: bool = True
    max_input_bytes_inline: int = 4096
    anonymize: bool = False
    locale: str = "en"
    author: str = ""
    organization: str = ""
    generated_at: str = field(default_factory=lambda: utc_string())
    output_dir: str = ""
    template: Optional[str] = None
    styles: Dict[str, Any] = field(default_factory=dict)
    redact_sensitive: bool = True

    def __post_init__(self) -> None:
        cleaned: List[str] = []
        for fmt in self.formats:
            try:
                cleaned.append(str(ReportFormat.coerce(fmt).value))
            except Exception:
                raise InvalidValueError(f"unknown report format '{fmt}'", details={"allowed": ReportFormat.tokens()})
        self.formats = list(dict.fromkeys(cleaned)) or [ReportFormat.JSON.value]
        if int(self.max_input_bytes_inline) < 0:
            raise InvalidValueError("max_input_bytes_inline cannot be negative")
        self.output_dir = normalize_path(self.output_dir) if self.output_dir else ""

    def extensions(self) -> List[str]:
        return [ReportFormat.coerce(fmt).extension for fmt in self.formats]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ReportRequest":
        simple = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in simple})  # type: ignore[arg-type]


@dataclass
class ReportArtifact:
    request_id: str = ""
    format: str = ReportFormat.JSON.value
    path: str = ""
    bytes_written: int = 0
    content_hash: str = ""
    generated_at: str = field(default_factory=lambda: utc_string())
    sections: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.path = normalize_path(self.path) if self.path else ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EventEnvelope:
    """Wire-format event record shared between :mod:`kmcs.core.events` and storage."""

    topic: str
    payload: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: __import__("uuid").uuid4().hex)
    occurred_at: str = field(default_factory=lambda: utc_string())
    source: str = "kmcs"
    severity: str = "INFO"
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class JobRecord:
    """Serialisable mirror of a job (persisted by the database phase)."""

    job_id: str
    kind: str
    name: str = ""
    state: str = JobStateName.CREATED.value
    priority: int = int(Priority.NORMAL)
    definition: Dict[str, Any] = field(default_factory=dict)
    result: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None
    attempts: int = 0
    dependencies: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: utc_string())
    updated_at: str = field(default_factory=lambda: utc_string())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaskSpec:
    """Declarative description of a unit of work handed to :mod:`kmcs.core.jobs`."""

    name: str = ""
    kind: str = "generic"
    callable_ref: str = ""
    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    priority: int = int(Priority.NORMAL)
    timeout_seconds: Optional[float] = None
    retry: Dict[str, Any] = field(default_factory=dict)
    requires: List[str] = field(default_factory=list)
    resources: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self) -> None:
        self.name = self.name or _slug_token(self.kind)
        if float(self.priority) < 0:
            raise InvalidValueError("task priority cannot be negative")
        if self.timeout_seconds is not None and float(self.timeout_seconds) <= 0:
            raise InvalidValueError("task timeout must be positive when provided")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ===========================================================================
# taxonomy helpers & registration
# ===========================================================================


def crash_class_for_sanitizer(sanitizer: Any = "", message: str = "") -> CrashClass:
    """Map a sanitizer diagnostic string to a crash class (table-driven)."""
    text = str(message or "").lower()
    try:
        kind = SanitizerKind.coerce(sanitizer) if sanitizer else SanitizerKind.NONE
    except Exception:
        kind = SanitizerKind.NONE
    table = (
        ("heap-buffer-overflow", CrashClass.HEAP_BUFFER_OVERFLOW),
        ("heap-use-after-free", CrashClass.USE_AFTER_FREE),
        ("use-after-free", CrashClass.USE_AFTER_FREE),
        ("stack-buffer-overflow", CrashClass.STACK_BUFFER_OVERFLOW),
        ("stack-buffer-underflow", CrashClass.STACK_BUFFER_UNDERFLOW),
        ("global-buffer-overflow", CrashClass.GLOBAL_BUFFER_OVERFLOW),
        ("stack-use-after-return", CrashClass.USE_AFTER_RETURN),
        ("use-after-return", CrashClass.USE_AFTER_RETURN),
        ("use-after-scope", CrashClass.USE_AFTER_SCOPE),
        ("attempting double-free", CrashClass.DOUBLE_FREE),
        ("double-free", CrashClass.DOUBLE_FREE),
        ("freed through wrong allocator", CrashClass.INVALID_FREE),
        ("alloc-dealloc-mismatch", CrashClass.ALLOCATOR_MISUSE),
        ("detected memory leaks", CrashClass.MEMORY_LEAK),
        ("indirect leak", CrashClass.INDIRECT_LEAK),
        ("negative-size-param", CrashClass.OVERFLOW_ALLOC),
        ("use of uninitialised value", CrashClass.UNINITIALIZED_USE),
        ("use-of-uninitialized-value", CrashClass.UNINITIALIZED_USE),
        ("signed integer overflow", CrashClass.INTEGER_OVERFLOW),
        ("division by zero", CrashClass.DIVIDE_BY_ZERO),
        ("shift exponent", CrashClass.SIGNED_SHIFT_OVERFLOW),
        ("misaligned", CrashClass.MISALIGNED_ACCESS),
        ("unreachable", CrashClass.UNREACHABLE_CODE),
        ("data race", CrashClass.DATA_RACE),
        ("lock order inversion", CrashClass.LOCK_ORDER_INVERSION),
        ("segv on unknown address", CrashClass.SEGMENTATION_FAULT),
        ("segmentation fault", CrashClass.SEGMENTATION_FAULT),
        ("sigsegv", CrashClass.SEGMENTATION_FAULT),
        ("sigbus", CrashClass.BUS_ERROR),
        ("sigill", CrashClass.ILLEGAL_INSTRUCTION),
        ("sigabrt", CrashClass.ABORT),
        ("assertion", CrashClass.ASSERTION_FAILURE),
        ("stack-overflow", CrashClass.STACK_OVERFLOW),
        ("stack overflow", CrashClass.STACK_OVERFLOW),
        ("out of memory", CrashClass.OUT_OF_MEMORY),
        ("nullptr", CrashClass.NULL_DEREFERENCE),
        ("null-pointer", CrashClass.NULL_DEREFERENCE),
        ("object-size violation", CrashClass.OBJECT_SIZE_VIOLATION),
        ("member call on null", CrashClass.NULL_ARGUMENT),
        ("cannot convert", CrashClass.TYPE_MISSMATCH),
        ("value out of range for type", CrashClass.ENUM_OUT_OF_RANGE),
        ("timeout", CrashClass.TIMEOUT),
        ("time on task too long", CrashClass.TIMEOUT),
        ("hang", CrashClass.HANG),
    )
    for needle, mapped in table:
        if needle in text:
            return mapped
    fallback = {
        SanitizerKind.TSAN: CrashClass.DATA_RACE,
        SanitizerKind.MSAN: CrashClass.UNINITIALIZED_USE,
        SanitizerKind.LSAN: CrashClass.MEMORY_LEAK,
    }
    return fallback.get(kind, CrashClass.UNKNOWN)


_ALL_MODEL_CLASSES: Tuple[Type[Any], ...] = (
    TimestampRange, ByteRange, ResourceUsage, ToolAvailability, EngineCapabilities,
    StackFrame, StackTrace, SignalInfo, MemoryAccess, CrashLocation, SanitizerReport,
    Fingerprint, CorpusEntry, CorpusStats, Corpus, Scope, Authorisation, BuildRecipe,
    HarnessSpec, SourceLayout, ProductIdentity, Target, Crash, Vote, DedupDecisionDetail,
    RunMetrics, TelemetrySample, HealthSnapshot, CampaignMetrics, Campaign,
    ReproductionResult, MinimizationResult, Evidence, RootCauseHint, Reproducer, Finding,
    RegressionTest, ReportRequest, ReportArtifact, EventEnvelope, JobRecord, TaskSpec,
)

_ENUM_CLASSES: Tuple[Type[Enum], ...] = (
    Severity, Confidence, Priority, CrashClass, MemoryAccessType, SanitizerKind, EngineKind,
    InstrumentationKind, CompilerFamily, LinkageKind, OptimizationLevel, TargetKind, Language,
    Architecture, OperatingSystem, InputClass, RunStatus, CampaignStatus, JobStateName,
    CrashState, FindingState, ReproductionOutcome, DedupDecision, ReportFormat, ProcessRole,
    SymbolizerKind, CoverageMetric, OperationMode, TriggerCondition,
)


def _register_everything() -> Dict[str, int]:
    models = 0
    for klass in _ALL_MODEL_CLASSES:
        MODEL_REGISTRY.register(_default_model_name(klass), klass, override=True)
        models += 1
    enums = 0
    for enum_cls in _ENUM_CLASSES:
        MODEL_REGISTRY.register(f"enum_{_slug_token(enum_cls.__name__)}", enum_cls, override=True)
        enums += 1
    return {"models": models, "enums": enums, "total": len(MODEL_REGISTRY)}


_REGISTRATION = _register_everything()


def model_registration_summary() -> Dict[str, Any]:
    return {**_REGISTRATION, "names": MODEL_REGISTRY.names()}


def taxonomy_overview() -> Dict[str, Any]:
    """Compact overview of the crash/severity vocabulary (used by docs & GUI)."""
    return {
        "crash_classes": {
            str(member.value): {
                "family": member.family, "sanitizer": member.sanitizer_origin,
                "severity": str(member.typical_severity().value),
            }
            for member in CrashClass
        },
        "severities": Severity.tokens(),
        "sanitizers": {str(member.value): member.flag for member in SanitizerKind},
        "engines": {str(member.value): member.binaries for member in EngineKind},
        "report_formats": {str(member.value): member.extension for member in ReportFormat},
        "finding_transitions": {
            str(key.value): sorted(state.value for state in value) for key, value in _FINDING_TRANSITIONS.items()
        },
    }


build_default_registry()
