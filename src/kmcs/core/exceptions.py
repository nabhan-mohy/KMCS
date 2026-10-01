"""
kmcs.core.exceptions
====================

Centralised, structured exception hierarchy for the **Keyless Memory-Corruption
Scanner (KMCS)**.

Design goals
------------

1.  *Machine-readable errors.*  Every exception carries a stable ``code``
    (a short snake_case identifier), an HTTP-like numeric ``status``,
    structured ``context`` and an optional list of *remediation hints*.  This
    lets the CLI, GUI, database layer and reporting engine all render the same
    error faithfully without parsing human-oriented strings.

2.  *No secrets, ever.*  Exception payloads are deliberately scrubbed of
    anything that could look like a credential, bearer token, API key or
    private key material before they are logged or serialised.  KMCS is a
    fully offline tool: it never needs keys, and it must never leak them if
    the surrounding environment happens to contain some.

3.  *Composability.*  Exceptions support rich tracebacks, cause chaining
    (``raise X from Y``) and loss-less round-tripping through
    :meth:`KMCSBaseError.to_dict` / :meth:`KMCSBaseError.from_dict` so a
    worker process can send its failure across a process boundary and have it
    reconstructed verbatim in the supervisor.

Security boundary
-----------------

This module contains no exploit-related functionality whatsoever.  Errors
describe *operational* failures (build broke, fuzzer missing, crash could not
be parsed) and *policy* violations (attempting to run against an unauthorised
target).  Policy violations raise :class:`AuthorizationError` /
:class:`PolicyViolationError`.
"""

from __future__ import annotations

import builtins
import copy
import hashlib
import json
import os
import platform
import re
import socket
import sys
import threading
import time
import traceback
import uuid
from collections import deque
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Type, Union

__all__: List[str] = [
    # infrastructure
    "ErrorCode",
    "ErrorSeverity",
    "ErrorContext",
    "ExceptionRegistry",
    "ExceptionRecord",
    "exception_registry",
    "redact",
    "SENSITIVE_KEYS",
    "REDACTION_MASK",
    "install_excepthooks",
    "uninstall_excepthooks",
    "uncaught_errors",
    # base
    "KMCSBaseError",
    "KMCSException",
    "KMCSRuntimeError",
    "KMCSValueError",
    "InvalidValueError",
    "KMCSTypeError",
    "KMCSNotImplementedError",
    "KMCSOSError",
    "KMCSUsageError",
    "KMCSAssertionError",
    # configuration
    "ConfigurationError",
    "ConfigParseError",
    "ConfigValidationError",
    "ConfigMigrationError",
    "MissingRequiredFieldError",
    "UnknownOptionError",
    "SchemaVersionError",
    "CircularReferenceError",
    # authorization / policy
    "AuthorizationError",
    "ScopeExceededError",
    "ConsentRequiredError",
    "LicenseCheckError",
    "PolicyViolationError",
    "ProhibitedCapabilityError",
    "OutOfScopeTargetError",
    # environment / tools
    "EnvironmentErrorDetail",
    "ToolNotFoundError",
    "ToolVersionError",
    "CompilerNotFoundError",
    "SanitizerUnavailableError",
    "FuzzerUnavailableError",
    "DebuggerUnavailableError",
    # targets & builds
    "TargetError",
    "TargetNotFoundError",
    "TargetInvalidError",
    "BuildError",
    "InstrumentationError",
    "HarnessError",
    "HarnessTimeoutError",
    # fuzzing
    "FuzzingError",
    "FuzzerCrashedError",
    "FuzzerStartupError",
    "FuzzerTimeoutError",
    "FuzzerAlreadyRunningError",
    "FuzzerNotRunningError",
    "CoverageError",
    "EngineSelectionError",
    # corpus
    "CorpusError",
    "CorpusEmptyError",
    "CorpusValidationError",
    "SeedImportError",
    "InputTooLargeError",
    # crashes / analysis
    "CrashError",
    "CrashParseError",
    "CrashClassificationError",
    "FingerprintError",
    "DeduplicationError",
    "SeverityAssessmentError",
    "ReproductionError",
    "MinimizationError",
    # jobs / scheduling
    "JobError",
    "JobNotFoundError",
    "JobStateError",
    "JobCancelledError",
    "JobTimeoutError",
    "JobDependencyError",
    "WorkerError",
    "WorkerLostError",
    "SchedulerError",
    # database
    "DatabaseError",
    "MigrationError",
    "ConstraintViolationError",
    "RecordNotFoundError",
    "SessionError",
    # events
    "EventError",
    "EventPublishError",
    "SubscriberError",
    "EventLoopClosedError",
    # reporting
    "ReportError",
    "TemplateError",
    "ExportError",
    "SerializationError",
    # resources
    "ResourceError",
    "DiskSpaceError",
    "MemoryLimitError",
    "ProcessLimitError",
    "PermissionDeniedError",
    "FileLockedError",
    # pipeline
    "PipelineError",
    "StageError",
    "StageSkippedError",
    "RollbackError",
    "UnsupportedOperationError",
    # utility
    "format_exception",
    "exception_from_payload",
    "get_last_errors",
    "record_error",
    "clear_error_history",
    "error_catalogue_summary",
]


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

REDACTION_MASK = "***REDACTED***"


def _utc_now() -> datetime:
    """Timezone-aware *now* in UTC (never naive, never local-time ambiguous)."""
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _slug(text: str) -> str:
    out: List[str] = []
    for ch in str(text).strip():
        if ch.isalnum():
            out.append(ch.lower())
        elif ch in "-_":
            out.append("_")
        else:
            out.append("_")
    slug = "".join(out).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug or "error"


def _short_hash(payload: str, length: int = 12) -> str:
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:length]


def _clip(value: str, limit: int = 4096) -> str:
    """Bound string size so an error carrying a huge payload cannot balloon RAM."""
    value = value if isinstance(value, str) else str(value)
    if len(value) <= limit:
        return value
    head = value[: max(0, limit - 64)]
    return f"{head}\n...[truncated {len(value) - len(head)} characters]"


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------

#: Key names whose *values* must always be masked when they appear in a dict.
SENSITIVE_KEYS: Tuple[str, ...] = (
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "private_key",
    "session_token",
    "auth",
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "tokens",
    "bearer",
    "credentials",
    "credential",
    "aws_access_key_id",
    "aws_secret_access_key",
    "dburl",
    "database_url",
    "dsn",
    "connection_string",
    "ssh_key",
    "signing_key",
    "encryption_key",
    "master_key",
    "key",
)

#: Value patterns that look like credentials regardless of their key name.
_VALUE_PATTERNS: Tuple[Tuple[re.Pattern, int], ...] = (
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9\-._~+/]{12,}=*"), 1),
    (re.compile(r"(?i)\b((?:basic|digest)\s+[A-Za-z0-9+/=:_-]{8,})"), 0),
    (re.compile(r"(?i)\b(https?|ftp|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|amqps?|redis|mssql|oracle|jdbc:[a-z0-9]+)://([^\s/@:]*):([^\s/@]+)@"), 0),
    (re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"), 0),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), 0),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), 0),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), 0),
    (re.compile(r"\bgh[ousr]_[A-Za-z0-9]{36,}\b"), 0),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 0),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), 0),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{34,}\b"), 0),
    (re.compile(r"\bya29\.[A-Za-z0-9_\-]{20,}"), 0),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), 0),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b"), 0),
    (re.compile(r"(?i)\b(openapi|anthropic|google|azure|huggingface|slack|twilio|sendgrid)_?(?:api)?_?key\b\s*[:=]\s*\S+"), 0),
)

_KEYVALUE_PATTERN = re.compile(
    r"(?i)([\"']?[A-Za-z][A-Za-z0-9_.-]*(?:secret|token|password|passwd|pwd|api[-_]?key|apikey|access[-_]?key|"
    r"private[-_]?key|credential|authorization|auth|session|signature|nonce|key)[A-Za-z0-9_.-]*[\"']?)\s*[:=]\s*"
    r"([\"']?)([^\"'\s,;&}\]]{2,})(\2)"
)

_ENV_CREDENTIAL_NAMES = re.compile(
    r"(?i)(?:^|_)(?:api[_-]?key|apikey|token|secret|password|passwd|credential|access[_-]?key|private[_-]?key|auth|secret[_-]?key)(?:$|_)"
)


def _mask_scalar(val: Any, keep_length: int = 4) -> str:
    text = "" if val is None else str(val)
    if not text:
        return REDACTION_MASK
    prefix = text[:keep_length] if len(text) > keep_length * 2 else ""
    return f"{prefix}…{REDACTION_MASK}" if prefix else REDACTION_MASK


def _redact_string(text: str, keep_length: int = 4) -> str:
    if not text:
        return text
    result = text

    def _kv(m: re.Match) -> str:
        key, quote_a, value, quote_b = m.group(1), m.group(2), m.group(3), m.group(4)
        q = quote_a or ""
        return f"{key}={q}{_mask_scalar(value, keep_length)}{q}" if "=" in m.group(0) else f"{key}: {q}{_mask_scalar(value, keep_length)}{q}"

    for pattern, group in _VALUE_PATTERNS:
        if group == 1:
            result = pattern.sub(lambda m: m.group(1) + REDACTION_MASK, result)
        else:
            result = pattern.sub(REDACTION_MASK, result)
    result = _KEYVALUE_PATTERN.sub(_kv, result)
    # connection-string style ";Password=xxx" fragments
    result = re.sub(r"(?i)(;\s*(?:pwd|password|uid|user id|trusted_connection)\s*=\s*)([^;]{2,})", lambda m: m.group(1) + REDACTION_MASK, result)
    return result


def redact(value: Any, *, depth: int = 0, max_depth: int = 12, keep_length: int = 4) -> Any:
    """Return a copy of *value* with credential-looking material masked.

    Handles nested mappings/sequences, bytes, plain strings and arbitrary
    objects (which are reduced to a safe type-name placeholder).  The function
    is intentionally conservative: when in doubt it masks.

    Args:
        value: anything at all.
        depth: internal recursion guard.
        max_depth: stop recursing beyond this nesting level.
        keep_length: how many leading characters to preserve inside a masked
            value so operators can still tell *which* secret was present
            without exposing it.
    """
    if depth > max_depth:
        return REDACTION_MASK
    if isinstance(value, Mapping):
        out: Dict[Any, Any] = {}
        for key, val in value.items():
            key_str = key if isinstance(key, str) else str(key)
            lowered = key_str.lower().replace(" ", "_").replace("-", "_")
            sensitive = any(
                lowered == sk or lowered.startswith(sk + "_") or lowered.endswith("_" + sk)
                for sk in SENSITIVE_KEYS
            ) or bool(_ENV_CREDENTIAL_NAMES.search(lowered))
            if sensitive:
                if isinstance(val, (Mapping, list, tuple, set, frozenset)):
                    out[key] = REDACTION_MASK
                else:
                    out[key] = _mask_scalar(val, keep_length)
            else:
                out[key] = redact(val, depth=depth + 1, max_depth=max_depth, keep_length=keep_length)
        return out
    if isinstance(value, (list, tuple)):
        items = [redact(v, depth=depth + 1, max_depth=max_depth, keep_length=keep_length) for v in value]
        return type(value)(items) if isinstance(value, tuple) else items
    if isinstance(value, (set, frozenset)):
        return [redact(v, depth=depth + 1, max_depth=max_depth, keep_length=keep_length) for v in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return f"<binary {len(raw)} bytes sha256={_short_hash(raw.hex(), 16)}>"
        return _redact_string(text, keep_length)
    if isinstance(value, str):
        return _redact_string(value, keep_length)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (uuid.UUID, datetime)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, os.PathLike):
        return _redact_string(os.fspath(value), keep_length)
    return f"<{type(value).__module__}.{type(value).__name__}>"


def _redact_environment(env: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """Snapshot of the environment with credential-shaped variables masked."""
    source = os.environ if env is None else env
    out: Dict[str, str] = {}
    for name, value in sorted(source.items()):
        if _ENV_CREDENTIAL_NAMES.search(name):
            out[name] = REDACTION_MASK
        else:
            out[name] = _clip(str(value), 512)
    return out


# ---------------------------------------------------------------------------
# enumerations
# ---------------------------------------------------------------------------


class ErrorCode(str, Enum):
    """Stable machine-readable error identifiers.

    Values are part of KMCS's public contract: they are embedded in JSON
    reports and database rows and therefore must never be renamed, only added
    to.  Members are string-valued so they serialise naturally.
    """

    # generic
    INTERNAL_ERROR = "internal_error"
    NOT_IMPLEMENTED = "not_implemented"
    INVALID_VALUE = "invalid_value"
    INVALID_TYPE = "invalid_type"
    OPERATION_FAILED = "operation_failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNAVAILABLE = "unavailable"
    VERSION_CONFLICT = "version_conflict"
    UNSUPPORTED = "unsupported"
    # configuration
    CONFIG_INVALID = "config_invalid"
    CONFIG_PARSE = "config_parse"
    CONFIG_SCHEMA = "config_schema"
    CONFIG_MIGRATION = "config_migration"
    FIELD_REQUIRED = "field_required"
    OPTION_UNKNOWN = "option_unknown"
    REFERENCE_CYCLE = "reference_cycle"
    # authorization / policy
    AUTHORIZATION_REQUIRED = "authorization_required"
    SCOPE_EXCEEDED = "scope_exceeded"
    POLICY_VIOLATION = "policy_violation"
    CONSENT_REQUIRED = "consent_required"
    LICENSE_CHECK_FAILED = "license_check_failed"
    CAPABILITY_PROHIBITED = "capability_prohibited"
    # environment
    TOOL_MISSING = "tool_missing"
    TOOL_VERSION = "tool_version"
    COMPILER_MISSING = "compiler_missing"
    SANITIZER_UNAVAILABLE = "sanitizer_unavailable"
    FUZZER_UNAVAILABLE = "fuzzer_unavailable"
    DEBUGGER_UNAVAILABLE = "debugger_unavailable"
    # targets / build
    TARGET_NOT_FOUND = "target_not_found"
    TARGET_INVALID = "target_invalid"
    BUILD_FAILED = "build_failed"
    INSTRUMENTATION_FAILED = "instrumentation_failed"
    HARNESS_FAILED = "harness_failed"
    # fuzzing
    FUZZER_CRASHED = "fuzzer_crashed"
    FUZZER_STARTUP_FAILED = "fuzzer_startup_failed"
    FUZZER_ALREADY_RUNNING = "fuzzer_already_running"
    FUZZER_NOT_RUNNING = "fuzzer_not_running"
    COVERAGE_FAILED = "coverage_failed"
    ENGINE_SELECTION_FAILED = "engine_selection_failed"
    # corpus
    CORPUS_EMPTY = "corpus_empty"
    CORPUS_INVALID = "corpus_invalid"
    SEED_IMPORT_FAILED = "seed_import_failed"
    INPUT_TOO_LARGE = "input_too_large"
    # crashes
    CRASH_PARSE_FAILED = "crash_parse_failed"
    CLASSIFICATION_FAILED = "classification_failed"
    FINGERPRINT_FAILED = "fingerprint_failed"
    DEDUPLICATION_FAILED = "deduplication_failed"
    SEVERITY_FAILED = "severity_failed"
    REPRODUCTION_FAILED = "reproduction_failed"
    MINIMIZATION_FAILED = "minimization_failed"
    # jobs
    JOB_NOT_FOUND = "job_not_found"
    JOB_STATE_INVALID = "job_state_invalid"
    JOB_TIMEOUT = "job_timeout"
    JOB_DEPENDENCY_FAILED = "job_dependency_failed"
    WORKER_LOST = "worker_lost"
    SCHEDULER_FAILED = "scheduler_failed"
    # database
    DB_FAILED = "db_failed"
    DB_MIGRATION_FAILED = "db_migration_failed"
    DB_CONSTRAINT = "db_constraint"
    RECORD_NOT_FOUND = "record_not_found"
    # events
    EVENT_PUBLISH_FAILED = "event_publish_failed"
    SUBSCRIBER_FAILED = "subscriber_failed"
    EVENT_LOOP_CLOSED = "event_loop_closed"
    # reporting
    REPORT_FAILED = "report_failed"
    TEMPLATE_FAILED = "template_failed"
    EXPORT_FAILED = "export_failed"
    SERIALIZATION_FAILED = "serialization_failed"
    # resources
    DISK_FULL = "disk_full"
    MEMORY_LIMIT = "memory_limit"
    PROCESS_LIMIT = "process_limit"
    PERMISSION_DENIED = "permission_denied"
    FILE_LOCKED = "file_locked"
    # pipeline
    PIPELINE_FAILED = "pipeline_stage_failed"
    STAGE_SKIPPED = "stage_skipped"
    ROLLBACK_FAILED = "rollback_failed"

    # -- class methods ---------------------------------------------------

    @classmethod
    def from_name(cls, name: Any) -> "ErrorCode":
        """Resolve an :class:`ErrorCode` from either its member name or value."""
        if isinstance(name, cls):
            return name
        token = str(name).strip()
        try:
            return cls[token.upper()]
        except KeyError:
            pass
        try:
            return cls(token)
        except ValueError:
            for member in cls:
                if member.value.lower() == token.lower():
                    return member
            return cls.INTERNAL_ERROR

    @classmethod
    def coerce(cls, value: Any) -> "ErrorCode":
        return cls.from_name(value)

    def describe(self) -> str:
        """Human readable label derived from the code value."""
        return self.value.replace("_", " ").title()

    def as_json(self) -> Dict[str, str]:
        return {"code": self.value, "label": self.describe()}


class ErrorSeverity(int, Enum):
    """Ordered severity levels; comparisons behave intuitively (DEBUG < FATAL)."""

    DEBUG = 10
    INFO = 20
    NOTICE = 30
    WARNING = 40
    ERROR = 50
    CRITICAL = 60
    FATAL = 70

    def __str__(self) -> str:
        return self.name

    def at_least(self, other: Union["ErrorSeverity", int, str]) -> bool:
        return int(self) >= int(ErrorSeverity.parse(other))

    def escalate(self, steps: int = 1) -> "ErrorSeverity":
        members = list(type(self))
        index = min(len(members) - 1, max(0, members.index(self) + steps))
        return members[index]

    @classmethod
    def parse(cls, value: Any, default: "ErrorSeverity" = ERROR) -> "ErrorSeverity":
        if isinstance(value, cls):
            return value
        if isinstance(value, bool):
            return default
        if isinstance(value, int):
            for member in cls:
                if int(member) == value:
                    return member
            nearest = min(cls, key=lambda m: abs(int(m) - value))
            return nearest
        text = str(value).strip().upper()
        try:
            return cls[text]
        except KeyError:
            pass
        try:
            return cls.parse(int(text), default=default)
        except (TypeError, ValueError):
            aliases = {
                "ERR": cls.ERROR,
                "WARN": cls.WARNING,
                "CRIT": cls.CRITICAL,
                "FATAL": cls.FATAL,
                "SEV": cls.NOTICE,
                "NONE": cls.DEBUG,
            }
            return aliases.get(text, default)


# ---------------------------------------------------------------------------
# error context
# ---------------------------------------------------------------------------

_CONTEXT_FIELDS: Tuple[str, ...] = (
    "component", "operation", "target", "campaign", "job", "crash", "input_path",
    "stage", "tool", "tool_version", "sanitizer", "engine", "hostname", "pid", "tid",
    "thread", "cwd", "python", "platform_str", "kmcs_version", "occurred_at",
    "monotonic", "tags", "extra_env",
)


def _detect_kmcs_version() -> str:
    for getter in ("__version__", "VERSION"):
        try:
            pkg = __import__("kmcs", fromlist=[getter])
            candidate = getattr(pkg, getter, None)
            if candidate:
                return str(candidate)
        except Exception:
            continue
    return "0.1.0-core"


@dataclass
class ErrorContext:
    """Structured, serialisable metadata attached to every KMCS exception.

    Context is what turns a stack trace into a *finding*: which campaign,
    which target, which input file, which fuzzer stage.  It is always
    redacted before leaving the process.
    """

    values: Dict[str, Any] = dc_field(default_factory=dict)
    component: Optional[str] = None
    operation: Optional[str] = None
    target: Optional[str] = None
    campaign: Optional[str] = None
    job: Optional[str] = None
    crash: Optional[str] = None
    input_path: Optional[str] = None
    stage: Optional[str] = None
    tool: Optional[str] = None
    tool_version: Optional[str] = None
    sanitizer: Optional[str] = None
    engine: Optional[str] = None
    hostname: str = dc_field(default_factory=lambda: socket.gethostname())
    pid: int = dc_field(default_factory=os.getpid)
    tid: Optional[int] = None
    thread: Optional[str] = None
    cwd: str = dc_field(default_factory=lambda: os.getcwd())
    python: str = dc_field(default_factory=lambda: platform.python_version())
    platform_str: str = dc_field(default_factory=lambda: f"{platform.system()} {platform.release()} ({platform.machine()})")
    kmcs_version: Optional[str] = None
    occurred_at: datetime = dc_field(default_factory=_utc_now)
    monotonic: float = dc_field(default_factory=time.monotonic)
    tags: Tuple[str, ...] = ()
    extra_env: Dict[str, str] = dc_field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.tid is None:
            self.tid = threading.get_ident()
        if self.thread is None:
            self.thread = threading.current_thread().name
        if self.kmcs_version is None:
            self.kmcs_version = _detect_kmcs_version()
        if isinstance(self.tags, str):
            self.tags = (_slug(self.tags),)
        elif isinstance(self.tags, (list, tuple, set, frozenset)):
            self.tags = tuple(_slug(t) for t in self.tags if str(t).strip())
        if isinstance(self.occurred_at, str):
            try:
                self.occurred_at = datetime.fromisoformat(self.occurred_at)
            except ValueError:
                self.occurred_at = _utc_now()
        if not isinstance(self.values, dict):
            self.values = dict(self.values or {})

    # -- construction ----------------------------------------------------

    @classmethod
    def capture(cls, **kwargs: Any) -> "ErrorContext":
        """Build a context snapshot from the running environment + kwargs."""
        known = {k: v for k, v in kwargs.items() if k in _CONTEXT_FIELDS}
        extra = {k: v for k, v in kwargs.items() if k not in _CONTEXT_FIELDS}
        ctx = cls(**known)
        if extra:
            ctx.values.update(extra)
        return ctx

    @classmethod
    def from_any(cls, value: Any) -> "ErrorContext":
        if isinstance(value, ErrorContext):
            return value
        if isinstance(value, Mapping):
            return cls.from_mapping(value)
        if value is None:
            return cls.capture()
        return cls.capture(detail=str(value))

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "ErrorContext":
        kwargs: Dict[str, Any] = {}
        values: Dict[str, Any] = {}
        for key, val in mapping.items():
            if key in _CONTEXT_FIELDS:
                kwargs[key] = val
            elif key == "platform":
                kwargs["platform_str"] = val
            elif key == "values" and isinstance(val, Mapping):
                values.update(dict(val))
            else:
                values[key] = val
        return cls(values=values, **kwargs)

    # -- mutation --------------------------------------------------------

    _DIRECT = set(_CONTEXT_FIELDS) - {"values"}

    def set(self, key: str, value: Any) -> "ErrorContext":
        if key in self._DIRECT:
            setattr(self, key, value)
        elif key == "values" and isinstance(value, Mapping):
            self.values.update(value)
        else:
            self.values[key] = value
        return self

    def update(self, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> "ErrorContext":
        for src in (dict(mapping or {}), kwargs):
            for key, value in src.items():
                self.set(key, value)
        return self

    def add_tag(self, *tags: str) -> "ErrorContext":
        merged = list(self.tags)
        for tag in tags:
            token = _slug(str(tag))
            if token and token not in merged:
                merged.append(token)
        self.tags = tuple(merged)
        return self

    def child(self, **overrides: Any) -> "ErrorContext":
        """Derive a related context (e.g. a sub-stage) inheriting this one."""
        base = self.to_mapping(include_environment=False, redact_values=False)
        base["values"] = dict(self.values)
        base.update({k: v for k, v in overrides.items() if v is not None})
        return ErrorContext.from_mapping(base)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.values:
            return self.values[key]
        value = getattr(self, key, None)
        return default if value is None else value

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        return key in self.values or key in self._DIRECT

    def __getitem__(self, key: str) -> Any:
        found = self.get(key, ... )
        if found is Ellipsis:
            raise KeyError(key)
        return found

    def as_dict(self) -> Dict[str, Any]:
        return self.to_mapping()

    # -- output ----------------------------------------------------------

    def to_mapping(self, *, include_environment: bool = False, redact_values: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "component": self.component,
            "operation": self.operation,
            "target": self.target,
            "campaign": self.campaign,
            "job": self.job,
            "crash": self.crash,
            "input_path": self.input_path,
            "stage": self.stage,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "sanitizer": self.sanitizer,
            "engine": self.engine,
            "hostname": self.hostname,
            "pid": self.pid,
            "tid": self.tid,
            "thread": self.thread,
            "cwd": self.cwd,
            "python": self.python,
            "platform": self.platform_str,
            "kmcs_version": self.kmcs_version,
            "occurred_at": _iso(self.occurred_at),
            "tags": list(self.tags),
            "values": dict(self.values),
        }
        if include_environment:
            data["environment"] = self.extra_env or _redact_environment()
        cleaned = {k: v for k, v in data.items() if v not in (None, [], {}, ())}
        return redact(cleaned) if redact_values else cleaned

    def fingerprint(self) -> str:
        """Stable short digest of the *meaningful* context fields.

        Used by higher layers to decide whether two exceptions describe the
        same underlying problem.  Volatile fields (pid, tid, timestamps) are
        excluded on purpose.
        """
        payload = json.dumps(
            {
                "component": self.component,
                "operation": self.operation,
                "target": self.target,
                "campaign": self.campaign,
                "stage": self.stage,
                "tool": self.tool,
                "engine": self.engine,
                "sanitizer": self.sanitizer,
                "values": {k: _stable(v) for k, v in sorted(self.values.items(), key=lambda kv: str(kv[0]))},
            },
            sort_keys=True,
            default=str,
        )
        return _short_hash(payload, 16)

    def elapsed_ms(self) -> float:
        """Milliseconds between context creation and now (monotonic clock)."""
        return round((time.monotonic() - self.monotonic) * 1000.0, 3)

    def summary_line(self) -> str:
        parts: List[str] = []
        for label, value in (
            ("component", self.component),
            ("op", self.operation),
            ("target", self.target),
            ("campaign", self.campaign),
            ("job", self.job),
            ("stage", self.stage),
            ("engine", self.engine),
            ("tool", self.tool),
            ("sanitizer", self.sanitizer),
        ):
            if value:
                parts.append(f"{label}={value}")
        return " ".join(parts)

    def merge_into(self, other: "ErrorContext") -> "ErrorContext":
        """Fill unset fields of *other* from this context; returns *other*."""
        for field_name in _CONTEXT_FIELDS:
            if field_name in {"values", "occurred_at", "monotonic"}:
                continue
            if getattr(other, field_name, None) in (None, "", (), {}) and getattr(self, field_name, None) is not None:
                setattr(other, field_name, getattr(self, field_name))
        for key, value in self.values.items():
            other.values.setdefault(key, value)
        other.tags = tuple(dict.fromkeys((*other.tags, *self.tags)))
        return other


def _stable(value: Any) -> Any:
    """Normalise a value for fingerprinting (paths → basename, floats rounded)."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, os.PathLike):
        return os.path.basename(os.fspath(value))
    if isinstance(value, Mapping):
        return {str(k): _stable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_stable(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return _short_hash(bytes(value).hex(), 16)
    return _clip(str(value), 256)


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------


@dataclass
class ExceptionRecord:
    exception_class: Type[BaseException]
    code: ErrorCode
    status: int
    category: str
    retryable: bool
    remediation: Tuple[str, ...]
    introduced_in: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exception": f"{self.exception_class.__module__}.{self.exception_class.__qualname__}",
            "name": self.exception_class.__name__,
            "code": self.code.value,
            "status": self.status,
            "category": self.category,
            "retryable": self.retryable,
            "remediation": list(self.remediation),
            "introduced_in": self.introduced_in,
            "description": self.description,
        }


_CATEGORY_TABLE: Tuple[Tuple[str, str], ...] = (
    ("config", "configuration"),
    ("schema", "configuration"),
    ("auth", "authorization"),
    ("consent", "authorization"),
    ("scope", "authorization"),
    ("license", "authorization"),
    ("policy", "policy"),
    ("prohibit", "policy"),
    ("tool", "environment"),
    ("compiler", "environment"),
    ("sanitizer", "environment"),
    ("debugger", "environment"),
    ("fuzz", "fuzzing"),
    ("coverage", "fuzzing"),
    ("engine", "fuzzing"),
    ("corpus", "corpus"),
    ("seed", "corpus"),
    ("input", "corpus"),
    ("crash", "analysis"),
    ("fingerprint", "analysis"),
    ("dedup", "analysis"),
    ("classif", "analysis"),
    ("severity", "analysis"),
    ("minimi", "analysis"),
    ("reproduc", "reproduction"),
    ("job", "jobs"),
    ("worker", "jobs"),
    ("schedul", "jobs"),
    ("database", "database"),
    ("migration", "database"),
    ("record", "database"),
    ("session", "database"),
    ("constraint", "database"),
    ("event", "events"),
    ("subscri", "events"),
    ("report", "reporting"),
    ("template", "reporting"),
    ("export", "reporting"),
    ("serial", "reporting"),
    ("disk", "resources"),
    ("memory", "resources"),
    ("process", "resources"),
    ("permission", "resources"),
    ("lock", "resources"),
    ("file", "resources"),
    ("stage", "pipeline"),
    ("pipeline", "pipeline"),
    ("rollback", "pipeline"),
    ("target", "targets"),
    ("build", "targets"),
    ("harness", "targets"),
    ("instrument", "targets"),
)


def _category_for(name: str) -> str:
    lowered = str(name).lower()
    for needle, category in _CATEGORY_TABLE:
        if needle in lowered:
            return category
    return "general"


def inspect_doc_summary(klass: type) -> str:
    doc = (getattr(klass, "__doc__", "") or "").strip()
    if not doc:
        return ""
    first_block = doc.split("\n\n", 1)[0]
    flat = " ".join(line.strip() for line in first_block.splitlines() if line.strip())
    return _clip(flat, 400)


class ExceptionRegistry:
    """Catalogue of every KMCS exception type plus runtime statistics.

    The registry answers three operational questions:

    * *lookup* — given an error code or class name, find the right class
      (used when deserialising failures produced by another process);
    * *guidance* — given a failure, what should the researcher do next;
    * *telemetry* — which failures dominate a campaign, so we can prioritise
      hardening of the tooling itself.
    """

    def __init__(self) -> None:
        self._records: Dict[str, ExceptionRecord] = {}
        self._by_code: Dict[ErrorCode, List[str]] = {}
        self._counts: Dict[str, int] = {}
        self._first_seen: Dict[str, datetime] = {}
        self._last_seen: Dict[str, datetime] = {}
        self._recent: Deque[Dict[str, Any]] = deque(maxlen=512)
        self._lock = threading.RLock()
        self._listeners: List[Callable[[ExceptionRecord, BaseException], None]] = []

    # -- registration ----------------------------------------------------

    def register(
        self,
        exception_class: Type[BaseException],
        *,
        code: Optional[Union[ErrorCode, str]] = None,
        status: Optional[int] = None,
        category: Optional[str] = None,
        retryable: Optional[bool] = None,
        remediation: Sequence[str] = (),
        introduced_in: str = "phase-1-core",
        description: str = "",
        override: bool = False,
    ) -> ExceptionRecord:
        if not (isinstance(exception_class, type) and issubclass(exception_class, BaseException)):
            raise TypeError(f"cannot register {exception_class!r}: not an exception class")
        name = exception_class.__name__
        with self._lock:
            existing = self._records.get(name)
            if existing is not None and not override:
                # merge rather than clobber so subclass defaults survive
                code = code or existing.code
                status = status if status is not None else existing.status
                category = category or existing.category
                retryable = existing.retryable if retryable is None else retryable
                remediation = tuple(dict.fromkeys((*existing.remediation, *remediation)))
                description = description or existing.description
                introduced_in = existing.introduced_in or introduced_in
            record = ExceptionRecord(
                exception_class=exception_class,
                code=ErrorCode.from_name(code if code is not None else ErrorCode.INTERNAL_ERROR),
                status=int(status if status is not None else 500),
                category=category or _category_for(name),
                retryable=bool(retryable) if retryable is not None else False,
                remediation=tuple(str(h) for h in remediation if str(h).strip()),
                introduced_in=introduced_in,
                description=description or inspect_doc_summary(exception_class),
            )
            previous = self._records.get(name)
            self._records[name] = record
            bucket = self._by_code.setdefault(record.code, [])
            if name not in bucket:
                bucket.append(name)
            if previous is not None and previous.code != record.code and name in self._by_code.get(previous.code, []):
                self._by_code[previous.code].remove(name)
            return record

    def unregister(self, name: str) -> bool:
        with self._lock:
            record = self._records.pop(name, None)
            if record is None:
                return False
            bucket = self._by_code.get(record.code, [])
            if name in bucket:
                bucket.remove(name)
            return True

    def ensure(self, exception_class: Type[BaseException]) -> ExceptionRecord:
        """Register *exception_class* lazily using its own class attributes."""
        name = getattr(exception_class, "__name__", str(exception_class))
        existing = self.get(name)
        if existing is not None:
            return existing
        return self.register(
            exception_class,
            code=getattr(exception_class, "default_code", ErrorCode.INTERNAL_ERROR),
            status=getattr(exception_class, "default_status", 500),
            category=getattr(exception_class, "category", None),
            retryable=getattr(exception_class, "retryable", None),
            remediation=getattr(exception_class, "remediation", ()) or (),
            description=inspect_doc_summary(exception_class),
        )

    # -- queries ---------------------------------------------------------

    def get(self, name: Any) -> Optional[ExceptionRecord]:
        if isinstance(name, type):
            name = name.__name__
        with self._lock:
            return self._records.get(str(name))

    def lookup_class(self, name: str) -> Optional[Type[BaseException]]:
        simple = str(name).rsplit(".", 1)[-1]
        record = self.get(simple)
        if record is not None:
            return record.exception_class
        for module_name in ("kmcs.core.exceptions", "builtins"):
            try:
                mod = __import__(module_name, fromlist=[simple])
                candidate = getattr(mod, simple, None)
                if isinstance(candidate, type) and issubclass(candidate, BaseException):
                    return candidate
            except Exception:
                continue
        return None

    def classes_for_code(self, code: Union[ErrorCode, str]) -> List[Type[BaseException]]:
        resolved = ErrorCode.from_name(code)
        with self._lock:
            names = list(self._by_code.get(resolved, []))
        return [self._records[n].exception_class for n in names if n in self._records]

    def all_records(self, category: Optional[str] = None) -> List[ExceptionRecord]:
        with self._lock:
            records = list(self._records.values())
        if category:
            records = [r for r in records if r.category == category]
        return sorted(records, key=lambda r: (r.category, r.code.value, r.name))

    def categories(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for record in self.all_records():
            counts[record.category] = counts.get(record.category, 0)
        return dict(sorted(counts.items()))

    def guidance(self, code_or_name: Any) -> List[str]:
        """Remediation hints for an exception name or error code."""
        record = self.get(code_or_name)
        if record is None:
            candidates = self.classes_for_code(code_or_name)
            if candidates:
                record = self.get(candidates[0])
        if record is None:
            return ["Inspect the traceback and the structured context payload."]
        return list(record.remediation)

    # -- telemetry -------------------------------------------------------

    def observe(self, exc: BaseException) -> None:
        name = type(exc).__name__
        code_value = None
        if isinstance(exc, KMCSBaseError):
            code_value = exc.code.value
        with self._lock:
            self._counts[name] = self._counts.get(name, 0) + 1
            now = _utc_now()
            self._first_seen.setdefault(name, now)
            self._last_seen[name] = now
            self._recent.append(
                {
                    "name": name,
                    "at": _iso(now),
                    "code": code_value,
                    "summary": _clip(str(exc).replace("\n", " "), 300),
                }
            )
            listeners = list(self._listeners)
            record = self._records.get(name)
        for listener in listeners:
            try:
                if record is not None:
                    listener(record, exc)
            except Exception:  # listeners must never break the caller
                continue

    def add_listener(self, callback: Callable[[ExceptionRecord, BaseException], None]) -> None:
        if not callable(callback):
            raise TypeError("listener must be callable")
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[ExceptionRecord, BaseException], None]) -> bool:
        try:
            self._listeners.remove(callback)
            return True
        except ValueError:
            return False

    def count(self, name: Optional[str] = None) -> int:
        with self._lock:
            if name is None:
                return sum(self._counts.values())
            return self._counts.get(str(name), 0)

    def reset_stats(self) -> None:
        with self._lock:
            self._counts.clear()
            self._first_seen.clear()
            self._last_seen.clear()
            self._recent.clear()

    def stats(self, top: int = 10) -> Dict[str, Any]:
        with self._lock:
            counts = dict(self._counts)
            recent = list(self._recent)[-max(0, top) :]
            first = {k: _iso(v) for k, v in self._first_seen.items()}
            last = {k: _iso(v) for k, v in self._last_seen.items()}
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[: max(0, top)]
        return {
            "total_raised": sum(counts.values()),
            "distinct": len(counts),
            "top": [{"name": n, "count": c} for n, c in ranked],
            "first_seen": first,
            "last_seen": last,
            "recent": recent,
        }

    def catalogue(self) -> Dict[str, Any]:
        with self._lock:
            codes = {code.value: sorted(names) for code, names in self._by_code.items()}
        return {
            "registered": len(self),
            "categories": self.categories(),
            "codes": dict(sorted(codes.items())),
            "records": [r.to_dict() for r in self.all_records()],
            "statistics": self.stats(),
        }

    def export_markdown(self) -> str:
        lines = ["# KMCS exception catalogue", ""]
        current = ""
        for record in self.all_records():
            if record.category != current:
                current = record.category
                lines += [f"## Category: `{current}`", "", "| Exception | Code | Status | Retry | Description |", "|---|---|---|---|---|"]
            lines.append(
                f"| `{record.name}` | `{record.code.value}` | {record.status} | "
                f"{'yes' if record.retryable else 'no'} | {_clip(record.description, 160)} |"
            )
        lines.append("")
        for record in self.all_records():
            if record.remediation:
                lines.append(f"**`{record.name}`**")
                lines += [f"* {hint}" for hint in record.remediation]
                lines.append("")
        return "\n".join(lines)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def __contains__(self, item: Any) -> bool:
        if isinstance(item, type):
            return item.__name__ in self._records
        return str(item) in self._records

    def __iter__(self):
        return iter(self.all_records())


exception_registry = ExceptionRegistry()


# ---------------------------------------------------------------------------
# base exception
# ---------------------------------------------------------------------------


class KMCSBaseError(Exception):
    """Root class for every KMCS failure.

    Subclasses customise behaviour purely through class attributes::

        class CorpusEmptyError(CorpusError):
            default_code   = ErrorCode.CORPUS_EMPTY
            default_status = 409
            retryable      = False
            remediation    = ("Add at least one seed input.",)

    Instances carry:

    ``message``           cleaned human message
    ``code``              :class:`ErrorCode`
    ``severity``          :class:`ErrorSeverity`
    ``status``            HTTP-like numeric status
    ``context``           :class:`ErrorContext` (redacted on output)
    ``hints``             per-instance remediation hints
    ``details``           free-form structured details (alias of context.values)
    ``error_id``          UUID for cross-referencing logs ↔ reports
    ``fingerprint``       stable digest for grouping identical failures
    ``retry_after``       suggested backoff base in seconds (if retryable)
    ``cause_chain``       list of serialised upstream causes
    """

    default_code: ErrorCode = ErrorCode.INTERNAL_ERROR
    default_status: int = 500
    default_severity: ErrorSeverity = ErrorSeverity.ERROR
    category: str = "general"
    retryable: bool = False
    retry_after_seconds: Optional[float] = None
    remediation: Tuple[str, ...] = ()
    #: When True the class registers itself in the global registry on creation.
    auto_register: bool = True

    def __init__(
        self,
        message: Any = None,
        *,
        code: Optional[Union[ErrorCode, str]] = None,
        status: Optional[int] = None,
        severity: Optional[Union[ErrorSeverity, str, int]] = None,
        context: Optional[Union[ErrorContext, Mapping[str, Any]]] = None,
        hints: Optional[Sequence[str]] = None,
        details: Optional[Mapping[str, Any]] = None,
        component: Optional[str] = None,
        operation: Optional[str] = None,
        target: Optional[str] = None,
        campaign: Optional[str] = None,
        job: Optional[str] = None,
        stage: Optional[str] = None,
        tool: Optional[str] = None,
        engine: Optional[str] = None,
        sanitizer: Optional[str] = None,
        input_path: Optional[str] = None,
        crash: Optional[str] = None,
        tags: Sequence[str] = (),
        error_id: Optional[str] = None,
        retryable: Optional[bool] = None,
        retry_after: Optional[float] = None,
        cause: Optional[BaseException] = None,
        tb: Optional[str] = None,
        **extra: Any,
    ) -> None:
        rendered = self._render_message(message, extra)
        super().__init__(rendered)
        cls = type(self)
        if self.auto_register and cls.__name__ not in exception_registry:
            try:
                exception_registry.ensure(cls)
            except Exception:  # registry problems must never mask the real error
                pass

        self.message: str = rendered
        self.code: ErrorCode = ErrorCode.from_name(self.default_code if code is None else code)
        self.severity: ErrorSeverity = ErrorSeverity.parse(
            self._severity_for_status(status) if severity is None else severity
        )
        self.status: int = int(self.default_status if status is None else status)
        self.error_id: str = str(error_id) if error_id else str(uuid.uuid4())
        self.created_at: datetime = _utc_now()
        self.retryable_flag: bool = bool(cls.retryable if retryable is None else retryable)
        self.retry_after: Optional[float] = float(retry_after) if retry_after is not None else (
            float(cls.retry_after_seconds) if cls.retry_after_seconds is not None else None
        )

        ctx = ErrorContext.from_any(context)
        ctx.component = component or ctx.component or cls.category or "kmcs"
        ctx.operation = operation or ctx.operation
        ctx.target = target or ctx.target
        ctx.campaign = campaign or ctx.campaign
        ctx.job = job or ctx.job
        ctx.stage = stage or ctx.stage
        ctx.tool = tool or ctx.tool
        ctx.engine = engine or ctx.engine
        ctx.sanitizer = sanitizer or ctx.sanitizer
        ctx.input_path = input_path or ctx.input_path
        ctx.crash = crash or ctx.crash
        if details:
            ctx.update(details)
        if extra:
            ctx.update(extra)
        if tags:
            ctx.add_tag(*tags)
        self.context: ErrorContext = ctx

        merged_hints: List[str] = []
        for hint in (*tuple(hints or ()), *tuple(cls.remediation or ())):
            text = str(hint).strip()
            if text and text not in merged_hints:
                merged_hints.append(text)
        self.hints: Tuple[str, ...] = tuple(merged_hints)

        self.traceback_text: str = tb or ""
        self.cause_chain: List[Dict[str, Any]] = []
        resolved_cause = cause if cause is not None else self._infer_cause()
        if cause is not None and self.__cause__ is None:
            self.__cause__ = cause
        cursor: Optional[BaseException] = resolved_cause
        seen: set = set()
        while cursor is not None and id(cursor) not in seen and len(self.cause_chain) < 16:
            seen.add(id(cursor))
            self.cause_chain.append(self._serialize_cause(cursor))
            cursor = cursor.__cause__ or cursor.__context__
        self._fingerprint_cache: Optional[str] = None

    # -- message handling ------------------------------------------------

    @staticmethod
    def _render_message(message: Any, extra: Mapping[str, Any]) -> str:
        if message is None:
            message = ErrorCode.INTERNAL_ERROR.describe()
        if isinstance(message, str):
            if extra and "{" in message and "}" in message:
                try:
                    message = message.format(**{k: _safe_format(v) for k, v in extra.items()})
                except (KeyError, IndexError, ValueError):
                    pass  # keep raw template rather than exploding inside an error path
        elif isinstance(message, BaseException):
            message = _clip(redact(str(message)), 4096)
        else:
            message = str(message)
        return _clip(_redact_string(message), 8192)

    def _severity_for_status(self, status: Optional[int]) -> ErrorSeverity:
        if status is None:
            return self.default_severity
        status = int(status)
        if status >= 600:
            return ErrorSeverity.FATAL
        if status >= 500:
            return ErrorSeverity.CRITICAL
        if status >= 400:
            return ErrorSeverity.ERROR
        if status >= 300:
            return ErrorSeverity.WARNING
        return self.default_severity

    def _infer_cause(self) -> Optional[BaseException]:
        exc = sys.exc_info()[1]
        if exc is not None and exc is not self:
            return exc
        return None

    @staticmethod
    def _serialize_cause(exc: BaseException) -> Dict[str, Any]:
        code = getattr(exc, "code", None)
        return {
            "type": f"{type(exc).__module__}.{type(exc).__qualname__}",
            "name": type(exc).__name__,
            "message": _clip(_redact_string(str(exc)), 2048),
            "code": code.value if isinstance(code, ErrorCode) else None,
        }

    # -- properties ------------------------------------------------------

    @property
    def details(self) -> Dict[str, Any]:
        return self.context.values

    @property
    def component(self) -> Optional[str]:
        return self.context.component

    @property
    def target(self) -> Optional[str]:
        return self.context.target

    @property
    def campaign(self) -> Optional[str]:
        return self.context.campaign

    @property
    def job(self) -> Optional[str]:
        return self.context.job

    @property
    def stage(self) -> Optional[str]:
        return self.context.stage

    @property
    def tool(self) -> Optional[str]:
        return self.context.tool

    @property
    def engine(self) -> Optional[str]:
        return self.context.engine

    @property
    def sanitizer(self) -> Optional[str]:
        return self.context.sanitizer

    @property
    def input_path(self) -> Optional[str]:
        return self.context.input_path

    @property
    def is_fatal(self) -> bool:
        return self.severity.at_least(ErrorSeverity.FATAL)

    @property
    def is_retryable(self) -> bool:
        return self.retryable_flag

    @property
    def short_id(self) -> str:
        return self.error_id.split("-")[0]

    @property
    def fingerprint(self) -> str:
        if self._fingerprint_cache is None:
            payload = f"{type(self).__name__}|{self.code.value}|{self._normalised_message()}|{self.context.fingerprint()}"
            self._fingerprint_cache = _short_hash(payload, 16)
        return self._fingerprint_cache

    def _normalised_message(self) -> str:
        """Message with digits/paths/uuids masked so similar errors group together."""
        text = self.message
        text = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F\-]{27,}", "<uuid>", text)
        text = re.sub(r"(?:/|[A-Za-z]:\\\\)[^\s'\"]+", "<path>", text)
        text = re.sub(r"\b\d+(?:\.\d+)?\b", "<num>", text)
        return text

    # -- control flow helpers -------------------------------------------

    def mark_retried(self) -> "KMCSBaseError":
        self.context.set("retry_count", int(self.context.get("retry_count", 0) or 0) + 1)
        return self

    def should_retry(self, attempt: int, max_attempts: int = 3) -> bool:
        return self.retryable_flag and attempt < max_attempts

    def backoff_delay(self, attempt: int = 1, jitter: bool = True, maximum: float = 300.0) -> float:
        base = float(self.retry_after if self.retry_after is not None else 1.0)
        delay = base * (2 ** max(0, int(attempt) - 1))
        if jitter:
            delay *= 0.8 + 0.4 * ((int(hashlib.md5(self.error_id.encode()).hexdigest(), 16) % 1000) / 1000.0)
        return round(min(delay, maximum), 3)

    def add_hint(self, *hints: str) -> "KMCSBaseError":
        merged = list(self.hints)
        for hint in hints:
            text = str(hint).strip()
            if text and text not in merged:
                merged.append(text)
        self.hints = tuple(merged)
        return self

    def with_context(self, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> "KMCSBaseError":
        self.context.update(mapping, **kwargs)
        self._fingerprint_cache = None
        return self

    def escalate(self, severity: Union[ErrorSeverity, str, int]) -> "KMCSBaseError":
        self.severity = ErrorSeverity.parse(severity)
        return self

    def derive(
        self,
        klass: Optional[Type["KMCSBaseError"]] = None,
        message: Optional[str] = None,
        **kwargs: Any,
    ) -> "KMCSBaseError":
        """Create a related exception inheriting this one's context (as cause)."""
        target_klass = klass or type(self)
        overrides = {k: v for k, v in kwargs.items() if k in _CONTEXT_FIELDS}
        rest = {k: v for k, v in kwargs.items() if k not in _CONTEXT_FIELDS}
        new = target_klass(
            message or self.message,
            context=self.context.child(**overrides),
            cause=self,
            **rest,
        )
        return new

    def reraise(self) -> "KMCSBaseError":  # pragma: no cover - convenience
        raise self

    # -- rendering -------------------------------------------------------

    def to_dict(self, *, include_traceback: bool = True, include_environment: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "error_id": self.error_id,
            "type": f"{type(self).__module__}.{type(self).__qualname__}",
            "name": type(self).__name__,
            "category": getattr(type(self), "category", self.category),
            "code": self.code.value,
            "code_label": self.code.describe(),
            "status": self.status,
            "severity": self.severity.name,
            "message": self.message,
            "hints": list(self.hints),
            "retryable": self.retryable_flag,
            "retry_after": self.retry_after,
            "fingerprint": self.fingerprint,
            "occurred_at": _iso(self.created_at),
            "context": self.context.to_mapping(include_environment=include_environment),
            "causes": list(self.cause_chain),
        }
        if include_traceback and self.traceback_text:
            payload["traceback"] = _clip(self.traceback_text, 16384)
        return payload

    def to_json(self, *, indent: int = 2, include_traceback: bool = True) -> str:
        return json.dumps(
            self.to_dict(include_traceback=include_traceback),
            indent=indent,
            sort_keys=True,
            default=str,
            ensure_ascii=False,
        )

    def to_logline(self, level: Optional[str] = None) -> str:
        level = level or self.severity.name
        bits = [f"[{level}]", f"{type(self).__name__}({self.code.value})", f"id={self.short_id}", f"fp={self.fingerprint}"]
        summary = self.context.summary_line()
        if summary:
            bits.append(summary)
        bits.append("-")
        bits.append(_clip(self.message.replace("\n", " / "), 400))
        return " ".join(bits)

    def to_markdown(self) -> str:
        lines = [
            f"### {type(self).__name__} — `{self.code.value}`",
            "",
            f"* **Error ID:** `{self.error_id}`",
            f"* **Severity:** {self.severity.name}",
            f"* **Status:** {self.status}",
            f"* **Occurred:** {_iso(self.created_at)}",
            f"* **Message:** {self.message}",
        ]
        summary = self.context.summary_line()
        if summary:
            lines.append(f"* **Where:** {summary}")
        if self.hints:
            lines.append("* **Remediation:**")
            lines += [f"  {i}. {hint}" for i, hint in enumerate(self.hints, 1)]
        if self.cause_chain:
            lines.append("* **Cause chain:**")
            for index, cause in enumerate(self.cause_chain, 1):
                lines.append(f"  {index}. `{cause['name']}` — {cause['message']}")
        if self.context.values:
            lines.append("* **Details:**")
            for key, value in sorted(self.context.values.items(), key=lambda kv: str(kv[0])):
                lines.append(f"  * `{key}`: {redact(value)}")
        if self.traceback_text:
            lines += ["", "```text", _clip(self.traceback_text, 8000), "```"]
        return "\n".join(lines)

    def user_facing(self, verbose: bool = False) -> str:
        head = f"{self.code.describe()}: {self.message}"
        if not verbose:
            return head
        tail_lines = [head, f"  error-id : {self.error_id}", f"  code       : {self.code.value}", f"  severity   : {self.severity.name}"]
        summary = self.context.summary_line()
        if summary:
            tail_lines.append(f"  where      : {summary}")
        for key, value in sorted(self.context.values.items(), key=lambda kv: str(kv[0])):
            tail_lines.append(f"  {key:<10}: {redact(value)}")
        for hint in self.hints:
            tail_lines.append(f"  -> {hint}")
        return "\n".join(tail_lines)

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code.value!r}, severity={self.severity.name}, "
            f"status={self.status}, error_id={self.short_id!r}, message={self.message!r})"
        )

    def __reduce__(self):
        return (_reconstruct_exception, (type(self).__module__, type(self).__name__, self.to_dict(include_traceback=True)))

    # -- attachment helpers ---------------------------------------------

    def attach_traceback(self, tb_obj: Any = None) -> "KMCSBaseError":
        if tb_obj is None:
            frames = traceback.extract_tb(sys.exc_info()[2])
            self.traceback_text = "".join(traceback.format_list(frames)) if frames else self.traceback_text
        else:
            self.traceback_text = "".join(traceback.format_tb(tb_obj))
        return self

    def record(self) -> "KMCSBaseError":
        """Push this failure into the global registry statistics + history."""
        exception_registry.observe(self)
        _LAST_ERRORS.append(copy.copy(self))
        return self

    # -- deserialisation -------------------------------------------------

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        prefer_name: Optional[str] = None,
        fallback: Optional[Type["KMCSBaseError"]] = None,
    ) -> "KMCSBaseError":
        """Reconstruct an exception (of this class or the named class) from a dict."""
        data = dict(payload)
        name = prefer_name or data.get("name") or data.get("type") or cls.__name__
        simple = str(name).rsplit(".", 1)[-1]
        klass: Optional[Type[BaseException]] = None
        record = exception_registry.get(simple)
        if record is not None:
            klass = record.exception_class
        else:
            klass = exception_registry.lookup_class(simple)
        if not (isinstance(klass, type) and issubclass(klass, KMCSBaseError)):
            wrapper = fallback or KMCSBaseError
            instance = wrapper(
                data.get("message", f"remote error {simple}"),
                code=data.get("code"),
                status=data.get("status"),
                severity=data.get("severity"),
                context=data.get("context") or {},
                hints=data.get("hints") or (),
                tb=data.get("traceback"),
                error_id=data.get("error_id"),
                retryable=data.get("retryable"),
                retry_after=data.get("retry_after"),
            )
            instance.context.set("original_exception", simple)
            return instance
        kwargs: Dict[str, Any] = {
            "message": data.get("message", ""),
            "code": data.get("code"),
            "status": data.get("status"),
            "severity": data.get("severity"),
            "context": data.get("context") or {},
            "hints": data.get("hints") or (),
            "tb": data.get("traceback"),
            "error_id": data.get("error_id"),
            "retryable": data.get("retryable"),
            "retry_after": data.get("retry_after"),
        }
        try:
            instance = klass(**{k: v for k, v in kwargs.items() if v is not None})
        except TypeError:
            instance = klass(kwargs["message"])
        assert isinstance(instance, KMCSBaseError)
        for cause in reversed(data.get("causes") or []):
            try:
                inner = builtins.Exception(str(cause.get("message", "")))
                inner.__kmcs_cause_name__ = cause.get("name")  # type: ignore[attr-defined]
                instance.__cause__ = inner
                break
            except Exception:
                continue
        return instance

    @classmethod
    def from_json(cls, text: str, **kwargs: Any) -> "KMCSBaseError":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SerializationError(f"error payload is not valid JSON: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise SerializationError("error payload must decode to a JSON object")
        return cls.from_dict(payload, **kwargs)

    @classmethod
    def wrap(cls, exc: BaseException, message: Optional[str] = None, **kwargs: Any) -> "KMCSBaseError":
        """Wrap an arbitrary exception into the KMCS hierarchy, preserving cause."""
        if isinstance(exc, KMCSBaseError):
            if message:
                exc.message = message
            return exc.with_context(**kwargs) if kwargs else exc
        tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        wrapped = cls(
            message or f"{type(exc).__name__}: {exc}",
            cause=exc,
            tb=tb_text,
            **kwargs,
        )
        wrapped.context.set("wrapped_type", f"{type(exc).__module__}.{type(exc).__qualname__}")
        return wrapped


def _safe_format(value: Any) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, str):
        return value
    return redact(value)


def _reconstruct_exception(module: str, name: str, payload: Dict[str, Any]) -> KMCSBaseError:
    return KMCSBaseError.from_dict(payload, prefer_name=f"{module}.{name}")


# ---------------------------------------------------------------------------
# intermediate bases
# ---------------------------------------------------------------------------


class KMCSRuntimeError(KMCSBaseError, RuntimeError):
    """Base for runtime/operational failures."""

    default_code = ErrorCode.OPERATION_FAILED
    category = "runtime"
    remediation = ("Retry the operation once; if it persists, capture the full log bundle.",)


class KMCSValueError(KMCSBaseError, ValueError):
    """Base for invalid-value failures (bad config, bad input, bad option)."""

    default_code = ErrorCode.INVALID_VALUE
    default_status = 400
    category = "validation"
    remediation = ("Correct the supplied value and re-run.",)


class KMCSTypeError(KMCSBaseError, TypeError):
    default_code = ErrorCode.INVALID_TYPE
    default_status = 400
    category = "validation"
    remediation = ("Fix the argument type at the call site.",)


class KMCSNotImplementedError(KMCSBaseError, NotImplementedError):
    default_code = ErrorCode.NOT_IMPLEMENTED
    default_status = 501
    category = "general"


class KMCSOSError(KMCSBaseError, OSError):
    default_code = ErrorCode.OPERATION_FAILED
    default_status = 500
    category = "resources"
    remediation = ("Check filesystem/network permissions and resource limits.",)


class KMCSUsageError(KMCSValueError):
    """The operator asked for something syntactically valid but nonsensical."""

    default_code = ErrorCode.INVALID_VALUE
    default_status = 400
    category = "cli"
    remediation = ("Run the command again with --help and correct the arguments.",)


class KMCSAssertionError(KMCSBaseError, AssertionError):
    """Internal invariant violated — always a defect in KMCS itself."""

    default_code = ErrorCode.INTERNAL_ERROR
    default_status = 500
    default_severity = ErrorSeverity.CRITICAL
    category = "internal"
    remediation = ("File a tool-defect report including the fingerprint and traceback.",)


# ---------------------------------------------------------------------------
# configuration family
# ---------------------------------------------------------------------------


class ConfigurationError(KMCSValueError):
    """Base class for all configuration subsystem failures."""

    default_code = ErrorCode.CONFIG_INVALID
    default_status = 400
    category = "configuration"
    remediation = (
        "Validate the file with the KMCS config validator.",
        "Compare against the shipped example configuration.",
        "Check that no legacy key names survived a version upgrade.",
    )


class ConfigParseError(ConfigurationError):
    """The configuration document could not be parsed at all."""

    default_code = ErrorCode.CONFIG_PARSE
    remediation = (
        "Check for tabs/indentation mistakes in structured blocks.",
        "Confirm the file is UTF-8 encoded and not truncated.",
    )


class ConfigValidationError(ConfigurationError):
    """Parsed fine, but violates the schema/invariants."""

    default_code = ErrorCode.CONFIG_SCHEMA
    remediation = (
        "Read the offending field list in the error details.",
        "Correct the value or restore the documented default.",
    )


class ConfigMigrationError(ConfigurationError):
    default_code = ErrorCode.CONFIG_MIGRATION
    remediation = ("Export the old configuration, then re-import it with the current schema.",)


class MissingRequiredFieldError(ConfigValidationError):
    default_code = ErrorCode.FIELD_REQUIRED
    remediation = ("Set the missing key explicitly, or point KMCS at a complete profile.",)

    def __init__(self, field: str = "", message: Optional[str] = None, **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.setdefault("missing_field", field)
        super().__init__(message or f"required configuration field '{field}' is missing", details=details, **kw)
        self.field = field


class UnknownOptionError(ConfigValidationError):
    default_code = ErrorCode.OPTION_UNKNOWN
    remediation = ("Remove the key, or install/register the plugin that provides it.",)

    def __init__(self, option: str = "", message: Optional[str] = None, suggestions: Sequence[str] = (), **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.setdefault("unknown_option", option)
        if suggestions:
            details.setdefault("did_you_mean", list(suggestions))
        suffix = f" (did you mean: {', '.join(suggestions)})" if suggestions else ""
        super().__init__(message or f"unknown configuration option '{option}'{suffix}", details=details, **kw)
        self.option = option
        self.suggestions = tuple(suggestions)


class SchemaVersionError(ConfigurationError):
    default_code = ErrorCode.VERSION_CONFLICT
    remediation = ("Upgrade KMCS, or migrate the configuration to the supported schema version.",)


class CircularReferenceError(ConfigurationError):
    default_code = ErrorCode.REFERENCE_CYCLE
    remediation = ("Break the include/profile cycle; KMCS profiles must form a DAG.",)

    def __init__(self, cycle: Sequence[str] = (), **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.setdefault("cycle", list(cycle))
        rendered = " -> ".join(cycle) if cycle else "unnamed cycle"
        super().__init__(f"circular configuration reference detected: {rendered}", details=details, **kw)
        self.cycle = tuple(cycle)


# ---------------------------------------------------------------------------
# authorization / policy family
# ---------------------------------------------------------------------------


class AuthorizationError(KMCSBaseError):
    """Raised when authorisation for a scan is absent or insufficient.

    KMCS refuses to operate against a target unless the researcher has
    recorded explicit authorisation.  This is a *hard* gate: it is raised
    before any fuzzing process is spawned.
    """

    default_code = ErrorCode.AUTHORIZATION_REQUIRED
    default_status = 403
    default_severity = ErrorSeverity.CRITICAL
    category = "authorization"
    retryable = False
    remediation = (
        "Record written authorisation from the asset owner on the target entry.",
        "Verify you are scanning assets inside your declared engagement scope.",
        "Never fuzz third-party infrastructure without explicit permission.",
    )


class ScopeExceededError(AuthorizationError):
    default_code = ErrorCode.SCOPE_EXCEEDED
    remediation = ("Restrict the campaign to the authorised paths/binaries in the scope definition.",)

    def __init__(self, requested: str = "", allowed: Sequence[str] = (), **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.setdefault("requested", requested)
        details.setdefault("allowed_scope", list(allowed)[:50])
        super().__init__(f"'{requested}' is outside the authorised scope", details=details, **kw)


class OutOfScopeTargetError(ScopeExceededError):
    default_code = ErrorCode.SCOPE_EXCEEDED


class ConsentRequiredError(AuthorizationError):
    default_code = ErrorCode.CONSENT_REQUIRED
    remediation = ("Acknowledge the authorisation statement explicitly before starting the campaign.",)


class LicenseCheckError(AuthorizationError):
    default_code = ErrorCode.LICENSE_CHECK_FAILED
    remediation = ("Ensure the target's licence permits security research and disclosure.",)


class PolicyViolationError(KMCSBaseError):
    """Raised when requested behaviour conflicts with KMCS's defensive charter.

    Examples: asking the tool to generate shellcode, weaponise a crash, evade
    detection, or scan without authorisation.  These requests are refused by
    design and are *not implemented anywhere* in KMCS.
    """

    default_code = ErrorCode.POLICY_VIOLATION
    default_status = 403
    default_severity = ErrorSeverity.CRITICAL
    category = "policy"
    retryable = False
    remediation = (
        "KMCS is a defensive research tool; offensive capabilities are intentionally absent.",
        "Use the crash finding data to write a responsible disclosure report instead.",
    )

    def __init__(self, message: Any = "requested operation violates the KMCS defensive-use policy", **kw: Any) -> None:
        super().__init__(message, **kw)


class ProhibitedCapabilityError(PolicyViolationError):
    default_code = ErrorCode.CAPABILITY_PROHIBITED
    remediation = (
        "Remove the request; exploitation primitives are outside KMCS's scope by design.",
        "Use crash analysis, reproduction and reporting features instead.",
    )


# ---------------------------------------------------------------------------
# environment / external tool family
# ---------------------------------------------------------------------------


class EnvironmentErrorDetail(KMCSBaseError):
    """Base for problems with the host toolchain.

    Named ``EnvironmentErrorDetail`` to avoid shadowing the builtin
    ``EnvironmentError`` while keeping the semantics obvious.
    """

    default_code = ErrorCode.UNAVAILABLE
    default_status = 503
    category = "environment"
    retryable = False
    remediation = (
        "Install the missing component and re-run the KMCS environment probe.",
        "Point KMCS at a non-standard binary via the tool-path settings.",
    )


class ToolNotFoundError(EnvironmentErrorDetail):
    default_code = ErrorCode.TOOL_MISSING
    default_status = 503
    remediation = (
        "Install the tool (package manager or build from source).",
        "Set the explicit executable path in the KMCS configuration.",
        "Re-run the environment probe; KMCS reports unavailability rather than faking results.",
    )

    def __init__(self, tool: str = "", message: Optional[str] = None, *, searched: Sequence[str] = (), version_hint: str = "", **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.setdefault("tool", tool)
        if searched:
            details.setdefault("searched_paths", [str(p) for p in searched][:20])
        if version_hint:
            details.setdefault("expected", version_hint)
        super().__init__(
            message or f"required tool '{tool}' was not found on PATH; KMCS will not simulate its output",
            tool=tool,
            details=details,
            **kw,
        )
        self.tool = tool
        self.searched = tuple(str(p) for p in searched)


class ToolVersionError(EnvironmentErrorDetail):
    default_code = ErrorCode.TOOL_VERSION
    remediation = ("Upgrade/downgrade the tool so its version satisfies the requirement.",)

    def __init__(self, tool: str = "", found: str = "", required: str = "", **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.update({"tool": tool, "found_version": found, "required_version": required})
        super().__init__(f"{tool} version '{found}' does not satisfy requirement '{required}'", tool=tool, details=details, **kw)
        self.tool = tool
        self.found = found
        self.required = required


class CompilerNotFoundError(ToolNotFoundError):
    default_code = ErrorCode.COMPILER_MISSING
    remediation = ("Install clang/clang++ (LLVM) and/or gcc, then rebuild the target.",)


class SanitizerUnavailableError(ToolNotFoundError):
    default_code = ErrorCode.SANITIZER_UNAVAILABLE
    remediation = (
        "Compile the target with the sanitizer flag (e.g. -fsanitize=address).",
        "Confirm the compiler runtime libraries are installed.",
    )


class FuzzerUnavailableError(ToolNotFoundError):
    default_code = ErrorCode.FUZZER_UNAVAILABLE
    remediation = ("Install AFL++ / libFuzzer / Honggfuzz, or select an available engine.",)


class DebuggerUnavailableError(ToolNotFoundError):
    default_code = ErrorCode.DEBUGGER_UNAVAILABLE
    remediation = ("Install gdb (or lldb) so KMCS can collect post-mortem traces for findings.",)


# ---------------------------------------------------------------------------
# targets / build family
# ---------------------------------------------------------------------------


class TargetError(KMCSBaseError):
    default_code = ErrorCode.TARGET_INVALID
    category = "targets"
    remediation = ("Re-register the target with correct paths and metadata.")


class TargetNotFoundError(TargetError):
    default_code = ErrorCode.TARGET_NOT_FOUND
    default_status = 404

    def __init__(self, target: str = "", **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.setdefault("target", target)
        super().__init__(f"target '{target}' is not registered", target=target, details=details, **kw)
        self.target_name = target


class TargetInvalidError(TargetError):
    default_code = ErrorCode.TARGET_INVALID
    remediation = ("Confirm the binary exists, is executable and matches the declared architecture.",)


class BuildError(KMCSBaseError):
    default_code = ErrorCode.BUILD_FAILED
    category = "targets"
    remediation = (
        "Reproduce the failure manually with the printed compiler command line.",
        "Check that all build dependencies and headers are installed.",
    )

    def __init__(self, message: Any = "target build failed", *, exit_code: Optional[int] = None, log_path: Optional[str] = None, command: Optional[str] = None, **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        if exit_code is not None:
            details.setdefault("exit_code", exit_code)
        if log_path:
            details.setdefault("build_log", log_path)
        if command:
            details.setdefault("command", _clip(command, 1000))
        super().__init__(message, details=details, **kw)
        self.exit_code = exit_code
        self.log_path = log_path
        self.command = command


class InstrumentationError(BuildError):
    default_code = ErrorCode.INSTRUMENTATION_FAILED
    remediation = (
        "Use afl-clang-fast/afl-clang-lto for AFL++ coverage instrumentation.",
        "Address any AFL++ warnings about core_pattern or the CPU governor before retrying.",
    )


class HarnessError(KMCSBaseError):
    default_code = ErrorCode.HARNESS_FAILED
    category = "targets"
    remediation = ("Run the harness manually with one seed input to isolate the fault.")


class HarnessTimeoutError(HarnessError):
    default_code = ErrorCode.TIMEOUT
    retryable = True
    retry_after_seconds = 2.0


# ---------------------------------------------------------------------------
# fuzzing family
# ---------------------------------------------------------------------------


class FuzzingError(KMCSBaseError):
    default_code = ErrorCode.OPERATION_FAILED
    category = "fuzzing"
    remediation = ("Review the fuzzer log for the first fatal diagnostic line.")


class FuzzerStartupError(FuzzingError):
    default_code = ErrorCode.FUZZER_STARTUP_FAILED
    remediation = (
        "Inspect the engine's stderr for the first fatal line.",
        "Confirm the instrumented binary runs standalone before fuzzing.",
        "Apply AFL++ system prerequisites (core_pattern, performance governor) it prints.",
    )


class FuzzerCrashedError(FuzzingError):
    """The fuzzing engine itself died (as opposed to the target crashing)."""

    default_code = ErrorCode.FUZZER_CRASHED
    remediation = ("Collect the engine's stderr, then restart the campaign worker.",)


class FuzzerTimeoutError(FuzzingError):
    default_code = ErrorCode.TIMEOUT
    retryable = True


class FuzzerAlreadyRunningError(FuzzingError):
    default_code = ErrorCode.FUZZER_ALREADY_RUNNING
    default_status = 409
    remediation = ("Stop the existing session first, or attach the dashboard to it instead.")


class FuzzerNotRunningError(FuzzingError):
    default_code = ErrorCode.FUZZER_NOT_RUNNING
    default_status = 409


class CoverageError(FuzzingError):
    default_code = ErrorCode.COVERAGE_FAILED
    remediation = ("Re-instrument the target; verify llvm-profdata/llvm-cov availability.")


class EngineSelectionError(FuzzingError):
    default_code = ErrorCode.ENGINE_SELECTION_FAILED
    remediation = ("List available engines and pick one that is actually installed.")


# ---------------------------------------------------------------------------
# corpus family
# ---------------------------------------------------------------------------


class CorpusError(KMCSBaseError):
    default_code = ErrorCode.CORPUS_INVALID
    category = "corpus"
    remediation = ("Re-validate the corpus with the KMCS corpus validator.")


class CorpusEmptyError(CorpusError):
    default_code = ErrorCode.CORPUS_EMPTY
    default_status = 409
    remediation = ("Provide at least one valid seed input; fuzzers need a starting corpus.",)


class CorpusValidationError(CorpusError):
    default_code = ErrorCode.CORPUS_INVALID
    remediation = ("Run the corpus validator to identify rejected files and why.")


class SeedImportError(CorpusError):
    default_code = ErrorCode.SEED_IMPORT_FAILED
    remediation = ("Check file permissions and disk quota in the corpus directory.")


class InputTooLargeError(CorpusError):
    default_code = ErrorCode.INPUT_TOO_LARGE
    default_status = 413

    def __init__(self, size: int = 0, limit: int = 0, path: Optional[str] = None, **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.update({"size_bytes": size, "limit_bytes": limit, "path": path})
        super().__init__(
            f"input of {size} bytes exceeds configured limit of {limit} bytes",
            input_path=path,
            details=details,
            **kw,
        )
        self.size = size
        self.limit = limit


# ---------------------------------------------------------------------------
# crash analysis family
# ---------------------------------------------------------------------------


class CrashError(KMCSBaseError):
    default_code = ErrorCode.CRASH_PARSE_FAILED
    category = "analysis"
    remediation = ("Retain the raw sanitizer output alongside the parsed record for auditing.")


class CrashParseError(CrashError):
    default_code = ErrorCode.CRASH_PARSE_FAILED
    remediation = ("Keep the raw sanitizer output; extend the parser only from real samples.")


class CrashClassificationError(CrashError):
    default_code = ErrorCode.CLASSIFICATION_FAILED


class FingerprintError(CrashError):
    default_code = ErrorCode.FINGERPRINT_FAILED


class DeduplicationError(CrashError):
    default_code = ErrorCode.DEDUPLICATION_FAILED


class SeverityAssessmentError(CrashError):
    default_code = ErrorCode.SEVERITY_FAILED


class ReproductionError(CrashError):
    default_code = ErrorCode.REPRODUCTION_FAILED
    category = "reproduction"
    retryable = True
    remediation = ("Re-run under the exact sanitizer options and environment recorded in the finding.")


class MinimizationError(CrashError):
    default_code = ErrorCode.MINIMIZATION_FAILED
    remediation = ("Reduce the per-attempt timeout, or minimise from a smaller parent input.")


# ---------------------------------------------------------------------------
# jobs / workers family
# ---------------------------------------------------------------------------


class JobError(KMCSBaseError):
    default_code = ErrorCode.OPERATION_FAILED
    category = "jobs"
    remediation = ("Inspect the job state history in the dashboard.")


class JobNotFoundError(JobError):
    default_code = ErrorCode.JOB_NOT_FOUND
    default_status = 404

    def __init__(self, job_id: str = "", **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.setdefault("job_id", job_id)
        super().__init__(f"job '{job_id}' does not exist", job=job_id, details=details, **kw)
        self.job_id = job_id


class JobStateError(JobError):
    default_code = ErrorCode.JOB_STATE_INVALID
    default_status = 409
    remediation = ("Query the job's state history to see why the transition was rejected.")


class JobCancelledError(JobError):
    default_code = ErrorCode.CANCELLED
    default_status = 499


class JobTimeoutError(JobError):
    default_code = ErrorCode.JOB_TIMEOUT
    retryable = True


class JobDependencyError(JobError):
    default_code = ErrorCode.JOB_DEPENDENCY_FAILED
    remediation = ("Resolve the failing prerequisite job before re-queueing this one.")


class WorkerError(JobError):
    default_code = ErrorCode.OPERATION_FAILED
    category = "jobs"


class WorkerLostError(WorkerError):
    default_code = ErrorCode.WORKER_LOST
    retryable = True
    remediation = ("Restart the scheduler; the lost worker's jobs will be requeued automatically.")


class SchedulerError(JobError):
    default_code = ErrorCode.SCHEDULER_FAILED
    retryable = True


# ---------------------------------------------------------------------------
# database family
# ---------------------------------------------------------------------------


class DatabaseError(KMCSBaseError):
    default_code = ErrorCode.DB_FAILED
    category = "database"
    remediation = ("Check that the SQLite file is writable and not locked by another process.")


class MigrationError(DatabaseError):
    default_code = ErrorCode.DB_MIGRATION_FAILED
    remediation = ("Back up the database, then run migrations from a clean checkout.")


class ConstraintViolationError(DatabaseError):
    default_code = ErrorCode.DB_CONSTRAINT
    default_status = 409


class RecordNotFoundError(DatabaseError):
    default_code = ErrorCode.RECORD_NOT_FOUND
    default_status = 404


class SessionError(DatabaseError):
    default_code = ErrorCode.DB_FAILED
    retryable = True


# ---------------------------------------------------------------------------
# events family
# ---------------------------------------------------------------------------


class EventError(KMCSBaseError):
    default_code = ErrorCode.EVENT_PUBLISH_FAILED
    category = "events"


class EventPublishError(EventError):
    default_code = ErrorCode.EVENT_PUBLISH_FAILED
    retryable = True


class SubscriberError(EventError):
    default_code = ErrorCode.SUBSCRIBER_FAILED
    remediation = ("The subscriber raised; check its isolated traceback in the event log.")


class EventLoopClosedError(EventError):
    default_code = ErrorCode.EVENT_LOOP_CLOSED
    default_status = 409


# ---------------------------------------------------------------------------
# reporting family
# ---------------------------------------------------------------------------


class ReportError(KMCSBaseError):
    default_code = ErrorCode.REPORT_FAILED
    category = "reporting"


class TemplateError(ReportError):
    default_code = ErrorCode.TEMPLATE_FAILED


class ExportError(ReportError):
    default_code = ErrorCode.EXPORT_FAILED
    remediation = ("Verify the output directory is writable and has free space.")


class SerializationError(ReportError):
    default_code = ErrorCode.SERIALIZATION_FAILED


# ---------------------------------------------------------------------------
# resource family
# ---------------------------------------------------------------------------


class ResourceError(KMCSOSError):
    default_code = ErrorCode.OPERATION_FAILED
    category = "resources"


class DiskSpaceError(ResourceError):
    default_code = ErrorCode.DISK_FULL
    default_status = 507
    retryable = True

    def __init__(self, path: str = "", required: int = 0, available: int = 0, **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.update({"path": path, "required_bytes": required, "available_bytes": available})
        super().__init__(
            f"insufficient disk space at {path}: need {required} bytes, have {available}",
            details=details,
            **kw,
        )


class MemoryLimitError(ResourceError):
    default_code = ErrorCode.MEMORY_LIMIT
    default_status = 507
    retryable = True


class ProcessLimitError(ResourceError):
    default_code = ErrorCode.PROCESS_LIMIT
    default_status = 503
    retryable = True


class PermissionDeniedError(ResourceError):
    default_code = ErrorCode.PERMISSION_DENIED
    default_status = 403
    remediation = ("Adjust filesystem ownership, or run KMCS as a user with access to the workspace.")

    def __init__(self, path: str = "", mode: str = "rw", **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.update({"path": path, "mode": mode})
        super().__init__(f"permission denied: cannot open '{path}' for {mode}", input_path=path, details=details, **kw)


class FileLockedError(ResourceError):
    default_code = ErrorCode.FILE_LOCKED
    default_status = 423
    retryable = True
    retry_after_seconds = 1.0


# ---------------------------------------------------------------------------
# pipeline family
# ---------------------------------------------------------------------------


class PipelineError(KMCSBaseError):
    default_code = ErrorCode.PIPELINE_FAILED
    category = "pipeline"
    remediation = ("Re-run the failed stage in isolation to reproduce it.")


class StageError(PipelineError):
    default_code = ErrorCode.PIPELINE_FAILED

    def __init__(self, stage: str = "", message: Optional[str] = None, **kw: Any) -> None:
        details = dict(kw.pop("details", None) or {})
        details.setdefault("stage", stage)
        super().__init__(message or f"pipeline stage '{stage}' failed", stage=stage, details=details, **kw)
        self.stage_name = stage


class StageSkippedError(StageError):
    default_code = ErrorCode.STAGE_SKIPPED
    default_status = 409


class RollbackError(PipelineError):
    default_code = ErrorCode.ROLLBACK_FAILED
    default_severity = ErrorSeverity.CRITICAL


class UnsupportedOperationError(KMCSNotImplementedError):
    default_code = ErrorCode.UNSUPPORTED
    default_status = 501
    remediation = ("Track this capability in the phase plan; it is intentionally not built yet.")


# ---------------------------------------------------------------------------
# compatibility aliases
# ---------------------------------------------------------------------------
#
# Earlier design drafts referred to the root of the taxonomy as
# ``KMCSException`` and exposed a dedicated invalid-value error.  Both names
# are part of the public contract now, so they alias onto the canonical
# classes defined above instead of introducing parallel hierarchies:
#
#   KMCSException      -> KMCSBaseError   (root of every KMCS failure)
#   InvalidValueError  -> KMCSValueError  (tolerant enum / value parsing)
#
# Aliasing (rather than subclassing) keeps ``except KMCSBaseError`` working
# for code that raises either spelling, and keeps the registry, serialisation
# and formatting utilities single-sourced.

#: Alias kept for API compatibility with earlier core drafts.
KMCSException = KMCSBaseError

#: Raised by :mod:`kmcs.core.models` when a value cannot be coerced into one
#: of the domain enumerations (severity, engine kind, sanitizer kind, ...).
InvalidValueError = KMCSValueError


# ---------------------------------------------------------------------------
# deserialisation & formatting utilities
# ---------------------------------------------------------------------------

_BUILTIN_EXCEPTION_MAP: Dict[str, Type[BaseException]] = {
    name: getattr(builtins, name)
    for name in (
        "Exception", "ValueError", "TypeError", "RuntimeError", "KeyError", "IndexError",
        "AttributeError", "OSError", "IOError", "FileNotFoundError", "PermissionError",
        "NotImplementedError", "ZeroDivisionError", "StopIteration", "TimeoutError",
        "ConnectionError", "InterruptedError", "IsADirectoryError", "NotADirectoryError",
        "RecursionError", "MemoryError", "NameError", "ImportError", "ModuleNotFoundError",
        "EOFError", "ArithmeticError", "LookupError", "SystemError", "BufferError",
    )
    if isinstance(getattr(builtins, name, None), type) and issubclass(getattr(builtins, name), BaseException)
}


def exception_from_payload(
    payload: Mapping[str, Any],
    *,
    fallback: Type[KMCSBaseError] = KMCSBaseError,
) -> KMCSBaseError:
    """Rebuild an exception instance from :meth:`KMCSBaseError.to_dict` output."""
    return KMCSBaseError.from_dict(dict(payload), prefer_name=payload.get("name") or payload.get("type"), fallback=fallback)


_STYLE_COLOURS = {
    ErrorSeverity.DEBUG: "\033[90m",
    ErrorSeverity.INFO: "\033[36m",
    ErrorSeverity.NOTICE: "\033[36m",
    ErrorSeverity.WARNING: "\033[33m",
    ErrorSeverity.ERROR: "\033[31m",
    ErrorSeverity.CRITICAL: "\033[1;31m",
    ErrorSeverity.FATAL: "\033[97;41m",
}


def format_exception(
    exc: BaseException,
    *,
    style: str = "text",
    color: bool = False,
    show_traceback: bool = True,
    show_context: bool = True,
    indent: int = 0,
    max_frames: int = 24,
) -> str:
    """Render *exc* as text, markdown, JSON or ANSI-coloured console output.

    Non-KMCS exceptions are handled gracefully: they are presented generically
    so nothing in the display path can crash while reporting a crash.
    """
    style = (style or "text").lower()
    pad = " " * max(0, int(indent))
    if isinstance(exc, KMCSBaseError):
        headline = f"{type(exc).__name__} [{exc.code.value}] ({exc.severity.name})"
        body = exc.message
        hints: List[str] = list(exc.hints)
        context: Optional[ErrorContext] = exc.context
    else:
        headline = f"{type(exc).__name__}"
        body = _clip(_redact_string(str(exc)), 4096) or "(no message)"
        hints = []
        context = None

    if style in ("json", "application/json"):
        data = (
            exc.to_dict(include_traceback=show_traceback)
            if isinstance(exc, KMCSBaseError)
            else {
                "name": type(exc).__name__,
                "type": f"{type(exc).__module__}.{type(exc).__qualname__}",
                "message": body,
                "code": ErrorCode.INTERNAL_ERROR.value,
                "severity": ErrorSeverity.ERROR.name,
            }
        )
        return pad + json.dumps(data, indent=2, sort_keys=True, default=str, ensure_ascii=False)

    if style in ("md", "markdown"):
        if isinstance(exc, KMCSBaseError):
            return pad + exc.to_markdown()
        return pad + "\n".join([f"### {headline}", "", f"* **Message:** {body}"])

    reset, bold, dim = ("\033[0m", "\033[1m", "\033[2m") if color else ("", "", "")
    tint = _STYLE_COLOURS.get(getattr(exc, "severity", ErrorSeverity.ERROR), "") if color else ""
    off = reset if color else ""

    out: List[str] = [f"{pad}{bold}{tint}x {headline}{off}"]
    for line in body.splitlines() or [""]:
        out.append(f"{pad}  {line}")
    if isinstance(exc, KMCSBaseError):
        out.append(f"{pad}{dim}  error-id: {exc.error_id} | fingerprint: {exc.fingerprint}{off}")
    if show_context and context is not None:
        summary = context.summary_line()
        if summary:
            out.append(f"{pad}  where: {summary}")
        for key, value in sorted(context.values.items(), key=lambda kv: str(kv[0])):
            out.append(f"{pad}    {key} = {redact(value)}")
    if hints:
        out.append(f"{pad}  next steps:")
        out += [f"{pad}    - {hint}" for hint in hints]
    for cause in getattr(exc, "cause_chain", []) or []:
        out.append(f"{pad}  caused by: {cause['name']}: {cause['message']}")
    if show_traceback:
        tb_text = getattr(exc, "traceback_text", "") if isinstance(exc, KMCSBaseError) else ""
        if not tb_text:
            tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        frames = [ln for ln in tb_text.splitlines() if ln.strip()]
        if frames:
            shown = frames[-max(1, max_frames) :]
            out.append(f"{pad}  traceback (last {len(shown)} lines):")
            out += [f"{pad}    {frame}" for frame in shown]
    return "\n".join(out)


_LAST_ERRORS: Deque[KMCSBaseError] = deque(maxlen=128)


def get_last_errors(
    limit: int = 10,
    *,
    name: Optional[str] = None,
    code: Optional[Union[ErrorCode, str]] = None,
) -> List[KMCSBaseError]:
    """Most recent recorded KMCS errors (newest first), optionally filtered."""
    items: Iterable[KMCSBaseError] = list(_LAST_ERRORS)
    if name:
        items = [e for e in items if type(e).__name__ == name]
    if code is not None:
        resolved = ErrorCode.from_name(code)
        items = [e for e in items if e.code == resolved]
    return list(reversed(list(items)))[: max(0, int(limit))]


def record_error(exc: BaseException) -> BaseException:
    """Observe *exc* in the registry without altering control flow."""
    exception_registry.observe(exc)
    if isinstance(exc, KMCSBaseError):
        _LAST_ERRORS.append(copy.copy(exc))
    return exc


def clear_error_history() -> None:
    _LAST_ERRORS.clear()
    exception_registry.reset_stats()


# ---------------------------------------------------------------------------
# top-level hooks (so unexpected failures become structured errors)
# ---------------------------------------------------------------------------

_HOOKS_INSTALLED = False
_PREVIOUS_GLOBAL_HOOK: Optional[Callable[..., Any]] = None
_PREVIOUS_THREAD_HOOK: Optional[Callable[..., Any]] = None
_UNCAUGHT: Deque[Dict[str, Any]] = deque(maxlen=64)


def _build_uncaught_record(exc_type: Any, exc_value: Any, tb: Any, source: str) -> Dict[str, Any]:
    if isinstance(exc_value, KMCSBaseError):
        exc_value.attach_traceback(tb).record()
        payload = exc_value.to_dict(include_traceback=True)
    else:
        text = "".join(traceback.format_exception(exc_type, exc_value, tb))
        original_name = getattr(exc_type, "__name__", str(exc_type))
        wrapped = KMCSRuntimeError(
            _clip(_redact_string(f"unexpected {original_name}: {exc_value}"), 4000),
            code=ErrorCode.INTERNAL_ERROR,
            component="kmcs.unhandled",
            details={"source": source, "original_type": original_name},
            tb=text,
        ).record()
        payload = wrapped.to_dict(include_traceback=True)
    payload["source"] = source
    return payload


def install_excepthooks(
    *,
    wrap_unexpected: bool = True,
    on_uncaught: Optional[Callable[[Dict[str, Any]], None]] = None,
    echo_to_stderr: bool = True,
) -> Dict[str, Any]:
    """Install global ``sys.excepthook`` / ``threading.excepthook`` handlers.

    Uncaught exceptions are converted into structured records so the CLI/GUI
    can display them consistently and so a stray builtin error deep inside a
    helper never silently kills a fuzzing supervisor.

    Returns a descriptor of what was installed (useful in tests/diagnostics).
    """
    global _HOOKS_INSTALLED, _PREVIOUS_GLOBAL_HOOK, _PREVIOUS_THREAD_HOOK

    def new_excepthook(exc_type: Any, exc_value: Any, tb: Any) -> None:
        try:
            record = _build_uncaught_record(exc_type, exc_value, tb, "main-thread")
            _UNCAUGHT.append(record)
            if on_uncaught is not None:
                on_uncaught(record)
            elif echo_to_stderr:
                subject = exc_value if isinstance(exc_value, BaseException) else KMCSRuntimeError(str(exc_value))
                sys.stderr.write(format_exception(subject, style="text", color=sys.stderr.isatty()) + "\n")
        except Exception:
            traceback.print_exc()

    def new_threadhook(args: Any) -> None:
        try:
            ident = getattr(getattr(args, "thread", None), "ident", None) or 0
            record = _build_uncaught_record(args.exc_type, args.exc_value, args.exc_traceback, f"thread-{ident}")
            _UNCAUGHT.append(record)
            if on_uncaught is not None:
                on_uncaught(record)
            elif echo_to_stderr:
                sys.stderr.write(str(record.get("message", "uncaught thread error")) + "\n")
        except Exception:
            traceback.print_exc()

    if wrap_unexpected:
        if _PREVIOUS_GLOBAL_HOOK is None:
            _PREVIOUS_GLOBAL_HOOK = sys.excepthook
        sys.excepthook = new_excepthook
        try:
            if _PREVIOUS_THREAD_HOOK is None:
                _PREVIOUS_THREAD_HOOK = threading.excepthook
            threading.excepthook = new_threadhook
        except AttributeError:  # pragma: no cover - very old interpreters
            pass
        _HOOKS_INSTALLED = True

    return {
        "installed": _HOOKS_INSTALLED,
        "wrap_unexpected": wrap_unexpected,
        "buffer_size": _UNCAUGHT.maxlen,
        "previous_global_hook": getattr(_PREVIOUS_GLOBAL_HOOK, "__name__", repr(_PREVIOUS_GLOBAL_HOOK)),
        "previous_thread_hook": getattr(_PREVIOUS_THREAD_HOOK, "__name__", repr(_PREVIOUS_THREAD_HOOK)),
    }


def uninstall_excepthooks() -> bool:
    """Restore interpreter defaults. Returns ``True`` if hooks were active."""
    global _HOOKS_INSTALLED, _PREVIOUS_GLOBAL_HOOK, _PREVIOUS_THREAD_HOOK
    if not _HOOKS_INSTALLED:
        return False
    if _PREVIOUS_GLOBAL_HOOK is not None:
        sys.excepthook = _PREVIOUS_GLOBAL_HOOK
    else:
        sys.excepthook = sys.__excepthook__
    if _PREVIOUS_THREAD_HOOK is not None:
        try:
            threading.excepthook = _PREVIOUS_THREAD_HOOK
        except Exception:  # pragma: no cover
            pass
    _PREVIOUS_GLOBAL_HOOK = None
    _PREVIOUS_THREAD_HOOK = None
    _HOOKS_INSTALLED = False
    return True


def uncaught_errors(limit: int = 10) -> List[Dict[str, Any]]:
    """Recently captured uncaught exceptions as serialisable dicts."""
    return list(_UNCAUGHT)[-max(0, int(limit)) :]


def excepthooks_active() -> bool:
    return _HOOKS_INSTALLED


# ---------------------------------------------------------------------------
# bulk registration of the catalogue defined above
# ---------------------------------------------------------------------------

_DEFAULT_REMEDIATION: Dict[str, Tuple[str, ...]] = {
    "KMCSBaseError": ("Inspect the structured error payload for the failing stage.",),
    "KMCSValueError": ("Correct the supplied value and re-run.",),
    "KMCSTypeError": ("Fix the argument type at the call site.",),
    "KMCSNotImplementedError": ("Implement or enable the feature in a later phase.",),
    "FuzzingError": ("Review the fuzzer log for the first fatal diagnostic.",),
    "CorpusError": ("Re-validate the corpus with the KMCS corpus validator.",),
    "CrashError": ("Retain the raw sanitizer output for manual review.",),
    "JobError": ("Inspect the job state history in the dashboard.",),
    "DatabaseError": ("Verify the SQLite path is writable and unlocked.",),
    "EventError": ("Check subscriber health; subscribers are isolated by design.",),
    "ReportError": ("Regenerate the report after fixing the input data.",),
    "ResourceError": ("Free capacity or raise the configured limits.",),
    "PipelineError": ("Re-run the failed stage in isolation to reproduce it.",),
    "TargetError": ("Re-register the target with correct paths and metadata.",),
    "EnvironmentErrorDetail": ("Run the KMCS environment probe again after installing components.",),
    "AuthorizationError": ("Do not proceed without documented authorisation.",),
    "PolicyViolationError": ("Refuse the request; KMCS implements defensive analysis only.",),
}


def _register_all() -> Dict[str, int]:
    registered = 0
    skipped_foreign = 0
    module = sys.modules[__name__]
    for name in __all__:
        obj = getattr(module, name, None)
        if isinstance(obj, type) and issubclass(obj, BaseException):
            if obj.__module__ != __name__:
                skipped_foreign += 1
                continue
            hints = tuple(obj.remediation) if getattr(obj, "remediation", None) else _DEFAULT_REMEDIATION.get(name, ())
            exception_registry.register(
                obj,
                code=getattr(obj, "default_code", ErrorCode.INTERNAL_ERROR),
                status=getattr(obj, "default_status", 500),
                category=getattr(obj, "category", None) or _category_for(name),
                retryable=getattr(obj, "retryable", False),
                remediation=hints,
                description=inspect_doc_summary(obj),
                override=True,
            )
            registered += 1
    for builtin_name, builtin_cls in _BUILTIN_EXCEPTION_MAP.items():
        if builtin_name not in exception_registry:
            exception_registry.register(
                builtin_cls,
                code=ErrorCode.INTERNAL_ERROR,
                status=500,
                category="builtin",
                retryable=False,
                remediation=("An unhandled builtin escaped KMCS; report it as a tool defect.",),
                description=inspect_doc_summary(builtin_cls),
                override=False,
            )
    return {
        "registered": registered,
        "skipped_foreign": skipped_foreign,
        "builtins": len(_BUILTIN_EXCEPTION_MAP),
        "total_records": len(exception_registry),
    }


_REGISTRATION_SUMMARY = _register_all()


def error_catalogue_summary() -> Dict[str, Any]:
    """Programmatic view of the exception taxonomy (handy for docs/tests)."""
    return {
        **_REGISTRATION_SUMMARY,
        "total_codes": len(list(ErrorCode)),
        "severities": [s.name for s in ErrorSeverity],
        "categories": exception_registry.categories(),
    }
