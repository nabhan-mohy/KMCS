# KMCS Regression Tests
# =====================
#
# Persistence and re-testing of confirmed findings.
#
# Where :mod:`kmcs.reproduction.runner` answers "does this input still
# reproduce?", this module answers a longer-term question: "has the
# behavior of any previously confirmed finding changed since we last
# checked?"
#
# A *regression case* is a saved pairing of an input, the reference
# behaviour that input was observed to produce, and the metadata that
# describes where it came from. Regression cases live on disk in a
# stable, human-inspectable layout. Each case can be re-tested any
# number of times against any target; every re-test appends to the
# case's history.
#
# Design principles
# -----------------
#
# * **Stable layout.** A regression case is stored under
#   ``<root>/<case-id>/`` as a directory containing:
#
#       case.json      — case metadata (reference, provenance, tags)
#       input.bin      — the exact input bytes
#       history.jsonl  — one JSON record per completed regression run
#
#   The layout is stable across KMCS versions. Tools that do not
#   import this module can still inspect and archive cases.
#
# * **Content addressing.** A case is identified by the SHA-256
#   digest of its input. Registering the same input twice produces
#   the same case ID. This makes the store idempotent: callers can
#   register without worrying about duplicates.
#
# * **Delegation.** Regression re-tests use the same machinery as
#   :class:`~kmcs.reproduction.runner.Reproducer`. This module does
#   not duplicate process execution, crash parsing, or fingerprint
#   extraction. It calls into the runner, which calls into the
#   validator, which calls into the crash parser.
#
# * **History is append-only.** A case's history is never rewritten
#   or pruned by the module. Callers who need to retire a case
#   explicitly delete it via :meth:`RegressionStore.remove`.
#
# * **Classification is explicit.** Each re-test produces one of
#   PASSED, FAILED, CHANGED, or ERROR. The distinction between FAILED
#   and CHANGED matters: FAILED means "the reference behaviour no
#   longer occurs" (the bug has been fixed), while CHANGED means "a
#   different behaviour now occurs" (something new is happening).
#   Both are actionable, but they call for different responses.
#
# Workflow
# --------
#
# 1. Fuzzing finds a crash and saves the input.
# 2. The reproduction runner confirms the input reproduces the crash.
# 3. The caller registers the input with :meth:`RegressionStore.register`,
#    passing the confirmed :class:`ReproductionResult`. The reference
#    signature from that result is stored verbatim.
# 4. Later — after the target has been rebuilt, patched, or ported —
#    the caller runs :meth:`RegressionRunner.run_case` or
#    :meth:`RegressionRunner.run_all`.
# 5. For each case, the runner compares the current outcome against
#    the stored reference and appends a :class:`RegressionRun`
#    record to the case's history.
# 6. The aggregate :class:`RegressionSuiteResult` summarises which
#    cases passed, which failed, which changed, and which errored.
#
# Threading
# ---------
#
# :class:`RegressionStore` is safe to use from multiple threads.
# :class:`RegressionRunner` serialises its internal :class:`Reproducer`
# calls; callers who want parallel regression runs should construct
# one runner per thread, all pointed at the same store.
#
# Compatibility
# ------------
#
# Python 3.10+.

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TYPE_CHECKING,
    Union,
)

from ..core.exceptions import KMCSException
from ..core.events import EventBus, Event, EventType, get_default_bus
from ..core.config import KMCSConfig, get_default_config


# ---------------------------------------------------------------------------
# Optional subsystem imports
# ---------------------------------------------------------------------------
#
# The regression layer delegates execution to the reproduction runner
# and reference matching to the corpus validator. Both are imported
# defensively; a missing subsystem is reported when the affected API
# is invoked, never silently ignored.

try:
    from .runner import (
        Reproducer,
        ReproductionResult,
        ReproductionStatus,
        ReferenceSignature,
        ReproductionConfig,
        ReproductionMode,
    )
    _HAVE_RUNNER = True
except ImportError as exc:  # pragma: no cover - depends on layout
    Reproducer = None  # type: ignore[assignment]
    ReproductionResult = None  # type: ignore[assignment]
    ReproductionStatus = None  # type: ignore[assignment]
    ReferenceSignature = None  # type: ignore[assignment]
    ReproductionConfig = None  # type: ignore[assignment]
    ReproductionMode = None  # type: ignore[assignment]
    _HAVE_RUNNER = False
    _RUNNER_IMPORT_ERROR = str(exc)
else:
    _RUNNER_IMPORT_ERROR = None


try:
    from ..corpus.validator import (
        InputValidator,
        TargetSpec,
        ExpectedBehavior,
        ValidationOutcome,
        OutcomeKind,
        ValidatorError,
    )
    _HAVE_VALIDATOR = True
except ImportError as exc:  # pragma: no cover
    InputValidator = None  # type: ignore[assignment]
    TargetSpec = None  # type: ignore[assignment]
    ExpectedBehavior = None  # type: ignore[assignment]
    ValidationOutcome = None  # type: ignore[assignment]
    OutcomeKind = None  # type: ignore[assignment]
    ValidatorError = Exception  # type: ignore[assignment,misc]
    _HAVE_VALIDATOR = False
    _VALIDATOR_IMPORT_ERROR = str(exc)
else:
    _VALIDATOR_IMPORT_ERROR = None


if TYPE_CHECKING:
    from ..corpus.manager import CorpusEntry


__all__ = [
    "RegressionStore",
    "RegressionRunner",
    "RegressionCase",
    "RegressionReference",
    "RegressionRun",
    "RegressionResult",
    "RegressionSuiteResult",
    "RegressionStatus",
    "RegressionRunStatus",
    "RegressionStats",
    "RegressionError",
    "CaseNotFoundError",
    "CaseAlreadyExistsError",
    "CaseCorruptedError",
    "StoreNotWritableError",
    "RegressionRunnerNotAvailableError",
    "DEFAULT_CASE_DIR_NAME",
    "DEFAULT_CASE_FILE_NAME",
    "DEFAULT_INPUT_FILE_NAME",
    "DEFAULT_HISTORY_FILE_NAME",
    "DEFAULT_HISTORY_LIMIT",
    "DEFAULT_MAX_INPUT_BYTES",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Default subdirectory name used inside the store root.
DEFAULT_CASE_DIR_NAME: str = "regression-cases"

#: Filename for the case metadata file.
DEFAULT_CASE_FILE_NAME: str = "case.json"

#: Filename for the input bytes.
DEFAULT_INPUT_FILE_NAME: str = "input.bin"

#: Filename for the case history (newline-delimited JSON).
DEFAULT_HISTORY_FILE_NAME: str = "history.jsonl"

#: Maximum number of historical runs retained per case. Older runs
#: are dropped from the in-memory view but the file is never pruned
#: by the module: callers can read the full history directly.
DEFAULT_HISTORY_LIMIT: int = 10_000

#: Maximum size of an input that may be registered. Matches the
#: corpus manager's default file size cap.
DEFAULT_MAX_INPUT_BYTES: int = 16 * 1024 * 1024  # 16 MiB


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RegressionError(KMCSException):
    """Base class for all regression errors."""


class CaseNotFoundError(RegressionError):
    """Raised when a case ID does not correspond to a stored case."""

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        super().__init__(f"regression case not found: {case_id}")


class CaseAlreadyExistsError(RegressionError):
    """Raised when registering a case with an explicit colliding ID."""

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        super().__init__(f"regression case already exists: {case_id}")


class CaseCorruptedError(RegressionError):
    """Raised when a case's on-disk representation cannot be read."""

    def __init__(self, case_id: str, reason: str) -> None:
        self.case_id = case_id
        self.reason = reason
        super().__init__(f"regression case {case_id} is corrupted: {reason}")


class StoreNotWritableError(RegressionError):
    """Raised when the store's root directory is not writable."""


class RegressionRunnerNotAvailableError(RegressionError):
    """Raised when the reproduction runner subsystem is unavailable."""

    def __init__(self, detail: Optional[str] = None) -> None:
        message = "reproduction.runner subsystem is not available"
        if detail:
            message += f" ({detail})"
        super().__init__(message)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class RegressionStatus(str, Enum):
    """Lifecycle status of a stored regression case.

    This describes the case itself, not the outcome of any particular
    run. The outcome of a run is recorded on
    :class:`RegressionRunStatus`.
    """

    #: The case has been registered and is eligible for re-testing.
    ACTIVE = "active"
    #: The case is retained but excluded from default runs. Set by
    #: the caller when a case's bug has been acknowledged as fixed
    #: but the case is worth keeping for historical reasons.
    QUARANTINED = "quarantined"
    #: The case is retained and always reported, but its result is
    #: not allowed to fail a suite. Useful for known-flaky cases.
    INFORMATIONAL = "informational"

    @property
    def is_runnable_by_default(self) -> bool:
        """Return True if the case runs during a default suite run."""
        return self is RegressionStatus.ACTIVE


class RegressionRunStatus(str, Enum):
    """Outcome of a single regression re-test."""

    #: The current outcome matches the stored reference exactly.
    PASSED = "passed"
    #: The current outcome no longer matches the reference, and it
    #: also does not match any other interesting behaviour. In
    #: practice this usually means the bug has been fixed.
    FAILED = "failed"
    #: The current outcome does not match the reference, but it is
    #: different from a clean run: a different crash, a different
    #: signal, a different sanitizer diagnostic, or a timeout where
    #: none was expected. This is the "something new is happening"
    #: signal.
    CHANGED = "changed"
    #: The re-test could not be executed at all (missing target,
    #: permission error, internal failure). The case's status is
    #: unaffected; the failure is a property of the run environment.
    ERROR = "error"

    @property
    def is_pass(self) -> bool:
        return self is RegressionRunStatus.PASSED

    @property
    def is_failure(self) -> bool:
        return self in (RegressionRunStatus.FAILED, RegressionRunStatus.CHANGED)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegressionReference:
    """A serialisable snapshot of the reference used by a case.

    This is a JSON-friendly mirror of
    :class:`~kmcs.reproduction.runner.ReferenceSignature`, kept
    separate so that the store remains usable even when the runner
    subsystem is unavailable.
    """

    exit_code: Optional[int] = None
    signal_number: Optional[int] = None
    timed_out: bool = False
    no_signal: bool = False
    stdout_contains: Tuple[str, ...] = ()
    stdout_excludes: Tuple[str, ...] = ()
    fingerprint: Optional[str] = None
    source: str = "unspecified"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "timed_out": self.timed_out,
            "no_signal": self.no_signal,
            "stdout_contains": list(self.stdout_contains),
            "stdout_excludes": list(self.stdout_excludes),
            "fingerprint": self.fingerprint,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RegressionReference":
        """Reconstruct a reference from its JSON representation."""
        return cls(
            exit_code=_coerce_optional_int(payload.get("exit_code")),
            signal_number=_coerce_optional_int(payload.get("signal_number")),
            timed_out=bool(payload.get("timed_out", False)),
            no_signal=bool(payload.get("no_signal", False)),
            stdout_contains=tuple(payload.get("stdout_contains") or ()),
            stdout_excludes=tuple(payload.get("stdout_excludes") or ()),
            fingerprint=payload.get("fingerprint") or None,
            source=str(payload.get("source", "unspecified")),
        )

    def to_runner_signature(self) -> "ReferenceSignature":
        """Convert to the runner's native signature type.

        Raises
        ------
        RegressionRunnerNotAvailableError
            If the runner subsystem is not importable.
        """
        if not _HAVE_RUNNER:
            raise RegressionRunnerNotAvailableError(_RUNNER_IMPORT_ERROR)
        return ReferenceSignature(  # type: ignore[misc]
            exit_code=self.exit_code,
            signal_number=self.signal_number,
            timed_out=self.timed_out,
            no_signal=self.no_signal,
            stdout_contains=self.stdout_contains,
            stdout_excludes=self.stdout_excludes,
            fingerprint=self.fingerprint,
            source=self.source,
        )

    @classmethod
    def from_runner_signature(
        cls, signature: "ReferenceSignature"
    ) -> "RegressionReference":
        """Convert from the runner's native signature type."""
        return cls(
            exit_code=getattr(signature, "exit_code", None),
            signal_number=getattr(signature, "signal_number", None),
            timed_out=bool(getattr(signature, "timed_out", False)),
            no_signal=bool(getattr(signature, "no_signal", False)),
            stdout_contains=tuple(getattr(signature, "stdout_contains", ()) or ()),
            stdout_excludes=tuple(getattr(signature, "stdout_excludes", ()) or ()),
            fingerprint=getattr(signature, "fingerprint", None),
            source=str(getattr(signature, "source", "unspecified")),
        )


@dataclass
class RegressionCase:
    """A single persisted regression case.

    This dataclass is the in-memory view of the ``case.json`` file
    plus the input's on-disk digest. It is deliberately mutable so
    that the store can update metadata (tags, status, counts) without
    copying the entire record.
    """

    case_id: str
    input_digest: str
    input_size: int
    reference: RegressionReference
    status: RegressionStatus = RegressionStatus.ACTIVE
    tags: FrozenSet[str] = field(default_factory=frozenset)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unspecified"
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_run_at: Optional[datetime] = None
    last_run_status: Optional[RegressionRunStatus] = None
    total_runs: int = 0
    total_passed: int = 0
    total_failed: int = 0
    total_changed: int = 0
    total_errors: int = 0

    @property
    def directory_name(self) -> str:
        """Return the on-disk directory name used for this case."""
        return self.case_id

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of the case."""
        return {
            "case_id": self.case_id,
            "input_digest": self.input_digest,
            "input_size": self.input_size,
            "reference": self.reference.to_dict(),
            "status": self.status.value,
            "tags": sorted(self.tags),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "source": self.source,
            "metadata": dict(self.metadata),
            "last_run_at": (
                self.last_run_at.isoformat() if self.last_run_at else None
            ),
            "last_run_status": (
                self.last_run_status.value if self.last_run_status else None
            ),
            "total_runs": self.total_runs,
            "total_passed": self.total_passed,
            "total_failed": self.total_failed,
            "total_changed": self.total_changed,
            "total_errors": self.total_errors,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RegressionCase":
        """Reconstruct a case from its JSON representation.

        Raises
        ------
        CaseCorruptedError
            If a required field is missing or malformed.
        """
        try:
            case_id = str(payload["case_id"])
            input_digest = str(payload["input_digest"])
            input_size = int(payload["input_size"])
            reference = RegressionReference.from_dict(payload["reference"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CaseCorruptedError(
                str(payload.get("case_id", "<unknown>")),
                f"missing or malformed required field: {exc}",
            ) from exc

        def _parse_dt(value: Any) -> Optional[datetime]:
            if value is None:
                return None
            if isinstance(value, datetime):
                return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return None
            return None

        try:
            status = RegressionStatus(payload.get("status", "active"))
        except ValueError:
            status = RegressionStatus.ACTIVE

        last_status: Optional[RegressionRunStatus] = None
        last_status_raw = payload.get("last_run_status")
        if last_status_raw:
            try:
                last_status = RegressionRunStatus(last_status_raw)
            except ValueError:
                last_status = None

        return cls(
            case_id=case_id,
            input_digest=input_digest,
            input_size=input_size,
            reference=reference,
            status=status,
            tags=frozenset(payload.get("tags") or ()),
            created_at=_parse_dt(payload.get("created_at")) or datetime.now(timezone.utc),
            updated_at=_parse_dt(payload.get("updated_at")) or datetime.now(timezone.utc),
            source=str(payload.get("source", "unspecified")),
            metadata=dict(payload.get("metadata") or {}),
            last_run_at=_parse_dt(payload.get("last_run_at")),
            last_run_status=last_status,
            total_runs=int(payload.get("total_runs", 0)),
            total_passed=int(payload.get("total_passed", 0)),
            total_failed=int(payload.get("total_failed", 0)),
            total_changed=int(payload.get("total_changed", 0)),
            total_errors=int(payload.get("total_errors", 0)),
        )


@dataclass
class RegressionRun:
    """A single historical regression re-test."""

    run_id: str
    case_id: str
    status: RegressionRunStatus
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    exit_code: Optional[int] = None
    signal_number: Optional[int] = None
    timed_out: bool = False
    fingerprint: Optional[str] = None
    reference_matched: bool = False
    error_message: Optional[str] = None
    attempt_count: int = 0
    matched_attempt_count: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "timed_out": self.timed_out,
            "fingerprint": self.fingerprint,
            "reference_matched": self.reference_matched,
            "error_message": self.error_message,
            "attempt_count": self.attempt_count,
            "matched_attempt_count": self.matched_attempt_count,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RegressionRun":
        """Reconstruct a run from its JSON representation."""

        def _parse_dt(value: Any) -> Optional[datetime]:
            if value is None:
                return None
            if isinstance(value, datetime):
                return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            try:
                return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except ValueError:
                return None

        try:
            status = RegressionRunStatus(payload["status"])
        except (KeyError, ValueError):
            status = RegressionRunStatus.ERROR

        return cls(
            run_id=str(payload.get("run_id", uuid.uuid4().hex)),
            case_id=str(payload.get("case_id", "")),
            status=status,
            started_at=_parse_dt(payload.get("started_at")) or datetime.now(timezone.utc),
            finished_at=_parse_dt(payload.get("finished_at")) or datetime.now(timezone.utc),
            duration_seconds=float(payload.get("duration_seconds", 0.0)),
            exit_code=_coerce_optional_int(payload.get("exit_code")),
            signal_number=_coerce_optional_int(payload.get("signal_number")),
            timed_out=bool(payload.get("timed_out", False)),
            fingerprint=payload.get("fingerprint") or None,
            reference_matched=bool(payload.get("reference_matched", False)),
            error_message=payload.get("error_message") or None,
            attempt_count=int(payload.get("attempt_count", 0)),
            matched_attempt_count=int(payload.get("matched_attempt_count", 0)),
            notes=str(payload.get("notes", "")),
        )


@dataclass
class RegressionResult:
    """The result of running a single regression case."""

    case_id: str
    status: RegressionRunStatus
    run: RegressionRun
    case: Optional[RegressionCase] = None
    error_message: Optional[str] = None

    @property
    def is_pass(self) -> bool:
        return self.status is RegressionRunStatus.PASSED

    @property
    def is_failure(self) -> bool:
        return self.status.is_failure

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "status": self.status.value,
            "run": self.run.to_dict(),
            "case": self.case.to_dict() if self.case else None,
            "error_message": self.error_message,
        }

    def summary(self) -> str:
        """Return a concise one-line summary."""
        parts = [
            self.status.value.upper(),
            self.case_id,
        ]
        if self.run.exit_code is not None:
            parts.append(f"exit={self.run.exit_code}")
        if self.run.signal_number is not None:
            parts.append(f"signal={self.run.signal_number}")
        if self.run.timed_out:
            parts.append("timed_out")
        parts.append(f"{self.run.duration_seconds:.2f}s")
        if self.error_message:
            parts.append(f"({self.error_message})")
        return " ".join(parts)


@dataclass
class RegressionSuiteResult:
    """The result of running many regression cases."""

    runs: List[RegressionResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    selection_description: str = ""

    @property
    def total(self) -> int:
        return len(self.runs)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.runs if r.status is RegressionRunStatus.PASSED)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.runs if r.status is RegressionRunStatus.FAILED)

    @property
    def changed(self) -> int:
        return sum(1 for r in self.runs if r.status is RegressionRunStatus.CHANGED)

    @property
    def errored(self) -> int:
        return sum(1 for r in self.runs if r.status is RegressionRunStatus.ERROR)

    @property
    def all_passed(self) -> bool:
        return self.total > 0 and self.passed == self.total

    @property
    def any_failed(self) -> bool:
        return self.failed > 0 or self.changed > 0

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "changed": self.changed,
            "errored": self.errored,
            "all_passed": self.all_passed,
            "any_failed": self.any_failed,
            "runs": [r.to_dict() for r in self.runs],
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
            "duration_seconds": self.duration_seconds,
            "selection_description": self.selection_description,
        }

    def summary(self) -> str:
        """Return a compact, human-readable summary of the suite."""
        return (
            f"total={self.total} passed={self.passed} "
            f"failed={self.failed} changed={self.changed} "
            f"errored={self.errored} "
            f"({self.duration_seconds:.2f}s)"
        )


@dataclass
class RegressionStats:
    """Aggregate statistics for a regression store."""

    total_cases: int = 0
    active_cases: int = 0
    quarantined_cases: int = 0
    informational_cases: int = 0
    total_runs: int = 0
    total_passed: int = 0
    total_failed: int = 0
    total_changed: int = 0
    total_errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cases": self.total_cases,
            "active_cases": self.active_cases,
            "quarantined_cases": self.quarantined_cases,
            "informational_cases": self.informational_cases,
            "total_runs": self.total_runs,
            "total_passed": self.total_passed,
            "total_failed": self.total_failed,
            "total_changed": self.total_changed,
            "total_errors": self.total_errors,
        }


# ---------------------------------------------------------------------------
# RegressionStore
# ---------------------------------------------------------------------------


class RegressionStore:
    """Persistent storage of regression cases.

    Parameters
    ----------
    root:
        Directory under which cases are stored. The store creates
        ``<root>/regression-cases/`` and places each case in its own
        subdirectory. The root is created on demand.
    history_limit:
        Maximum number of history entries loaded into memory per
        case. The on-disk history file is never truncated by the
        store; the limit only bounds the in-memory view.
    max_input_bytes:
        Maximum size of an input that may be registered. Attempts to
        register larger inputs raise
        :class:`~kmcs.core.exceptions.KMCSException` before any disk
        I/O occurs.
    event_bus:
        Optional :class:`~kmcs.core.events.EventBus`.
    config:
        Optional :class:`~kmcs.core.config.KMCSConfig`.
    """

    def __init__(
        self,
        root: Union[str, os.PathLike[str]],
        *,
        history_limit: int = DEFAULT_HISTORY_LIMIT,
        max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
        event_bus: Optional[EventBus] = None,
        config: Optional[KMCSConfig] = None,
    ) -> None:
        if history_limit <= 0:
            raise ValueError("history_limit must be positive")
        if max_input_bytes <= 0:
            raise ValueError("max_input_bytes must be positive")

        self._root = Path(root).expanduser().resolve()
        self._cases_root = self._root / DEFAULT_CASE_DIR_NAME
        self._history_limit = int(history_limit)
        self._max_input_bytes = int(max_input_bytes)
        self._bus = event_bus or get_default_bus()
        self._config = config or get_default_config()

        self._lock = threading.RLock()
        self._cache: Dict[str, RegressionCase] = {}

        try:
            self._cases_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StoreNotWritableError(
                f"failed to create store root {self._cases_root}: {exc}"
            ) from exc

        if not os.access(self._cases_root, os.W_OK):
            raise StoreNotWritableError(
                f"store root is not writable: {self._cases_root}"
            )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    @property
    def cases_root(self) -> Path:
        return self._cases_root

    @property
    def max_input_bytes(self) -> int:
        return self._max_input_bytes

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _emit(self, event_name: str, payload: Dict[str, Any]) -> None:
        try:
            et = getattr(EventType, event_name, None)
            if et is None:
                for fallback in ("SYSTEM", "INFO", "MESSAGE", "GENERIC"):
                    et = getattr(EventType, fallback, None)
                    if et is not None:
                        break
            if et is None:
                try:
                    et = next(iter(EventType))  # type: ignore[arg-type]
                except (TypeError, StopIteration):
                    et = event_name
            event = Event(
                type=et,
                source="reproduction.regression",
                data={"event": event_name, **payload},
            )
            self._bus.publish(event)
        except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
            logger.debug("regression event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Case ID and paths
    # ------------------------------------------------------------------

    @staticmethod
    def case_id_for(data: bytes) -> str:
        """Return the canonical case ID for ``data``.

        The ID is the SHA-256 hex digest of the bytes. Two callers
        registering the same input produce the same ID.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        return hashlib.sha256(bytes(data)).hexdigest()

    def _case_dir(self, case_id: str) -> Path:
        return self._cases_root / case_id

    def _case_file(self, case_id: str) -> Path:
        return self._case_dir(case_id) / DEFAULT_CASE_FILE_NAME

    def _input_file(self, case_id: str) -> Path:
        return self._case_dir(case_id) / DEFAULT_INPUT_FILE_NAME

    def _history_file(self, case_id: str) -> Path:
        return self._case_dir(case_id) / DEFAULT_HISTORY_FILE_NAME

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        data: bytes,
        reference: Union["ReferenceSignature", RegressionReference, Mapping[str, Any]],
        *,
        source: str = "unspecified",
        tags: Optional[Iterable[str]] = None,
        status: RegressionStatus = RegressionStatus.ACTIVE,
        metadata: Optional[Mapping[str, Any]] = None,
        case_id: Optional[str] = None,
        overwrite: bool = False,
    ) -> RegressionCase:
        """Register a new regression case.

        Parameters
        ----------
        data:
            The exact bytes to store. Must be non-empty and no larger
            than ``max_input_bytes``.
        reference:
            The behaviour to compare future runs against. Accepts a
            runner ``ReferenceSignature``, a ``RegressionReference``,
            or a plain mapping.
        source:
            Free-form provenance string, for example
            ``"campaign:abc123"``.
        tags:
            Labels for filtering.
        status:
            Initial case status.
        metadata:
            Opaque key/value payload.
        case_id:
            Optional explicit ID. When None, the ID is derived from the
            input's digest. When provided, it must match the digest
            unless ``overwrite=True``.
        overwrite:
            When True and a case already exists with the same ID, its
            metadata is replaced and its history is preserved. When
            False (the default), re-registering an existing case is a
            no-op that returns the existing case unchanged.

        Returns
        -------
        RegressionCase
            The newly registered or existing case.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        payload = bytes(data)
        if not payload:
            raise RegressionError("refusing to register an empty input")
        if len(payload) > self._max_input_bytes:
            raise RegressionError(
                f"input size {len(payload)} exceeds max_input_bytes "
                f"{self._max_input_bytes}"
            )

        digest = self.case_id_for(payload)
        cid = case_id or digest

        if case_id is not None and case_id != digest and not overwrite:
            raise RegressionError(
                "explicit case_id must match the input digest unless "
                "overwrite=True"
            )

        ref = _coerce_reference(reference)
        tag_set = frozenset(tags or ())

        with self._lock:
            existing_dir = self._case_dir(cid)
            if existing_dir.exists() and not overwrite:
                try:
                    existing = self._load_case_locked(cid)
                except CaseCorruptedError:
                    existing = None
                if existing is not None:
                    # Idempotent registration: return the existing case.
                    return existing

            case_dir = self._case_dir(cid)
            try:
                case_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise RegressionError(
                    f"failed to create case directory {case_dir}: {exc}"
                ) from exc

            # Write the input bytes.
            input_path = self._input_file(cid)
            if not input_path.exists() or overwrite:
                try:
                    _atomic_write_bytes(input_path, payload)
                except OSError as exc:
                    raise RegressionError(
                        f"failed to write input for case {cid}: {exc}"
                    ) from exc

            # Build the case record. If overwriting an existing case,
            # preserve its history counters and creation time.
            now = datetime.now(timezone.utc)
            existing_case: Optional[RegressionCase] = None
            if overwrite and existing_dir.exists():
                try:
                    existing_case = self._load_case_locked(cid)
                except CaseCorruptedError:
                    existing_case = None

            if existing_case is not None and overwrite:
                case = RegressionCase(
                    case_id=cid,
                    input_digest=digest,
                    input_size=len(payload),
                    reference=ref,
                    status=status,
                    tags=tag_set,
                    created_at=existing_case.created_at,
                    updated_at=now,
                    source=source,
                    metadata=dict(metadata or {}),
                    last_run_at=existing_case.last_run_at,
                    last_run_status=existing_case.last_run_status,
                    total_runs=existing_case.total_runs,
                    total_passed=existing_case.total_passed,
                    total_failed=existing_case.total_failed,
                    total_changed=existing_case.total_changed,
                    total_errors=existing_case.total_errors,
                )
            else:
                case = RegressionCase(
                    case_id=cid,
                    input_digest=digest,
                    input_size=len(payload),
                    reference=ref,
                    status=status,
                    tags=tag_set,
                    created_at=now,
                    updated_at=now,
                    source=source,
                    metadata=dict(metadata or {}),
                )

            try:
                self._write_case_file(case)
            except OSError as exc:
                raise RegressionError(
                    f"failed to write case file for {cid}: {exc}"
                ) from exc

            self._cache[cid] = case

        self._emit(
            "REGRESSION_CASE_REGISTERED",
            {
                "case_id": cid,
                "input_digest": digest,
                "input_size": len(payload),
                "source": source,
                "tags": sorted(tag_set),
                "status": status.value,
                "overwrite": overwrite,
            },
        )
        return case

    def register_from_result(
        self,
        result: "ReproductionResult",
        data: bytes,
        *,
        source: str = "reproduction",
        tags: Optional[Iterable[str]] = None,
        status: RegressionStatus = RegressionStatus.ACTIVE,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> RegressionCase:
        """Register a case from a completed reproduction result.

        The result's reference signature and input digest are used
        verbatim. This is the canonical entry point for the campaign
        layer: after the reproduction runner confirms a finding, the
        campaign passes its result here to persist the case.

        Raises
        ------
        RegressionError
            If the result indicates the finding was not reproduced.
            Registering a non-reproduced finding as a regression case
            would create a test that is expected to fail from the
            outset.
        """
        if result is None:
            raise RegressionError("result must not be None")
        status_attr = getattr(result, "status", None)
        status_name = getattr(status_attr, "value", str(status_attr))
        if status_name not in ("reproduced",):
            raise RegressionError(
                f"cannot register a case from a non-reproduced result "
                f"(status={status_name})"
            )
        reference = getattr(result, "reference", None)
        if reference is None:
            raise RegressionError("result has no reference signature")
        return self.register(
            data,
            reference,
            source=source,
            tags=tags,
            status=status,
            metadata=metadata,
        )

    def register_from_file(
        self,
        path: Union[str, os.PathLike[str]],
        reference: Union["ReferenceSignature", RegressionReference, Mapping[str, Any]],
        *,
        source: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        status: RegressionStatus = RegressionStatus.ACTIVE,
        metadata: Optional[Mapping[str, Any]] = None,
        overwrite: bool = False,
    ) -> RegressionCase:
        """Register a case by reading ``path`` from disk."""
        p = Path(path)
        try:
            data = p.read_bytes()
        except OSError as exc:
            raise RegressionError(f"failed to read {p}: {exc}") from exc
        return self.register(
            data,
            reference,
            source=source or f"file:{p}",
            tags=tags,
            status=status,
            metadata=metadata,
            overwrite=overwrite,
        )

    def register_from_entry(
        self,
        entry: "CorpusEntry",
        reference: Union["ReferenceSignature", RegressionReference, Mapping[str, Any]],
        *,
        source: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        status: RegressionStatus = RegressionStatus.ACTIVE,
        metadata: Optional[Mapping[str, Any]] = None,
        overwrite: bool = False,
    ) -> RegressionCase:
        """Register a case from a :class:`~kmcs.corpus.manager.CorpusEntry`."""
        path = getattr(entry, "path", None)
        digest = getattr(entry, "digest", None)
        if path is None:
            raise RegressionError("corpus entry has no path")
        p = Path(path)
        try:
            data = p.read_bytes()
        except OSError as exc:
            raise RegressionError(
                f"failed to read corpus entry {p}: {exc}"
            ) from exc
        return self.register(
            data,
            reference,
            source=source or f"corpus:{digest}",
            tags=tags,
            status=status,
            metadata=metadata,
            overwrite=overwrite,
        )

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_case_locked(self, case_id: str) -> RegressionCase:
        """Load a case from disk. Caller must hold ``self._lock``."""
        case_file = self._case_file(case_id)
        if not case_file.exists():
            raise CaseNotFoundError(case_id)
        try:
            with open(case_file, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except json.JSONDecodeError as exc:
            raise CaseCorruptedError(case_id, f"invalid JSON: {exc}") from exc
        except OSError as exc:
            raise CaseCorruptedError(case_id, f"read failed: {exc}") from exc
        case = RegressionCase.from_dict(payload)
        self._cache[case_id] = case
        return case

    def get(self, case_id: str) -> RegressionCase:
        """Return the case with the given ID.

        Raises
        ------
        CaseNotFoundError
            If the ID does not correspond to a stored case.
        CaseCorruptedError
            If the case file exists but cannot be read.
        """
        with self._lock:
            cached = self._cache.get(case_id)
        if cached is not None:
            return cached
        with self._lock:
            return self._load_case_locked(case_id)

    def has(self, case_id: str) -> bool:
        """Return True if a case with the given ID exists on disk."""
        return self._case_file(case_id).exists()

    def read_input(self, case_id: str) -> bytes:
        """Return the exact input bytes for a case."""
        path = self._input_file(case_id)
        if not path.exists():
            raise CaseNotFoundError(case_id)
        try:
            return path.read_bytes()
        except OSError as exc:
            raise RegressionError(
                f"failed to read input for case {case_id}: {exc}"
            ) from exc

    def list_cases(
        self,
        *,
        statuses: Optional[Iterable[RegressionStatus]] = None,
        tags: Optional[Iterable[str]] = None,
        limit: Optional[int] = None,
    ) -> List[RegressionCase]:
        """List cases matching the given filters.

        Cases are returned ordered by creation time (newest first).
        Corrupted cases are skipped with a warning; they do not abort
        the listing.
        """
        case_ids = self._scan_case_ids()
        status_set = frozenset(statuses) if statuses is not None else None
        tag_set = frozenset(tags) if tags is not None else None

        cases: List[RegressionCase] = []
        for cid in case_ids:
            try:
                case = self.get(cid)
            except (CaseNotFoundError, CaseCorruptedError) as exc:
                logger.warning("skipping case %s: %s", cid, exc)
                continue
            if status_set is not None and case.status not in status_set:
                continue
            if tag_set is not None and not (case.tags & tag_set):
                continue
            cases.append(case)

        cases.sort(key=lambda c: c.created_at, reverse=True)
        if limit is not None:
            cases = cases[:limit]
        return cases

    def _scan_case_ids(self) -> List[str]:
        """Return the IDs of every case directory present on disk."""
        if not self._cases_root.exists():
            return []
        ids: List[str] = []
        try:
            for entry in self._cases_root.iterdir():
                if not entry.is_dir():
                    continue
                ids.append(entry.name)
        except OSError as exc:
            logger.warning("failed to scan cases root: %s", exc)
            return []
        return ids

    # ------------------------------------------------------------------
    # Metadata mutation
    # ------------------------------------------------------------------

    def set_status(
        self, case_id: str, status: RegressionStatus
    ) -> RegressionCase:
        """Update a case's status and persist it."""
        with self._lock:
            case = self.get(case_id)
            case.status = status
            case.updated_at = datetime.now(timezone.utc)
            self._write_case_file(case)
        self._emit(
            "REGRESSION_CASE_STATUS_CHANGED",
            {"case_id": case_id, "status": status.value},
        )
        return case

    def add_tags(
        self, case_id: str, tags: Iterable[str]
    ) -> RegressionCase:
        """Add tags to a case. Duplicate tags are ignored."""
        with self._lock:
            case = self.get(case_id)
            new_tags = set(case.tags) | set(tags)
            case.tags = frozenset(new_tags)
            case.updated_at = datetime.now(timezone.utc)
            self._write_case_file(case)
        self._emit(
            "REGRESSION_CASE_TAGS_UPDATED",
            {"case_id": case_id, "tags": sorted(case.tags)},
        )
        return case

    def remove_tags(
        self, case_id: str, tags: Iterable[str]
    ) -> RegressionCase:
        """Remove tags from a case. Missing tags are ignored."""
        with self._lock:
            case = self.get(case_id)
            new_tags = set(case.tags) - set(tags)
            case.tags = frozenset(new_tags)
            case.updated_at = datetime.now(timezone.utc)
            self._write_case_file(case)
        self._emit(
            "REGRESSION_CASE_TAGS_UPDATED",
            {"case_id": case_id, "tags": sorted(case.tags)},
        )
        return case

    def update_metadata(
        self, case_id: str, metadata: Mapping[str, Any]
    ) -> RegressionCase:
        """Merge ``metadata`` into a case's metadata and persist."""
        with self._lock:
            case = self.get(case_id)
            merged = dict(case.metadata)
            merged.update(metadata)
            case.metadata = merged
            case.updated_at = datetime.now(timezone.utc)
            self._write_case_file(case)
        return case

    # ------------------------------------------------------------------
    # Run recording
    # ------------------------------------------------------------------

    def record_run(self, run: RegressionRun) -> RegressionCase:
        """Append ``run`` to a case's history and update its counters.

        Returns the updated case.

        Raises
        ------
        CaseNotFoundError
            If the case does not exist.
        """
        with self._lock:
            case = self.get(run.case_id)
            history_path = self._history_file(run.case_id)
            try:
                with open(history_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(run.to_dict(), default=str))
                    fh.write("\n")
            except OSError as exc:
                logger.warning(
                    "failed to append run to history for %s: %s",
                    run.case_id,
                    exc,
                )

            case.last_run_at = run.finished_at
            case.last_run_status = run.status
            case.total_runs += 1
            if run.status is RegressionRunStatus.PASSED:
                case.total_passed += 1
            elif run.status is RegressionRunStatus.FAILED:
                case.total_failed += 1
            elif run.status is RegressionRunStatus.CHANGED:
                case.total_changed += 1
            elif run.status is RegressionRunStatus.ERROR:
                case.total_errors += 1
            case.updated_at = datetime.now(timezone.utc)
            self._write_case_file(case)

        self._emit(
            "REGRESSION_CASE_RUN_RECORDED",
            {
                "case_id": run.case_id,
                "run_id": run.run_id,
                "status": run.status.value,
                "total_runs": case.total_runs,
            },
        )
        return case

    def history(
        self,
        case_id: str,
        *,
        limit: Optional[int] = None,
    ) -> List[RegressionRun]:
        """Return the recorded history for a case, oldest first.

        Parameters
        ----------
        case_id:
            The case whose history to read.
        limit:
            Optional cap on the number of runs returned. When set,
            the *most recent* runs are returned in chronological
            order.

        Raises
        ------
        CaseNotFoundError
            If the case does not exist.
        """
        if not self.has(case_id):
            raise CaseNotFoundError(case_id)
        path = self._history_file(case_id)
        if not path.exists():
            return []
        runs: List[RegressionRun] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    runs.append(RegressionRun.from_dict(payload))
        except OSError as exc:
            raise RegressionError(
                f"failed to read history for case {case_id}: {exc}"
            ) from exc
        if limit is not None:
            if limit <= 0:
                return []
            runs = runs[-limit:]
        return runs

    # ------------------------------------------------------------------
    # Removal
    # ------------------------------------------------------------------

    def remove(self, case_id: str, *, missing_ok: bool = False) -> bool:
        """Delete a case and all its on-disk state.

        Parameters
        ----------
        case_id:
            The case to delete.
        missing_ok:
            When True, deleting a non-existent case returns False
            instead of raising.

        Returns
        -------
        bool
            True if the case was deleted.

        Raises
        ------
        CaseNotFoundError
            If the case does not exist and ``missing_ok`` is False.
        RegressionError
            If the case directory exists but cannot be removed.
        """
        case_dir = self._case_dir(case_id)
        if not case_dir.exists():
            if missing_ok:
                return False
            raise CaseNotFoundError(case_id)
        try:
            shutil.rmtree(case_dir)
        except OSError as exc:
            raise RegressionError(
                f"failed to remove case {case_id}: {exc}"
            ) from exc
        with self._lock:
            self._cache.pop(case_id, None)
        self._emit(
            "REGRESSION_CASE_REMOVED",
            {"case_id": case_id},
        )
        return True

    def clear(self, *, statuses: Optional[Iterable[RegressionStatus]] = None) -> int:
        """Remove cases, optionally filtered by status.

        Parameters
        ----------
        statuses:
            When provided, only cases in one of these states are
            removed. When None, every case is removed.

        Returns
        -------
        int
            The number of cases removed.
        """
        status_set = frozenset(statuses) if statuses is not None else None
        removed = 0
        for cid in self._scan_case_ids():
            try:
                case = self.get(cid)
            except (CaseNotFoundError, CaseCorruptedError):
                continue
            if status_set is not None and case.status not in status_set:
                continue
            try:
                self.remove(cid, missing_ok=True)
                removed += 1
            except RegressionError as exc:
                logger.warning("failed to remove case %s: %s", cid, exc)
        return removed

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> RegressionStats:
        """Return aggregate statistics for the store."""
        cases = self.list_cases()
        stats = RegressionStats(total_cases=len(cases))
        for case in cases:
            if case.status is RegressionStatus.ACTIVE:
                stats.active_cases += 1
            elif case.status is RegressionStatus.QUARANTINED:
                stats.quarantined_cases += 1
            elif case.status is RegressionStatus.INFORMATIONAL:
                stats.informational_cases += 1
            stats.total_runs += case.total_runs
            stats.total_passed += case.total_passed
            stats.total_failed += case.total_failed
            stats.total_changed += case.total_changed
            stats.total_errors += case.total_errors
        return stats

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _write_case_file(self, case: RegressionCase) -> None:
        path = self._case_file(case.case_id)
        payload = json.dumps(case.to_dict(), indent=2, default=str)
        _atomic_write_bytes(path, payload.encode("utf-8"))

    def refresh(self) -> int:
        """Reload every case from disk. Returns the number loaded."""
        with self._lock:
            self._cache.clear()
        count = 0
        for cid in self._scan_case_ids():
            try:
                self.get(cid)
                count += 1
            except (CaseNotFoundError, CaseCorruptedError) as exc:
                logger.warning("failed to refresh case %s: %s", cid, exc)
        return count

    def __len__(self) -> int:
        return len(self._scan_case_ids())

    def __contains__(self, case_id: object) -> bool:
        if not isinstance(case_id, str):
            return False
        return self.has(case_id)

    def __repr__(self) -> str:
        return (
            f"RegressionStore(root={self._root!r}, "
            f"cases={len(self)})"
        )


# ---------------------------------------------------------------------------
# RegressionRunner
# ---------------------------------------------------------------------------


class RegressionRunner:
    """Runs stored regression cases against a target.

    Parameters
    ----------
    store:
        The :class:`RegressionStore` holding the cases to run.
    target:
        The :class:`~kmcs.corpus.validator.TargetSpec` describing the
        target binary.
    config:
        Optional :class:`~kmcs.reproduction.runner.ReproductionConfig`.
        The runner uses this for its internal :class:`Reproducer`
        unless a pre-built reproducer is supplied.
    validator:
        Optional pre-built :class:`~kmcs.corpus.validator.InputValidator`.
        When omitted, the runner constructs one from ``target``.
    reproducer:
        Optional pre-built :class:`~kmcs.reproduction.runner.Reproducer`.
        When omitted, the runner constructs one from ``target``,
        ``validator``, and ``config``.
    event_bus:
        Optional :class:`~kmcs.core.events.EventBus`.
    kmcs_config:
        Optional :class:`~kmcs.core.config.KMCSConfig`.
    """

    def __init__(
        self,
        store: RegressionStore,
        target: Optional["TargetSpec"] = None,
        *,
        config: Optional["ReproductionConfig"] = None,
        validator: Optional["InputValidator"] = None,
        reproducer: Optional["Reproducer"] = None,
        event_bus: Optional[EventBus] = None,
        kmcs_config: Optional[KMCSConfig] = None,
    ) -> None:
        if not _HAVE_RUNNER:
            raise RegressionRunnerNotAvailableError(_RUNNER_IMPORT_ERROR)

        self._store = store
        self._target = target
        self._config = config or ReproductionConfig()
        self._bus = event_bus or get_default_bus()
        self._kmcs_config = kmcs_config or get_default_config()

        self._owns_reproducer = reproducer is None
        if reproducer is not None:
            self._reproducer = reproducer
        else:
            if target is None and validator is None:
                raise ValueError(
                    "either target, validator, or reproducer must be provided"
                )
            self._reproducer = Reproducer(  # type: ignore[misc]
                target,
                config=self._config,
                event_bus=self._bus,
                kmcs_config=self._kmcs_config,
                validator=validator,
            )

        self._lock = threading.RLock()
        self._closed = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def store(self) -> RegressionStore:
        return self._store

    @property
    def reproducer(self) -> "Reproducer":
        return self._reproducer

    @property
    def config(self) -> "ReproductionConfig":
        return self._config

    # ------------------------------------------------------------------
    # Single-case execution
    # ------------------------------------------------------------------

    def run_case(self, case_id: str) -> RegressionResult:
        """Run a single regression case.

        Returns
        -------
        RegressionResult
            The outcome of this run, including the updated case.

        Raises
        ------
        CaseNotFoundError
            If the case does not exist.
        """
        if self._closed:
            raise RegressionError("regression runner has been closed")

        case = self._store.get(case_id)
        payload = self._store.read_input(case_id)

        reference = case.reference.to_runner_signature()

        started_at = datetime.now(timezone.utc)
        run_id = uuid.uuid4().hex

        try:
            reproduction = self._reproducer.reproduce(
                payload,
                digest=case.input_digest,
                reference=reference,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("regression run failed for case %s", case_id)
            finished_at = datetime.now(timezone.utc)
            run = RegressionRun(
                run_id=run_id,
                case_id=case_id,
                status=RegressionRunStatus.ERROR,
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=(finished_at - started_at).total_seconds(),
                error_message=f"{type(exc).__name__}: {exc}",
                notes="reproduction raised",
            )
            try:
                updated_case = self._store.record_run(run)
            except Exception:  # noqa: BLE001
                updated_case = case
            return RegressionResult(
                case_id=case_id,
                status=RegressionRunStatus.ERROR,
                run=run,
                case=updated_case,
                error_message=run.error_message,
            )

        finished_at = datetime.now(timezone.utc)
        run_status = self._classify_reproduction(reproduction, case)
        run = RegressionRun(
            run_id=run_id,
            case_id=case_id,
            status=run_status,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=(finished_at - started_at).total_seconds(),
            exit_code=_first_attempt_field(reproduction, "exit_code"),
            signal_number=_first_attempt_field(reproduction, "signal_number"),
            timed_out=bool(_first_attempt_field(reproduction, "timed_out") or False),
            fingerprint=_first_attempt_fingerprint(reproduction),
            reference_matched=(
                getattr(reproduction, "status", None) is not None
                and _reproduction_status_name(reproduction) == "reproduced"
            ),
            attempt_count=int(getattr(reproduction, "attempt_count", 0) or 0),
            matched_attempt_count=int(
                getattr(reproduction, "matched_count", 0) or 0
            ),
        )

        try:
            updated_case = self._store.record_run(run)
        except CaseNotFoundError:
            updated_case = None
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "failed to record run for case %s: %s", case_id, exc
            )
            updated_case = case

        self._emit(
            "REGRESSION_CASE_RUN_COMPLETED",
            {
                "case_id": case_id,
                "run_id": run_id,
                "status": run_status.value,
                "duration_seconds": run.duration_seconds,
            },
        )

        return RegressionResult(
            case_id=case_id,
            status=run_status,
            run=run,
            case=updated_case,
        )

    def _classify_reproduction(
        self,
        reproduction: "ReproductionResult",
        case: RegressionCase,
    ) -> RegressionRunStatus:
        """Map a reproduction result onto a regression run status.

        The rules are:

        * If every executable attempt matched the reference, the run
          PASSED. This is the "bug still reproduces as before" case.
        * If the reference is a *crash-like* reference (signal or
          non-zero exit or a fingerprint) and the current run did not
          crash at all, the run FAILED. This is the "bug appears to
          be fixed" case.
        * If the reference is a crash-like reference and the current
          run *did* crash but with a different signature, the run
          CHANGED. The bug still exists but manifests differently.
        * If no attempt could be executed, the run ERRORED.
        * Any other case is conservatively reported as FAILED.
        """
        if reproduction is None:
            return RegressionRunStatus.ERROR

        status_name = _reproduction_status_name(reproduction)
        if status_name == "error":
            return RegressionRunStatus.ERROR
        if status_name == "reproduced":
            return RegressionRunStatus.PASSED
        if status_name == "intermittent":
            return RegressionRunStatus.CHANGED
        if status_name == "not_reproduced":
            if _reference_is_crash_like(case.reference):
                # The bug no longer occurs at all.
                return RegressionRunStatus.FAILED
            # A non-crash reference that no longer matches. This is
            # rare but legitimate: treat as changed so the operator
            # sees it.
            return RegressionRunStatus.CHANGED
        return RegressionRunStatus.ERROR

    # ------------------------------------------------------------------
    # Batch execution
    # ------------------------------------------------------------------

    def run_all(
        self,
        *,
        statuses: Optional[Iterable[RegressionStatus]] = None,
        tags: Optional[Iterable[str]] = None,
        stop_on_first_failure: bool = False,
    ) -> RegressionSuiteResult:
        """Run every matching case.

        Parameters
        ----------
        statuses:
            Filter on case status. Defaults to ACTIVE only, so that
            quarantined and informational cases are not run unless
            explicitly requested.
        tags:
            Filter on tags.
        stop_on_first_failure:
            When True, the run stops after the first FAILED or
            CHANGED case. Cases already run are still recorded.

        Returns
        -------
        RegressionSuiteResult
        """
        if statuses is None:
            statuses = (RegressionStatus.ACTIVE,)
        cases = self._store.list_cases(statuses=statuses, tags=tags)

        result = RegressionSuiteResult(
            started_at=datetime.now(timezone.utc),
            selection_description=_describe_selection(statuses, tags),
        )

        for case in cases:
            try:
                case_result = self.run_case(case.case_id)
            except CaseNotFoundError:
                continue
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "regression run for case %s raised", case.case_id
                )
                now = datetime.now(timezone.utc)
                run = RegressionRun(
                    run_id=uuid.uuid4().hex,
                    case_id=case.case_id,
                    status=RegressionRunStatus.ERROR,
                    started_at=now,
                    finished_at=now,
                    duration_seconds=0.0,
                    error_message=f"{type(exc).__name__}: {exc}",
                )
                case_result = RegressionResult(
                    case_id=case.case_id,
                    status=RegressionRunStatus.ERROR,
                    run=run,
                    case=case,
                    error_message=run.error_message,
                )
            result.runs.append(case_result)
            if stop_on_first_failure and case_result.is_failure:
                break

        result.finished_at = datetime.now(timezone.utc)

        self._emit(
            "REGRESSION_SUITE_COMPLETED",
            {
                "total": result.total,
                "passed": result.passed,
                "failed": result.failed,
                "changed": result.changed,
                "errored": result.errored,
                "duration_seconds": result.duration_seconds,
            },
        )

        return result

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release the internal reproducer, if this runner owns it."""
        if self._closed:
            return
        self._closed = True
        if self._owns_reproducer:
            try:
                self._reproducer.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("failed to close reproducer: %s", exc)

    def __enter__(self) -> "RegressionRunner":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"RegressionRunner(store={self._store!r}, "
            f"closed={self._closed})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_reference(
    reference: Union["ReferenceSignature", RegressionReference, Mapping[str, Any]]
) -> RegressionReference:
    """Normalise a reference to a :class:`RegressionReference`."""
    if isinstance(reference, RegressionReference):
        return reference
    if _HAVE_RUNNER and ReferenceSignature is not None and isinstance(
        reference, ReferenceSignature
    ):
        return RegressionReference.from_runner_signature(reference)
    if isinstance(reference, Mapping):
        return RegressionReference.from_dict(reference)
    # Duck-typed: has at least one of the reference's distinguishing
    # fields.
    if hasattr(reference, "exit_code") and hasattr(reference, "timed_out"):
        return RegressionReference(
            exit_code=getattr(reference, "exit_code", None),
            signal_number=getattr(reference, "signal_number", None),
            timed_out=bool(getattr(reference, "timed_out", False)),
            no_signal=bool(getattr(reference, "no_signal", False)),
            stdout_contains=tuple(getattr(reference, "stdout_contains", ()) or ()),
            stdout_excludes=tuple(getattr(reference, "stdout_excludes", ()) or ()),
            fingerprint=getattr(reference, "fingerprint", None),
            source=str(getattr(reference, "source", "duck-typed")),
        )
    raise TypeError(
        f"unsupported reference type: {type(reference).__name__}"
    )


def _atomic_write_bytes(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Write ``data`` to ``path`` atomically via a sibling temp file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    import tempfile

    fd, tmp_name = tempfile.mkstemp(prefix=".kmcs-regression-", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        try:
            os.chmod(tmp_path, mode)
        except OSError:
            pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def _reproduction_status_name(reproduction: "ReproductionResult") -> str:
    """Return the string value of a reproduction result's status."""
    if reproduction is None:
        return ""
    status = getattr(reproduction, "status", None)
    value = getattr(status, "value", None)
    if isinstance(value, str):
        return value
    return str(status) if status is not None else ""


def _first_attempt_field(reproduction: "ReproductionResult", field_name: str) -> Any:
    """Return the first non-None value of a field across attempts."""
    attempts = getattr(reproduction, "attempts", None) or ()
    for attempt in attempts:
        value = getattr(attempt, field_name, None)
        if value is not None:
            return value
    return None


def _first_attempt_fingerprint(reproduction: "ReproductionResult") -> Optional[str]:
    """Return the fingerprint of the first attempt that has one."""
    attempts = getattr(reproduction, "attempts", None) or ()
    for attempt in attempts:
        fp = getattr(attempt, "parsed_fingerprint", None)
        if fp:
            return fp
    return None


def _reference_is_crash_like(reference: RegressionReference) -> bool:
    """Return True if the reference describes a crash-like outcome.

    A reference is crash-like when it constrains a signal, a non-zero
    exit code, a timeout, or a fingerprint. A reference that only
    constrains exit code 0 is not crash-like.
    """
    if reference is None:
        return False
    if reference.signal_number is not None:
        return True
    if reference.timed_out:
        return True
    if reference.exit_code is not None and reference.exit_code != 0:
        return True
    if reference.fingerprint is not None:
        return True
    return False


def _describe_selection(
    statuses: Optional[Iterable[RegressionStatus]],
    tags: Optional[Iterable[str]],
) -> str:
    """Return a human-readable description of a suite selection."""
    parts: List[str] = []
    if statuses is not None:
        status_list = sorted({s.value for s in statuses})
        parts.append(f"statuses={status_list}")
    if tags is not None:
        parts.append(f"tags={sorted(set(tags))}")
    return ", ".join(parts) if parts else "all cases"


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
