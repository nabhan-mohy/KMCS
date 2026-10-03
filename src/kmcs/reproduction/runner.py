# KMCS Reproduction Runner
# =========================
#
# Verifies that a previously observed behaviour can be reproduced.
#
# The runner takes an input that was previously observed to produce an
# interesting behaviour (a crash, a hang, a specific exit code, a
# sanitizer diagnostic) and re-executes it against the target under the
# same execution configuration. It records what actually happens on
# each attempt and classifies the overall result as REPRODUCED,
# NOT_REPRODUCED, INTERMITTENT, or ERROR.
#
# This module does not reimplement process execution. It delegates the
# actual subprocess invocation to :class:`~kmcs.corpus.validator.InputValidator`,
# which already owns the mechanics of spawning the target, capturing
# output, enforcing timeouts, and classifying raw process outcomes.
# The runner's responsibility is verification: running that machinery
# multiple times, comparing the results against a reference, and
# producing a single, authoritative verdict.
#
# Structural crash information is likewise delegated: when the target
# produces output that looks like a crash, the runner asks
# :func:`~kmcs.analysis.crash_parser.parse_crash_output` to interpret
# it, and uses the resulting record for fingerprint comparison. The
# runner never attempts to interpret sanitizer output itself.
#
# Design principles
# -----------------
#
# * **Evidence is preserved.** Every attempt writes its stdout, stderr,
#   exit code, signal, and duration to a per-attempt JSON file inside
#   the runner's evidence directory. The evidence directory is created
#   on demand and never deleted by the runner; callers who wish to
#   clean up are responsible for doing so.
#
# * **Classification is deterministic.** Given the same sequence of
#   attempts and the same reference, the runner produces the same
#   verdict. Tie-breaking rules are explicit and documented on
#   :class:`ReproductionMode`.
#
# * **Never claim reproduction on error.** If an attempt cannot be
#   executed at all (target missing, permission denied, internal
#   error), that attempt is recorded as an error and does not count
#   as either success or failure. Modes that require all attempts to
#   match treat error attempts as non-matches.
#
# * **Delegation over duplication.** The runner contains no target
#   argv construction, no sanitizer environment assembly, and no
#   line-level crash pattern matching. Those responsibilities belong
#   to :mod:`kmcs.targets`, :mod:`kmcs.sanitizers`, and
#   :mod:`kmcs.analysis`. Where those modules are unavailable, the
#   runner records a clear error rather than silently degrading.
#
# Modes
# -----
#
# :class:`ReproductionMode` controls how per-attempt matches are
# combined into a verdict:
#
# STRICT
#     Every attempt must match, and every attempt must have been
#     executable. Any non-matching or errored attempt yields
#     NOT_REPRODUCED or ERROR respectively.
#
# MAJORITY
#     More than half of the *executable* attempts must match. Errors
#     are excluded from the count but recorded in the result. A
#     majority of zero valid attempts yields ERROR.
#
# ANY
#     At least one attempt must match. Errors are excluded.
#
# ALL_OR_NONE
#     Either every executable attempt matches (REPRODUCED) or none
#     do (NOT_REPRODUCED). A mix yields INTERMITTENT.
#
# The default mode is MAJORITY, which is robust against transient
# environmental noise (for example, a single run interrupted by a
# system sleep) while still requiring genuine reproducibility.
#
# Reference signatures
# --------------------
#
# A reference is anything that describes "what the interesting
# behaviour looks like". Three forms are accepted:
#
# 1. An explicit :class:`~kmcs.corpus.validator.ExpectedBehavior`. This
#    is the simplest form and is suitable when the caller already
#    knows the exact exit code, signal, or output substring they are
#    looking for.
#
# 2. A :class:`ValidationOutcome` from a previous run. The runner
#    derives a :class:`ReferenceSignature` from it. This is the form
#    used by the campaign layer: the finding's original outcome is
#    passed in, and the runner checks whether subsequent runs match.
#
# 3. A :class:`ReferenceSignature` directly, for callers that want
#    full control over the reference.
#
# Fingerprints
# ------------
#
# When the crash parser is available, the runner computes a stable
# fingerprint from each attempt's parsed crash record. If the
# reference provides a fingerprint, attempts are additionally
# required to match on fingerprint (in addition to the outcome-level
# checks). This catches the case where two different bugs produce the
# same exit code.
#
# Threading
# ---------
#
# A :class:`Reproducer` instance is safe to use from multiple threads.
# Internally it holds an :class:`InputValidator` whose lifecycle is
# managed by the runner; concurrent calls to :meth:`Reproducer.reproduce`
# are serialised through the validator's own locking. Callers that
# need parallel reproduction of many inputs should construct one
# :class:`Reproducer` per thread.
#
# Compatibility
# -------------
#
# Python 3.10+.

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
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
    List,
    Mapping,
    Optional,
    Sequence,
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
# The runner delegates execution to corpus.validator, structural crash
# parsing to analysis.crash_parser, and fingerprint extraction to
# analysis.fingerprint. Each of these is imported defensively: a
# missing subsystem is recorded at import time and reported at use
# time, never silently ignored.

try:
    from ..corpus.validator import (
        InputValidator,
        TargetSpec,
        ExpectedBehavior,
        ValidationOutcome,
        ValidationResult,
        OutcomeKind,
        ValidatorError,
        TargetNotFoundError,
        TargetPermissionError,
        DEFAULT_TIMEOUT_SECONDS,
        DEFAULT_STDOUT_LIMIT_BYTES,
        DEFAULT_MEMORY_LIMIT_BYTES,
        make_reproduction_predicate,
        describe_outcome,
    )
    _HAVE_VALIDATOR = True
except ImportError as exc:  # pragma: no cover - depends on package layout
    InputValidator = None  # type: ignore[assignment]
    TargetSpec = None  # type: ignore[assignment]
    ExpectedBehavior = None  # type: ignore[assignment]
    ValidationOutcome = None  # type: ignore[assignment]
    ValidationResult = None  # type: ignore[assignment]
    OutcomeKind = None  # type: ignore[assignment]
    ValidatorError = Exception  # type: ignore[assignment,misc]
    TargetNotFoundError = Exception  # type: ignore[assignment,misc]
    TargetPermissionError = Exception  # type: ignore[assignment,misc]
    DEFAULT_TIMEOUT_SECONDS = 30.0
    DEFAULT_STDOUT_LIMIT_BYTES = 4 * 1024 * 1024
    DEFAULT_MEMORY_LIMIT_BYTES = 2 * 1024 * 1024 * 1024
    make_reproduction_predicate = None  # type: ignore[assignment]
    describe_outcome = None  # type: ignore[assignment]
    _HAVE_VALIDATOR = False
    _VALIDATOR_IMPORT_ERROR = str(exc)
else:
    _VALIDATOR_IMPORT_ERROR = None


try:
    from ..analysis.crash_parser import parse_crash_output
    _HAVE_CRASH_PARSER = True
except ImportError as exc:  # pragma: no cover
    parse_crash_output = None  # type: ignore[assignment]
    _HAVE_CRASH_PARSER = False
    _CRASH_PARSER_IMPORT_ERROR = str(exc)
else:
    _CRASH_PARSER_IMPORT_ERROR = None


try:
    from ..analysis.fingerprint import extract_features
    _HAVE_FINGERPRINT = True
except ImportError as exc:  # pragma: no cover
    extract_features = None  # type: ignore[assignment]
    _HAVE_FINGERPRINT = False
    _FINGERPRINT_IMPORT_ERROR = str(exc)
else:
    _FINGERPRINT_IMPORT_ERROR = None


if TYPE_CHECKING:
    from ..corpus.manager import CorpusEntry


__all__ = [
    "Reproducer",
    "ReferenceSignature",
    "ReproductionConfig",
    "ReproductionAttempt",
    "ReproductionResult",
    "ReproductionStats",
    "ReproductionStatus",
    "ReproductionMode",
    "ReproductionError",
    "ReproducerNotAvailableError",
    "ReferenceRequiredError",
    "EvidenceError",
    "reproduce_once",
    "reproduce_with_retries",
    "DEFAULT_RUNS",
    "DEFAULT_REPRODUCTION_MODE",
    "DEFAULT_EVIDENCE_DIR_NAME",
    "DEFAULT_MAX_EVIDENCE_BYTES",
    "SUBSYSTEM_AVAILABILITY",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Default number of attempts per reproduction.
DEFAULT_RUNS: int = 3

#: Default classification mode.
DEFAULT_REPRODUCTION_MODE: str = "majority"

#: Name of the subdirectory created inside the evidence root for a
#: single reproduction.
DEFAULT_EVIDENCE_DIR_NAME: str = "reproduction"

#: Cap on the size of a single evidence artifact. Output longer than
#: this is truncated and marked as such in the evidence metadata.
DEFAULT_MAX_EVIDENCE_BYTES: int = 8 * 1024 * 1024  # 8 MiB

#: Per-attempt timeout default when the target spec does not override.
DEFAULT_REPRODUCTION_TIMEOUT: float = 30.0

#: Environment variable that, when truthy, causes a warning-free run
#: even when the crash parser is unavailable. Set this when the caller
#: deliberately wants to reproduce without structural parsing.
_ENV_SKIP_PARSER_WARNING = "KMCS_REPRODUCTION_SKIP_PARSER_WARNING"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ReproductionError(KMCSException):
    """Base class for all reproduction errors."""


class ReproducerNotAvailableError(ReproductionError):
    """Raised when a required subsystem is not importable.

    The message names the missing subsystem and provides the underlying
    import error, so that callers can diagnose the failure without
    grepping logs.
    """

    def __init__(self, subsystem: str, detail: Optional[str] = None) -> None:
        self.subsystem = subsystem
        self.detail = detail
        message = f"required subsystem not available: {subsystem}"
        if detail:
            message += f" ({detail})"
        super().__init__(message)


class ReferenceRequiredError(ReproductionError):
    """Raised when :meth:`Reproducer.reproduce` is called with no reference.

    A reference is required because the runner cannot decide what
    "reproduced" means without one. Provide an
    :class:`~kmcs.corpus.validator.ExpectedBehavior`, a
    :class:`~kmcs.corpus.validator.ValidationOutcome`, or a
    :class:`ReferenceSignature`.
    """


class EvidenceError(ReproductionError):
    """Raised when evidence cannot be written to disk.

    The runner treats evidence-writing failures as non-fatal by
    default: the reproduction continues, and the failure is recorded
    on the result. Callers that require evidence integrity can check
    :attr:`ReproductionResult.evidence_errors` and act accordingly.
    """


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ReproductionStatus(str, Enum):
    """Overall verdict for a reproduction attempt set."""

    #: The behaviour was reproduced consistently.
    REPRODUCED = "reproduced"
    #: The behaviour was not reproduced on any attempt.
    NOT_REPRODUCED = "not_reproduced"
    #: The behaviour was reproduced on some attempts but not others.
    INTERMITTENT = "intermittent"
    #: The reproduction could not be attempted (missing target,
    #: permission error, internal failure).
    ERROR = "error"
    #: The reproduction has not yet completed. Only appears in
    #: in-flight result objects; never returned by a completed call.
    PENDING = "pending"

    @property
    def is_conclusive(self) -> bool:
        """Return True for verdicts that resolve the finding one way or another."""
        return self in (
            ReproductionStatus.REPRODUCED,
            ReproductionStatus.NOT_REPRODUCED,
        )

    @property
    def is_success(self) -> bool:
        return self is ReproductionStatus.REPRODUCED


class ReproductionMode(str, Enum):
    """How per-attempt results are combined into a verdict.

    See the module docstring for the precise semantics of each mode.
    """

    STRICT = "strict"
    MAJORITY = "majority"
    ANY = "any"
    ALL_OR_NONE = "all_or_none"


# ---------------------------------------------------------------------------
# Reference signature
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReferenceSignature:
    """A compact description of the "interesting behaviour".

    A :class:`ReferenceSignature` is derived from a reference outcome,
    an explicit :class:`~kmcs.corpus.validator.ExpectedBehavior`, or
    supplied by the caller directly. It captures the minimum set of
    facts needed to decide whether a subsequent run reproduced the
    behaviour.
    """

    #: Expected exit code, or None if not constrained.
    exit_code: Optional[int] = None
    #: Expected terminating signal number, or None if not constrained.
    signal_number: Optional[int] = None
    #: When True, the run must have timed out.
    timed_out: bool = False
    #: When True, the run must not have been killed by a signal.
    no_signal: bool = False
    #: Substrings that must appear in stdout or stderr.
    stdout_contains: Tuple[str, ...] = ()
    #: Substrings that must not appear in stdout or stderr.
    stdout_excludes: Tuple[str, ...] = ()
    #: Optional crash fingerprint.
    fingerprint: Optional[str] = None
    #: Human-readable description of where this signature came from.
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

    def describe(self) -> str:
        """Return a concise human-readable summary of this signature."""
        parts: List[str] = []
        if self.exit_code is not None:
            parts.append(f"exit={self.exit_code}")
        if self.signal_number is not None:
            parts.append(f"signal={self.signal_number}")
        if self.no_signal:
            parts.append("no_signal")
        if self.timed_out:
            parts.append("timed_out")
        for needle in self.stdout_contains:
            parts.append(f"stdout~{needle!r}")
        for needle in self.stdout_excludes:
            parts.append(f"stdout!{needle!r}")
        if self.fingerprint is not None:
            parts.append(f"fp={self.fingerprint[:12]}")
        return " ".join(parts) if parts else "<empty>"

    @classmethod
    def from_outcome(
        cls,
        outcome: "ValidationOutcome",
        *,
        fingerprint: Optional[str] = None,
        source: str = "observed outcome",
    ) -> "ReferenceSignature":
        """Derive a signature from a previously observed outcome.

        The signature captures every field that can be compared
        objectively:

        * exit code (if the process exited normally),
        * signal number (if it was killed),
        * whether it timed out,
        * a null exit-code constraint when it was killed by a signal.

        Output substrings are *not* captured here: matching on
        output text is a policy decision that belongs to the caller,
        and capturing the full output would make the signature
        unstable across runs due to timing-dependent fields.
        """
        if outcome is None:
            raise ValueError("outcome must not be None")

        timed_out = bool(getattr(outcome, "timed_out", False))
        exit_code = getattr(outcome, "exit_code", None)
        signal_number = getattr(outcome, "signal_number", None)

        # A timed-out run has no meaningful exit code; encode it as
        # timed_out=True and constrain nothing else.
        if timed_out:
            return cls(
                exit_code=None,
                signal_number=None,
                timed_out=True,
                no_signal=False,
                fingerprint=fingerprint,
                source=source,
            )

        # A signal-terminated run: exit code is None by contract.
        if signal_number is not None:
            return cls(
                exit_code=None,
                signal_number=int(signal_number),
                timed_out=False,
                no_signal=False,
                fingerprint=fingerprint,
                source=source,
            )

        # A normal exit.
        return cls(
            exit_code=int(exit_code) if exit_code is not None else None,
            signal_number=None,
            timed_out=False,
            no_signal=True,
            fingerprint=fingerprint,
            source=source,
        )

    @classmethod
    def from_expected(
        cls,
        expected: "ExpectedBehavior",
        *,
        fingerprint: Optional[str] = None,
        source: str = "caller-supplied ExpectedBehavior",
    ) -> "ReferenceSignature":
        """Derive a signature from an explicit ExpectedBehavior."""
        if expected is None:
            raise ValueError("expected must not be None")
        return cls(
            exit_code=getattr(expected, "exit_code", None),
            signal_number=getattr(expected, "signal_number", None),
            timed_out=bool(getattr(expected, "timed_out", False)),
            no_signal=bool(getattr(expected, "no_signal", False)),
            stdout_contains=tuple(getattr(expected, "stdout_contains", ()) or ()),
            stdout_excludes=tuple(getattr(expected, "stdout_excludes", ()) or ()),
            fingerprint=fingerprint,
            source=source,
        )

    def to_expected_behavior(self) -> "ExpectedBehavior":
        """Reconstruct an :class:`ExpectedBehavior` from this signature.

        Used when the underlying validator is invoked: rather than
        teach the validator about signatures, the runner translates
        its own signature back into the validator's native type.
        """
        if not _HAVE_VALIDATOR:
            raise ReproducerNotAvailableError(
                "corpus.validator", _VALIDATOR_IMPORT_ERROR
            )
        return ExpectedBehavior(  # type: ignore[misc]
            exit_code=self.exit_code,
            signal_number=self.signal_number,
            no_signal=self.no_signal,
            stdout_contains=self.stdout_contains,
            stdout_excludes=self.stdout_excludes,
            timed_out=self.timed_out,
            not_timed_out=not self.timed_out and (
                self.timed_out is False and not self.timed_out
            ),
        )

    def matches_outcome(
        self,
        outcome: "ValidationOutcome",
        *,
        parsed_fingerprint: Optional[str] = None,
    ) -> bool:
        """Return True if ``outcome`` satisfies this signature.

        A ``False`` return does not necessarily mean the run failed:
        it means the run did not look like the reference. The
        distinction matters for INTERMITTENT classification.
        """
        if outcome is None:
            return False

        timed_out = bool(getattr(outcome, "timed_out", False))
        exit_code = getattr(outcome, "exit_code", None)
        signal_number = getattr(outcome, "signal_number", None)
        outcome_kind = getattr(outcome, "kind", None)

        # A run that could not be executed is not a match. The caller
        # classifies it separately as an error.
        if outcome_kind is not None and _kind_name(outcome_kind) in (
            "unavailable",
            "internal_error",
        ):
            return False

        # Timed-out reference.
        if self.timed_out:
            if not timed_out:
                return False
        else:
            # Non-timeout reference: a timed-out run is never a match.
            if timed_out:
                return False

        # Signal reference.
        if self.signal_number is not None:
            if signal_number != self.signal_number:
                return False
        elif self.no_signal:
            if signal_number is not None:
                return False

        # Exit code reference.
        if self.exit_code is not None:
            if exit_code != self.exit_code:
                return False

        # Output substring checks. Both stdout and stderr are
        # consulted, concatenated. This mirrors the validator's own
        # matching logic.
        if self.stdout_contains or self.stdout_excludes:
            text = _combined_output(outcome)
            for needle in self.stdout_contains:
                if needle not in text:
                    return False
            for needle in self.stdout_excludes:
                if needle in text:
                    return False

        # Fingerprint check, only when the signature carries one.
        if self.fingerprint is not None:
            if parsed_fingerprint is None:
                return False
            if self.fingerprint != parsed_fingerprint:
                return False

        return True


# ---------------------------------------------------------------------------
# Config and result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReproductionConfig:
    """Immutable configuration for a :class:`Reproducer`.

    Fields
    ------
    runs:
        Number of attempts per reproduction. Must be positive.
    mode:
        Classification mode. See :class:`ReproductionMode`.
    verify_fingerprint:
        When True and the reference carries a fingerprint, require
        every matching attempt to also match on fingerprint.
    timeout_seconds:
        Per-attempt wall-clock timeout. When None, the target spec's
        own timeout is used.
    preserve_evidence:
        When True, per-attempt evidence is written to disk.
    evidence_root:
        Directory under which per-reproduction evidence directories
        are created. When None, evidence is not written even if
        ``preserve_evidence`` is True.
    max_evidence_bytes:
        Cap on the size of a single evidence artifact.
    stop_on_first_match:
        When True, the runner stops after the first matching attempt.
        Useful when the caller only needs to confirm that the
        behaviour is reproducible once, and not to characterise its
        stability.
    stop_on_first_error:
        When True, the runner stops on the first attempt that could
        not be executed. Useful when a missing target should abort
        the reproduction immediately rather than burn through
        attempts.
    """

    runs: int = DEFAULT_RUNS
    mode: ReproductionMode = ReproductionMode.MAJORITY
    verify_fingerprint: bool = True
    timeout_seconds: Optional[float] = None
    preserve_evidence: bool = False
    evidence_root: Optional[str] = None
    max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES
    stop_on_first_match: bool = False
    stop_on_first_error: bool = False

    def __post_init__(self) -> None:
        if self.runs <= 0:
            raise ValueError("runs must be positive")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive or None")
        if self.max_evidence_bytes <= 0:
            raise ValueError("max_evidence_bytes must be positive")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runs": self.runs,
            "mode": self.mode.value,
            "verify_fingerprint": self.verify_fingerprint,
            "timeout_seconds": self.timeout_seconds,
            "preserve_evidence": self.preserve_evidence,
            "evidence_root": self.evidence_root,
            "max_evidence_bytes": self.max_evidence_bytes,
            "stop_on_first_match": self.stop_on_first_match,
            "stop_on_first_error": self.stop_on_first_error,
        }


@dataclass
class ReproductionAttempt:
    """A single execution attempt within a reproduction."""

    attempt_index: int
    outcome: Optional["ValidationOutcome"]
    matched: bool
    errored: bool
    parsed_fingerprint: Optional[str] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    wall_seconds: float = 0.0
    error_message: Optional[str] = None
    evidence_path: Optional[Path] = None

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return self.wall_seconds
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def exit_code(self) -> Optional[int]:
        if self.outcome is None:
            return None
        return getattr(self.outcome, "exit_code", None)

    @property
    def signal_number(self) -> Optional[int]:
        if self.outcome is None:
            return None
        return getattr(self.outcome, "signal_number", None)

    @property
    def timed_out(self) -> bool:
        if self.outcome is None:
            return False
        return bool(getattr(self.outcome, "timed_out", False))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempt_index": self.attempt_index,
            "matched": self.matched,
            "errored": self.errored,
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "timed_out": self.timed_out,
            "parsed_fingerprint": self.parsed_fingerprint,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
            "wall_seconds": self.wall_seconds,
            "error_message": self.error_message,
            "evidence_path": (
                str(self.evidence_path) if self.evidence_path else None
            ),
            "outcome": (
                self.outcome.to_dict()
                if self.outcome is not None and hasattr(self.outcome, "to_dict")
                else None
            ),
        }


@dataclass
class ReproductionResult:
    """The complete result of a reproduction."""

    status: ReproductionStatus
    input_digest: str
    input_size: int
    reference: ReferenceSignature
    attempts: List[ReproductionAttempt] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    evidence_dir: Optional[Path] = None
    evidence_errors: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def attempt_count(self) -> int:
        return len(self.attempts)

    @property
    def matched_count(self) -> int:
        return sum(1 for a in self.attempts if a.matched)

    @property
    def errored_count(self) -> int:
        return sum(1 for a in self.attempts if a.errored)

    @property
    def executable_count(self) -> int:
        return sum(
            1 for a in self.attempts if not a.errored
        )

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def is_success(self) -> bool:
        return self.status is ReproductionStatus.REPRODUCED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "input_digest": self.input_digest,
            "input_size": self.input_size,
            "reference": self.reference.to_dict(),
            "attempt_count": self.attempt_count,
            "matched_count": self.matched_count,
            "errored_count": self.errored_count,
            "executable_count": self.executable_count,
            "attempts": [a.to_dict() for a in self.attempts],
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
            "duration_seconds": self.duration_seconds,
            "evidence_dir": str(self.evidence_dir) if self.evidence_dir else None,
            "evidence_errors": list(self.evidence_errors),
            "error_message": self.error_message,
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of this result."""
        parts = [
            self.status.value,
            f"{self.matched_count}/{self.attempt_count} matched",
        ]
        if self.errored_count:
            parts.append(f"{self.errored_count} errored")
        parts.append(f"digest={self.input_digest[:12]}")
        return " ".join(parts)


@dataclass
class ReproductionStats:
    """Aggregate statistics for a :class:`Reproducer` instance."""

    reproductions: int = 0
    attempts: int = 0
    reproduced: int = 0
    not_reproduced: int = 0
    intermittent: int = 0
    errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reproductions": self.reproductions,
            "attempts": self.attempts,
            "reproduced": self.reproduced,
            "not_reproduced": self.not_reproduced,
            "intermittent": self.intermittent,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Subsystem availability
# ---------------------------------------------------------------------------


#: Reported at import time so that callers can query which subsystems
#: the runner can delegate to.
SUBSYSTEM_AVAILABILITY: Mapping[str, bool] = {
    "corpus.validator": _HAVE_VALIDATOR,
    "analysis.crash_parser": _HAVE_CRASH_PARSER,
    "analysis.fingerprint": _HAVE_FINGERPRINT,
}


def _require_validator() -> None:
    """Raise :class:`ReproducerNotAvailableError` if the validator is missing."""
    if not _HAVE_VALIDATOR:
        raise ReproducerNotAvailableError(
            "corpus.validator", _VALIDATOR_IMPORT_ERROR
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _combined_output(outcome: "ValidationOutcome") -> str:
    """Return stdout + stderr as a single text blob.

    Uses the outcome's own helpers when available; falls back to
    decoding the raw byte attributes. The function never raises on a
    partially-populated outcome.
    """
    getter = getattr(outcome, "combined_output", None)
    if callable(getter):
        try:
            result = getter()
        except Exception:  # noqa: BLE001
            result = None
        if isinstance(result, str):
            return result
    stdout = getattr(outcome, "stdout", b"") or b""
    stderr = getattr(outcome, "stderr", b"") or b""
    try:
        return stdout.decode("utf-8", errors="replace") + stderr.decode(
            "utf-8", errors="replace"
        )
    except Exception:  # noqa: BLE001
        return ""


def _kind_name(kind: Any) -> str:
    """Return the string value of an outcome kind, tolerating None."""
    if kind is None:
        return ""
    value = getattr(kind, "value", None)
    if isinstance(value, str):
        return value
    return str(kind)


def _is_unavailable_kind(kind: Any) -> bool:
    """Return True if ``kind`` denotes an execution that could not happen."""
    name = _kind_name(kind)
    return name in ("unavailable", "internal_error")


def _fingerprint_parsed_crash(parsed: Any) -> Optional[str]:
    """Compute a stable fingerprint from a parsed crash record.

    The fingerprint is a SHA-256 over a canonical, sorted view of the
    record's string and integer fields. It is stable across processes
    and Python versions. Returns None if no usable fields are present.
    """
    if parsed is None:
        return None
    if _HAVE_FINGERPRINT and extract_features is not None:
        try:
            features = extract_features(_parsed_crash_to_bytes(parsed))
        except Exception:  # noqa: BLE001
            features = None
        if features is not None:
            # Prefer the fingerprint module's own stable representation
            # when it provides one; otherwise fall through to the
            # structural hash below.
            stable = getattr(features, "stable_hash", None)
            if callable(stable):
                try:
                    value = stable()
                except Exception:  # noqa: BLE001
                    value = None
                if isinstance(value, str):
                    return value

    # Structural hash: canonicalise fields, drop volatile ones.
    record: Dict[str, Any] = {}
    for key in (
        "kind",
        "category",
        "sanitizer",
        "error_type",
        "signal",
        "signal_number",
        "exit_code",
        "frames",
        "top_frame",
        "function",
        "file",
        "line",
        "access_type",
        "fault_address_pattern",
    ):
        value = getattr(parsed, key, None)
        if value is None and isinstance(parsed, Mapping):
            value = parsed.get(key)
        if value is None:
            continue
        record[key] = _canonicalize(value)
    if not record:
        return None
    try:
        payload = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
    except Exception:  # noqa: BLE001
        return None
    return _sha256(payload)


def _canonicalize(value: Any) -> Any:
    """Reduce an arbitrary value to a canonical, hashable form.

    - Scalars pass through unchanged.
    - Sequences become lists of canonicalised elements.
    - Mappings become sorted key/value lists.
    - Everything else becomes its string representation.
    """
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        return [
            [k, _canonicalize(v)]
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        ]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_canonicalize(v) for v in value]
    return str(value)


def _parsed_crash_to_bytes(parsed: Any) -> bytes:
    """Return a byte representation of a parsed crash, for fingerprinting."""
    if isinstance(parsed, (bytes, bytearray)):
        return bytes(parsed)
    try:
        return json.dumps(parsed, sort_keys=True, default=str).encode("utf-8")
    except Exception:  # noqa: BLE001
        return str(parsed).encode("utf-8", errors="replace")


def _truncate(data: bytes, limit: int) -> Tuple[bytes, bool]:
    """Truncate ``data`` to ``limit`` bytes; return (data, truncated)."""
    if limit <= 0 or len(data) <= limit:
        return data, False
    return data[:limit], True


def _safe_mkdir(path: Path) -> None:
    """Create ``path`` and its parents, ignoring race-with-mkdir errors."""
    path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Reproducer
# ---------------------------------------------------------------------------


class Reproducer:
    """Runs a saved input against the target and classifies the result.

    Parameters
    ----------
    target:
        A :class:`~kmcs.corpus.validator.TargetSpec` describing the
        target binary. Required.
    reference:
        The reference against which attempts are compared. May be an
        :class:`~kmcs.corpus.validator.ExpectedBehavior`, a
        :class:`~kmcs.corpus.validator.ValidationOutcome`, or a
        :class:`ReferenceSignature`. When None, the caller must pass
        a reference to :meth:`reproduce` explicitly.
    config:
        Optional :class:`ReproductionConfig`. Defaults are used when
        omitted.
    event_bus:
        Optional :class:`~kmcs.core.events.EventBus`.
    kmcs_config:
        Optional :class:`~kmcs.core.config.KMCSConfig`.
    validator:
        Optional pre-built :class:`~kmcs.corpus.validator.InputValidator`.
        When omitted, the runner constructs one from ``target``. This
        is the recommended way to share a validator between the
        reproduction layer and the campaign layer, so that both use
        the same scratch directory and the same target spec.
    """

    def __init__(
        self,
        target: Optional["TargetSpec"] = None,
        *,
        reference: Optional[Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature]] = None,
        config: Optional[ReproductionConfig] = None,
        event_bus: Optional[EventBus] = None,
        kmcs_config: Optional[KMCSConfig] = None,
        validator: Optional["InputValidator"] = None,
    ) -> None:
        _require_validator()

        if target is None and validator is None:
            raise ValueError(
                "either target or validator must be provided"
            )

        self._kmcs_config = kmcs_config or get_default_config()
        self._bus = event_bus or get_default_bus()
        self._config = config or ReproductionConfig()

        self._target = target
        self._validator: Optional["InputValidator"] = validator
        self._owns_validator = validator is None
        if self._validator is None:
            assert target is not None
            self._validator = InputValidator(  # type: ignore[misc]
                target,
                config=self._kmcs_config,
                event_bus=self._bus,
            )

        self._reference: Optional[ReferenceSignature] = None
        if reference is not None:
            self._reference = self._coerce_reference(reference)

        self._lock = threading.RLock()
        self._stats = ReproductionStats()
        self._closed = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def target(self) -> Optional["TargetSpec"]:
        return self._target

    @property
    def validator(self) -> "InputValidator":
        assert self._validator is not None
        return self._validator

    @property
    def config(self) -> ReproductionConfig:
        return self._config

    @property
    def reference(self) -> Optional[ReferenceSignature]:
        with self._lock:
            return self._reference

    @property
    def stats(self) -> ReproductionStats:
        with self._lock:
            return ReproductionStats(**self._stats.to_dict())

    @property
    def closed(self) -> bool:
        return self._closed

    # ------------------------------------------------------------------
    # Reference management
    # ------------------------------------------------------------------

    def set_reference(
        self,
        reference: Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature],
    ) -> ReferenceSignature:
        """Set or replace the reference used by subsequent reproductions."""
        with self._lock:
            self._reference = self._coerce_reference(reference)
            return self._reference

    def clear_reference(self) -> None:
        """Clear the reference. Subsequent calls must supply one explicitly."""
        with self._lock:
            self._reference = None

    def _coerce_reference(
        self,
        reference: Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature, Mapping[str, Any]],
    ) -> ReferenceSignature:
        """Normalise an arbitrary reference to a :class:`ReferenceSignature`."""
        if isinstance(reference, ReferenceSignature):
            return reference

        # ExpectedBehavior has a well-known shape: check for its
        # distinguishing fields before trying Outcome.
        if _HAVE_VALIDATOR and ExpectedBehavior is not None and isinstance(
            reference, ExpectedBehavior
        ):
            return ReferenceSignature.from_expected(
                reference, source="caller-supplied ExpectedBehavior"
            )

        # ValidationOutcome is recognised by its kind/exit_code/wall_seconds trio.
        if _HAVE_VALIDATOR and ValidationOutcome is not None and isinstance(
            reference, ValidationOutcome
        ):
            fingerprint = self._fingerprint_outcome(reference)
            return ReferenceSignature.from_outcome(
                reference,
                fingerprint=fingerprint,
                source="observed outcome",
            )

        # Fall back to duck-typed detection for callers who build
        # their own reference objects.
        if isinstance(reference, Mapping):
            return ReferenceSignature(
                exit_code=_coerce_optional_int(reference.get("exit_code")),
                signal_number=_coerce_optional_int(reference.get("signal_number")),
                timed_out=bool(reference.get("timed_out", False)),
                no_signal=bool(reference.get("no_signal", False)),
                stdout_contains=tuple(reference.get("stdout_contains") or ()),
                stdout_excludes=tuple(reference.get("stdout_excludes") or ()),
                fingerprint=reference.get("fingerprint"),
                source=str(reference.get("source", "mapping")),
            )

        if hasattr(reference, "kind") and hasattr(reference, "exit_code"):
            fingerprint = self._fingerprint_outcome(reference)
            return ReferenceSignature.from_outcome(
                reference,
                fingerprint=fingerprint,
                source="duck-typed outcome",
            )

        if hasattr(reference, "exit_code") and hasattr(reference, "stdout_contains"):
            return ReferenceSignature.from_expected(
                reference, source="duck-typed ExpectedBehavior"
            )

        raise TypeError(
            f"unsupported reference type: {type(reference).__name__}"
        )

    def _fingerprint_outcome(self, outcome: "ValidationOutcome") -> Optional[str]:
        """Compute a fingerprint for an outcome, if the parser is available."""
        if not _HAVE_CRASH_PARSER or parse_crash_output is None:
            return None
        parsed = self._parse_outcome(outcome)
        if parsed is None:
            return None
        return _fingerprint_parsed_crash(parsed)

    # ------------------------------------------------------------------
    # Public reproduction API
    # ------------------------------------------------------------------

    def reproduce(
        self,
        data: bytes,
        *,
        digest: Optional[str] = None,
        reference: Optional[Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature]] = None,
    ) -> ReproductionResult:
        """Reproduce the reference using ``data``.

        Parameters
        ----------
        data:
            The bytes to run against the target. Never modified.
        digest:
            Optional pre-computed SHA-256 digest of ``data``. When
            None, the digest is computed from the bytes.
        reference:
            Optional per-call reference that overrides the instance
            reference. When both are absent, :class:`ReferenceRequiredError`
            is raised.

        Returns
        -------
        ReproductionResult
            A structured verdict with per-attempt evidence.

        Raises
        ------
        ReferenceRequiredError
            If no reference is available.
        ReproducerNotAvailableError
            If the validator subsystem is unavailable.
        ReproductionError
            If the reproduction cannot start at all (for example, the
            target spec is missing).
        """
        if self._closed:
            raise ReproductionError("reproducer has been closed")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        payload = bytes(data)
        if digest is None:
            digest = _sha256(payload)

        with self._lock:
            ref = (
                self._coerce_reference(reference)
                if reference is not None
                else self._reference
            )
        if ref is None:
            raise ReferenceRequiredError(
                "no reference available; supply reference= or set one at construction"
            )

        started_at = _now_utc()
        result = ReproductionResult(
            status=ReproductionStatus.PENDING,
            input_digest=digest,
            input_size=len(payload),
            reference=ref,
            started_at=started_at,
        )

        self._emit(
            "REPRODUCTION_STARTED",
            {
                "input_digest": digest,
                "input_size": len(payload),
                "runs": self._config.runs,
                "mode": self._config.mode.value,
                "reference": ref.to_dict(),
            },
        )

        evidence_dir: Optional[Path] = None
        if self._config.preserve_evidence and self._config.evidence_root:
            evidence_dir = self._make_evidence_dir(digest)
            result.evidence_dir = evidence_dir

        try:
            self._run_attempts(payload, digest, ref, result, evidence_dir)
        except Exception as exc:  # noqa: BLE001 - top-level safety net
            logger.exception("reproduction failed unexpectedly")
            result.error_message = f"{type(exc).__name__}: {exc}"
            result.status = ReproductionStatus.ERROR

        # Classify, unless an internal error already forced ERROR.
        if result.status != ReproductionStatus.ERROR:
            try:
                result.status = self._classify(result.attempts)
            except Exception as exc:  # noqa: BLE001
                logger.exception("classification failed")
                result.error_message = f"classification failed: {exc}"
                result.status = ReproductionStatus.ERROR

        result.finished_at = _now_utc()

        if evidence_dir is not None:
            self._write_result_evidence(result, evidence_dir)

        with self._lock:
            self._stats.reproductions += 1
            self._stats.attempts += result.attempt_count
            if result.status is ReproductionStatus.REPRODUCED:
                self._stats.reproduced += 1
            elif result.status is ReproductionStatus.NOT_REPRODUCED:
                self._stats.not_reproduced += 1
            elif result.status is ReproductionStatus.INTERMITTENT:
                self._stats.intermittent += 1
            elif result.status is ReproductionStatus.ERROR:
                self._stats.errors += 1

        self._emit(
            "REPRODUCTION_FINISHED",
            {
                "input_digest": digest,
                "status": result.status.value,
                "attempts": result.attempt_count,
                "matched": result.matched_count,
                "errored": result.errored_count,
                "duration_seconds": result.duration_seconds,
            },
        )

        return result

    def reproduce_file(
        self,
        path: Union[str, os.PathLike[str]],
        *,
        digest: Optional[str] = None,
        reference: Optional[Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature]] = None,
    ) -> ReproductionResult:
        """Reproduce using the file at ``path`` as the input."""
        p = Path(path)
        try:
            data = p.read_bytes()
        except OSError as exc:
            raise ReproductionError(f"failed to read {p}: {exc}") from exc
        return self.reproduce(data, digest=digest, reference=reference)

    def reproduce_entry(
        self,
        entry: "CorpusEntry",
        *,
        reference: Optional[Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature]] = None,
    ) -> ReproductionResult:
        """Reproduce a :class:`~kmcs.corpus.manager.CorpusEntry`.

        The entry's digest is reused; the bytes are read from disk.
        Entries whose blob is missing produce an ERROR result rather
        than raising.
        """
        path = getattr(entry, "path", None)
        digest = getattr(entry, "digest", None)
        if path is None:
            result = self._empty_error_result(
                digest or "<unknown>",
                0,
                reference,
                "corpus entry has no path",
            )
            return result
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            return self._empty_error_result(
                digest or "<unknown>",
                0,
                reference,
                f"failed to read corpus entry: {exc}",
            )
        return self.reproduce(data, digest=digest, reference=reference)

    def reproduce_many(
        self,
        items: Iterable[Tuple[Optional[str], bytes]],
        *,
        reference: Optional[Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature]] = None,
    ) -> List[ReproductionResult]:
        """Reproduce several inputs serially.

        Failures on one item do not abort the batch: each item gets
        its own result object, and errors are recorded in it.
        """
        results: List[ReproductionResult] = []
        for digest, data in items:
            try:
                result = self.reproduce(
                    data, digest=digest, reference=reference
                )
            except ReferenceRequiredError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.exception("reproduce_many: item failed")
                results.append(
                    self._empty_error_result(
                        digest or "<unknown>",
                        len(data) if data else 0,
                        reference,
                        str(exc),
                    )
                )
                continue
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Core attempt loop
    # ------------------------------------------------------------------

    def _run_attempts(
        self,
        payload: bytes,
        digest: str,
        reference: ReferenceSignature,
        result: ReproductionResult,
        evidence_dir: Optional[Path],
    ) -> None:
        """Execute up to ``config.runs`` attempts, appending to ``result``."""
        for i in range(self._config.runs):
            attempt = ReproductionAttempt(
                attempt_index=i,
                outcome=None,
                matched=False,
                errored=False,
            )
            try:
                outcome = self._execute_once(payload, digest)
            except Exception as exc:  # noqa: BLE001
                attempt.errored = True
                attempt.error_message = f"{type(exc).__name__}: {exc}"
                attempt.finished_at = _now_utc()
                attempt.wall_seconds = (
                    attempt.finished_at - attempt.started_at
                ).total_seconds()
                result.attempts.append(attempt)
                if self._config.stop_on_first_error:
                    break
                continue

            attempt.outcome = outcome
            attempt.finished_at = _now_utc()
            attempt.wall_seconds = (
                attempt.finished_at - attempt.started_at
            ).total_seconds()

            # Classify executability from the outcome kind. An outcome
            # that could not be executed is treated as an error, not
            # as a match or a non-match.
            kind = getattr(outcome, "kind", None)
            if _is_unavailable_kind(kind):
                attempt.errored = True
                attempt.error_message = _error_message_from_outcome(outcome)
                result.attempts.append(attempt)
                if evidence_dir is not None:
                    self._write_attempt_evidence(attempt, evidence_dir)
                if self._config.stop_on_first_error:
                    break
                continue

            # Parse the crash output once; used for both fingerprinting
            # and for the parsed-crash field on the outcome (which the
            # validator may already have populated).
            parsed = self._parse_outcome(outcome)
            if parsed is not None:
                parsed_fp = _fingerprint_parsed_crash(parsed)
                attempt.parsed_fingerprint = parsed_fp
            else:
                parsed_fp = None

            attempt.matched = reference.matches_outcome(
                outcome,
                parsed_fingerprint=(
                    parsed_fp if self._config.verify_fingerprint else None
                ),
            )

            result.attempts.append(attempt)
            if evidence_dir is not None:
                self._write_attempt_evidence(attempt, evidence_dir)

            if attempt.matched and self._config.stop_on_first_match:
                break

    def _execute_once(
        self, payload: bytes, digest: str
    ) -> "ValidationOutcome":
        """Execute one attempt through the validator.

        Uses the synchronous wrapper so that the runner's public API
        is callable from any thread. The validator itself runs an
        event loop internally; the runner does not need to.
        """
        assert self._validator is not None
        try:
            outcome = self._validator.run_sync(payload, digest=digest)
        except ValidatorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ReproductionError(
                f"validator failed to run: {exc}"
            ) from exc
        if outcome is None:
            raise ReproductionError("validator returned no outcome")
        return outcome

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_outcome(self, outcome: "ValidationOutcome") -> Optional[Any]:
        """Parse the structural crash record for ``outcome``.

        Prefers the outcome's own ``parsed_crash`` when the validator
        already attached one; otherwise calls the parser directly.
        Returns None when the parser is unavailable or the output is
        not crash-like.
        """
        if outcome is None:
            return None
        existing = getattr(outcome, "parsed_crash", None)
        if existing is not None:
            return existing
        if not _HAVE_CRASH_PARSER or parse_crash_output is None:
            return None

        stdout = getattr(outcome, "stdout", b"") or b""
        stderr = getattr(outcome, "stderr", b"") or b""
        exit_code = getattr(outcome, "exit_code", None)
        signal_number = getattr(outcome, "signal_number", None)

        try:
            parsed = parse_crash_output(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                signal_number=signal_number,
            )
        except TypeError:
            # Older signature: positional args only.
            try:
                parsed = parse_crash_output(stdout, stderr, exit_code, signal_number)  # type: ignore[misc]
            except Exception as exc:  # noqa: BLE001
                logger.debug("crash parser failed: %s", exc)
                return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("crash parser failed: %s", exc)
            return None
        return parsed

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(self, attempts: Sequence[ReproductionAttempt]) -> ReproductionStatus:
        """Apply the configured mode to a sequence of attempts."""
        if not attempts:
            return ReproductionStatus.ERROR

        executable = [a for a in attempts if not a.errored]
        errored = [a for a in attempts if a.errored]
        matched = [a for a in executable if a.matched]
        unmatched = [a for a in executable if not a.matched]

        # All attempts errored: this is never REPRODUCED.
        if not executable:
            return ReproductionStatus.ERROR

        mode = self._config.mode

        if mode is ReproductionMode.STRICT:
            if errored:
                # Any errored attempt invalidates strict reproduction.
                return ReproductionStatus.ERROR
            if not unmatched:
                return ReproductionStatus.REPRODUCED
            if not matched:
                return ReproductionStatus.NOT_REPRODUCED
            return ReproductionStatus.INTERMITTENT

        if mode is ReproductionMode.MAJORITY:
            if len(matched) * 2 > len(executable):
                return ReproductionStatus.REPRODUCED
            if not matched:
                return ReproductionStatus.NOT_REPRODUCED
            return ReproductionStatus.INTERMITTENT

        if mode is ReproductionMode.ANY:
            if matched:
                return ReproductionStatus.REPRODUCED
            return ReproductionStatus.NOT_REPRODUCED

        if mode is ReproductionMode.ALL_OR_NONE:
            if not unmatched:
                return ReproductionStatus.REPRODUCED
            if not matched:
                return ReproductionStatus.NOT_REPRODUCED
            return ReproductionStatus.INTERMITTENT

        # Unknown mode: fail safe.
        return ReproductionStatus.ERROR

    # ------------------------------------------------------------------
    # Evidence handling
    # ------------------------------------------------------------------

    def _make_evidence_dir(self, digest: str) -> Optional[Path]:
        """Create a fresh evidence directory for a reproduction."""
        root = self._config.evidence_root
        if not root:
            return None
        timestamp = _now_utc().strftime("%Y%m%dT%H%M%S")
        dirname = f"{timestamp}-{digest[:16]}"
        base = Path(root) / DEFAULT_EVIDENCE_DIR_NAME / dirname
        try:
            _safe_mkdir(base)
        except OSError as exc:
            logger.warning("failed to create evidence dir %s: %s", base, exc)
            return None
        return base

    def _write_attempt_evidence(
        self, attempt: ReproductionAttempt, evidence_dir: Path
    ) -> None:
        """Write per-attempt evidence to disk."""
        path = evidence_dir / f"attempt-{attempt.attempt_index:03d}.json"
        try:
            payload = attempt.to_dict()
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to write attempt evidence: %s", exc)
            return

        attempt.evidence_path = path

        # Write stdout and stderr sidecars as well; they are the
        # primary artifact for human inspection.
        outcome = attempt.outcome
        if outcome is not None:
            stdout = getattr(outcome, "stdout", b"") or b""
            stderr = getattr(outcome, "stderr", b"") or b""
            limit = self._config.max_evidence_bytes
            stdout, _ = _truncate(stdout, limit)
            stderr, _ = _truncate(stderr, limit)
            try:
                (evidence_dir / f"attempt-{attempt.attempt_index:03d}.stdout").write_bytes(stdout)
                (evidence_dir / f"attempt-{attempt.attempt_index:03d}.stderr").write_bytes(stderr)
            except OSError as exc:
                logger.debug("failed to write attempt streams: %s", exc)

    def _write_result_evidence(
        self, result: ReproductionResult, evidence_dir: Path
    ) -> None:
        """Write the result summary to the evidence directory."""
        path = evidence_dir / "result.json"
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(result.to_dict(), fh, indent=2, default=str)
        except Exception as exc:  # noqa: BLE001
            result.evidence_errors.append(
                f"failed to write result evidence: {exc}"
            )

    # ------------------------------------------------------------------
    # Error result helpers
    # ------------------------------------------------------------------

    def _empty_error_result(
        self,
        digest: str,
        size: int,
        reference: Optional[Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature]],
        message: str,
    ) -> ReproductionResult:
        """Build a well-formed ERROR result for a reproduction that could not run."""
        if reference is not None:
            ref = self._coerce_reference(reference)
        else:
            with self._lock:
                ref = self._reference
        if ref is None:
            ref = ReferenceSignature(source="unavailable")
        result = ReproductionResult(
            status=ReproductionStatus.ERROR,
            input_digest=digest,
            input_size=size,
            reference=ref,
            error_message=message,
        )
        result.finished_at = _now_utc()
        return result

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
                source="reproduction.runner",
                data={"event": event_name, **payload},
            )
            self._bus.publish(event)
        except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
            logger.debug("reproduction event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release the validator if the runner owns it.

        Idempotent. A runner that was constructed with an externally
        supplied validator does not close it: the caller owns that
        object and may share it with other components.
        """
        if self._closed:
            return
        self._closed = True
        if self._owns_validator and self._validator is not None:
            try:
                self._validator.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("validator close failed: %s", exc)

    def __enter__(self) -> "Reproducer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:
        target_name = getattr(self._target, "command", None) if self._target else None
        return (
            f"Reproducer(target={target_name!r}, "
            f"runs={self._config.runs}, "
            f"mode={self._config.mode.value})"
        )


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def reproduce_once(
    target: "TargetSpec",
    data: bytes,
    reference: Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature],
    *,
    timeout_seconds: Optional[float] = None,
    event_bus: Optional[EventBus] = None,
    kmcs_config: Optional[KMCSConfig] = None,
) -> ReproductionResult:
    """Run ``data`` once and return a single-attempt result.

    Convenience wrapper for callers who only need a yes/no answer and
    do not care about stability. For anything more nuanced, construct
    a :class:`Reproducer` directly.
    """
    config = ReproductionConfig(
        runs=1,
        mode=ReproductionMode.STRICT,
        timeout_seconds=timeout_seconds,
    )
    with Reproducer(
        target,
        reference=reference,
        config=config,
        event_bus=event_bus,
        kmcs_config=kmcs_config,
    ) as repro:
        return repro.reproduce(data)


def reproduce_with_retries(
    target: "TargetSpec",
    data: bytes,
    reference: Union["ExpectedBehavior", "ValidationOutcome", ReferenceSignature],
    *,
    runs: int = DEFAULT_RUNS,
    mode: Union[ReproductionMode, str] = ReproductionMode.MAJORITY,
    timeout_seconds: Optional[float] = None,
    preserve_evidence: bool = False,
    evidence_root: Optional[str] = None,
    event_bus: Optional[EventBus] = None,
    kmcs_config: Optional[KMCSConfig] = None,
) -> ReproductionResult:
    """Run ``data`` ``runs`` times and classify the result.

    Convenience wrapper. Mode may be given as a string for callers
    that persist the mode in configuration files.
    """
    if isinstance(mode, str):
        try:
            mode_enum = ReproductionMode(mode)
        except ValueError as exc:
            raise ValueError(f"unknown reproduction mode: {mode!r}") from exc
    else:
        mode_enum = mode

    config = ReproductionConfig(
        runs=runs,
        mode=mode_enum,
        timeout_seconds=timeout_seconds,
        preserve_evidence=preserve_evidence,
        evidence_root=evidence_root,
    )
    with Reproducer(
        target,
        reference=reference,
        config=config,
        event_bus=event_bus,
        kmcs_config=kmcs_config,
    ) as repro:
        return repro.reproduce(data)


# ---------------------------------------------------------------------------
# Small private helpers
# ---------------------------------------------------------------------------


def _coerce_optional_int(value: Any) -> Optional[int]:
    """Return an int or None, tolerating strings and floats."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _error_message_from_outcome(outcome: "ValidationOutcome") -> str:
    """Extract a human-readable error message from an unavailable outcome."""
    msg = getattr(outcome, "error_message", None)
    if isinstance(msg, str) and msg:
        return msg
    kind = getattr(outcome, "kind", None)
    name = _kind_name(kind)
    if name:
        return f"outcome kind: {name}"
    return "execution unavailable"


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
