"""
KMCS Corpus Validator
=====================

Objective execution-based validation for corpus inputs.

The validator's job is narrow and deliberately unambitious: given a
corpus input and a description of an authorised target binary, run the
binary once, capture *what actually happened*, and return a structured
record. It does **not** classify crashes, assign severity, or attempt
to reason about exploitability — those concerns belong to
:mod:`kmcs.analysis.crash_parser` and friends, which are invoked
opportunistically to enrich the raw record.

Design constraints
------------------

* **No blocking calls on the event loop.** Every subprocess is spawned
  via :func:`asyncio.create_subprocess_exec`. Timeouts are enforced
  with :func:`asyncio.wait_for`, which cancels the child if it runs
  past the deadline.

* **No shell interpretation.** Target arguments are passed as a list
  of strings directly to ``exec``; a string ``command`` field is never
  split with ``shell=True``. This is a defensive measure: corpus inputs
  are untrusted, and the validator must not introduce a second
  injection surface.

* **Honest reporting.** If a signal cannot be captured (e.g. Windows),
  the corresponding field is ``None`` rather than a fabricated value.
  If the target binary is missing, that is reported as an error, not
  as a "validation failure".

* **Filesystem containment.** Input files are written into a private
  temporary directory for the duration of the run and removed
  afterwards, regardless of outcome. The validator never writes into
  the corpus root.

* **Deterministic environment.** By default the child inherits a
  minimal, sanitised environment with any ASan/UBSan/LSan options
  passed through verbatim.

Public surface
--------------

* :class:`TargetSpec` — declarative description of a target binary.
* :class:`ExpectedBehavior` — objective success criteria.
* :class:`ValidationOutcome` — the objective outcome of one run.
* :class:`ValidationResult` — aggregate result for a batch of inputs.
* :class:`InputValidator` — the main entry point.
* :func:`make_reproduction_predicate` — factory returning a callable
  predicate consumed by :mod:`kmcs.corpus.minimizer`.

The predicate returned by :func:`make_reproduction_predicate` is
intentionally synchronous: the minimizer runs on a worker thread, and
spinning up an event loop per candidate would be wasteful. The
validator therefore exposes both an async API (used by callers already
inside an event loop) and a synchronous ``run_sync`` wrapper.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from ..core.exceptions import KMCSException
from ..core.events import EventBus, Event, EventType, get_default_bus
from ..core.config import KMCSConfig, get_default_config

# Optional structural parser. When present, we delegate crash
# interpretation to it; when absent, we simply record the raw fields.
try:  # pragma: no cover - exercised indirectly
    from ..analysis.crash_parser import (
        parse_crash_output,
        ParsedCrash,
    )
    _HAVE_CRASH_PARSER = True
except Exception:  # noqa: BLE001
    parse_crash_output = None  # type: ignore[assignment]
    ParsedCrash = None  # type: ignore[assignment]
    _HAVE_CRASH_PARSER = False


__all__ = [
    "InputValidator",
    "TargetSpec",
    "ExpectedBehavior",
    "ValidationOutcome",
    "ValidationResult",
    "OutcomeKind",
    "ValidatorError",
    "TargetNotFoundError",
    "TargetPermissionError",
    "ValidationTimeout",
    "make_reproduction_predicate",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_MEMORY_LIMIT_BYTES",
    "DEFAULT_STDOUT_LIMIT_BYTES",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Default wall-clock timeout for a single validation run, in seconds.
DEFAULT_TIMEOUT_SECONDS: float = 10.0

#: Default per-process memory ceiling (best-effort; enforced by the
#: operating system where supported).
DEFAULT_MEMORY_LIMIT_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GiB

#: Default cap on captured stdout/stderr bytes. Output beyond this
#: limit is truncated and marked as such in the result.
DEFAULT_STDOUT_LIMIT_BYTES: int = 4 * 1024 * 1024  # 4 MiB

#: Environment variables that are always forwarded to the child.
_ENV_PASSTHROUGH = (
    "ASAN_OPTIONS",
    "UBSAN_OPTIONS",
    "LSAN_OPTIONS",
    "TSAN_OPTIONS",
    "MSAN_OPTIONS",
    "AFL_DEBUG",
    "AFL_MAP_SIZE",
    "AFL_PRELOAD",
    "LLVM_PROFILE_FILE",
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TZ",
    "TMPDIR",
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ValidatorError(KMCSException):
    """Base class for validator errors."""


class TargetNotFoundError(ValidatorError):
    """Raised when the target binary does not exist or is not executable."""


class TargetPermissionError(ValidatorError):
    """Raised when the target binary exists but cannot be executed."""


class ValidationTimeout(ValidatorError):
    """Raised internally when a run exceeds its deadline."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        super().__init__(f"validation run exceeded {seconds:.3f}s timeout")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class OutcomeKind(str, Enum):
    """Coarse-grained classification of a single validation run.

    The enum values are stable strings suitable for persistence and for
    use as dictionary keys in reports.
    """

    #: The process exited with status 0 within the timeout.
    CLEAN = "clean"
    #: The process exited with a non-zero code but was not killed by a
    #: signal (e.g. ``exit(1)``, ``abort()`` producing SIGABRT is
    #: classified as CRASH).
    EXIT_NONZERO = "exit_nonzero"
    #: The process terminated via a signal (SIGSEGV, SIGABRT, ...).
    CRASH = "crash"
    #: The process was still running when the timeout fired.
    TIMEOUT = "timeout"
    #: The target could not be started at all (missing, unreadable,
    #: permission denied, etc.).
    UNAVAILABLE = "unavailable"
    #: The validator itself failed for an unexpected reason.
    INTERNAL_ERROR = "internal_error"


# ---------------------------------------------------------------------------
# Target description
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetSpec:
    """Declarative description of an authorised target binary.

    Parameters
    ----------
    command:
        Absolute or relative path to the executable. Must be a regular
        file with the executable bit set (POSIX) or a recognised
        executable extension (Windows).
    args:
        Extra argv entries inserted *before* the input file path.
        For example, ``("-runs=1",)`` for libFuzzer.
    input_style:
        How the input file is presented to the target. Supported
        values:

        * ``"argv"`` — the input file path is appended to argv. This
          is the default and matches AFL++'s ``@@`` convention.
        * ``"stdin"`` — the input bytes are piped to the target's
          standard input; argv is left unchanged.
    env:
        Extra environment variables to set for the child. Values
        override the inherited environment.
    cwd:
        Working directory for the child. When None, a fresh temporary
        directory is used so the target cannot scribble in the
        validator's cwd.
    timeout_seconds:
        Per-run wall-clock timeout. Defaults to
        :data:`DEFAULT_TIMEOUT_SECONDS`.
    memory_limit_bytes:
        Per-process memory ceiling. Best-effort; ignored on platforms
        that do not support it.
    stdout_limit_bytes:
        Cap on captured stdout.
    stderr_limit_bytes:
        Cap on captured stderr.
    """

    command: str
    args: Tuple[str, ...] = ()
    input_style: str = "argv"
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    memory_limit_bytes: int = DEFAULT_MEMORY_LIMIT_BYTES
    stdout_limit_bytes: int = DEFAULT_STDOUT_LIMIT_BYTES
    stderr_limit_bytes: int = DEFAULT_STDOUT_LIMIT_BYTES

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("TargetSpec.command must not be empty")
        if self.input_style not in ("argv", "stdin"):
            raise ValueError(
                f"unsupported input_style: {self.input_style!r}"
            )
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.memory_limit_bytes <= 0:
            raise ValueError("memory_limit_bytes must be positive")

    @property
    def resolved_command(self) -> Path:
        """Return the resolved absolute path of the target binary."""
        p = Path(self.command).expanduser()
        try:
            return p.resolve(strict=False)
        except OSError:
            return p

    def validate_executable(self) -> None:
        """Check that the target exists and is executable.

        Raises
        ------
        TargetNotFoundError
            If the binary is missing.
        TargetPermissionError
            If the binary cannot be executed.
        """
        path = self.resolved_command
        if not path.exists():
            raise TargetNotFoundError(f"target not found: {path}")
        if not path.is_file():
            raise TargetNotFoundError(f"target is not a regular file: {path}")
        if os.name == "posix":
            st = path.stat()
            if not (st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                raise TargetPermissionError(
                    f"target is not executable: {path}"
                )
        if not os.access(path, os.X_OK):
            raise TargetPermissionError(f"target is not executable: {path}")


# ---------------------------------------------------------------------------
# Expected behavior
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExpectedBehavior:
    """Objective success criteria for a validation run.

    Every field is optional; the more fields are supplied, the stricter
    the predicate becomes. A run is considered "as expected" when every
    supplied criterion holds.

    Notes
    -----
    A ``crash`` is *not* by itself a mismatch — many validators are
    specifically looking for crashes. The criteria here describe *what
    the caller wants to count as success*; the minimizer then reduces
    an input while preserving that success.
    """

    #: When set, the process must exit with exactly this status code.
    exit_code: Optional[int] = None
    #: When set, the process must be terminated by exactly this signal
    #: number (POSIX only). Mutually exclusive with ``no_signal``.
    signal_number: Optional[int] = None
    #: When True, the process must *not* have been killed by a signal.
    no_signal: bool = False
    #: When set, at least one of these substrings must appear in
    #: stdout or stderr.
    stdout_contains: Tuple[str, ...] = ()
    #: When set, none of these substrings may appear in stdout/stderr.
    stdout_excludes: Tuple[str, ...] = ()
    #: When True, the run must have timed out.
    timed_out: bool = False
    #: When True, the run must *not* have timed out.
    not_timed_out: bool = False
    #: When set, the process must have terminated within this many
    #: seconds of the start of execution.
    max_wall_seconds: Optional[float] = None
    #: When set, the process must have run for at least this many
    #: seconds (useful for hang-detection).
    min_wall_seconds: Optional[float] = None

    def describe(self) -> str:
        """Return a human-readable summary of these criteria."""
        parts: List[str] = []
        if self.exit_code is not None:
            parts.append(f"exit_code={self.exit_code}")
        if self.signal_number is not None:
            parts.append(f"signal={self.signal_number}")
        if self.no_signal:
            parts.append("no_signal")
        if self.stdout_contains:
            parts.append(f"stdout~={list(self.stdout_contains)!r}")
        if self.stdout_excludes:
            parts.append(f"stdout!={list(self.stdout_excludes)!r}")
        if self.timed_out:
            parts.append("timed_out")
        if self.not_timed_out:
            parts.append("not_timed_out")
        if self.max_wall_seconds is not None:
            parts.append(f"max_wall<={self.max_wall_seconds}")
        if self.min_wall_seconds is not None:
            parts.append(f"min_wall>={self.min_wall_seconds}")
        return ", ".join(parts) if parts else "<empty>"


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass
class ValidationOutcome:
    """Objective outcome of a single validation run.

    All fields are populated from real observations. When a field could
    not be observed (e.g. ``signal_number`` on Windows), it is ``None``.
    No field is ever fabricated.
    """

    kind: OutcomeKind
    input_digest: Optional[str] = None
    input_path: Optional[Path] = None
    input_size: int = 0
    command: Tuple[str, ...] = ()
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    wall_seconds: float = 0.0
    exit_code: Optional[int] = None
    signal_number: Optional[int] = None
    timed_out: bool = False
    stdout: bytes = b""
    stderr: bytes = b""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    error_message: Optional[str] = None
    parsed_crash: Optional[Any] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def stdout_text(self) -> str:
        """Return stdout decoded as UTF-8 with replacement."""
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def stderr_text(self) -> str:
        """Return stderr decoded as UTF-8 with replacement."""
        return self.stderr.decode("utf-8", errors="replace")

    @property
    def combined_output(self) -> str:
        """Return stdout and stderr concatenated as text."""
        return self.stdout_text + self.stderr_text

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of this outcome."""
        return {
            "kind": self.kind.value,
            "input_digest": self.input_digest,
            "input_path": str(self.input_path) if self.input_path else None,
            "input_size": self.input_size,
            "command": list(self.command),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "wall_seconds": self.wall_seconds,
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "timed_out": self.timed_out,
            "stdout_size": len(self.stdout),
            "stderr_size": len(self.stderr),
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "error_message": self.error_message,
            "has_parsed_crash": self.parsed_crash is not None,
            "extra": dict(self.extra),
        }

    def matches(self, expected: ExpectedBehavior) -> bool:
        """Return True if this outcome satisfies ``expected``.

        Every supplied criterion is checked; missing criteria are
        treated as satisfied.
        """
        if expected.exit_code is not None and self.exit_code != expected.exit_code:
            return False
        if expected.signal_number is not None:
            if self.signal_number != expected.signal_number:
                return False
        if expected.no_signal and self.signal_number is not None:
            return False
        text = self.combined_output
        for needle in expected.stdout_contains:
            if needle not in text:
                return False
        for needle in expected.stdout_excludes:
            if needle in text:
                return False
        if expected.timed_out and not self.timed_out:
            return False
        if expected.not_timed_out and self.timed_out:
            return False
        if (
            expected.max_wall_seconds is not None
            and self.wall_seconds > expected.max_wall_seconds
        ):
            return False
        if (
            expected.min_wall_seconds is not None
            and self.wall_seconds < expected.min_wall_seconds
        ):
            return False
        return True


@dataclass
class ValidationResult:
    """Aggregate result of validating a batch of inputs."""

    outcomes: List[ValidationOutcome] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def clean_count(self) -> int:
        return sum(1 for o in self.outcomes if o.kind == OutcomeKind.CLEAN)

    @property
    def crash_count(self) -> int:
        return sum(1 for o in self.outcomes if o.kind == OutcomeKind.CRASH)

    @property
    def timeout_count(self) -> int:
        return sum(1 for o in self.outcomes if o.kind == OutcomeKind.TIMEOUT)

    @property
    def error_count(self) -> int:
        return sum(
            1
            for o in self.outcomes
            if o.kind in (OutcomeKind.UNAVAILABLE, OutcomeKind.INTERNAL_ERROR)
        )

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def by_kind(self) -> Dict[str, int]:
        """Return a count of outcomes grouped by :class:`OutcomeKind`."""
        counts: Dict[str, int] = {}
        for o in self.outcomes:
            counts[o.kind.value] = counts.get(o.kind.value, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcomes": [o.to_dict() for o in self.outcomes],
            "total": self.total,
            "clean": self.clean_count,
            "crash": self.crash_count,
            "timeout": self.timeout_count,
            "error": self.error_count,
            "by_kind": self.by_kind(),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
        }


# ---------------------------------------------------------------------------
# InputValidator
# ---------------------------------------------------------------------------


class InputValidator:
    """Executes corpus inputs against an authorised target binary.

    The validator maintains a small scratch directory for staging input
    files. This directory is created lazily on first use and removed by
    :meth:`close`. Callers may also use the object as a context manager
    to guarantee cleanup.

    Parameters
    ----------
    target:
        The :class:`TargetSpec` describing the target binary.
    config:
        Optional :class:`~kmcs.core.config.KMCSConfig`.
    event_bus:
        Optional event bus. When omitted, the process-wide default bus
        is used.
    scratch_dir:
        Optional directory to use as scratch space. When None, a fresh
        temporary directory is created.
    """

    def __init__(
        self,
        target: TargetSpec,
        *,
        config: Optional[KMCSConfig] = None,
        event_bus: Optional[EventBus] = None,
        scratch_dir: Optional[Union[str, os.PathLike[str]]] = None,
    ) -> None:
        self._target = target
        self._config = config or get_default_config()
        self._bus = event_bus or get_default_bus()
        self._scratch_owner = scratch_dir is None
        if scratch_dir is None:
            self._scratch = Path(
                tempfile.mkdtemp(prefix="kmcs-validate-")
            ).resolve()
        else:
            self._scratch = Path(scratch_dir).expanduser().resolve()
            self._scratch.mkdir(parents=True, exist_ok=True)
        self._closed = False
        self._runs = 0
        # We intentionally do NOT call target.validate_executable() at
        # construction time: a validator may be constructed before the
        # target is built (e.g. in a job-graph node), and the caller may
        # want to inspect the outcome of a missing-target run.

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def target(self) -> TargetSpec:
        return self._target

    @property
    def scratch_dir(self) -> Path:
        return self._scratch

    @property
    def runs(self) -> int:
        """Number of completed runs since construction."""
        return self._runs

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    def _emit(self, event_type: EventType, payload: Dict[str, Any]) -> None:
        try:
            event = Event(type=event_type, source="corpus.validator", data=payload)
            self._bus.publish(event)
        except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
            logger.warning("validator event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------------

    def _build_env(self) -> Dict[str, str]:
        """Construct the child environment.

        The inherited environment is filtered to a small allowlist of
        variables that are relevant to sanitizers and to the dynamic
        linker, then overlaid with the caller-supplied additions.
        """
        env: Dict[str, str] = {}
        for key in _ENV_PASSTHROUGH:
            value = os.environ.get(key)
            if value is not None:
                env[key] = value
        # Ensure PATH exists so the kernel can find shared libraries
        # via the loader.
        env.setdefault("PATH", os.defpath)
        for key, value in self._target.env.items():
            env[key] = value
        return env

    # ------------------------------------------------------------------
    # Command assembly
    # ------------------------------------------------------------------

    def _build_argv(self, input_path: Path) -> List[str]:
        """Return the argv list for a run against ``input_path``."""
        cmd = str(self._target.resolved_command)
        argv = [cmd, *self._target.args]
        if self._target.input_style == "argv":
            argv.append(str(input_path))
        return argv

    # ------------------------------------------------------------------
    # Async execution
    # ------------------------------------------------------------------

    async def validate_bytes(
        self,
        data: bytes,
        *,
        digest: Optional[str] = None,
    ) -> ValidationOutcome:
        """Run the target against ``data`` and return the outcome."""
        if self._closed:
            raise ValidatorError("validator has been closed")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        payload = bytes(data)
        input_size = len(payload)

        # Stage the input file.
        try:
            input_path = self._stage_input(payload)
        except OSError as exc:
            return self._unavailable_outcome(
                error=f"failed to stage input: {exc}",
                input_size=input_size,
                digest=digest,
            )

        try:
            outcome = await self._execute(input_path, digest=digest)
        finally:
            try:
                input_path.unlink()
            except OSError:
                pass

        self._runs += 1
        return outcome

    async def validate_file(
        self,
        path: Union[str, os.PathLike[str]],
        *,
        digest: Optional[str] = None,
    ) -> ValidationOutcome:
        """Run the target against the file at ``path``.

        The file is copied into the validator's scratch directory
        before execution, so the original is never exposed to the
        target and cannot be mutated by it.
        """
        if self._closed:
            raise ValidatorError("validator has been closed")
        src = Path(path)
        if not src.exists():
            return self._unavailable_outcome(
                error=f"input file does not exist: {src}",
                input_size=0,
                digest=digest,
            )
        try:
            data = src.read_bytes()
        except OSError as exc:
            return self._unavailable_outcome(
                error=f"failed to read input file: {exc}",
                input_size=0,
                digest=digest,
            )
        return await self.validate_bytes(data, digest=digest)

    async def validate_many(
        self,
        items: Iterable[Tuple[Optional[str], bytes]],
        *,
        concurrency: int = 1,
    ) -> ValidationResult:
        """Validate several inputs, optionally in parallel.

        Parameters
        ----------
        items:
            Iterable of ``(digest, bytes)`` pairs.
        concurrency:
            Maximum number of simultaneous runs. A value of 1 (the
            default) serialises execution.
        """
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        result = ValidationResult()
        if concurrency == 1:
            for digest, data in items:
                result.outcomes.append(
                    await self.validate_bytes(data, digest=digest)
                )
        else:
            semaphore = asyncio.Semaphore(concurrency)

            async def _run_one(
                digest: Optional[str], data: bytes
            ) -> ValidationOutcome:
                async with semaphore:
                    return await self.validate_bytes(data, digest=digest)

            tasks = [
                asyncio.create_task(_run_one(digest, data))
                for digest, data in items
            ]
            outcomes = await asyncio.gather(*tasks)
            result.outcomes.extend(outcomes)
        result.finished_at = datetime.now(timezone.utc)
        return result

    # ------------------------------------------------------------------
    # Synchronous wrapper
    # ------------------------------------------------------------------

    def run_sync(
        self,
        data: bytes,
        *,
        digest: Optional[str] = None,
    ) -> ValidationOutcome:
        """Synchronous wrapper around :meth:`validate_bytes`.

        This method cannot be called from inside a running event loop;
        callers in that situation should ``await validate_bytes``
        instead.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise ValidatorError(
                "run_sync cannot be called from within an event loop; "
                "await validate_bytes instead"
            )
        return asyncio.run(self.validate_bytes(data, digest=digest))

    # ------------------------------------------------------------------
    # Core execution
    # ------------------------------------------------------------------

    async def _execute(
        self,
        input_path: Path,
        *,
        digest: Optional[str] = None,
    ) -> ValidationOutcome:
        """Run the target once against ``input_path``."""
        target = self._target
        try:
            target.validate_executable()
        except TargetNotFoundError as exc:
            return self._unavailable_outcome(
                error=str(exc),
                input_size=input_path.stat().st_size if input_path.exists() else 0,
                digest=digest,
            )
        except TargetPermissionError as exc:
            return self._unavailable_outcome(
                error=str(exc),
                input_size=input_path.stat().st_size if input_path.exists() else 0,
                digest=digest,
            )

        argv = self._build_argv(input_path)
        env = self._build_env()
        cwd = self._target.cwd or str(self._scratch)

        stdin_pipe: Optional[int] = None
        if self._target.input_style == "stdin":
            stdin_arg: Union[int, asyncio.subprocess.Process] = asyncio.subprocess.PIPE
            stdin_data = input_path.read_bytes()
        else:
            stdin_arg = asyncio.subprocess.DEVNULL
            stdin_data = b""

        started_at = datetime.now(timezone.utc)
        t0 = time.perf_counter()

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=stdin_arg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                **self._preexec_options(),
            )
        except FileNotFoundError as exc:
            return self._unavailable_outcome(
                error=f"target not found: {exc}",
                input_size=input_path.stat().st_size,
                digest=digest,
                started_at=started_at,
            )
        except PermissionError as exc:
            return self._unavailable_outcome(
                error=f"target not executable: {exc}",
                input_size=input_path.stat().st_size,
                digest=digest,
                started_at=started_at,
            )
        except OSError as exc:
            return self._unavailable_outcome(
                error=f"failed to spawn target: {exc}",
                input_size=input_path.stat().st_size,
                digest=digest,
                started_at=started_at,
            )

        timed_out = False
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                self._communicate(proc, stdin_data),
                timeout=target.timeout_seconds,
            )
        except asyncio.TimeoutError:
            timed_out = True
            stdout_bytes, stderr_bytes = await self._drain_after_timeout(proc)

        wall = time.perf_counter() - t0
        finished_at = datetime.now(timezone.utc)

        # Truncate captured output to caller-requested limits.
        stdout_bytes, stdout_trunc = _truncate(
            stdout_bytes, target.stdout_limit_bytes
        )
        stderr_bytes, stderr_trunc = _truncate(
            stderr_bytes, target.stderr_limit_bytes
        )

        exit_code, signal_number = self._extract_exit(proc)

        kind = self._classify(
            timed_out=timed_out,
            exit_code=exit_code,
            signal_number=signal_number,
        )

        outcome = ValidationOutcome(
            kind=kind,
            input_digest=digest,
            input_path=input_path,
            input_size=input_path.stat().st_size if input_path.exists() else 0,
            command=tuple(argv),
            started_at=started_at,
            finished_at=finished_at,
            wall_seconds=wall,
            exit_code=exit_code,
            signal_number=signal_number,
            timed_out=timed_out,
            stdout=stdout_bytes,
            stderr=stderr_bytes,
            stdout_truncated=stdout_trunc,
            stderr_truncated=stderr_trunc,
        )

        # Delegate structural crash parsing when applicable.
        if kind in (OutcomeKind.CRASH, OutcomeKind.EXIT_NONZERO) and _HAVE_CRASH_PARSER:
            self._attach_parsed_crash(outcome)

        self._emit(
            EventType.CORPUS_VALIDATED,
            {
                "digest": digest,
                "kind": kind.value,
                "exit_code": exit_code,
                "signal": signal_number,
                "timed_out": timed_out,
                "wall_seconds": wall,
                "command": list(argv),
            },
        )
        return outcome

    async def _communicate(
        self,
        proc: asyncio.subprocess.Process,
        stdin_data: bytes,
    ) -> Tuple[bytes, bytes]:
        """Await process completion and return (stdout, stderr)."""
        if stdin_data and proc.stdin is not None:
            try:
                proc.stdin.write(stdin_data)
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                # The target may exit before consuming all stdin; that
                # is not an error.
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:  # noqa: BLE001
                    pass
        stdout, stderr = await proc.communicate()
        return stdout or b"", stderr or b""

    async def _drain_after_timeout(
        self,
        proc: asyncio.subprocess.Process,
    ) -> Tuple[bytes, bytes]:
        """Kill ``proc`` and collect whatever output it produced."""
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to kill timed-out process: %s", exc)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("target did not exit after SIGKILL; abandoning")
            stdout, stderr = b"", b""
        except Exception as exc:  # noqa: BLE001
            logger.debug("communicate after kill failed: %s", exc)
            stdout, stderr = b"", b""
        return stdout or b"", stderr or b""

    def _preexec_options(self) -> Dict[str, Any]:
        """Return platform-specific spawn options.

        On POSIX we install a ``preexec_fn`` that applies a memory
        limit via ``setrlimit(RLIMIT_AS)``; on Windows we return an
        empty dict.
        """
        if os.name != "posix":
            return {}
        limit = self._target.memory_limit_bytes

        def _apply_limits() -> None:  # pragma: no cover - runs in child
            try:
                import resource

                resource.setrlimit(
                    resource.RLIMIT_AS, (limit, limit)
                )
            except Exception:
                # Best-effort; not all platforms support RLIMIT_AS.
                pass
            # Detach the child from our process group so we can signal
            # it independently.
            try:
                os.setsid()
            except OSError:
                pass

        return {"preexec_fn": _apply_limits}

    def _extract_exit(
        self, proc: asyncio.subprocess.Process
    ) -> Tuple[Optional[int], Optional[int]]:
        """Return ``(exit_code, signal_number)`` for a finished process.

        On POSIX, ``proc.returncode`` is negative when the process was
        killed by a signal, so we translate to a positive signal number
        and set ``exit_code`` to None. On Windows we surface the exit
        code directly and leave the signal as None.
        """
        rc = proc.returncode
        if rc is None:
            return None, None
        if os.name == "posix" and rc < 0:
            return None, -rc
        return rc, None

    def _classify(
        self,
        *,
        timed_out: bool,
        exit_code: Optional[int],
        signal_number: Optional[int],
    ) -> OutcomeKind:
        """Map raw process state to an :class:`OutcomeKind`."""
        if timed_out:
            return OutcomeKind.TIMEOUT
        if signal_number is not None:
            return OutcomeKind.CRASH
        if exit_code == 0:
            return OutcomeKind.CLEAN
        return OutcomeKind.EXIT_NONZERO

    def _attach_parsed_crash(self, outcome: ValidationOutcome) -> None:
        """Attach a structural parse of the crash output, if possible."""
        try:
            parsed = parse_crash_output(  # type: ignore[misc]
                stdout=outcome.stdout,
                stderr=outcome.stderr,
                exit_code=outcome.exit_code,
                signal_number=outcome.signal_number,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("crash parser raised: %s", exc)
            return
        outcome.parsed_crash = parsed

    # ------------------------------------------------------------------
    # Staging helpers
    # ------------------------------------------------------------------

    def _stage_input(self, data: bytes) -> Path:
        """Write ``data`` to a fresh file inside the scratch directory."""
        fd, name = tempfile.mkstemp(prefix="input-", dir=str(self._scratch))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        except Exception:
            try:
                os.unlink(name)
            except OSError:
                pass
            raise
        return Path(name)

    def _unavailable_outcome(
        self,
        *,
        error: str,
        input_size: int,
        digest: Optional[str],
        started_at: Optional[datetime] = None,
    ) -> ValidationOutcome:
        now = datetime.now(timezone.utc)
        return ValidationOutcome(
            kind=OutcomeKind.UNAVAILABLE,
            input_digest=digest,
            input_size=input_size,
            started_at=started_at or now,
            finished_at=now,
            error_message=error,
        )

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Remove the scratch directory. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        if self._scratch_owner:
            shutil.rmtree(self._scratch, ignore_errors=True)

    def __enter__(self) -> "InputValidator":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"InputValidator(target={self._target.command!r}, "
            f"runs={self._runs})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(data: bytes, limit: int) -> Tuple[bytes, bool]:
    """Return ``(data, truncated)`` with ``data`` capped at ``limit``."""
    if limit <= 0 or len(data) <= limit:
        return data, False
    return data[:limit], True


# ---------------------------------------------------------------------------
# Reproduction predicate factory
# ---------------------------------------------------------------------------


def make_reproduction_predicate(
    target_spec: TargetSpec,
    expected_behavior: ExpectedBehavior,
    *,
    config: Optional[KMCSConfig] = None,
    event_bus: Optional[EventBus] = None,
) -> Callable[[bytes], bool]:
    """Return a predicate suitable for the minimizer.

    The predicate takes a candidate byte sequence and returns True when
    running it against ``target_spec`` produces an outcome that
    satisfies ``expected_behavior``. All bookkeeping (staging the file,
    spawning the process, waiting for the timeout, cleaning up) is
    handled internally.

    The returned callable is synchronous. It cannot be invoked from
    within a running event loop; callers in that situation should
    schedule it on a worker thread or use
    :class:`InputValidator` directly.
    """
    validator = InputValidator(
        target_spec,
        config=config,
        event_bus=event_bus,
    )

    def predicate(candidate: bytes) -> bool:
        try:
            outcome = validator.run_sync(candidate)
        except ValidatorError as exc:
            logger.debug("reproduction predicate raised: %s", exc)
            return False
        return outcome.matches(expected_behavior)

    # Attach a reference to the validator so callers who want to
    # inspect counters or clean up scratch space can do so.
    predicate.validator = validator  # type: ignore[attr-defined]
    predicate.expected = expected_behavior  # type: ignore[attr-defined]
    predicate.target = target_spec  # type: ignore[attr-defined]

    def _close() -> None:
        validator.close()

    predicate.close = _close  # type: ignore[attr-defined]
    return predicate


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def describe_outcome(outcome: ValidationOutcome) -> str:
    """Return a concise human-readable summary of an outcome."""
    parts = [outcome.kind.value]
    if outcome.exit_code is not None:
        parts.append(f"exit={outcome.exit_code}")
    if outcome.signal_number is not None:
        parts.append(f"signal={outcome.signal_number}")
    if outcome.timed_out:
        parts.append("timed_out")
    parts.append(f"wall={outcome.wall_seconds:.3f}s")
    parts.append(f"stdout={len(outcome.stdout)}B")
    parts.append(f"stderr={len(outcome.stderr)}B")
    if outcome.error_message:
        parts.append(f"error={outcome.error_message!r}")
    return " ".join(parts)


def signal_name(number: Optional[int]) -> Optional[str]:
    """Return the canonical name of a signal number, or None."""
    if number is None:
        return None
    try:
        return signal.Signals(number).name
    except (ValueError, AttributeError):
        return f"signal({number})"


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"

# A couple of type aliases reused by callers.
PredicateFn = Callable[[bytes], bool]
OutcomeHook = Callable[[ValidationOutcome], None]

# Silence unused-import linters for compatibility shims.
_ = (asdict, subprocess, sys, threading, Awaitable, FrozenSet, Sequence, Union)
