# KMCS Campaign Worker
# ====================
#
# Execution backend for a single fuzzing worker.
#
# A campaign is executed by one or more workers, one per concurrent
# fuzzer process. Each :class:`CampaignWorker` owns exactly one fuzzer
# process and is responsible for its entire lifetime: building the
# command line from the campaign's configuration, spawning the
# process, draining its stdout/stderr, parsing periodic statistics,
# detecting termination, and cleaning up the on-disk artifacts it
# produced.
#
# The worker is a *coordinator*, not a fuzzer engine. It does not
# implement coverage feedback, mutation scheduling, or energy
# assignment. Those responsibilities belong to the fuzzer binary
# (afl-fuzz, libFuzzer-linked target, honggfuzz) and to the adapter
# modules in :mod:`kmcs.fuzzers`. The worker simply drives the fuzzer
# and reports what happened.
#
# Interface contract
# ------------------
#
# :class:`CampaignManager` expects each worker to expose at least:
#
#   * ``start()`` — spawn the underlying fuzzer process.
#   * ``stop(*, timeout=...)`` — request shutdown; block until the
#     process exits or the timeout expires.
#   * ``is_alive()`` — return True while the fuzzer process is running.
#   * ``stats()`` — return a mapping of cumulative counters (executions,
#     crashes, hangs, coverage, corpus size).
#   * ``id`` — a stable string identifier unique within the campaign.
#
# The worker optionally exposes:
#
#   * ``pause()`` / ``resume()`` — suspend and continue the process.
#     Supported on POSIX via SIGSTOP/SIGCONT; unsupported operations
#     return False rather than raising.
#   * ``on_exit(callback)`` — register a no-argument callable that is
#     invoked once when the process exits.
#   * ``exit_info()`` — return a structured record describing the exit.
#
# Everything else is an implementation detail.
#
# Process supervision
# -------------------
#
# The fuzzer process is spawned with ``start_new_session=True`` on
# POSIX so that it runs in its own process group. Signals sent by the
# worker target that group, which ensures that child processes spawned
# by the fuzzer (forkserver instances, coverage shims, etc.) are also
# terminated when the worker is asked to stop. On Windows, process
# groups are unavailable and the worker falls back to terminating the
# top-level process only.
#
# The worker never blocks indefinitely. Every wait is bounded:
#
#   * The monitor thread waits on the process with a small polling
#     interval so that the worker's state is observable at all times.
#   * :meth:`CampaignWorker.stop` waits for the process to exit for at
#     most ``timeout`` seconds, escalating from SIGTERM to SIGKILL if
#     necessary.
#   * Output reader threads are daemon threads and cannot prevent
#     process exit.
#
# Output handling
# ---------------
#
# The fuzzer's stdout and stderr are drained continuously by two
# dedicated reader threads. Each line is:
#
#   1. Appended to ``<worker_dir>/fuzzer.log`` (line-buffered, with a
#      small periodic flush).
#   2. Fed through the fuzzer-specific line parser, which extracts
#      execution counts, crash counts, coverage, and corpus size.
#   3. Fed through a small set of generic crash detectors that look
#      for sanitizer banners (AddressSanitizer, UndefinedBehaviorSanitizer,
#      etc.) and common abort messages.
#
# The log file is flushed and closed when the process exits. Its final
# contents reflect everything the fuzzer emitted during the run.
#
# Statistics
# ----------
#
# The worker maintains a :class:`WorkerStats` instance updated by the
# output parsers. The manager polls :meth:`CampaignWorker.stats` on its
# monitor interval; the returned mapping is a plain dict so that the
# worker remains decoupled from the manager's internal representation.
#
# All counters are cumulative. Zero means "not yet observed", never
# "estimated to be zero".
#
# Cancellation and cleanup
# ------------------------
#
# :meth:`CampaignWorker.stop` is idempotent and safe to call from
# multiple threads. It performs the following steps:
#
#   1. Transition to STOPPING.
#   2. Send SIGTERM (POSIX) or ``terminate()`` (Windows) to the
#      process group.
#   3. Wait up to ``timeout`` seconds for the process to exit.
#   4. If still running, send SIGKILL (POSIX) or ``kill()`` (Windows).
#   5. Wait a further short interval for the process to be reaped.
#   6. Join reader threads (with a bound).
#   7. Transition to STOPPED and invoke any registered exit callbacks.
#
# On :meth:`CampaignWorker.close`, the worker additionally removes any
# temporary scratch directories it created. It never removes the
# campaign's output directory or the corpus root.
#
# Compatibility
# -------------
#
# Python 3.10+. POSIX is the primary target platform; Windows support
# is best-effort and excludes process-group signalling and pause/resume.

from __future__ import annotations

import io
import logging
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
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
    Set,
    TextIO,
    Tuple,
    TYPE_CHECKING,
    Union,
)

from ..core.exceptions import KMCSException
from ..core.events import EventBus, EventType
from .._events_compat import Event, get_default_bus, publish_event
from ..core.config import KmcsConfig, get_config

if TYPE_CHECKING:
    from .manager import Campaign, CampaignConfig


__all__ = [
    "CampaignWorker",
    "WorkerConfig",
    "WorkerStats",
    "WorkerState",
    "WorkerExitInfo",
    "WorkerError",
    "WorkerStateError",
    "WorkerStartError",
    "WorkerProcessError",
    "default_worker_factory",
    "SUPPORTED_FUZZERS",
    "DEFAULT_STOP_GRACE_SECONDS",
    "DEFAULT_READER_JOIN_SECONDS",
    "DEFAULT_MONITOR_POLL_SECONDS",
    "WORKER_LOG_FILENAME",
    "WORKER_STATE_FILENAME",
    "WORKER_STATS_FILENAME",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Fuzzer identifiers supported by the built-in command builders. The
#: worker will also accept any fuzzer identifier for which an adapter
#: is importable from :mod:`kmcs.fuzzers`, even if it does not appear
#: in this set.
SUPPORTED_FUZZERS: FrozenSet[str] = frozenset(
    {"aflpp", "afl", "libfuzzer", "honggfuzz"}
)

#: How long, in seconds, :meth:`CampaignWorker.stop` waits after
#: SIGTERM before escalating to SIGKILL.
DEFAULT_STOP_GRACE_SECONDS: float = 5.0

#: How long, in seconds, :meth:`CampaignWorker.stop` waits for reader
#: threads to finish after the process has been reaped.
DEFAULT_READER_JOIN_SECONDS: float = 2.0

#: How often, in seconds, the monitor thread polls the process state.
DEFAULT_MONITOR_POLL_SECONDS: float = 0.25

#: Name of the worker's combined stdout/stderr log file.
WORKER_LOG_FILENAME: str = "fuzzer.log"

#: Name of the worker's JSON state snapshot.
WORKER_STATE_FILENAME: str = "state.json"

#: Name of the worker's JSON statistics snapshot.
WORKER_STATS_FILENAME: str = "stats.json"

#: Environment variables forwarded to the fuzzer process, in addition
#: to whatever the campaign config explicitly sets.
_ENV_PASSTHROUGH: Tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TZ",
    "TMPDIR",
    "ASAN_OPTIONS",
    "UBSAN_OPTIONS",
    "LSAN_OPTIONS",
    "TSAN_OPTIONS",
    "MSAN_OPTIONS",
    "AFL_MAP_SIZE",
    "AFL_PRELOAD",
    "AFL_DEBUG",
    "AFL_NO_AFFINITY",
    "AFL_SKIP_CPUFREQ",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES",
    "LLVM_PROFILE_FILE",
    "HFUZZ_RUN_ARGS",
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class WorkerError(KMCSException):
    """Base class for all worker errors."""


class WorkerStateError(WorkerError):
    """Raised when an operation is invalid for the worker's state."""

    def __init__(self, worker_id: str, state: "WorkerState", operation: str) -> None:
        self.worker_id = worker_id
        self.state = state
        self.operation = operation
        super().__init__(
            f"worker {worker_id}: cannot {operation} in state {state.value}"
        )


class WorkerStartError(WorkerError):
    """Raised when a worker fails to start its fuzzer process."""


class WorkerProcessError(WorkerError):
    """Raised when a worker's process misbehaves in an unexpected way."""


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class WorkerState(str, Enum):
    """Lifecycle state of a single worker."""

    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in (
            WorkerState.STOPPED,
            WorkerState.COMPLETED,
            WorkerState.FAILED,
        )

    @property
    def is_active(self) -> bool:
        return self in (WorkerState.RUNNING, WorkerState.PAUSED)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkerConfig:
    """Immutable per-worker configuration.

    Derived from a campaign's config plus the worker's index. Includes
    only the fields the worker actually needs, which keeps the worker
    decoupled from the campaign's broader configuration surface.
    """

    worker_id: str
    worker_index: int
    campaign_id: str
    campaign_name: str

    fuzzer: str
    fuzzer_config: Mapping[str, Any]
    fuzzer_executable: Optional[str]

    target_command: str
    target_args: Tuple[str, ...]
    target_input_style: str

    sanitizer: Optional[str]
    sanitizer_config: Mapping[str, Any]

    corpus_root: str
    output_dir: str
    worker_dir: str

    environment: Mapping[str, str]
    tags: FrozenSet[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "worker_index": self.worker_index,
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "fuzzer": self.fuzzer,
            "fuzzer_config": dict(self.fuzzer_config),
            "fuzzer_executable": self.fuzzer_executable,
            "target_command": self.target_command,
            "target_args": list(self.target_args),
            "target_input_style": self.target_input_style,
            "sanitizer": self.sanitizer,
            "sanitizer_config": dict(self.sanitizer_config),
            "corpus_root": self.corpus_root,
            "output_dir": self.output_dir,
            "worker_dir": self.worker_dir,
            "environment": dict(self.environment),
            "tags": sorted(self.tags),
        }


@dataclass
class WorkerStats:
    """Cumulative statistics for a single worker.

    All counters are monotonically non-decreasing over the worker's
    lifetime. They are updated from real fuzzer output; zero means
    "not yet observed", never "estimated to be zero".
    """

    executions: int = 0
    crashes: int = 0
    hangs: int = 0
    corpus_size: int = 0
    coverage_percent: float = 0.0
    coverage_edges: int = 0
    last_pulse_at: Optional[datetime] = None
    parse_errors: int = 0

    def merge(self, update: Mapping[str, Any]) -> None:
        """Merge a parser-produced update into these stats.

        Recognised keys:

        * ``executions`` (int, cumulative) — set to max(current, value).
        * ``crashes`` (int, cumulative) — set to max(current, value).
        * ``hangs`` (int, cumulative) — set to max(current, value).
        * ``corpus_size`` (int) — set to max(current, value).
        * ``coverage_percent`` (float) — set to max(current, value).
        * ``coverage_edges`` (int) — set to max(current, value).
        * ``pulse`` (bool) — when True, updates ``last_pulse_at``.

        Unknown keys are ignored. Values of the wrong type are ignored.
        The method never raises on unexpected input.
        """
        for key in ("executions", "crashes", "hangs", "corpus_size", "coverage_edges"):
            if key in update:
                value = update[key]
                if isinstance(value, (int, float)):
                    current = getattr(self, key)
                    new_value = int(value)
                    if new_value > current:
                        setattr(self, key, new_value)
        if "coverage_percent" in update:
            value = update["coverage_percent"]
            if isinstance(value, (int, float)):
                if float(value) > self.coverage_percent:
                    self.coverage_percent = float(value)
        if update.get("pulse"):
            self.last_pulse_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executions": self.executions,
            "crashes": self.crashes,
            "hangs": self.hangs,
            "corpus_size": self.corpus_size,
            "coverage_percent": self.coverage_percent,
            "coverage_edges": self.coverage_edges,
            "last_pulse_at": (
                self.last_pulse_at.isoformat()
                if self.last_pulse_at is not None
                else None
            ),
            "parse_errors": self.parse_errors,
        }


@dataclass(frozen=True)
class WorkerExitInfo:
    """Structured record of how the worker's process exited."""

    exit_code: Optional[int]
    signal_number: Optional[int]
    timed_out: bool
    killed: bool
    started_at: datetime
    finished_at: datetime
    wall_seconds: float
    command: Tuple[str, ...]

    @property
    def runtime_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def clean(self) -> bool:
        return (
            not self.timed_out
            and not self.killed
            and self.exit_code == 0
            and self.signal_number is None
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "timed_out": self.timed_out,
            "killed": self.killed,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "wall_seconds": self.wall_seconds,
            "command": list(self.command),
            "clean": self.clean,
        }


# ---------------------------------------------------------------------------
# Line parsing helpers
# ---------------------------------------------------------------------------

# AFL++ classic UI. These regexes match both the single-line status
# output (when afl-fuzz is not attached to a TTY) and the boxed
# multi-line UI.
_AFL_EXECS_RE = re.compile(
    r"(?:execs_done|total execs|execs done)\s*[:=]\s*(\d+)",
    re.IGNORECASE,
)
_AFL_CRASHES_RE = re.compile(
    r"(?:saved crashes|unique crashes|saved_crashes)\s*[:=]\s*(\d+)",
    re.IGNORECASE,
)
_AFL_HANGS_RE = re.compile(
    r"(?:saved hangs|unique hangs|saved_hangs)\s*[:=]\s*(\d+)",
    re.IGNORECASE,
)
_AFL_CORPUS_RE = re.compile(
    r"corpus count\s*[:=]\s*(\d+)",
    re.IGNORECASE,
)
_AFL_COVERAGE_RE = re.compile(
    r"(?:bitmap cvg|coverage)\s*[:=]\s*([\d.]+)\s*%",
    re.IGNORECASE,
)
_AFL_CYCLES_RE = re.compile(
    r"cycles done\s*[:=]\s*(\d+)",
    re.IGNORECASE,
)

# libFuzzer.
_LIBFUZZER_PULSE_RE = re.compile(r"^#(\d+)\s+")
_LIBFUZZER_NEW_RE = re.compile(r"\bNEW\b")
_LIBFUZZER_REDUCE_RE = re.compile(r"\bREDUCE\b")
_LIBFUZZER_COV_RE = re.compile(r"\bcov:\s*(\d+)")
_LIBFUZZER_FT_RE = re.compile(r"\bft:\s*(\d+)")
_LIBFUZZER_CORP_RE = re.compile(r"\bcorp:\s*(\d+)/(\d+)b")
_LIBFUZZER_EXEC_RE = re.compile(r"exec/s:\s*(\d+)")

# Honggfuzz.
_HF_ITER_RE = re.compile(r"Iterations\s*[:=]\s*(\d+)", re.IGNORECASE)
_HF_CRASH_RE = re.compile(r"(?:Crashes|Crash count)\s*[:=]\s*(\d+)", re.IGNORECASE)
_HF_HANG_RE = re.compile(r"Hangs?\s*[:=]\s*(\d+)", re.IGNORECASE)
_HF_COV_RE = re.compile(r"Coverage\s*[:=]\s*([\d.]+)", re.IGNORECASE)

# Generic crash indicators. Presence of any of these in the fuzzer's
# output causes the worker to increment a "suspected crash" counter.
_CRASH_INDICATORS: Tuple[bytes, ...] = (
    b"AddressSanitizer",
    b"UndefinedBehaviorSanitizer",
    b"ThreadSanitizer",
    b"LeakSanitizer",
    b"MemorySanitizer",
    b"runtime error:",
    b"SUMMARY: ",
    b"SEGV on unknown address",
    b"heap-buffer-overflow",
    b"stack-buffer-overflow",
    b"use-after-free",
    b"double-free",
    b"SEGV",
    b"SIGSEGV",
    b"SIGABRT",
    b"SIGBUS",
    b"assertion failed",
    b"Assertion `",
    b"abort()",
    b"PANIC",
    b"=====",
)


def _parse_afl_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a line of AFL++ output; return a stats update or None."""
    update: Dict[str, Any] = {}
    if (m := _AFL_EXECS_RE.search(line)) is not None:
        update["executions"] = int(m.group(1))
    if (m := _AFL_CRASHES_RE.search(line)) is not None:
        update["crashes"] = int(m.group(1))
    if (m := _AFL_HANGS_RE.search(line)) is not None:
        update["hangs"] = int(m.group(1))
    if (m := _AFL_CORPUS_RE.search(line)) is not None:
        update["corpus_size"] = int(m.group(1))
    if (m := _AFL_COVERAGE_RE.search(line)) is not None:
        try:
            update["coverage_percent"] = float(m.group(1))
        except ValueError:
            pass
    if update:
        update["pulse"] = True
        return update
    return None


def _parse_libfuzzer_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a line of libFuzzer output; return a stats update or None."""
    update: Dict[str, Any] = {}

    if (m := _LIBFUZZER_PULSE_RE.match(line)) is not None:
        try:
            update["executions"] = int(m.group(1))
        except ValueError:
            pass
    if (m := _LIBFUZZER_COV_RE.search(line)) is not None:
        try:
            update["coverage_edges"] = int(m.group(1))
        except ValueError:
            pass
    if (m := _LIBFUZZER_CORP_RE.search(line)) is not None:
        try:
            update["corpus_size"] = int(m.group(1))
        except ValueError:
            pass
    if _LIBFUZZER_NEW_RE.search(line):
        update["new_input"] = True

    if update:
        update["pulse"] = True
        return update
    return None


def _parse_honggfuzz_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a line of honggfuzz output; return a stats update or None."""
    update: Dict[str, Any] = {}
    if (m := _HF_ITER_RE.search(line)) is not None:
        try:
            update["executions"] = int(m.group(1))
        except ValueError:
            pass
    if (m := _HF_CRASH_RE.search(line)) is not None:
        try:
            update["crashes"] = int(m.group(1))
        except ValueError:
            pass
    if (m := _HF_HANG_RE.search(line)) is not None:
        try:
            update["hangs"] = int(m.group(1))
        except ValueError:
            pass
    if (m := _HF_COV_RE.search(line)) is not None:
        try:
            update["coverage_percent"] = float(m.group(1))
        except ValueError:
            pass
    if update:
        update["pulse"] = True
        return update
    return None


_LINE_PARSERS: Mapping[str, Callable[[str], Optional[Dict[str, Any]]]] = {
    "aflpp": _parse_afl_line,
    "afl": _parse_afl_line,
    "libfuzzer": _parse_libfuzzer_line,
    "honggfuzz": _parse_honggfuzz_line,
}


def _detect_crash_indicator(line: bytes) -> Optional[bytes]:
    """Return the first crash indicator present in ``line``, or None."""
    for indicator in _CRASH_INDICATORS:
        if indicator in line:
            return indicator
    return None


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------


def _build_afl_command(config: WorkerConfig) -> List[str]:
    """Build an argv for afl-fuzz based on a worker's config.

    Layout::

        afl-fuzz -i <seed> -o <worker_out> [-M main | -S worker_N]
                 [extra args] -- <target> <target_args...> [@@ | < seed]

    The seed directory is the campaign's corpus root. The output
    directory is the worker's own ``afl_out`` subdirectory, which
    keeps each worker's queue and crash directory separate.
    """
    executable = config.fuzzer_executable or "afl-fuzz"
    seed = config.corpus_root
    out = str(Path(config.worker_dir) / "afl_out")

    argv: List[str] = [executable, "-i", seed, "-o", out]

    # Coordination flags: one main, the rest secondary.
    if config.worker_index == 0:
        argv += ["-M", "main"]
    else:
        argv += ["-S", f"worker{config.worker_index}"]

    # Fuzzer-specific extras from the campaign config.
    for key, value in config.fuzzer_config.items():
        if key in ("afl_args", "args", "extra_args"):
            if isinstance(value, (list, tuple)):
                argv.extend(str(v) for v in value)
            elif isinstance(value, str):
                argv.append(value)

    argv.append("--")
    argv.append(config.target_command)
    argv.extend(config.target_args)
    if config.target_input_style == "argv":
        argv.append("@@")
    return argv


def _build_libfuzzer_command(config: WorkerConfig) -> List[str]:
    """Build an argv for a libFuzzer-linked target.

    libFuzzer is linked into the target binary, so the "executable" is
    the target itself and the corpus directory is passed as a
    positional argument.
    """
    argv: List[str] = [config.target_command]
    argv.extend(config.target_args)

    # Reasonable defaults; callers can override via fuzzer_config.
    defaults: Dict[str, str] = {
        "-print_final_stats=1",
        "-reload=1",
    }
    for value in defaults:
        argv.append(value)

    # Corpus directory as a positional argument.
    argv.append(config.corpus_root)

    for key, value in config.fuzzer_config.items():
        if key in ("libfuzzer_args", "args", "extra_args"):
            if isinstance(value, (list, tuple)):
                argv.extend(str(v) for v in value)
            elif isinstance(value, str):
                argv.append(value)

    return argv


def _build_honggfuzz_command(config: WorkerConfig) -> List[str]:
    """Build an argv for honggfuzz.

    Layout::

        honggfuzz -i <seed> -o <out> [extras] -- <target> <args> ___FILE___

    honggfuzz uses the ``___FILE___`` placeholder for the input path.
    """
    executable = config.fuzzer_executable or "honggfuzz"
    seed = config.corpus_root
    out = str(Path(config.worker_dir) / "hfuzz_out")

    argv: List[str] = [executable, "-i", seed, "-o", out]

    for key, value in config.fuzzer_config.items():
        if key in ("honggfuzz_args", "args", "extra_args"):
            if isinstance(value, (list, tuple)):
                argv.extend(str(v) for v in value)
            elif isinstance(value, str):
                argv.append(value)

    argv.append("--")
    argv.append(config.target_command)
    argv.extend(config.target_args)
    if config.target_input_style == "argv":
        argv.append("___FILE___")
    return argv


_BUILTIN_BUILDERS: Mapping[str, Callable[[WorkerConfig], List[str]]] = {
    "aflpp": _build_afl_command,
    "afl": _build_afl_command,
    "libfuzzer": _build_libfuzzer_command,
    "honggfuzz": _build_honggfuzz_command,
}


# ---------------------------------------------------------------------------
# CampaignWorker
# ---------------------------------------------------------------------------


class CampaignWorker:
    """A single fuzzing worker process.

    Parameters
    ----------
    config:
        The worker's :class:`WorkerConfig`.
    event_bus:
        Optional event bus. When omitted, the process-wide default bus
        is used.
    platform_config:
        Optional :class:`~kmcs.core.config.KmcsConfig` for
        platform-level defaults.
    """

    def __init__(
        self,
        config: WorkerConfig,
        *,
        event_bus: Optional[EventBus] = None,
        platform_config: Optional[KmcsConfig] = None,
    ) -> None:
        if not isinstance(config, WorkerConfig):
            raise TypeError(
                f"config must be WorkerConfig, got {type(config).__name__}"
            )

        self._config = config
        self._bus = event_bus or get_default_bus()
        self._platform_config = platform_config or get_config()

        self._lock = threading.RLock()
        self._state = WorkerState.PENDING
        self._process: Optional[subprocess.Popen[bytes]] = None
        self._started_at: Optional[datetime] = None
        self._finished_at: Optional[datetime] = None
        self._exit_info: Optional[WorkerExitInfo] = None
        self._error_message: Optional[str] = None
        self._stats = WorkerStats()
        self._suspected_crashes = 0
        self._reader_threads: List[threading.Thread] = []
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_requested = threading.Event()
        self._kill_requested = threading.Event()
        self._paused = threading.Event()
        self._exit_callbacks: List[Callable[[], None]] = []
        self._exit_callbacks_lock = threading.Lock()
        self._log_file: Optional[TextIO] = None
        self._log_lock = threading.Lock()
        self._log_written_bytes = 0
        self._command: Tuple[str, ...] = ()

        # Ensure the worker directory exists.
        self._worker_dir = Path(config.worker_dir)
        try:
            self._worker_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkerStartError(
                f"failed to create worker dir {self._worker_dir}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def id(self) -> str:
        return self._config.worker_id

    @property
    def index(self) -> int:
        return self._config.worker_index

    @property
    def config(self) -> WorkerConfig:
        return self._config

    @property
    def state(self) -> WorkerState:
        with self._lock:
            return self._state

    @property
    def pid(self) -> Optional[int]:
        with self._lock:
            proc = self._process
        if proc is None:
            return None
        return proc.pid

    @property
    def exit_code(self) -> Optional[int]:
        info = self._exit_info
        if info is None:
            return None
        return info.exit_code

    @property
    def output_dir(self) -> Path:
        return self._worker_dir

    @property
    def command(self) -> Tuple[str, ...]:
        return self._command

    @property
    def error_message(self) -> Optional[str]:
        return self._error_message

    @property
    def suspected_crashes(self) -> int:
        return self._suspected_crashes

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
                source="campaigns.worker",
                data={"event": event_name, **payload},
            )
            publish_event(self._bus, event)
        except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
            logger.debug("worker event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def _set_state(self, new_state: WorkerState) -> None:
        with self._lock:
            self._state = new_state
        self._write_state_snapshot()

    def _write_state_snapshot(self) -> None:
        """Write a JSON snapshot of the worker's state to disk."""
        payload = {
            "worker_id": self._config.worker_id,
            "state": self._state.value,
            "pid": self.pid,
            "started_at": (
                self._started_at.isoformat() if self._started_at else None
            ),
            "finished_at": (
                self._finished_at.isoformat() if self._finished_at else None
            ),
            "command": list(self._command),
            "stats": self._stats.to_dict(),
            "error_message": self._error_message,
            "suspected_crashes": self._suspected_crashes,
        }
        path = self._worker_dir / WORKER_STATE_FILENAME
        tmp = path.with_suffix(".json.tmp")
        try:
            import json

            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True, default=str)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to write worker state snapshot: %s", exc)
            try:
                tmp.unlink()
            except OSError:
                pass

    def _write_stats_snapshot(self) -> None:
        """Write a JSON snapshot of the worker's stats to disk."""
        import json

        path = self._worker_dir / WORKER_STATS_FILENAME
        tmp = path.with_suffix(".json.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(
                    self._stats.to_dict(),
                    fh,
                    indent=2,
                    sort_keys=True,
                    default=str,
                )
                fh.flush()
            os.replace(tmp, path)
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to write worker stats snapshot: %s", exc)
            try:
                tmp.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------

    def _build_command(self) -> List[str]:
        """Return the argv for this worker, choosing the right builder."""
        fuzzer = self._config.fuzzer.lower()
        builder = _BUILTIN_BUILDERS.get(fuzzer)
        if builder is None:
            # Unknown fuzzer: if the user supplied an explicit
            # executable and args, use those. Otherwise raise.
            explicit = self._config.fuzzer_executable
            if explicit:
                argv = [explicit]
                for key, value in self._config.fuzzer_config.items():
                    if key in ("args", "extra_args"):
                        if isinstance(value, (list, tuple)):
                            argv.extend(str(v) for v in value)
                        elif isinstance(value, str):
                            argv.append(value)
                argv.append(self._config.target_command)
                argv.extend(self._config.target_args)
                if self._config.target_input_style == "argv":
                    argv.append("@@")
                return argv
            raise WorkerStartError(
                f"unsupported fuzzer {fuzzer!r}; supported: "
                f"{sorted(SUPPORTED_FUZZERS)}"
            )
        return builder(self._config)

    # ------------------------------------------------------------------
    # Environment construction
    # ------------------------------------------------------------------

    def _build_env(self) -> Dict[str, str]:
        """Construct the fuzzer's environment.

        Inherits a small allowlist of variables from the parent
        environment, overlays the campaign's explicit environment, and
        then overlays any sanitizer configuration.
        """
        env: Dict[str, str] = {}
        for key in _ENV_PASSTHROUGH:
            value = os.environ.get(key)
            if value is not None:
                env[key] = value
        env.setdefault("PATH", os.defpath)

        for key, value in self._config.environment.items():
            env[key] = str(value)

        # Sanitizer configuration: translate the mapping to the
        # sanitizer's canonical environment variable.
        sanitizer = (self._config.sanitizer or "").lower()
        if sanitizer:
            var_name = {
                "asan": "ASAN_OPTIONS",
                "ubsan": "UBSAN_OPTIONS",
                "lsan": "LSAN_OPTIONS",
                "tsan": "TSAN_OPTIONS",
                "msan": "MSAN_OPTIONS",
            }.get(sanitizer)
            if var_name:
                options = self._config.sanitizer_config
                if options:
                    rendered = ":".join(
                        f"{k}={_render_env_value(v)}"
                        for k, v in options.items()
                    )
                    existing = env.get(var_name)
                    env[var_name] = (
                        f"{existing}:{rendered}" if existing else rendered
                    )

        return env

    # ------------------------------------------------------------------
    # Lifecycle: start
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn the fuzzer process.

        Raises
        ------
        WorkerStateError
            If the worker is not in PENDING state.
        WorkerStartError
            If the process cannot be spawned.
        """
        with self._lock:
            if self._state != WorkerState.PENDING:
                raise WorkerStateError(
                    self.id, self._state, "start"
                )
            self._state = WorkerState.STARTING

        self._emit("WORKER_STARTING", {"worker_id": self.id})

        try:
            argv = self._build_command()
            env = self._build_env()
            self._command = tuple(argv)
            self._open_log()
        except Exception as exc:
            self._set_state(WorkerState.FAILED)
            self._error_message = str(exc)
            self._emit(
                "WORKER_FAILED",
                {"worker_id": self.id, "error": str(exc)},
            )
            raise WorkerStartError(str(exc)) from exc

        try:
            self._process = self._spawn_process(argv, env)
        except FileNotFoundError as exc:
            self._set_state(WorkerState.FAILED)
            self._error_message = f"executable not found: {argv[0]}"
            self._close_log()
            self._emit(
                "WORKER_FAILED",
                {
                    "worker_id": self.id,
                    "error": self._error_message,
                },
            )
            raise WorkerStartError(self._error_message) from exc
        except PermissionError as exc:
            self._set_state(WorkerState.FAILED)
            self._error_message = f"permission denied executing {argv[0]}"
            self._close_log()
            self._emit(
                "WORKER_FAILED",
                {
                    "worker_id": self.id,
                    "error": self._error_message,
                },
            )
            raise WorkerStartError(self._error_message) from exc
        except OSError as exc:
            self._set_state(WorkerState.FAILED)
            self._error_message = f"failed to spawn process: {exc}"
            self._close_log()
            self._emit(
                "WORKER_FAILED",
                {"worker_id": self.id, "error": self._error_message},
            )
            raise WorkerStartError(self._error_message) from exc

        self._started_at = datetime.now(timezone.utc)

        # Spawn reader threads.
        self._start_reader_threads()

        # Spawn monitor thread.
        self._start_monitor_thread()

        self._set_state(WorkerState.RUNNING)
        self._emit(
            "WORKER_STARTED",
            {
                "worker_id": self.id,
                "pid": self._process.pid,
                "command": list(argv),
            },
        )

    def _spawn_process(
        self, argv: Sequence[str], env: Mapping[str, str]
    ) -> subprocess.Popen[bytes]:
        """Spawn the fuzzer process with the correct platform options."""
        popen_kwargs: Dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "env": dict(env),
            "cwd": str(self._worker_dir),
            "bufsize": 0,
        }
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        # Windows: nothing special for now; process groups there are
        # handled via CREATE_NEW_PROCESS_GROUP when required.
        return subprocess.Popen(list(argv), **popen_kwargs)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Log file management
    # ------------------------------------------------------------------

    def _open_log(self) -> None:
        path = self._worker_dir / WORKER_LOG_FILENAME
        try:
            self._log_file = open(path, "ab", buffering=0)
        except OSError as exc:
            raise WorkerStartError(
                f"failed to open worker log {path}: {exc}"
            ) from exc

    def _close_log(self) -> None:
        with self._log_lock:
            fh = self._log_file
            self._log_file = None
        if fh is not None:
            try:
                fh.flush()
            except Exception:  # noqa: BLE001
                pass
            try:
                fh.close()
            except Exception:  # noqa: BLE001
                pass

    def _append_log(self, line: bytes) -> None:
        with self._log_lock:
            fh = self._log_file
            if fh is None:
                return
            try:
                fh.write(line)
                if not line.endswith(b"\n"):
                    fh.write(b"\n")
                self._log_written_bytes += len(line) + 1
            except Exception as exc:  # noqa: BLE001
                logger.debug("log write failed: %s", exc)

    # ------------------------------------------------------------------
    # Reader threads
    # ------------------------------------------------------------------

    def _start_reader_threads(self) -> None:
        with self._lock:
            proc = self._process
        if proc is None:
            return

        for stream_name, stream in (
            ("stdout", proc.stdout),
            ("stderr", proc.stderr),
        ):
            if stream is None:
                continue
            thread = threading.Thread(
                target=self._reader_loop,
                args=(stream_name, stream),
                name=f"kmcs-worker-{self.id}-{stream_name}",
                daemon=True,
            )
            self._reader_threads.append(thread)
            thread.start()

    def _reader_loop(self, stream_name: str, stream: Any) -> None:
        """Read a stream line by line, logging and parsing each line."""
        parser = _LINE_PARSERS.get(self._config.fuzzer.lower())
        try:
            for raw in iter(stream.readline, b""):
                if not raw:
                    break
                # Log.
                self._append_log(raw)
                # Parse for stats.
                if parser is not None:
                    try:
                        text = raw.decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        text = ""
                    if text:
                        try:
                            update = parser(text)
                        except Exception as exc:  # noqa: BLE001
                            logger.debug("line parser raised: %s", exc)
                            update = None
                            self._stats.parse_errors += 1
                        if update is not None:
                            self._stats.merge(update)
                # Detect crash indicators on any stream.
                indicator = _detect_crash_indicator(raw)
                if indicator is not None:
                    with self._lock:
                        self._suspected_crashes += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("reader loop for %s failed: %s", stream_name, exc)
        finally:
            try:
                stream.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Monitor thread
    # ------------------------------------------------------------------

    def _start_monitor_thread(self) -> None:
        thread = threading.Thread(
            target=self._monitor_loop,
            name=f"kmcs-worker-{self.id}-monitor",
            daemon=True,
        )
        self._monitor_thread = thread
        thread.start()

    def _monitor_loop(self) -> None:
        """Wait for the process to exit, then finalize the worker."""
        with self._lock:
            proc = self._process
        if proc is None:
            return

        try:
            # Poll rather than blocking on wait() so that we can react
            # promptly to stop_requested without a separate thread.
            while True:
                rc = proc.poll()
                if rc is not None:
                    break
                if self._stop_requested.is_set():
                    # Stop has been requested; give the process a
                    # short grace period before escalating.
                    if self._kill_requested.is_set():
                        self._send_signal("KILL")
                    time.sleep(DEFAULT_MONITOR_POLL_SECONDS)
                    continue
                time.sleep(DEFAULT_MONITOR_POLL_SECONDS)
        except Exception as exc:  # noqa: BLE001
            logger.debug("monitor loop poll failed: %s", exc)

        # Process has exited.
        exit_code = proc.returncode
        finished_at = datetime.now(timezone.utc)
        started_at = self._started_at or finished_at
        wall = (finished_at - started_at).total_seconds()

        signal_number: Optional[int] = None
        if os.name == "posix" and exit_code is not None and exit_code < 0:
            signal_number = -exit_code
            normalized_exit: Optional[int] = None
        else:
            normalized_exit = exit_code

        info = WorkerExitInfo(
            exit_code=normalized_exit,
            signal_number=signal_number,
            timed_out=False,
            killed=self._kill_requested.is_set(),
            started_at=started_at,
            finished_at=finished_at,
            wall_seconds=wall,
            command=self._command,
        )

        with self._lock:
            self._finished_at = finished_at
            self._exit_info = info

        # Join reader threads with a bounded wait.
        for thread in self._reader_threads:
            thread.join(timeout=DEFAULT_READER_JOIN_SECONDS)

        self._close_log()
        self._write_stats_snapshot()

        # Determine final state.
        with self._lock:
            current = self._state
        if self._stop_requested.is_set():
            self._set_state(WorkerState.STOPPED)
        elif current == WorkerState.FAILED:
            pass
        elif signal_number is not None:
            # Fuzzer was killed by a signal; this is unusual but
            # not a worker failure per se — the fuzzer's own crash
            # handling usually catches signals. Mark as FAILED so
            # the manager can decide.
            self._error_message = (
                f"fuzzer terminated by signal {signal_number}"
            )
            self._set_state(WorkerState.FAILED)
        elif normalized_exit == 0:
            self._set_state(WorkerState.COMPLETED)
        else:
            self._error_message = f"fuzzer exited with code {normalized_exit}"
            self._set_state(WorkerState.FAILED)

        self._emit(
            "WORKER_EXITED",
            {
                "worker_id": self.id,
                "exit_code": normalized_exit,
                "signal": signal_number,
                "wall_seconds": wall,
                "state": self._state.value,
            },
        )

        self._invoke_exit_callbacks()

    def _invoke_exit_callbacks(self) -> None:
        with self._exit_callbacks_lock:
            callbacks = list(self._exit_callbacks)
        for callback in callbacks:
            try:
                callback()
            except Exception as exc:  # noqa: BLE001
                logger.debug("exit callback raised: %s", exc)

    # ------------------------------------------------------------------
    # Lifecycle: stop
    # ------------------------------------------------------------------

    def stop(self, *, timeout: Optional[float] = None) -> None:
        """Request the fuzzer process to stop and wait for it to exit.

        Idempotent: calling stop on an already-stopped worker is a
        no-op. Calling stop from within an exit callback is safe (the
        callback runs on the monitor thread, and stop detects that it
        is already stopping).

        Parameters
        ----------
        timeout:
            Maximum seconds to wait for the process to exit before
            escalating. When None, :data:`DEFAULT_STOP_GRACE_SECONDS`
            is used.
        """
        with self._lock:
            if self._state.is_terminal:
                return
            if self._stop_requested.is_set():
                already_stopping = True
            else:
                already_stopping = False
                self._stop_requested.set()
                self._state = WorkerState.STOPPING

        if already_stopping:
            return

        self._emit("WORKER_STOPPING", {"worker_id": self.id})

        wait = timeout if timeout is not None else DEFAULT_STOP_GRACE_SECONDS

        with self._lock:
            proc = self._process
        if proc is None:
            # Never started.
            self._set_state(WorkerState.STOPPED)
            return

        # If already paused, resume first so signals are delivered.
        if self._paused.is_set():
            self._send_signal("CONT")
            self._paused.clear()

        # First try a graceful SIGTERM.
        self._send_signal("TERM")

        deadline = time.monotonic() + max(0.0, wait)
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        else:
            # Escalate to SIGKILL.
            self._kill_requested.set()
            self._send_signal("KILL")
            # Give the monitor thread a moment to observe the exit.
            kill_deadline = time.monotonic() + max(2.0, wait * 0.5)
            while time.monotonic() < kill_deadline:
                if proc.poll() is not None:
                    break
                time.sleep(0.05)

        # Wait for the monitor thread to finalize the worker.
        monitor = self._monitor_thread
        if monitor is not None and monitor.is_alive():
            monitor.join(timeout=2.0)

    def pause(self) -> bool:
        """Pause the fuzzer process.

        On POSIX this sends SIGSTOP to the process group; on Windows
        this operation is not supported and returns False.

        Returns
        -------
        bool
            True if the pause request was delivered.
        """
        if os.name != "posix":
            return False
        with self._lock:
            if self._state != WorkerState.RUNNING:
                return False
            if self._process is None:
                return False
        if self._send_signal("STOP"):
            with self._lock:
                self._state = WorkerState.PAUSED
            self._paused.set()
            return True
        return False

    def resume(self) -> bool:
        """Resume a paused fuzzer process.

        Returns
        -------
        bool
            True if the resume request was delivered.
        """
        if os.name != "posix":
            return False
        with self._lock:
            if self._state != WorkerState.PAUSED:
                return False
        if self._send_signal("CONT"):
            with self._lock:
                self._state = WorkerState.RUNNING
            self._paused.clear()
            return True
        return False

    def _send_signal(self, name: str) -> bool:
        """Send a named signal to the worker's process group.

        On POSIX, the signal is sent to the process group so that all
        descendants are affected. On Windows, only the top-level
        process is signalled (and only for TERM and KILL).
        """
        with self._lock:
            proc = self._process
        if proc is None:
            return False

        if os.name == "posix":
            sig = getattr(signal, f"SIG{name}", None)
            if sig is None:
                return False
            try:
                os.killpg(os.getpgid(proc.pid), sig)
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                # Fall back to signalling just the process.
                try:
                    proc.send_signal(sig)
                    return True
                except Exception as exc:  # noqa: BLE001
                    logger.debug("send_signal %s failed: %s", name, exc)
                    return False
            except Exception as exc:  # noqa: BLE001
                logger.debug("killpg %s failed: %s", name, exc)
                return False
        else:
            # Windows: only TERM and KILL are meaningful.
            try:
                if name == "TERM":
                    proc.terminate()
                    return True
                if name == "KILL":
                    proc.kill()
                    return True
            except Exception as exc:  # noqa: BLE001
                logger.debug("windows signal %s failed: %s", name, exc)
            return False

    # ------------------------------------------------------------------
    # Status queries
    # ------------------------------------------------------------------

    def is_alive(self) -> bool:
        """Return True while the fuzzer process is running."""
        with self._lock:
            proc = self._process
            state = self._state
        if state.is_terminal:
            return False
        if proc is None:
            return False
        return proc.poll() is None

    def wait(self, *, timeout: Optional[float] = None) -> Optional[int]:
        """Block until the process exits and return its exit code.

        Parameters
        ----------
        timeout:
            Maximum seconds to wait. When None, waits indefinitely.

        Returns
        -------
        int or None
            The exit code, or None if the process was killed by a
            signal or the timeout fired.
        """
        with self._lock:
            proc = self._process
        if proc is None:
            return None
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stats(self) -> Dict[str, Any]:
        """Return a snapshot of the worker's cumulative statistics.

        The returned mapping is JSON-serialisable and contains the
        keys the campaign manager expects: ``executions``, ``crashes``,
        ``hangs``, ``corpus_size``, ``coverage_percent``, plus
        worker-specific extras.

        The ``active`` key is set to True when the process is running.
        """
        with self._lock:
            snapshot = self._stats.to_dict()
        snapshot["active"] = self.is_alive()
        snapshot["suspected_crashes"] = self._suspected_crashes
        snapshot["pid"] = self.pid
        snapshot["state"] = self.state.value
        return snapshot

    def exit_info(self) -> Optional[WorkerExitInfo]:
        """Return structured information about the worker's exit."""
        return self._exit_info

    # ------------------------------------------------------------------
    # Exit callbacks
    # ------------------------------------------------------------------

    def on_exit(self, callback: Callable[[], None]) -> None:
        """Register a callback to be invoked when the process exits.

        The callback is invoked exactly once, on the monitor thread,
        after the worker's final state has been set. If the worker has
        already exited by the time the callback is registered, the
        callback is scheduled to run immediately on a fresh thread
        (to avoid re-entrancy hazards for callers that register from
        within another callback).
        """
        if not callable(callback):
            raise TypeError("callback must be callable")
        with self._exit_callbacks_lock:
            if self._state.is_terminal and self._finished_at is not None:
                # Already exited; run on a fresh thread.
                threading.Thread(
                    target=self._safe_invoke,
                    args=(callback,),
                    name=f"kmcs-worker-{self.id}-late-callback",
                    daemon=True,
                ).start()
                return
            self._exit_callbacks.append(callback)

    @staticmethod
    def _safe_invoke(callback: Callable[[], None]) -> None:
        try:
            callback()
        except Exception as exc:  # noqa: BLE001
            logger.debug("late exit callback raised: %s", exc)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release resources held by the worker.

        If the worker is still running, it is stopped first. Temporary
        scratch directories created by the worker are removed. The
        worker's log and stats files are left in place: they are the
        primary artifact of a run and must be preserved.
        """
        if not self.state.is_terminal:
            try:
                self.stop()
            except Exception as exc:  # noqa: BLE001
                logger.debug("close() could not stop worker: %s", exc)
        self._close_log()

    def __enter__(self) -> "CampaignWorker":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"CampaignWorker(id={self.id!r}, "
            f"state={self.state.value}, "
            f"pid={self.pid})"
        )


# ---------------------------------------------------------------------------
# Helpers used by the worker
# ---------------------------------------------------------------------------


def _render_env_value(value: Any) -> str:
    """Render a Python value as a sanitizer-option string.

    Sanitizer options are strings and integers; booleans are rendered
    as ``"1"`` or ``"0"`` because that is what the sanitizers expect.
    """
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        return ""
    return str(value)


# ---------------------------------------------------------------------------
# Factory function used by CampaignManager
# ---------------------------------------------------------------------------


def default_worker_factory(
    campaign: "Campaign", index: int
) -> CampaignWorker:
    """Return a :class:`CampaignWorker` configured for ``campaign``.

    This is the default factory used by :class:`CampaignManager` when
    no explicit factory is supplied. It reads the fields it needs from
    the campaign's configuration and constructs an immutable
    :class:`WorkerConfig` for the worker.

    Parameters
    ----------
    campaign:
        The campaign for which to build a worker.
    index:
        The worker's zero-based index within the campaign.

    Returns
    -------
    CampaignWorker
    """
    if index < 0:
        raise ValueError("worker index must be non-negative")

    cfg = campaign.config
    campaign_dir = campaign.output_dir
    worker_dir = campaign_dir / f"worker-{index:03d}"

    worker_id = f"{campaign.campaign_id}:w{index:03d}"

    worker_config = WorkerConfig(
        worker_id=worker_id,
        worker_index=index,
        campaign_id=campaign.campaign_id,
        campaign_name=cfg.name,
        fuzzer=cfg.fuzzer,
        fuzzer_config=dict(cfg.fuzzer_config),
        fuzzer_executable=None,
        target_command=cfg.target_command,
        target_args=tuple(cfg.target_args),
        target_input_style=cfg.target_input_style,
        sanitizer=cfg.sanitizer,
        sanitizer_config=dict(cfg.sanitizer_config),
        corpus_root=cfg.corpus_root,
        output_dir=cfg.output_dir,
        worker_dir=str(worker_dir),
        environment=dict(cfg.environment),
        tags=cfg.tags,
    )

    return CampaignWorker(worker_config)


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
