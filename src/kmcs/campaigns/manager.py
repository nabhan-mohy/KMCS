# KMCS Campaign Manager
# =====================
#
# Supervisor for fuzzing campaigns.
#
# A *campaign* is a planned, bounded fuzzing job: it names a target, a
# fuzzer, a corpus, a sanitizer configuration, a worker count, and a
# set of stopping conditions (wall-clock duration, iteration count,
# crash count, and so on). The manager in this module owns the
# lifecycle of campaigns: creating them, transitioning them through
# well-defined states, coordinating their workers, and recording their
# final outcome.
#
# The manager is a *supervisor*, not an executor. It never spawns a
# fuzzer process directly, never parses fuzzer output, and never talks
# to sanitizers. Those concerns belong to:
#
#   * ``worker.py``   — one worker per concurrent fuzzer process,
#                       responsible for spawning, monitoring, and
#                       stopping that process.
#   * ``scheduler.py``— decides when to add or remove workers, how to
#                       distribute the corpus, and how to balance load.
#   * ``telemetry.py``— collects and aggregates live statistics
#                       (executions, coverage, crashes) from workers.
#
# The manager keeps those components in sync by owning their lifecycle
# and by publishing events when a campaign's state changes.
#
# State machine
# -------------
#
# Every campaign is always in exactly one of nine states:
#
#     PENDING       — created, not yet started
#     INITIALIZING  — start() called; workers/telemetry/scheduler
#                     being spun up
#     RUNNING       — workers active
#     PAUSED        — workers halted temporarily, state preserved
#     STOPPING      — stop() called; waiting for workers to exit
#     STOPPED       — stopped by user or by an external signal
#     COMPLETED     — stopping condition satisfied (duration, crash
#                     limit, iteration limit, ...)
#     FAILED        — unrecoverable error
#     CANCELLED     — cancelled before start (or from PAUSED)
#
# Transitions are validated against an explicit table. Illegal
# transitions raise :class:`InvalidStateTransitionError`; the manager
# never silently coerces a state.
#
# Threading
# ---------
#
# All public methods are safe to call from multiple threads. Internal
# state is protected by a single reentrant lock; state transitions are
# atomic with respect to that lock. The manager also runs one monitor
# thread that periodically polls active campaigns to enforce stopping
# conditions and to detect worker exits that were not signalled
# explicitly.
#
# The monitor thread is created lazily on the first campaign start and
# torn down by :meth:`CampaignManager.shutdown`. Tests may construct a
# manager with ``auto_monitor=False`` and call :meth:`CampaignManager.tick`
# manually to drive the state machine deterministically.
#
# Persistence
# -----------
#
# When a :class:`~kmcs.database.database.DatabaseManager` is supplied,
# every state transition is persisted to the database. The manager
# degrades gracefully when the database is unavailable or when its
# schema does not yet include campaign tables: persistence failures
# are logged, never raised.
#
# Compatibility
# -------------
#
# Python 3.10+.

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict, replace
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

if TYPE_CHECKING:
    from .worker import CampaignWorker
    from .scheduler import CampaignScheduler
    from .telemetry import CampaignTelemetry


__all__ = [
    "CampaignManager",
    "Campaign",
    "CampaignConfig",
    "CampaignStats",
    "CampaignState",
    "StateChange",
    "ManagerStats",
    "CampaignError",
    "CampaignNotFoundError",
    "InvalidStateTransitionError",
    "CampaignAlreadyTerminalError",
    "CampaignStartError",
    "DEFAULT_MONITOR_INTERVAL",
    "DEFAULT_STOP_TIMEOUT",
    "DEFAULT_CAMPAIGN_DURATION",
    "DEFAULT_WORKER_COUNT",
    "VALID_TRANSITIONS",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: How often, in seconds, the monitor thread inspects active campaigns.
DEFAULT_MONITOR_INTERVAL: float = 1.0

#: How long, in seconds, :meth:`CampaignManager.stop_campaign` waits for
#: workers to exit before giving up and marking the campaign STOPPED.
DEFAULT_STOP_TIMEOUT: float = 15.0

#: Default campaign duration, in seconds, when the caller does not
#: specify one. One hour is a reasonable default for an interactive
#: fuzzing session and short enough that a mistake does not consume a
#: whole machine overnight.
DEFAULT_CAMPAIGN_DURATION: float = 3600.0

#: Default number of workers per campaign. One is the safest choice
#: because it matches the number of CPUs a small CI runner has, and
#: does not surprise users on shared machines.
DEFAULT_WORKER_COUNT: int = 1

#: Filenames and directory names used inside a campaign output dir.
_OUTPUT_SUBDIRS: Tuple[str, ...] = ("corpus", "crashes", "logs", "telemetry")
_OUTPUT_STATE_FILE = "campaign.json"
_OUTPUT_CONFIG_FILE = "config.json"
_OUTPUT_HISTORY_FILE = "history.jsonl"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CampaignError(KMCSException):
    """Base class for all campaign-manager errors."""


class CampaignNotFoundError(CampaignError):
    """Raised when a campaign ID is not registered with the manager."""

    def __init__(self, campaign_id: str) -> None:
        self.campaign_id = campaign_id
        super().__init__(f"campaign not found: {campaign_id}")


class InvalidStateTransitionError(CampaignError):
    """Raised when a state transition is not permitted.

    Attributes
    ----------
    from_state:
        The campaign's current state.
    to_state:
        The requested (rejected) state.
    campaign_id:
        The campaign whose transition was rejected.
    """

    def __init__(
        self,
        campaign_id: str,
        from_state: "CampaignState",
        to_state: "CampaignState",
    ) -> None:
        self.campaign_id = campaign_id
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(
            f"campaign {campaign_id}: "
            f"cannot transition {from_state.value} -> {to_state.value}"
        )


class CampaignAlreadyTerminalError(CampaignError):
    """Raised when an operation is attempted on a terminal campaign."""

    def __init__(self, campaign_id: str, state: "CampaignState") -> None:
        self.campaign_id = campaign_id
        self.state = state
        super().__init__(
            f"campaign {campaign_id} is in terminal state {state.value}"
        )


class CampaignStartError(CampaignError):
    """Raised when a campaign cannot be started.

    The underlying cause is preserved as ``__cause__``.
    """


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class CampaignState(str, Enum):
    """Lifecycle state of a campaign.

    The string values are stable and suitable for persistence. The
    iteration order of the enum follows the natural lifecycle, not
    alphabetical order, which is useful for sorting and reporting.
    """

    PENDING = "pending"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """Return True if no further transitions are possible."""
        return self in (
            CampaignState.STOPPED,
            CampaignState.COMPLETED,
            CampaignState.FAILED,
            CampaignState.CANCELLED,
        )

    @property
    def is_active(self) -> bool:
        """Return True if workers are expected to be running."""
        return self in (CampaignState.RUNNING, CampaignState.PAUSED)

    @property
    def is_settled(self) -> bool:
        """Return True if the campaign is not in the middle of a transition."""
        return self not in (
            CampaignState.INITIALIZING,
            CampaignState.STOPPING,
        )


#: Valid transitions from each state. Transitions not listed here are
#: rejected by :meth:`CampaignManager._transition`.
VALID_TRANSITIONS: Mapping[CampaignState, FrozenSet[CampaignState]] = {
    CampaignState.PENDING: frozenset(
        {
            CampaignState.INITIALIZING,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.INITIALIZING: frozenset(
        {
            CampaignState.RUNNING,
            CampaignState.FAILED,
            CampaignState.STOPPING,
        }
    ),
    CampaignState.RUNNING: frozenset(
        {
            CampaignState.PAUSED,
            CampaignState.STOPPING,
            CampaignState.COMPLETED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.PAUSED: frozenset(
        {
            CampaignState.RUNNING,
            CampaignState.STOPPING,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.STOPPING: frozenset(
        {
            CampaignState.STOPPED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.STOPPED: frozenset(),
    CampaignState.COMPLETED: frozenset(),
    CampaignState.FAILED: frozenset(),
    CampaignState.CANCELLED: frozenset(),
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StateChange:
    """A single transition in a campaign's lifecycle.

    The list of :class:`StateChange` records is the campaign's audit
    log: it records every state the campaign has been in, when, and
    why. It is never pruned, and it is persisted alongside the
    campaign's terminal state so that a post-mortem can reconstruct
    exactly what happened.
    """

    at: datetime
    from_state: CampaignState
    to_state: CampaignState
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "at": self.at.isoformat(),
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CampaignConfig:
    """Immutable configuration for a campaign.

    A campaign's config is fixed at creation time. Callers who want to
    change a config after creation must cancel the campaign and create
    a new one; this guarantees that a running campaign's workers never
    see a config mutation mid-flight.

    Fields
    ------
    name:
        Human-readable name for the campaign. Need not be unique, but
        it is used in log lines and reports, so it should be
        descriptive.
    target_command:
        Path to the target binary. Must be executable.
    target_args:
        Extra argv entries inserted before the input path.
    target_input_style:
        ``"argv"`` or ``"stdin"`` — how the target consumes inputs.
    fuzzer:
        Fuzzer identifier: one of ``"aflpp"``, ``"libfuzzer"``,
        ``"honggfuzz"``. The manager does not interpret this string
        beyond passing it to the worker factory.
    fuzzer_config:
        Fuzzer-specific configuration. The manager treats this as an
        opaque mapping.
    corpus_root:
        Directory holding the seed corpus. Created if missing.
    output_dir:
        Directory holding all campaign output. Created if missing.
    sanitizer:
        Optional sanitizer name (``"asan"``, ``"ubsan"``, ``"tsan"``,
        ``"lsan"``) or None.
    sanitizer_config:
        Optional sanitizer-specific configuration.
    workers:
        Number of concurrent workers to spawn.
    duration_seconds:
        Wall-clock budget. When None, the campaign runs until stopped
        or until another stopping condition fires.
    max_iterations:
        Optional cap on total fuzzer executions across all workers.
    max_crashes:
        Optional cap on total crashes; when reached the campaign
        completes.
    stop_on_first_crash:
        Convenience boolean that sets ``max_crashes=1``.
    monitor_interval:
        Override for the campaign's monitor polling interval.
    environment:
        Extra environment variables for workers.
    tags:
        Free-form labels for filtering and reporting.
    metadata:
        Opaque key/value payload for downstream tooling.
    """

    name: str
    target_command: str
    target_args: Tuple[str, ...] = ()
    target_input_style: str = "argv"
    fuzzer: str = "aflpp"
    fuzzer_config: Mapping[str, Any] = field(default_factory=dict)
    corpus_root: str = "./corpus"
    output_dir: str = "./campaigns"
    sanitizer: Optional[str] = None
    sanitizer_config: Mapping[str, Any] = field(default_factory=dict)
    workers: int = DEFAULT_WORKER_COUNT
    duration_seconds: Optional[float] = DEFAULT_CAMPAIGN_DURATION
    max_iterations: Optional[int] = None
    max_crashes: Optional[int] = None
    stop_on_first_crash: bool = False
    monitor_interval: float = DEFAULT_MONITOR_INTERVAL
    environment: Mapping[str, str] = field(default_factory=dict)
    tags: FrozenSet[str] = field(default_factory=frozenset)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("CampaignConfig.name must not be empty")
        if not self.target_command:
            raise ValueError("CampaignConfig.target_command must not be empty")
        if self.target_input_style not in ("argv", "stdin"):
            raise ValueError(
                f"unsupported target_input_style: "
                f"{self.target_input_style!r}"
            )
        if self.workers <= 0:
            raise ValueError("CampaignConfig.workers must be positive")
        if self.monitor_interval <= 0:
            raise ValueError("CampaignConfig.monitor_interval must be positive")
        if self.duration_seconds is not None and self.duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive or None")
        if self.max_iterations is not None and self.max_iterations <= 0:
            raise ValueError("max_iterations must be positive or None")
        if self.max_crashes is not None and self.max_crashes <= 0:
            raise ValueError("max_crashes must be positive or None")
        if self.stop_on_first_crash and self.max_crashes not in (None, 1):
            raise ValueError(
                "stop_on_first_crash=True conflicts with max_crashes != 1"
            )

    @property
    def effective_max_crashes(self) -> Optional[int]:
        """Return ``max_crashes`` after applying ``stop_on_first_crash``."""
        if self.stop_on_first_crash:
            return 1
        return self.max_crashes

    def with_overrides(self, **changes: Any) -> "CampaignConfig":
        """Return a copy of this config with the given fields replaced."""
        return replace(self, **changes)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of this config."""
        return {
            "name": self.name,
            "target_command": self.target_command,
            "target_args": list(self.target_args),
            "target_input_style": self.target_input_style,
            "fuzzer": self.fuzzer,
            "fuzzer_config": dict(self.fuzzer_config),
            "corpus_root": self.corpus_root,
            "output_dir": self.output_dir,
            "sanitizer": self.sanitizer,
            "sanitizer_config": dict(self.sanitizer_config),
            "workers": self.workers,
            "duration_seconds": self.duration_seconds,
            "max_iterations": self.max_iterations,
            "max_crashes": self.max_crashes,
            "stop_on_first_crash": self.stop_on_first_crash,
            "monitor_interval": self.monitor_interval,
            "environment": dict(self.environment),
            "tags": sorted(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass
class CampaignStats:
    """Cumulative statistics for a campaign.

    All fields are updated from real worker and telemetry reports. Zero
    means "no data reported yet", never "estimated to be zero".
    """

    total_executions: int = 0
    total_crashes: int = 0
    total_hangs: int = 0
    corpus_size: int = 0
    coverage_percent: float = 0.0
    active_workers: int = 0
    elapsed_seconds: float = 0.0
    last_updated: Optional[datetime] = None

    def merge_worker_stats(self, stats: Mapping[str, Any]) -> None:
        """Merge a worker-level stats mapping into this aggregate.

        Recognised keys:

        * ``executions`` / ``total_executions`` — added to
          ``total_executions``.
        * ``crashes`` / ``total_crashes`` — added to ``total_crashes``.
        * ``hangs`` / ``total_hangs`` — added to ``total_hangs``.
        * ``corpus_size`` — max-combined into ``corpus_size``.
        * ``coverage_percent`` / ``coverage`` — max-combined.
        * ``active`` (bool) — counted toward ``active_workers`` when
          the caller resets ``active_workers`` before merging.

        Unknown keys are ignored; this method never raises on
        unexpected worker output.
        """
        def _get(*keys: str) -> Optional[Any]:
            for key in keys:
                if key in stats:
                    return stats[key]
            return None

        executions = _get("executions", "total_executions")
        if isinstance(executions, (int, float)):
            self.total_executions += int(executions)

        crashes = _get("crashes", "total_crashes")
        if isinstance(crashes, (int, float)):
            self.total_crashes += int(crashes)

        hangs = _get("hangs", "total_hangs")
        if isinstance(hangs, (int, float)):
            self.total_hangs += int(hangs)

        corpus_size = _get("corpus_size")
        if isinstance(corpus_size, (int, float)):
            self.corpus_size = max(self.corpus_size, int(corpus_size))

        coverage = _get("coverage_percent", "coverage")
        if isinstance(coverage, (int, float)):
            self.coverage_percent = max(
                self.coverage_percent, float(coverage)
            )

        self.last_updated = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of these stats."""
        return {
            "total_executions": self.total_executions,
            "total_crashes": self.total_crashes,
            "total_hangs": self.total_hangs,
            "corpus_size": self.corpus_size,
            "coverage_percent": self.coverage_percent,
            "active_workers": self.active_workers,
            "elapsed_seconds": self.elapsed_seconds,
            "last_updated": (
                self.last_updated.isoformat()
                if self.last_updated is not None
                else None
            ),
        }


@dataclass
class Campaign:
    """Mutable runtime state of a single campaign.

    A :class:`Campaign` is created by :meth:`CampaignManager.create_campaign`
    and evolves over its lifetime. Callers should treat its fields as
    read-only: mutating them directly will corrupt the manager's
    internal bookkeeping. Use the manager's public methods to drive
    state changes.
    """

    campaign_id: str
    config: CampaignConfig
    state: CampaignState = CampaignState.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    stats: CampaignStats = field(default_factory=CampaignStats)
    error_message: Optional[str] = None
    state_history: List[StateChange] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def output_dir(self) -> Path:
        """The campaign's output directory, derived from config + id."""
        return Path(self.config.output_dir) / self.campaign_id

    @property
    def is_terminal(self) -> bool:
        return self.state.is_terminal

    @property
    def is_active(self) -> bool:
        return self.state.is_active

    @property
    def runtime_seconds(self) -> float:
        """Seconds elapsed since the campaign started, or 0 if it has not."""
        if self.started_at is None:
            return 0.0
        end = self.finished_at or datetime.now(timezone.utc)
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of this campaign."""
        return {
            "campaign_id": self.campaign_id,
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "started_at": (
                self.started_at.isoformat() if self.started_at else None
            ),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
            "runtime_seconds": self.runtime_seconds,
            "stats": self.stats.to_dict(),
            "error_message": self.error_message,
            "config": self.config.to_dict(),
            "state_history": [s.to_dict() for s in self.state_history],
            "metadata": dict(self.metadata),
        }


@dataclass
class ManagerStats:
    """Aggregate statistics describing the manager as a whole."""

    total_campaigns: int = 0
    by_state: Dict[str, int] = field(default_factory=dict)
    active_campaigns: int = 0
    uptime_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_campaigns": self.total_campaigns,
            "by_state": dict(self.by_state),
            "active_campaigns": self.active_campaigns,
            "uptime_seconds": self.uptime_seconds,
        }


# ---------------------------------------------------------------------------
# Internal runtime container
# ---------------------------------------------------------------------------


@dataclass
class _CampaignRuntime:
    """Non-serialisable runtime state for a single campaign.

    Kept separate from :class:`Campaign` so that the latter remains
    JSON-serialisable and clean to log, while workers, schedulers, and
    telemetry objects live in a container that is never persisted.
    """

    workers: List[Any] = field(default_factory=list)
    scheduler: Optional[Any] = None
    telemetry: Optional[Any] = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    stop_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

#: Factory that produces a worker for a (campaign, worker_index) pair.
WorkerFactory = Callable[["Campaign", int], Any]

#: Factory that produces a scheduler for a campaign.
SchedulerFactory = Callable[["Campaign"], Any]

#: Factory that produces a telemetry collector for a campaign.
TelemetryFactory = Callable[["Campaign"], Any]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _event_type(name: str) -> Any:
    """Return an :class:`EventType` member by name, or a fallback.

    Different versions of the events module may expose different sets
    of event types. Rather than hard-coding a specific one (and
    breaking when it is missing), this helper resolves the name and
    falls back to any generic member that does exist. The manager
    never fails to emit an event purely because a specific event type
    is unavailable.
    """
    member = getattr(EventType, name, None)
    if member is not None:
        return member
    for fallback in ("SYSTEM", "INFO", "MESSAGE", "GENERIC"):
        candidate = getattr(EventType, fallback, None)
        if candidate is not None:
            return candidate
    try:
        return next(iter(EventType))  # type: ignore[arg-type]
    except (TypeError, StopIteration):
        return name


def _serialize_worker_stats(worker: Any) -> Mapping[str, Any]:
    """Call ``worker.stats()`` and normalise the result.

    The function is defensive: any exception raised by the worker is
    logged and converted to an empty mapping. The monitor loop uses
    this helper and must never crash because a single worker misbehaves.
    """
    getter = getattr(worker, "stats", None)
    if not callable(getter):
        return {}
    try:
        result = getter()
    except Exception as exc:  # noqa: BLE001 - worker is untrusted
        logger.debug("worker.stats() raised: %s", exc)
        return {}
    if isinstance(result, Mapping):
        return result
    return {}


def _safe_call(obj: Any, method_name: str, *args: Any, **kwargs: Any) -> bool:
    """Call ``obj.method_name(*args, **kwargs)`` if it exists; return success.

    Any exception is logged at DEBUG level and swallowed. Callers use
    this to invoke optional worker/scheduler/telemetry methods without
    committing to a specific interface.
    """
    method = getattr(obj, method_name, None)
    if not callable(method):
        return False
    try:
        method(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.debug("%s.%s raised: %s", type(obj).__name__, method_name, exc)
        return False
    return True


# ---------------------------------------------------------------------------
# CampaignManager
# ---------------------------------------------------------------------------


class CampaignManager:
    """Supervisor for fuzzing campaigns.

    Parameters
    ----------
    config:
        Optional :class:`~kmcs.core.config.KMCSConfig` used for
        platform-level defaults.
    database:
        Optional :class:`~kmcs.database.database.DatabaseManager`. When
        provided, every campaign is persisted to the database at
        creation and after every state transition. Persistence
        failures are logged, never raised.
    event_bus:
        Optional :class:`~kmcs.core.events.EventBus`. When omitted,
        the process-wide default bus is used.
    worker_factory:
        Callable producing a worker for a given campaign and worker
        index. When None, the manager tries to import the default
        factory from :mod:`kmcs.campaigns.worker`; if that module is
        not importable, campaign start fails with a clear error.
    scheduler_factory:
        Same pattern as ``worker_factory``, for the scheduler.
    telemetry_factory:
        Same pattern as ``worker_factory``, for telemetry.
    auto_monitor:
        When True (default), the manager runs a background monitor
        thread that periodically calls :meth:`tick`. When False, the
        caller is responsible for calling :meth:`tick` manually.
    monitor_interval:
        Polling interval for the monitor thread, in seconds.
    default_stop_timeout:
        How long to wait for workers to exit during
        :meth:`stop_campaign`, in seconds.
    """

    def __init__(
        self,
        *,
        config: Optional[KMCSConfig] = None,
        database: Optional[Any] = None,
        event_bus: Optional[EventBus] = None,
        worker_factory: Optional[WorkerFactory] = None,
        scheduler_factory: Optional[SchedulerFactory] = None,
        telemetry_factory: Optional[TelemetryFactory] = None,
        auto_monitor: bool = True,
        monitor_interval: float = DEFAULT_MONITOR_INTERVAL,
        default_stop_timeout: float = DEFAULT_STOP_TIMEOUT,
    ) -> None:
        if monitor_interval <= 0:
            raise ValueError("monitor_interval must be positive")
        if default_stop_timeout <= 0:
            raise ValueError("default_stop_timeout must be positive")

        self._config = config or get_default_config()
        self._database = database
        self._bus = event_bus or get_default_bus()
        self._worker_factory = worker_factory
        self._scheduler_factory = scheduler_factory
        self._telemetry_factory = telemetry_factory
        self._auto_monitor = bool(auto_monitor)
        self._monitor_interval = float(monitor_interval)
        self._default_stop_timeout = float(default_stop_timeout)

        self._lock = threading.RLock()
        self._campaigns: Dict[str, Campaign] = {}
        self._runtime: Dict[str, _CampaignRuntime] = {}

        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_shutdown = threading.Event()
        self._started_at = time.monotonic()
        self._closed = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def config(self) -> KMCSConfig:
        return self._config

    @property
    def database(self) -> Optional[Any]:
        return self._database

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def campaign_count(self) -> int:
        with self._lock:
            return len(self._campaigns)

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _emit(self, event_name: str, payload: Dict[str, Any]) -> None:
        """Publish an event on the internal bus.

        The event type is resolved by name; if the specific member is
        missing from :class:`EventType`, a generic fallback is used.
        Subscriber exceptions are swallowed and logged.
        """
        try:
            et = _event_type(event_name)
            event = Event(
                type=et,
                source="campaigns.manager",
                data={"event": event_name, **payload},
            )
            self._bus.publish(event)
        except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
            logger.warning("campaign event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Database persistence
    # ------------------------------------------------------------------

    def _persist_campaign(self, campaign: Campaign) -> None:
        """Persist a campaign snapshot to the database, if attached."""
        if self._database is None:
            return
        writer = getattr(self._database, "upsert_campaign", None) or getattr(
            self._database, "add_campaign", None
        )
        if writer is None:
            return
        try:
            writer(campaign.to_dict())
        except Exception as exc:  # noqa: BLE001 - DB failure must not abort
            logger.debug("failed to persist campaign %s: %s", campaign.campaign_id, exc)

    # ------------------------------------------------------------------
    # Filesystem layout
    # ------------------------------------------------------------------

    def _prepare_output_dirs(self, campaign: Campaign) -> Path:
        """Create the campaign's output directory tree.

        Returns the top-level campaign directory. Subdirectories are
        created for corpus snapshots, crashes, logs, and telemetry.
        Raises :class:`CampaignStartError` if any of these operations
        fail.
        """
        top = campaign.output_dir
        try:
            top.mkdir(parents=True, exist_ok=True)
            for name in _OUTPUT_SUBDIRS:
                (top / name).mkdir(exist_ok=True)
        except OSError as exc:
            raise CampaignStartError(
                f"failed to create output directory {top}: {exc}"
            ) from exc
        # Write the campaign config snapshot once.
        try:
            self._write_json(top / _OUTPUT_CONFIG_FILE, campaign.config.to_dict())
            self._write_json(top / _OUTPUT_STATE_FILE, campaign.to_dict())
        except OSError as exc:
            raise CampaignStartError(
                f"failed to write campaign state to {top}: {exc}"
            ) from exc
        return top

    def _write_json(self, path: Path, payload: Any) -> None:
        """Write ``payload`` to ``path`` as JSON, atomically."""
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True, default=str)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except Exception:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    def _append_history(self, campaign: Campaign, change: StateChange) -> None:
        """Append a state-change record to the campaign's history file."""
        try:
            path = campaign.output_dir / _OUTPUT_HISTORY_FILE
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(change.to_dict(), default=str))
                fh.write("\n")
        except OSError as exc:
            logger.debug("failed to append campaign history: %s", exc)

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def _transition(
        self,
        campaign: Campaign,
        new_state: CampaignState,
        reason: str,
    ) -> None:
        """Transition ``campaign`` to ``new_state``.

        Validates the transition, records a :class:`StateChange`,
        updates timestamps, emits an event, and persists the campaign.

        Raises
        ------
        InvalidStateTransitionError
            If the transition is not permitted.
        """
        old_state = campaign.state
        if old_state == new_state:
            return
        allowed = VALID_TRANSITIONS.get(old_state, frozenset())
        if new_state not in allowed:
            raise InvalidStateTransitionError(
                campaign.campaign_id, old_state, new_state
            )

        campaign.state = new_state
        now = _now()

        if new_state == CampaignState.RUNNING and campaign.started_at is None:
            campaign.started_at = now
        if new_state.is_terminal and campaign.finished_at is None:
            campaign.finished_at = now

        change = StateChange(
            at=now,
            from_state=old_state,
            to_state=new_state,
            reason=reason,
        )
        campaign.state_history.append(change)

        self._append_history(campaign, change)
        self._persist_campaign(campaign)

        self._emit(
            "CAMPAIGN_STATE_CHANGED",
            {
                "campaign_id": campaign.campaign_id,
                "from_state": old_state.value,
                "to_state": new_state.value,
                "reason": reason,
            },
        )

    # ------------------------------------------------------------------
    # Campaign lifecycle: creation
    # ------------------------------------------------------------------

    def create_campaign(
        self,
        config: CampaignConfig,
        *,
        campaign_id: Optional[str] = None,
    ) -> Campaign:
        """Create a new campaign in the PENDING state.

        Parameters
        ----------
        config:
            The campaign's configuration. Immutable once accepted.
        campaign_id:
            Optional explicit identifier. When None, a UUID4 is
            generated. The identifier must be unique across the
            manager's lifetime; a collision raises
            :class:`CampaignError`.

        Returns
        -------
        Campaign
            The newly-created campaign, in PENDING state.
        """
        if self._closed:
            raise CampaignError("manager has been shut down")
        if not isinstance(config, CampaignConfig):
            raise TypeError(
                f"config must be CampaignConfig, got {type(config).__name__}"
            )
        cid = campaign_id or str(uuid.uuid4())

        with self._lock:
            if cid in self._campaigns:
                raise CampaignError(f"campaign id already in use: {cid}")
            campaign = Campaign(campaign_id=cid, config=config)
            self._campaigns[cid] = campaign
            self._runtime[cid] = _CampaignRuntime()

        self._persist_campaign(campaign)
        self._emit(
            "CAMPAIGN_CREATED",
            {
                "campaign_id": cid,
                "name": config.name,
                "fuzzer": config.fuzzer,
                "workers": config.workers,
                "target": config.target_command,
            },
        )
        return campaign

    # ------------------------------------------------------------------
    # Campaign lifecycle: start
    # ------------------------------------------------------------------

    def start_campaign(self, campaign_id: str) -> Campaign:
        """Start a PENDING campaign.

        The method:

        1. Transitions the campaign to INITIALIZING.
        2. Creates the output directory tree and writes a config
           snapshot.
        3. Instantiates the telemetry collector, the scheduler, and the
           worker pool via the configured factories.
        4. Transitions the campaign to RUNNING.
        5. Ensures the monitor thread is running.

        If any step fails, the campaign is transitioned to FAILED and
        the original exception is wrapped in
        :class:`CampaignStartError`.

        Raises
        ------
        CampaignNotFoundError
            If the ID is unknown.
        InvalidStateTransitionError
            If the campaign is not in a state from which starting is
            permitted.
        CampaignStartError
            If a step of the startup sequence fails.
        """
        if self._closed:
            raise CampaignError("manager has been shut down")

        with self._lock:
            campaign = self._require_campaign(campaign_id)
            self._transition(campaign, CampaignState.INITIALIZING, "start requested")
            runtime = self._runtime[campaign_id]

        try:
            self._prepare_output_dirs(campaign)
            self._setup_telemetry(campaign, runtime)
            self._setup_scheduler(campaign, runtime)
            self._spawn_workers(campaign, runtime)
        except Exception as exc:
            logger.exception("campaign %s failed to start", campaign_id)
            with self._lock:
                campaign.error_message = str(exc)
                try:
                    self._transition(campaign, CampaignState.FAILED, f"start error: {exc}")
                except InvalidStateTransitionError:
                    pass
            raise CampaignStartError(str(exc)) from exc

        with self._lock:
            campaign.started_at = campaign.started_at or _now()
            self._transition(campaign, CampaignState.RUNNING, "workers started")

        self._ensure_monitor_thread()

        self._emit(
            "CAMPAIGN_STARTED",
            {
                "campaign_id": campaign_id,
                "workers": len(runtime.workers),
                "output_dir": str(campaign.output_dir),
            },
        )
        return campaign

    def _setup_telemetry(
        self, campaign: Campaign, runtime: _CampaignRuntime
    ) -> None:
        """Instantiate and start the telemetry collector, if configured."""
        factory = self._telemetry_factory or self._default_telemetry_factory()
        if factory is None:
            return
        telemetry = factory(campaign)
        _safe_call(telemetry, "start")
        runtime.telemetry = telemetry

    def _setup_scheduler(
        self, campaign: Campaign, runtime: _CampaignRuntime
    ) -> None:
        """Instantiate and start the scheduler, if configured."""
        factory = self._scheduler_factory or self._default_scheduler_factory()
        if factory is None:
            return
        scheduler = factory(campaign)
        _safe_call(scheduler, "start")
        runtime.scheduler = scheduler

    def _spawn_workers(
        self, campaign: Campaign, runtime: _CampaignRuntime
    ) -> None:
        """Instantiate and start every worker for the campaign."""
        factory = self._worker_factory or self._default_worker_factory()
        if factory is None:
            raise CampaignStartError(
                "no worker factory available; either pass worker_factory= "
                "or ensure kmcs.campaigns.worker is importable"
            )
        for index in range(campaign.config.workers):
            worker = factory(campaign, index)
            starter = getattr(worker, "start", None)
            if not callable(starter):
                raise CampaignStartError(
                    f"worker {index} has no start() method"
                )
            starter()
            # If the worker supports an exit callback, register one so
            # that worker exits are detected promptly instead of only on
            # the next monitor tick.
            on_exit = getattr(worker, "on_exit", None)
            if callable(on_exit):
                try:
                    on_exit(
                        lambda wid=index: self._on_worker_exit(
                            campaign.campaign_id, wid
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("failed to register worker exit callback: %s", exc)
            runtime.workers.append(worker)

    # ------------------------------------------------------------------
    # Default factories
    # ------------------------------------------------------------------

    def _default_worker_factory(self) -> Optional[WorkerFactory]:
        """Return the default worker factory, importing lazily."""
        try:
            from .worker import default_worker_factory
        except ImportError:
            return None
        return default_worker_factory

    def _default_scheduler_factory(self) -> Optional[SchedulerFactory]:
        """Return the default scheduler factory, importing lazily."""
        try:
            from .scheduler import default_scheduler_factory
        except ImportError:
            return None
        return default_scheduler_factory

    def _default_telemetry_factory(self) -> Optional[TelemetryFactory]:
        """Return the default telemetry factory, importing lazily."""
        try:
            from .telemetry import default_telemetry_factory
        except ImportError:
            return None
        return default_telemetry_factory

    # ------------------------------------------------------------------
    # Campaign lifecycle: pause / resume
    # ------------------------------------------------------------------

    def pause_campaign(self, campaign_id: str) -> Campaign:
        """Pause a running campaign.

        Pausing suspends workers but preserves their state. Whether
        this is possible depends on the fuzzer: workers that cannot be
        paused expose no ``pause`` method, in which case the manager
        logs a warning and returns the campaign unchanged.

        Raises
        ------
        CampaignNotFoundError
            If the ID is unknown.
        InvalidStateTransitionError
            If the campaign is not RUNNING.
        """
        with self._lock:
            campaign = self._require_campaign(campaign_id)
            self._transition(campaign, CampaignState.PAUSED, "pause requested")
            runtime = self._runtime[campaign_id]

        paused = 0
        for worker in runtime.workers:
            if _safe_call(worker, "pause"):
                paused += 1
        _safe_call(runtime.scheduler, "pause")
        _safe_call(runtime.telemetry, "pause")

        self._emit(
            "CAMPAIGN_PAUSED",
            {
                "campaign_id": campaign_id,
                "workers_paused": paused,
                "workers_total": len(runtime.workers),
            },
        )
        return campaign

    def resume_campaign(self, campaign_id: str) -> Campaign:
        """Resume a paused campaign.

        Raises
        ------
        CampaignNotFoundError
            If the ID is unknown.
        InvalidStateTransitionError
            If the campaign is not PAUSED.
        """
        with self._lock:
            campaign = self._require_campaign(campaign_id)
            self._transition(campaign, CampaignState.RUNNING, "resume requested")
            runtime = self._runtime[campaign_id]

        resumed = 0
        for worker in runtime.workers:
            if _safe_call(worker, "resume"):
                resumed += 1
        _safe_call(runtime.scheduler, "resume")
        _safe_call(runtime.telemetry, "resume")

        self._emit(
            "CAMPAIGN_RESUMED",
            {
                "campaign_id": campaign_id,
                "workers_resumed": resumed,
                "workers_total": len(runtime.workers),
            },
        )
        return campaign

    # ------------------------------------------------------------------
    # Campaign lifecycle: stop / cancel
    # ------------------------------------------------------------------

    def stop_campaign(
        self,
        campaign_id: str,
        *,
        reason: str = "user requested stop",
        timeout: Optional[float] = None,
    ) -> Campaign:
        """Stop a running or paused campaign.

        The method transitions the campaign to STOPPING, asks every
        worker to stop, waits up to ``timeout`` seconds for them to
        exit, then transitions to STOPPED and tears down the scheduler
        and telemetry collector.

        Raises
        ------
        CampaignNotFoundError
            If the ID is unknown.
        InvalidStateTransitionError
            If the campaign is not RUNNING or PAUSED.
        """
        with self._lock:
            campaign = self._require_campaign(campaign_id)
            if campaign.state.is_terminal:
                raise CampaignAlreadyTerminalError(
                    campaign_id, campaign.state
                )
            self._transition(campaign, CampaignState.STOPPING, reason)
            runtime = self._runtime[campaign_id]
            runtime.stop_reason = reason
            runtime.stop_event.set()

        self._stop_workers(runtime, timeout=timeout)

        with self._lock:
            try:
                self._transition(
                    campaign, CampaignState.STOPPED, reason
                )
            except InvalidStateTransitionError:
                # A concurrent path (e.g. FAILED) may have already
                # moved us out of STOPPING; accept that.
                pass

        self._teardown_components(runtime)
        self._emit(
            "CAMPAIGN_STOPPED",
            {"campaign_id": campaign_id, "reason": reason},
        )
        return campaign

    def cancel_campaign(
        self,
        campaign_id: str,
        *,
        reason: str = "user cancelled",
    ) -> Campaign:
        """Cancel a PENDING or PAUSED campaign.

        Cancellation is only permitted before the campaign has ever
        started, or while it is paused. Running campaigns must be
        stopped first; this restriction avoids losing worker output
        mid-flight.

        Raises
        ------
        CampaignNotFoundError
            If the ID is unknown.
        InvalidStateTransitionError
            If the campaign is not PENDING or PAUSED.
        """
        with self._lock:
            campaign = self._require_campaign(campaign_id)
            if campaign.state not in (
                CampaignState.PENDING,
                CampaignState.PAUSED,
            ):
                raise InvalidStateTransitionError(
                    campaign_id, campaign.state, CampaignState.CANCELLED
                )
            runtime = self._runtime[campaign_id]
            self._transition(campaign, CampaignState.CANCELLED, reason)

        self._stop_workers(runtime, timeout=self._default_stop_timeout)
        self._teardown_components(runtime)
        self._emit(
            "CAMPAIGN_CANCELLED",
            {"campaign_id": campaign_id, "reason": reason},
        )
        return campaign

    def _stop_workers(
        self, runtime: _CampaignRuntime, *, timeout: Optional[float]
    ) -> None:
        """Ask every worker to stop, then wait for them to exit."""
        wait = timeout if timeout is not None else self._default_stop_timeout

        # First, request cooperative stop.
        for worker in runtime.workers:
            _safe_call(worker, "stop", timeout=wait)

        # Then, wait for is_alive() to return False.
        deadline = time.monotonic() + wait
        for worker in runtime.workers:
            is_alive = getattr(worker, "is_alive", None)
            if not callable(is_alive):
                continue
            while time.monotonic() < deadline:
                try:
                    if not is_alive():
                        break
                except Exception:  # noqa: BLE001
                    break
                time.sleep(0.05)
            else:
                logger.warning(
                    "worker %r did not exit within %.2fs",
                    getattr(worker, "id", worker),
                    wait,
                )

        _safe_call(runtime.scheduler, "stop")
        _safe_call(runtime.telemetry, "stop")

    def _teardown_components(self, runtime: _CampaignRuntime) -> None:
        """Release references to the campaign's runtime components."""
        runtime.workers.clear()
        runtime.scheduler = None
        runtime.telemetry = None

    # ------------------------------------------------------------------
    # Worker exit handling
    # ------------------------------------------------------------------

    def _on_worker_exit(self, campaign_id: str, worker_index: int) -> None:
        """Called by workers when they exit.

        If every worker for the campaign has exited and the campaign is
        still RUNNING, the campaign is transitioned to COMPLETED (if
        all workers exited cleanly) or FAILED (otherwise).
        """
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            runtime = self._runtime.get(campaign_id)
            if campaign is None or runtime is None:
                return
            if campaign.state != CampaignState.RUNNING:
                return

        # Give workers a moment to settle, then reassess.
        time.sleep(0.05)
        self._reassess_worker_health(campaign_id)

    def _reassess_worker_health(self, campaign_id: str) -> None:
        """Update a campaign's state based on current worker health."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            runtime = self._runtime.get(campaign_id)
            if campaign is None or runtime is None:
                return
            if campaign.state not in (CampaignState.RUNNING, CampaignState.PAUSED):
                return
            alive = 0
            for worker in runtime.workers:
                is_alive = getattr(worker, "is_alive", None)
                if not callable(is_alive):
                    alive += 1
                    continue
                try:
                    if is_alive():
                        alive += 1
                except Exception:  # noqa: BLE001
                    alive += 1

        if alive == 0:
            # All workers exited. Distinguish clean completion from
            # failure using the aggregate crash / error stats.
            try:
                with self._lock:
                    campaign = self._campaigns.get(campaign_id)
                    if campaign is None:
                        return
                    target = (
                        CampaignState.COMPLETED
                        if campaign.error_message is None
                        else CampaignState.FAILED
                    )
                    self._transition(
                        campaign,
                        target,
                        "all workers exited",
                    )
                    runtime = self._runtime.get(campaign_id)
                    if runtime is not None:
                        self._teardown_components(runtime)
                self._emit(
                    "CAMPAIGN_COMPLETED" if target == CampaignState.COMPLETED
                    else "CAMPAIGN_FAILED",
                    {"campaign_id": campaign_id},
                )
            except InvalidStateTransitionError:
                pass

    # ------------------------------------------------------------------
    # Monitor thread
    # ------------------------------------------------------------------

    def _ensure_monitor_thread(self) -> None:
        """Start the monitor thread, if it is not already running."""
        if not self._auto_monitor:
            return
        with self._lock:
            if self._monitor_thread is not None and self._monitor_thread.is_alive():
                return
            self._monitor_shutdown.clear()
            thread = threading.Thread(
                target=self._monitor_loop,
                name="kmcs-campaign-monitor",
                daemon=True,
            )
            self._monitor_thread = thread
            thread.start()

    def _monitor_loop(self) -> None:
        """Periodically call :meth:`tick` until shutdown is signalled."""
        while not self._monitor_shutdown.wait(self._monitor_interval):
            try:
                self.tick()
            except Exception:
                logger.exception("campaign monitor tick failed")

    def tick(self) -> None:
        """Run one pass of the campaign-monitor logic.

        This method is public so that tests and single-threaded
        embedders can drive the state machine deterministically by
        calling it directly with ``auto_monitor=False``.
        """
        with self._lock:
            campaign_ids = list(self._campaigns.keys())
        for cid in campaign_ids:
            try:
                self._tick_campaign(cid)
            except Exception:
                logger.exception("tick failed for campaign %s", cid)

    def _tick_campaign(self, campaign_id: str) -> None:
        """Advance one campaign's monitoring state."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            runtime = self._runtime.get(campaign_id)
            if campaign is None or runtime is None:
                return
            if campaign.state.is_terminal:
                return
            if not campaign.state.is_active:
                return

        # Refresh aggregate stats from workers.
        self._update_stats(campaign_id)

        # Check stopping conditions.
        self._check_stopping_conditions(campaign_id)

        # Detect workers that have exited without notifying.
        self._reassess_worker_health(campaign_id)

    def _update_stats(self, campaign_id: str) -> None:
        """Recompute the campaign's aggregate statistics from workers."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            runtime = self._runtime.get(campaign_id)
            if campaign is None or runtime is None:
                return

            fresh = CampaignStats()
            active = 0
            for worker in runtime.workers:
                is_alive = getattr(worker, "is_alive", None)
                if callable(is_alive):
                    try:
                        if is_alive():
                            active += 1
                    except Exception:  # noqa: BLE001
                        pass
                stats = _serialize_worker_stats(worker)
                fresh.merge_worker_stats(stats)
            fresh.active_workers = active
            fresh.elapsed_seconds = campaign.runtime_seconds

            campaign.stats = fresh

    def _check_stopping_conditions(self, campaign_id: str) -> None:
        """Evaluate the campaign's stopping conditions and complete it if met."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                return
            if campaign.state != CampaignState.RUNNING:
                return

            config = campaign.config
            stats = campaign.stats

            reason: Optional[str] = None
            if (
                config.duration_seconds is not None
                and campaign.runtime_seconds >= config.duration_seconds
            ):
                reason = (
                    f"duration reached: {campaign.runtime_seconds:.1f}s "
                    f">= {config.duration_seconds:.1f}s"
                )
            elif (
                config.max_iterations is not None
                and stats.total_executions >= config.max_iterations
            ):
                reason = (
                    f"iteration limit reached: {stats.total_executions} "
                    f">= {config.max_iterations}"
                )
            else:
                max_crashes = config.effective_max_crashes
                if (
                    max_crashes is not None
                    and stats.total_crashes >= max_crashes
                ):
                    reason = (
                        f"crash limit reached: {stats.total_crashes} "
                        f">= {max_crashes}"
                    )

            if reason is None:
                return

            try:
                self._transition(campaign, CampaignState.COMPLETED, reason)
            except InvalidStateTransitionError:
                return
            runtime = self._runtime.get(campaign_id)
            if runtime is not None:
                runtime.stop_event.set()

        # Stop workers outside the lock to avoid holding it while
        # workers shut down.
        self._stop_workers_after_completion(campaign_id)

        self._emit(
            "CAMPAIGN_COMPLETED",
            {"campaign_id": campaign_id, "reason": reason},
        )

    def _stop_workers_after_completion(self, campaign_id: str) -> None:
        """Stop the workers of a campaign that just completed naturally."""
        with self._lock:
            runtime = self._runtime.get(campaign_id)
            if runtime is None:
                return
            workers = list(runtime.workers)
        for worker in workers:
            _safe_call(worker, "stop", timeout=self._default_stop_timeout)
        with self._lock:
            runtime = self._runtime.get(campaign_id)
            if runtime is not None:
                self._teardown_components(runtime)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def _require_campaign(self, campaign_id: str) -> Campaign:
        """Return the campaign or raise :class:`CampaignNotFoundError`."""
        campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            raise CampaignNotFoundError(campaign_id)
        return campaign

    def get_campaign(self, campaign_id: str) -> Campaign:
        """Return a campaign by ID.

        The returned object is live: mutations to its ``state`` field
        by other threads may be observed. Callers who need a snapshot
        should serialise it via :meth:`Campaign.to_dict`.
        """
        with self._lock:
            return self._require_campaign(campaign_id)

    def list_campaigns(
        self,
        *,
        states: Optional[Iterable[CampaignState]] = None,
        tags: Optional[Iterable[str]] = None,
        limit: Optional[int] = None,
    ) -> List[Campaign]:
        """List campaigns matching the given filters.

        Parameters
        ----------
        states:
            If provided, only campaigns in one of these states are
            returned.
        tags:
            If provided, only campaigns whose config tags include at
            least one of the given tags are returned.
        limit:
            If provided, the result is truncated to at most this many
            campaigns, ordered by creation time (newest first).

        Returns
        -------
        list of Campaign
        """
        state_set = frozenset(states) if states is not None else None
        tag_set = frozenset(tags) if tags is not None else None

        with self._lock:
            items = list(self._campaigns.values())

        if state_set is not None:
            items = [c for c in items if c.state in state_set]
        if tag_set is not None:
            items = [
                c for c in items
                if c.config.tags & tag_set
            ]
        items.sort(key=lambda c: c.created_at, reverse=True)
        if limit is not None:
            items = items[:limit]
        return items

    def list_active_campaigns(self) -> List[Campaign]:
        """Return campaigns whose state is RUNNING or PAUSED."""
        return self.list_campaigns(
            states=(CampaignState.RUNNING, CampaignState.PAUSED)
        )

    def stats(self) -> ManagerStats:
        """Return aggregate statistics describing the manager."""
        with self._lock:
            campaigns = list(self._campaigns.values())
        by_state: Dict[str, int] = {}
        active = 0
        for c in campaigns:
            by_state[c.state.value] = by_state.get(c.state.value, 0) + 1
            if c.is_active:
                active += 1
        return ManagerStats(
            total_campaigns=len(campaigns),
            by_state=by_state,
            active_campaigns=active,
            uptime_seconds=time.monotonic() - self._started_at,
        )

    # ------------------------------------------------------------------
    # Waiting
    # ------------------------------------------------------------------

    def wait_campaign(
        self,
        campaign_id: str,
        *,
        timeout: Optional[float] = None,
        poll_interval: float = 0.1,
    ) -> CampaignState:
        """Block until a campaign reaches a terminal state.

        Parameters
        ----------
        campaign_id:
            The campaign to wait for.
        timeout:
            Maximum seconds to wait. When None, waits indefinitely.
        poll_interval:
            How often to check the campaign's state, in seconds.

        Returns
        -------
        CampaignState
            The campaign's state when the wait completed. If the
            timeout fired, the campaign's current (non-terminal)
            state is returned.
        """
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                campaign = self._require_campaign(campaign_id)
                if campaign.state.is_terminal:
                    return campaign.state
            if deadline is not None and time.monotonic() >= deadline:
                with self._lock:
                    campaign = self._require_campaign(campaign_id)
                    return campaign.state
            time.sleep(poll_interval)

    # ------------------------------------------------------------------
    # Removal
    # ------------------------------------------------------------------

    def remove_campaign(self, campaign_id: str) -> None:
        """Remove a terminal campaign from the manager's registry.

        Running or paused campaigns cannot be removed: call
        :meth:`stop_campaign` or :meth:`cancel_campaign` first.

        Raises
        ------
        CampaignNotFoundError
            If the ID is unknown.
        CampaignError
            If the campaign is not in a terminal state.
        """
        with self._lock:
            campaign = self._require_campaign(campaign_id)
            if not campaign.state.is_terminal:
                raise CampaignError(
                    f"cannot remove non-terminal campaign {campaign_id} "
                    f"(state={campaign.state.value})"
                )
            self._campaigns.pop(campaign_id, None)
            self._runtime.pop(campaign_id, None)

        self._emit(
            "CAMPAIGN_REMOVED",
            {"campaign_id": campaign_id},
        )

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def shutdown(
        self,
        *,
        stop_active: bool = True,
        timeout: Optional[float] = None,
    ) -> None:
        """Shut the manager down.

        Parameters
        ----------
        stop_active:
            When True (default), all active campaigns are stopped
            before the monitor thread is torn down. When False, active
            campaigns are left running; their worker objects remain
            alive but unreferenced by this manager.
        timeout:
            Per-campaign stop timeout. Defaults to
            :data:`DEFAULT_STOP_TIMEOUT`.
        """
        if self._closed:
            return

        # First, request stop on active campaigns.
        if stop_active:
            with self._lock:
                active = [
                    c for c in self._campaigns.values()
                    if c.is_active
                ]
            for campaign in active:
                try:
                    self.stop_campaign(
                        campaign.campaign_id,
                        reason="manager shutdown",
                        timeout=timeout,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "failed to stop campaign %s during shutdown: %s",
                        campaign.campaign_id,
                        exc,
                    )

        # Signal the monitor thread and wait for it.
        self._monitor_shutdown.set()
        thread = self._monitor_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

        self._closed = True
        self._emit("CAMPAIGN_MANAGER_SHUTDOWN", {})

    def __enter__(self) -> "CampaignManager":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()

    def __repr__(self) -> str:
        return (
            f"CampaignManager(campaigns={self.campaign_count}, "
            f"closed={self._closed})"
        )


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
