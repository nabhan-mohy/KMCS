# KMCS Campaign Telemetry
# =======================
#
# Real-time collection and representation of campaign activity.
#
# Telemetry answers one question: "What is actually happening in this
# campaign right now?" It does so by sampling the sources that already
# know the answer — the workers, the fuzzers' own status files, and the
# fuzzers' log output — and by aggregating their answers into a single
# structured snapshot that can be displayed in a UI, streamed to a
# reporting tool, or written to disk.
#
# Design principles
# -----------------
#
# The telemetry layer is deliberately conservative in three ways:
#
#   1. **It never fabricates metrics.** Every value that appears in a
#      :class:`FuzzerMetrics` record was produced by a real source.
#      When a fuzzer does not expose a metric (for example, libFuzzer
#      does not expose a per-second execution rate in the same form
#      that AFL++ does), the corresponding field is ``None`` rather
#      than 0. Downstream consumers distinguish "unknown" from "zero".
#
#   2. **It respects each fuzzer's real capabilities.** A
#      :class:`MetricCapability` set describes which metrics a given
#      fuzzer can, in principle, provide. The telemetry layer consults
#      this set when deciding whether to surface a metric as a hard
#      value or as a "not available" placeholder.
#
#   3. **It is non-blocking and bounded.** The sampler thread runs on
#      a fixed interval, drains sources with short timeouts, and never
#      blocks the campaign manager or the workers. Sampling state is
#      stored in a bounded ring buffer; the telemetry layer's memory
#      footprint is therefore constant over the lifetime of a
#      campaign, regardless of runtime.
#
# Sources
# -------
#
# Telemetry reads from any source implementing the lightweight duck-
# typed protocol:
#
#     source_id: str
#     def sample(self) -> Mapping[str, Any] | None: ...
#
# Three concrete sources ship with the module:
#
# * :class:`WorkerSource` — wraps a :class:`~kmcs.campaigns.worker.CampaignWorker`
#   and pulls its :meth:`stats` mapping plus process liveness.
#
# * :class:`AflStatsFileSource` — reads an AFL++ ``fuzzer_stats``
#   file directly. This source is richer than the worker's line
#   parser and is preferred when available, because AFL++ writes
#   precise values to that file (execs_per_sec, bitmap_cvg,
#   stability, peak_rss_mb, ...).
#
# * :class:`JsonFileSource` — reads a JSON file with a flat
#   key/value layout. Intended for custom fuzzers that KMCS does not
#   ship an adapter for but that can be instrumented to write a small
#   status file.
#
# The telemetry collector itself is agnostic to how sources produce
# their mappings. A caller with a bespoke source need only implement
# the two attributes above.
#
# Aggregation
# -----------
#
# A :class:`CampaignTelemetry` collector maintains:
#
#   * A registry of sources, keyed by ``source_id``.
#   * The latest :class:`CampaignSnapshot`, recomputed on every poll.
#   * A bounded history of :class:`TelemetrySample` records, one per
#     poll, for time-series views and windowed aggregates.
#
# :meth:`CampaignTelemetry.snapshot` returns the most recent
# snapshot; :meth:`CampaignTelemetry.history` returns the recorded
# samples; :meth:`CampaignTelemetry.aggregate` returns an aggregate
# over a caller-specified time window.
#
# Execution rates
# ---------------
#
# Execution rate is derived from real deltas: the collector remembers
# the last cumulative execution count and its timestamp for each
# worker, and computes ``(execs_now - execs_prev) / (t_now - t_prev)``
# on every poll. Rate is ``None`` until two polls have been observed.
# When a source publishes its own rate (AFL++'s ``execs_per_sec``),
# that published value takes precedence over the derived one,
# because the fuzzer itself has more accurate visibility into its own
# throughput.
#
# Threading
# ---------
#
# The collector's public methods are thread-safe. Sampling runs on a
# dedicated daemon thread; the collector never blocks the caller's
# thread. :meth:`CampaignTelemetry.stop` shuts the sampler down
# gracefully, with a bounded join.
#
# When ``auto_sample=False``, the caller is responsible for calling
# :meth:`CampaignTelemetry.poll` periodically. This is useful for
# tests and for embedders that already have a scheduler loop.
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
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Deque,
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
from ..core.events import EventBus, EventType
from .._events_compat import Event, get_default_bus, publish_event
from ..core.config import KmcsConfig, get_config

if TYPE_CHECKING:
    from .manager import Campaign


__all__ = [
    "CampaignTelemetry",
    "FuzzerMetrics",
    "WorkerSnapshot",
    "CampaignSnapshot",
    "TelemetrySample",
    "TelemetryStats",
    "TelemetryAggregate",
    "TelemetrySource",
    "WorkerSource",
    "AflStatsFileSource",
    "JsonFileSource",
    "MetricCapability",
    "TelemetryState",
    "TelemetryError",
    "TelemetrySourceError",
    "default_telemetry_factory",
    "FUZZER_CAPABILITIES",
    "capabilities_for_fuzzer",
    "parse_afl_stats_file",
    "parse_afl_stats_text",
    "DEFAULT_SAMPLE_INTERVAL_SECONDS",
    "DEFAULT_HISTORY_CAPACITY",
    "DEFAULT_SOURCE_TIMEOUT_SECONDS",
    "AFL_STATS_FILENAME",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Default interval between samples, in seconds. One second is a
#: reasonable default: fine-grained enough that a GUI update feels
#: live, coarse enough that reading a fuzzer's status file is not a
#: measurable load on the machine.
DEFAULT_SAMPLE_INTERVAL_SECONDS: float = 1.0

#: Default number of samples retained in the history ring buffer.
#: At the default sample interval this is one hour of history, which
#: is a good balance between memory and usefulness for typical
#: campaigns.
DEFAULT_HISTORY_CAPACITY: int = 3600

#: How long, in seconds, a single source's ``sample()`` call is
#: permitted to block before the collector gives up on it. Sources
#: are expected to be fast; a slow source is a bug, not a feature.
DEFAULT_SOURCE_TIMEOUT_SECONDS: float = 2.0

#: Filename used by AFL++ for its per-instance statistics file. The
#: file lives inside the AFL++ output directory, next to the queue
#: and crashes directories.
AFL_STATS_FILENAME: str = "fuzzer_stats"

#: Capability table: for each fuzzer identifier, the set of metrics
#: that the fuzzer can, in principle, publish. A metric that is not
#: in the set will be reported as ``None`` even if a source happens to
#: supply it, because we have no confidence the value is meaningful.
FUZZER_CAPABILITIES: Mapping[str, FrozenSet["MetricCapability"]] = {}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TelemetryError(KMCSException):
    """Base class for all telemetry errors."""


class TelemetrySourceError(TelemetryError):
    """Raised by a source when it cannot produce a sample.

    The collector treats this exception as a signal to skip the source
    for the current poll; it does not propagate to the caller.
    """


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class MetricCapability(str, Enum):
    """Enumerates every metric a fuzzer may publish.

    A capability is a promise that the metric is meaningful for a
    fuzzer. Capabilities are used by the collector to decide whether
    a missing value should be reported as ``None`` (unknown) or
    omitted entirely.
    """

    EXECUTIONS = "executions"
    EXEC_RATE = "exec_rate"
    CRASHES = "crashes"
    HANGS = "hangs"
    COVERAGE_PERCENT = "coverage_percent"
    COVERAGE_EDGES = "coverage_edges"
    CORPUS_SIZE = "corpus_size"
    CORPUS_PENDING = "corpus_pending"
    CYCLES_DONE = "cycles_done"
    STABILITY = "stability"
    EXEC_TIMEOUT = "exec_timeout"
    LAST_FIND = "last_find"
    LAST_CRASH = "last_crash"
    PEAK_RSS = "peak_rss"


class TelemetryState(str, Enum):
    """Lifecycle state of a telemetry collector."""

    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"

    @property
    def is_collecting(self) -> bool:
        return self is TelemetryState.RUNNING

    @property
    def is_terminal(self) -> bool:
        return self is TelemetryState.STOPPED


# ---------------------------------------------------------------------------
# Capability table
# ---------------------------------------------------------------------------

# Populated after the enum definition so the enum members are
# available for reference.
FUZZER_CAPABILITIES = {
    "aflpp": frozenset(
        {
            MetricCapability.EXECUTIONS,
            MetricCapability.EXEC_RATE,
            MetricCapability.CRASHES,
            MetricCapability.HANGS,
            MetricCapability.COVERAGE_PERCENT,
            MetricCapability.COVERAGE_EDGES,
            MetricCapability.CORPUS_SIZE,
            MetricCapability.CORPUS_PENDING,
            MetricCapability.CYCLES_DONE,
            MetricCapability.STABILITY,
            MetricCapability.EXEC_TIMEOUT,
            MetricCapability.LAST_FIND,
            MetricCapability.LAST_CRASH,
            MetricCapability.PEAK_RSS,
        }
    ),
    "afl": frozenset(
        {
            MetricCapability.EXECUTIONS,
            MetricCapability.EXEC_RATE,
            MetricCapability.CRASHES,
            MetricCapability.HANGS,
            MetricCapability.COVERAGE_PERCENT,
            MetricCapability.CORPUS_SIZE,
            MetricCapability.CORPUS_PENDING,
            MetricCapability.CYCLES_DONE,
            MetricCapability.STABILITY,
            MetricCapability.EXEC_TIMEOUT,
            MetricCapability.LAST_FIND,
            MetricCapability.LAST_CRASH,
        }
    ),
    "libfuzzer": frozenset(
        {
            MetricCapability.EXECUTIONS,
            MetricCapability.EXEC_RATE,
            MetricCapability.CRASHES,
            MetricCapability.COVERAGE_EDGES,
            MetricCapability.CORPUS_SIZE,
            MetricCapability.PEAK_RSS,
        }
    ),
    "honggfuzz": frozenset(
        {
            MetricCapability.EXECUTIONS,
            MetricCapability.CRASHES,
            MetricCapability.HANGS,
            MetricCapability.COVERAGE_PERCENT,
        }
    ),
}

#: Capabilities assigned to fuzzers not listed above. Conservative:
#: only the metrics that any well-behaved fuzzer is expected to expose.
_DEFAULT_CAPABILITIES: FrozenSet[MetricCapability] = frozenset(
    {
        MetricCapability.EXECUTIONS,
        MetricCapability.CRASHES,
    }
)


def capabilities_for_fuzzer(fuzzer: str) -> FrozenSet[MetricCapability]:
    """Return the capability set for ``fuzzer``.

    Unknown fuzzers receive a conservative default set. Lookup is
    case-insensitive.
    """
    return FUZZER_CAPABILITIES.get(fuzzer.lower(), _DEFAULT_CAPABILITIES)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FuzzerMetrics:
    """A single, immutable snapshot of a fuzzer's metrics.

    Every field is optional. ``None`` means "not reported by this
    fuzzer", never "zero". Consumers that render these values must
    display unknown fields distinctly from zero-valued ones.

    Fields
    ------
    executions:
        Cumulative count of test cases executed by the fuzzer.
    exec_rate:
        Current executions per second, as reported by the fuzzer or
        derived from consecutive samples.
    crashes:
        Cumulative count of unique crashes discovered.
    hangs:
        Cumulative count of unique hangs discovered.
    coverage_percent:
        Coverage as a percentage of the fuzzer's tracking space, in
        ``[0.0, 100.0]``.
    coverage_edges:
        Absolute count of edges (or equivalent unit) covered.
    corpus_size:
        Number of inputs in the fuzzer's active corpus.
    corpus_pending:
        Number of corpus entries not yet processed.
    cycles_done:
        Number of complete passes through the corpus.
    stability_percent:
        Stability of the target, as a percentage, in
        ``[0.0, 100.0]``.
    exec_timeout_ms:
        Configured per-execution timeout, in milliseconds.
    last_find_at:
        When the most recent new corpus entry was discovered.
    last_crash_at:
        When the most recent crash was discovered.
    peak_rss_mb:
        Peak resident-set size observed by the fuzzer, in megabytes.
    """

    executions: Optional[int] = None
    exec_rate: Optional[float] = None
    crashes: Optional[int] = None
    hangs: Optional[int] = None
    coverage_percent: Optional[float] = None
    coverage_edges: Optional[int] = None
    corpus_size: Optional[int] = None
    corpus_pending: Optional[int] = None
    cycles_done: Optional[int] = None
    stability_percent: Optional[float] = None
    exec_timeout_ms: Optional[int] = None
    last_find_at: Optional[datetime] = None
    last_crash_at: Optional[datetime] = None
    peak_rss_mb: Optional[float] = None

    def is_empty(self) -> bool:
        """Return True if no metric is set."""
        for value in self.__dict__.values():
            if value is not None:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of these metrics."""
        return {
            "executions": self.executions,
            "exec_rate": self.exec_rate,
            "crashes": self.crashes,
            "hangs": self.hangs,
            "coverage_percent": self.coverage_percent,
            "coverage_edges": self.coverage_edges,
            "corpus_size": self.corpus_size,
            "corpus_pending": self.corpus_pending,
            "cycles_done": self.cycles_done,
            "stability_percent": self.stability_percent,
            "exec_timeout_ms": self.exec_timeout_ms,
            "last_find_at": (
                self.last_find_at.isoformat()
                if self.last_find_at is not None
                else None
            ),
            "last_crash_at": (
                self.last_crash_at.isoformat()
                if self.last_crash_at is not None
                else None
            ),
            "peak_rss_mb": self.peak_rss_mb,
        }

    @staticmethod
    def from_mapping(mapping: Mapping[str, Any]) -> "FuzzerMetrics":
        """Build metrics from a loose key/value mapping.

        Keys are matched case-insensitively and may use either snake
        case or the common variants emitted by fuzzer tools (for
        example ``execs_done`` for ``executions``, ``execs_per_sec``
        for ``exec_rate``). Missing or malformed values become
        ``None``; malformed values never raise.
        """
        getters: Dict[str, Tuple[str, ...]] = {
            "executions": (
                "executions", "execs_done", "total_execs", "iterations",
                "execs", "runs", "total_executions",
            ),
            "exec_rate": (
                "exec_rate", "execs_per_sec", "executions_per_second",
                "execs_per_second", "eps", "rate",
            ),
            "crashes": (
                "crashes", "saved_crashes", "unique_crashes", "crash_count",
                "total_crashes",
            ),
            "hangs": (
                "hangs", "saved_hangs", "unique_hangs", "hang_count",
                "total_hangs",
            ),
            "coverage_percent": (
                "coverage_percent", "bitmap_cvg", "coverage", "cov_pct",
                "coverage_pct",
            ),
            "coverage_edges": (
                "coverage_edges", "edges_found", "cov", "ft",
                "coverage_count",
            ),
            "corpus_size": (
                "corpus_size", "corpus_count", "queue_size", "corp",
                "corpus",
            ),
            "corpus_pending": (
                "corpus_pending", "pending_total", "pending",
            ),
            "cycles_done": (
                "cycles_done", "cycles", "queue_cycles",
            ),
            "stability_percent": (
                "stability_percent", "stability",
            ),
            "exec_timeout_ms": (
                "exec_timeout_ms", "exec_timeout", "timeout_ms",
            ),
            "peak_rss_mb": (
                "peak_rss_mb", "rss_mb", "max_rss_mb",
            ),
        }

        lowered: Dict[str, Any] = {k.lower(): v for k, v in mapping.items()}

        def _fetch(keys: Tuple[str, ...]) -> Any:
            for key in keys:
                if key in lowered:
                    return lowered[key]
            return None

        def _as_int(value: Any) -> Optional[int]:
            if value is None:
                return None
            try:
                return int(value)
            except (TypeError, ValueError):
                return None

        def _as_float(value: Any) -> Optional[float]:
            if value is None:
                return None
            try:
                return float(value)
            except (TypeError, ValueError):
                return None

        def _as_datetime(value: Any) -> Optional[datetime]:
            if value is None:
                return None
            if isinstance(value, datetime):
                return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            if isinstance(value, (int, float)):
                # Unix epoch seconds.
                try:
                    return datetime.fromtimestamp(float(value), tz=timezone.utc)
                except (OSError, ValueError, OverflowError):
                    return None
            if isinstance(value, str):
                # ISO 8601 or unix epoch string.
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    pass
                try:
                    return datetime.fromtimestamp(float(value), tz=timezone.utc)
                except (ValueError, OSError, OverflowError):
                    return None
            return None

        return FuzzerMetrics(
            executions=_as_int(_fetch(getters["executions"])),
            exec_rate=_as_float(_fetch(getters["exec_rate"])),
            crashes=_as_int(_fetch(getters["crashes"])),
            hangs=_as_int(_fetch(getters["hangs"])),
            coverage_percent=_as_float(_fetch(getters["coverage_percent"])),
            coverage_edges=_as_int(_fetch(getters["coverage_edges"])),
            corpus_size=_as_int(_fetch(getters["corpus_size"])),
            corpus_pending=_as_int(_fetch(getters["corpus_pending"])),
            cycles_done=_as_int(_fetch(getters["cycles_done"])),
            stability_percent=_as_float(_fetch(getters["stability_percent"])),
            exec_timeout_ms=_as_int(_fetch(getters["exec_timeout_ms"])),
            peak_rss_mb=_as_float(_fetch(getters["peak_rss_mb"])),
            last_find_at=_as_datetime(lowered.get("last_find")),
            last_crash_at=_as_datetime(lowered.get("last_crash")),
        )


@dataclass(frozen=True)
class WorkerSnapshot:
    """A per-worker snapshot taken during a single poll."""

    worker_id: str
    worker_index: int
    alive: bool
    pid: Optional[int]
    state: str
    metrics: FuzzerMetrics
    source_ids: Tuple[str, ...] = ()
    sampled_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    errors: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "worker_index": self.worker_index,
            "alive": self.alive,
            "pid": self.pid,
            "state": self.state,
            "metrics": self.metrics.to_dict(),
            "source_ids": list(self.source_ids),
            "sampled_at": self.sampled_at.isoformat(),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class TelemetryAggregate:
    """Aggregated metrics across all workers in a snapshot.

    Semantics per field:

    * Cumulative counters (executions, crashes, hangs, cycles) are
      summed across workers, because each worker reports its own
      cumulative count and the campaign total is their sum.
    * Peak or max-like values (coverage_percent, coverage_edges,
      peak_rss_mb) take the maximum across workers, because two
      workers do not add coverage — they converge on the same total.
    * Rates are summed, because each worker's rate contributes to
      the campaign's overall throughput.
    * Timestamps are the most recent across workers.
    """

    total_executions: Optional[int] = None
    total_crashes: Optional[int] = None
    total_hangs: Optional[int] = None
    current_exec_rate: Optional[float] = None
    max_coverage_percent: Optional[float] = None
    max_coverage_edges: Optional[int] = None
    total_corpus_size: Optional[int] = None
    total_corpus_pending: Optional[int] = None
    total_cycles: Optional[int] = None
    min_stability_percent: Optional[float] = None
    peak_rss_mb: Optional[float] = None
    last_find_at: Optional[datetime] = None
    last_crash_at: Optional[datetime] = None
    worker_count: int = 0
    alive_worker_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_executions": self.total_executions,
            "total_crashes": self.total_crashes,
            "total_hangs": self.total_hangs,
            "current_exec_rate": self.current_exec_rate,
            "max_coverage_percent": self.max_coverage_percent,
            "max_coverage_edges": self.max_coverage_edges,
            "total_corpus_size": self.total_corpus_size,
            "total_corpus_pending": self.total_corpus_pending,
            "total_cycles": self.total_cycles,
            "min_stability_percent": self.min_stability_percent,
            "peak_rss_mb": self.peak_rss_mb,
            "last_find_at": (
                self.last_find_at.isoformat()
                if self.last_find_at is not None
                else None
            ),
            "last_crash_at": (
                self.last_crash_at.isoformat()
                if self.last_crash_at is not None
                else None
            ),
            "worker_count": self.worker_count,
            "alive_worker_count": self.alive_worker_count,
        }


@dataclass(frozen=True)
class CampaignSnapshot:
    """A complete snapshot of a campaign at a moment in time."""

    campaign_id: str
    campaign_name: str
    fuzzer: str
    state: str
    sampled_at: datetime
    runtime_seconds: float
    workers: Tuple[WorkerSnapshot, ...] = ()
    aggregate: TelemetryAggregate = field(default_factory=TelemetryAggregate)
    capabilities: FrozenSet[MetricCapability] = field(default_factory=frozenset)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "fuzzer": self.fuzzer,
            "state": self.state,
            "sampled_at": self.sampled_at.isoformat(),
            "runtime_seconds": self.runtime_seconds,
            "workers": [w.to_dict() for w in self.workers],
            "aggregate": self.aggregate.to_dict(),
            "capabilities": sorted(c.value for c in self.capabilities),
        }


@dataclass(frozen=True)
class TelemetrySample:
    """A single recorded sample in the telemetry history."""

    timestamp: datetime
    snapshot: CampaignSnapshot

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "snapshot": self.snapshot.to_dict(),
        }


@dataclass
class TelemetryStats:
    """Internal statistics describing the telemetry collector itself."""

    samples_collected: int = 0
    source_errors: int = 0
    last_sample_at: Optional[datetime] = None
    average_sample_duration_seconds: float = 0.0
    uptime_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "samples_collected": self.samples_collected,
            "source_errors": self.source_errors,
            "last_sample_at": (
                self.last_sample_at.isoformat()
                if self.last_sample_at is not None
                else None
            ),
            "average_sample_duration_seconds": self.average_sample_duration_seconds,
            "uptime_seconds": self.uptime_seconds,
        }


# ---------------------------------------------------------------------------
# AFL++ fuzzer_stats parsing
# ---------------------------------------------------------------------------


def parse_afl_stats_text(text: str) -> Dict[str, Any]:
    """Parse the contents of an AFL++ ``fuzzer_stats`` file.

    The file format is a sequence of ``key : value`` lines. Values
    may carry units such as ``%`` or ``Mb``; those are stripped before
    the value is coerced to an int or float. Unknown keys are passed
    through unchanged so that later versions of AFL++ can be supported
    without code changes.

    Parameters
    ----------
    text:
        Raw file contents.

    Returns
    -------
    dict
        A mapping of key to coerced value. Malformed lines are skipped
        silently — the parser never raises on unexpected input, because
        AFL++ occasionally writes partial lines while a run is in
        progress.
    """
    result: Dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        result[key] = _coerce_afl_value(value)
    return result


def _coerce_afl_value(value: str) -> Any:
    """Coerce an AFL++ stats file value to an int, float, or string."""
    # Strip common unit suffixes.
    stripped = value.rstrip("%").rstrip("b").rstrip("B").strip()
    # Try integer first.
    try:
        return int(stripped)
    except ValueError:
        pass
    # Then float.
    try:
        return float(stripped)
    except ValueError:
        pass
    # Fall back to string.
    return value


def parse_afl_stats_file(path: Union[str, os.PathLike[str]]) -> Dict[str, Any]:
    """Read and parse an AFL++ ``fuzzer_stats`` file.

    Returns an empty mapping if the file is missing, unreadable, or
    empty. Never raises: a missing stats file is a normal transient
    state while a fuzzer starts up.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except (FileNotFoundError, PermissionError):
        return {}
    except OSError as exc:
        logger.debug("failed to read AFL stats file %s: %s", path, exc)
        return {}
    return parse_afl_stats_text(text)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


class TelemetrySource:
    """Abstract base class for a telemetry source.

    A source produces a mapping of loose key/value pairs on demand.
    The collector coerces the mapping into a :class:`FuzzerMetrics`
    using the same tolerant rules that :meth:`FuzzerMetrics.from_mapping`
    uses. Subclasses should override :meth:`sample` and set
    :attr:`source_id`.
    """

    #: A short, stable identifier for the source. Used as a registry
    #: key and in diagnostic output.
    source_id: str = "unnamed"

    def sample(self) -> Optional[Mapping[str, Any]]:
        """Return a mapping of raw metrics, or None if unavailable.

        Returning None signals "this source has no data right now",
        which is not an error. Raising :class:`TelemetrySourceError`
        signals the same but is recorded in the collector's error
        counters.
        """
        raise NotImplementedError

    def describe(self) -> Mapping[str, Any]:
        """Return a description of this source for diagnostics."""
        return {"source_id": self.source_id, "kind": type(self).__name__}

    def close(self) -> None:
        """Release any resources held by the source. Default: no-op."""
        return None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(source_id={self.source_id!r})"


class WorkerSource(TelemetrySource):
    """A telemetry source that wraps a :class:`CampaignWorker`.

    The source calls ``worker.stats()`` and ``worker.is_alive()`` on
    every sample. It also carries through the worker's ``state`` and
    ``pid`` so that the telemetry snapshot reflects process health in
    addition to fuzzer metrics.

    The wrapper never raises on a missing or misbehaving worker; it
    returns None (no data) and records the failure internally.
    """

    def __init__(self, worker: Any, *, source_id: Optional[str] = None) -> None:
        self._worker = worker
        self.source_id = source_id or f"worker:{getattr(worker, 'id', 'unknown')}"
        self._last_error: Optional[str] = None

    @property
    def worker(self) -> Any:
        return self._worker

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    def sample(self) -> Optional[Mapping[str, Any]]:
        stats_getter = getattr(self._worker, "stats", None)
        if not callable(stats_getter):
            self._last_error = "worker has no stats() method"
            return None
        try:
            stats = stats_getter()
        except Exception as exc:  # noqa: BLE001 - worker is untrusted
            self._last_error = f"worker.stats() raised: {exc}"
            return None
        if not isinstance(stats, Mapping):
            self._last_error = f"worker.stats() returned {type(stats).__name__}"
            return None

        # Enrich with process-level fields that stats() may not
        # include. We prefer the worker's own values when present.
        result: Dict[str, Any] = dict(stats)

        alive_getter = getattr(self._worker, "is_alive", None)
        if callable(alive_getter):
            try:
                result.setdefault("alive", bool(alive_getter()))
            except Exception:  # noqa: BLE001
                pass

        pid = getattr(self._worker, "pid", None)
        if pid is not None:
            result.setdefault("pid", pid)

        state = getattr(self._worker, "state", None)
        if state is not None:
            # state is a WorkerState enum; use its value.
            value = getattr(state, "value", state)
            result.setdefault("state", str(value))

        self._last_error = None
        return result

    def describe(self) -> Mapping[str, Any]:
        base = super().describe()
        base.update(
            {
                "worker_id": getattr(self._worker, "id", None),
                "worker_index": getattr(self._worker, "index", None),
                "pid": getattr(self._worker, "pid", None),
            }
        )
        return base


class AflStatsFileSource(TelemetrySource):
    """A telemetry source that reads an AFL++ ``fuzzer_stats`` file.

    This source is preferred over the worker's line parser when an
    AFL++ stats file is present, because the stats file contains more
    metrics (stability, bitmap coverage, peak_rss_mb) than the fuzzer
    emits on stdout.
    """

    def __init__(
        self,
        path: Union[str, os.PathLike[str]],
        *,
        source_id: Optional[str] = None,
    ) -> None:
        self._path = Path(path)
        self.source_id = source_id or f"afl-stats:{self._path}"
        self._last_error: Optional[str] = None
        self._last_mtime: float = 0.0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    def sample(self) -> Optional[Mapping[str, Any]]:
        try:
            st = self._path.stat()
        except FileNotFoundError:
            # Not yet written; not an error.
            self._last_error = None
            return None
        except OSError as exc:
            self._last_error = f"stat failed: {exc}"
            return None

        if st.st_mtime == self._last_mtime:
            # File has not changed since the last sample; return the
            # cached parse to avoid unnecessary I/O.
            cached = getattr(self, "_cached", None)
            if cached is not None:
                return cached

        data = parse_afl_stats_file(self._path)
        if not data:
            self._last_error = None
            return None

        self._last_mtime = st.st_mtime
        self._cached = data
        self._last_error = None
        return data

    def describe(self) -> Mapping[str, Any]:
        base = super().describe()
        base.update({"path": str(self._path)})
        return base


class JsonFileSource(TelemetrySource):
    """A telemetry source that reads a JSON file with a flat layout.

    Intended for fuzzers that KMCS does not ship a dedicated adapter
    for but that can be instrumented to periodically write a small
    status file. The file must be a JSON object whose values are
    scalars or ISO-8601 strings.
    """

    def __init__(
        self,
        path: Union[str, os.PathLike[str]],
        *,
        source_id: Optional[str] = None,
    ) -> None:
        self._path = Path(path)
        self.source_id = source_id or f"json:{self._path}"
        self._last_error: Optional[str] = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    def sample(self) -> Optional[Mapping[str, Any]]:
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except FileNotFoundError:
            self._last_error = None
            return None
        except json.JSONDecodeError as exc:
            self._last_error = f"invalid JSON: {exc}"
            return None
        except OSError as exc:
            self._last_error = f"read failed: {exc}"
            return None
        if not isinstance(payload, Mapping):
            self._last_error = (
                f"JSON root is {type(payload).__name__}, expected object"
            )
            return None
        self._last_error = None
        return payload


# ---------------------------------------------------------------------------
# Rate estimator
# ---------------------------------------------------------------------------


class _RateEstimator:
    """Derives executions-per-second from consecutive cumulative samples.

    The estimator keeps a short window of recent (timestamp, count)
    observations and returns the slope across that window. The window
    is bounded to avoid a growing memory footprint, and observations
    older than ``max_age_seconds`` are evicted before each computation.
    """

    def __init__(self, *, window: int = 8, max_age_seconds: float = 10.0) -> None:
        if window < 2:
            raise ValueError("window must be at least 2")
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be positive")
        self._samples: Deque[Tuple[float, int]] = deque(maxlen=window)
        self._max_age = float(max_age_seconds)

    def observe(self, timestamp: float, count: int) -> Optional[float]:
        """Record an observation and return the current rate.

        Returns
        -------
        float or None
            Executions per second over the retained window, or None
            if fewer than two observations are available or if the
            observed delta is non-positive.
        """
        # Drop stale samples before adding the new one.
        cutoff = timestamp - self._max_age
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()
        self._samples.append((timestamp, int(count)))
        if len(self._samples) < 2:
            return None
        t0, c0 = self._samples[0]
        t1, c1 = self._samples[-1]
        dt = t1 - t0
        if dt <= 0:
            return None
        delta = c1 - c0
        if delta < 0:
            # Counter reset (worker restarted). Drop the window.
            self._samples.clear()
            self._samples.append((t1, c1))
            return None
        return delta / dt

    def reset(self) -> None:
        self._samples.clear()


# ---------------------------------------------------------------------------
# CampaignTelemetry
# ---------------------------------------------------------------------------


class CampaignTelemetry:
    """Real-time telemetry collector for a single campaign.

    Parameters
    ----------
    campaign:
        The campaign being observed. Only its identity and
        configuration are read; the collector never mutates it.
    event_bus:
        Optional event bus for publishing telemetry updates. When
        omitted, the process-wide default bus is used.
    config:
        Optional :class:`~kmcs.core.config.KmcsConfig`.
    sample_interval:
        Seconds between automatic samples. Ignored if
        ``auto_sample=False``.
    history_capacity:
        Number of samples retained in the ring buffer. At the default
        interval this is the number of seconds of history retained.
    auto_sample:
        When True (default), the collector runs a background thread
        that samples on the configured interval. When False, the
        caller must invoke :meth:`poll` to advance the collector.
    source_timeout:
        Upper bound, in seconds, on how long a single source may
        block. Sources are expected to be fast; a stuck source is
        skipped for the current poll and recorded as an error.
    """

    def __init__(
        self,
        campaign: "Campaign",
        *,
        event_bus: Optional[EventBus] = None,
        config: Optional[KmcsConfig] = None,
        sample_interval: float = DEFAULT_SAMPLE_INTERVAL_SECONDS,
        history_capacity: int = DEFAULT_HISTORY_CAPACITY,
        auto_sample: bool = True,
        source_timeout: float = DEFAULT_SOURCE_TIMEOUT_SECONDS,
    ) -> None:
        if sample_interval <= 0:
            raise ValueError("sample_interval must be positive")
        if history_capacity <= 0:
            raise ValueError("history_capacity must be positive")
        if source_timeout <= 0:
            raise ValueError("source_timeout must be positive")

        self._campaign = campaign
        self._bus = event_bus or get_default_bus()
        self._config = config or get_config()
        self._sample_interval = float(sample_interval)
        self._history_capacity = int(history_capacity)
        self._auto_sample = bool(auto_sample)
        self._source_timeout = float(source_timeout)

        # Fuzzer capabilities: derived from the campaign's config.
        try:
            fuzzer = str(campaign.config.fuzzer).lower()
        except AttributeError:
            fuzzer = "unknown"
        self._fuzzer = fuzzer
        self._capabilities = capabilities_for_fuzzer(fuzzer)

        self._lock = threading.RLock()
        self._state = TelemetryState.IDLE
        self._sources: Dict[str, TelemetrySource] = {}
        self._worker_sources: Dict[str, WorkerSource] = {}
        self._rate_estimators: Dict[str, _RateEstimator] = {}
        self._history: Deque[TelemetrySample] = deque(maxlen=self._history_capacity)
        self._latest: Optional[CampaignSnapshot] = None
        self._stats = TelemetryStats()
        self._sample_durations: Deque[float] = deque(maxlen=64)
        self._started_at_monotonic: Optional[float] = None
        self._stop_event = threading.Event()
        self._sample_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def campaign_id(self) -> str:
        return getattr(self._campaign, "campaign_id", "unknown")

    @property
    def campaign_name(self) -> str:
        config = getattr(self._campaign, "config", None)
        return getattr(config, "name", "unknown")

    @property
    def fuzzer(self) -> str:
        return self._fuzzer

    @property
    def capabilities(self) -> FrozenSet[MetricCapability]:
        return self._capabilities

    @property
    def state(self) -> TelemetryState:
        with self._lock:
            return self._state

    @property
    def history_capacity(self) -> int:
        return self._history_capacity

    @property
    def sample_interval(self) -> float:
        return self._sample_interval

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
                source="campaigns.telemetry",
                data={"event": event_name, **payload},
            )
            publish_event(self._bus, event)
        except Exception as exc:  # noqa: BLE001
            logger.debug("telemetry event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Source management
    # ------------------------------------------------------------------

    def attach_source(self, source: TelemetrySource) -> None:
        """Register a telemetry source.

        Replaces any existing source with the same ``source_id``. The
        source is not sampled until the next poll.
        """
        if not isinstance(source, TelemetrySource):
            raise TypeError(
                f"source must be a TelemetrySource, got {type(source).__name__}"
            )
        with self._lock:
            existing = self._sources.get(source.source_id)
            if existing is not None and existing is not source:
                try:
                    existing.close()
                except Exception as exc:  # noqa: BLE001
                    logger.debug("failed to close replaced source: %s", exc)
            self._sources[source.source_id] = source
        self._emit(
            "TELEMETRY_SOURCE_ATTACHED",
            {"source_id": source.source_id, "kind": type(source).__name__},
        )

    def detach_source(self, source_id: str) -> bool:
        """Remove a source by ID. Returns True if a source was removed."""
        with self._lock:
            source = self._sources.pop(source_id, None)
        if source is None:
            return False
        try:
            source.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("failed to close detached source: %s", exc)
        self._emit(
            "TELEMETRY_SOURCE_DETACHED",
            {"source_id": source_id},
        )
        return True

    def attach_worker(self, worker: Any) -> WorkerSource:
        """Attach a :class:`~kmcs.campaigns.worker.CampaignWorker`.

        Convenience wrapper that constructs a :class:`WorkerSource` and
        registers it. If a source for the same worker is already
        attached, the old source is replaced.
        """
        worker_id = getattr(worker, "id", None) or f"worker:{id(worker)}"
        source = WorkerSource(worker, source_id=f"worker:{worker_id}")
        with self._lock:
            self._worker_sources[worker_id] = source
        self.attach_source(source)
        return source

    def detach_worker(self, worker_id: str) -> bool:
        """Detach a worker source by worker ID."""
        with self._lock:
            source = self._worker_sources.pop(worker_id, None)
        if source is None:
            return False
        return self.detach_source(source.source_id)

    def list_sources(self) -> List[Mapping[str, Any]]:
        """Return a description of every registered source."""
        with self._lock:
            sources = list(self._sources.values())
        return [s.describe() for s in sources]

    # ------------------------------------------------------------------
    # Discovery helpers
    # ------------------------------------------------------------------

    def discover_afl_stats_files(self) -> List[Path]:
        """Return AFL++ stats files found under the campaign output dir.

        The search walks ``<output_dir>/<campaign_id>/worker-*/afl_out``
        and looks for ``*/fuzzer_stats`` at the top level of each
        secondary instance directory, plus the ``fuzzer_stats`` file
        written by the main instance.
        """
        campaign_dir = getattr(self._campaign, "output_dir", None)
        if campaign_dir is None:
            return []
        root = Path(campaign_dir)
        if not root.exists():
            return []
        found: List[Path] = []
        # Main instance writes to afl_out/fuzzer_stats; secondaries
        # write to afl_out/<instance>/fuzzer_stats.
        for worker_dir in sorted(root.glob("worker-*")):
            afl_dir = worker_dir / "afl_out"
            if not afl_dir.is_dir():
                continue
            main_stats = afl_dir / AFL_STATS_FILENAME
            if main_stats.is_file():
                found.append(main_stats)
            for sub in sorted(afl_dir.iterdir()):
                if not sub.is_dir():
                    continue
                candidate = sub / AFL_STATS_FILENAME
                if candidate.is_file():
                    found.append(candidate)
        return found

    def autodiscover_afl_sources(self) -> int:
        """Discover and attach every AFL++ stats file for the campaign.

        Returns the number of sources attached. Safe to call
        repeatedly; re-attaching a source with the same ID replaces
        the old one.
        """
        count = 0
        for path in self.discover_afl_stats_files():
            source = AflStatsFileSource(path)
            self.attach_source(source)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Sampling
    # ------------------------------------------------------------------

    def _sample_sources(self) -> Tuple[List[WorkerSnapshot], List[str]]:
        """Sample every registered source and build worker snapshots.

        Returns
        -------
        tuple
            ``(worker_snapshots, errors)``. Errors is a list of
            human-readable messages for sources that failed.
        """
        with self._lock:
            sources = list(self._sources.values())
            worker_sources = dict(self._worker_sources)

        errors: List[str] = []
        # Bucket sources: worker sources grouped by worker_id; other
        # sources kept separate and merged into the aggregate only.
        per_worker_metrics: Dict[str, FuzzerMetrics] = {}
        per_worker_sources: Dict[str, List[str]] = {}
        per_worker_errors: Dict[str, List[str]] = {}
        extra_metrics: List[FuzzerMetrics] = []

        for source in sources:
            deadline = time.monotonic() + self._source_timeout
            try:
                raw = source.sample()
            except TelemetrySourceError as exc:
                msg = f"{source.source_id}: {exc}"
                errors.append(msg)
                continue
            except Exception as exc:  # noqa: BLE001 - sources are untrusted
                msg = f"{source.source_id}: sample() raised {type(exc).__name__}: {exc}"
                errors.append(msg)
                continue
            if raw is None:
                continue
            if time.monotonic() > deadline:
                errors.append(f"{source.source_id}: sample() exceeded timeout")
                continue

            metrics = FuzzerMetrics.from_mapping(raw)

            # Prefer the source's own reported rate; if absent, we
            # leave the field as None and compute a rate later from
            # consecutive samples of the same source.
            reported_rate = metrics.exec_rate
            if reported_rate is None and metrics.executions is not None:
                rate = self._update_rate(source.source_id, metrics.executions)
                if rate is not None:
                    metrics = FuzzerMetrics(
                        executions=metrics.executions,
                        exec_rate=rate,
                        crashes=metrics.crashes,
                        hangs=metrics.hangs,
                        coverage_percent=metrics.coverage_percent,
                        coverage_edges=metrics.coverage_edges,
                        corpus_size=metrics.corpus_size,
                        corpus_pending=metrics.corpus_pending,
                        cycles_done=metrics.cycles_done,
                        stability_percent=metrics.stability_percent,
                        exec_timeout_ms=metrics.exec_timeout_ms,
                        last_find_at=metrics.last_find_at,
                        last_crash_at=metrics.last_crash_at,
                        peak_rss_mb=metrics.peak_rss_mb,
                    )

            if source.source_id in {s.source_id for s in worker_sources.values()}:
                # Find the worker_id for this source.
                worker_id = None
                for wid, wsrc in worker_sources.items():
                    if wsrc.source_id == source.source_id:
                        worker_id = wid
                        break
                if worker_id is not None:
                    merged = _merge_metrics(
                        per_worker_metrics.get(worker_id), metrics
                    )
                    per_worker_metrics[worker_id] = merged
                    per_worker_sources.setdefault(worker_id, []).append(
                        source.source_id
                    )
            else:
                extra_metrics.append(metrics)

        # Build per-worker snapshots.
        now = datetime.now(timezone.utc)
        snapshots: List[WorkerSnapshot] = []
        for worker_id, source in worker_sources.items():
            worker = source.worker
            alive = _safe_bool(getattr(worker, "is_alive", None))
            pid = getattr(worker, "pid", None)
            state_obj = getattr(worker, "state", None)
            state_str = str(getattr(state_obj, "value", state_obj or "unknown"))
            index = getattr(worker, "index", 0)
            try:
                index = int(index)
            except (TypeError, ValueError):
                index = 0
            snapshots.append(
                WorkerSnapshot(
                    worker_id=worker_id,
                    worker_index=index,
                    alive=bool(alive),
                    pid=pid if isinstance(pid, int) else None,
                    state=state_str,
                    metrics=per_worker_metrics.get(worker_id, FuzzerMetrics()),
                    source_ids=tuple(per_worker_sources.get(worker_id, ())),
                    sampled_at=now,
                    errors=tuple(per_worker_errors.get(worker_id, ())),
                )
            )

        # Sources that are neither worker sources nor matched to a
        # worker contribute only to the aggregate. We merge them into a
        # synthetic worker snapshot so the aggregate sees them.
        if extra_metrics:
            aggregate_extra = FuzzerMetrics()
            for m in extra_metrics:
                aggregate_extra = _merge_metrics(aggregate_extra, m)
            snapshots.append(
                WorkerSnapshot(
                    worker_id="__external__",
                    worker_index=-1,
                    alive=True,
                    pid=None,
                    state="external",
                    metrics=aggregate_extra,
                    source_ids=tuple(s.source_id for s in sources
                                     if s.source_id not in {
                                         ws.source_id
                                         for ws in worker_sources.values()
                                     }),
                    sampled_at=now,
                    errors=(),
                )
            )

        return snapshots, errors

    def _update_rate(self, source_id: str, executions: int) -> Optional[float]:
        """Update the rate estimator for ``source_id`` and return the rate."""
        with self._lock:
            estimator = self._rate_estimators.get(source_id)
            if estimator is None:
                estimator = _RateEstimator()
                self._rate_estimators[source_id] = estimator
        return estimator.observe(time.monotonic(), executions)

    def poll(self) -> CampaignSnapshot:
        """Take a fresh sample and return the resulting snapshot.

        This method is safe to call from any thread. It acquires a
        short-lived lock for the duration of the sample, and never
        calls any user-supplied callback while holding it.
        """
        start = time.monotonic()

        worker_snapshots, errors = self._sample_sources()

        aggregate = _aggregate_worker_snapshots(worker_snapshots)

        runtime_seconds = 0.0
        campaign_state = "unknown"
        try:
            runtime_seconds = float(getattr(self._campaign, "runtime_seconds", 0.0))
        except Exception:  # noqa: BLE001
            pass
        try:
            state_obj = getattr(self._campaign, "state", None)
            campaign_state = str(getattr(state_obj, "value", state_obj or "unknown"))
        except Exception:  # noqa: BLE001
            pass

        now = datetime.now(timezone.utc)
        snapshot = CampaignSnapshot(
            campaign_id=self.campaign_id,
            campaign_name=self.campaign_name,
            fuzzer=self._fuzzer,
            state=campaign_state,
            sampled_at=now,
            runtime_seconds=runtime_seconds,
            workers=tuple(worker_snapshots),
            aggregate=aggregate,
            capabilities=self._capabilities,
        )

        sample = TelemetrySample(timestamp=now, snapshot=snapshot)

        duration = time.monotonic() - start

        with self._lock:
            self._latest = snapshot
            self._history.append(sample)
            self._stats.samples_collected += 1
            self._stats.last_sample_at = now
            self._stats.source_errors += len(errors)
            self._sample_durations.append(duration)
            if self._sample_durations:
                self._stats.average_sample_duration_seconds = (
                    sum(self._sample_durations) / len(self._sample_durations)
                )
            if self._started_at_monotonic is not None:
                self._stats.uptime_seconds = (
                    time.monotonic() - self._started_at_monotonic
                )

        self._emit(
            "TELEMETRY_SAMPLED",
            {
                "campaign_id": self.campaign_id,
                "executions": aggregate.total_executions,
                "crashes": aggregate.total_crashes,
                "alive_workers": aggregate.alive_worker_count,
                "worker_count": aggregate.worker_count,
                "duration_seconds": duration,
                "errors": errors,
            },
        )

        if errors:
            for err in errors:
                logger.debug("telemetry source error: %s", err)

        return snapshot

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start collecting telemetry.

        Idempotent: calling start on an already-running collector is a
        no-op. If ``auto_sample`` is True, the sampler thread is
        created and begins polling on the configured interval.
        """
        with self._lock:
            if self._state == TelemetryState.RUNNING:
                return
            self._state = TelemetryState.RUNNING
            if self._started_at_monotonic is None:
                self._started_at_monotonic = time.monotonic()
            if self._auto_sample and self._sample_thread is None:
                self._stop_event.clear()
                thread = threading.Thread(
                    target=self._sample_loop,
                    name=f"kmcs-telemetry-{self.campaign_id}",
                    daemon=True,
                )
                self._sample_thread = thread
                thread.start()

        # Immediate first sample so that consumers do not have to wait
        # for the first interval to elapse.
        try:
            self.poll()
        except Exception:
            logger.exception("initial telemetry poll failed")

        self._emit(
            "TELEMETRY_STARTED",
            {
                "campaign_id": self.campaign_id,
                "sample_interval": self._sample_interval,
                "auto_sample": self._auto_sample,
            },
        )

    def pause(self) -> None:
        """Pause automatic sampling.

        The sampler thread stays alive but stops issuing polls. The
        most recent snapshot remains available.
        """
        with self._lock:
            if self._state == TelemetryState.RUNNING:
                self._state = TelemetryState.PAUSED
                self._stop_event.set()
        self._emit("TELEMETRY_PAUSED", {"campaign_id": self.campaign_id})

    def resume(self) -> None:
        """Resume automatic sampling after :meth:`pause`."""
        with self._lock:
            if self._state == TelemetryState.PAUSED:
                self._state = TelemetryState.RUNNING
                self._stop_event.clear()
                if self._auto_sample and (
                    self._sample_thread is None
                    or not self._sample_thread.is_alive()
                ):
                    thread = threading.Thread(
                        target=self._sample_loop,
                        name=f"kmcs-telemetry-{self.campaign_id}",
                        daemon=True,
                    )
                    self._sample_thread = thread
                    thread.start()
        self._emit("TELEMETRY_RESUMED", {"campaign_id": self.campaign_id})

    def stop(self) -> None:
        """Stop collecting telemetry and release resources.

        Idempotent. After stop, the collector may not be restarted:
        create a fresh instance if a new collection is required.
        """
        with self._lock:
            if self._state == TelemetryState.STOPPED:
                return
            self._state = TelemetryState.STOPPED
            self._stop_event.set()
            thread = self._sample_thread
            self._sample_thread = None

        if thread is not None and thread.is_alive():
            thread.join(timeout=max(2.0, self._sample_interval * 2.0))

        # Close every source.
        with self._lock:
            sources = list(self._sources.values())
            self._sources.clear()
            self._worker_sources.clear()
        for source in sources:
            try:
                source.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("failed to close source %s: %s", source.source_id, exc)

        self._emit(
            "TELEMETRY_STOPPED",
            {
                "campaign_id": self.campaign_id,
                "samples_collected": self._stats.samples_collected,
            },
        )

    def _sample_loop(self) -> None:
        while True:
            # Wait for the interval or the stop signal.
            if self._stop_event.wait(self._sample_interval):
                return
            with self._lock:
                if self._state != TelemetryState.RUNNING:
                    # Paused; keep the thread alive but skip polls.
                    continue
            try:
                self.poll()
            except Exception:
                logger.exception("telemetry sample poll failed")

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def snapshot(self) -> Optional[CampaignSnapshot]:
        """Return the most recent snapshot, or None if never polled."""
        with self._lock:
            return self._latest

    def history(
        self,
        *,
        limit: Optional[int] = None,
        since: Optional[datetime] = None,
    ) -> List[TelemetrySample]:
        """Return recorded samples, oldest first.

        Parameters
        ----------
        limit:
            Optional maximum number of samples to return. When
            provided, the *most recent* samples are returned, but
            still in oldest-first order.
        since:
            Optional lower bound on sample timestamp. Samples strictly
            older than ``since`` are excluded.
        """
        with self._lock:
            samples = list(self._history)
        if since is not None:
            samples = [s for s in samples if s.timestamp >= since]
        if limit is not None:
            if limit <= 0:
                return []
            samples = samples[-limit:]
        return samples

    def aggregate(
        self, *, window_seconds: Optional[float] = None
    ) -> Optional[TelemetryAggregate]:
        """Return an aggregate over a time window.

        Parameters
        ----------
        window_seconds:
            Length of the window, in seconds, ending at the most
            recent sample. When None, the entire retained history is
            used.

        Returns
        -------
        TelemetryAggregate or None
            None if no samples have been recorded.
        """
        with self._lock:
            samples = list(self._history)
        if not samples:
            return None
        if window_seconds is not None and window_seconds > 0:
            latest = samples[-1].timestamp
            cutoff = latest.timestamp() - window_seconds
            samples = [
                s for s in samples
                if s.timestamp.timestamp() >= cutoff
            ]
        if not samples:
            return None
        # Use the most recent sample's worker set as the aggregate
        # input; earlier samples are used only for the "since" window.
        latest_snapshot = samples[-1].snapshot
        return latest_snapshot.aggregate

    def history_series(
        self,
        metric: str,
        *,
        limit: Optional[int] = None,
    ) -> List[Tuple[datetime, Optional[float]]]:
        """Return a time series for a single aggregate metric.

        Parameters
        ----------
        metric:
            Name of the aggregate metric to extract. Must be a field
            of :class:`TelemetryAggregate`.
        limit:
            Optional maximum number of points, most recent first.

        Returns
        -------
        list of (datetime, value)
            Points in chronological order. Values may be None if the
            metric was unavailable at that sample.

        Raises
        ------
        ValueError
            If ``metric`` is not a recognised field.
        """
        valid_fields = {
            "total_executions",
            "total_crashes",
            "total_hangs",
            "current_exec_rate",
            "max_coverage_percent",
            "max_coverage_edges",
            "total_corpus_size",
            "total_corpus_pending",
            "total_cycles",
            "min_stability_percent",
            "peak_rss_mb",
            "worker_count",
            "alive_worker_count",
        }
        if metric not in valid_fields:
            raise ValueError(
                f"unknown aggregate metric {metric!r}; "
                f"valid: {sorted(valid_fields)}"
            )
        with self._lock:
            samples = list(self._history)
        if limit is not None and limit > 0:
            samples = samples[-limit:]
        series: List[Tuple[datetime, Optional[float]]] = []
        for sample in samples:
            value = getattr(sample.snapshot.aggregate, metric, None)
            if value is not None:
                value = float(value)
            series.append((sample.timestamp, value))
        return series

    def stats(self) -> TelemetryStats:
        """Return a snapshot of the collector's own statistics."""
        with self._lock:
            stats = TelemetryStats(
                samples_collected=self._stats.samples_collected,
                source_errors=self._stats.source_errors,
                last_sample_at=self._stats.last_sample_at,
                average_sample_duration_seconds=self._stats.average_sample_duration_seconds,
                uptime_seconds=self._stats.uptime_seconds,
            )
        return stats

    def clear_history(self) -> None:
        """Discard the retained history. Does not affect sources."""
        with self._lock:
            self._history.clear()

    # ------------------------------------------------------------------
    # Context manager / cleanup
    # ------------------------------------------------------------------

    def __enter__(self) -> "CampaignTelemetry":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def __repr__(self) -> str:
        return (
            f"CampaignTelemetry(campaign_id={self.campaign_id!r}, "
            f"fuzzer={self._fuzzer!r}, "
            f"state={self.state.value}, "
            f"sources={len(self._sources)})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_bool(getter: Any) -> bool:
    """Call ``getter`` and coerce the result to bool, defaulting to False."""
    if not callable(getter):
        return False
    try:
        return bool(getter())
    except Exception:  # noqa: BLE001
        return False


def _merge_metrics(
    base: Optional[FuzzerMetrics], update: FuzzerMetrics
) -> FuzzerMetrics:
    """Merge two :class:`FuzzerMetrics`, summing cumulative fields.

    Cumulative counters (executions, crashes, hangs, cycles) are
    summed when both operands provide a value; when one operand is
    None, the other is used. Peak values (coverage, RSS) take the max.
    Timestamps take the later of the two.
    """
    if base is None:
        return update

    def _sum_opt(a: Optional[int], b: Optional[int]) -> Optional[int]:
        if a is None:
            return b
        if b is None:
            return a
        return a + b

    def _sum_rate(a: Optional[float], b: Optional[float]) -> Optional[float]:
        if a is None:
            return b
        if b is None:
            return a
        return a + b

    def _max_opt(
        a: Optional[Union[int, float]], b: Optional[Union[int, float]]
    ) -> Optional[Union[int, float]]:
        if a is None:
            return b
        if b is None:
            return a
        return max(a, b)

    def _max_dt(a: Optional[datetime], b: Optional[datetime]) -> Optional[datetime]:
        if a is None:
            return b
        if b is None:
            return a
        return max(a, b)

    return FuzzerMetrics(
        executions=_sum_opt(base.executions, update.executions),
        exec_rate=_sum_rate(base.exec_rate, update.exec_rate),
        crashes=_sum_opt(base.crashes, update.crashes),
        hangs=_sum_opt(base.hangs, update.hangs),
        coverage_percent=_max_opt(
            base.coverage_percent, update.coverage_percent
        ),
        coverage_edges=_max_opt(base.coverage_edges, update.coverage_edges),
        corpus_size=_sum_opt(base.corpus_size, update.corpus_size),
        corpus_pending=_sum_opt(base.corpus_pending, update.corpus_pending),
        cycles_done=_sum_opt(base.cycles_done, update.cycles_done),
        stability_percent=_max_opt(
            base.stability_percent, update.stability_percent
        ),
        exec_timeout_ms=_max_opt(base.exec_timeout_ms, update.exec_timeout_ms),
        last_find_at=_max_dt(base.last_find_at, update.last_find_at),
        last_crash_at=_max_dt(base.last_crash_at, update.last_crash_at),
        peak_rss_mb=_max_opt(base.peak_rss_mb, update.peak_rss_mb),
    )


def _aggregate_worker_snapshots(
    snapshots: Sequence[WorkerSnapshot],
) -> TelemetryAggregate:
    """Aggregate a list of worker snapshots into a campaign total.

    Semantics:

    * Cumulative counters are summed across workers. A worker that
      reports no value for a counter contributes zero to the sum
      *only if at least one worker reported a value*; otherwise the
      aggregate field is None.
    * Peak values take the max.
    * Exec rates are summed.
    * Timestamps take the latest.
    """
    if not snapshots:
        return TelemetryAggregate()

    def _sum_opt(
        current: Optional[int], value: Optional[int], any_value: bool
    ) -> Tuple[Optional[int], bool]:
        if value is None:
            return current, any_value
        if current is None:
            return value, True
        return current + value, True

    executions: Optional[int] = None
    crashes: Optional[int] = None
    hangs: Optional[int] = None
    rate: Optional[float] = None
    cov_pct: Optional[float] = None
    cov_edges: Optional[int] = None
    corpus_size: Optional[int] = None
    corpus_pending: Optional[int] = None
    cycles: Optional[int] = None
    stability: Optional[float] = None
    rss: Optional[float] = None
    last_find: Optional[datetime] = None
    last_crash: Optional[datetime] = None
    any_exec = False
    any_crash = False
    any_hang = False
    any_rate = False
    alive_count = 0

    for snap in snapshots:
        m = snap.metrics
        executions, any_exec = _sum_opt(executions, m.executions, any_exec)
        crashes, any_crash = _sum_opt(crashes, m.crashes, any_crash)
        hangs, any_hang = _sum_opt(hangs, m.hangs, any_hang)
        if m.exec_rate is not None:
            rate = (rate or 0.0) + m.exec_rate
            any_rate = True
        if m.coverage_percent is not None:
            cov_pct = (
                m.coverage_percent
                if cov_pct is None
                else max(cov_pct, m.coverage_percent)
            )
        if m.coverage_edges is not None:
            cov_edges = (
                m.coverage_edges
                if cov_edges is None
                else max(cov_edges, m.coverage_edges)
            )
        if m.corpus_size is not None:
            corpus_size = (corpus_size or 0) + m.corpus_size
        if m.corpus_pending is not None:
            corpus_pending = (corpus_pending or 0) + m.corpus_pending
        if m.cycles_done is not None:
            cycles = (cycles or 0) + m.cycles_done
        if m.stability_percent is not None:
            stability = (
                m.stability_percent
                if stability is None
                else min(stability, m.stability_percent)
            )
        if m.peak_rss_mb is not None:
            rss = m.peak_rss_mb if rss is None else max(rss, m.peak_rss_mb)
        if m.last_find_at is not None:
            last_find = (
                m.last_find_at if last_find is None
                else max(last_find, m.last_find_at)
            )
        if m.last_crash_at is not None:
            last_crash = (
                m.last_crash_at if last_crash is None
                else max(last_crash, m.last_crash_at)
            )
        if snap.alive:
            alive_count += 1

    return TelemetryAggregate(
        total_executions=executions if any_exec else None,
        total_crashes=crashes if any_crash else None,
        total_hangs=hangs if any_hang else None,
        current_exec_rate=rate if any_rate else None,
        max_coverage_percent=cov_pct,
        max_coverage_edges=cov_edges,
        total_corpus_size=corpus_size,
        total_corpus_pending=corpus_pending,
        total_cycles=cycles,
        min_stability_percent=stability,
        peak_rss_mb=rss,
        last_find_at=last_find,
        last_crash_at=last_crash,
        worker_count=len(snapshots),
        alive_worker_count=alive_count,
    )


# ---------------------------------------------------------------------------
# Factory function used by CampaignManager
# ---------------------------------------------------------------------------


def default_telemetry_factory(campaign: "Campaign") -> CampaignTelemetry:
    """Return a :class:`CampaignTelemetry` for a campaign.

    The collector is constructed with the campaign's fuzzer
    capabilities and default sampling parameters. The caller (usually
    :class:`CampaignManager`) is responsible for calling :meth:`start`
    and for attaching workers.

    Parameters
    ----------
    campaign:
        The campaign being observed.

    Returns
    -------
    CampaignTelemetry
    """
    return CampaignTelemetry(campaign)


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
