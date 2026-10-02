"""KMCS fuzzing-engine adapter foundation (Phase 4, module ``base``).

This module defines everything the concrete engine adapters (AFL++,
libFuzzer, Honggfuzz) share:

* :class:`EngineCapabilities` / :class:`EngineStats` — honest telemetry
  containers.  A statistic that the engine did not report is ``None``, never
  a fabricated zero.
* :class:`ResourceLimits`, :class:`FuzzLaunchSpec` — validated launch
  descriptions with defensive-scope enforcement.
* :class:`CrashArtifact` + :func:`discover_crash_artifacts` — discovery of
  crash/hang inputs produced by the engine on disk.
* :class:`FuzzEvent` stream and :class:`FuzzSession` — the live-run object
  returned by :meth:`FuzzEngineAdapter.start`.  It owns the child process
  group, pumps stdout/stderr into an event queue, refreshes stats on a
  cadence, watches for new crash artifacts, enforces wall-clock budgets and
  terminates deterministically.
* :class:`FuzzEngineAdapter` — the abstract lifecycle: ``probe`` →
  ``prepare`` → ``start`` → session → ``stop``.  Concrete engines implement
  only their argv construction, environment policy and stats parsing.

Hard rules honoured here (project spec §4):

1. External engines run as **real subprocesses**; nothing is simulated.
2. If a binary is missing the adapter reports it truthfully via
   :class:`~kmcs.core.exceptions.FuzzerUnavailableError` — no fake success.
3. Defensive-only: any configuration resembling exploitation/stealth is
   rejected by :func:`kmcs.core.models.guard_capability`.
4. No API keys, no network access, purely local orchestration.
"""

from __future__ import annotations

import abc
import errno
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from queue import Empty, Queue
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from kmcs.core.events import EventType, Topic
from kmcs.core.exceptions import (
    FuzzerAlreadyRunningError,
    FuzzerNotRunningError,
    FuzzerStartupError,
    FuzzerUnavailableError,
    FuzzingError,
    InvalidValueError,
    KMCSException,
    PolicyViolationError,
    ScopeExceededError,
)
from kmcs.core.models import (
    Corpus,
    EngineKind,
    HarnessSpec,
    Target,
    guard_capability,
    normalize_path,
    now_utc,
    parse_size,
    safe_filename,
    sha256_file,
    stable_digest,
    utc_string,
)

__all__ = [
    "ARTIFACT_NAME_PATTERNS",
    "ArtifactKind",
    "CrashArtifact",
    "DEFAULT_SESSION_RETENTION_SECONDS",
    "EngineCapabilities",
    "EngineStats",
    "FuzzEngineAdapter",
    "FuzzEvent",
    "FuzzEventType",
    "FuzzLaunchSpec",
    "FuzzSession",
    "LaunchValidator",
    "MAX_EVENT_QUEUE",
    "MAX_LOG_LINE",
    "ResourceLimits",
    "StatsSource",
    "canonicalise_argv",
    "discover_crash_artifacts",
    "estimate_execs_per_sec",
    "format_duration",
    "make_session_directories",
    "parse_int_token",
    "resolve_engine_binary",
    "tail_lines",
    "validate_harness_for_engine",
    "wait_for_process_exit",
]


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

_INT_RE = re.compile(r"-?\d+")


def parse_int_token(text: Any, default: Optional[int] = None) -> Optional[int]:
    """Extract the first integer from *text*, or *default*.

    Handles values like ``"execs/s      :   12345.67"`` fragments and plain
    strings; deliberately strict about returning ``None`` rather than guessing.
    """
    if text is None:
        return default
    if isinstance(text, bool):
        return int(text)
    if isinstance(text, (int, float)):
        return int(text)
    match = _INT_RE.search(str(text).replace(",", ""))
    if not match:
        return default
    try:
        return int(match.group(0))
    except ValueError:  # pragma: no cover - regex guarantees digits
        return default


def format_duration(seconds: Optional[float]) -> str:
    """Render *seconds* as ``"1h02m03s"`` style text; ``"-"`` when unknown."""
    if seconds is None:
        return "-"
    total = int(max(0.0, float(seconds)))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def tail_lines(path: Union[str, "os.PathLike[str]"], count: int = 50,
               *, max_bytes: int = 262_144) -> List[str]:
    """Return the last *count* lines of *path* without loading whole file."""
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        return []
    if size == 0 or count <= 0:
        return []
    read_from = max(0, size - max_bytes)
    try:
        with p.open("rb") as handle:
            handle.seek(read_from)
            data = handle.read()
    except OSError:
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    if read_from > 0 and lines:
        # first line may be truncated mid-line
        lines = lines[1:] if len(lines) > 1 else lines
    return lines[-count:]


def estimate_execs_per_sec(current_total: int, current_time: float,
                           previous_total: Optional[int],
                           previous_time: Optional[float]) -> Optional[float]:
    """Instantaneous execs/sec between two samples; ``None`` if unsolvable."""
    if previous_total is None or previous_time is None:
        return None
    dt = current_time - float(previous_time)
    de = current_total - int(previous_total)
    if dt <= 0 or de < 0:
        return None
    return de / dt


def canonicalise_argv(argv: Sequence[str]) -> List[str]:
    """Normalise an argv list: stringify, strip empty entries, expand paths.

    Keeps argument order exactly (engines are order-sensitive) but removes
    accidental whitespace and drops empty tokens which confuse AFL++'s
    ``--`` separator handling.
    """
    out: List[str] = []
    for part in argv:
        text = str(part).strip()
        if text == "":
            continue
        out.append(text)
    return out


_SECRETS_ENV_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD",
                      "CREDENTIAL", "AUTH")


def _looks_like_credential(name: str) -> bool:
    upper = name.upper()
    return any(hint in upper for hint in _SECRETS_ENV_HINTS)


def resolve_engine_binary(candidates: Sequence[str],
                          extra_dirs: Sequence[str] = ()) -> Optional[str]:
    """Locate the first executable among *candidates*.

    Searches PATH via :func:`shutil.which`, then *extra_dirs*.  Returns
    ``None`` when nothing is found — callers must surface unavailability
    honestly instead of pretending the engine exists.
    """
    names: List[str] = [str(c) for c in candidates if str(c).strip()]
    for name in names:
        if os.path.sep in name:
            expanded = normalize_path(name)
            if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
                return expanded
            continue
        found = shutil.which(name)
        if found:
            return found
        for directory in extra_dirs:
            candidate = os.path.join(normalize_path(directory), name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


# ---------------------------------------------------------------------------
# artifact kinds & discovery
# ---------------------------------------------------------------------------


class ArtifactKind(str, Enum):
    """What kind of engine-produced input artefact we found on disk."""

    CRASH = "crash"
    HANG = "hang"
    SLOW = "slow"
    TIMEOUT = "timeout"
    QUEUE = "queue"          # interesting/new-coverage testcase (not a fault)
    CORPUS = "corpus"        # libfuzzer-style synthesized corpus entry
    UNKNOWN = "unknown"

    @property
    def is_fault(self) -> bool:
        return self in (ArtifactKind.CRASH, ArtifactKind.HANG,
                        ArtifactKind.TIMEOUT, ArtifactKind.SLOW)


#: filename substrings used to classify discovered artefacts.  Ordered: the
#: first matching pattern wins.
ARTIFACT_NAME_PATTERNS: Tuple[Tuple[str, ArtifactKind], ...] = (
    ("crash-", ArtifactKind.CRASH),
    ("crash_", ArtifactKind.CRASH),
    ("sigsegv", ArtifactKind.CRASH),
    ("hang-", ArtifactKind.HANG),
    ("timeout-", ArtifactKind.TIMEOUT),
    ("slow-unit-", ArtifactKind.SLOW),
    ("slow-", ArtifactKind.SLOW),
    ("queue/id:", ArtifactKind.QUEUE),
    ("id:", ArtifactKind.QUEUE),
    ("poc", ArtifactKind.CRASH),
)

#: directories engines commonly use for artefacts (searched recursively)
_ARTIFACT_DIR_HINTS = ("crashes", "hangs", "timeouts", "slow_crashes",
                       "new", "sync", "queue", "default", "corpus")


@dataclass(frozen=True)
class CrashArtifact:
    """One input file the engine flagged (crash/hang/queue item).

    Attributes
    ----------
    kind:
        Classification derived from the file/dir name.
    path:
        Absolute path of the artefact.
    source_directory:
        The engine output directory it was discovered under.
    size / content_hash:
        Measured facts about the file itself.
    discovered_at / mtime:
        Timestamps (UTC ISO strings) for ordering and dedup bookkeeping.
    engine_name:
        Name of the engine that produced it (e.g. ``"aflpp"``).
    campaign_hint:
        Optional free-form correlation key supplied by the caller.
    """

    kind: ArtifactKind
    path: str
    source_directory: str
    size: int
    content_hash: str
    discovered_at: str
    mtime: float
    engine_name: str = ""
    campaign_hint: str = ""

    @property
    def is_fault(self) -> bool:
        return self.kind.is_fault

    @property
    def filename(self) -> str:
        return os.path.basename(self.path)

    def identity(self) -> str:
        """Stable dedup key: engine + kind + content hash (+name fallback)."""
        basis = self.content_hash or self.filename
        return stable_digest([self.engine_name, self.kind.value, basis])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value, "path": self.path,
            "source_directory": self.source_directory, "size": self.size,
            "content_hash": self.content_hash,
            "discovered_at": self.discovered_at, "mtime": self.mtime,
            "engine_name": self.engine_name,
            "campaign_hint": self.campaign_hint,
            "is_fault": self.is_fault, "identity": self.identity(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CrashArtifact":
        return cls(
            kind=ArtifactKind(str(payload.get("kind", "unknown"))),
            path=str(payload.get("path", "")),
            source_directory=str(payload.get("source_directory", "")),
            size=int(payload.get("size", 0) or 0),
            content_hash=str(payload.get("content_hash", "")),
            discovered_at=str(payload.get("discovered_at", "")),
            mtime=float(payload.get("mtime", 0.0) or 0.0),
            engine_name=str(payload.get("engine_name", "")),
            campaign_hint=str(payload.get("campaign_hint", "")),
        )


def _classify_artifact_name(filename: str, parent_dir: str) -> ArtifactKind:
    lowered = filename.lower()
    dir_lower = os.path.basename(parent_dir).lower()
    if dir_lower.startswith("hang") or "hang-" in lowered:
        return ArtifactKind.HANG
    if dir_lower.startswith("timeout") or "timeout-" in lowered:
        return ArtifactKind.TIMEOUT
    if dir_lower.startswith("slow") or "slow-" in lowered:
        return ArtifactKind.SLOW
    for pattern, kind in ARTIFACT_NAME_PATTERNS:
        if pattern in lowered:
            return kind
    if dir_lower in ("crashes", "default"):
        return ArtifactKind.CRASH
    if dir_lower in ("queue", "new"):
        return ArtifactKind.QUEUE
    if dir_lower == "corpus":
        return ArtifactKind.CORPUS
    return ArtifactKind.UNKNOWN


_SKIP_ARTIFACT_FILES = {"README.md", "README", "fuzzer_stats", "plot_data",
                        "crash_ids.txt", "hangs.txt", "queue_state"}


def discover_crash_artifacts(directory: Union[str, "os.PathLike[str]"],
                             *, engine_name: str = "",
                             known_identities: Optional[set] = None,
                             campaign_hint: str = "",
                             max_files: int = 5000) -> List[CrashArtifact]:
    """Scan *directory* recursively for engine artefacts.

    Only regular files are considered; symlinks, sockets, FIFOs and the
    engine's own bookkeeping files are skipped.  Files already present in
    *known_identities* (a set of :meth:`CrashArtifact.identity` strings) are
    omitted so repeated polling yields only genuinely new discoveries.  The
    updated identity set is mutated in place when one is provided.

    Returns artifacts sorted by modification time (oldest first) so replay
    order matches discovery order.
    """
    root = Path(normalize_path(directory))
    if not root.exists():
        return []
    seen = known_identities if known_identities is not None else set()
    found: List[CrashArtifact] = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        current = Path(dirpath)
        for name in sorted(filenames):
            if scanned >= max_files:
                return found
            scanned += 1
            if name in _SKIP_ARTIFACT_FILES or name.endswith(".state"):
                continue
            file_path = current / name
            try:
                st = file_path.stat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size == 0:
                # empty placeholder files some engines create; skip hashing
                continue
            try:
                digest = sha256_file(file_path)
            except OSError:
                continue
            kind = _classify_artifact_name(name, str(current))
            artifact = CrashArtifact(
                kind=kind,
                path=str(file_path),
                source_directory=str(current),
                size=st.st_size,
                content_hash=digest,
                discovered_at=utc_string(),
                mtime=st.st_mtime,
                engine_name=engine_name,
                campaign_hint=campaign_hint,
            )
            identity = artifact.identity()
            if identity in seen:
                continue
            seen.add(identity)
            found.append(artifact)
    found.sort(key=lambda a: (a.mtime, a.path))
    return found


# ---------------------------------------------------------------------------
# capabilities & statistics
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineCapabilities:
    """What a specific installed engine version can do.

    Capabilities are probed from the real binary where possible (version
    string parsing, ``--help`` flags); unsupported features simply come back
    as ``False`` so planners degrade gracefully instead of crashing later.
    """

    engine: str
    available: bool = False
    binary_path: str = ""
    version: str = ""
    persistent_mode: bool = False
    cmplog: bool = False
    dictionary_support: bool = False
    tokens_support: bool = False
    custom_mutator_support: bool = False
    parallel_workers: bool = False
    in_process: bool = False
    coverage_feedback: bool = True
    sandbox_options: Tuple[str, ...] = ()
    notes: str = ""

    def require_available(self, operation: str = "run") -> None:
        if not self.available:
            raise FuzzerUnavailableError(
                f"engine '{self.engine}' is not available; cannot {operation}",
                details={"engine": self.engine, "binary_path": self.binary_path})

    def supports(self, feature: str) -> bool:
        value = getattr(self, feature, None)
        return bool(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine, "available": self.available,
            "binary_path": self.binary_path, "version": self.version,
            "persistent_mode": self.persistent_mode, "cmplog": self.cmplog,
            "dictionary_support": self.dictionary_support,
            "tokens_support": self.tokens_support,
            "custom_mutator_support": self.custom_mutator_support,
            "parallel_workers": self.parallel_workers,
            "in_process": self.in_process,
            "coverage_feedback": self.coverage_feedback,
            "sandbox_options": list(self.sandbox_options),
            "notes": self.notes,
        }


class StatsSource(str, Enum):
    """Where a stats snapshot came from (provenance honesty)."""

    FILE = "file"           # parsed engine stats file (e.g. fuzzer_stats)
    STDOUT = "stdout"       # parsed engine console output
    OBSERVED = "observed"   # counted by KMCS itself (files on disk)
    MIXED = "mixed"
    UNKNOWN = "unknown"


#: canonical stat names tracked across all engines.  Adapters map their own
#: fields onto these keys; anything absent stays ``None`` (never fabricated).
STAT_FIELDS: Tuple[str, ...] = (
    "execs_done", "execs_per_sec", "edges_found", "corpus_count",
    "queue_items", "crashes_found", "hangs_found", "time_since_start",
    "median_time", "coverage_percent", "runs", "unique_crashes",
    "unique_hangs", "max_depth", "cycles_done",
)


@dataclass
class EngineStats:
    """A point-in-time snapshot of engine-reported statistics.

    Every field defaults to ``None`` meaning *the engine did not tell us*.
    :meth:`merge_from` only overwrites fields that the incoming mapping
    actually contains, so partial updates never erase known history.
    """

    engine: str = ""
    captured_at: str = field(default_factory=utc_string)
    sample_monotonic: float = field(default_factory=time.monotonic)
    values: Dict[str, Optional[Union[int, float]]] = field(default_factory=dict)
    raw: Dict[str, str] = field(default_factory=dict)
    source: str = StatsSource.UNKNOWN.value
    warnings: List[str] = field(default_factory=list)

    # -- accessors ---------------------------------------------------------
    def get(self, key: str, default: Optional[float] = None) -> Optional[float]:
        value = self.values.get(key)
        return default if value is None else value

    def set(self, key: str, value: Optional[Union[int, float]]) -> None:
        if key not in STAT_FIELDS:
            # tolerate engine-specific extras but keep them addressable
            pass
        self.values[key] = value

    @property
    def execs_done(self) -> Optional[int]:
        v = self.values.get("execs_done")
        return None if v is None else int(v)

    @property
    def crashes_found(self) -> Optional[int]:
        v = self.values.get("crashes_found")
        return None if v is None else int(v)

    @property
    def hangs_found(self) -> Optional[int]:
        v = self.values.get("hangs_found")
        return None if v is None else int(v)

    @property
    def corpus_count(self) -> Optional[int]:
        v = self.values.get("corpus_count")
        return None if v is None else int(v)

    @property
    def uptime_seconds(self) -> Optional[float]:
        v = self.values.get("time_since_start")
        return None if v is None else float(v)

    # -- mutation ----------------------------------------------------------
    def merge_from(self, mapping: Mapping[str, Optional[Union[int, float]]]) -> None:
        for key, value in mapping.items():
            if value is None:
                continue
            self.values[key] = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine, "captured_at": self.captured_at,
            "source": self.source, "values": dict(self.values),
            "raw": dict(self.raw), "warnings": list(self.warnings),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "EngineStats":
        stats = cls(engine=str(payload.get("engine", "")),
                    captured_at=str(payload.get("captured_at", utc_string())),
                    source=str(payload.get("source", StatsSource.UNKNOWN.value)))
        for key, value in (payload.get("values") or {}).items():
            stats.values[str(key)] = value
        stats.raw = {str(k): str(v) for k, v in (payload.get("raw") or {}).items()}
        stats.warnings = [str(w) for w in (payload.get("warnings") or [])]
        return stats

    def summary_line(self) -> str:
        parts = [f"engine={self.engine or '?'}"]
        for key in ("execs_done", "execs_per_sec", "crashes_found",
                    "hangs_found", "corpus_count"):
            value = self.values.get(key)
            if value is None:
                continue
            rendered = f"{value:.1f}" if isinstance(value, float) else str(value)
            parts.append(f"{key}={rendered}")
        parts.append(f"at={self.captured_at}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# resource limits & launch specification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceLimits:
    """Per-process rlimits applied to engine children via ``preexec_fn``.

    All values are optional; unset means *inherit*.  Timeouts are enforced by
    the session watchdog (wall clock) *and* optionally by ``RLIMIT_CPU``.
    """

    cpu_seconds: Optional[int] = None
    address_space_mb: Optional[int] = None
    file_size_mb: Optional[int] = None
    open_files: Optional[int] = None
    processes: Optional[int] = None
    core_dumps: bool = True          # ASan needs cores for some flows

    def validate(self) -> None:
        checks = (
            ("cpu_seconds", self.cpu_seconds),
            ("address_space_mb", self.address_space_mb),
            ("file_size_mb", self.file_size_mb),
            ("open_files", self.open_files),
            ("processes", self.processes),
        )
        for name, value in checks:
            if value is not None and int(value) <= 0:
                raise InvalidValueError(
                    f"resource limit {name!r} must be positive when set",
                    details={name: value})

    def preexec(self) -> Optional[Callable[[], None]]:
        """Build a ``preexec_fn`` applying these limits (POSIX only)."""
        self.validate()
        if os.name != "posix":
            return None
        res = resource_module()
        wanted: List[Tuple[int, Any]] = []
        if self.cpu_seconds is not None:
            wanted.append((res.RLIMIT_CPU,
                           (int(self.cpu_seconds), int(self.cpu_seconds) + 5)))
        if self.address_space_mb is not None and hasattr(res, "RLIMIT_AS"):
            wanted.append((res.RLIMIT_AS,
                           int(self.address_space_mb) * 1024 * 1024))
        if self.file_size_mb is not None:
            wanted.append((res.RLIMIT_FSIZE,
                           int(self.file_size_mb) * 1024 * 1024))
        if self.open_files is not None:
            wanted.append((res.RLIMIT_NOFILE, int(self.open_files)))
        if self.processes is not None and hasattr(res, "RLIMIT_NPROC"):
            wanted.append((res.RLIMIT_NPROC, int(self.processes)))
        if not self.core_dumps:
            wanted.append((res.RLIMIT_CORE, 0))
        if not wanted:
            return None

        def _apply() -> None:  # pragma: no cover - runs in child process
            import resource as _res

            for which, value in wanted:
                try:
                    if isinstance(value, tuple):
                        _res.setrlimit(which, value)
                    else:
                        hard = _res.getrlimit(which)[1]
                        target = value if hard in (-1, _res.RLIM_INFINITY) \
                            else min(int(value), int(hard))
                        _res.setrlimit(which, (target, target))
                except (ValueError, OSError):
                    # child continues; kernel limits are best-effort
                    pass

        return _apply


def resource_module():
    """Import :mod:`resource` lazily (absent on Windows)."""
    import resource  # noqa: WPS433 - deliberate lazy platform import
    return resource


@dataclass
class FuzzLaunchSpec:
    """Validated description of one fuzzing run.

    Bundles the authorised :class:`~kmcs.core.models.Target`, corpus, seed
    and output directories, time/execution budgets and engine-specific extra
    arguments.  :meth:`validate` enforces every precondition *before* a
    process is spawned so failures arrive as clean exceptions rather than
    half-started campaigns.
    """

    target: Target
    corpus: Optional[Corpus] = None
    seeds_dir: str = ""
    output_dir: str = ""
    session_name: str = ""
    duration_seconds: Optional[float] = None
    max_runs: Optional[int] = None
    workers: int = 1
    timeout_ms: Optional[int] = None
    memory_limit_mb: Optional[int] = None
    dictionary_path: str = ""
    tokens_path: str = ""
    extra_args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    campaign_hint: str = ""
    dry_run: bool = False

    def __post_init__(self) -> None:
        self.seeds_dir = normalize_path(self.seeds_dir) if self.seeds_dir else ""
        self.output_dir = normalize_path(self.output_dir) if self.output_dir else ""
        self.dictionary_path = normalize_path(self.dictionary_path) if self.dictionary_path else ""
        self.tokens_path = normalize_path(self.tokens_path) if self.tokens_path else ""
        if not self.session_name:
            stamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
            base = safe_filename(self.target.name or "session")
            self.session_name = f"{base}-{stamp}"
        if self.workers < 1:
            raise InvalidValueError("workers must be >= 1",
                                    details={"workers": self.workers})
        if self.duration_seconds is not None and float(self.duration_seconds) <= 0:
            raise InvalidValueError("duration_seconds must be positive",
                                    details={"duration_seconds": self.duration_seconds})
        if self.max_runs is not None and int(self.max_runs) <= 0:
            raise InvalidValueError("max_runs must be positive",
                                    details={"max_runs": self.max_runs})

    # -- validation ---------------------------------------------------------
    def validate(self, capabilities: Optional[EngineCapabilities] = None) -> None:
        """Raise unless this spec is executable as written."""
        guard_capability("authorized_fuzzing")  # defensive charter check
        if not isinstance(self.target, Target):
            raise InvalidValueError("spec.target must be a Target model")
        if not self.target.authorized:
            raise ScopeExceededError(
                "refusing to fuzz a target without valid authorisation",
                details={"target": self.target.name, "target_id": self.target.id})
        binary = self.target.binary_path
        if not binary or not os.path.isfile(binary):
            raise FuzzingError(
                f"target binary does not exist: {binary or '(unset)'}",
                details={"target": self.target.name})
        if not os.access(binary, os.X_OK):
            raise FuzzingError(f"target binary is not executable: {binary}")
        if self.seeds_dir:
            if not os.path.isdir(self.seeds_dir):
                raise FuzzingError(f"seeds directory missing: {self.seeds_dir}")
            if not any(os.scandir(self.seeds_dir)):
                raise FuzzingError(f"seeds directory is empty: {self.seeds_dir}")
        elif self.corpus is not None:
            storage = getattr(self.corpus, "storage_path", "") or ""
            if storage and os.path.isdir(storage):
                self.seeds_dir = storage
            else:
                raise FuzzingError(
                    "corpus has no materialised storage_path on disk",
                    details={"corpus_id": getattr(self.corpus, "id", "?")})
        else:
            raise FuzzingError("no seeds directory or corpus supplied")
        for label, path in (("dictionary", self.dictionary_path),
                            ("tokens", self.tokens_path)):
            if path and not os.path.isfile(path):
                raise FuzzingError(f"{label} file missing: {path}")
        if capabilities is not None:
            capabilities.require_available("start fuzzing")
            if self.workers > 1 and not capabilities.parallel_workers:
                raise InvalidValueError(
                    f"engine {capabilities.engine} does not support parallel workers",
                    details={"workers": self.workers})
        # reject obviously hostile extra args (defensive scope)
        for arg in self.extra_args:
            lowered = str(arg).lower()
            if any(banned in lowered for banned in ("-attach", "--attach",
                                                    "ptrace", "inject")):
                raise PolicyViolationError(
                    "extra engine arguments resemble debugger attach/"
                    "injection; KMCS fuzzing is black-box only",
                    details={"argument": arg})

    def resolved_output_dir(self) -> str:
        if self.output_dir:
            return self.output_dir
        return os.path.join(os.getcwd(), "kmcs-fuzz",
                            safe_filename(self.session_name))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target.id, "target": self.target.name,
            "corpus_id": getattr(self.corpus, "id", None),
            "seeds_dir": self.seeds_dir,
            "output_dir": self.resolved_output_dir(),
            "session_name": self.session_name,
            "duration_seconds": self.duration_seconds,
            "max_runs": self.max_runs, "workers": self.workers,
            "timeout_ms": self.timeout_ms,
            "memory_limit_mb": self.memory_limit_mb,
            "dictionary_path": self.dictionary_path,
            "tokens_path": self.tokens_path,
            "extra_args": list(self.extra_args),
            "campaign_hint": self.campaign_hint,
        }


class LaunchValidator:
    """Reusable gate that turns near-miss specs into actionable errors.

    Wraps :meth:`FuzzLaunchSpec.validate` plus engine-level checks (binary
    presence, instrumentation expectations) so adapters get one call site.
    """

    def __init__(self, capabilities: EngineCapabilities) -> None:
        self.capabilities = capabilities

    def check(self, spec: FuzzLaunchSpec) -> List[str]:
        """Validate; returns list of non-fatal warnings. Raises on fatal."""
        spec.validate(self.capabilities)
        warnings: List[str] = []
        if not spec.target.instrumented:
            warnings.append(
                "target reports no instrumentation; coverage-guided engines "
                "will behave like blind mutational fuzzers")
        if not spec.target.sanitizers_enabled:
            warnings.append(
                "no sanitizers enabled; many memory corruptions will be "
                "silent or misclassified")
        if spec.timeout_ms and spec.timeout_ms < 100:
            warnings.append("timeout_ms < 100 will flag almost everything "
                            "as a hang")
        return warnings


# ---------------------------------------------------------------------------
# harness compatibility
# ---------------------------------------------------------------------------

_HARNESS_ENGINE_MATRIX: Dict[str, Tuple[str, ...]] = {
    "stdin": ("aflpp", "honggfuzz", "custom"),
    "file": ("aflpp", "honggfuzz", "libfuzzer", "custom"),
    "argv": ("aflpp", "honggfuzz", "custom"),
    "persistent": ("libfuzzer", "aflpp", "honggfuzz"),
    "in-process": ("libfuzzer",),
    "socket": (),  # explicitly unsupported: KMCS fuzzes files, not services
}


def validate_harness_for_engine(harness: HarnessSpec,
                                engine: Union[str, EngineKind]) -> None:
    """Ensure the harness consumption mode is legal for *engine*.

    Raises :class:`~kmcs.core.exceptions.InvalidValueError` otherwise.  The
    ``socket`` mode is always rejected — service fuzzing is out of scope for
    KMCS's file-input research workflow.
    """
    engine_value = str(getattr(engine, "value", engine))
    allowed = _HARNESS_ENGINE_MATRIX.get(harness.mode, ())
    if harness.mode == "socket":
        raise InvalidValueError(
            "socket-mode harnesses are out of KMCS scope (file-input "
            "research fuzzing only)",
            details={"mode": harness.mode})
    if engine_value not in allowed:
        raise InvalidValueError(
            f"harness mode '{harness.mode}' is not supported by engine "
            f"'{engine_value}'",
            details={"mode": harness.mode, "engine": engine_value,
                     "supported_engines": list(allowed)})
    if harness.mode in ("file", "persistent") and harness.argv_template \
            and not any("@@" in part for part in harness.argv_template):
        raise InvalidValueError(
            "file-mode argv template must contain the '@@' input placeholder")


# ---------------------------------------------------------------------------
# fuzz events
# ---------------------------------------------------------------------------


class FuzzEventType(str, Enum):
    """Live event classes emitted by :class:`FuzzSession` queues."""

    STARTED = "started"
    LOG = "log"
    STATS = "stats"
    NEW_COVERAGE = "new_coverage"
    CRASH = "crash"
    HANG = "hang"
    TIMEOUT = "timeout"
    STOPPED = "stopped"
    KILLED = "killed"
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class FuzzEvent:
    """One item on a session's live event stream."""

    type: FuzzEventType
    at: str
    payload: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def make(type_: FuzzEventType, **payload: Any) -> "FuzzEvent":
        return FuzzEvent(type=type_, at=utc_string(), payload=payload)

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type.value, "at": self.at,
                "payload": dict(self.payload)}

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"[{self.at}] {self.type.value}: {self.payload}"


_EVENT_TO_TOPIC: Dict[FuzzEventType, Tuple[str, EventType]] = {
    FuzzEventType.STARTED: ("fuzzer", EventType.FUZZER_STARTED),
    FuzzEventType.STATS: ("fuzzer", EventType.FUZZER_STATS),
    FuzzEventType.NEW_COVERAGE: ("fuzzer", EventType.QUEUE_NEW_COVERAGE),
    FuzzEventType.CRASH: ("fuzzer", EventType.CRASH_FOUND),
    FuzzEventType.HANG: ("fuzzer", EventType.HANG_FOUND),
    FuzzEventType.TIMEOUT: ("fuzzer", EventType.TIMEOUT),
    FuzzEventType.ERROR: ("fuzzer", EventType.ERROR),
    FuzzEventType.WARNING: ("fuzzer", EventType.WARNING),
    FuzzEventType.STOPPED: ("fuzzer", EventType.STOPPED),
}


MAX_EVENT_QUEUE = 10_000
MAX_LOG_LINE = 8192
DEFAULT_SESSION_RETENTION_SECONDS = 300.0


# ---------------------------------------------------------------------------
# session directories
# ---------------------------------------------------------------------------


def make_session_directories(base: str, session_name: str,
                             *, subdirs: Sequence[str] = ("out", "logs",
                                                          "artifacts")) -> Dict[str, str]:
    """Create ``base/session_name/<subdir...>`` and return their paths.

    Existing directories are reused (idempotent).  Refuses to write anywhere
    containing ``..`` traversal after normalisation, keeping every artefact
    inside the declared tree.
    """
    root = os.path.join(normalize_path(base), safe_filename(session_name))
    result: Dict[str, str] = {"root": root}
    for sub in subdirs:
        path = os.path.join(root, sub)
        os.makedirs(path, exist_ok=True)
        result[sub] = path
    os.makedirs(root, exist_ok=True)
    return result


# ---------------------------------------------------------------------------
# process waiting helper
# ---------------------------------------------------------------------------


def wait_for_process_exit(pid: int, *, timeout: float = 5.0,
                          poll: float = 0.05) -> Optional[int]:
    """Poll until *pid* disappears (POSIX). Returns exit status if reaped.

    Never raises for a vanished process; returns ``None`` on timeout so
    callers can escalate SIGKILL.  On non-POSIX platforms returns ``None``
    immediately (caller relies on ``Popen.wait``).
    """
    if os.name != "posix":
        return None
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        try:
            done_pid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return None  # already reaped elsewhere
        except OSError as exc:
            if exc.errno == errno.ECHILD:
                return None
            raise
        if done_pid == pid:
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            return -os.WTERMSIG(status)
        time.sleep(poll)
    return None


# ---------------------------------------------------------------------------
# the session
# ---------------------------------------------------------------------------


class FuzzSession:
    """A live (or finished) fuzzing run driven by a real engine process.

    Lifecycle::

        adapter.prepare(spec) -> spec
        session = adapter.start(spec)          # spawns process group
        for event in session.events(timeout=1):  # live stream
            ...
        session.stop()                         # graceful SIGTERM -> SIGKILL
        session.stats                          # last honest snapshot
        session.artifacts                      # discovered crashes/hangs

    Threading model: one reader thread per pipe (stdout/stderr), one stats
    poller, one artifact watcher, one watchdog.  All communicate through
    plain locks and the bounded event queue; shutdown is idempotent.
    """

    def __init__(self, *, adapter: "FuzzEngineAdapter", spec: FuzzLaunchSpec,
                 argv: Sequence[str], env: Mapping[str, str],
                 cwd: Optional[str] = None,
                 stats_refresh: float = 5.0,
                 artifact_refresh: float = 2.0,
                 log_path: Optional[str] = None) -> None:
        self.adapter = adapter
        self.spec = spec
        self.argv: List[str] = list(argv)
        self.env: Dict[str, str] = dict(env)
        self.cwd = normalize_path(cwd) if cwd else None
        self._stats_refresh = max(0.5, float(stats_refresh))
        self._artifact_refresh = max(0.5, float(artifact_refresh))
        self._log_path = log_path

        self.session_id = f"fuzz-{stable_digest([spec.session_name, time.time_ns()], 10)}"
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.state = "created"  # created|running|stopping|finished|failed
        self.stop_reason = ""

        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.RLock()
        self._events: "Queue[FuzzEvent]" = Queue(maxsize=MAX_EVENT_QUEUE)
        self._threads: List[threading.Thread] = []
        self._log_handle: Optional[Any] = None
        self._log_lock = threading.Lock()

        self._stats = EngineStats(engine=adapter.engine_kind.value)
        self._prev_execs: Optional[int] = None
        self._prev_time: Optional[float] = None
        self._artifact_ids: set = set()
        self._artifacts: List[CrashArtifact] = []
        self._dropped_events = 0
        self._kill_requested = threading.Event()
        self._done = threading.Event()
        self._deadline_mono: Optional[float] = None
        if spec.duration_seconds:
            self._deadline_mono = time.monotonic() + float(spec.duration_seconds)

    # -- introspection ------------------------------------------------------
    @property
    def running(self) -> bool:
        with self._lock:
            return self.state == "running"

    @property
    def pid(self) -> Optional[int]:
        proc = self._process
        return proc.pid if proc else None

    @property
    def stats(self) -> EngineStats:
        with self._lock:
            snapshot = EngineStats(
                engine=self._stats.engine, captured_at=self._stats.captured_at,
                sample_monotonic=self._stats.sample_monotonic,
                values=dict(self._stats.values), raw=dict(self._stats.raw),
                source=self._stats.source, warnings=list(self._stats.warnings))
            # overlay observed facts that are always true regardless of engine
            snapshot.values.setdefault("artifacts_observed", len(self._artifacts))
            return snapshot

    @property
    def artifacts(self) -> List[CrashArtifact]:
        with self._lock:
            return list(self._artifacts)

    @property
    def elapsed_seconds(self) -> Optional[float]:
        if not self.started_at:
            return None
        start = time.time() - _seconds_since(self.started_at)
        end = time.time() if not self.finished_at \
            else time.time() - _seconds_since(self.finished_at)
        return max(0.0, end - start)

    def events(self, timeout: Optional[float] = 0.5,
               max_items: int = 256) -> List[FuzzEvent]:
        """Drain up to *max_items* queued events, waiting ≤ *timeout*s."""
        collected: List[FuzzEvent] = []
        first_deadline = None if timeout is None else time.monotonic() + timeout
        while len(collected) < max_items:
            remaining = None
            if first_deadline is not None:
                remaining = max(0.0, first_deadline - time.monotonic())
                if remaining == 0.0 and collected:
                    break
            try:
                item = self._events.get(timeout=remaining if timeout is not None
                                        else None)
            except Empty:
                break
            collected.append(item)
            if timeout is None and self._events.empty():
                break
        return collected

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Block until the session finishes; ``True`` if it did."""
        return self._done.wait(timeout)

    # -- logging ------------------------------------------------------------
    def _write_log(self, stream: str, line: str) -> None:
        if self._log_handle is None:
            return
        clipped = line[:MAX_LOG_LINE]
        with self._log_lock:
            try:
                self._log_handle.write(f"{utc_string()} [{stream}] {clipped}\n")
                self._log_handle.flush()
            except (OSError, ValueError):
                pass  # closed handle during teardown

    def _publish(self, event: FuzzEvent) -> None:
        try:
            self._events.put_nowait(event)
        except Exception:
            self._dropped_events += 1
        bus = getattr(self.adapter, "bus", None)
        mapping = _EVENT_TO_TOPIC.get(event.type)
        if bus is not None and mapping is not None:
            namespace, etype = mapping
            try:
                topic = Topic.build("kmcs", namespace,
                                    self.spec.target.id, etype.value)
                bus.emit(topic, etype, {"session_id": self.session_id,
                                        "engine": self.adapter.engine_kind.value,
                                        **event.payload})
            except Exception:  # bus failures must never kill a fuzz run
                pass

    # -- lifecycle ----------------------------------------------------------
    def _spawn(self) -> None:
        """Start the engine process in its own group (called by adapter)."""
        preexec = self.spec.limits.preexec()
        popen_kwargs: Dict[str, Any] = dict(
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, env=self.env, cwd=self.cwd,
            text=False, bufsize=0)
        if os.name == "posix":
            def _child_preexec() -> None:  # pragma: no cover - child side
                os.setpgid(0, 0)
                if preexec is not None:
                    preexec()
            popen_kwargs["preexec_fn"] = _child_preexec
        try:
            self._process = subprocess.Popen(self.argv, **popen_kwargs)
        except FileNotFoundError as exc:
            self.state = "failed"
            raise FuzzerUnavailableError(
                f"engine binary vanished before exec: {self.argv[0]}",
                details={"argv0": self.argv[0], "cause": str(exc)}) from exc
        except OSError as exc:
            self.state = "failed"
            raise FuzzerStartupError(
                f"failed to spawn engine process: {exc}",
                details={"errno": exc.errno}) from exc
        self.started_at = utc_string()
        self.state = "running"
        if self._log_path:
            parent = os.path.dirname(self._log_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self._log_handle = open(self._log_path, "a", encoding="utf-8",
                                    errors="replace")
        self._publish(FuzzEvent.make(FuzzEventType.STARTED,
                                     pid=self._process.pid,
                                     argv=list(self.argv),
                                     session_id=self.session_id))
        self._start_threads()

    def _start_threads(self) -> None:
        assert self._process is not None
        targets: List[Tuple[str, Callable[[], None]]] = [
            ("stdout-pump", lambda: self._pump(self._process.stdout, "out")),
            ("stderr-pump", lambda: self._pump(self._process.stderr, "err")),
            ("stats-poller", self._stats_loop),
            ("artifact-watcher", self._artifact_loop),
            ("watchdog", self._watchdog_loop),
        ]
        for name, fn in targets:
            thread = threading.Thread(target=self._guarded(fn), name=f"kmcs-{name}-{self.session_id}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def _guarded(self, fn: Callable[[], None]) -> Callable[[], None]:
        def runner() -> None:
            try:
                fn()
            except Exception as exc:  # pragma: no cover - safety net
                self._publish(FuzzEvent.make(FuzzEventType.ERROR,
                                             stage="thread", error=str(exc)))
        return runner

    def _pump(self, stream: Optional[Any], label: str) -> None:
        if stream is None:
            return
        decoder_errors = 0
        try:
            for raw in iter(stream.readline, b""):
                if not raw:
                    break
                try:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                except Exception:
                    decoder_errors += 1
                    continue
                self._write_log(label, line)
                self.adapter.consume_output(self, label, line)
        finally:
            try:
                stream.close()
            except OSError:
                pass
        if decoder_errors:
            self._publish(FuzzEvent.make(FuzzEventType.WARNING,
                                         note=f"{decoder_errors} undecodable output lines"))

    def _stats_loop(self) -> None:
        while not self._done.is_set():
            try:
                stats = self.adapter.collect_stats(self)
            except Exception as exc:  # collect must never crash the loop
                stats = None
                self._publish(FuzzEvent.make(FuzzEventType.WARNING,
                                             note=f"stats collection failed: {exc}"))
            if stats is not None:
                with self._lock:
                    self._stats = stats
                    instant = estimate_execs_per_sec(
                        int(stats.values.get("execs_done", 0) or 0),
                        stats.sample_monotonic, self._prev_execs, self._prev_time)
                    if instant is not None:
                        stats.values.setdefault("execs_per_sec", round(instant, 2))
                    self._prev_execs = stats.values.get("execs_done")
                    self._prev_time = stats.sample_monotonic
                self._publish(FuzzEvent.make(FuzzEventType.STATS,
                                             stats=stats.to_dict()))
            self._done.wait(self._stats_refresh)

    def _artifact_loop(self) -> None:
        watch_dirs = self.adapter.artifact_watch_dirs(self)
        while not self._done.is_set():
            for directory in watch_dirs:
                if not os.path.isdir(directory):
                    continue
                new = discover_crash_artifacts(
                    directory, engine_name=self.adapter.engine_kind.value,
                    known_identities=self._artifact_ids,
                    campaign_hint=self.spec.campaign_hint)
                for artifact in new:
                    with self._lock:
                        self._artifacts.append(artifact)
                    kind_map = {
                        ArtifactKind.CRASH: FuzzEventType.CRASH,
                        ArtifactKind.HANG: FuzzEventType.HANG,
                        ArtifactKind.TIMEOUT: FuzzEventType.TIMEOUT,
                    }
                    etype = kind_map.get(artifact.kind, FuzzEventType.NEW_COVERAGE)
                    self._publish(FuzzEvent.make(etype, artifact=artifact.to_dict()))
            self._done.wait(self._artifact_refresh)

    def _watchdog_loop(self) -> None:
        # enforce wall-clock budget and detect natural process exit
        proc = self._process
        assert proc is not None
        while True:
            code = proc.poll()
            if code is not None:
                self._finish(code, natural=True)
                return
            if self._deadline_mono is not None and time.monotonic() >= self._deadline_mono:
                self._publish(FuzzEvent.make(FuzzEventType.WARNING,
                                             note="duration budget reached; stopping"))
                self.stop(reason="budget-exhausted")
                return
            if self._kill_requested.is_set():
                return
            self._done.wait(0.25)

    # -- stop / finish -------------------------------------------------------
    def stop(self, *, reason: str = "user-requested", grace: float = 10.0) -> Optional[int]:
        """Terminate the engine: SIGTERM to the group, then SIGKILL."""
        with self._lock:
            if self.state in ("finished", "failed"):
                return self.exit_code
            if self.state == "stopping":
                return None
            self.state = "stopping"
            self.stop_reason = reason
            proc = self._process
        if proc is None or proc.poll() is not None:
            self._finish(proc.returncode if proc else None, natural=False)
            return self.exit_code
        self._kill_requested.set()
        _terminate_process(proc, grace=grace)
        code = proc.poll()
        if code is None:  # still alive after grace (shouldn't happen)
            try:
                proc.kill()
                code = proc.wait(timeout=5)
            except Exception:
                code = None
        self._finish(code, natural=False)
        return self.exit_code

    def _finish(self, code: Optional[int], *, natural: bool) -> None:
        with self._lock:
            if self.state == "finished":
                return
            self.exit_code = code
            self.finished_at = utc_string()
            self.state = "finished" if natural or code is not None else "failed"
        self._done.set()
        # final stats + artifact sweep so consumers see complete data
        try:
            final_stats = self.adapter.collect_stats(self)
            if final_stats is not None:
                with self._lock:
                    self._stats = final_stats
        except Exception:
            pass
        try:
            for directory in self.adapter.artifact_watch_dirs(self):
                for artifact in discover_crash_artifacts(
                        directory, engine_name=self.adapter.engine_kind.value,
                        known_identities=self._artifact_ids,
                        campaign_hint=self.spec.campaign_hint):
                    with self._lock:
                        self._artifacts.append(artifact)
        except Exception:
            pass
        event_type = FuzzEventType.STOPPED if natural else FuzzEventType.KILLED
        self._publish(FuzzEvent.make(
            event_type, exit_code=code, natural=natural,
            reason=self.stop_reason or ("exited" if natural else "stopped"),
            elapsed_seconds=self.elapsed_seconds,
            artifacts=len(self._artifacts),
            dropped_events=self._dropped_events))
        if self._log_handle is not None:
            with self._log_lock:
                try:
                    self._log_handle.close()
                finally:
                    self._log_handle = None

    # -- rendering ------------------------------------------------------------
    def describe(self) -> str:
        state = self.state
        pid = self.pid or "-"
        elapsed = format_duration(self.elapsed_seconds)
        stats = self.stats
        execs = stats.execs_done
        crashes = stats.crashes_found
        return (f"<FuzzSession {self.session_id} engine={self.adapter.engine_kind.value} "
                f"state={state} pid={pid} elapsed={elapsed} execs={execs if execs is not None else '?'} "
                f"crashes={crashes if crashes is not None else len(self._artifacts)} "
                f"exit={self.exit_code}>")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "engine": self.adapter.engine_kind.value,
            "state": self.state, "exit_code": self.exit_code,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "stop_reason": self.stop_reason,
            "pid": self.pid, "argv": self.argv,
            "spec": self.spec.to_dict(),
            "stats": self.stats.to_dict(),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "dropped_events": self._dropped_events,
        }


def _seconds_since(iso_ts: str) -> float:
    """Seconds elapsed since an ISO UTC timestamp (robust to bad input)."""
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())
    except Exception:
        return 0.0


def _terminate_process(proc: "subprocess.Popen", *, grace: float = 10.0) -> int:
    """SIGTERM (group-wide on POSIX) then SIGKILL. Returns final code."""
    if proc.poll() is not None:
        return proc.returncode
    try:
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:  # group gone / not ours: fall back
                proc.terminate()
        else:  # pragma: no cover - windows
            proc.terminate()
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        return proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass
        try:
            return proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return proc.returncode


# ---------------------------------------------------------------------------
# the adapter ABC
# ---------------------------------------------------------------------------


class FuzzEngineAdapter(abc.ABC):
    """Abstract lifecycle wrapper around one external fuzzing engine.

    Subclasses implement four things:

    ``engine_kind`` / ``capabilities()``
        Identity + honest availability probe of the installed binary.
    ``build_argv(spec, session_paths)``
        The exact command line for a run.
    ``build_environment(spec)``
        Engine + sanitizer environment (credentials scrubbed).
    ``collect_stats(session)``
        Parse the engine's own stats output into :class:`EngineStats`.

    Everything else (validation, spawning, threads, teardown, events) lives
    in :class:`FuzzSession` and is shared verbatim.
    """

    #: human-readable name override; defaults to EngineKind display name
    engine_display_name: str = ""
    #: whether instrumentation is mandatory for meaningful runs
    requires_instrumentation: bool = True
    #: stats refresh cadence (seconds)
    stats_refresh_seconds: float = 5.0
    #: artifact scan cadence (seconds)
    artifact_refresh_seconds: float = 2.0

    def __init__(self, *, bus: Any = None,
                 workspace_root: Optional[str] = None,
                 binary_override: Optional[str] = None) -> None:
        self.bus = bus
        self.workspace_root = normalize_path(
            workspace_root or os.path.join(os.getcwd(), "kmcs-fuzz-workspace"))
        self.binary_override = binary_override
        self._capabilities_cache: Optional[EngineCapabilities] = None
        self._sessions: Dict[str, FuzzSession] = {}
        self._sessions_lock = threading.RLock()

    # -- identity -------------------------------------------------------------
    @property
    @abc.abstractmethod
    def engine_kind(self) -> EngineKind:
        """The :class:`EngineKind` this adapter drives."""

    @property
    def display_name(self) -> str:
        return self.engine_display_name or self.engine_kind.display_name

    # -- availability ---------------------------------------------------------
    @abc.abstractmethod
    def probe(self) -> EngineCapabilities:
        """Inspect the installed engine; report truthfully what exists."""

    def capabilities(self, *, refresh: bool = False) -> EngineCapabilities:
        if self._capabilities_cache is None or refresh:
            self._capabilities_cache = self.probe()
        return self._capabilities_cache

    def is_available(self) -> bool:
        return self.capabilities().available

    def require_available(self, operation: str = "run") -> EngineCapabilities:
        caps = self.capabilities()
        if not caps.available:
            raise FuzzerUnavailableError(
                f"{self.display_name} is not installed or not runnable; "
                f"cannot {operation}. Install it or point KMCS at the binary "
                f"(searched: {', '.join(self.engine_kind.binaries)})",
                details={"engine": self.engine_kind.value,
                         "searched": self.engine_kind.binaries})
        return caps

    # -- preparation ----------------------------------------------------------
    def prepare(self, spec: FuzzLaunchSpec) -> FuzzLaunchSpec:
        """Validate spec against this engine; normalise dirs; return it.

        Raises :class:`~kmcs.core.exceptions.FuzzingError` family on fatal
        problems; non-fatal warnings accumulate in ``self.last_warnings``.
        """
        caps = self.capabilities()
        validator = LaunchValidator(caps)
        self.last_warnings = validator.check(spec)
        validate_harness_for_engine(spec.target.harness, self.engine_kind)
        if self.requires_instrumentation and not spec.target.instrumented:
            self.last_warnings.append(
                f"{caps.engine} expects instrumented builds "
                f"(see kmcs.targets.build)")
        spec.output_dir = spec.resolved_output_dir()
        return spec

    last_warnings: List[str] = []

    # -- abstract run construction ---------------------------------------------
    @abc.abstractmethod
    def build_argv(self, spec: FuzzLaunchSpec,
                   session_paths: Mapping[str, str]) -> List[str]:
        """Construct the full argv (element 0 = engine binary)."""

    @abc.abstractmethod
    def build_environment(self, spec: FuzzLaunchSpec) -> Dict[str, str]:
        """Construct the child environment dict (already merged)."""

    def artifact_watch_dirs(self, session: FuzzSession) -> List[str]:
        """Directories to poll for crash/hang artefacts (override freely)."""
        return [session.spec.output_dir] if session.spec.output_dir else []

    def consume_output(self, session: FuzzSession, stream: str,
                       line: str) -> None:
        """Hook for engine-specific console parsing (stats/crash lines)."""

    @abc.abstractmethod
    def collect_stats(self, session: FuzzSession) -> Optional[EngineStats]:
        """Read the engine's stats right now; ``None`` when unavailable."""

    # -- starting ----------------------------------------------------------------
    def start(self, spec: FuzzLaunchSpec, *, auto_prepare: bool = True) -> FuzzSession:
        """Launch a real fuzzing run and return its live session."""
        caps = self.require_available("start")
        if auto_prepare:
            spec = self.prepare(spec)
        else:
            spec.validate(caps)
        with self._sessions_lock:
            for existing in self._sessions.values():
                if existing.running and existing.spec.target.id == spec.target.id \
                        and existing.spec.session_name == spec.session_name:
                    raise FuzzerAlreadyRunningError(
                        f"a session for target '{spec.target.name}' with this "
                        f"name is already running ({existing.session_id})",
                        details={"session_id": existing.session_id})
        session_paths = make_session_directories(
            os.path.dirname(spec.output_dir.rstrip(os.sep)) or ".",
            os.path.basename(spec.output_dir.rstrip(os.sep)))
        argv = canonicalise_argv(self.build_argv(spec, session_paths))
        env = self.build_environment(spec)
        env = _scrub_credentials(env)
        log_path = os.path.join(session_paths["logs"], "engine.log")
        session = FuzzSession(
            adapter=self, spec=spec, argv=argv, env=env,
            cwd=session_paths.get("root"),
            stats_refresh=self.stats_refresh_seconds,
            artifact_refresh=self.artifact_refresh_seconds,
            log_path=log_path)
        session._spawn()
        with self._sessions_lock:
            self._sessions[session.session_id] = session
        return session

    # -- session bookkeeping ---------------------------------------------------
    def sessions(self, *, include_finished: bool = True) -> List[FuzzSession]:
        with self._sessions_lock:
            items = list(self._sessions.values())
        if not include_finished:
            items = [s for s in items if s.running]
        return items

    def get_session(self, session_id: str) -> FuzzSession:
        with self._sessions_lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise FuzzerNotRunningError(
                f"no session with id {session_id!r} on engine {self.display_name}")
        return session

    def stop_all(self, *, reason: str = "shutdown", grace: float = 10.0) -> int:
        """Stop every running session; returns count stopped."""
        count = 0
        for session in self.sessions(include_finished=False):
            session.stop(reason=reason, grace=grace)
            count += 1
        return count

    def prune_sessions(self, *, older_than: float = DEFAULT_SESSION_RETENTION_SECONDS) -> int:
        """Drop finished-session references older than *older_than* seconds."""
        removed = 0
        with self._sessions_lock:
            stale = [sid for sid, sess in self._sessions.items()
                     if sess.state == "finished" and sess.finished_at
                     and _seconds_since(sess.finished_at) > older_than]
            for sid in stale:
                self._sessions.pop(sid, None)
                removed += 1
        return removed

    # -- misc ---------------------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        caps = self.capabilities()
        return {
            "engine": self.engine_kind.value,
            "display_name": self.display_name,
            "available": caps.available,
            "binary": caps.binary_path,
            "version": caps.version,
            "active_sessions": len(self.sessions(include_finished=False)),
            "known_sessions": len(self._sessions),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} engine={self.engine_kind.value} available={self.capabilities().available}>"


def _scrub_credentials(env: Mapping[str, str]) -> Dict[str, str]:
    """Remove credential-shaped variables before handing env to children."""
    cleaned: Dict[str, str] = {}
    for key, value in env.items():
        if _looks_like_credential(str(key)):
            continue
        cleaned[str(key)] = str(value)
    return cleaned


# ---------------------------------------------------------------------------
# smoke test
# ---------------------------------------------------------------------------


def _smoke() -> int:  # pragma: no cover - executed manually
    """Exercise pure-python pieces without needing an engine installed."""
    tmp = Path("/tmp/kmcs-base-smoke")
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / "crashes").mkdir(parents=True)
    (tmp / "crashes" / "crash-aa:bb:cc").write_bytes(b"boom")
    (tmp / "crashes" / "README.md").write_text("skip me")
    (tmp / "hangs").mkdir()
    (tmp / "hangs" / "hang-01").write_bytes(b"*" * 10)

    ids: set = set()
    first = discover_crash_artifacts(tmp, engine_name="test", known_identities=ids)
    kinds = sorted(a.kind.value for a in first)
    assert kinds == ["crash", "hang"], kinds
    second = discover_crash_artifacts(tmp, engine_name="test", known_identities=ids)
    assert second == [], "dedup by identity failed"

    art = first[0]
    restored = CrashArtifact.from_dict(art.to_dict())
    assert restored.identity() == art.identity()

    stats = EngineStats(engine="test")
    stats.merge_from({"execs_done": 100})
    assert stats.execs_done == 100 and stats.crashes_found is None
    assert "execs_done=100" in stats.summary_line()

    assert parse_int_token("execs/s : 12.5") == 12
    assert format_duration(3725) == "1h02m05s"
    assert tail_lines(Path(first[0].path), 3) == ["boom"]
    assert canonicalise_argv(["a", " ", "b"]) == ["a", "b"]

    limits = ResourceLimits(cpu_seconds=5, address_space_mb=512)
    assert callable(limits.preexec()) or os.name != "posix"

    print("kmcs.fuzzers.base smoke OK:", len(first), "artifacts,",
          stats.summary_line())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_smoke())
