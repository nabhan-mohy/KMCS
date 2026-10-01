"""
KMCS job engine (Phase 1 — ``kmcs.core.jobs``)
==============================================

A dependency-aware, finite-state job engine used to orchestrate the KMCS
pipeline: build → corpus import → fuzz → parse → classify → fingerprint →
dedup → reproduce → minimise → finding → report → regression.

This is *real* execution plumbing — no simulation:

* :class:`FunctionExecutor` runs Python callables in threads or processes.
* A dedicated :class:`Executor` subclass contract exists for the future
  ``ProcessExecutor`` that will spawn AFL++/libFuzzer/GDB as actual OS
  processes via :mod:`subprocess` (Phase 2+).
* Every state transition is recorded (:class:`StateTransition`) and can be
  mirrored onto an :class:`kmcs.core.events.EventBus`.

Capabilities
------------
* Finite-state machine with validated transitions (:class:`JobState`).
* DAG dependency graph with cycle detection & topological planning
  (:class:`DependencyGraph`, :class:`JobPlan`).
* Retries with exponential/polynomial backoff + jitter (:class:`RetryPolicy`,
  :class:`BackoffPolicy`).
* Cooperative cancellation tokens, registries and scoped cancellation
  (:class:`Cancellation`, :class:`CancellationRegistry`,
  :class:`CancellationScope`, :class:`CancellationError`).
* Resource accounting with leases (:class:`ResourceManager`, :class:`Lease`).
* Progress reporting (:class:`Progress`).
* Priority scheduling and pluggable executors (:class:`JobPriority`,
  :class:`Executor`, :class:`FunctionExecutor`, :class:`NoExecutorAvailable`).

Everything is offline and key-free by construction.
"""

from __future__ import annotations

import abc
import concurrent.futures as _cf
import contextlib
import dataclasses
import enum
import fnmatch
import hashlib
import itertools
import json
import math
import os
import random
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    Union,
)

from kmcs.core.exceptions import (
    JobError,
    ResourceError,
    PolicyViolationError,
)
from kmcs.core.models import JobStateName

__all__ = [
    "BackoffPolicy",
    "CancellationError",
    "CancellationRegistry",
    "CancellationScope",
    "Cancellation",
    "DependencyGraph",
    "ExecutionRecord",
    "Executor",
    "FunctionExecutor",
    "JobBuilder",
    "JobDefinition",
    "JobKind",
    "JobPlan",
    "JobPriority",
    "JobResult",
    "JobState",
    "JobView",
    "Lease",
    "NoExecutorAvailable",
    "Progress",
    "RetryPolicy",
    "ResourceManager",
    "StateTransition",
    "WorkItem",
]

# --------------------------------------------------------------------------- #
# Small shared helpers
# --------------------------------------------------------------------------- #

_ids = itertools.count(1)


def _new_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix}-{stamp}-{next(_ids):06d}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _monotonic() -> float:
    return time.monotonic()


# --------------------------------------------------------------------------- #
# Job taxonomy & state machine
# --------------------------------------------------------------------------- #

class JobKind(str, enum.Enum):
    """Canonical pipeline stages KMCS schedules as jobs."""

    PROBE_TOOLCHAIN = "probe_toolchain"
    BUILD_TARGET = "build_target"
    IMPORT_CORPUS = "import_corpus"
    VALIDATE_CORPUS = "validate_corpus"
    FUZZ = "fuzz"
    PARSE_CRASHES = "parse_crashes"
    CLASSIFY = "classify"
    FINGERPRINT = "fingerprint"
    DEDUPLICATE = "deduplicate"
    REPRODUCE = "reproduce"
    MINIMISE = "minimise"
    CREATE_FINDING = "create_finding"
    GENERATE_REPORT = "generate_report"
    ADD_REGRESSION = "add_regression"
    CUSTOM = "custom"

    @property
    def default_priority(self) -> "JobPriority":
        if self in (JobKind.FUZZ, JobKind.REPRODUCE):
            return JobPriority.HIGH
        if self in (JobKind.GENERATE_REPORT, JobKind.ADD_REGRESSION):
            return JobPriority.LOW
        return JobPriority.NORMAL


class JobState(str, enum.Enum):
    """Finite-state machine states for a scheduled job.

    Mirrors :class:`kmcs.core.models.JobStateName` (domain vocabulary) while
    owning the *transition rules* needed by the scheduler.
    """

    CREATED = "created"
    PENDING = "pending"          # deps satisfied, waiting for capacity
    RUNNING = "running"
    PAUSED = "paused"
    RETRYING = "retrying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    BLOCKED = "blocked"          # unsatisfiable / failed dependency

    # -- terminality ---------------------------------------------------------
    def is_terminal(self) -> bool:
        return self in (JobState.SUCCEEDED, JobState.FAILED,
                        JobState.CANCELLED, JobState.TIMED_OUT)

    def is_active(self) -> bool:
        return self in (JobState.RUNNING, JobState.PAUSED, JobState.RETRYING)

    # -- transition rules -------------------------------------------------------
    # The actual table lives in the module-level _JOB_TRANSITIONS dict below
    # (Python enums forbid reassigning class attributes after member creation).
    def can_transition_to(self, target: "JobState") -> bool:
        return target in _JOB_TRANSITIONS[self]

    def allowed_transitions(self) -> Tuple["JobState", ...]:
        return _JOB_TRANSITIONS[self]

    @classmethod
    def from_domain(cls, name: Union[JobStateName, str]) -> "JobState":
        value = name.value if isinstance(name, JobStateName) else str(name)
        alias = {
            "queued": cls.PENDING.value, "waiting": cls.PENDING.value,
            "done": cls.SUCCEEDED.value, "error": cls.FAILED.value,
            "aborted": cls.CANCELLED.value,
        }.get(value, value)
        try:
            return cls(alias)
        except ValueError as exc:
            raise JobError(f"unknown job state {name!r}") from exc

    def to_domain(self) -> JobStateName:
        try:
            return JobStateName(self.value)
        except ValueError:
            return JobStateName.CREATED


#: External transition table (enums forbid reassigning class attributes).
_JOB_TRANSITIONS: Dict[JobState, Tuple[JobState, ...]] = {
    JobState.CREATED: (JobState.PENDING, JobState.BLOCKED, JobState.CANCELLED),
    JobState.PENDING: (JobState.RUNNING, JobState.BLOCKED, JobState.CANCELLED),
    JobState.RUNNING: (JobState.SUCCEEDED, JobState.FAILED, JobState.RETRYING,
                       JobState.CANCELLED, JobState.TIMED_OUT, JobState.PAUSED),
    JobState.PAUSED: (JobState.RUNNING, JobState.CANCELLED),
    JobState.RETRYING: (JobState.PENDING, JobState.RUNNING, JobState.FAILED,
                        JobState.CANCELLED),
    JobState.SUCCEEDED: (),
    JobState.FAILED: (JobState.RETRYING,),   # manual re-drive only
    JobState.CANCELLED: (),
    JobState.TIMED_OUT: (JobState.RETRYING, JobState.FAILED),
    JobState.BLOCKED: (JobState.PENDING,),   # unblocks when dep later succeeds
}


@dataclass(frozen=True)
class StateTransition:
    """Audited record of one state change."""

    job_id: str
    frm: JobState
    to: JobState
    at: float
    reason: str = ""
    attempt: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"job_id": self.job_id, "from": self.frm.value,
                "to": self.to.value, "at": self.at, "reason": self.reason,
                "attempt": self.attempt}

    def __str__(self) -> str:
        return (f"{self.job_id}: {self.frm.value} -> {self.to.value}"
                + (f" ({self.reason})" if self.reason else ""))


class JobPriority(enum.IntEnum):
    """Higher integer == scheduled first on ties (documented deliberately)."""

    LOWEST = 0
    LOW = 25
    NORMAL = 50
    HIGH = 75
    CRITICAL = 100

    @classmethod
    def coerce(cls, value: Union[int, str, "JobPriority"]) -> "JobPriority":
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls[value.upper()]
            except KeyError:
                value = int(value)
        for member in sorted(cls, reverse=True):
            if int(value) >= member.value:
                return member
        return cls.LOWEST


# --------------------------------------------------------------------------- #
# Cancellation
# --------------------------------------------------------------------------- #

class CancellationError(JobError):
    """Raised inside a job body when its token has been cancelled."""


class Cancellation:
    """Cooperative cancellation token (thread-safe, hierarchical).

    A token may have children; cancelling a parent cascades.  Job bodies
    should poll :attr:`cancelled` or call :meth:`raise_if_cancelled` at safe
    points, and register callbacks for immediate wake-ups (e.g. killing a
    subprocess).
    """

    def __init__(self, name: str = "", *, parent: Optional["Cancellation"] = None) -> None:
        self.name = name or _new_id("cancel")
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: List[Callable[[], None]] = []
        self._children: List["Cancellation"] = []
        self._parent = parent
        self.reason = ""
        self.cancelled_at: Optional[float] = None
        if parent is not None:
            parent._adopt(self)

    def _adopt(self, child: "Cancellation") -> None:
        with self._lock:
            self._children.append(child)
            if self._event.is_set():
                cascade = True
            else:
                cascade = False
        if cascade:
            child.cancel(self.reason or "parent-cancelled")

    # -- state -----------------------------------------------------------------
    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self, reason: str = "cancelled") -> bool:
        """Cancel this token and every descendant. Returns True if newly set."""
        with self._lock:
            already = self._event.is_set()
            if not already:
                self.reason = reason
                self.cancelled_at = _monotonic()
                cbs = list(self._callbacks)
                kids = list(self._children)
                self._event.set()
        if already:
            return False
        for cb in cbs:
            with contextlib.suppress(Exception):
                cb()
        for kid in kids:
            kid.cancel(reason=f"cascaded:{reason}")
        return True

    def then(self, callback: Callable[[], None]) -> None:
        """Run *callback* now if already cancelled, else on cancellation."""
        with self._lock:
            if self._event.is_set():
                fire_now = True
            else:
                self._callbacks.append(callback)
                fire_now = False
        if fire_now:
            with contextlib.suppress(Exception):
                callback()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise CancellationError(f"job cancelled: {self.reason}",
                                    context={"token": self.name})

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._event.wait(timeout)

    def child(self, name: str = "") -> "Cancellation":
        return Cancellation(name=name, parent=self)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Cancellation {self.name} {'CANCELLED' if self.cancelled else 'armed'}>"


class CancellationRegistry:
    """Named registry of live tokens so external actors (CLI Ctrl-C, GUI stop)
    can cancel by job id, tag pattern, or globally."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_job: Dict[str, Cancellation] = {}
        self._by_name: Dict[str, Cancellation] = {}

    def register(self, job_id: str, token: Cancellation) -> None:
        with self._lock:
            self._by_job[job_id] = token
            self._by_name[token.name] = token

    def unregister(self, job_id: str) -> None:
        with self._lock:
            token = self._by_job.pop(job_id, None)
            if token is not None:
                self._by_name.pop(token.name, None)

    def get(self, job_id: str) -> Optional[Cancellation]:
        with self._lock:
            return self._by_job.get(job_id)

    def cancel(self, job_id: str, reason: str = "requested") -> bool:
        token = self.get(job_id)
        if token is None:
            return False
        return token.cancel(reason)

    def cancel_matching(self, pattern: str, reason: str = "pattern") -> int:
        """Cancel every registered job whose id matches a glob *pattern*."""
        with self._lock:
            targets = [t for jid, t in self._by_job.items()
                       if fnmatch.fnmatch(jid, pattern)]
        count = 0
        for tok in targets:
            if tok.cancel(reason):
                count += 1
        return count

    def cancel_all(self, reason: str = "shutdown") -> int:
        with self._lock:
            tokens = list(self._by_job.values())
        n = 0
        for tok in tokens:
            if tok.cancel(reason):
                n += 1
        return n

    def live_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._by_job.values() if not t.cancelled)


@contextlib.contextmanager
def CancellationScope(registry: Optional[CancellationRegistry] = None,
                      name: str = "") -> Iterator[Cancellation]:
    """Scoped token: cancels itself (and children) on exception/exit-by-default.

    Usage::

        with CancellationScope() as tok:
            run_long_thing(tok)     # exits early if user stops the block
    """
    token = Cancellation(name=name or _new_id("scope"))
    reg = registry
    key = token.name
    if reg is not None:
        reg.register(key, token)
    completed = False
    try:
        yield token
        completed = True
    finally:
        if reg is not None:
            reg.unregister(key)
        if not completed:
            token.cancel("scope-exit")
        else:
            # normal exit: disarm children still attached? keep simple: cancel
            token.cancel("scope-complete")


# --------------------------------------------------------------------------- #
# Retry / backoff
# --------------------------------------------------------------------------- #

class BackoffPolicy(str, enum.Enum):
    """How the delay between attempts grows."""

    FIXED = "fixed"
    EXPONENTIAL = "exponential"
    POLYNOMIAL = "polynomial"
    LINEAR = "linear"
    DECORRELATED_JITTER = "decorrelated-jitter"

    def delay(self, attempt: int, base: float, maximum: float,
              rng: Optional[random.Random] = None,
              previous_delay: Optional[float] = None) -> float:
        """Compute the sleep before attempt number ``attempt`` (1-based)."""
        r = rng or random
        if attempt <= 0:
            return 0.0
        if self is BackoffPolicy.FIXED:
            raw = base
        elif self is BackoffPolicy.LINEAR:
            raw = base * attempt
        elif self is BackoffPolicy.POLYNOMIAL:
            raw = base * (attempt ** 2)
        elif self is BackoffPolicy.EXPONENTIAL:
            raw = base * (2 ** (attempt - 1))
        else:  # decorrelated jitter (AWS-style)
            prev = previous_delay if previous_delay is not None else base
            raw = min(maximum, r.uniform(base, prev * 3))
        return max(0.0, min(raw, maximum))

    def full_jitter(self, delay_seconds: float,
                    rng: Optional[random.Random] = None) -> float:
        r = rng or random
        return r.uniform(0.0, delay_seconds)


@dataclass(frozen=True)
class RetryPolicy:
    """Attempt budget + growth schedule + error filtering."""

    max_attempts: int = 3
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 60.0
    policy: BackoffPolicy = BackoffPolicy.EXPONENTIAL
    jitter: bool = True
    retry_on: Tuple[str, ...] = ()       # exception class names; empty = all
    never_retry_on: Tuple[str, ...] = (
        "CancellationError", "PolicyViolationError", "ProhibitedCapabilityError",
    )
    seed: Optional[int] = None

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise JobError("max_attempts must be >= 1")
        if self.base_delay_seconds < 0 or self.max_delay_seconds < 0:
            raise JobError("delays must be non-negative")
        if self.base_delay_seconds > self.max_delay_seconds:
            raise JobError("base_delay_seconds exceeds max_delay_seconds")

    #: singleton shortcuts
    NO_RETRY = None  # filled after class body

    def should_retry(self, exc: BaseException, attempt: int) -> bool:
        if attempt >= self.max_attempts:
            return False
        if isinstance(exc, CancellationError):
            return False
        names = {type(exc).__name__, *(c.__name__ for c in type(exc).__mro__)}
        if names & set(self.never_retry_on):
            return False
        if self.retry_on and not (names & set(self.retry_on)):
            return False
        return True

    def delay_before(self, attempt: int,
                     previous: Optional[float] = None) -> float:
        rng = random.Random(self.seed + attempt) if self.seed is not None else random
        d = self.policy.delay(attempt, self.base_delay_seconds,
                              self.max_delay_seconds, rng=rng,
                              previous_delay=previous)
        if self.jitter:
            d = self.policy.full_jitter(d, rng) if previous is None else d
        return d

    def describe(self) -> str:
        return (f"{self.max_attempts} attempts, {self.policy.value} "
                f"base={self.base_delay_seconds}s max={self.max_delay_seconds}s "
                f"jitter={self.jitter}")


RetryPolicy.NO_RETRY = RetryPolicy(max_attempts=1)


# --------------------------------------------------------------------------- #
# Progress
# --------------------------------------------------------------------------- #

class Progress:
    """Thread-safe progress meter supporting absolute counts or fractions.

    ``update(+0.1)`` style deltas and ``set(0.42)`` absolute updates both work;
    listeners receive ``(value, total, label)`` triples and are isolated from
    each other's exceptions.
    """

    def __init__(self, total: float = 1.0, *, label: str = "") -> None:
        if total <= 0:
            raise JobError("Progress total must be positive")
        self.total = float(total)
        self.value = 0.0
        self.label = label
        self.started_at = _monotonic()
        self.finished_at: Optional[float] = None
        self._lock = threading.Lock()
        self._listeners: List[Callable[[float, float, str], None]] = []

    def add_listener(self, cb: Callable[[float, float, str], None]) -> None:
        with self._lock:
            self._listeners.append(cb)

    def update(self, delta: float) -> float:
        with self._lock:
            self.value = max(0.0, min(self.total, self.value + delta))
            v, t, lbl = self.value, self.total, self.label
            listeners = list(self._listeners)
            done = self.value >= self.total
            if done and self.finished_at is None:
                self.finished_at = _monotonic()
        for cb in listeners:
            with contextlib.suppress(Exception):
                cb(v, t, lbl)
        return v

    def set(self, absolute: float) -> float:
        with self._lock:
            current = self.value
        return self.update(absolute - current)

    def fraction(self) -> float:
        with self._lock:
            return self.value / self.total if self.total else 1.0

    def rate_per_second(self) -> float:
        elapsed = (self.finished_at or _monotonic()) - self.started_at
        return self.value / elapsed if elapsed > 0 else 0.0

    def eta_seconds(self) -> Optional[float]:
        remaining = self.total - self.value
        rate = self.rate_per_second()
        if rate <= 0:
            return None
        return remaining / rate

    def snapshot(self) -> Dict[str, Any]:
        return {
            "label": self.label, "value": self.value, "total": self.total,
            "fraction": round(self.fraction(), 6),
            "rate": round(self.rate_per_second(), 6),
            "eta": self.eta_seconds(),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Progress {self.label} {self.value}/{self.total}>"


# --------------------------------------------------------------------------- #
# Resources & leases
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Lease:
    """A granted resource reservation with expiry & release semantics."""

    lease_id: str
    resource: str
    amount: float
    job_id: str
    granted_at: float
    ttl_seconds: Optional[float] = None
    released: bool = False
    revoked_reason: str = ""

    def expired(self, now: Optional[float] = None) -> bool:
        if self.ttl_seconds is None or self.released:
            return False
        return (now or _monotonic()) - self.granted_at > self.ttl_seconds

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class NoExecutorAvailable(JobError):
    """Raised when no registered executor can accept a job."""


class ResourceManager:
    """Counting semaphores for named resources (cores, shmem slots, GPUs…).

    Jobs request amounts; grants produce :class:`Lease` objects.  Leases expire
    (optional TTL) or are explicitly released; acquisition can block with a
    deadline or fail fast.  Prevents campaign oversubscription of the host.
    """

    def __init__(self) -> None:
        self._lock = threading.Condition()
        self._capacity: Dict[str, float] = {}
        self._used: Dict[str, float] = defaultdict(float)
        self._leases: Dict[str, Lease] = {}
        self._waiters = 0

    # -- topology ----------------------------------------------------------------
    def declare(self, resource: str, capacity: float) -> None:
        if capacity < 0:
            raise ResourceError(f"capacity for {resource!r} must be >= 0")
        with self._lock:
            self._capacity[resource] = float(capacity)
            self._lock.notify_all()

    def capacities(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._capacity)

    def available(self, resource: str) -> float:
        self._expire_due()
        with self._lock:
            cap = self._capacity.get(resource)
            if cap is None:
                raise ResourceError(f"undeclared resource {resource!r}")
            return max(0.0, cap - self._used[resource])

    # -- acquire/release -------------------------------------------------------------
    def acquire(self, resource: str, amount: float, *, job_id: str = "",
                timeout: Optional[float] = None,
                ttl_seconds: Optional[float] = None) -> Lease:
        if amount <= 0:
            raise ResourceError("acquire amount must be positive")
        self._expire_due()
        deadline = None if timeout is None else _monotonic() + timeout
        with self._lock:
            if resource not in self._capacity:
                raise ResourceError(
                    f"resource {resource!r} not declared; "
                    f"known: {sorted(self._capacity)}")
            self._waiters += 1
            try:
                while self._used[resource] + amount > self._capacity[resource]:
                    if deadline is None:
                        self._lock.wait(0.25)
                    else:
                        remaining = deadline - _monotonic()
                        if remaining <= 0:
                            raise ResourceError(
                                f"timeout acquiring {amount} of {resource!r} "
                                f"(used={self._used[resource]:g}/"
                                f"cap={self._capacity[resource]:g})",
                                context={"resource": resource, "job_id": job_id},
                            )
                        self._lock.wait(min(0.25, remaining))
                lease = Lease(lease_id=_new_id("lease"), resource=resource,
                              amount=float(amount), job_id=job_id,
                              granted_at=_monotonic(), ttl_seconds=ttl_seconds)
                self._used[resource] += amount
                self._leases[lease.lease_id] = lease
                return lease
            finally:
                self._waiters -= 1

    def release(self, lease_id: str) -> bool:
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None or lease.released:
                return False
            self._used[lease.resource] = max(
                0.0, self._used[lease.resource] - lease.amount)
            self._leases[lease_id] = dataclasses.replace(lease, released=True)
            self._lock.notify_all()
            return True

    def revoke_for_job(self, job_id: str, reason: str = "job-ended") -> int:
        with self._lock:
            mine = [l for l in self._leases.values()
                    if l.job_id == job_id and not l.released]
        n = 0
        for lease in mine:
            if self.release(lease.lease_id):
                n += 1
        return n

    def _expire_due(self) -> None:
        now = _monotonic()
        with self._lock:
            due = [l for l in self._leases.values()
                   if not l.released and l.expired(now)]
        for lease in due:
            self.release(lease.lease_id)

    def snapshot(self) -> Dict[str, Any]:
        self._expire_due()
        with self._lock:
            return {
                "capacity": dict(self._capacity),
                "used": dict(self._used),
                "live_leases": sum(1 for l in self._leases.values()
                                   if not l.released),
                "waiters": self._waiters,
            }

    @contextlib.contextmanager
    def hold(self, resource: str, amount: float, *, job_id: str = "",
             timeout: Optional[float] = None,
             ttl_seconds: Optional[float] = None) -> Iterator[Lease]:
        lease = self.acquire(resource, amount, job_id=job_id, timeout=timeout,
                             ttl_seconds=ttl_seconds)
        try:
            yield lease
        finally:
            self.release(lease.lease_id)


# --------------------------------------------------------------------------- #
# Job definitions & views
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class JobDefinition:
    """Immutable description of schedulable work."""

    id: str
    kind: JobKind
    name: str = ""
    depends_on: Tuple[str, ...] = ()
    priority: JobPriority = JobPriority.NORMAL
    retry: RetryPolicy = field(default_factory=lambda: RetryPolicy())
    requires: Tuple[Tuple[str, float], ...] = ()   # (resource, amount) pairs
    timeout_seconds: Optional[float] = None
    tags: Tuple[str, ...] = ()
    payload: Mapping[str, Any] = field(default_factory=dict)
    executor_hint: str = ""
    created_at: datetime = field(default_factory=_utcnow)
    #: callable spec for FunctionExecutor: dotted module path or picklable fn
    entrypoint: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.id:
            raise JobError("job id must be non-empty")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise JobError(f"duplicate dependencies in job {self.id}")
        if self.id in self.depends_on:
            raise JobError(f"job {self.id} depends on itself")
        if not isinstance(self.kind, JobKind):
            raise JobError("kind must be a JobKind")
        for res, amt in self.requires:
            if amt <= 0:
                raise JobError(f"job {self.id}: requirement {res!r} amount must be > 0")

    @property
    def display_name(self) -> str:
        return self.name or f"{self.kind.value}:{self.id}"

    def resource_requirements(self) -> Dict[str, float]:
        merged: Dict[str, float] = defaultdict(float)
        for res, amt in self.requires:
            merged[res] += amt
        return dict(merged)

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["kind"] = self.kind.value
        d["priority"] = int(self.priority)
        d["retry"] = dataclasses.asdict(self.retry)
        d["requires"] = [list(r) for r in self.requires]
        d["created_at"] = self.created_at.isoformat()
        return d


@dataclass
class ExecutionRecord:
    """One attempt outcome (success or failure) for audit & telemetry."""

    job_id: str
    attempt: int
    started_at: float
    finished_at: float
    state: JobState
    duration_seconds: float
    error: Optional[str] = None
    error_type: Optional[str] = None
    result_digest: str = ""
    executor: str = ""
    log_tail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class JobResult:
    """Terminal outcome handed back to callers/waiters."""

    job_id: str
    state: JobState
    value: Any = None
    error: Optional[BaseException] = None
    attempts: int = 1
    started_at: float = 0.0
    finished_at: float = 0.0
    history: Tuple[ExecutionRecord, ...] = ()

    @property
    def ok(self) -> bool:
        return self.state is JobState.SUCCEEDED

    @property
    def duration(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    def unwrap(self) -> Any:
        """Return value or raise the captured error (caller-friendly)."""
        if self.error is not None:
            raise self.error
        if not self.ok:
            raise JobError(f"job {self.job_id} ended in {self.state.value}",
                           context={"attempts": self.attempts})
        return self.value

    def summary(self) -> str:
        line = f"{self.job_id}: {self.state.value} ({self.duration:.3f}s, {self.attempts} attempt(s))"
        if self.error:
            line += f" error={type(self.error).__name__}: {self.error}"
        return line


@dataclass(frozen=True)
class JobView:
    """Read-only projection of live scheduler state for UIs/CLIs."""

    definition: JobDefinition
    state: JobState
    attempts: int
    progress: Dict[str, Any]
    last_error: Optional[str]
    updated_at: float
    transitions: Tuple[StateTransition, ...] = ()
    running_since: Optional[float] = None

    @property
    def job_id(self) -> str:
        return self.definition.id

    def elapsed(self) -> Optional[float]:
        if self.running_since is None:
            return None
        return _monotonic() - self.running_since

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.job_id, "kind": self.definition.kind.value,
            "name": self.definition.display_name, "state": self.state.value,
            "attempts": self.attempts, "progress": self.progress,
            "last_error": self.last_error, "updated_at": self.updated_at,
            "transitions": [t.to_dict() for t in self.transitions],
        }


class WorkItem:
    """Internal scheduler envelope pairing a definition with runtime state."""

    __slots__ = ("definition", "state", "attempts", "progress", "history",
                 "last_error", "updated_at", "transitions", "running_since",
                 "result", "done_event", "cancellation", "held_leases",
                 "dependents", "unmet", "scheduled_once")

    def __init__(self, definition: JobDefinition) -> None:
        self.definition = definition
        self.state = JobState.CREATED
        self.attempts = 0
        self.progress = Progress(total=1.0, label=definition.display_name)
        self.history: List[ExecutionRecord] = []
        self.last_error: Optional[str] = None
        self.updated_at = time.time()
        self.transitions: List[StateTransition] = []
        self.running_since: Optional[float] = None
        self.result: Optional[JobResult] = None
        self.done_event = threading.Event()
        self.cancellation = Cancellation(name=f"job-{definition.id}")
        self.held_leases: List[str] = []
        self.dependents: List[str] = []
        self.unmet: Set[str] = set(definition.depends_on)
        self.scheduled_once = False

    # -- state mutation ------------------------------------------------------------
    def transition(self, to: JobState, reason: str = "") -> StateTransition:
        if not self.state.can_transition_to(to):
            raise JobError(
                f"illegal transition {self.state.value} -> {to.value} "
                f"for job {self.definition.id}")
        tr = StateTransition(job_id=self.definition.id, frm=self.state, to=to,
                             at=time.time(), reason=reason,
                             attempt=self.attempts)
        self.state = to
        self.updated_at = tr.at
        self.transitions.append(tr)
        if to is JobState.RUNNING:
            self.running_since = _monotonic()
        elif to.is_terminal():
            self.running_since = None
        return tr

    def view(self) -> JobView:
        return JobView(definition=self.definition, state=self.state,
                       attempts=self.attempts,
                       progress=self.progress.snapshot(),
                       last_error=self.last_error, updated_at=self.updated_at,
                       transitions=tuple(self.transitions),
                       running_since=self.running_since)

    def finish(self, result: JobResult) -> None:
        self.result = result
        self.done_event.set()


# --------------------------------------------------------------------------- #
# Dependency graph & plan
# --------------------------------------------------------------------------- #

class DependencyGraph:
    """Directed acyclic job-dependency graph.

    Supports incremental insertion, cycle detection (DFS colouring with the
    offending cycle reported), Kahn topological sort with deterministic
    ordering ((−priority, id)), levelisation for parallel waves, and queries
    used by the scheduler (:meth:`ready`, :meth:`blockers`).
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, JobDefinition] = {}
        self._deps: Dict[str, Set[str]] = {}          # node -> prerequisites
        self._rdeps: Dict[str, Set[str]] = defaultdict(set)  # node -> dependents

    # -- mutation -----------------------------------------------------------------
    def add(self, definition: JobDefinition) -> None:
        if definition.id in self._nodes:
            raise JobError(f"duplicate job id {definition.id!r}")
        self._nodes[definition.id] = definition
        self._deps[definition.id] = set(definition.depends_on)
        for dep in definition.depends_on:
            self._rdeps[dep].add(definition.id)

    def remove(self, job_id: str) -> None:
        definition = self._nodes.pop(job_id, None)
        if definition is None:
            return
        for dep in self._deps.pop(job_id, set()):
            self._rdeps.get(dep, set()).discard(job_id)
        # orphan-check: anything depending on removed node keeps a dangling dep
        # which validate() will surface as unknown-dependency.

    # -- queries --------------------------------------------------------------------
    def nodes(self) -> Dict[str, JobDefinition]:
        return dict(self._nodes)

    def dependencies_of(self, job_id: str) -> Set[str]:
        return set(self._deps.get(job_id, set()))

    def dependents_of(self, job_id: str) -> Set[str]:
        return set(self._rdeps.get(job_id, set()))

    def validate(self) -> List[str]:
        """Return human-readable structural problems (empty == OK)."""
        problems: List[str] = []
        for nid, deps in self._deps.items():
            for d in sorted(deps):
                if d not in self._nodes:
                    problems.append(f"job {nid!r} depends on unknown job {d!r}")
        cycle = self.find_cycle()
        if cycle:
            problems.append("dependency cycle: " + " -> ".join(cycle))
        return problems

    # -- cycles ------------------------------------------------------------------------
    def find_cycle(self) -> Optional[List[str]]:
        WHITE, GREY, BLACK = 0, 1, 2
        colour: Dict[str, int] = {n: WHITE for n in self._nodes}
        stack: List[str] = []

        def dfs(node: str) -> Optional[List[str]]:
            colour[node] = GREY
            stack.append(node)
            for dep in sorted(self._deps.get(node, ())):
                if dep not in colour:      # unknown dep handled by validate()
                    continue
                if colour[dep] == GREY:
                    idx = stack.index(dep)
                    return stack[idx:] + [dep]
                if colour[dep] == WHITE:
                    found = dfs(dep)
                    if found:
                        return found
            stack.pop()
            colour[node] = BLACK
            return None

        for n in sorted(self._nodes):
            if colour[n] == WHITE:
                found = dfs(n)
                if found:
                    return found
        return None

    def is_dag(self) -> bool:
        return self.find_cycle() is None

    # -- ordering ------------------------------------------------------------------------
    def topo_order(self) -> List[str]:
        """Kahn's algorithm; deterministic tie-break by (-priority, id)."""
        indeg = {n: len(self._deps.get(n, set()) & set(self._nodes))
                 for n in self._nodes}
        ready = sorted((n for n, d in indeg.items() if d == 0),
                       key=lambda n: (-self._nodes[n].priority.value, n))
        order: List[str] = []
        while ready:
            node = ready.pop(0)
            order.append(node)
            for child in sorted(self._rdeps.get(node, ())):
                indeg[child] -= 1
                if indeg[child] == 0:
                    ready.append(child)
            ready.sort(key=lambda n: (-self._nodes[n].priority.value, n))
        if len(order) != len(self._nodes):
            cycle = self.find_cycle() or ["?"]
            raise JobError("topological sort failed; graph contains a cycle: "
                           + " -> ".join(cycle))
        return order

    def levels(self) -> List[List[str]]:
        """Group jobs into parallelisable waves (longest-path layering)."""
        order = self.topo_order()
        depth: Dict[str, int] = {}
        for node in order:
            deps = self._deps.get(node, set()) & set(self._nodes)
            depth[node] = (max(depth[d] for d in deps) + 1) if deps else 0
        waves: Dict[int, List[str]] = defaultdict(list)
        for node, lvl in depth.items():
            waves[lvl].append(node)
        return [sorted(waves[i], key=lambda n: (-self._nodes[n].priority.value, n))
                for i in sorted(waves)]

    def ancestors(self, job_id: str) -> Set[str]:
        seen: Set[str] = set()
        frontier = deque(self._deps.get(job_id, ()))
        while frontier:
            cur = frontier.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            frontier.extend(self._deps.get(cur, ()))
        return seen

    def descendants(self, job_id: str) -> Set[str]:
        seen: Set[str] = set()
        frontier = deque(self._rdeps.get(job_id, ()))
        while frontier:
            cur = frontier.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            frontier.extend(self._rdeps.get(cur, ()))
        return seen

    def subgraph(self, root_ids: Iterable[str]) -> "DependencyGraph":
        """Closure over ancestors of *root_ids* (what must run to reach them)."""
        wanted: Set[str] = set()
        for rid in root_ids:
            if rid in self._nodes:
                wanted |= self.ancestors(rid) | {rid}
        out = DependencyGraph()
        for nid in sorted(wanted):
            definition = self._nodes[nid]
            pruned = tuple(d for d in definition.depends_on if d in wanted)
            out.add(dataclasses.replace(definition, depends_on=pruned))
        return out

    def __len__(self) -> int:
        return len(self._nodes)


@dataclass(frozen=True)
class JobPlan:
    """An executable, validated schedule derived from a graph + policies."""

    graph: DependencyGraph
    order: Tuple[str, ...]
    waves: Tuple[Tuple[str, ...], ...]
    digest: str

    @classmethod
    def compile(cls, graph: DependencyGraph) -> "JobPlan":
        problems = graph.validate()
        if problems:
            raise JobError("cannot build plan: " + "; ".join(problems))
        order = tuple(graph.topo_order())
        waves = tuple(tuple(w) for w in graph.levels())
        blob = json.dumps({"order": order,
                           "waves": [list(w) for w in waves]}, sort_keys=True)
        digest = hashlib.sha256(blob.encode()).hexdigest()[:16]
        return cls(graph=graph, order=order, waves=waves, digest=digest)

    def position(self, job_id: str) -> int:
        return self.order.index(job_id)

    def wave_of(self, job_id: str) -> int:
        for i, wave in enumerate(self.waves):
            if job_id in wave:
                return i
        raise JobError(f"{job_id!r} not in plan")

    def describe(self) -> str:
        lines = [f"plan digest={self.digest} jobs={len(self.order)} waves={len(self.waves)}"]
        for i, wave in enumerate(self.waves):
            lines.append(f"  wave {i}: {', '.join(wave)}")
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.describe()


class JobBuilder:
    """Fluent builder producing validated :class:`JobDefinition` objects."""

    def __init__(self, kind: JobKind = JobKind.CUSTOM, *, job_id: Optional[str] = None) -> None:
        self._kind = kind
        self._id = job_id or _new_id(kind.value)
        self._name = ""
        self._deps: List[str] = []
        self._priority = kind.default_priority
        self._retry = RetryPolicy()
        self._requires: List[Tuple[str, float]] = []
        self._timeout: Optional[float] = None
        self._tags: List[str] = []
        self._payload: Dict[str, Any] = {}
        self._entrypoint: Optional[str] = None
        self._executor_hint = ""

    def id(self, value: str) -> "JobBuilder":
        self._id = value
        return self

    def name(self, value: str) -> "JobBuilder":
        self._name = value
        return self

    def depends_on(self, *jobs: str) -> "JobBuilder":
        for j in jobs:
            if j not in self._deps:
                self._deps.append(j)
        return self

    def priority(self, value: Union[int, str, JobPriority]) -> "JobBuilder":
        self._priority = JobPriority.coerce(value)
        return self

    def retries(self, max_attempts: int, *, base: float = 0.5,
                maximum: float = 60.0,
                policy: BackoffPolicy = BackoffPolicy.EXPONENTIAL,
                jitter: bool = True) -> "JobBuilder":
        self._retry = RetryPolicy(max_attempts=max_attempts,
                                  base_delay_seconds=base,
                                  max_delay_seconds=maximum, policy=policy,
                                  jitter=jitter)
        return self

    def requires(self, resource: str, amount: float = 1.0) -> "JobBuilder":
        self._requires.append((resource, float(amount)))
        return self

    def timeout(self, seconds: Optional[float]) -> "JobBuilder":
        self._timeout = seconds
        return self

    def tag(self, *tags: str) -> "JobBuilder":
        self._tags.extend(t for t in tags if t not in self._tags)
        return self

    def payload(self, **kw: Any) -> "JobBuilder":
        self._payload.update(kw)
        return self

    def entrypoint(self, dotted: str) -> "JobBuilder":
        self._entrypoint = dotted
        return self

    def executor(self, hint: str) -> "JobBuilder":
        self._executor_hint = hint
        return self

    def build(self) -> JobDefinition:
        return JobDefinition(
            id=self._id, kind=self._kind, name=self._name,
            depends_on=tuple(self._deps), priority=self._priority,
            retry=self._retry, requires=tuple(self._requires),
            timeout_seconds=self._timeout, tags=tuple(self._tags),
            payload=dict(self._payload), entrypoint=self._entrypoint,
            executor_hint=self._executor_hint,
        )


# --------------------------------------------------------------------------- #
# Executors
# --------------------------------------------------------------------------- #

class Executor(abc.ABC):
    """Abstract execution backend for job bodies.

    Concrete subclasses decide *how* work runs (thread pool, process pool,
    subprocess launch of afl-fuzz, …).  Implementations MUST honour the
    cancellation token and MUST NOT fabricate results: if the underlying
    facility is missing, raise (the scheduler records the honest failure).
    """

    name: str = "executor"

    def __init__(self, *, accepts: Optional[Iterable[JobKind]] = None,
                 max_concurrency: int = 4) -> None:
        self.accepts = frozenset(accepts) if accepts is not None else None
        self.max_concurrency = max(1, int(max_concurrency))
        self._sem = threading.Semaphore(self.max_concurrency)
        self.completed = 0
        self.failed = 0

    def can_run(self, definition: JobDefinition) -> bool:
        if self.accepts is None:
            return True
        return definition.kind in self.accepts

    @abc.abstractmethod
    def _execute(self, definition: JobDefinition, cancellation: Cancellation,
                 progress: Progress) -> Any:
        ...

    def execute(self, definition: JobDefinition, cancellation: Cancellation,
                progress: Progress) -> Any:
        if not self.can_run(definition):
            raise NoExecutorAvailable(
                f"executor {self.name!r} does not accept kind "
                f"{definition.kind.value!r}",
                context={"job_id": definition.id})
        with self._sem:
            cancellation.raise_if_cancelled()
            try:
                value = self._execute(definition, cancellation, progress)
                self.completed += 1
                return value
            except Exception:
                self.failed += 1
                raise

    def stats(self) -> Dict[str, Any]:
        return {"name": self.name, "completed": self.completed,
                "failed": self.failed, "max_concurrency": self.max_concurrency}

    def shutdown(self) -> None:
        return None


class FunctionExecutor(Executor):
    """Runs Python callables supplied through ``payload['fn']`` or resolved
    from ``entrypoint`` (``module:attribute``). Thread or process mode.

    * thread mode shares interpreter state — good for DB/report steps;
    * process mode isolates CPU-heavy analysis and enforces wall-clock
      timeouts via :mod:`concurrent.futures` (worker killed on timeout best
      effort; the *job* is marked TIMED_OUT honestly).
    """

    def __init__(self, *, mode: str = "thread", max_workers: int = 8,
                 name: str = "functions") -> None:
        super().__init__(max_concurrency=max_workers)
        if mode not in ("thread", "process"):
            raise JobError(f"bad FunctionExecutor mode {mode!r}")
        self.mode = mode
        self.name = name
        factory = (_cf.ThreadPoolExecutor if mode == "thread"
                   else _cf.ProcessPoolExecutor)
        self._pool = factory(max_workers=max_workers)  # type: ignore[operator]

    def _resolve(self, definition: JobDefinition) -> Callable[..., Any]:
        fn = definition.payload.get("fn")
        if callable(fn):
            return fn
        target = definition.entrypoint
        if not target:
            raise JobError(
                f"job {definition.id}: FunctionExecutor needs payload['fn'] "
                f"or an entrypoint 'module:function'")
        mod_name, sep, attr = target.partition(":")
        if not sep:
            raise JobError(f"bad entrypoint {target!r}; expected 'module:attr'")
        import importlib
        module = importlib.import_module(mod_name)
        obj = module
        for part in attr.split("."):
            obj = getattr(obj, part)
        if not callable(obj):
            raise JobError(f"entrypoint {target!r} is not callable")
        return obj

    def _execute(self, definition: JobDefinition, cancellation: Cancellation,
                 progress: Progress) -> Any:
        fn = self._resolve(definition)
        kwargs = {k: v for k, v in definition.payload.items()
                  if k not in ("fn",)}
        call_kwargs = dict(kwargs)
        sig_needs_ctx = True
        # Inject context args only if the function tolerates them.
        try:
            import inspect
            params = inspect.signature(fn).parameters
            call_kwargs = {}
            for key, value in kwargs.items():
                call_kwargs[key] = value
            sig_needs_ctx = ("cancellation" in params or "progress" in params
                             or any(p.kind == p.VAR_KEYWORD for p in params.values()))
        except (TypeError, ValueError):
            sig_needs_ctx = False
        if sig_needs_ctx:
            call_kwargs.setdefault("cancellation", cancellation)
            call_kwargs.setdefault("progress", progress)

        future = self._pool.submit(fn, **call_kwargs)
        cancellation.then(lambda: future.cancel())
        try:
            if definition.timeout_seconds:
                result = future.result(timeout=definition.timeout_seconds)
            else:
                while not future.done():
                    if cancellation.wait(0.05):
                        future.cancel()
                        raise CancellationError(
                            f"job {definition.id} cancelled",
                            context={"job_id": definition.id})
                    time.sleep(0.01)
                result = future.result()
        except _cf.TimeoutError as exc:
            raise TimeoutError(
                f"job {definition.id} exceeded {definition.timeout_seconds}s") from exc
        except CancellationError:
            raise
        except concurrent_future_error_types() as exc:  # pragma: no cover
            raise JobError(f"job {definition.id} worker crashed: {exc}") from exc
        return result

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def concurrent_future_error_types() -> Tuple[Type[BaseException], ...]:
    return (_cf.CancelledError,)


# NOTE: process-mode FunctionExecutor cannot ship closures; document loudly.
# Real subprocess engines (afl-fuzz etc.) arrive with Phase 3 fuzzers/.


# --------------------------------------------------------------------------- #
# Scheduler / engine
# --------------------------------------------------------------------------- #

class JobEngine:
    """Dependency-aware scheduler wiring graphs, executors, resources,
    cancellation and (optionally) an event bus together.

    Lifecycle per job: CREATED → PENDING (deps met) → RUNNING →
    SUCCEEDED/FAILED/RETRYING/TIMED_OUT/CANCELLED/BLOCKED.  Retries re-enter
    PENDING after the backoff delay.  Failed jobs cascade BLOCKED to their
    transitive dependents (unless ``continue_on_failure``).
    """

    def __init__(self, *, default_executor: Optional[Executor] = None,
                 resources: Optional[ResourceManager] = None,
                 bus: Any = None, continue_on_failure: bool = False,
                 max_inflight: int = 32) -> None:
        self._lock = threading.RLock()
        self._items: Dict[str, WorkItem] = {}
        self._executors: List[Executor] = []
        self.resources = resources or ResourceManager()
        self.bus = bus
        self.continue_on_failure = continue_on_failure
        self.graph = DependencyGraph()
        self.plan: Optional[JobPlan] = None
        self.registry = CancellationRegistry()
        self._max_inflight = max(1, max_inflight)
        self._inflight = 0
        self._cv = threading.Condition(self._lock)
        self._stop = threading.Event()
        self._dispatcher: Optional[threading.Thread] = None
        self._timers: List[threading.Timer] = []
        if default_executor is not None:
            self.register_executor(default_executor)
        self.started_at = time.time()

    # -- registration --------------------------------------------------------------
    def register_executor(self, executor: Executor) -> None:
        with self._lock:
            self._executors.append(executor)

    def add_job(self, definition: JobDefinition) -> JobView:
        with self._lock:
            if definition.id in self._items:
                raise JobError(f"job {definition.id!r} already added")
            item = WorkItem(definition)
            self._items[definition.id] = item
            self.graph.add(definition)
            for dep in definition.depends_on:
                if dep in self._items:
                    self._items[dep].dependents.append(definition.id)
            self.plan = None  # invalidate compiled plan
            self.registry.register(definition.id, item.cancellation)
            self._emit(item, "job_added")
            return item.view()

    def add(self, kind: JobKind) -> JobBuilder:
        return JobBuilder(kind)

    # -- validation / planning ----------------------------------------------------------
    def compile_plan(self) -> JobPlan:
        with self._lock:
            if self.plan is None:
                self.plan = JobPlan.compile(self.graph)
            return self.plan

    def validate(self) -> List[str]:
        return self.graph.validate()

    # -- dispatch loop --------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._dispatcher and self._dispatcher.is_alive():
                return
            self._stop.clear()
            self._dispatcher = threading.Thread(target=self._dispatch_loop,
                                                name="kmcs-job-dispatcher",
                                                daemon=True)
            self._dispatcher.start()

    def submit_all(self) -> int:
        """Move every CREATED job with satisfied deps toward PENDING."""
        submitted = 0
        with self._lock:
            for item in self._items.values():
                if item.state is JobState.CREATED:
                    if item.unmet:
                        item.transition(JobState.CREATED, "noop")  # stays
                    else:
                        item.transition(JobState.PENDING, "submit")
                        submitted += 1
                        self._cv.notify_all()
        return submitted

    def _dispatch_loop(self) -> None:
        while not self._stop.is_set():
            runnable: List[WorkItem] = []
            with self._cv:
                for item in list(self._items.values()):
                    if item.state is JobState.PENDING and not item.scheduled_once:
                        if self._inflight < self._max_inflight:
                            item.scheduled_once = True
                            self._inflight += 1
                            runnable.append(item)
                if not runnable:
                    self._cv.wait(timeout=0.05)
            for item in runnable:
                t = threading.Thread(target=self._run_item, args=(item,),
                                     name=f"kmcs-job-{item.definition.id}",
                                     daemon=True)
                t.start()
            if not runnable:
                time.sleep(0.005)

    # -- picking an executor ------------------------------------------------------------------
    def _pick_executor(self, definition: JobDefinition) -> Executor:
        with self._lock:
            candidates = list(self._executors)
        if definition.executor_hint:
            hinted = [e for e in candidates if e.name == definition.executor_hint]
            if hinted:
                return hinted[0]
        for ex in candidates:
            if ex.can_run(definition):
                return ex
        raise NoExecutorAvailable(
            f"no executor registered for job {definition.id} "
            f"(kind={definition.kind.value})",
            context={"registered": [e.name for e in candidates]})

    # -- the core run/retry machinery -------------------------------------------------------------
    def _run_item(self, item: WorkItem) -> None:
        definition = item.definition
        cancellation = item.cancellation
        started_overall = _monotonic()
        previous_delay: Optional[float] = None
        final_state = JobState.FAILED
        final_value: Any = None
        final_error: Optional[BaseException] = None

        try:
            # resource acquisition (non-blocking first pass w/ short timeout)
            leases: List[Lease] = []
            try:
                for res, amt in definition.resource_requirements().items():
                    lease = self.resources.acquire(res, amt, job_id=definition.id,
                                                   timeout=None)
                    leases.append(lease)
                    item.held_leases.append(lease.lease_id)
            except ResourceError as exc:
                with self._lock:
                    item.transition(JobState.PENDING, f"resource-wait: {exc}")
                    item.scheduled_once = False
                    self._inflight -= 1
                    self._cv.notify_all()
                # requeue shortly
                timer = threading.Timer(0.25, self._requeue, args=(definition.id,))
                timer.daemon = True
                timer.start()
                self._timers.append(timer)
                return

            try:
                with self._lock:
                    if item.state is JobState.PENDING:
                        item.transition(JobState.RUNNING, "start")
                self._emit(item, "job_running")

                attempt = 0
                while True:
                    attempt += 1
                    item.attempts = attempt
                    cancellation.raise_if_cancelled()
                    started = _monotonic()
                    error: Optional[BaseException] = None
                    value: Any = None
                    state = JobState.SUCCEEDED
                    try:
                        executor = self._pick_executor(definition)
                        value = executor.execute(definition, cancellation,
                                                item.progress)
                    except CancellationError as exc:
                        error, state = exc, JobState.CANCELLED
                    except TimeoutError as exc:
                        error, state = exc, JobState.TIMED_OUT
                    except NoExecutorAvailable as exc:
                        error, state = exc, JobState.FAILED
                        break  # configuration problem: retrying won't help
                    except Exception as exc:
                        error, state = exc, JobState.FAILED

                    finished = _monotonic()
                    record = ExecutionRecord(
                        job_id=definition.id, attempt=attempt,
                        started_at=started, finished_at=finished,
                        state=state, duration_seconds=finished - started,
                        error=str(error) if error else None,
                        error_type=type(error).__name__ if error else None,
                        result_digest=(hashlib.sha256(
                            json.dumps(value, sort_keys=True, default=str)
                            .encode()).hexdigest()[:16]
                            if state is JobState.SUCCEEDED else ""),
                        executor=getattr(self, "_last_executor_name", "") or "",
                    )
                    item.history.append(record)

                    if state is JobState.SUCCEEDED:
                        final_state = JobState.SUCCEEDED
                        final_value = value
                        break

                    # retry decision
                    if definition.retry.should_retry(error, attempt):  # type: ignore[arg-type]
                        delay = definition.retry.delay_before(attempt, previous_delay)
                        previous_delay = delay
                        with self._lock:
                            item.transition(JobState.RETRYING,
                                            f"attempt {attempt} failed: {error}; "
                                            f"backoff {delay:.2f}s")
                        self._emit(item, "job_retry",
                                   {"attempt": attempt, "delay": delay})
                        time.sleep(delay)
                        with self._lock:
                            if item.state is JobState.RETRYING:
                                item.transition(JobState.RUNNING, "re-attempt")
                        continue
                    final_state = state
                    final_error = error
                    break
            finally:
                for lease_id in item.held_leases:
                    self.resources.release(lease_id)
                item.held_leases.clear()

            # terminal transition
            with self._lock:
                if cancellation.cancelled and final_state not in (
                        JobState.SUCCEEDED, JobState.CANCELLED):
                    final_state = JobState.CANCELLED
                    final_error = final_error or CancellationError(
                        "cancelled", context={"job_id": definition.id})
                if item.state is not final_state:
                    item.transition(final_state, "terminal")
                item.last_error = str(final_error) if final_error else None
                result = JobResult(job_id=definition.id, state=final_state,
                                   value=final_value, error=final_error,
                                   attempts=item.attempts,
                                   started_at=started_overall,
                                   finished_at=_monotonic(),
                                   history=tuple(item.history))
                item.finish(result)
                self._inflight -= 1
                self._propagate_terminal(item)
                self._cv.notify_all()
            self._emit(item, "job_finished",
                       {"state": final_state.value, "attempts": item.attempts})
            self.registry.unregister(definition.id)
        except JobError:
            # bookkeeping errors during setup — mark failed honestly
            with self._lock:
                try:
                    if not item.state.is_terminal():
                        item.transition(JobState.FAILED, "engine-error")
                except JobError:
                    pass
                item.done_event.set()
                self._inflight -= 1
                self._cv.notify_all()

    def _requeue(self, job_id: str) -> None:
        with self._lock:
            item = self._items.get(job_id)
            if item and item.state is JobState.PENDING:
                item.scheduled_once = False
                self._cv.notify_all()

    def _propagate_terminal(self, item: WorkItem) -> None:
        """On failure/cancel, block dependents transitively (unless continuing)."""
        if item.state in (JobState.SUCCEEDED,):
            # unblock waiting dependents whose dep just succeeded
            for dep_id in item.definition.depends_on:
                dep = self._items.get(dep_id)
                if dep:
                    item.unmet.discard(dep_id)
            if not item.unmet and item.state is JobState.SUCCEEDED:
                for child_id in item.dependents:
                    child = self._items.get(child_id)
                    if child and child.state is JobState.BLOCKED:
                        child.unmet.discard(item.definition.id)
                        if not (child.unmet - {p for p in child.unmet
                                               if self._items.get(p) is None
                                               or self._items[p].state
                                               in (JobState.FAILED,
                                                   JobState.CANCELLED,
                                                   JobState.TIMED_OUT,
                                                   JobState.BLOCKED)}):
                            child.transition(JobState.PENDING, "dep-recovered")
                            self._cv.notify_all()
            return
        if self.continue_on_failure:
            return
        blocked = deque(item.dependents)
        seen: Set[str] = set()
        while blocked:
            cid = blocked.popleft()
            if cid in seen:
                continue
            seen.add(cid)
            child = self._items.get(cid)
            if child is None or child.state.is_terminal():
                continue
            if child.state in (JobState.CREATED, JobState.PENDING,
                               JobState.BLOCKED):
                if child.state is not JobState.BLOCKED:
                    child.transition(JobState.BLOCKED,
                                     f"dependency {item.definition.id} "
                                     f"{item.state.value}")
                blocked.extend(child.dependents)

    # -- public control -------------------------------------------------------------------
    def cancel(self, job_id: str, reason: str = "user-request") -> bool:
        item = self._items.get(job_id)
        if item is None or item.state.is_terminal():
            return False
        return item.cancellation.cancel(reason)

    def wait(self, job_id: Optional[str] = None,
             timeout: Optional[float] = None) -> Optional[JobResult]:
        """Wait for one job (or quiescence) and return its result."""
        if job_id is not None:
            item = self._items.get(job_id)
            if item is None:
                raise JobError(f"unknown job {job_id!r}")
            if not item.done_event.wait(timeout):
                return None
            return item.result
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                pending = [i for i in self._items.values()
                           if not i.state.is_terminal()]
            if not pending:
                return None
            if deadline is not None and time.monotonic() >= deadline:
                return None
            time.sleep(0.01)

    def result(self, job_id: str, timeout: Optional[float] = None) -> JobResult:
        res = self.wait(job_id, timeout)
        if res is None:
            raise JobError(f"job {job_id!r} did not finish within {timeout}s")
        return res

    def status(self, job_id: str) -> JobView:
        item = self._items.get(job_id)
        if item is None:
            raise JobError(f"unknown job {job_id!r}")
        return item.view()

    def all_status(self) -> Tuple[JobView, ...]:
        with self._lock:
            return tuple(i.view() for i in self._items.values())

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_state: Dict[str, int] = defaultdict(int)
            for item in self._items.values():
                by_state[item.state.value] += 1
        return {
            "jobs": len(self._items), "by_state": dict(by_state),
            "inflight": self._inflight, "max_inflight": self._max_inflight,
            "executors": [e.stats() for e in self._executors],
            "resources": self.resources.snapshot(),
            "uptime": _monotonic() - self.started_at,
            "plan": self.plan.digest if self.plan else None,
        }

    def run_foreground(self, timeout: Optional[float] = None) -> Dict[str, JobResult]:
        """Compile plan, start dispatcher, wait for quiescence, return results."""
        self.compile_plan()
        self.start()
        self.submit_all()
        self.wait(None, timeout)
        with self._lock:
            return {jid: i.result for jid, i in self._items.items()
                    if i.result is not None}

    def shutdown(self, cancel_remaining: bool = True) -> None:
        self._stop.set()
        if cancel_remaining:
            self.registry.cancel_all("engine-shutdown")
        for timer in self._timers:
            timer.cancel()
        with self._lock:
            for ex in self._executors:
                ex.shutdown()

    # -- events ----------------------------------------------------------------------
    def _emit(self, item: WorkItem, what: str, extra: Optional[Dict[str, Any]] = None) -> None:
        bus = self.bus
        if bus is None:
            return
        try:
            from kmcs.core.events import EventType, Topic  # local import: avoid cycle
            payload = {
                "job_id": item.definition.id, "kind": item.definition.kind.value,
                "state": item.state.value, "attempts": item.attempts,
                **(extra or {}),
            }
            topic = Topic.build("kmcs", "jobs", item.definition.id, what)
            etype = {
                "job_retry": EventType.JOB_RETRY,
                "job_failed": EventType.JOB_FAILED,
            }.get(what, EventType.JOB_STATE)
            if what == "job_finished" and item.state in (JobState.FAILED,
                                                         JobState.TIMED_OUT):
                etype = EventType.JOB_FAILED
            bus.emit(topic, etype, payload)
        except Exception:  # telemetry must never break scheduling
            pass


# Re-export-friendly aliases (core/__init__ imports these names):
Scheduler = JobEngine
