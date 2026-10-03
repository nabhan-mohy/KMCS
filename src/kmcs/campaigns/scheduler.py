# KMCS Campaign Scheduler
# =======================
#
# Concurrency coordinator for fuzzing workers.
#
# The scheduler owns a single global resource — the number of worker
# slots available for concurrent fuzzing — and hands those slots out
# to requesters according to a configurable policy. It is not a
# fuzzing engine, does not spawn processes, does not know about
# targets or corpora, and does not talk to workers directly. Its only
# job is to answer two questions:
#
#   1. "May this requester run N workers right now?"
#   2. "Which pending requester should get the next free slot?"
#
# A requester is any caller (typically :class:`~kmcs.campaigns.manager.CampaignManager`,
# but potentially also an interactive tool or a test harness) that
# submits a :meth:`Scheduler.submit` request and then waits to be
# granted capacity.
#
# Capacity model
# --------------
#
# The scheduler's capacity is a single integer: ``max_concurrency``.
# Every grant reduces the number of free slots by the number of slots
# granted; every release adds them back. The invariant is:
#
#     granted_total + available == max_concurrency
#
# where ``granted_total`` is the sum of all outstanding grants. The
# scheduler enforces this invariant atomically under its internal
# lock; a violation indicates a bug in the scheduler itself, and is
# reported as an internal error rather than silently tolerated.
#
# A request may be partially granted. For example, if a requester asks
# for four slots and only two are free, the scheduler grants two
# immediately and keeps the request pending for the remaining two.
# Partial grants let the manager start some workers promptly instead of
# waiting for the full set to become available.
#
# Scheduling policies
# -------------------
#
# Three policies are supported out of the box:
#
# FIFO
#     Requests are granted in submission order. Simple and predictable,
#     but a large request at the head of the queue can block smaller
#     requests behind it ("head-of-line blocking"). Suitable when all
#     requesters are cooperative and requests are of similar size.
#
# PRIORITY
#     Requests are granted in priority order (highest first). Ties are
#     broken by submission time. Starvation is prevented by adding an
#     age-based bonus to each request's effective priority: a request
#     that has been waiting for longer than the configured threshold
#     receives progressively larger boosts until it eventually wins.
#
# FAIR_SHARE
#     Requests are granted to whichever requester has received the
#     fewest slots so far in the current scheduling epoch. Prevents a
#     single requester from monopolising capacity at the expense of
#     others, which is the desired behaviour in a shared test bench.
#
# The policy is a parameter of the scheduler and can be changed at
# runtime via :meth:`Scheduler.set_policy`; the change takes effect on
# the next dispatch, never retroactively.
#
# Lifecycle
# ---------
#
# The scheduler has four states:
#
# RUNNING     — accepting new requests and dispatching grants.
# PAUSED      — accepting new requests but not dispatching. Existing
#               grants remain in force.
# DRAINING    — refusing new requests; waiting for all outstanding
#               grants to be released before moving to SHUTDOWN.
# SHUTDOWN    — terminal; no further operations are permitted.
#
# :meth:`Scheduler.shutdown` initiates a graceful drain. Callers that
# need to abort immediately can pass ``force=True``, which revokes all
# outstanding grants (with a callback to each affected requester) and
# moves straight to SHUTDOWN.
#
# Threading
# ---------
#
# The scheduler is thread-safe. All public methods acquire an internal
# reentrant lock. No user-supplied callback is ever invoked while that
# lock is held: callbacks are enqueued on a per-scheduler worker thread
# and delivered in submission order. This invariant is what makes the
# scheduler safe to use from within a callback — for example, a
# requester may call :meth:`Scheduler.submit` from within its grant
# callback without deadlocking.
#
# The scheduler also runs a lightweight dispatch thread that pumps the
# queue periodically. Tests and embedders who need fully synchronous
# behaviour can construct the scheduler with ``auto_dispatch=False``
# and call :meth:`Scheduler.tick` manually.
#
# Events
# ------
#
# Every state change and every grant/release is published on the
# scheduler's event bus. Subscribers are responsible for their own
# bookkeeping; the scheduler never blocks on a subscriber.
#
# Compatibility
# -------------
#
# Python 3.10+.

from __future__ import annotations

import heapq
import logging
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
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
    pass


__all__ = [
    "Scheduler",
    "SchedulingRequest",
    "SchedulingPolicy",
    "SchedulingRequestState",
    "SchedulerState",
    "SchedulerStats",
    "GrantEvent",
    "ReleaseEvent",
    "SchedulerError",
    "SchedulerShutdownError",
    "RequestNotFoundError",
    "CapacityError",
    "DEFAULT_MAX_CONCURRENCY",
    "DEFAULT_DISPATCH_INTERVAL_SECONDS",
    "DEFAULT_FAIR_SHARE_EPOCH_SECONDS",
    "DEFAULT_STARVATION_THRESHOLD_SECONDS",
    "GRANT_CALLBACK",
    "RELEASE_CALLBACK",
    "REVOKE_CALLBACK",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Default maximum number of concurrent worker slots managed by the
#: scheduler. Chosen to match a conservative number of CPUs on a
#: typical developer machine; production deployments should override.
DEFAULT_MAX_CONCURRENCY: int = 4

#: How often, in seconds, the dispatch thread pumps the queue.
#: Smaller values reduce grant latency at the cost of CPU; larger
#: values batch multiple grants together.
DEFAULT_DISPATCH_INTERVAL_SECONDS: float = 0.1

#: Length of a fair-share epoch, in seconds. Within an epoch, the
#: scheduler tracks how many slots each requester has received and
#: biases subsequent grants toward requesters who have received
#: fewer. At the end of each epoch the counters are reset.
DEFAULT_FAIR_SHARE_EPOCH_SECONDS: float = 30.0

#: Age at which a request begins receiving starvation-prevention
#: boosts. Each additional interval adds another boost step.
DEFAULT_STARVATION_THRESHOLD_SECONDS: float = 15.0

#: Size of the starvation-prevention boost applied per elapsed
#: threshold interval, in units of the requester-supplied priority.
DEFAULT_STARVATION_BOOST: int = 1

#: Maximum length of the callback delivery queue. When the queue is
#: full, further callback deliveries are dropped with a warning; this
#: bounds memory when a subscriber thread is stuck.
_MAX_CALLBACK_QUEUE: int = 4096


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

#: Signature of a grant callback. Called once per partial grant,
#: with the request that was granted and the number of slots that
#: were granted in this delivery.
GRANT_CALLBACK = Callable[["SchedulingRequest", int], None]

#: Signature of a release callback. Called when slots are released,
#: with the request and the number of slots released.
RELEASE_CALLBACK = Callable[["SchedulingRequest", int], None]

#: Signature of a revoke callback. Called when slots are forcibly
#: revoked during a forced shutdown. Receivers are expected to stop
#: whatever work those slots represent as quickly as possible.
REVOKE_CALLBACK = Callable[["SchedulingRequest", int], None]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SchedulerError(KMCSException):
    """Base class for all scheduler errors."""


class SchedulerShutdownError(SchedulerError):
    """Raised when an operation is attempted on a shutdown scheduler."""


class RequestNotFoundError(SchedulerError):
    """Raised when a request ID does not correspond to a known request."""

    def __init__(self, request_id: str) -> None:
        self.request_id = request_id
        super().__init__(f"unknown scheduling request: {request_id}")


class CapacityError(SchedulerError):
    """Raised when a request exceeds the scheduler's maximum capacity."""

    def __init__(self, requested: int, capacity: int) -> None:
        self.requested = requested
        self.capacity = capacity
        super().__init__(
            f"request of {requested} slots exceeds scheduler capacity {capacity}"
        )


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SchedulerState(str, Enum):
    """Lifecycle state of the scheduler."""

    RUNNING = "running"
    PAUSED = "paused"
    DRAINING = "draining"
    SHUTDOWN = "shutdown"

    @property
    def is_accepting(self) -> bool:
        """Return True if new requests are accepted in this state."""
        return self in (SchedulerState.RUNNING, SchedulerState.PAUSED)

    @property
    def is_dispatching(self) -> bool:
        """Return True if grants are being dispatched in this state."""
        return self is SchedulerState.RUNNING

    @property
    def is_terminal(self) -> bool:
        return self is SchedulerState.SHUTDOWN


class SchedulingPolicy(str, Enum):
    """The order in which pending requests are considered for grants."""

    FIFO = "fifo"
    PRIORITY = "priority"
    FAIR_SHARE = "fair_share"


class SchedulingRequestState(str, Enum):
    """Lifecycle state of a scheduling request."""

    PENDING = "pending"
    PARTIAL = "partial"
    GRANTED = "granted"
    CANCELLED = "cancelled"
    COMPLETED = "completed"

    @property
    def is_active(self) -> bool:
        """Return True if the request currently holds slots."""
        return self in (SchedulingRequestState.PARTIAL,
                        SchedulingRequestState.GRANTED)

    @property
    def is_final(self) -> bool:
        """Return True if the request cannot change state further."""
        return self in (SchedulingRequestState.CANCELLED,
                        SchedulingRequestState.COMPLETED)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SchedulingRequest:
    """A single request for worker slots.

    A request is created by :meth:`Scheduler.submit` and evolves over
    its lifetime. The scheduler never mutates a request except through
    its own internal methods, and callers should treat the fields as
    read-only.

    Fields
    ------
    request_id:
        Unique identifier assigned at submission time.
    requester_id:
        Opaque identifier of the party that submitted the request.
        Used for fair-share accounting and diagnostic grouping.
    requested_slots:
        The number of slots the requester asked for. Never changes.
    granted_slots:
        The number of slots currently granted. Increases on grant,
        decreases on release.
    total_granted_slots:
        Cumulative number of slots ever granted to this request,
        including those already released. Used for fair-share
        accounting and reporting.
    priority:
        Integer priority supplied at submission. Higher numbers are
        considered first under the PRIORITY policy.
    state:
        Current lifecycle state.
    submitted_at:
        When the request was submitted.
    first_grant_at:
        When the first slot was granted, or None.
    last_grant_at:
        When the most recent grant occurred, or None.
    completed_at:
        When the request reached a terminal state, or None.
    metadata:
        Opaque key/value payload supplied by the caller; carried
        through to grant and release callbacks.
    """

    request_id: str
    requester_id: str
    requested_slots: int
    granted_slots: int = 0
    total_granted_slots: int = 0
    priority: int = 0
    state: SchedulingRequestState = SchedulingRequestState.PENDING
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    first_grant_at: Optional[datetime] = None
    last_grant_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Non-serialisable internal bookkeeping. These fields are used by
    # the scheduler and reset when appropriate; they are not part of
    # the public interface.

    @property
    def outstanding_slots(self) -> int:
        """Number of slots requested but not yet granted."""
        return max(0, self.requested_slots - self.total_granted_slots)

    @property
    def is_fully_granted(self) -> bool:
        """Return True if all requested slots have been granted at least once."""
        return self.total_granted_slots >= self.requested_slots

    @property
    def age_seconds(self) -> float:
        """Seconds since submission."""
        end = self.completed_at or datetime.now(timezone.utc)
        return (end - self.submitted_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation of this request."""
        return {
            "request_id": self.request_id,
            "requester_id": self.requester_id,
            "requested_slots": self.requested_slots,
            "granted_slots": self.granted_slots,
            "total_granted_slots": self.total_granted_slots,
            "outstanding_slots": self.outstanding_slots,
            "priority": self.priority,
            "state": self.state.value,
            "submitted_at": self.submitted_at.isoformat(),
            "first_grant_at": (
                self.first_grant_at.isoformat()
                if self.first_grant_at is not None
                else None
            ),
            "last_grant_at": (
                self.last_grant_at.isoformat()
                if self.last_grant_at is not None
                else None
            ),
            "completed_at": (
                self.completed_at.isoformat()
                if self.completed_at is not None
                else None
            ),
            "age_seconds": self.age_seconds,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class GrantEvent:
    """Record of a single grant delivery."""

    request_id: str
    requester_id: str
    slots_granted: int
    total_granted_slots: int
    granted_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "requester_id": self.requester_id,
            "slots_granted": self.slots_granted,
            "total_granted_slots": self.total_granted_slots,
            "granted_at": self.granted_at.isoformat(),
        }


@dataclass(frozen=True)
class ReleaseEvent:
    """Record of a single release delivery."""

    request_id: str
    requester_id: str
    slots_released: int
    remaining_slots: int
    released_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "requester_id": self.requester_id,
            "slots_released": self.slots_released,
            "remaining_slots": self.remaining_slots,
            "released_at": self.released_at.isoformat(),
        }


@dataclass
class SchedulerStats:
    """Aggregate statistics describing the scheduler's current state."""

    state: SchedulerState = SchedulerState.RUNNING
    policy: SchedulingPolicy = SchedulingPolicy.FIFO
    capacity: int = 0
    available: int = 0
    granted: int = 0
    pending_requests: int = 0
    active_requests: int = 0
    total_requests_submitted: int = 0
    total_requests_completed: int = 0
    total_requests_cancelled: int = 0
    total_slots_granted: int = 0
    total_slots_released: int = 0
    total_slots_revoked: int = 0
    average_wait_seconds: float = 0.0
    longest_wait_seconds: float = 0.0
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "policy": self.policy.value,
            "capacity": self.capacity,
            "available": self.available,
            "granted": self.granted,
            "pending_requests": self.pending_requests,
            "active_requests": self.active_requests,
            "total_requests_submitted": self.total_requests_submitted,
            "total_requests_completed": self.total_requests_completed,
            "total_requests_cancelled": self.total_requests_cancelled,
            "total_slots_granted": self.total_slots_granted,
            "total_slots_released": self.total_slots_released,
            "total_slots_revoked": self.total_slots_revoked,
            "average_wait_seconds": self.average_wait_seconds,
            "longest_wait_seconds": self.longest_wait_seconds,
            "computed_at": self.computed_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Internal callback queue
# ---------------------------------------------------------------------------


class _CallbackKind(str, Enum):
    GRANT = "grant"
    RELEASE = "release"
    REVOKE = "revoke"


@dataclass
class _CallbackEnvelope:
    kind: _CallbackKind
    request: SchedulingRequest
    slots: int


class _CallbackDispatcher:
    """Delivers scheduler callbacks on a dedicated thread.

    All callbacks are enqueued here rather than invoked directly by the
    scheduler. This guarantees that user code never runs while the
    scheduler's lock is held, which in turn makes the scheduler safe
    to call from within a callback.

    The dispatcher uses a single background thread and a FIFO queue.
    When the queue is full, new deliveries are dropped with a warning;
    this bounds memory even if a subscriber is stuck.
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._queue: Deque[_CallbackEnvelope] = deque()
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._shutdown = False
        self._dropped = 0
        self._delivered = 0
        self._handlers: Dict[_CallbackKind, List[Callable[..., None]]] = {
            _CallbackKind.GRANT: [],
            _CallbackKind.RELEASE: [],
            _CallbackKind.REVOKE: [],
        }
        self._thread = threading.Thread(
            target=self._loop,
            name=name,
            daemon=True,
        )
        self._thread.start()

    def register(
        self, kind: _CallbackKind, handler: Callable[..., None]
    ) -> None:
        if not callable(handler):
            raise TypeError("handler must be callable")
        with self._lock:
            self._handlers[kind].append(handler)

    def unregister(
        self, kind: _CallbackKind, handler: Callable[..., None]
    ) -> bool:
        with self._lock:
            handlers = self._handlers[kind]
            try:
                handlers.remove(handler)
                return True
            except ValueError:
                return False

    def enqueue(self, envelope: _CallbackEnvelope) -> None:
        with self._cv:
            if self._shutdown:
                return
            if len(self._queue) >= _MAX_CALLBACK_QUEUE:
                self._dropped += 1
                if self._dropped == 1 or self._dropped % 100 == 0:
                    logger.warning(
                        "scheduler callback queue full; dropped %d callbacks",
                        self._dropped,
                    )
                return
            self._queue.append(envelope)
            self._cv.notify()

    def shutdown(self, *, drain: bool = True) -> None:
        with self._cv:
            self._shutdown = True
            if not drain:
                self._queue.clear()
            self._cv.notify_all()
        self._thread.join(timeout=2.0)

    @property
    def delivered(self) -> int:
        return self._delivered

    @property
    def dropped(self) -> int:
        return self._dropped

    def _loop(self) -> None:
        while True:
            with self._cv:
                while not self._queue and not self._shutdown:
                    self._cv.wait()
                if not self._queue and self._shutdown:
                    return
                envelope = self._queue.popleft()
                handlers = list(self._handlers[envelope.kind])
            for handler in handlers:
                try:
                    handler(envelope.request, envelope.slots)
                except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
                    logger.debug(
                        "scheduler %s callback raised: %s",
                        envelope.kind.value,
                        exc,
                    )
            self._delivered += 1


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class Scheduler:
    """Coordinates concurrent worker slots across requesters.

    Parameters
    ----------
    max_concurrency:
        The scheduler's total capacity, in worker slots. Must be
        positive. This is the hard upper bound on the number of
        simultaneous workers that any combination of requesters may
        hold.
    policy:
        Initial :class:`SchedulingPolicy`. Defaults to FIFO.
    config:
        Optional :class:`~kmcs.core.config.KmcsConfig`.
    event_bus:
        Optional :class:`~kmcs.core.events.EventBus`. When omitted,
        the process-wide default bus is used.
    auto_dispatch:
        When True (default), the scheduler runs a background thread
        that dispatches grants periodically. When False, the caller
        is responsible for calling :meth:`tick` to pump the queue.
    dispatch_interval:
        Polling interval for the dispatch thread, in seconds.
    fair_share_epoch_seconds:
        Length of a fair-share accounting epoch, in seconds. See
        :data:`DEFAULT_FAIR_SHARE_EPOCH_SECONDS`.
    starvation_threshold_seconds:
        Age at which a pending request starts receiving
        starvation-prevention boosts. Set to None to disable
        starvation prevention entirely.
    starvation_boost:
        Size of each starvation-prevention boost.
    """

    def __init__(
        self,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        *,
        policy: Union[SchedulingPolicy, str] = SchedulingPolicy.FIFO,
        config: Optional[KmcsConfig] = None,
        event_bus: Optional[EventBus] = None,
        auto_dispatch: bool = True,
        dispatch_interval: float = DEFAULT_DISPATCH_INTERVAL_SECONDS,
        fair_share_epoch_seconds: float = DEFAULT_FAIR_SHARE_EPOCH_SECONDS,
        starvation_threshold_seconds: Optional[
            float
        ] = DEFAULT_STARVATION_THRESHOLD_SECONDS,
        starvation_boost: int = DEFAULT_STARVATION_BOOST,
    ) -> None:
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        if dispatch_interval <= 0:
            raise ValueError("dispatch_interval must be positive")
        if fair_share_epoch_seconds <= 0:
            raise ValueError("fair_share_epoch_seconds must be positive")
        if starvation_threshold_seconds is not None and starvation_threshold_seconds <= 0:
            raise ValueError("starvation_threshold_seconds must be positive or None")
        if starvation_boost < 0:
            raise ValueError("starvation_boost must be non-negative")

        self._max_concurrency = int(max_concurrency)
        self._policy = _coerce_policy(policy)
        self._config = config or get_config()
        self._bus = event_bus or get_default_bus()
        self._auto_dispatch = bool(auto_dispatch)
        self._dispatch_interval = float(dispatch_interval)
        self._fair_share_epoch_seconds = float(fair_share_epoch_seconds)
        self._starvation_threshold_seconds = starvation_threshold_seconds
        self._starvation_boost = int(starvation_boost)

        self._lock = threading.RLock()
        self._state = SchedulerState.RUNNING
        self._requests: Dict[str, SchedulingRequest] = {}
        self._order: List[str] = []  # submission order for FIFO
        self._available = self._max_concurrency

        # Fair-share bookkeeping: number of slots granted to each
        # requester in the current epoch.
        self._fair_share_grants: Dict[str, int] = defaultdict(int)
        self._fair_share_epoch_started_at = time.monotonic()

        # Aggregate counters.
        self._total_submitted = 0
        self._total_completed = 0
        self._total_cancelled = 0
        self._total_granted = 0
        self._total_released = 0
        self._total_revoked = 0
        self._wait_samples: List[float] = []

        # Callback dispatcher.
        self._dispatcher = _CallbackDispatcher(
            name="kmcs-scheduler-callbacks"
        )

        # Dispatch thread.
        self._dispatch_stop = threading.Event()
        self._dispatch_thread: Optional[threading.Thread] = None
        if self._auto_dispatch:
            self._start_dispatch_thread()

        logger.debug(
            "Scheduler initialised: capacity=%d, policy=%s",
            self._max_concurrency,
            self._policy.value,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def max_concurrency(self) -> int:
        return self._max_concurrency

    @property
    def policy(self) -> SchedulingPolicy:
        with self._lock:
            return self._policy

    @property
    def state(self) -> SchedulerState:
        with self._lock:
            return self._state

    @property
    def config(self) -> KmcsConfig:
        return self._config

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
                source="campaigns.scheduler",
                data={"event": event_name, **payload},
            )
            publish_event(self._bus, event)
        except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
            logger.debug("scheduler event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Callback registration
    # ------------------------------------------------------------------

    def on_grant(self, callback: GRANT_CALLBACK) -> None:
        """Register a callback invoked when slots are granted."""
        self._dispatcher.register(_CallbackKind.GRANT, callback)

    def on_release(self, callback: RELEASE_CALLBACK) -> None:
        """Register a callback invoked when slots are released."""
        self._dispatcher.register(_CallbackKind.RELEASE, callback)

    def on_revoke(self, callback: REVOKE_CALLBACK) -> None:
        """Register a callback invoked when slots are forcibly revoked."""
        self._dispatcher.register(_CallbackKind.REVOKE, callback)

    def remove_grant_callback(self, callback: GRANT_CALLBACK) -> bool:
        return self._dispatcher.unregister(_CallbackKind.GRANT, callback)

    def remove_release_callback(self, callback: RELEASE_CALLBACK) -> bool:
        return self._dispatcher.unregister(_CallbackKind.RELEASE, callback)

    def remove_revoke_callback(self, callback: REVOKE_CALLBACK) -> bool:
        return self._dispatcher.unregister(_CallbackKind.REVOKE, callback)

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def submit(
        self,
        requester_id: str,
        slots: int,
        *,
        priority: int = 0,
        metadata: Optional[Mapping[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> SchedulingRequest:
        """Submit a request for ``slots`` worker slots.

        Parameters
        ----------
        requester_id:
            Identifier of the requesting party. Used for fair-share
            accounting and diagnostic grouping. Need not be unique
            across submissions; a single requester may hold multiple
            concurrent requests.
        slots:
            Number of slots requested. Must be positive and no larger
            than the scheduler's total capacity.
        priority:
            Scheduling priority. Higher numbers are considered first
            under the PRIORITY policy. Ignored under FIFO and
            FAIR_SHARE.
        metadata:
            Opaque caller-supplied payload. Carried through to grant
            and release callbacks.
        request_id:
            Optional explicit identifier. When None, a UUID4 is
            generated. Must be unique.

        Returns
        -------
        SchedulingRequest
            The submitted request, in PENDING state.

        Raises
        ------
        SchedulerShutdownError
            If the scheduler is shutting down or shut down.
        ValueError
            If ``slots`` or ``requester_id`` is invalid.
        CapacityError
            If ``slots`` exceeds the scheduler's capacity.
        """
        if not requester_id or not isinstance(requester_id, str):
            raise ValueError("requester_id must be a non-empty string")
        if not isinstance(slots, int):
            raise TypeError("slots must be int")
        if slots <= 0:
            raise ValueError("slots must be positive")
        if slots > self._max_concurrency:
            raise CapacityError(slots, self._max_concurrency)

        with self._lock:
            if not self._state.is_accepting:
                raise SchedulerShutdownError(
                    f"scheduler is {self._state.value}; not accepting requests"
                )
            rid = request_id or str(uuid.uuid4())
            if rid in self._requests:
                raise ValueError(f"request_id already in use: {rid}")
            request = SchedulingRequest(
                request_id=rid,
                requester_id=requester_id,
                requested_slots=int(slots),
                priority=int(priority),
                metadata=dict(metadata or {}),
            )
            self._requests[rid] = request
            self._order.append(rid)
            self._total_submitted += 1

        self._emit(
            "SCHEDULER_REQUEST_SUBMITTED",
            {
                "request_id": rid,
                "requester_id": requester_id,
                "slots": slots,
                "priority": priority,
                "capacity": self._max_concurrency,
            },
        )

        # Attempt an immediate dispatch so a fully-available capacity
        # grants without waiting for the next tick.
        if self.state.is_dispatching:
            try:
                self._dispatch()
            except Exception:
                logger.exception("immediate dispatch failed")

        return request

    # ------------------------------------------------------------------
    # Cancellation
    # ------------------------------------------------------------------

    def cancel(self, request_id: str) -> bool:
        """Cancel a request.

        If the request holds slots, they are released and the
        corresponding release callbacks fire. If the request is
        pending, it is simply removed from the queue. Cancelling an
        already-cancelled or completed request is a no-op.

        Returns
        -------
        bool
            True if the request was cancelled by this call.

        Raises
        ------
        RequestNotFoundError
            If ``request_id`` is unknown.
        """
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise RequestNotFoundError(request_id)
            if request.state.is_final:
                return False
            request.state = SchedulingRequestState.CANCELLED
            request.completed_at = datetime.now(timezone.utc)
            released = request.granted_slots
            if released:
                request.granted_slots = 0
                self._available += released
                self._total_released += released
            self._total_cancelled += 1

        if released:
            self._dispatcher.enqueue(
                _CallbackEnvelope(
                    kind=_CallbackKind.RELEASE,
                    request=request,
                    slots=released,
                )
            )
            self._emit(
                "SCHEDULER_RELEASED",
                {
                    "request_id": request_id,
                    "requester_id": request.requester_id,
                    "slots": released,
                    "available": self.available(),
                    "reason": "cancel",
                },
            )

        self._emit(
            "SCHEDULER_REQUEST_CANCELLED",
            {
                "request_id": request_id,
                "requester_id": request.requester_id,
                "released_slots": released,
            },
        )

        # A cancellation may make capacity available for other pending
        # requests.
        if self.state.is_dispatching:
            try:
                self._dispatch()
            except Exception:
                logger.exception("dispatch after cancel failed")

        return True

    # ------------------------------------------------------------------
    # Release
    # ------------------------------------------------------------------

    def release(
        self, request_id: str, count: Optional[int] = None
    ) -> int:
        """Release slots previously granted to ``request_id``.

        Parameters
        ----------
        request_id:
            The request whose slots are to be released.
        count:
            Number of slots to release. When None, all currently
            granted slots are released. When the count exceeds the
            request's granted slots, it is clamped to that value.

        Returns
        -------
        int
            The number of slots actually released.

        Raises
        ------
        RequestNotFoundError
            If ``request_id`` is unknown.
        """
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise RequestNotFoundError(request_id)
            if request.state.is_final:
                return 0
            currently_granted = request.granted_slots
            if currently_granted <= 0:
                return 0
            to_release = (
                currently_granted if count is None else min(int(count), currently_granted)
            )
            if to_release <= 0:
                return 0
            request.granted_slots -= to_release
            self._available += to_release
            self._total_released += to_release

            # Update request state:
            #   - still holds slots → PARTIAL or GRANTED
            #   - holds none but has received some → COMPLETED if all
            #     requested slots were granted at some point, else
            #     PARTIAL with granted=0 (waiting for a re-grant).
            if request.granted_slots > 0:
                if request.granted_slots >= request.requested_slots:
                    request.state = SchedulingRequestState.GRANTED
                else:
                    request.state = SchedulingRequestState.PARTIAL
            else:
                if request.is_fully_granted:
                    request.state = SchedulingRequestState.COMPLETED
                    request.completed_at = datetime.now(timezone.utc)
                    self._total_completed += 1
                else:
                    # The requester is temporarily done with this
                    # grant and will re-appear as pending for the
                    # remainder.
                    request.state = SchedulingRequestState.PENDING

        self._dispatcher.enqueue(
            _CallbackEnvelope(
                kind=_CallbackKind.RELEASE,
                request=request,
                slots=to_release,
            )
        )
        self._emit(
            "SCHEDULER_RELEASED",
            {
                "request_id": request_id,
                "requester_id": request.requester_id,
                "slots": to_release,
                "available": self.available(),
                "reason": "release",
            },
        )

        # Freed capacity may be granted to pending requests.
        if self.state.is_dispatching:
            try:
                self._dispatch()
            except Exception:
                logger.exception("dispatch after release failed")

        return to_release

    def release_all(self, request_id: str) -> int:
        """Release every slot currently held by ``request_id``."""
        return self.release(request_id, None)

    # ------------------------------------------------------------------
    # Capacity queries
    # ------------------------------------------------------------------

    def available(self) -> int:
        """Return the number of currently un-granted slots."""
        with self._lock:
            return self._available

    def granted(self) -> int:
        """Return the total number of currently granted slots."""
        with self._lock:
            return self._max_concurrency - self._available

    def granted_for(self, request_id: str) -> int:
        """Return the slots currently granted to ``request_id``."""
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise RequestNotFoundError(request_id)
            return request.granted_slots

    # ------------------------------------------------------------------
    # Request introspection
    # ------------------------------------------------------------------

    def get_request(self, request_id: str) -> SchedulingRequest:
        """Return a request by ID or raise :class:`RequestNotFoundError`."""
        with self._lock:
            request = self._requests.get(request_id)
            if request is None:
                raise RequestNotFoundError(request_id)
            return request

    def has_request(self, request_id: str) -> bool:
        """Return True if ``request_id`` is known to the scheduler."""
        with self._lock:
            return request_id in self._requests

    def list_requests(
        self,
        *,
        states: Optional[Iterable[SchedulingRequestState]] = None,
        requester_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[SchedulingRequest]:
        """List requests matching the given filters.

        Parameters
        ----------
        states:
            Optional filter on request state.
        requester_id:
            Optional filter on requester.
        limit:
            Optional truncation. Requests are returned in submission
            order (oldest first).

        Returns
        -------
        list of SchedulingRequest
        """
        state_set = frozenset(states) if states is not None else None
        with self._lock:
            ordered = list(self._requests.values())
        # Requests are stored in a dict; recover submission order.
        with self._lock:
            order_index = {rid: i for i, rid in enumerate(self._order)}
        ordered.sort(key=lambda r: order_index.get(r.request_id, 1 << 30))
        if state_set is not None:
            ordered = [r for r in ordered if r.state in state_set]
        if requester_id is not None:
            ordered = [r for r in ordered if r.requester_id == requester_id]
        if limit is not None:
            ordered = ordered[:limit]
        return ordered

    def pending_requests(self) -> List[SchedulingRequest]:
        """Return requests that still have outstanding slot demand."""
        return self.list_requests(
            states=(
                SchedulingRequestState.PENDING,
                SchedulingRequestState.PARTIAL,
            )
        )

    def active_requests(self) -> List[SchedulingRequest]:
        """Return requests that currently hold at least one slot."""
        with self._lock:
            return [
                r for r in self._requests.values()
                if r.granted_slots > 0
            ]

    # ------------------------------------------------------------------
    # Policy control
    # ------------------------------------------------------------------

    def set_policy(self, policy: Union[SchedulingPolicy, str]) -> None:
        """Change the scheduling policy.

        The new policy takes effect on the next dispatch. Grants that
        have already been issued are not affected.

        Raises
        ------
        ValueError
            If ``policy`` is not a recognised value.
        """
        new_policy = _coerce_policy(policy)
        with self._lock:
            self._policy = new_policy
        self._emit(
            "SCHEDULER_POLICY_CHANGED",
            {"policy": new_policy.value},
        )
        if self.state.is_dispatching:
            try:
                self._dispatch()
            except Exception:
                logger.exception("dispatch after policy change failed")

    # ------------------------------------------------------------------
    # Pause / resume
    # ------------------------------------------------------------------

    def pause(self) -> None:
        """Pause dispatch.

        New requests are still accepted; they are simply not granted
        until :meth:`resume` is called. Existing grants remain in
        force.
        """
        with self._lock:
            if self._state == SchedulerState.RUNNING:
                self._state = SchedulerState.PAUSED
        self._emit("SCHEDULER_PAUSED", {})

    def resume(self) -> None:
        """Resume dispatch after a :meth:`pause`."""
        with self._lock:
            if self._state == SchedulerState.PAUSED:
                self._state = SchedulerState.RUNNING
            else:
                return
        self._emit("SCHEDULER_RESUMED", {})
        try:
            self._dispatch()
        except Exception:
            logger.exception("dispatch after resume failed")

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def tick(self) -> None:
        """Run one dispatch pass.

        This method is public so that embedders and tests can drive
        the scheduler deterministically when ``auto_dispatch=False``.
        """
        self._dispatch()

    def _dispatch(self) -> None:
        """Attempt to grant free slots to pending requests."""
        grants: List[_CallbackEnvelope] = []
        now = datetime.now(timezone.utc)

        with self._lock:
            if self._state != SchedulerState.RUNNING:
                return
            self._roll_fair_share_epoch_locked()

            # Iterate until no further progress is possible. Each
            # iteration grants at least one slot or exits.
            while self._available > 0:
                candidate = self._pick_candidate_locked()
                if candidate is None:
                    break
                request = candidate
                outstanding = request.outstanding_slots
                if outstanding <= 0:
                    # Fully granted; mark and remove from consideration.
                    if request.state in (
                        SchedulingRequestState.PENDING,
                        SchedulingRequestState.PARTIAL,
                    ) and request.is_fully_granted and request.granted_slots == 0:
                        request.state = SchedulingRequestState.COMPLETED
                        request.completed_at = now
                        self._total_completed += 1
                    continue
                grant_count = min(self._available, outstanding)
                if grant_count <= 0:
                    break

                request.granted_slots += grant_count
                request.total_granted_slots += grant_count
                self._available -= grant_count
                self._total_granted += grant_count
                if request.first_grant_at is None:
                    request.first_grant_at = now
                    self._wait_samples.append(request.age_seconds)
                request.last_grant_at = now

                if request.granted_slots >= request.requested_slots:
                    request.state = SchedulingRequestState.GRANTED
                else:
                    request.state = SchedulingRequestState.PARTIAL

                self._fair_share_grants[request.requester_id] += grant_count

                grants.append(
                    _CallbackEnvelope(
                        kind=_CallbackKind.GRANT,
                        request=request,
                        slots=grant_count,
                    )
                )

        for envelope in grants:
            self._dispatcher.enqueue(envelope)
            self._emit(
                "SCHEDULER_GRANTED",
                {
                    "request_id": envelope.request.request_id,
                    "requester_id": envelope.request.requester_id,
                    "slots": envelope.slots,
                    "granted_total": envelope.request.granted_slots,
                    "available": self.available(),
                },
            )

    def _roll_fair_share_epoch_locked(self) -> None:
        """Reset fair-share counters when the current epoch expires."""
        now = time.monotonic()
        if now - self._fair_share_epoch_started_at >= self._fair_share_epoch_seconds:
            self._fair_share_grants.clear()
            self._fair_share_epoch_started_at = now

    def _pick_candidate_locked(self) -> Optional[SchedulingRequest]:
        """Return the request that should receive the next grant."""
        candidates = [
            r for r in self._requests.values()
            if r.state in (
                SchedulingRequestState.PENDING,
                SchedulingRequestState.PARTIAL,
            )
            and r.outstanding_slots > 0
            and not r.state.is_final
        ]
        if not candidates:
            return None

        policy = self._policy

        if policy == SchedulingPolicy.FIFO:
            candidates.sort(
                key=lambda r: (
                    r.submitted_at,
                    r.request_id,
                )
            )
            return candidates[0]

        if policy == SchedulingPolicy.PRIORITY:
            candidates.sort(
                key=lambda r: (
                    -self._effective_priority(r),
                    r.submitted_at,
                    r.request_id,
                )
            )
            return candidates[0]

        if policy == SchedulingPolicy.FAIR_SHARE:
            candidates.sort(
                key=lambda r: (
                    self._fair_share_grants.get(r.requester_id, 0),
                    r.submitted_at,
                    r.request_id,
                )
            )
            return candidates[0]

        # Unknown policy: fall back to FIFO. This should be unreachable
        # because set_policy validates its input.
        candidates.sort(key=lambda r: (r.submitted_at, r.request_id))
        return candidates[0]

    def _effective_priority(self, request: SchedulingRequest) -> int:
        """Return the priority used by the PRIORITY policy.

        Adds a starvation-prevention boost proportional to how long
        the request has been waiting without being granted.
        """
        base = request.priority
        if self._starvation_threshold_seconds is None:
            return base
        waited = request.age_seconds
        if waited <= self._starvation_threshold_seconds:
            return base
        steps = int(
            (waited - self._starvation_threshold_seconds)
            / self._starvation_threshold_seconds
        ) + 1
        return base + steps * self._starvation_boost

    # ------------------------------------------------------------------
    # Dispatch thread
    # ------------------------------------------------------------------

    def _start_dispatch_thread(self) -> None:
        self._dispatch_stop.clear()
        self._dispatch_thread = threading.Thread(
            target=self._dispatch_loop,
            name="kmcs-scheduler-dispatch",
            daemon=True,
        )
        self._dispatch_thread.start()

    def _dispatch_loop(self) -> None:
        while not self._dispatch_stop.wait(self._dispatch_interval):
            try:
                self._dispatch()
            except Exception:
                logger.exception("scheduler dispatch tick failed")

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> SchedulerStats:
        """Return a snapshot of the scheduler's aggregate statistics."""
        with self._lock:
            requests = list(self._requests.values())
            pending = sum(
                1 for r in requests
                if r.state in (
                    SchedulingRequestState.PENDING,
                    SchedulingRequestState.PARTIAL,
                )
            )
            active = sum(1 for r in requests if r.granted_slots > 0)
            total_grants = self._total_granted
            total_released = self._total_released
            total_revoked = self._total_revoked
            capacity = self._max_concurrency
            available = self._available
            state = self._state
            policy = self._policy
            submitted = self._total_submitted
            completed = self._total_completed
            cancelled = self._total_cancelled
            wait_samples = list(self._wait_samples)

        avg_wait = (
            sum(wait_samples) / len(wait_samples)
            if wait_samples
            else 0.0
        )
        max_wait = max(wait_samples) if wait_samples else 0.0

        return SchedulerStats(
            state=state,
            policy=policy,
            capacity=capacity,
            available=available,
            granted=capacity - available,
            pending_requests=pending,
            active_requests=active,
            total_requests_submitted=submitted,
            total_requests_completed=completed,
            total_requests_cancelled=cancelled,
            total_slots_granted=total_grants,
            total_slots_released=total_released,
            total_slots_revoked=total_revoked,
            average_wait_seconds=avg_wait,
            longest_wait_seconds=max_wait,
        )

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def shutdown(self, *, force: bool = False, drain_timeout: float = 5.0) -> None:
        """Shut the scheduler down.

        Parameters
        ----------
        force:
            When True, every outstanding grant is revoked immediately
            (with a revoke callback for each affected request) and the
            scheduler moves straight to SHUTDOWN. When False, the
            scheduler enters DRAINING and waits up to
            ``drain_timeout`` seconds for outstanding grants to be
            released naturally before forcing the transition.
        drain_timeout:
            Maximum seconds to wait in the graceful path.
        """
        with self._lock:
            if self._state.is_terminal:
                return
            if force:
                self._state = SchedulerState.SHUTDOWN
            else:
                self._state = SchedulerState.DRAINING

        if not force:
            deadline = time.monotonic() + max(0.0, drain_timeout)
            while time.monotonic() < deadline:
                with self._lock:
                    if self._available >= self._max_concurrency:
                        break
                time.sleep(0.05)

        # Revoke anything still outstanding.
        revokes: List[_CallbackEnvelope] = []
        with self._lock:
            for request in self._requests.values():
                if request.granted_slots > 0:
                    revoked = request.granted_slots
                    request.granted_slots = 0
                    self._available += revoked
                    self._total_revoked += revoked
                    if not request.state.is_final:
                        request.state = SchedulingRequestState.CANCELLED
                        request.completed_at = datetime.now(timezone.utc)
                        self._total_cancelled += 1
                    revokes.append(
                        _CallbackEnvelope(
                            kind=_CallbackKind.REVOKE,
                            request=request,
                            slots=revoked,
                        )
                    )
            self._state = SchedulerState.SHUTDOWN

        for envelope in revokes:
            self._dispatcher.enqueue(envelope)
            self._emit(
                "SCHEDULER_REVOKED",
                {
                    "request_id": envelope.request.request_id,
                    "requester_id": envelope.request.requester_id,
                    "slots": envelope.slots,
                    "reason": "shutdown",
                },
            )

        # Stop the dispatch thread.
        self._dispatch_stop.set()
        thread = self._dispatch_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

        # Stop the callback dispatcher, draining what is left.
        self._dispatcher.shutdown(drain=True)

        self._emit(
            "SCHEDULER_SHUTDOWN",
            {"force": force, "revoked": len(revokes)},
        )

    def __enter__(self) -> "Scheduler":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()

    def __repr__(self) -> str:
        return (
            f"Scheduler(capacity={self._max_concurrency}, "
            f"policy={self.policy.value}, "
            f"state={self.state.value}, "
            f"available={self.available()})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_policy(
    policy: Union[SchedulingPolicy, str]
) -> SchedulingPolicy:
    """Convert a policy identifier to a :class:`SchedulingPolicy`."""
    if isinstance(policy, SchedulingPolicy):
        return policy
    if isinstance(policy, str):
        try:
            return SchedulingPolicy(policy)
        except ValueError as exc:
            raise ValueError(
                f"unknown scheduling policy: {policy!r}"
            ) from exc
    raise TypeError(
        f"policy must be SchedulingPolicy or str, got {type(policy).__name__}"
    )


# ---------------------------------------------------------------------------
# Factory function used by CampaignManager
# ---------------------------------------------------------------------------


def default_scheduler_factory(campaign: Any) -> Scheduler:
    """Return a default :class:`Scheduler` for a campaign.

    The scheduler is configured from the campaign's configuration:

    * Capacity is the campaign's ``workers`` count.
    * Policy is FIFO by default.
    * Auto-dispatch is enabled.

    A campaign that does not use scheduling (for example, one that has
    a fixed worker count and no dynamic scaling) may simply not invoke
    this factory; the manager tolerates its absence.

    Parameters
    ----------
    campaign:
        The campaign for which to build a scheduler. Only the
        ``config`` attribute is read.

    Returns
    -------
    Scheduler
    """
    cfg = campaign.config
    return Scheduler(
        max_concurrency=max(1, int(cfg.workers)),
        policy=SchedulingPolicy.FIFO,
    )


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
