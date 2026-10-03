"""
KMCS event subsystem (Phase 1 — ``kmcs.core.events``)
=====================================================

A dependency-free, thread-safe in-process publish/subscribe bus that is the
backbone of live campaign telemetry (fuzzer stats, crash discoveries, job
transitions, sanitizer output…) for the future CLI/GUI layers.

Guarantees
----------
* **No network, no keys.**  Pure stdlib + local files only.
* **Publisher never blocks on subscribers** beyond the dispatch lock; slow
  consumers use :class:`BufferedSubscriber` and drain at their own pace.
* **Fault isolation.**  One subscriber raising an exception cannot stop
  delivery to others nor corrupt the bus; failures are captured as
  :class:`kmcs.core.exceptions.EventError` records.
* **Wildcard topics.**  ``kmcs.crash.#`` matches any descendant;
  ``kmcr.campaign.*`` matches exactly one level (see :class:`Topic`).
* **Replay.**  A bounded ring buffer lets late subscribers (e.g. a GUI pane
  opening mid-campaign) fetch recent history.
* **Ordering.**  Per-bus monotonic sequence numbers give a total order over
  emitted records; ``record_id`` derives from it plus content hash.

The module also exposes a contextvar-scoped *current bus* so deep call sites
can emit without plumbing the bus through every signature.
"""

from __future__ import annotations

import contextlib
import contextvars
import fnmatch
import hashlib
import itertools
import json
import os
import queue
import re
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
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from kmcs.core.exceptions import EventError

__all__ = [
    "AsyncEventBus",
    "BufferedSubscriber",
    "EventBus",
    "EventFilter",
    "EventSink",
    "EventType",
    "FNV1a",
    "InMemorySink",
    "JsonLineFileSink",
    "Event",
    "Record",
    "SubscriberHandle",
    "Topic",
    "TopicTrie",
    "content_hash",
    "current_bus",
    "emit",
    "subscribe",
]

# --------------------------------------------------------------------------- #
# Hashing helpers (pure python, deterministic across runs & platforms)
# --------------------------------------------------------------------------- #

_OFFSET64 = 0xCBF29CE484222325
_PRIME64 = 0x100000001B3
_MASK64 = (1 << 64) - 1


class FNV1a:
    """64-bit FNV-1a hash with a convenient streaming API."""

    __slots__ = ("_state",)

    def __init__(self, seed: int = _OFFSET64) -> None:
        self._state = seed & _MASK64

    def update(self, data: bytes) -> "FNV1a":
        for byte in data:
            self._state ^= byte
            self._state = (self._state * _PRIME64) & _MASK64
        return self

    def update_str(self, text: str) -> "FNV1a":
        return self.update(text.encode("utf-8", "surrogatepass"))

    @property
    def digest(self) -> int:
        return self._state

    @property
    def hexdigest(self) -> str:
        return f"{self._state:016x}"

    @classmethod
    def hash(cls, data: Union[bytes, str]) -> int:
        h = cls()
        if isinstance(data, str):
            h.update_str(data)
        else:
            h.update(data)
        return h.digest

    def __repr__(self) -> str:  # pragma: no cover
        return f"FNV1a({self.hexdigest})"


def _canonical(obj: Any) -> str:
    """Deterministic JSON encoding used for hashing (sorted keys, no spaces)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(payload: Any) -> str:
    """Stable sha256 hex digest of any JSON-ish payload."""
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Event taxonomy
# --------------------------------------------------------------------------- #

class EventType(str, Enum):
    """Canonical event classes. Values are the last topic segment."""

    # lifecycle
    STARTED = "started"
    STOPPED = "stopped"
    HEARTBEAT = "heartbeat"
    PROGRESS = "progress"
    # targets / build
    TARGET_REGISTERED = "target_registered"
    BUILD_STARTED = "build_started"
    BUILD_FINISHED = "build_finished"
    TOOL_MISSING = "tool_missing"
    # corpus
    CORPUS_IMPORTED = "corpus_imported"
    CORPUS_PRUNED = "corpus_pruned"
    SEED_ADDED = "seed_added"
    # fuzzing
    FUZZER_STARTED = "fuzzer_started"
    FUZZER_STATS = "fuzzer_stats"
    QUEUE_NEW_COVERAGE = "new_coverage"
    CRASH_FOUND = "crash_found"
    HANG_FOUND = "hang_found"
    TIMEOUT = "timeout"
    # analysis pipeline
    CRASH_PARSED = "crash_parsed"
    CRASH_CLASSIFIED = "crash_classified"
    CRASH_FINGERPRINTED = "crash_fingerprinted"
    CRASH_DEDUPED = "crash_deduped"
    # reproduction / minimisation
    REPRO_STARTED = "repro_started"
    REPRO_RESULT = "repro_result"
    MINIMISE_DONE = "minimise_done"
    # findings / reports
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    REPORT_GENERATED = "report_generated"
    REGRESSION_ADDED = "regression_added"
    # jobs
    JOB_STATE = "job_state"
    JOB_RETRY = "job_retry"
    JOB_FAILED = "job_failed"
    # errors & policy
    ERROR = "error"
    WARNING = "warning"
    POLICY_BLOCKED = "policy_blocked"

    @property
    def severity_hint(self) -> str:
        if self in (EventType.CRASH_FOUND, EventType.ERROR, EventType.POLICY_BLOCKED,
                    EventType.JOB_FAILED, EventType.HANG_FOUND):
            return "high"
        if self in (EventType.WARNING, EventType.TIMEOUT, EventType.TOOL_MISSING):
            return "medium"
        return "info"


#: Reserved root namespace for every KMCS topic.
ROOT_NAMESPACE = "kmcs"

_VALID_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")
_WILDCARD_ONE = "*"
_WILDCARD_MANY = "#"


class Topic:
    """Hierarchical dotted topic with glob semantics.

    Grammar::

        topic      := segment ("." segment)*
        segment    := name | "*" | "#"          (# only allowed last)
        name       := [A-Za-z0-9_][A-Za-z0-9_.-]*

    Examples::

        Topic("kmcs.campaign.a1.crash")
        Topic("kmcs.campaign.*.crash")     # one campaign level
        Topic("kmcs.#")                    # everything under kmcs
    """

    __slots__ = ("segments", "_text")

    def __init__(self, text: Union[str, "Topic"]) -> None:
        if isinstance(text, Topic):
            self.segments: Tuple[str, ...] = text.segments
        else:
            parts = tuple(p for p in str(text).split(".") if p != "")
            if not parts:
                raise EventError(f"empty topic: {text!r}")
            for i, part in enumerate(parts):
                if part == _WILDCARD_MANY and i != len(parts) - 1:
                    raise EventError(
                        f"'#' wildcard must be the final segment: {text!r}")
                if part != _WILDCARD_ONE and part != _WILDCARD_MANY:
                    if not _VALID_SEGMENT.match(part):
                        raise EventError(f"invalid topic segment {part!r} in {text!r}")
            self.segments = parts
        self._text = ".".join(self.segments)

    # -- construction helpers ------------------------------------------------
    @classmethod
    def build(cls, *parts: Union[str, int]) -> "Topic":
        return cls(".".join(str(p) for p in parts))

    @classmethod
    def from_event_type(cls, namespace: str, etype: EventType) -> "Topic":
        return cls.build(ROOT_NAMESPACE, namespace, etype.value)

    def child(self, *parts: Union[str, int]) -> "Topic":
        joined = ".".join(str(p) for p in parts)
        return Topic(f"{self._text}.{joined}")

    def parent(self) -> Optional["Topic"]:
        if len(self.segments) <= 1:
            return None
        return Topic(".".join(self.segments[:-1]))

    # -- matching -------------------------------------------------------------
    def matches(self, other: Union[str, "Topic"]) -> bool:
        """True if concrete topic *other* is covered by this (pattern) topic."""
        o = other if isinstance(other, Topic) else Topic(other)
        if _WILDCARD_MANY not in self.segments:
            if len(o.segments) != len(self.segments):
                return False
            return all(a == b or a == _WILDCARD_ONE for a, b in zip(self.segments, o.segments))
        head = list(self.segments)
        tail = head.pop()  # must be '#'
        if len(o.segments) < len(head):
            return False
        return all(a == b or a == _WILDCARD_ONE for a, b in zip(head, o.segments))

    def is_pattern(self) -> bool:
        return _WILDCARD_ONE in self.segments or _WILDCARD_MANY in self.segments

    def is_concrete(self) -> bool:
        return not self.is_pattern()

    def depth(self) -> int:
        return len(self.segments)

    def prefix(self, n: int) -> "Topic":
        return Topic(".".join(self.segments[:max(1, min(n, len(self.segments)))]))

    # -- dunders ---------------------------------------------------------------
    def __str__(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return f"Topic({self._text!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (Topic, str)):
            return self._text == str(Topic(other))
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._text)

    def __lt__(self, other: "Topic") -> bool:
        return self._text < other._text


class TopicTrie:
    """Prefix trie mapping concrete topics → sets of registered pattern ids.

    Used by :class:`EventBus` for O(depth) wildcard dispatch instead of
    scanning every subscription with fnmatch.
    """

    class _Node:
        __slots__ = ("children", "exact", "any_descendant")

        def __init__(self) -> None:
            self.children: Dict[str, "TopicTrie._Node"] = {}
            self.exact: Set[int] = set()           # ids stored under exact segment
            self.any_descendant: Set[int] = set()  # ids registered with trailing '#'

    def __init__(self) -> None:
        self._root = self._Node()
        self._patterns: Dict[int, Topic] = {}

    # -- mutation -------------------------------------------------------------
    def add(self, key: int, pattern: Topic) -> None:
        node = self._root
        segs = pattern.segments
        for i, seg in enumerate(segs):
            if seg == _WILDCARD_MANY:
                node.any_descendant.add(key)
                break
            node = node.children.setdefault(seg, self._Node())
            if i == len(segs) - 1:
                node.exact.add(key)
        self._patterns[key] = pattern

    def remove(self, key: int) -> Optional[Topic]:
        pattern = self._patterns.pop(key, None)
        if pattern is None:
            return None
        node = self._root
        segs = pattern.segments
        for i, seg in enumerate(segs):
            if seg == _WILDCARD_MANY:
                node.any_descendant.discard(key)
                return pattern
            node = node.children.get(seg)
            if node is None:
                return pattern
            if i == len(segs) - 1:
                node.exact.discard(key)
        return pattern

    def clear(self) -> None:
        self._root = self._Node()
        self._patterns.clear()

    # -- lookup ------------------------------------------------------------------
    def collect(self, concrete: Topic) -> Set[int]:
        """All registered keys whose pattern matches *concrete*."""
        found: Set[int] = set(self._root.any_descendant)
        node = self._root
        for seg in concrete.segments:
            star = node.children.get(_WILDCARD_ONE)
            if star is not None:
                found |= star.exact
                found |= star.any_descendant
            nxt = node.children.get(seg)
            if nxt is None:
                return found
            node = nxt
            found |= node.exact
            found |= node.any_descendant
        return found

    def size(self) -> int:
        return len(self._patterns)

    def patterns(self) -> Tuple[Topic, ...]:
        return tuple(self._patterns.values())

    def __len__(self) -> int:
        return len(self._patterns)


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Record:
    """An immutable event envelope travelling over the bus."""

    topic: Topic
    type: EventType
    payload: Mapping[str, Any]
    seq: int = 0
    ts: float = field(default_factory=time.time)
    source: str = ""
    tags: Tuple[str, ...] = ()
    record_id: str = ""
    correlation_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.topic, Topic):
            object.__setattr__(self, "topic", Topic(self.topic))
        if not isinstance(self.type, EventType):
            try:
                object.__setattr__(self, "type", EventType(self.type))
            except ValueError as exc:
                raise EventError(f"unknown event type {self.type!r}") from exc
        if not isinstance(self.payload, Mapping):
            raise EventError("Record.payload must be a mapping")
        if not self.record_id:
            derived = FNV1a.hash(f"{self.seq}:{self.topic}:{content_hash(self.payload)[:16]}")
            object.__setattr__(self, "record_id", f"{derived:016x}")

    # -- accessors --------------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags

    def age_seconds(self, now: Optional[float] = None) -> float:
        return max(0.0, (now or time.time()) - self.ts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "topic": str(self.topic),
            "type": self.type.value,
            "payload": dict(self.payload),
            "seq": self.seq,
            "ts": self.ts,
            "iso": datetime.fromtimestamp(self.ts, timezone.utc).isoformat(),
            "source": self.source,
            "tags": list(self.tags),
            "record_id": self.record_id,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Record":
        return cls(
            topic=Topic(data["topic"]),
            type=EventType(data["type"]),
            payload=dict(data.get("payload", {})),
            seq=int(data.get("seq", 0)),
            ts=float(data.get("ts", time.time())),
            source=str(data.get("source", "")),
            tags=tuple(data.get("tags", ())),
            record_id=str(data.get("record_id", "")),
            correlation_id=str(data.get("correlation_id", "")),
        )

    def with_tags(self, *tags: str) -> "Record":
        return Record(topic=self.topic, type=self.type, payload=self.payload,
                      seq=self.seq, ts=self.ts, source=self.source,
                      tags=self.tags + tuple(tags), record_id=self.record_id,
                      correlation_id=self.correlation_id)

    def __json__(self) -> Dict[str, Any]:  # used by json.dumps(default=...)
        return self.to_dict()


# Backwards/forwards compatibility alias.  Downstream subsystems (campaigns,
# corpus, reproduction) import the event record under the shorter name ``Event``.
# ``Record`` remains the canonical class name; ``Event`` is an identical alias so
# ``isinstance(x, Record) is isinstance(x, Event)`` holds everywhere.
Event = Record


# --------------------------------------------------------------------------- #
# Filters & sinks
# --------------------------------------------------------------------------- #

Predicate = Callable[[Record], bool]


class EventFilter:
    """Composable predicate wrapper around filters/subscriptions."""

    def __init__(self, *predicates: Predicate) -> None:
        self._preds: List[Predicate] = [p for p in predicates if callable(p)]

    def add(self, predicate: Predicate) -> "EventFilter":
        self._preds.append(predicate)
        return self

    def allow_topic(self, pattern: Union[str, Topic]) -> "EventFilter":
        pat = pattern if isinstance(pattern, Topic) else Topic(pattern)
        return self.add(lambda rec: pat.matches(rec.topic))

    def allow_type(self, *types: Union[EventType, str]) -> "EventFilter":
        wanted = {EventType(t) for t in types}
        return self.add(lambda rec: rec.type in wanted)

    def allow_min_severity(self, level: str) -> "EventFilter":
        order = {"info": 0, "medium": 1, "high": 2, "critical": 3}
        floor = order.get(level, 0)
        return self.add(lambda rec: order.get(rec.type.severity_hint, 0) >= floor)

    def deny_tagged(self, tag: str) -> "EventFilter":
        return self.add(lambda rec: not rec.has_tag(tag))

    def __call__(self, record: Record) -> bool:
        return all(p(record) for p in self._preds)

    def __bool__(self) -> bool:
        return bool(self._preds)


class EventSink:
    """Base class for anything that consumes batches of records.

    Subclasses override :meth:`write`; the base keeps drop accounting.
    """

    def __init__(self, name: str = "sink") -> None:
        self.name = name
        self.written = 0
        self.dropped = 0
        self._lock = threading.Lock()

    def write(self, records: Sequence[Record]) -> int:  # pragma: no cover
        raise NotImplementedError

    def note_drop(self, count: int = 1) -> None:
        with self._lock:
            self.dropped += count

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

    def stats(self) -> Dict[str, int]:
        return {"written": self.written, "dropped": self.dropped}


class InMemorySink(EventSink):
    """Ring-buffer sink for tests, dashboards and post-mortem inspection."""

    def __init__(self, capacity: int = 10_000, name: str = "memory") -> None:
        super().__init__(name=name)
        self._buf: Deque[Record] = deque(maxlen=max(1, capacity))

    def write(self, records: Sequence[Record]) -> int:
        n = 0
        for rec in records:
            self._buf.append(rec)
            n += 1
        with self._lock:
            self.written += n
        return n

    def drain(self) -> List[Record]:
        out = list(self._buf)
        self._buf.clear()
        return out

    def snapshot(self) -> Tuple[Record, ...]:
        return tuple(self._buf)

    def __len__(self) -> int:
        return len(self._buf)


class JsonLineFileSink(EventSink):
    """Append-only JSON-lines persistence (offline file logging).

    Writes are buffered and flushed either when ``flush_interval_seconds``
    elapses between writes or :meth:`flush`/:meth:`close` is called, so a
    busy fuzzing loop doesn't pay fsync costs per event.
    """

    def __init__(self, path: Union[str, Path], *, append: bool = True,
                 flush_interval_seconds: float = 2.0,
                 max_bytes: int = 64 * 1024 * 1024,
                 rotate_count: int = 3, name: str = "jsonl") -> None:
        super().__init__(name=name)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        self._fh = open(self.path, mode, encoding="utf-8")
        self._flush_interval = flush_interval_seconds
        self._last_flush = time.monotonic()
        self._max_bytes = max_bytes
        self._rotate_count = max(0, rotate_count)
        self._bytes_written = self._fh.tell()

    def write(self, records: Sequence[Record]) -> int:
        n = 0
        with self._lock:
            for rec in records:
                line = json.dumps(rec.to_dict(), sort_keys=True, default=str) + "\n"
                blob = line.encode("utf-8")
                if self._bytes_written + len(blob) > self._max_bytes:
                    self._rotate()
                self._fh.write(line)
                self._bytes_written += len(blob)
                n += 1
            now = time.monotonic()
            if now - self._last_flush >= self._flush_interval:
                self._fh.flush()
                self._last_flush = now
            self.written += n
        return n

    def _rotate(self) -> None:
        self._fh.close()
        for i in range(self._rotate_count - 1, 0, -1):
            src = self.path.with_suffix(f"{self.path.suffix}.{i}")
            dst = self.path.with_suffix(f"{self.path.suffix}.{i + 1}")
            if src.exists():
                src.replace(dst)
        if self._rotate_count:
            self.path.replace(self.path.with_suffix(f"{self.path.suffix}.1"))
        self._fh = open(self.path, "w", encoding="utf-8")
        self._bytes_written = 0

    def flush(self) -> None:
        with self._lock:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._last_flush = time.monotonic()

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
            finally:
                self._fh.close()

    def __enter__(self) -> "JsonLineFileSink":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.close()
        return False


# --------------------------------------------------------------------------- #
# Subscription handles & buffered subscribers
# --------------------------------------------------------------------------- #

Callback = Callable[[Record], None]

_handle_ids = itertools.count(1)


class SubscriberHandle:
    """Returned by :meth:`EventBus.subscribe`; usable as a context manager."""

    __slots__ = ("key", "pattern", "callback", "filter", "once", "bus",
                 "created_at", "delivered", "errors", "unsubscribed", "name")

    def __init__(self, bus: "EventBus", pattern: Topic, callback: Callback,
                 *, event_filter: Optional[EventFilter] = None,
                 once: bool = False, name: str = "") -> None:
        self.key = next(_handle_ids)
        self.pattern = pattern
        self.callback = callback
        self.filter = event_filter
        self.once = once
        self.bus = bus
        self.created_at = time.time()
        self.delivered = 0
        self.errors = 0
        self.unsubscribed = False
        self.name = name or getattr(callback, "__qualname__", repr(callback))

    def unsubscribe(self) -> bool:
        return self.bus.unsubscribe(self)

    def stats(self) -> Dict[str, Any]:
        return {
            "key": self.key, "pattern": str(self.pattern), "name": self.name,
            "delivered": self.delivered, "errors": self.errors,
            "active": not self.unsubscribed,
        }

    def __enter__(self) -> "SubscriberHandle":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.unsubscribe()
        return False

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Subscriber {self.name} on {self.pattern}>"


class BufferedSubscriber:
    """Adapts a blocking/slow consumer into a non-blocking queue.

    Attach with ``bus.subscribe(topic, buf.push)`` then consume via
    :meth:`pop`, :meth:`drain`, iteration, or :meth:`wait`.
    """

    def __init__(self, capacity: int = 1000, *, on_overflow: str = "drop-oldest",
                 name: str = "buffered") -> None:
        if on_overflow not in ("drop-oldest", "drop-newest", "block"):
            raise EventError(f"bad overflow policy {on_overflow!r}")
        self.name = name
        self.capacity = capacity
        self.policy = on_overflow
        self._q: Deque[Record] = deque(maxlen=capacity)
        self._not_empty = threading.Condition()
        self.overflowed = 0
        self._closed = False

    def push(self, record: Record) -> None:
        if self._closed:
            return
        with self._not_empty:
            if len(self._q) == self.capacity:
                self.overflowed += 1
                if self.policy == "drop-newest":
                    return
                if self.policy == "block":
                    while len(self._q) == self.capacity and not self._closed:
                        self._not_empty.wait(timeout=0.05)
                    if self._closed:
                        return
                # drop-oldest handled automatically by deque(maxlen=...)
            self._q.append(record)
            self._not_empty.notify_all()

    def pop(self, timeout: Optional[float] = None) -> Optional[Record]:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._not_empty:
            while not self._q and not self._closed:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    self._not_empty.wait(remaining)
                else:
                    self._not_empty.wait(timeout=0.1)
            if self._q:
                return self._q.popleft()
            return None

    def wait(self, predicate: Predicate, timeout: Optional[float] = None) -> Optional[Record]:
        """Block until a queued record satisfies *predicate* (or timeout)."""
        deadline = time.monotonic() + timeout if timeout else None
        seen: List[Record] = []
        while True:
            rec = self.pop(0.05 if deadline else None)
            if rec is None:
                if deadline and time.monotonic() >= deadline:
                    for s in reversed(seen):
                        self._q.appendleft(s)
                    return None
                continue
            if predicate(rec):
                for s in reversed(seen):
                    self._q.appendleft(s)
                return rec
            seen.append(rec)

    def drain(self) -> List[Record]:
        with self._not_empty:
            out = list(self._q)
            self._q.clear()
            return out

    def close(self) -> None:
        with self._not_empty:
            self._closed = True
            self._not_empty.notify_all()

    def __iter__(self) -> Iterator[Record]:
        while True:
            rec = self.pop()
            if rec is None:
                return
            yield rec

    def __len__(self) -> int:
        return len(self._q)


# --------------------------------------------------------------------------- #
# The bus
# --------------------------------------------------------------------------- #

class EventBus:
    """Synchronous, thread-safe publish/subscribe bus.

    Features: wildcard subscriptions (:class:`TopicTrie`), one-shot
    subscribers, filters, throttling per pattern, replay ring, metrics,
    pluggable :class:`EventSink`s, and structured error capture.
    """

    DEFAULT_REPLAY = 10_000

    def __init__(self, name: str = "default", *, replay_capacity: int = DEFAULT_REPLAY,
                 capture_errors: bool = True) -> None:
        self.name = name
        self._lock = threading.RLock()
        self._trie = TopicTrie()
        self._handles: Dict[int, SubscriberHandle] = {}
        self._seq_counter = itertools.count(1)
        self._replay: Deque[Record] = deque(maxlen=max(0, replay_capacity))
        self._sinks: List[EventSink] = []
        self._throttle: Dict[int, float] = {}
        self._published = 0
        self._delivered = 0
        self._errors: List[EventError] = []
        self._capture_errors = capture_errors
        self._closed = False
        self._hooks: List[Callable[[Record], None]] = []   # internal observers (jobs)

    # -- subscription -----------------------------------------------------------
    def subscribe(self, pattern: Union[str, Topic], callback: Callback,
                  *, filter: Optional[EventFilter] = None, once: bool = False,
                  throttle_seconds: float = 0.0, name: str = "") -> SubscriberHandle:
        if self._closed:
            raise EventError("bus is closed")
        if not callable(callback):
            raise EventError("callback must be callable")
        pat = pattern if isinstance(pattern, Topic) else Topic(pattern)
        handle = SubscriberHandle(self, pat, callback, event_filter=filter,
                                  once=once, name=name)
        if throttle_seconds > 0:
            self._throttle[handle.key] = throttle_seconds
        with self._lock:
            self._trie.add(handle.key, pat)
            self._handles[handle.key] = handle
        return handle

    def unsubscribe(self, handle: Union[SubscriberHandle, int]) -> bool:
        key = handle if isinstance(handle, int) else handle.key
        with self._lock:
            existed = self._handles.pop(key, None) is not None
            self._trie.remove(key)
            self._throttle.pop(key, None)
        if existed and not isinstance(handle, int):
            handle.unsubscribed = True
        return existed

    def on(self, pattern: Union[str, Topic]) -> Callable[[Callback], Callback]:
        """Decorator form: ``@bus.on("kmcs.#")``."""
        def deco(fn: Callback) -> Callback:
            self.subscribe(pattern, fn)
            return fn
        return deco

    def listeners(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(h.stats() for h in self._handles.values())

    # -- emission ------------------------------------------------------------------
    def emit(self, topic: Union[str, Topic], type: Union[EventType, str],
             payload: Optional[Mapping[str, Any]] = None, *,
             source: str = "", tags: Iterable[str] = (),
             correlation_id: str = "") -> Record:
        """Publish a record; returns the (immutable) record for chaining/tests."""
        if self._closed:
            raise EventError("bus is closed")
        rec = Record(
            topic=topic if isinstance(topic, Topic) else Topic(topic),
            type=type if isinstance(type, EventType) else EventType(type),
            payload=dict(payload or {}),
            seq=next(self._seq_counter),
            source=source or self.name,
            tags=tuple(tags),
            correlation_id=correlation_id,
        )
        self._dispatch(rec)
        return rec

    def emit_typed(self, namespace: str, etype: EventType,
                   payload: Optional[Mapping[str, Any]] = None, **kw: Any) -> Record:
        return self.emit(Topic.from_event_type(namespace, etype), etype, payload, **kw)

    def _dispatch(self, rec: Record) -> None:
        with self._lock:
            self._published += 1
            self._replay.append(rec)
            keys = self._trie.collect(rec.topic)
            handles = [self._handles[k] for k in keys if k in self._handles]
            sinks = list(self._sinks)
            hooks = list(self._hooks)

        now = time.monotonic()
        survivors: List[Tuple[SubscriberHandle, bool]] = []
        for h in handles:
            throttle = self._throttle.get(h.key, 0.0)
            if throttle:
                last = getattr(h, "_last_fire", 0.0)
                if now - last < throttle:
                    continue
                h._last_fire = now  # type: ignore[attr-defined]
            try:
                if h.filter is not None and not h.filter(rec):
                    continue
            except Exception as exc:  # filter bug → isolate
                self._record_error(rec, h, exc)
                continue
            survivors.append((h, h.once))

        for h, once in survivors:
            try:
                h.callback(rec)
                h.delivered += 1
                self._delivered += 1
            except Exception as exc:
                h.errors += 1
                self._record_error(rec, h, exc)
            finally:
                if once:
                    self.unsubscribe(h)

        for hook in hooks:
            try:
                hook(rec)
            except Exception:  # internal observer failure must never propagate
                pass

        for sink in sinks:
            try:
                sink.write([rec])
            except Exception as exc:
                self._record_error(rec, None, exc)

    # -- sinks / hooks ---------------------------------------------------------------
    def add_sink(self, sink: EventSink) -> None:
        with self._lock:
            self._sinks.append(sink)

    def remove_sink(self, sink: EventSink) -> bool:
        with self._lock:
            try:
                self._sinks.remove(sink)
                return True
            except ValueError:
                return False

    def _add_hook(self, cb: Callable[[Record], None]) -> None:
        with self._lock:
            self._hooks.append(cb)

    # -- replay ------------------------------------------------------------------------
    def replay(self, pattern: Union[str, Topic, None] = None,
               *, limit: Optional[int] = None,
               since_seq: int = 0) -> Tuple[Record, ...]:
        pat = None if pattern is None else (
            pattern if isinstance(pattern, Topic) else Topic(pattern))
        with self._lock:
            out: List[Record] = []
            for rec in self._replay:
                if rec.seq <= since_seq:
                    continue
                if pat is not None and not pat.matches(rec.topic):
                    continue
                out.append(rec)
                if limit and len(out) >= limit:
                    break
            return tuple(out)

    def latest(self, pattern: Union[str, Topic] = "kmcs.#") -> Optional[Record]:
        recs = self.replay(pattern, limit=None)
        return recs[-1] if recs else None

    # -- metrics --------------------------------------------------------------------------
    def metrics(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "published": self._published,
                "delivered": self._delivered,
                "subscribers": len(self._handles),
                "patterns": self._trie.size(),
                "replay_size": len(self._replay),
                "replay_capacity": self._replay.maxlen,
                "sinks": {s.name: s.stats() for s in self._sinks},
                "errors": len(self._errors),
                "closed": self._closed,
            }

    def recent_errors(self) -> Tuple[EventError, ...]:
        with self._lock:
            return tuple(self._errors)

    def _record_error(self, rec: Record, handle: Optional[SubscriberHandle],
                      exc: BaseException) -> None:
        if not self._capture_errors:
            return
        err = EventError(
            f"event delivery failed on '{rec.topic}' ({rec.type.value}): {exc}",
            context={
                "topic": str(rec.topic), "seq": rec.seq,
                "subscriber": handle.name if handle else "sink",
                "cause_type": type(exc).__name__,
            },
        )
        with self._lock:
            self._errors.append(err)
            if len(self._errors) > 1000:
                del self._errors[: len(self._errors) - 1000]

    # -- lifecycle --------------------------------------------------------------------------
    def clear(self) -> None:
        with self._lock:
            self._trie.clear()
            self._handles.clear()
            self._throttle.clear()
            self._replay.clear()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for sink in self._sinks:
                try:
                    sink.flush()
                    sink.close()
                except Exception:
                    pass
            self._handles.clear()
            self._trie.clear()

    def __enter__(self) -> "EventBus":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.close()
        return False

    def __repr__(self) -> str:  # pragma: no cover
        m = self.metrics()
        return f"<EventBus {self.name} pub={m['published']} subs={m['subscribers']}>"


class AsyncEventBus(EventBus):
    """EventBus variant that delivers to subscribers on a worker thread.

    ``emit`` enqueues and returns immediately (bounded queue; oldest dropped
    under backpressure when ``drop_on_backpressure`` is true — telemetry must
    never stall a fuzzing loop).  Ordering is preserved by the single worker.
    """

    def __init__(self, name: str = "async", *, queue_max: int = 50_000,
                 drop_on_backpressure: bool = True, **kw: Any) -> None:
        super().__init__(name=name, **kw)
        self._queue: "queue.SimpleQueue[Optional[Record]]" = queue.SimpleQueue()
        self._pending = 0
        self._pending_lock = threading.Lock()
        self._queue_max = queue_max
        self._drop_on_backpressure = drop_on_backpressure
        self._dropped = 0
        self._worker = threading.Thread(target=self._run, name=f"kmcs-events-{name}",
                                        daemon=True)
        self._started = False
        self._stopping = threading.Event()

    def start(self) -> None:
        with self._lock:
            if not self._started:
                self._started = True
                self._worker.start()

    def _ensure_started(self) -> None:
        if not self._started:
            self.start()

    def emit(self, topic, type, payload=None, **kw) -> Record:  # type: ignore[override]
        if self._closed:
            raise EventError("bus is closed")
        rec = Record(
            topic=topic if isinstance(topic, Topic) else Topic(topic),
            type=type if isinstance(type, EventType) else EventType(type),
            payload=dict(payload or {}),
            seq=next(self._seq_counter),
            source=kw.pop("source", "") or self.name,
            tags=tuple(kw.pop("tags", ())),
            correlation_id=kw.pop("correlation_id", ""),
        )
        with self._pending_lock:
            if self._pending >= self._queue_max:
                if not self._drop_on_backpressure:
                    raise EventError("async bus queue full and dropping disabled")
                self._dropped += 1
                return rec
            self._pending += 1
        self._ensure_started()
        self._queue.put(rec)
        with self._lock:
            self._published += 1
            self._replay.append(rec)
        return rec

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:  # pragma: no cover - SimpleQueue has no timeout attr? 
                continue
            if item is None:
                break
            with self._pending_lock:
                self._pending -= 1
            super()._dispatch(item)

    # expose sync dispatch under a different name for the worker
    def _dispatch(self, rec: Record) -> None:  # pragma: no cover - direct use = sync escape hatch
        EventBus._dispatch(self, rec)

    def drain(self, timeout: float = 2.0) -> bool:
        """Wait until the pending queue empties (for tests/shutdown)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._pending_lock:
                if self._pending == 0:
                    return True
            time.sleep(0.01)
        return False

    def metrics(self) -> Dict[str, Any]:
        m = super().metrics()
        m.update({"mode": "async", "pending": self._pending, "dropped": self._dropped})
        return m

    def close(self) -> None:
        self._stopping.set()
        self._queue.put(None)
        if self._started and self._worker.is_alive():
            self._worker.join(timeout=1.0)
        super().close()


# --------------------------------------------------------------------------- #
# Ambient bus (contextvar) + module-level convenience API
# --------------------------------------------------------------------------- #

_BUS_STACK: contextvars.ContextVar[Tuple[EventBus, ...]] = contextvars.ContextVar(
    "kmcs_event_buses", default=())


@contextlib.contextmanager
def current_bus(bus: Optional[EventBus]) -> Iterator[Optional[EventBus]]:
    """Scoped ambient bus: ``with current_bus(my_bus): emit(...)``."""
    stack = _BUS_STACK.get()
    token = _BUS_STACK.set(stack + ((bus,) if bus is not None else ()))
    try:
        yield bus
    finally:
        _BUS_STACK.reset(token)


def _ambient_bus() -> EventBus:
    stack = _BUS_STACK.get()
    if not stack:
        raise EventError(
            "no active event bus — use with current_bus(bus): or pass bus explicitly")
    return stack[-1]


def emit(topic: Union[str, Topic], type: Union[EventType, str],
         payload: Optional[Mapping[str, Any]] = None, **kw: Any) -> Record:
    """Emit on the ambient bus (see :func:`current_bus`)."""
    return _ambient_bus().emit(topic, type, payload, **kw)


def subscribe(pattern: Union[str, Topic], callback: Callback,
              **kw: Any) -> SubscriberHandle:
    """Subscribe on the ambient bus."""
    return _ambient_bus().subscribe(pattern, callback, **kw)


# --------------------------------------------------------------------------- #
# Self-smoke
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    bus = EventBus("smoke")
    box: List[Record] = []
    bus.subscribe("kmcs.campaign.*.crash", box.append)
    bus.emit("kmcs.campaign.c1.crash", EventType.CRASH_FOUND, {"fp": "abc"})
    assert len(box) == 1 and box[0].get("fp") == "abc"
    print("events smoke OK:", bus.metrics()["published"], "published")
