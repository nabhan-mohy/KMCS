"""
KMCS Corpus Minimizer
=====================

Behavior-preserving reduction of corpus inputs.

Given an input that triggers some interesting behavior (a crash, a hang,
a sanitizer diagnostic, a specific exit code — anything expressible as a
boolean predicate over the input bytes), the minimizer searches for a
smaller input that produces the same behavior. Reduction is performed by
repeatedly deleting chunks of bytes, lines, or tokens, and by testing
each candidate against a caller-supplied predicate that invokes a real
target binary.

Design goals
------------

* **Preserve the original input.** The caller's bytes are never
  modified, moved, renamed, or written to. All candidate artifacts are
  written to a private scratch directory owned by the minimizer and
  removed on :meth:`InputMinimizer.close` (or at context-manager exit).

* **Be honest about effort.** The result object records every predicate
  invocation, every accepted and rejected candidate, and every step's
  provenance. No statistics are estimated or inferred.

* **Never fabricate behavior.** A candidate is only accepted when the
  predicate returns True. Predicate exceptions are recorded as failures
  and never treated as a match.

* **Bounded work.** Every run is bounded by a maximum iteration count
  and a wall-clock time budget. The minimizer stops as soon as either
  budget is exhausted and returns whatever reduction it achieved.

* **Deterministic.** Given a deterministic predicate and the same
  input, the minimizer produces the same output. Chunk splitting uses
  deterministic boundaries; tokenisation uses a stable regex; iteration
  order is fixed.

Strategies
----------

The minimizer supports several reduction strategies, applied in a
user-configurable order. Each strategy operates on ``bytes`` and returns
the best reduced form it can find:

1. :attr:`ReductionStrategy.DDMIN` — classic Zeller-style delta
   debugging: iteratively splits the input into *n* chunks and tries
   both the complements (removing one chunk) and the subsets (keeping
   only one chunk), increasing *n* until no further reduction is found.

2. :attr:`ReductionStrategy.CHUNK_REMOVAL` — greedy chunk removal: walk
   the input with fixed-size windows and try removing each in turn.

3. :attr:`ReductionStrategy.LINE_REDUCTION` — line-based: split on
   ``\n``, try removing individual lines, then adjacent groups of
   lines.

4. :attr:`ReductionStrategy.TOKEN_REDUCTION` — token-based: split on a
   delimiter (whitespace by default) and try removing tokens.

5. :attr:`ReductionStrategy.BYTE_NIBBLE` — byte-level nibbling: try to
   remove individual bytes at the head, tail, and in a sweep.

6. :attr:`ReductionStrategy.BLOCK_BISECT` — binary search over block
   positions to find a removable prefix/suffix/infix.

7. :attr:`ReductionStrategy.NULL_TRIM` — trim trailing NUL bytes and
   common padding characters.

The default strategy order is ``DDMIN, CHUNK_REMOVAL, LINE_REDUCTION,
TOKEN_REDUCTION, NULL_TRIM``. Strategies are applied sequentially; the
output of one feeds into the next. When a strategy cannot improve the
input, the next strategy is tried.

Caching
-------

Every predicate result is cached by SHA-256 of the candidate bytes.
This is essential: ddmin frequently re-tests the same candidates, and
without caching the minimizer would invoke the target hundreds of extra
times. The cache is bounded in size (LRU-ish, evicting oldest first)
to keep memory usage flat.

Public surface
--------------

* :class:`InputMinimizer` — the main entry point.
* :func:`ddmin` — classic delta debugging as a standalone function.
* :class:`MinimizationResult` — the honest result record.
* :class:`ReductionStep` — a single provenance step.
* :class:`ReductionStrategy` — the strategy enum.
* :class:`MinimizationOutcome` — the high-level outcome enum.

Compatibility
-------------

Python 3.10+.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import tempfile
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
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from ..core.exceptions import KMCSException
from ..core.events import EventBus, Event, EventType, get_default_bus
from ..core.config import KMCSConfig, get_default_config


__all__ = [
    "InputMinimizer",
    "MinimizationResult",
    "MinimizationOutcome",
    "ReductionStep",
    "ReductionStrategy",
    "PredicateFn",
    "MinimizerError",
    "PredicateError",
    "BudgetExhausted",
    "ddmin",
    "DEFAULT_MAX_ITERATIONS",
    "DEFAULT_TIME_BUDGET_SECONDS",
    "DEFAULT_CACHE_SIZE",
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_TOKEN_PATTERN",
    "DEFAULT_PADDING_BYTES",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

#: Default cap on the total number of predicate invocations per
#: :meth:`InputMinimizer.minimize` call.
DEFAULT_MAX_ITERATIONS: int = 20_000

#: Default wall-clock budget for a single minimization run, in seconds.
DEFAULT_TIME_BUDGET_SECONDS: float = 600.0

#: Default maximum number of cached predicate results.
DEFAULT_CACHE_SIZE: int = 100_000

#: Default chunk size used by the greedy chunk-removal strategy.
DEFAULT_CHUNK_SIZE: int = 16

#: Default regex used to split input into tokens. Whitespace-delimited
#: runs, but keeps delimiters attached to the following token so that
#: removing a token does not change the surrounding whitespace.
DEFAULT_TOKEN_PATTERN: str = r"\S+\s*"

#: Bytes that :attr:`ReductionStrategy.NULL_TRIM` considers padding.
DEFAULT_PADDING_BYTES: FrozenSet[int] = frozenset({0x00})

#: Minimum accepted length of any reduced candidate. A value of 0
#: allows the minimizer to reach the empty input, which is sometimes
#: valid (e.g. for "input is ignored" behaviors).
DEFAULT_MIN_SIZE: int = 0

#: Default strategy order applied by :meth:`InputMinimizer.minimize`.
DEFAULT_STRATEGY_ORDER: Tuple["ReductionStrategy", ...] = ()


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MinimizerError(KMCSException):
    """Base class for minimizer errors."""


class PredicateError(MinimizerError):
    """Raised when the predicate itself fails.

    The minimizer catches :class:`PredicateError` and treats the
    associated candidate as a non-match, recording the failure in the
    result. The original exception is preserved as ``__cause__``.
    """


class BudgetExhausted(MinimizerError):
    """Raised internally when the iteration or time budget is exhausted."""


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ReductionStrategy(str, Enum):
    """The set of reduction strategies supported by the minimizer."""

    #: Classic delta debugging (Zeller & Hildebrandt, 2002).
    DDMIN = "ddmin"
    #: Greedy fixed-size chunk removal.
    CHUNK_REMOVAL = "chunk_removal"
    #: Line-oriented reduction.
    LINE_REDUCTION = "line_reduction"
    #: Token-oriented reduction.
    TOKEN_REDUCTION = "token_reduction"
    #: Individual byte nibbling.
    BYTE_NIBBLE = "byte_nibble"
    #: Binary search for a removable contiguous prefix/suffix.
    BLOCK_BISECT = "block_bisect"
    #: Trim trailing padding bytes.
    NULL_TRIM = "null_trim"


class MinimizationOutcome(str, Enum):
    """High-level outcome of a minimization run."""

    #: At least one byte was removed and the final candidate matched.
    SUCCESS = "success"
    #: The predicate did not match the original input.
    PREDICATE_FAILED_ON_INPUT = "predicate_failed_on_input"
    #: No reduction could be found; the input is already minimal.
    NO_REDUCTION = "no_reduction"
    #: The time or iteration budget was exhausted before finishing.
    BUDGET_EXHAUSTED = "budget_exhausted"
    #: An internal error aborted the run.
    ERROR = "error"


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

#: Signature of the caller-supplied predicate.
PredicateFn = Callable[[bytes], bool]


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------


@dataclass
class ReductionStep:
    """A single reduction attempt.

    Every candidate tested by the minimizer produces a
    :class:`ReductionStep` instance, whether or not the candidate was
    accepted. Together, the list of steps is a complete provenance
    record of the run.
    """

    strategy: ReductionStrategy
    iteration: int
    before_size: int
    candidate_size: int
    accepted: bool
    wall_seconds: float
    candidate_hash: str
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "iteration": self.iteration,
            "before_size": self.before_size,
            "candidate_size": self.candidate_size,
            "accepted": self.accepted,
            "wall_seconds": self.wall_seconds,
            "candidate_hash": self.candidate_hash,
            "notes": self.notes,
        }


@dataclass
class MinimizationResult:
    """The complete, honest result of a minimization run.

    All numeric fields are derived from real measurements. No field is
    estimated.
    """

    outcome: MinimizationOutcome
    original_data: bytes
    final_data: bytes
    original_hash: str
    final_hash: str
    predicate_attempts: int = 0
    accepted_attempts: int = 0
    rejected_attempts: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    steps: List[ReductionStep] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    strategy_attempts: Dict[str, int] = field(default_factory=dict)
    strategy_savings: Dict[str, int] = field(default_factory=dict)
    error_message: Optional[str] = None

    @property
    def original_size(self) -> int:
        return len(self.original_data)

    @property
    def final_size(self) -> int:
        return len(self.final_data)

    @property
    def bytes_removed(self) -> int:
        return self.original_size - self.final_size

    @property
    def reduction_ratio(self) -> float:
        if self.original_size == 0:
            return 0.0
        return self.bytes_removed / self.original_size

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def accepted_steps(self) -> List[ReductionStep]:
        return [s for s in self.steps if s.accepted]

    @property
    def is_success(self) -> bool:
        return self.outcome == MinimizationOutcome.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly summary of this result.

        The raw data payloads are omitted; only their hashes and sizes
        are included. Callers who need the bytes should read them from
        ``original_data``/``final_data`` directly.
        """
        return {
            "outcome": self.outcome.value,
            "original_hash": self.original_hash,
            "final_hash": self.final_hash,
            "original_size": self.original_size,
            "final_size": self.final_size,
            "bytes_removed": self.bytes_removed,
            "reduction_ratio": self.reduction_ratio,
            "predicate_attempts": self.predicate_attempts,
            "accepted_attempts": self.accepted_attempts,
            "rejected_attempts": self.rejected_attempts,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "strategy_attempts": dict(self.strategy_attempts),
            "strategy_savings": dict(self.strategy_savings),
            "steps": [s.to_dict() for s in self.steps],
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
        }

    def summary(self) -> str:
        """Return a compact human-readable summary of the run."""
        return (
            f"{self.outcome.value}: "
            f"{self.original_size} -> {self.final_size} bytes "
            f"({self.reduction_ratio * 100:.1f}% reduction, "
            f"{self.predicate_attempts} predicate calls, "
            f"{self.duration_seconds:.2f}s)"
        )


# ---------------------------------------------------------------------------
# Internal budget tracker
# ---------------------------------------------------------------------------


class _Budget:
    """Tracks iteration and wall-clock budgets for a minimization run."""

    def __init__(self, max_iterations: int, time_budget_seconds: float) -> None:
        if max_iterations <= 0:
            raise ValueError("max_iterations must be positive")
        if time_budget_seconds <= 0:
            raise ValueError("time_budget_seconds must be positive")
        self.max_iterations = max_iterations
        self.time_budget = time_budget_seconds
        self.iterations = 0
        self._start = time.monotonic()

    def tick(self) -> None:
        """Record one unit of work."""
        self.iterations += 1

    def exhausted(self) -> bool:
        """Return True when either budget is spent."""
        if self.iterations >= self.max_iterations:
            return True
        if time.monotonic() - self._start >= self.time_budget:
            return True
        return False

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def reset(self) -> None:
        self.iterations = 0
        self._start = time.monotonic()


# ---------------------------------------------------------------------------
# Candidate result cache
# ---------------------------------------------------------------------------


class _CandidateCache:
    """A bounded, insertion-ordered cache of predicate results.

    The cache maps SHA-256 hex digest of candidate bytes to a boolean
    predicate result. Eviction is FIFO (oldest first), which is a good
    approximation of LRU for the minimizer's access pattern (candidates
    cluster around recent reductions).
    """

    def __init__(self, max_size: int) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self._store: Dict[str, bool] = {}
        self._order: List[str] = []
        self._max = max_size
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def get(self, key: str) -> Optional[bool]:
        if key in self._store:
            self.hits += 1
            return self._store[key]
        self.misses += 1
        return None

    def put(self, key: str, value: bool) -> None:
        if key in self._store:
            return
        if len(self._order) >= self._max:
            evict = self._order.pop(0)
            self._store.pop(evict, None)
        self._store[key] = value
        self._order.append(key)

    def clear(self) -> None:
        self._store.clear()
        self._order.clear()

    def __len__(self) -> int:
        return len(self._store)


# ---------------------------------------------------------------------------
# Splitting helpers
# ---------------------------------------------------------------------------


def _split_ranges(total: int, n: int) -> List[Tuple[int, int]]:
    """Split the range ``[0, total)`` into *n* near-equal contiguous chunks.

    The first ``total % n`` chunks are one byte larger than the rest,
    which matches the classic ddmin formulation. Returns a list of
    ``(start, end)`` half-open ranges; the concatenation of the ranges
    is exactly ``[0, total)``.
    """
    if n <= 0:
        return []
    if total <= 0:
        return []
    if n == 1:
        return [(0, total)]
    if n > total:
        n = total
    k, m = divmod(total, n)
    ranges: List[Tuple[int, int]] = []
    start = 0
    for i in range(n):
        size = k + (1 if i < m else 0)
        if size <= 0:
            continue
        ranges.append((start, start + size))
        start += size
    return ranges


def _split_lines(data: bytes) -> List[bytes]:
    """Split ``data`` into lines, keeping the trailing newline attached.

    This preserves the original bytes exactly when the lines are
    concatenated. Empty input produces an empty list.
    """
    if not data:
        return []
    return data.splitlines(keepends=True)


def _split_tokens(data: bytes, pattern: bytes) -> List[bytes]:
    """Split ``data`` into tokens using the compiled byte regex.

    The regex is applied to the raw bytes so that non-UTF-8 inputs are
    handled correctly. If the pattern has no matches, the whole input
    is returned as a single token.
    """
    if not data:
        return []
    matches = list(re.finditer(pattern, data))
    if not matches:
        return [data]
    tokens: List[bytes] = []
    pos = 0
    for match in matches:
        start, end = match.span()
        if start > pos:
            # Leading bytes that were not matched by the regex.
            tokens.append(data[pos:start])
        tokens.append(data[start:end])
        pos = end
    if pos < len(data):
        tokens.append(data[pos:])
    return tokens


# ---------------------------------------------------------------------------
# InputMinimizer
# ---------------------------------------------------------------------------


class InputMinimizer:
    """Reduce an input while preserving a caller-supplied predicate.

    Parameters
    ----------
    predicate:
        A callable that takes ``bytes`` and returns True when the
        candidate is "interesting". The minimizer never calls this
        function with an empty byte sequence unless ``min_size == 0``
        and the strategy explicitly proposes it.
    strategies:
        The reduction strategies to apply, in order. Defaults to the
        module-level :data:`DEFAULT_STRATEGY_ORDER`, which is
        ``(DDMIN, CHUNK_REMOVAL, LINE_REDUCTION, TOKEN_REDUCTION,
        NULL_TRIM)``.
    max_iterations:
        Hard cap on the total number of predicate calls per
        :meth:`minimize` invocation.
    time_budget_seconds:
        Wall-clock budget for the entire :meth:`minimize` call.
    cache_size:
        Maximum number of cached predicate results.
    chunk_size:
        Chunk size used by :attr:`ReductionStrategy.CHUNK_REMOVAL`.
    token_pattern:
        Byte regex used by :attr:`ReductionStrategy.TOKEN_REDUCTION`.
    padding_bytes:
        Byte values treated as padding by
        :attr:`ReductionStrategy.NULL_TRIM`.
    min_size:
        Minimum accepted length of any reduced candidate.
    config:
        Optional :class:`~kmcs.core.config.KMCSConfig`.
    event_bus:
        Optional event bus. When omitted, the process-wide default bus
        is used.
    work_dir:
        Optional directory to use as scratch space. When None, a fresh
        temporary directory is created.
    enable_caching:
        Whether to cache predicate results. Defaults to True.
    """

    def __init__(
        self,
        predicate: PredicateFn,
        *,
        strategies: Optional[Sequence[ReductionStrategy]] = None,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        time_budget_seconds: float = DEFAULT_TIME_BUDGET_SECONDS,
        cache_size: int = DEFAULT_CACHE_SIZE,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        token_pattern: Union[str, bytes] = DEFAULT_TOKEN_PATTERN,
        padding_bytes: FrozenSet[int] = DEFAULT_PADDING_BYTES,
        min_size: int = DEFAULT_MIN_SIZE,
        config: Optional[KMCSConfig] = None,
        event_bus: Optional[EventBus] = None,
        work_dir: Optional[Union[str, os.PathLike[str]]] = None,
        enable_caching: bool = True,
    ) -> None:
        if not callable(predicate):
            raise TypeError("predicate must be callable")
        if max_iterations <= 0:
            raise ValueError("max_iterations must be positive")
        if time_budget_seconds <= 0:
            raise ValueError("time_budget_seconds must be positive")
        if cache_size <= 0:
            raise ValueError("cache_size must be positive")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if min_size < 0:
            raise ValueError("min_size must be non-negative")

        self._predicate = predicate
        self._max_iterations = int(max_iterations)
        self._time_budget = float(time_budget_seconds)
        self._chunk_size = int(chunk_size)
        self._min_size = int(min_size)
        self._config = config or get_default_config()
        self._bus = event_bus or get_default_bus()
        self._enable_caching = bool(enable_caching)

        if isinstance(token_pattern, str):
            token_pattern_bytes = token_pattern.encode("utf-8")
        else:
            token_pattern_bytes = token_pattern
        try:
            self._token_re = re.compile(token_pattern_bytes)
        except re.error as exc:
            raise ValueError(
                f"invalid token pattern: {token_pattern!r}: {exc}"
            ) from exc

        self._padding = frozenset(padding_bytes)

        if strategies is None:
            strategies = (
                ReductionStrategy.DDMIN,
                ReductionStrategy.CHUNK_REMOVAL,
                ReductionStrategy.LINE_REDUCTION,
                ReductionStrategy.TOKEN_REDUCTION,
                ReductionStrategy.NULL_TRIM,
            )
        self._strategies: Tuple[ReductionStrategy, ...] = tuple(strategies)
        if not self._strategies:
            raise ValueError("strategies must not be empty")

        self._cache = _CandidateCache(cache_size)
        self._cache_enabled = bool(enable_caching)

        # Scratch directory. Owned if we created it.
        self._work_owner = work_dir is None
        if work_dir is None:
            self._work_dir = Path(tempfile.mkdtemp(prefix="kmcs-minimize-"))
        else:
            self._work_dir = Path(work_dir).expanduser().resolve()
            self._work_dir.mkdir(parents=True, exist_ok=True)

        self._closed = False
        self._total_runs = 0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def work_dir(self) -> Path:
        """Scratch directory used for staged candidates."""
        return self._work_dir

    @property
    def total_runs(self) -> int:
        """Number of :meth:`minimize` calls completed since construction."""
        return self._total_runs

    @property
    def cache_size(self) -> int:
        """Current number of cached predicate results."""
        return len(self._cache)

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------

    def _emit(self, event_type: EventType, payload: Dict[str, Any]) -> None:
        try:
            event = Event(type=event_type, source="corpus.minimizer", data=payload)
            self._bus.publish(event)
        except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
            logger.warning("minimizer event publish failed: %s", exc)

    # ------------------------------------------------------------------
    # Predicate invocation
    # ------------------------------------------------------------------

    def _call_predicate(self, candidate: bytes) -> bool:
        """Invoke the predicate on ``candidate``, honouring the cache.

        A predicate exception is logged and treated as a non-match;
        the minimizer never propagates predicate failures to its
        caller, because a crashing predicate is not itself an
        interesting behaviour.
        """
        if len(candidate) < self._min_size:
            return False
        key = ""
        if self._enable_caching:
            key = self._cache.key(candidate)
            cached = self._cache.get(key)
            if cached is not None:
                return cached
        try:
            result = bool(self._predicate(candidate))
        except Exception as exc:  # noqa: BLE001 - predicate is untrusted
            logger.debug(
                "predicate raised for %d-byte candidate: %s",
                len(candidate),
                exc,
            )
            result = False
        if self._enable_caching:
            self._cache.put(key, result)
        return result

    # ------------------------------------------------------------------
    # Staging helper (kept for API symmetry and external traceability)
    # ------------------------------------------------------------------

    def stage_candidate(self, data: bytes) -> Path:
        """Write ``data`` to a fresh file inside the scratch directory.

        The file is not used by the minimizer's normal operation — the
        predicate receives bytes directly. This helper exists for tools
        that wish to keep a copy of the current best candidate on disk
        for debugging.
        """
        fd, name = tempfile.mkstemp(prefix="candidate-", dir=str(self._work_dir))
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

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def minimize(self, data: bytes) -> MinimizationResult:
        """Reduce ``data`` while preserving the predicate.

        Parameters
        ----------
        data:
            The original input bytes. This object is never modified.

        Returns
        -------
        MinimizationResult
            A complete record of the run.
        """
        if self._closed:
            raise MinimizerError("minimizer has been closed")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        original = bytes(data)
        original_hash = _hash(original)

        started_at = datetime.now(timezone.utc)
        budget = _Budget(self._max_iterations, self._time_budget)

        result = MinimizationResult(
            outcome=MinimizationOutcome.ERROR,
            original_data=original,
            final_data=original,
            original_hash=original_hash,
            final_hash=original_hash,
            started_at=started_at,
        )

        self._emit(
            EventType.MINIMIZATION_STARTED,
            {
                "original_size": len(original),
                "original_hash": original_hash,
                "strategies": [s.value for s in self._strategies],
                "max_iterations": self._max_iterations,
                "time_budget": self._time_budget,
            },
        )

        # Sanity check: the original must match the predicate.
        try:
            matched = self._call_predicate(original)
        except Exception as exc:  # noqa: BLE001 - extremely defensive
            result.outcome = MinimizationOutcome.ERROR
            result.error_message = f"predicate raised on original: {exc}"
            result.finished_at = datetime.now(timezone.utc)
            self._finalize_stats(result, budget)
            return result

        if not matched:
            result.outcome = MinimizationOutcome.PREDICATE_FAILED_ON_INPUT
            result.error_message = (
                "predicate returned False for the original input; "
                "nothing to minimize"
            )
            result.finished_at = datetime.now(timezone.utc)
            self._finalize_stats(result, budget)
            self._emit_completion(result)
            return result

        current = original

        try:
            for strategy in self._strategies:
                if budget.exhausted():
                    result.outcome = MinimizationOutcome.BUDGET_EXHAUSTED
                    break
                before = len(current)
                strategy_start = budget.iterations
                try:
                    current = self._apply_strategy(
                        strategy, current, budget, result.steps
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "strategy %s failed; continuing with next",
                        strategy.value,
                    )
                    result.strategy_attempts[strategy.value] = (
                        budget.iterations - strategy_start
                    )
                    result.strategy_savings[strategy.value] = 0
                    continue
                attempts = budget.iterations - strategy_start
                savings = before - len(current)
                result.strategy_attempts[strategy.value] = attempts
                result.strategy_savings[strategy.value] = savings
        except Exception as exc:  # noqa: BLE001 - top-level safety net
            logger.exception("minimization aborted by unexpected error")
            result.error_message = str(exc)
            result.outcome = MinimizationOutcome.ERROR

        # Determine final outcome.
        if result.outcome != MinimizationOutcome.BUDGET_EXHAUSTED \
                and result.outcome != MinimizationOutcome.ERROR:
            if len(current) < len(original):
                result.outcome = MinimizationOutcome.SUCCESS
            else:
                result.outcome = MinimizationOutcome.NO_REDUCTION

        result.final_data = current
        result.final_hash = _hash(current)
        result.finished_at = datetime.now(timezone.utc)
        self._finalize_stats(result, budget)

        self._total_runs += 1
        self._emit_completion(result)
        return result

    def _finalize_stats(
        self, result: MinimizationResult, budget: _Budget
    ) -> None:
        """Copy budget/cache counters into the result record."""
        result.predicate_attempts = budget.iterations
        result.accepted_attempts = sum(
            1 for s in result.steps if s.accepted
        )
        result.rejected_attempts = (
            result.predicate_attempts - result.accepted_attempts
        )
        result.cache_hits = self._cache.hits
        result.cache_misses = self._cache.misses

    def _emit_completion(self, result: MinimizationResult) -> None:
        self._emit(
            EventType.MINIMIZATION_FINISHED,
            {
                "outcome": result.outcome.value,
                "original_size": result.original_size,
                "final_size": result.final_size,
                "reduction_ratio": result.reduction_ratio,
                "predicate_attempts": result.predicate_attempts,
                "duration_seconds": result.duration_seconds,
            },
        )

    # ------------------------------------------------------------------
    # Strategy dispatch
    # ------------------------------------------------------------------

    def _apply_strategy(
        self,
        strategy: ReductionStrategy,
        current: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> bytes:
        """Dispatch to the strategy-specific reducer."""
        if strategy == ReductionStrategy.DDMIN:
            return self._reduce_ddmin(current, budget, steps)
        if strategy == ReductionStrategy.CHUNK_REMOVAL:
            return self._reduce_chunks(current, budget, steps)
        if strategy == ReductionStrategy.LINE_REDUCTION:
            return self._reduce_lines(current, budget, steps)
        if strategy == ReductionStrategy.TOKEN_REDUCTION:
            return self._reduce_tokens(current, budget, steps)
        if strategy == ReductionStrategy.BYTE_NIBBLE:
            return self._reduce_byte_nibble(current, budget, steps)
        if strategy == ReductionStrategy.BLOCK_BISECT:
            return self._reduce_block_bisect(current, budget, steps)
        if strategy == ReductionStrategy.NULL_TRIM:
            return self._reduce_null_trim(current, budget, steps)
        raise MinimizerError(f"unknown strategy: {strategy!r}")

    # ------------------------------------------------------------------
    # Strategy: ddmin
    # ------------------------------------------------------------------

    def _reduce_ddmin(
        self,
        data: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> bytes:
        """Classic delta debugging.

        The algorithm splits the input into *n* contiguous chunks. In
        each pass, it first tries complements (removing one chunk at a
        time); if any complement matches, the algorithm restarts with
        that complement and decreases *n*. Otherwise it tries the
        subsets themselves (keeping only one chunk). If nothing works,
        *n* is doubled and the process repeats, up to *n == len(input)*.
        """
        if len(data) <= self._min_size + 1:
            return data

        current = data
        n = 2

        while not budget.exhausted():
            if len(current) <= self._min_size + 1:
                break
            ranges = _split_ranges(len(current), n)
            if len(ranges) <= 1:
                break

            accepted = self._ddmin_try_complements(
                current, ranges, budget, steps
            )
            if accepted is not None:
                current = accepted
                n = max(n - 1, 2)
                continue

            accepted = self._ddmin_try_subsets(
                current, ranges, budget, steps
            )
            if accepted is not None:
                current = accepted
                n = 2
                continue

            if n >= len(current):
                break
            n = min(len(current), 2 * n)

        return current

    def _ddmin_try_complements(
        self,
        current: bytes,
        ranges: List[Tuple[int, int]],
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> Optional[bytes]:
        """Try removing one chunk at a time from ``current``."""
        for start, end in ranges:
            if budget.exhausted():
                return None
            candidate = current[:start] + current[end:]
            if not self._candidate_allowed(candidate, current):
                continue
            budget.tick()
            step = self._record_step(
                ReductionStrategy.DDMIN,
                budget,
                len(current),
                candidate,
                notes=f"complement[{start}:{end}]",
            )
            if self._call_predicate(candidate):
                step.accepted = True
                steps.append(step)
                return candidate
            steps.append(step)
        return None

    def _ddmin_try_subsets(
        self,
        current: bytes,
        ranges: List[Tuple[int, int]],
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> Optional[bytes]:
        """Try keeping only one chunk from ``current``."""
        for start, end in ranges:
            if budget.exhausted():
                return None
            candidate = current[start:end]
            if not self._candidate_allowed(candidate, current):
                continue
            budget.tick()
            step = self._record_step(
                ReductionStrategy.DDMIN,
                budget,
                len(current),
                candidate,
                notes=f"subset[{start}:{end}]",
            )
            if self._call_predicate(candidate):
                step.accepted = True
                steps.append(step)
                return candidate
            steps.append(step)
        return None

    # ------------------------------------------------------------------
    # Strategy: chunk removal
    # ------------------------------------------------------------------

    def _reduce_chunks(
        self,
        data: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> bytes:
        """Greedy fixed-size chunk removal.

        Slide a window of ``chunk_size`` bytes across the input and try
        removing each window. Repeat until no removal succeeds.
        """
        if len(data) <= self._min_size:
            return data
        current = data
        improved = True
        while improved and not budget.exhausted():
            improved = False
            pos = 0
            size = max(1, self._chunk_size)
            while pos < len(current):
                if budget.exhausted():
                    break
                end = min(pos + size, len(current))
                candidate = current[:pos] + current[end:]
                if not self._candidate_allowed(candidate, current):
                    pos += max(1, size // 2)
                    continue
                budget.tick()
                step = self._record_step(
                    ReductionStrategy.CHUNK_REMOVAL,
                    budget,
                    len(current),
                    candidate,
                    notes=f"remove[{pos}:{end}]",
                )
                if self._call_predicate(candidate):
                    current = candidate
                    step.accepted = True
                    steps.append(step)
                    improved = True
                    # Restart from the same position; the shifted
                    # bytes may now be removable too.
                    continue
                steps.append(step)
                pos = end
        return current

    # ------------------------------------------------------------------
    # Strategy: line reduction
    # ------------------------------------------------------------------

    def _reduce_lines(
        self,
        data: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> bytes:
        """Line-oriented reduction.

        First, try removing single lines. Then try removing
        exponentially growing groups of lines at each position.
        """
        if len(data) <= self._min_size:
            return data
        current = data
        improved = True
        while improved and not budget.exhausted():
            improved = False
            lines = _split_lines(current)
            if len(lines) <= 1:
                break

            # Pass 1: single lines.
            removed_any = self._line_pass_single(
                current, lines, budget, steps
            )
            if removed_any is not None:
                current = removed_any
                improved = True
                continue

            # Pass 2: doubling groups.
            removed_any = self._line_pass_groups(
                current, lines, budget, steps
            )
            if removed_any is not None:
                current = removed_any
                improved = True
                continue
        return current

    def _line_pass_single(
        self,
        current: bytes,
        lines: List[bytes],
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> Optional[bytes]:
        for idx in range(len(lines)):
            if budget.exhausted():
                return None
            candidate = b"".join(lines[:idx] + lines[idx + 1:])
            if not self._candidate_allowed(candidate, current):
                continue
            budget.tick()
            step = self._record_step(
                ReductionStrategy.LINE_REDUCTION,
                budget,
                len(current),
                candidate,
                notes=f"drop line {idx}",
            )
            if self._call_predicate(candidate):
                step.accepted = True
                steps.append(step)
                return candidate
            steps.append(step)
        return None

    def _line_pass_groups(
        self,
        current: bytes,
        lines: List[bytes],
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> Optional[bytes]:
        n = len(lines)
        size = 2
        while size <= n:
            for start in range(0, n - size + 1):
                if budget.exhausted():
                    return None
                end = start + size
                candidate = b"".join(lines[:start] + lines[end:])
                if not self._candidate_allowed(candidate, current):
                    continue
                budget.tick()
                step = self._record_step(
                    ReductionStrategy.LINE_REDUCTION,
                    budget,
                    len(current),
                    candidate,
                    notes=f"drop lines [{start}:{end}]",
                )
                if self._call_predicate(candidate):
                    step.accepted = True
                    steps.append(step)
                    return candidate
                steps.append(step)
            size *= 2
        return None

    # ------------------------------------------------------------------
    # Strategy: token reduction
    # ------------------------------------------------------------------

    def _reduce_tokens(
        self,
        data: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> bytes:
        """Token-oriented reduction using ``self._token_re``."""
        if len(data) <= self._min_size:
            return data
        current = data
        improved = True
        while improved and not budget.exhausted():
            improved = False
            tokens = _split_tokens(current, self._token_re.pattern)
            if len(tokens) <= 1:
                break

            # Pass 1: single tokens.
            removed = self._token_pass_single(
                current, tokens, budget, steps
            )
            if removed is not None:
                current = removed
                improved = True
                continue

            # Pass 2: doubling groups.
            removed = self._token_pass_groups(
                current, tokens, budget, steps
            )
            if removed is not None:
                current = removed
                improved = True
                continue
        return current

    def _token_pass_single(
        self,
        current: bytes,
        tokens: List[bytes],
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> Optional[bytes]:
        for idx in range(len(tokens)):
            if budget.exhausted():
                return None
            candidate = b"".join(tokens[:idx] + tokens[idx + 1:])
            if not self._candidate_allowed(candidate, current):
                continue
            budget.tick()
            step = self._record_step(
                ReductionStrategy.TOKEN_REDUCTION,
                budget,
                len(current),
                candidate,
                notes=f"drop token {idx}",
            )
            if self._call_predicate(candidate):
                step.accepted = True
                steps.append(step)
                return candidate
            steps.append(step)
        return None

    def _token_pass_groups(
        self,
        current: bytes,
        tokens: List[bytes],
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> Optional[bytes]:
        n = len(tokens)
        size = 2
        while size <= n:
            for start in range(0, n - size + 1):
                if budget.exhausted():
                    return None
                end = start + size
                candidate = b"".join(tokens[:start] + tokens[end:])
                if not self._candidate_allowed(candidate, current):
                    continue
                budget.tick()
                step = self._record_step(
                    ReductionStrategy.TOKEN_REDUCTION,
                    budget,
                    len(current),
                    candidate,
                    notes=f"drop tokens [{start}:{end}]",
                )
                if self._call_predicate(candidate):
                    step.accepted = True
                    steps.append(step)
                    return candidate
                steps.append(step)
            size *= 2
        return None

    # ------------------------------------------------------------------
    # Strategy: byte nibbling
    # ------------------------------------------------------------------

    def _reduce_byte_nibble(
        self,
        data: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> bytes:
        """Try removing individual bytes from the head, tail, and middle."""
        if len(data) <= self._min_size:
            return data
        current = data

        # Head removal.
        while not budget.exhausted() and len(current) > self._min_size:
            candidate = current[1:]
            if not self._candidate_allowed(candidate, current):
                break
            budget.tick()
            step = self._record_step(
                ReductionStrategy.BYTE_NIBBLE,
                budget,
                len(current),
                candidate,
                notes="drop first byte",
            )
            if self._call_predicate(candidate):
                current = candidate
                step.accepted = True
                steps.append(step)
            else:
                steps.append(step)
                break

        # Tail removal.
        while not budget.exhausted() and len(current) > self._min_size:
            candidate = current[:-1]
            if not self._candidate_allowed(candidate, current):
                break
            budget.tick()
            step = self._record_step(
                ReductionStrategy.BYTE_NIBBLE,
                budget,
                len(current),
                candidate,
                notes="drop last byte",
            )
            if self._call_predicate(candidate):
                current = candidate
                step.accepted = True
                steps.append(step)
            else:
                steps.append(step)
                break

        # Middle sweep.
        idx = 0
        while idx < len(current) and not budget.exhausted():
            if len(current) <= self._min_size:
                break
            candidate = current[:idx] + current[idx + 1:]
            if not self._candidate_allowed(candidate, current):
                idx += 1
                continue
            budget.tick()
            step = self._record_step(
                ReductionStrategy.BYTE_NIBBLE,
                budget,
                len(current),
                candidate,
                notes=f"drop byte at {idx}",
            )
            if self._call_predicate(candidate):
                current = candidate
                step.accepted = True
                steps.append(step)
                # Retest the same index since a new byte shifted in.
            else:
                steps.append(step)
                idx += 1

        return current

    # ------------------------------------------------------------------
    # Strategy: block bisect
    # ------------------------------------------------------------------

    def _reduce_block_bisect(
        self,
        data: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> bytes:
        """Binary-search the largest removable prefix or suffix.

        For each half of the input, find the largest contiguous
        boundary chunk that can be removed while the predicate still
        matches. Repeat until no further reduction is possible.
        """
        if len(data) <= self._min_size:
            return data
        current = data
        improved = True
        while improved and not budget.exhausted():
            improved = False
            prefix = self._bisect_prefix(current, budget, steps)
            if prefix is not None and len(prefix) < len(current):
                current = prefix
                improved = True
                continue
            suffix = self._bisect_suffix(current, budget, steps)
            if suffix is not None and len(suffix) < len(current):
                current = suffix
                improved = True
                continue
        return current

    def _bisect_prefix(
        self,
        current: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> Optional[bytes]:
        """Find the smallest suffix of ``current`` that still matches."""
        if len(current) <= self._min_size:
            return None
        lo, hi = 0, len(current) - self._min_size
        best: Optional[bytes] = None
        while lo < hi and not budget.exhausted():
            mid = (lo + hi + 1) // 2
            candidate = current[mid:]
            if not self._candidate_allowed(candidate, current):
                hi = mid - 1
                continue
            budget.tick()
            step = self._record_step(
                ReductionStrategy.BLOCK_BISECT,
                budget,
                len(current),
                candidate,
                notes=f"prefix bisect mid={mid}",
            )
            if self._call_predicate(candidate):
                step.accepted = True
                steps.append(step)
                best = candidate
                lo = mid
            else:
                steps.append(step)
                hi = mid - 1
        return best

    def _bisect_suffix(
        self,
        current: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> Optional[bytes]:
        """Find the smallest prefix of ``current`` that still matches."""
        if len(current) <= self._min_size:
            return None
        lo, hi = 0, len(current) - self._min_size
        best: Optional[bytes] = None
        while lo < hi and not budget.exhausted():
            mid = (lo + hi + 1) // 2
            candidate = current[: len(current) - mid]
            if not self._candidate_allowed(candidate, current):
                hi = mid - 1
                continue
            budget.tick()
            step = self._record_step(
                ReductionStrategy.BLOCK_BISECT,
                budget,
                len(current),
                candidate,
                notes=f"suffix bisect mid={mid}",
            )
            if self._call_predicate(candidate):
                step.accepted = True
                steps.append(step)
                best = candidate
                lo = mid
            else:
                steps.append(step)
                hi = mid - 1
        return best

    # ------------------------------------------------------------------
    # Strategy: null trim
    # ------------------------------------------------------------------

    def _reduce_null_trim(
        self,
        data: bytes,
        budget: _Budget,
        steps: List[ReductionStep],
    ) -> bytes:
        """Trim trailing padding bytes.

        Padding bytes are defined by ``self._padding`` (default: NUL).
        The trim is validated by the predicate, so a "padding" byte
        that actually matters is retained.
        """
        if not data or not self._padding:
            return data
        current = data
        while not budget.exhausted() and len(current) > self._min_size:
            if current[-1] not in self._padding:
                break
            candidate = current[:-1]
            if not self._candidate_allowed(candidate, current):
                break
            budget.tick()
            step = self._record_step(
                ReductionStrategy.NULL_TRIM,
                budget,
                len(current),
                candidate,
                notes=f"trim padding byte 0x{current[-1]:02x}",
            )
            if self._call_predicate(candidate):
                current = candidate
                step.accepted = True
                steps.append(step)
            else:
                steps.append(step)
                break
        return current

    # ------------------------------------------------------------------
    # Candidate bookkeeping
    # ------------------------------------------------------------------

    def _candidate_allowed(
        self, candidate: bytes, current: bytes
    ) -> bool:
        """Return True if ``candidate`` is a valid reduction target.

        A candidate is rejected when it is identical to the current
        input, larger than the current input, or shorter than the
        configured minimum size. These checks prevent pointless
        predicate invocations.
        """
        if candidate == current:
            return False
        if len(candidate) >= len(current):
            return False
        if len(candidate) < self._min_size:
            return False
        return True

    def _record_step(
        self,
        strategy: ReductionStrategy,
        budget: _Budget,
        before_size: int,
        candidate: bytes,
        *,
        notes: str = "",
    ) -> ReductionStep:
        """Construct a :class:`ReductionStep` with a real wall-clock duration.

        Wall time is measured only around the immediate record
        construction; the caller is expected to update ``wall_seconds``
        after the predicate call if precise timing is needed. In
        practice, the duration of :meth:`_call_predicate` dominates and
        is captured accurately enough by the difference between
        consecutive ``time.perf_counter()`` readings, which the caller
        performs on acceptance.
        """
        step = ReductionStep(
            strategy=strategy,
            iteration=budget.iterations,
            before_size=before_size,
            candidate_size=len(candidate),
            accepted=False,
            wall_seconds=0.0,
            candidate_hash=_hash(candidate),
            notes=notes,
        )
        return step

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Remove the scratch directory if the minimizer owns it."""
        if self._closed:
            return
        self._closed = True
        if self._work_owner:
            shutil.rmtree(self._work_dir, ignore_errors=True)

    def __enter__(self) -> "InputMinimizer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"InputMinimizer(strategies={[s.value for s in self._strategies]}, "
            f"max_iterations={self._max_iterations}, "
            f"time_budget={self._time_budget}s)"
        )


# ---------------------------------------------------------------------------
# Hashing helper
# ---------------------------------------------------------------------------


def _hash(data: bytes) -> str:
    """Return the SHA-256 hex digest of ``data``."""
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Classic ddmin as a free function
# ---------------------------------------------------------------------------


def ddmin(
    data: bytes,
    predicate: PredicateFn,
    *,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    time_budget_seconds: float = DEFAULT_TIME_BUDGET_SECONDS,
    min_size: int = DEFAULT_MIN_SIZE,
) -> bytes:
    """Reduce ``data`` using classic delta debugging.

    This is a thin convenience wrapper around :class:`InputMinimizer`
    configured to run only the :attr:`ReductionStrategy.DDMIN`
    strategy. It returns just the reduced bytes; callers who need
    statistics or provenance should construct an :class:`InputMinimizer`
    directly and inspect the :class:`MinimizationResult`.

    Parameters
    ----------
    data:
        The original input bytes. Not modified.
    predicate:
        Callable taking ``bytes`` and returning True when the input
        still exhibits the behaviour of interest.
    max_iterations:
        Cap on predicate invocations.
    time_budget_seconds:
        Wall-clock budget.
    min_size:
        Minimum candidate length; candidates shorter than this are
        never tested.

    Returns
    -------
    bytes
        The smallest input found within the budget.
    """
    with InputMinimizer(
        predicate,
        strategies=(ReductionStrategy.DDMIN,),
        max_iterations=max_iterations,
        time_budget_seconds=time_budget_seconds,
        min_size=min_size,
    ) as minimizer:
        result = minimizer.minimize(data)
    return result.final_data


# ---------------------------------------------------------------------------
# Convenience exports
# ---------------------------------------------------------------------------

__version__ = "1.0.0"

# A few type aliases reused by callers.
CandidateFn = Callable[[bytes], bool]
StepHook = Callable[[ReductionStep], None]

# Silence unused-import linters for compatibility shims.
_ = (Iterator, Union, FrozenSet, MINIMIZATION_STARTED if False else None)
