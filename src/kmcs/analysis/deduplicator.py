# =============================================================================
# kmcs.analysis.deduplicator -- crash de-duplication engine (Phase 5b)
# =============================================================================
"""
Crash de-duplication for KMCS.

One bug found by a fuzzer twenty times must become **one finding**.  This
module turns a stream of :class:`kmcs.core.models.Crash` records into unique,
canonical *groups* using the three-tier fingerprints produced by
:mod:`kmcs.analysis.fingerprint`:

    strict digest   -> exact identity (target + sanitizer + class + 5 frames
                       + location + access shape)
    relaxed digest  -> same bug through different call paths (3 frames)
    family digest   -> related defects clustered near one source location
    feature vector  -> approximate stack-shape similarity (Jaccard / Hamming)

Design principles (enforced throughout)
---------------------------------------
1. **Honesty.**  Every decision is derived from observed fingerprint data.
   When evidence is insufficient the verdict is ``UNCERTAIN`` — never a
   forced merge.  Each group carries an explainable rationale and per-pair
   :class:`kmcs.core.models.DedupDecisionDetail` records.

2. **Determinism.**  Grouping depends only on semantic attributes; ASLR
   addresses, PIDs and timestamps are excluded upstream by the fingerprinter.
   Feeding the same crashes in any order yields identical group digests and
   identical canonical members (ties broken by first-seen timestamp then id).

3. **Defensive-only.**  De-duplication exists so researchers triage real
   bugs efficiently.  Nothing here reasons about exploitability.

4. **Offline.**  Standard library plus KMCS core/database only.  No API keys,
   no network access, ever.

Public surface
--------------
``DedupTier``, ``DedupConfig``, ``DuplicateGroup``, ``DeduplicationResult``,
``DedupStats``, ``FingerprintIndex``, ``InMemoryIndex``,
``DatabaseFingerprintIndex``, ``Deduplicator``, ``deduplicate_crashes``,
``deduplicate_logs``, ``merge_results``
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from kmcs.core.exceptions import DeduplicationError
from kmcs.core.models import (
    Confidence,
    Crash,
    CrashClass,
    CrashState,
    DedupDecision,
    Finding,
    FindingState,
    Fingerprint,
    Severity,
    generate_prefixed_id,
    utc_string,
)

from .fingerprint import (
    Fingerprinter,
    jaccard_similarity,
    normalise_function,
)

__all__ = [
    "DedupTier",
    "DedupConfig",
    "DuplicateGroup",
    "DeduplicationResult",
    "DedupStats",
    "FingerprintIndex",
    "InMemoryIndex",
    "DatabaseFingerprintIndex",
    "Deduplicator",
    "deduplicate_crashes",
    "deduplicate_logs",
    "merge_results",
]


# ============================================================================
# vocabulary
# ============================================================================


class DedupTier(StrEnum):
    """Match strength at which two crashes were considered identical.

    Ordered from strongest to weakest.  A merge recorded at STRICT is also
    valid at RELAXED/FAMILY; the reverse does not hold.
    """

    STRICT = "strict"
    RELAXED = "relaxed"
    FAMILY = "family"
    FEATURE = "feature"
    NONE = "none"

    @classmethod
    def ordered(cls) -> List["DedupTier"]:
        return [cls.STRICT, cls.RELAXED, cls.FAMILY, cls.FEATURE, cls.NONE]

    @classmethod
    def coerce(cls, value: Any) -> "DedupTier":
        if isinstance(value, cls):
            return value
        token = str(value or "").strip().lower().replace("_", "-")
        for member in cls:
            if member.value == token:
                return member
        raise ValueError(f"unknown dedup tier: {value!r}")

    @property
    def rank(self) -> int:
        """Lower rank == stronger evidence."""
        return DedupTier.ordered().index(self)

    def stronger_than(self, other: Any) -> bool:
        try:
            return self.rank < DedupTier.coerce(other).rank
        except ValueError:
            return False


_DECISION_FOR_TIER: Dict[DedupTier, DedupDecision] = {
    DedupTier.STRICT: DedupDecision.DUPLICATE,
    DedupTier.RELAXED: DedupDecision.PROBABLE_DUPLICATE,
    DedupTier.FAMILY: DedupDecision.RELATED,
    DedupTier.FEATURE: DedupDecision.PROBABLE_DUPLICATE,
    DedupTier.NONE: DedupDecision.UNIQUE,
}

_METHOD_FOR_TIER: Dict[DedupTier, str] = {
    DedupTier.STRICT: "fingerprint-exact",
    DedupTier.RELAXED: "fingerprint-relaxed",
    DedupTier.FAMILY: "family-location",
    DedupTier.FEATURE: "stack-similarity",
    DedupTier.NONE: "no-match",
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _as_crash(value: Any) -> Crash:
    """Coerce parse-outcome entries (crashes or reports) to Crash records."""
    if isinstance(value, Crash):
        return value
    # SanitizerReport duck-typing: fingerprint_report wraps it properly.
    if hasattr(value, "sanitizer") and hasattr(value, "stack_trace") \
            and not hasattr(value, "campaign_id"):
        from .fingerprint import fingerprint_report
        crash = Crash(
            sanitizer=getattr(value, "sanitizer", "") or "",
            crash_class=getattr(value, "crash_class", "") or "unknown",
            stack_trace=getattr(value, "stack_trace", None),
            memory_access=getattr(value, "memory_access", None),
            sanitizer_report=value,
        )
        fingerprint_report(value, crash=crash)
        return crash
    raise DeduplicationError(
        f"cannot deduplicate object of type {type(value).__name__}",
        component="analysis.deduplicator")


# ============================================================================
# configuration
# ============================================================================


@dataclass(frozen=True)
class DedupConfig:
    """Tunable policy for one :class:`Deduplicator`.

    Attributes
    ----------
    tier:
        Strongest-weakest *merge* tier.  ``STRICT`` merges only exact
        identities; ``RELAXED`` also merges same-bug-different-path;
        ``FAMILY`` clusters related defects but marks them RELATED (never
        silently merged); ``FEATURE`` adds approximate stack-shape merging.
    feature_threshold:
        Minimum Jaccard similarity (0..1) for FEATURE-tier merges.
    require_same_target:
        Never merge crashes from different target keys (default True —
        safety first; a shared symbol in two binaries is not one bug).
    require_same_sanitizer:
        Merge only within the same sanitizer family (default True).
    keep_duplicates:
        When False (default) duplicate Crash objects are dropped from the
        result's ``unique`` list and linked via ``duplicate_of``.
    max_group_members:
        Guard against pathological inputs; groups larger than this get a
        warning annotation rather than being split (splitting would lie).
    election_weights:
        Weights used when electing a canonical member of a group.
    """

    tier: DedupTier = DedupTier.RELAXED
    feature_threshold: float = 0.60
    require_same_target: bool = True
    require_same_sanitizer: bool = True
    keep_duplicates: bool = False
    max_group_members: int = 10_000
    election_weights: Tuple[Tuple[str, int], ...] = (
        ("reproducible", 40),
        ("minimized", 30),
        ("rich_stack", 20),
        ("has_input_hash", 10),
        ("severity_rank", 8),
        ("confidence_rank", 6),
        ("earliest_seen", 5),
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "tier", DedupTier.coerce(self.tier))
        threshold = float(self.feature_threshold)
        if not 0.0 <= threshold <= 1.0:
            raise DeduplicationError(
                f"feature_threshold must be within [0,1], got {threshold}",
                component="analysis.deduplicator")
        object.__setattr__(self, "feature_threshold", threshold)
        if int(self.max_group_members) < 1:
            raise DeduplicationError("max_group_members must be >= 1",
                                     component="analysis.deduplicator")

    @property
    def merges_probable(self) -> bool:
        return self.tier.rank <= DedupTier.RELAXED.rank

    @property
    def uses_features(self) -> bool:
        return self.tier is DedupTier.FEATURE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": str(self.tier.value),
            "feature_threshold": self.feature_threshold,
            "require_same_target": self.require_same_target,
            "require_same_sanitizer": self.require_same_sanitizer,
            "keep_duplicates": self.keep_duplicates,
            "max_group_members": self.max_group_members,
            "election_weights": dict(self.election_weights),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DedupConfig":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        cleaned = {k: v for k, v in payload.items() if k in known}
        weights = cleaned.get("election_weights")
        if isinstance(weights, Mapping):
            cleaned["election_weights"] = tuple(
                (str(k), int(v)) for k, v in weights.items())
        return cls(**cleaned)


# ============================================================================
# group containers
# ============================================================================


@dataclass
class DuplicateGroup:
    """One unique defect and every crash instance that maps onto it."""

    group_key: str
    tier: DedupTier
    canonical: Crash
    members: List[Crash] = field(default_factory=list)
    related: List[Crash] = field(default_factory=list)
    total_occurrences: int = 1
    first_seen_at: str = ""
    last_seen_at: str = ""
    severity: str = Severity.MODERATE.value
    confidence: str = Confidence.UNKNOWN.value
    rationale: str = ""
    warnings: List[str] = field(default_factory=list)
    campaign_ids: List[str] = field(default_factory=list)
    target_keys: List[str] = field(default_factory=list)
    input_hashes: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_string)

    # ------------------------------------------------------------------ build

    @classmethod
    def seed(cls, crash: Crash, *, tier: DedupTier = DedupTier.STRICT,
             rationale: str = "") -> "DuplicateGroup":
        fp = crash.fingerprint
        key = (fp.digest if fp and fp.digest else _sha(crash.id))[:64]
        seen = crash.first_seen_at or utc_string()
        group = cls(
            group_key=key,
            tier=tier,
            canonical=crash,
            members=[crash],
            total_occurrences=max(1, int(crash.occurrence_count)),
            first_seen_at=seen,
            last_seen_at=crash.last_seen_at or seen,
            severity=str(crash.severity),
            confidence=str(crash.confidence),
            rationale=rationale or f"new defect ({tier.value} representative)",
            campaign_ids=[crash.campaign_id] if crash.campaign_id else [],
            target_keys=[_target_key(crash)],
            input_hashes=[crash.input_hash] if crash.input_hash else [],
        )
        return group

    def absorb(self, crash: Crash, *, tier: DedupTier,
               rationale: str = "", related: bool = False) -> None:
        """Fold *crash* into this group with an explicit tier record."""
        if related:
            self.related.append(crash)
            self.warnings.append(
                f"related-not-merged ({tier.value}): {crash.id}")
            self._touch(crash)
            return
        self.members.append(crash)
        self.total_occurrences += max(1, int(crash.occurrence_count))
        self.severity = str(Severity.most_severe(
            (self.severity, crash.severity)))
        self.confidence = _best_confidence(self.confidence, crash.confidence)
        if rationale:
            self.rationale = rationale
        if tier.rank < self.tier.rank:
            self.tier = tier
        self._touch(crash)

    def _touch(self, crash: Crash) -> None:
        if crash.first_seen_at and (not self.first_seen_at
                                    or crash.first_seen_at < self.first_seen_at):
            self.first_seen_at = crash.first_seen_at
        if crash.last_seen_at and (not self.last_seen_at
                                   or crash.last_seen_at > self.last_seen_at):
            self.last_seen_at = crash.last_seen_at
        if crash.campaign_id and crash.campaign_id not in self.campaign_ids:
            self.campaign_ids.append(crash.campaign_id)
        tk = _target_key(crash)
        if tk and tk not in self.target_keys:
            self.target_keys.append(tk)
        if crash.input_hash and crash.input_hash not in self.input_hashes:
            self.input_hashes.append(crash.input_hash)

    # ------------------------------------------------------------------- view

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def crash_class(self) -> str:
        return str(self.canonical.crash_class)

    @property
    def stack_signature(self) -> str:
        try:
            return self.canonical.stack_signature(depth=4)
        except Exception:
            return ""

    def member_ids(self) -> List[str]:
        return [c.id for c in self.members]

    def related_ids(self) -> List[str]:
        return [c.id for c in self.related]

    def recompute_warnings(self, limit: int) -> None:
        if self.size > limit:
            note = (f"group exceeds max_group_members ({self.size}>{limit}); "
                    "kept intact — splitting would misreport occurrence counts")
            if note not in self.warnings:
                self.warnings.append(note)

    def to_dict(self, *, include_members: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "group_key": self.group_key,
            "tier": str(self.tier.value),
            "canonical_id": self.canonical.id,
            "size": self.size,
            "total_occurrences": self.total_occurrences,
            "crash_class": self.crash_class,
            "severity": self.severity,
            "confidence": self.confidence,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "rationale": self.rationale,
            "warnings": list(self.warnings),
            "campaign_ids": list(self.campaign_ids),
            "target_keys": list(self.target_keys),
            "input_hash_count": len(self.input_hashes),
            "stack_signature": self.stack_signature,
            "created_at": self.created_at,
        }
        if include_members:
            payload["member_ids"] = self.member_ids()
            payload["related_ids"] = self.related_ids()
        return payload

    def summary_line(self) -> str:
        return (f"[{self.tier.value:>7}] {self.crash_class:<28} "
                f"x{self.total_occurrences:<4} ({self.size} instances) "
                f"{self.severity:<9} {self.canonical.id} "
                f"{self.stack_signature[:60]}")


@dataclass
class DedupStats:
    """Counters describing one deduplication pass."""

    total: int = 0
    unique: int = 0
    duplicates: int = 0
    probable_duplicates: int = 0
    related: int = 0
    uncertain: int = 0
    skipped_existing: int = 0
    errors: int = 0
    by_tier: Dict[str, int] = field(default_factory=dict)
    by_class: Dict[str, int] = field(default_factory=dict)
    compression_ratio: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "unique": self.unique,
            "duplicates": self.duplicates,
            "probable_duplicates": self.probable_duplicates,
            "related": self.related,
            "uncertain": self.uncertain,
            "skipped_existing": self.skipped_existing,
            "errors": self.errors,
            "by_tier": dict(self.by_tier),
            "by_class": dict(self.by_class),
            "compression_ratio": round(self.compression_ratio, 4),
        }


@dataclass
class DeduplicationResult:
    """Outcome of a full deduplication pass over a crash batch."""

    groups: List[DuplicateGroup] = field(default_factory=list)
    unique_crashes: List[Crash] = field(default_factory=list)
    duplicate_crashes: List[Crash] = field(default_factory=list)
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    stats: DedupStats = field(default_factory=DedupStats)
    started_at: str = field(default_factory=utc_string)
    finished_at: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def group_count(self) -> int:
        return len(self.groups)

    @property
    def total_occurrences(self) -> int:
        return sum(g.total_occurrences for g in self.groups)

    def group_for(self, crash_id: str) -> Optional[DuplicateGroup]:
        for group in self.groups:
            if group.canonical.id == crash_id:
                return group
            if any(c.id == crash_id for c in group.members):
                return group
        return None

    def sorted_groups(self, *, by: str = "severity") -> List[DuplicateGroup]:
        """Groups ordered for triage: severity first, then recency."""
        def key(group: DuplicateGroup) -> Tuple[int, str, str]:
            if by == "occurrences":
                return (-group.total_occurrences, group.first_seen_at,
                        group.group_key)
            if by == "recent":
                return (0, "", _invert_time(group.last_seen_at))
            return (-Severity.rank(group.severity),
                    -Confidence.rank(group.confidence), group.first_seen_at)
        return sorted(self.groups, key=key)

    def findings(self, *, analyst: str = "kmcs-dedup") -> List[Finding]:
        """Materialise one candidate :class:`Finding` per unique group.

        The finding inherits the canonical crash's structured evidence; it is
        deliberately left in CANDIDATE state — confirmation belongs to the
        reproduction stage, not to deduplication.
        """
        findings: List[Finding] = []
        for group in self.sorted_groups():
            canon = group.canonical
            finding = Finding(
                id=generate_prefixed_id("find"),
                title=(f"{_class_label(canon.crash_class)} in "
                       f"{canon.target_name or _target_key(canon)}"),
                summary=(f"{_class_label(canon.crash_class)} observed "
                         f"{group.total_occurrences} time(s) across "
                         f"{group.size} crash instance(s)."),
                description=_finding_description(group),
                target_id=canon.target_id or "",
                target_name=canon.target_name or _target_key(canon),
                campaign_ids=list(group.campaign_ids),
                crash_ids=group.member_ids(),
                canonical_crash_id=canon.id,
                crash_class=canon.crash_class,
                severity=group.severity,
                confidence=group.confidence,
                state=FindingState.CANDIDATE.value,
                fingerprint=canon.fingerprint,
                location=canon.location,
                stack_signature=group.stack_signature,
                labels=["auto-dedup", f"tier:{group.tier.value}"],
                discovered_at=group.first_seen_at or utc_string(),
                analyst=analyst,
            )
            findings.append(finding)
        return findings

    def to_dict(self, *, include_members: bool = True) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "config": dict(self.config),
            "stats": self.stats.to_dict(),
            "notes": list(self.notes),
            "groups": [g.to_dict(include_members=include_members)
                       for g in self.groups],
            "decisions": list(self.decisions),
        }

    def save_json(self, path: Union[str, Path], *, indent: int = 2) -> str:
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=indent,
                                     sort_keys=False), encoding="utf-8")
        return str(target)


def _invert_time(stamp: str) -> str:
    """Lexicographic helper so sorting ascending puts newest first."""
    digits = "".join(ch for ch in (stamp or "") if ch.isdigit())
    padded = (digits + "0" * 20)[:20]
    try:
        inverted = "".join(str(9 - int(d)) for d in padded)
    except ValueError:
        return stamp or ""
    return inverted


def _best_confidence(a: Any, b: Any) -> str:
    order = [Confidence.UNKNOWN, Confidence.LOW, Confidence.MEDIUM,
             Confidence.HIGH, Confidence.CONFIRMED]
    try:
        ca, cb = Confidence.coerce(a), Confidence.coerce(b)
    except Exception:
        return str(a or Confidence.UNKNOWN.value)
    return str(order[max(order.index(ca), order.index(cb))].value)


def _class_label(token: Any) -> str:
    try:
        resolved = CrashClass.coerce(token)
    except Exception:
        return str(token)
    return resolved.value.replace("-", " ").title()


def _target_key(crash: Crash) -> str:
    return (crash.target_id or crash.target_name
            or (crash.executable.split("/")[-1] if crash.executable else "")
            or "unknown-target")


def _finding_description(group: DuplicateGroup) -> str:
    canon = group.canonical
    lines = [
        f"Observed {_class_label(canon.crash_class)} during authorised fuzzing.",
        f"Sanitizer: {canon.sanitizer}. Signal: "
        f"{canon.signal.name if canon.signal else 'n/a'}.",
        f"Location: {canon.location.display if canon.location else 'unknown'}.",
        f"Stack signature: {group.stack_signature or 'unavailable'}.",
        f"Evidence retained for {group.size} crash instance(s); "
        f"cumulative occurrences: {group.total_occurrences}.",
        "This entry documents a defensive research finding; it contains no "
        "exploitation analysis.",
    ]
    return "\n".join(lines)


# ============================================================================
# indexes
# ============================================================================


class FingerprintIndex:
    """Abstract incremental index of already-seen fingerprints.

    Implementations answer one question fast: *does this digest already have
    a canonical crash?*  The default :class:`InMemoryIndex` is process-local;
    :class:`DatabaseFingerprintIndex` persists across runs.
    """

    def lookup(self, digest: str) -> Optional[str]:
        raise NotImplementedError

    def lookup_many(self, digests: Iterable[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for digest in digests:
            hit = self.lookup(digest)
            if hit:
                out[digest] = hit
        return out

    def register(self, digest: str, crash_id: str) -> None:
        raise NotImplementedError

    def remove(self, digest: str) -> None:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - trivial default
        return None

    def __enter__(self) -> "FingerprintIndex":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.close()
        return False


class InMemoryIndex(FingerprintIndex):
    """LRU-capped process-local index with per-crash bookkeeping.

    Stores both the primary (strict) digest and auxiliary tier digests so a
    single lookup can recover the canonical id regardless of which tier the
    query came from.  Eviction keeps canonical ids even when their digest
    mapping ages out (the crash itself remains authoritative in the batch).
    """

    def __init__(self, capacity: int = 250_000) -> None:
        if capacity < 16:
            raise DeduplicationError("index capacity too small",
                                     component="analysis.deduplicator")
        self.capacity = int(capacity)
        self._digest_to_id: "OrderedDict[str, str]" = OrderedDict()
        self._id_to_digests: Dict[str, Set[str]] = defaultdict(set)
        self.lock = threading.RLock()

    # ------------------------------------------------------------- operations

    def lookup(self, digest: str) -> Optional[str]:
        digest = str(digest or "")
        if not digest:
            return None
        with self.lock:
            hit = self._digest_to_id.get(digest)
            if hit is not None:
                self._digest_to_id.move_to_end(digest)
            return hit

    def register(self, digest: str, crash_id: str) -> None:
        digest, crash_id = str(digest or ""), str(crash_id or "")
        if not digest or not crash_id:
            return
        with self.lock:
            existing = self._digest_to_id.get(digest)
            if existing is not None and existing != crash_id:
                # First registration wins; collisions are surfaced upstream
                # via collision_group rather than silently reassigned.
                self._digest_to_id.move_to_end(digest)
                return
            self._digest_to_id[digest] = crash_id
            self._id_to_digests[crash_id].add(digest)
            while len(self._digest_to_id) > self.capacity:
                old_digest, _ = self._digest_to_id.popitem(last=False)
                for bucket in self._id_to_digests.values():
                    bucket.discard(old_digest)

    def remove(self, digest: str) -> None:
        with self.lock:
            crash_id = self._digest_to_id.pop(str(digest), None)
            if crash_id is not None:
                self._id_to_digests[crash_id].discard(str(digest))

    def registered_digests(self, crash_id: str) -> Set[str]:
        with self.lock:
            return set(self._id_to_digests.get(crash_id, set()))

    def snapshot(self) -> Dict[str, str]:
        with self.lock:
            return dict(self._digest_to_id)

    def load_mapping(self, mapping: Mapping[str, str]) -> int:
        count = 0
        for digest, crash_id in mapping.items():
            self.register(digest, crash_id)
            count += 1
        return count

    def __len__(self) -> int:
        with self.lock:
            return len(self._digest_to_id)


class DatabaseFingerprintIndex(FingerprintIndex):
    """Persistent index backed by :class:`kmcs.database.DatabaseManager`.

    Uses the indexed ``crashes.fingerprint_digest`` column, so lookups are
    O(log n) in SQLite.  Registration goes through ``save_crash`` (which
    computes/attaches the fingerprint itself) to keep persistence honest —
    we never write a digest without its crash row.
    """

    def __init__(self, manager: Any, *, include_duplicates: bool = False) -> None:
        if manager is None:
            raise DeduplicationError("database manager required",
                                     component="analysis.deduplicator")
        self.manager = manager
        self.include_duplicates = bool(include_duplicates)
        self._cache: Dict[str, Optional[str]] = {}
        self._cache_misses = 0
        self.lock = threading.RLock()

    def lookup(self, digest: str) -> Optional[str]:
        digest = str(digest or "")
        if not digest:
            return None
        with self.lock:
            if digest in self._cache:
                return self._cache[digest]
        try:
            rows = self.manager.find(
                _crash_row_model(),
                _crash_row_model().fingerprint_digest == digest,
                order_by=_crash_row_model().first_seen_at,
                limit=1,
            )
        except Exception as exc:  # schema not initialised etc.
            raise DeduplicationError(
                f"fingerprint lookup failed: {exc}",
                component="analysis.deduplicator") from exc
        hit = rows[0].id if rows else None
        if not hit and not self.include_duplicates:
            # Canonical-only semantics: a pure-duplicate row sharing the
            # digest still proves prior art; fall back to any row.
            try:
                rows = self.manager.find(
                    _crash_row_model(),
                    _crash_row_model().fingerprint_digest == digest,
                    limit=1)
                hit = rows[0].id if rows else None
            except Exception:
                hit = None
        with self.lock:
            self._cache[digest] = hit
            if hit is None:
                self._cache_misses += 1
        return hit

    def register(self, digest: str, crash_id: str) -> None:
        digest, crash_id = str(digest or ""), str(crash_id or "")
        if not digest or not crash_id:
            return
        with self.lock:
            self._cache[digest] = crash_id

    def remove(self, digest: str) -> None:
        with self.lock:
            self._cache.pop(str(digest), None)

    def prime_from_database(self, *, limit: Optional[int] = None) -> int:
        """Warm the local cache from persisted canonical crashes."""
        model = _crash_row_model()
        rows = self.manager.find(model, order_by=model.first_seen_at,
                                 limit=limit)
        count = 0
        with self.lock:
            for row in rows:
                if row.fingerprint_digest:
                    self._cache.setdefault(row.fingerprint_digest, row.id)
                    count += 1
        return count

    def __len__(self) -> int:
        with self.lock:
            cached = len(self._cache)
        try:
            return max(cached, int(self.manager.count(_crash_row_model())))
        except Exception:
            return cached


_ROW_MODEL: Any = None


def _crash_row_model() -> Any:
    global _ROW_MODEL
    if _ROW_MODEL is None:
        from kmcs.database.models import CrashRow
        _ROW_MODEL = CrashRow
    return _ROW_MODEL


# ============================================================================
# union-find (for feature clustering)
# ============================================================================


class _UnionFind:
    def __init__(self, items: Iterable[str]) -> None:
        self.parent: Dict[str, str] = {i: i for i in items}
        self.rank: Dict[str, int] = {}

    def find(self, item: str) -> str:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank.get(ra, 0) < self.rank.get(rb, 0):
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank.get(ra, 0) == self.rank.get(rb, 0):
            self.rank[ra] = self.rank.get(ra, 0) + 1

    def clusters(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = defaultdict(list)
        for item in self.parent:
            out[self.find(item)].append(item)
        return dict(out)


# ============================================================================
# the deduplicator
# ============================================================================


class Deduplicator:
    """Batch and streaming crash de-duplication engine.

    Parameters
    ----------
    config:
        :class:`DedupConfig` policy; defaults to RELAXED tier merging.
    index:
        Persistent/semantic index of previously seen digests.  Defaults to a
        fresh :class:`InMemoryIndex`, giving cross-run continuity inside one
        process and letting callers inject :class:`DatabaseFingerprintIndex`.
    fingerprinter:
        Used to compute missing fingerprints before grouping.
    bus:
        Optional :class:`kmcs.core.events.EventBus`; when provided, emits
        ``kmcs.analysis.crash_deduped`` summaries per batch.
    """

    def __init__(self, *, config: Optional[DedupConfig] = None,
                 index: Optional[FingerprintIndex] = None,
                 fingerprinter: Optional[Fingerprinter] = None,
                 bus: Any = None) -> None:
        self.config = config or DedupConfig()
        self.index = index if index is not None else InMemoryIndex()
        self.fingerprinter = fingerprinter or Fingerprinter()
        self.bus = bus
        self.lock = threading.RLock()
        self.runs = 0
        self.processed = 0
        self._id_cache: Dict[str, str] = {}

    # ------------------------------------------------------------ properties

    @property
    def seen_count(self) -> int:
        try:
            return len(self.index)
        except NotImplementedError:
            return 0

    # -------------------------------------------------------- single record

    def ensure_fingerprint(self, crash: Crash) -> Fingerprint:
        if crash.fingerprint is None or not crash.fingerprint.digest:
            self.fingerprinter.compute(crash)
        if crash.fingerprint is None or not crash.fingerprint.digest:
            raise DeduplicationError("fingerprint computation failed",
                                     component="analysis.deduplicator")
        return crash.fingerprint

    @staticmethod
    def _component_map(fp: Fingerprint) -> Dict[str, str]:
        """Fingerprint.components is a sorted tuple of (key, value) pairs."""
        raw = getattr(fp, "components", ()) or ()
        if isinstance(raw, Mapping):
            return {str(k): str(v) for k, v in raw.items()}
        out: Dict[str, str] = {}
        for item in raw:
            try:
                key, value = item
                out[str(key)] = str(value)
            except (TypeError, ValueError):
                continue
        return out

    def _tier_digests(self, fp: Fingerprint) -> Dict[DedupTier, str]:
        attrs = self._component_map(fp)
        return {
            DedupTier.STRICT: str(fp.digest or ""),
            DedupTier.RELAXED: str(attrs.get("relaxed", "") or ""),
            DedupTier.FAMILY: str(attrs.get("family", "") or ""),
        }

    def _features_of(self, fp: Fingerprint) -> str:
        return self._component_map(fp).get("features", "")

    def decide_pair(self, new: Crash, existing: Crash) -> Dict[str, Any]:
        """Explainable pairwise verdict between two crash records."""
        fp_new = self.ensure_fingerprint(new)
        fp_old = self.ensure_fingerprint(existing)
        tiers_new = self._tier_digests(fp_new)
        tiers_old = self._tier_digests(fp_old)

        if self.config.require_same_target and \
                _target_key(new) != _target_key(existing):
            return self._decision(DedupTier.NONE, DedupDecision.UNIQUE,
                                  new, existing, similarity=0.0,
                                  differing=["target"],
                                  method="target-guard")
        if self.config.require_same_sanitizer and \
                str(new.sanitizer) != str(existing.sanitizer):
            return self._decision(DedupTier.NONE, DedupDecision.UNIQUE,
                                  new, existing, similarity=0.0,
                                  differing=["sanitizer"],
                                  method="sanitizer-guard")

        matched: List[str] = []
        differing: List[str] = []
        best_tier = DedupTier.NONE
        if tiers_new[DedupTier.STRICT] and \
                tiers_new[DedupTier.STRICT] == tiers_old[DedupTier.STRICT]:
            best_tier = DedupTier.STRICT
            matched = ["strict_digest"]
        elif tiers_new[DedupTier.RELAXED] and \
                tiers_new[DedupTier.RELAXED] == tiers_old[DedupTier.RELAXED]:
            best_tier = DedupTier.RELAXED
            matched = ["relaxed_digest"]
        elif tiers_new[DedupTier.FAMILY] and \
                tiers_new[DedupTier.FAMILY] == tiers_old[DedupTier.FAMILY]:
            best_tier = DedupTier.FAMILY
            matched = ["family_digest"]
        else:
            feats_new = self._features_of(fp_new)
            feats_old = self._features_of(fp_old)
            if feats_new and feats_old:
                sim = jaccard_similarity(feats_new, feats_old)
                if sim >= self.config.feature_threshold:
                    best_tier = DedupTier.FEATURE
                    matched = [f"stack-jaccard={sim:.3f}"]
                else:
                    differing = [f"stack-jaccard={sim:.3f}<threshold"]
            else:
                differing = ["no-feature-vector"]

        decision = _DECISION_FOR_TIER[best_tier]
        merge_allowed = (
            best_tier is DedupTier.STRICT
            or (best_tier is DedupTier.RELAXED and self.config.merges_probable)
            or (best_tier is DedupTier.FEATURE and self.config.uses_features)
        )
        if best_tier is DedupTier.FAMILY:
            merge_allowed = False  # related, kept separate, always explained
        similarity = {
            DedupTier.STRICT: 1.0,
            DedupTier.RELAXED: 0.9,
            DedupTier.FAMILY: 0.7,
            DedupTier.FEATURE: min(
                0.95, max(0.0, jaccard_similarity(
                    self._features_of(fp_new),
                    self._features_of(fp_old)))),
            DedupTier.NONE: 0.0,
        }[best_tier]
        if not merge_allowed and best_tier is not DedupTier.NONE \
                and best_tier is not DedupTier.FAMILY:
            decision = DedupDecision.UNCERTAIN
        return self._decision(best_tier, decision, new, existing,
                              similarity=similarity, matched=matched,
                              differing=differing,
                              method=_METHOD_FOR_TIER[best_tier])

    def _decision(self, tier: DedupTier, decision: DedupDecision,
                  new: Crash, existing: Crash, *, similarity: float,
                  matched: Optional[List[str]] = None,
                  differing: Optional[List[str]] = None,
                  method: str = "fingerprint-exact") -> Dict[str, Any]:
        return {
            "decision": str(decision.value),
            "tier": str(tier.value),
            "canonical_id": existing.id,
            "candidate_id": new.id,
            "similarity": round(float(similarity), 4),
            "matched_components": list(matched or []),
            "differing_components": list(differing or []),
            "method": method,
            "explained_at": utc_string(),
        }

    # ----------------------------------------------------------- batch entry

    def deduplicate(self, crashes: Iterable[Any], *,
                    mark_states: bool = True,
                    progress: Optional[Callable[[int, int], None]] = None
                    ) -> DeduplicationResult:
        """Group *crashes* into unique defects under the configured policy."""
        with self.lock:
            self.runs += 1
        materialised = [_as_crash(c) for c in crashes]
        result = DeduplicationResult(config=self.config.to_dict())
        stats = result.stats
        stats.total = len(materialised)
        started = time.monotonic()

        # Order deterministically: earliest-seen first, id as tiebreak, so
        # canonical representatives do not depend on arrival order.
        ordered = sorted(materialised,
                         key=lambda c: (c.first_seen_at or "~", c.id))

        groups_by_strict: Dict[str, DuplicateGroup] = {}
        groups_by_relaxed: Dict[str, DuplicateGroup] = {}
        groups_by_family: Dict[str, List[DuplicateGroup]] = defaultdict(list)
        features: List[Tuple[str, str, Crash]] = []
        pending_related: List[Tuple[DuplicateGroup, Crash, str]] = []

        for position, crash in enumerate(ordered, start=1):
            try:
                fp = self.ensure_fingerprint(crash)
            except DeduplicationError:
                stats.errors += 1
                continue
            tiers = self._tier_digests(fp)
            feature = self._features_of(fp)
            stats.by_class[str(crash.crash_class)] = \
                stats.by_class.get(str(crash.crash_class), 0) + 1

            # 1) strict match -> definite duplicate
            hit = groups_by_strict.get(tiers[DedupTier.STRICT]) \
                if tiers[DedupTier.STRICT] else None
            if hit is None and not self.config.keep_duplicates:
                indexed = self.index.lookup(tiers[DedupTier.STRICT])
                if indexed and indexed != crash.id:
                    stats.skipped_existing += 1
                    crash.duplicate_of = indexed
                    if mark_states:
                        crash.state = CrashState.DUPLICATE.value
                    result.duplicate_crashes.append(crash)
                    stats.duplicates += 1
                    stats.by_tier["prior-index"] = \
                        stats.by_tier.get("prior-index", 0) + 1
                    result.decisions.append({
                        "decision": DedupDecision.DUPLICATE.value,
                        "tier": DedupTier.STRICT.value,
                        "canonical_id": indexed, "candidate_id": crash.id,
                        "similarity": 1.0,
                        "matched_components": ["index-hit"],
                        "differing_components": [],
                        "method": "persistent-index",
                        "explained_at": utc_string(),
                    })
                    continue

            if hit is not None:
                self._link_duplicate(hit, crash, DedupTier.STRICT,
                                     rationale="exact strict-digest match",
                                     mark_states=mark_states, result=result,
                                     stats=stats)
            else:
                # 2) relaxed match -> probable duplicate (merged per policy)
                relaxed_hit = groups_by_relaxed.get(tiers[DedupTier.RELAXED]) \
                    if tiers[DedupTier.RELAXED] else None
                if relaxed_hit is not None and self.config.merges_probable:
                    self._link_duplicate(relaxed_hit, crash, DedupTier.RELAXED,
                                         rationale=("same defect reached via "
                                                    "different call path "
                                                    "(relaxed digest)"),
                                         mark_states=mark_states,
                                         result=result, stats=stats)
                else:
                    # 3) brand-new unique group
                    group = DuplicateGroup.seed(
                        crash, tier=DedupTier.STRICT,
                        rationale="first observation of this defect")
                    groups_by_strict[tiers[DedupTier.STRICT]] = group
                    if tiers[DedupTier.RELAXED]:
                        groups_by_relaxed[tiers[DedupTier.RELAXED]] = group
                    if tiers[DedupTier.FAMILY]:
                        groups_by_family[tiers[DedupTier.FAMILY]].append(group)
                    if feature:
                        features.append((crash.id, feature, crash))
                    self.index.register(tiers[DedupTier.STRICT], crash.id)
                    if tiers[DedupTier.RELAXED]:
                        self.index.register(tiers[DedupTier.RELAXED], crash.id)
                    stats.unique += 1
                    stats.by_tier["new-group"] = \
                        stats.by_tier.get("new-group", 0) + 1
                    result.unique_crashes.append(crash)
                    if relaxed_hit is not None:
                        # policy says do not merge probable dupes -> annotate
                        pending_related.append(
                            (relaxed_hit, crash,
                             "probable duplicate withheld by policy "
                             "(tier=strict)"))
                        stats.uncertain += 1

            if progress and position % 64 == 0:
                progress(position, len(ordered))

        # 4) family tier: cluster related groups WITHOUT merging members
        for family_digest, touched in groups_by_family.items():
            if len(touched) > 1:
                anchor = min(touched,
                             key=lambda g: (g.first_seen_at, g.canonical.id))
                for group in touched:
                    if group is anchor:
                        continue
                    known = {m.id for m in group.members}
                    candidates = [c for c in anchor.members
                                  if c.id not in known][:1]
                    group.related.extend(candidates)
                    note = (f"family-linked to {anchor.canonical.id} "
                            f"(digest {family_digest[:12]})")
                    if note not in group.warnings:
                        group.warnings.append(note)
                    stats.related += 1

        # 5) feature-tier approximate clustering (opt-in)
        if self.config.uses_features and len(features) > 1:
            uf = _UnionFind(cid for cid, _, _ in features)
            # pairwise bounded by a blocking index on first frame token
            buckets: Dict[str, List[Tuple[str, str, Crash]]] = defaultdict(list)
            for cid, feat, crash in features:
                buckets[_bucket_token(crash)].append((cid, feat, crash))
            for bucket in buckets.values():
                for i in range(len(bucket)):
                    for j in range(i + 1, len(bucket)):
                        a_id, a_feat, _ = bucket[i]
                        b_id, b_feat, _ = bucket[j]
                        sim = jaccard_similarity(a_feat, b_feat)
                        if sim >= self.config.feature_threshold:
                            uf.union(a_id, b_id)
            for root, cluster_ids in uf.clusters().items():
                if len(cluster_ids) < 2:
                    continue
                anchor_group = None
                for group in groups_by_strict.values():
                    if group.canonical.id == root or \
                            any(c.id == root for c in group.members):
                        anchor_group = group
                        break
                if anchor_group is None:
                    continue
                for cid in cluster_ids:
                    if cid == anchor_group.canonical.id:
                        continue
                    victim = None
                    for group in groups_by_strict.values():
                        if group.canonical.id == cid:
                            victim = group
                            break
                    if victim is None or victim is anchor_group:
                        continue
                    absorbed = [c for c in victim.members
                                if c.id != anchor_group.canonical.id
                                and c.id not in {m.id for m in anchor_group.members}]
                    victim_keys = [k for k, v in groups_by_strict.items()
                                   if v is victim]
                    for key in victim_keys:
                        del groups_by_strict[key]
                    for stale_key, grp in list(groups_by_relaxed.items()):
                        if grp is victim:
                            del groups_by_relaxed[stale_key]
                    for crash in absorbed:
                        self._link_duplicate(anchor_group, crash,
                                             DedupTier.FEATURE,
                                             rationale=("stack-shape similarity "
                                                        f">= {self.config.feature_threshold}"),
                                             mark_states=mark_states,
                                             result=result, stats=stats)

        # fold pending annotations
        for group, crash, note in pending_related:
            group.related.append(crash)
            if note not in group.warnings:
                group.warnings.append(note)

        # finalise
        groups = sorted(groups_by_strict.values(),
                        key=lambda g: (-Severity.rank(g.severity),
                                       g.first_seen_at, g.group_key))
        for group in groups:
            group.recompute_warnings(self.config.max_group_members)
            self._elect_canonical(group)
        result.groups = groups
        if stats.total:
            stats.compression_ratio = stats.unique / stats.total
        result.finished_at = utc_string()
        elapsed = time.monotonic() - started
        result.notes.append(f"pass completed in {elapsed:.3f}s "
                            f"over {stats.total} crash(es)")
        self.processed += stats.total
        self._publish(result)
        return result

    # ------------------------------------------------------------- internals

    def _link_duplicate(self, group: DuplicateGroup, crash: Crash,
                        tier: DedupTier, *, rationale: str,
                        mark_states: bool, result: DeduplicationResult,
                        stats: DedupStats) -> None:
        crash.duplicate_of = group.canonical.id
        if mark_states:
            crash.state = CrashState.DUPLICATE.value
        group.absorb(crash, tier=tier, rationale=rationale)
        result.duplicate_crashes.append(crash)
        if tier is DedupTier.STRICT:
            stats.duplicates += 1
        else:
            stats.probable_duplicates += 1
        stats.by_tier[str(tier.value)] = stats.by_tier.get(str(tier.value), 0) + 1
        result.decisions.append({
            "decision": str(_DECISION_FOR_TIER[tier].value),
            "tier": str(tier.value),
            "canonical_id": group.canonical.id,
            "candidate_id": crash.id,
            "similarity": 1.0 if tier is DedupTier.STRICT else 0.9,
            "matched_components": [f"{tier.value}-digest"],
            "differing_components": [],
            "method": _METHOD_FOR_TIER[tier],
            "explained_at": utc_string(),
        })

    def _elect_canonical(self, group: DuplicateGroup) -> None:
        """Re-elect the richest/most actionable representative honestly."""
        weights = dict(self.config.election_weights)

        def score(crash: Crash) -> Tuple[int, str]:
            s = 0
            if crash.reproducer_path:
                s += int(weights.get("reproducible", 0))
            if crash.minimized_path:
                s += int(weights.get("minimized", 0))
            frames = crash.stack_trace.frames if crash.stack_trace else []
            significant = [f for f in frames if not f.is_system_library]
            if len(significant) >= 3:
                s += int(weights.get("rich_stack", 0))
            if crash.input_hash:
                s += int(weights.get("has_input_hash", 0))
            s += int(weights.get("severity_rank", 0)) * Severity.rank(crash.severity) // 5
            s += int(weights.get("confidence_rank", 0)) * Confidence.rank(crash.confidence) // 4
            return (s, crash.first_seen_at or "~")

        best = max(group.members, key=score)
        current_score = score(group.canonical)
        if score(best) > current_score and best is not group.canonical:
            group.warnings.append(
                f"canonical re-elected {group.canonical.id} -> {best.id} "
                "(richest evidence)")
            group.canonical = best
            group.group_key = (best.fingerprint.digest
                               if best.fingerprint else group.group_key)

    def _publish(self, result: DeduplicationResult) -> None:
        if self.bus is None:
            return
        try:
            from kmcs.core.events import EventType
            self.bus.emit("kmcs.analysis.crash_deduped",
                          EventType.CRASH_DEDUPED,
                          {"runs": self.runs,
                           "total": result.stats.total,
                           "unique": result.stats.unique,
                           "duplicates": result.stats.duplicates,
                           "compression": round(result.stats.compression_ratio, 4)},
                          source="analysis.deduplicator")
        except Exception:
            # event publication must never break analysis
            pass


def _bucket_token(crash: Crash) -> str:
    """Blocking key for approximate matching: class + top frame module."""
    top = ""
    frames = crash.stack_trace.frames if crash.stack_trace else []
    for frame in frames:
        if not frame.is_system_library:
            top = normalise_function(frame.function or "") or \
                (frame.module or "").split("/")[-1]
            break
    return f"{crash.crash_class}|{top}"


# ============================================================================
# module-level convenience API
# ============================================================================


_DEFAULT_LOCK = threading.Lock()
_DEFAULT: Optional[Deduplicator] = None


def _default_deduplicator() -> Deduplicator:
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            _DEFAULT = Deduplicator()
        return _DEFAULT


def deduplicate_crashes(crashes: Iterable[Any], *,
                        config: Optional[DedupConfig] = None,
                        index: Optional[FingerprintIndex] = None,
                        **kw: Any) -> DeduplicationResult:
    """One-shot batch deduplication (fresh engine unless *index* given)."""
    if config is not None or index is not None:
        engine = Deduplicator(config=config, index=index)
    else:
        engine = _default_deduplicator()
    return engine.deduplicate(crashes, **kw)


def deduplicate_logs(texts: Iterable[str], *,
                     config: Optional[DedupConfig] = None,
                     parser_kwargs: Optional[Mapping[str, Any]] = None,
                     **meta: Any) -> DeduplicationResult:
    """Parse raw sanitizer logs then deduplicate the resulting crashes."""
    from .crash_parser import CrashParser, RawCrashRecord
    parser = CrashParser(**dict(parser_kwargs or {}))
    crashes: List[Crash] = []
    for text in texts:
        outcome = parser.parse_record(RawCrashRecord.from_text(text, **meta))
        crashes.extend(outcome.crashes)
    return deduplicate_crashes(crashes, config=config)


def merge_results(*results: DeduplicationResult) -> DeduplicationResult:
    """Combine several passes into one coherent view (non-destructive).

    Groups with equal strict digests are folded together; occurrence counts
    are summed, never averaged or invented.
    """
    merged = DeduplicationResult(config=dict(results[0].config) if results else {})
    by_key: Dict[str, DuplicateGroup] = {}
    order: List[str] = []
    for result in results:
        for group in result.groups:
            existing = by_key.get(group.group_key)
            if existing is None:
                clone = replace(group,
                                members=list(group.members),
                                related=list(group.related),
                                campaign_ids=list(group.campaign_ids),
                                target_keys=list(group.target_keys),
                                input_hashes=list(group.input_hashes),
                                warnings=list(group.warnings))
                by_key[group.group_key] = clone
                order.append(group.group_key)
            else:
                known = {m.id for m in existing.members}
                for crash in group.members:
                    if crash.id not in known:
                        existing.absorb(crash, tier=group.tier,
                                        rationale="merged from second pass")
                        known.add(crash.id)
                for crash in group.related:
                    if crash.id not in {r.id for r in existing.related}:
                        existing.related.append(crash)
                for cid in group.campaign_ids:
                    if cid not in existing.campaign_ids:
                        existing.campaign_ids.append(cid)
        merged.decisions.extend(result.decisions)
        merged.notes.extend(result.notes)
    groups = [by_key[k] for k in order]
    merged.groups = groups
    merged.unique_crashes = [g.canonical for g in groups]
    merged.duplicate_crashes = [c for g in groups for c in g.members
                               if c.id != g.canonical.id]
    stats = merged.stats
    stats.total = sum(r.stats.total for r in results)
    stats.unique = len(groups)
    stats.duplicates = sum(len(g.members) - 1 for g in groups)
    stats.compression_ratio = (stats.total and
                               stats.unique / stats.total or 0.0)
    return merged


# ============================================================================
# smoke test (executable proof of behaviour)
# ============================================================================


def _smoke() -> int:
    from .crash_parser import GOLDEN_SAMPLES

    parser_mod = __import__("kmcs.analysis.crash_parser",
                            fromlist=["CrashParser"])
    CrashParser = parser_mod.CrashParser
    parser = CrashParser()

    failures = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal failures
        status = "OK " if condition else "FAIL"
        if not condition:
            failures += 1
        print(f"  [{status}] {name}{(': ' + detail) if detail else ''}")

    # --- 1. identical log twice -> one group, occurrence bookkeeping --------
    sample = GOLDEN_SAMPLES["asan_heap_overflow"]
    outcomes = [parser.parse_text(sample, target_id="t1") for _ in range(2)]
    crashes = [o.crashes[0] for o in outcomes]
    res = deduplicate_crashes(crashes, config=DedupConfig(tier=DedupTier.STRICT))
    check("identical crash dedupes to one group",
          res.stats.unique == 1 and res.stats.duplicates == 1,
          f"unique={res.stats.unique} dupes={res.stats.duplicates}")
    dup = res.duplicate_crashes[0]
    check("duplicate links to canonical",
          dup.duplicate_of == res.groups[0].canonical.id
          and dup.state == CrashState.DUPLICATE.value)
    check("occurrences counted honestly",
          res.groups[0].total_occurrences == 2)

    # --- 2. different classes stay separate ---------------------------------
    mixed_texts = [GOLDEN_SAMPLES["asan_heap_overflow"],
                   GOLDEN_SAMPLES["asan_uaf"]]
    mixed = []
    for text in mixed_texts:
        outcome = parser.parse_text(text, target_id="t1")
        mixed.extend(outcome.crashes)
    res2 = deduplicate_crashes(mixed)
    check("distinct defects remain distinct",
          res2.stats.unique == 2, f"groups={[g.crash_class for g in res2.groups]}")

    # --- 3. ASLR-shifted copy merges (deterministic digests) ----------------
    shifted = GOLDEN_SAMPLES["asan_heap_overflow"].replace(
        "0x4af3c1", "0x5bf3c1").replace("0x602000000011", "0x7030000000ff")
    pair = [parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"],
                              target_id="t1").crashes[0],
            parser.parse_text(shifted, target_id="t1").crashes[0]]
    res3 = deduplicate_crashes(pair)
    check("address-shifted duplicate merges", res3.stats.unique == 1)

    # --- 4. target guard prevents cross-target merge ------------------------
    cross = [parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"],
                               target_id="alpha").crashes[0],
             parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"],
                               target_id="beta").crashes[0]]
    res4 = deduplicate_crashes(cross)
    check("different targets never merge", res4.stats.unique == 2)

    # --- 5. persistent index recognises prior art ---------------------------
    mem_index = InMemoryIndex()
    engine = Deduplicator(index=mem_index)
    engine.deduplicate([parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"],
                                          target_id="t1").crashes[0]])
    later = parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"],
                              target_id="t1").crashes[0]
    res5 = engine.deduplicate([later])
    check("index catches crash seen in earlier run",
          res5.stats.skipped_existing == 1
          and res5.stats.unique == 0,
          f"skipped={res5.stats.skipped_existing}")

    # --- 6. pairwise explanation is well-formed -----------------------------
    a = parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"],
                          target_id="t1").crashes[0]
    b = parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"],
                          target_id="t1").crashes[0]
    verdict = Deduplicator().decide_pair(a, b)
    check("pairwise verdict explains strict match",
          verdict["decision"] == DedupDecision.DUPLICATE.value
          and verdict["tier"] == "strict"
          and 0.0 <= verdict["similarity"] <= 1.0,
          json.dumps(verdict["matched_components"]))

    # --- 7. findings materialisation ----------------------------------------
    findings = res.findings()
    check("one candidate finding per unique group",
          len(findings) == 1
          and findings[0].state == FindingState.CANDIDATE.value
          and findings[0].canonical_crash_id == res.groups[0].canonical.id)

    # --- 8. JSON export round-trips structurally ----------------------------
    payload = res.to_dict()
    encoded = json.dumps(payload)
    decoded = json.loads(encoded)
    check("result serialises to JSON",
          decoded["stats"]["unique"] == 1 and len(decoded["groups"]) == 1)

    # --- 9. merge_results folds two passes ----------------------------------
    merged = merge_results(res, res5)
    check("merge_results folds equal digests",
          merged.stats.unique == 1 and merged.groups[0].total_occurrences >= 2,
          f"occ={merged.groups[0].total_occurrences}")

    # --- 10. family tier annotates without merging --------------------------
    fam_cfg = DedupConfig(tier=DedupTier.FAMILY)
    res6 = deduplicate_crashes(mixed, config=fam_cfg)
    check("family policy keeps independent bugs separate",
          res6.stats.unique == 2)

    total = 10
    print(f"[kmcs.analysis.deduplicator] {total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
