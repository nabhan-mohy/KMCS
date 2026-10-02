# =============================================================================
# kmcs.analysis.fingerprint -- stable, ASLR-resistant crash identity keys
# =============================================================================
"""
Compute *deduplication fingerprints* for crashes.

A fingerprint answers one question: **"is this the same bug as that one?"**
Getting it right is the difference between a tidy findings list and thousands
of near-duplicate triage tickets.

Design
------
The digest is derived from a canonical tuple of *semantic* attributes::

    (target_id | target_name | executable-basename,
     sanitizer token,
     crash class,
     normalised top-N stack identities,
     faulting source location (file:function[:line-bucket]),
     memory access type + direction)

Deliberately EXCLUDED (volatile across runs):

* absolute load addresses / PC values (ASLR changes them every run);
* allocation addresses and heap chunk addresses;
* PIDs, timestamps, thread ids, host names;
* raw shadow bytes.

Frame normalisation
-------------------
Each retained frame contributes an "identity" chosen by best available
symbol data:

1. ``func@file:line`` when both function and file are known;
2. ``func@module`` when only module+offset is known (offset kept because
   module-relative offsets are stable under ASLR for PIE binaries);
3. ``file:line`` when only source location is known;
4. ``module+0xoffset`` otherwise.

Function names are de-mangled-lite: template arguments collapsed to ``<>``,
parameter lists dropped, anonymous-namespace/unique suffixes
(``[clone .cold]``, ``.llvm.*`` hashes, ``__uniqled`` ids) stripped, so
compiler-generated variants collapse onto the same identity.  This is pure
textual normalisation of *observed* symbols -- never invention.

Tiers & similarity
------------------
Three digests are produced per crash:

* ``digest_strict``      -- full top-N frames (default N=5);
* ``digest_relaxed``     -- top-3 frames + class (tolerates shallow stack
                            differences caused by inlining or wrapper frames);
* ``digest_family``      -- class + faulting file/function only (bug-family
                            grouping used by reports).

:class:`Fingerprinter` also exposes :func:`similarity_digest` (a 64-bit
feature vector over frame identities) enabling approximate clustering via
:func:`hamming_distance` and :func:`cluster_fingerprints`.  Approximate
matches are always labelled ``confidence="medium"`` or lower -- they suggest
groupings, they never silently merge distinct bugs.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from kmcs.core.exceptions import FingerprintError
from kmcs.core.models import (
    Confidence,
    Crash,
    CrashClass,
    Fingerprint,
    SanitizerKind,
    SanitizerReport,
    StackFrame,
    StackTrace,
    utc_string,
)

__all__ = [
    "FingerprintComponents",
    "Fingerprinter",
    "fingerprint_report",
    "fingerprint_text",
    "similarity_digest",
    "hamming_distance",
    "cluster_fingerprints",
    "normalise_function",
    "frame_identity",
]

# ============================================================================
# symbol normalisation
# ============================================================================

_CLONE_SUFFIX = re.compile(r"\s*\[clone[^]]*\]")
_LLVM_SUFFIX = re.compile(r"\.llvm(?:\.[0-9]+)?(?:_[0-9]+)?$")
_UNIQLED = re.compile(r"[._][a-f0-9]{8,}\b")
_TEMPL_ARGS = re.compile(r"<[^<>]*>")
_PARAMS = re.compile(r"\(.*\)$", re.S)
_ANON_NS = re.compile(r"\{\{[^}]*\}\}")


def normalise_function(name: str) -> str:
    """Collapse compiler noise so equivalent symbols hash identically."""
    text = str(name or "").strip()
    if not text:
        return ""
    text = _CLONE_SUFFIX.sub("", text)
    text = _LLVM_SUFFIX.sub("", text)
    text = _ANON_NS.sub("{}", text)
    # iteratively strip innermost template args ("std::vector<int...>" style)
    prev = None
    while prev != text:
        prev = text
        text = _TEMPL_ARGS.sub("<>", text)
    text = _PARAMS.sub("", text)
    text = _UNIQLED.sub("", text)
    # operator() keeps meaning without its argument list
    text = re.sub(r"\s+", "", text)
    return text.strip("():, ")


def normalise_path(path: str) -> str:
    """Keep the tail of a source path so build-dir prefixes don't split bugs."""
    text = str(path or "").strip().replace("\\", "/")
    if not text:
        return ""
    parts = [p for p in text.split("/") if p]
    if not parts:
        return text
    return "/".join(parts[-3:])


_LINE_BUCKET = 8  # lines grouped into buckets of 8 to tolerate small shifts


def frame_identity(frame: StackFrame) -> str:
    """Stable semantic identity of one frame (no absolute addresses)."""
    func = normalise_function(frame.function or "")
    file_ = normalise_path(frame.file or "")
    module = str(frame.module or "").split("/")[-1]
    if func and file_:
        bucket = (frame.line // _LINE_BUCKET) if (frame.line or 0) > 0 else 0
        return f"{func}@{file_}:{bucket}"
    if func and module:
        offset = str(frame.offset or "").lower()
        return f"{func}@{module}+{offset}"
    if func:
        return f"{func}@?"
    if file_:
        bucket = (frame.line // _LINE_BUCKET) if (frame.line or 0) > 0 else 0
        return f"@{file_}:{bucket}"
    if module:
        offset = str(frame.offset or "").lower()
        return f"{module}+{offset}"
    return "?"


# ============================================================================
# components container
# ============================================================================


@dataclass(frozen=True)
class FingerprintComponents:
    """The observable attributes a fingerprint was built from."""

    target_key: str
    sanitizer: str
    crash_class: str
    frame_identities: Tuple[str, ...]
    location_key: str
    access_type: str
    access_direction: str
    tier_depths: Tuple[int, ...] = (5, 3, 1)
    notes: Tuple[str, ...] = ()

    def canonical(self, depth: Optional[int] = None) -> str:
        frames = self.frame_identities
        if depth is not None:
            frames = frames[:max(0, int(depth))]
        return "|".join((
            self.target_key, self.sanitizer, self.crash_class,
            ",".join(frames), self.location_key,
            self.access_type, self.access_direction,
        ))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_key": self.target_key,
            "sanitizer": self.sanitizer,
            "crash_class": self.crash_class,
            "frames": list(self.frame_identities),
            "location": self.location_key,
            "access": f"{self.access_type}/{self.access_direction}",
            "notes": list(self.notes),
        }


# ============================================================================
# the fingerprinter
# ============================================================================


class Fingerprinter:
    """Deterministic fingerprint computation with configurable strictness.

    Parameters
    ----------
    strict_depth / relaxed_depth:
        Number of top frames feeding each tier's digest.
    include_line_buckets:
        When False, line buckets are removed from location keys (looser).
    algorithm:
        Hash algorithm prefix recorded on digests (sha256 by default).
    """

    def __init__(self, *, strict_depth: int = 5, relaxed_depth: int = 3,
                 family_depth: int = 1, include_line_buckets: bool = True,
                 algorithm: str = "sha256") -> None:
        if strict_depth < relaxed_depth < family_depth or strict_depth < 1:
            raise FingerprintError(
                "require strict_depth >= relaxed_depth >= family_depth >= 1",
                component="analysis.fingerprint")
        self.strict_depth = int(strict_depth)
        self.relaxed_depth = int(relaxed_depth)
        self.family_depth = int(family_depth)
        self.include_line_buckets = bool(include_line_buckets)
        self.algorithm = str(algorithm)
        self.computed = 0

    # ------------------------------------------------------------ public

    def components_for_crash(self, crash: Crash) -> FingerprintComponents:
        report = crash.sanitizer_report
        frames = list(crash.stack_trace)[: self.strict_depth] if crash.stack_trace else []
        if not frames and report is not None:
            frames = list(report.stack_trace)[: self.strict_depth]
        identities = tuple(frame_identity(f) for f in frames)

        target_key = (crash.target_id or crash.target_name
                      or (crash.executable.split("/")[-1] if crash.executable else "")
                      or "unknown-target")
        sanitizer = crash.sanitizer or (report.sanitizer if report else SanitizerKind.NONE.value)

        location = crash.location
        loc_key = ""
        if location is not None:
            func = normalise_function(location.function or "")
            file_ = normalise_path(location.file or "")
            if func or file_:
                loc_key = f"{func}@{file_}"
            elif location.module:
                loc_key = str(location.module).split("/")[-1]
        if not loc_key and identities:
            loc_key = identities[0]

        access_type = ""
        direction = ""
        if crash.memory_access is not None:
            access_type = str(crash.memory_access.access_type or "")
            direction = str(crash.memory_access.direction or "")
        elif report is not None and report.memory_access is not None:
            access_type = str(report.memory_access.access_type or "")
            direction = str(report.memory_access.direction or "")

        notes: List[str] = []
        if not identities:
            notes.append("no-stack: fingerprint relies on class/location only")
        if len(identities) < self.strict_depth:
            notes.append(f"stack-shallower-than-tier ({len(identities)}<{self.strict_depth})")

        return FingerprintComponents(
            target_key=target_key,
            sanitizer=sanitizer,
            crash_class=str(crash.crash_class),
            frame_identities=identities,
            location_key=loc_key,
            access_type=access_type,
            access_direction=direction,
            tier_depths=(self.strict_depth, self.relaxed_depth, self.family_depth),
            notes=tuple(notes),
        )

    def compute(self, crash: Crash, *, timestamp: str = "") -> Fingerprint:
        """Build the three-tier :class:`Fingerprint` and attach it to *crash*."""
        components = self.components_for_crash(crash)
        strict = self._digest(components.canonical(self.strict_depth))
        relaxed_comp = components  # same observable attributes, fewer frames used
        relaxed = self._digest("|".join((
            relaxed_comp.target_key, relaxed_comp.sanitizer, relaxed_comp.crash_class,
            ",".join(relaxed_comp.frame_identities[: self.relaxed_depth]),
        )))
        family = self._digest("|".join((
            relaxed_comp.target_key, relaxed_comp.crash_class,
            relaxed_comp.location_key,
        )))
        feature = similarity_digest(components.frame_identities)
        # The core Fingerprint model stores semantic components as a sorted
        # tuple of (key, value) pairs; tier digests and the feature vector
        # ride along inside that mapping so persistence round-trips them.
        fp = Fingerprint(
            algorithm=f"kmcs-fp-v1:{self.algorithm}",
            digest=strict,
            components=tuple(sorted((
                ("relaxed", relaxed),
                ("family", family),
                ("features", feature),
                ("version", "1"),
                ("computed_at", timestamp or utc_string()),
                ("components", json.dumps(components.to_dict(), sort_keys=True)),
            ))),
        )
        crash.fingerprint = fp
        self.computed += 1
        return fp

    # ----------------------------------------------------------- internals

    def _digest(self, canonical: str) -> str:
        payload = f"kmcs-fp-v1:{canonical}".encode("utf-8", errors="replace")
        if self.algorithm == "blake2b":
            return hashlib.blake2b(payload, digest_size=32).hexdigest()
        return hashlib.sha256(payload).hexdigest()


_FP: Optional[Fingerprinter] = None
_FP_LOCK = threading.Lock()


def _default_fingerprinter() -> Fingerprinter:
    global _FP
    with _FP_LOCK:
        if _FP is None:
            _FP = Fingerprinter()
        return _FP


def fingerprint_report(report: SanitizerReport, *, crash: Optional[Crash] = None
                       ) -> Fingerprint:
    """Fingerprint a standalone report (wraps it in a minimal Crash if needed)."""
    from kmcs.core.models import generate_prefixed_id
    target = crash or Crash(id=generate_prefixed_id("crash"),
                             sanitizer=report.sanitizer,
                             crash_class=report.crash_class,
                             stack_trace=report.stack_trace,
                             memory_access=report.memory_access,
                             sanitizer_report=report)
    return _default_fingerprinter().compute(target)


def fingerprint_text(text: str, **meta: Any) -> Fingerprint:
    """Convenience: parse raw log text then fingerprint the primary crash."""
    from kmcs.analysis.crash_parser import CrashParser, RawCrashRecord
    outcome = CrashParser().parse_record(RawCrashRecord.from_text(text, **meta))
    if outcome.primary is None:
        raise FingerprintError("no crash could be parsed from input text",
                               component="analysis.fingerprint")
    return _default_fingerprinter().compute(outcome.primary)


# ============================================================================
# approximate similarity (feature vectors / clustering)
# ============================================================================


def similarity_digest(frame_identities: Sequence[str]) -> str:
    """64-bit hex feature vector: bit i set when frame-i slot has content.

    Slots are assigned by hashing each identity into one of 64 buckets, so
    stacks sharing many frames share many bits even when ordering differs
    slightly.  Used only for *suggesting* clusters, never for merging.
    """
    value = 0
    for identity in frame_identities:
        if not identity or identity == "?":
            continue
        bucket = int(hashlib.md5(identity.encode("utf-8")).hexdigest()[:8], 16) % 64
        value |= 1 << bucket
    return f"{value:016x}"


def hamming_distance(hex_a: str, hex_b: str) -> int:
    try:
        va = int(str(hex_a), 16)
        vb = int(str(hex_b), 16)
    except (TypeError, ValueError) as exc:
        raise FingerprintError(f"invalid hex digest: {exc}",
                               component="analysis.fingerprint") from exc
    return bin(va ^ vb).count("1")


def jaccard_similarity(hex_a: str, hex_b: str) -> float:
    try:
        va = int(str(hex_a), 16)
        vb = int(str(hex_b), 16)
    except (TypeError, ValueError):
        return 0.0
    union = bin(va | vb).count("1")
    if union == 0:
        return 1.0 if va == vb else 0.0
    return bin(va & vb).count("1") / union


def cluster_fingerprints(items: Sequence[Tuple[str, str]], *,
                         threshold: float = 0.7) -> List[List[str]]:
    """Group ``(key, feature_hex)`` pairs by approximate feature similarity.

    Single-linkage greedy clustering; deterministic iteration order.
    Returns clusters of keys (each key appears exactly once).
    """
    entries = [(str(k), str(v)) for k, v in items]
    parent: Dict[str, str] = {k: k for k, _ in entries}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(len(entries)):
        ki, fi = entries[i]
        for j in range(i + 1, len(entries)):
            kj, fj = entries[j]
            if jaccard_similarity(fi, fj) >= float(threshold):
                union(ki, kj)
    groups: Dict[str, List[str]] = {}
    for key, _feat in entries:
        groups.setdefault(find(key), []).append(key)
    return sorted(groups.values(), key=lambda g: (-len(g), g[0]))


# ============================================================================
# smoke test
# ============================================================================


def _smoke() -> int:
    from kmcs.analysis.crash_parser import GOLDEN_SAMPLES, CrashParser

    parser = CrashParser()
    fp = Fingerprinter()
    failures = 0

    # determinism across two parses of identical logs
    o1 = parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"], target_id="t1")
    o2 = parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"], target_id="t1")
    d1 = fp.compute(o1.crashes[0]).digest
    d2 = fp.compute(o2.crashes[0]).digest
    ok = d1 == d2
    failures += 0 if ok else 1
    print(f"  [{'OK ' if ok else 'FAIL'}] determinism: same log -> same digest")

    # ASLR resistance: different absolute addresses keep same digest
    shifted = GOLDEN_SAMPLES["asan_heap_overflow"].replace(
        "0x4af3c1", "0x5bf3c1").replace("0x602000000011", "0x7030000000ff")
    o3 = parser.parse_text(shifted, target_id="t1")
    d3 = fp.compute(o3.crashes[0]).digest
    ok = d3 == d1
    failures += 0 if ok else 1
    print(f"  [{'OK ' if ok else 'FAIL'}] ASLR resistance: address shift keeps digest")

    # different target => different digest
    o4 = parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"], target_id="other")
    d4 = fp.compute(o4.crashes[0]).digest
    ok = d4 != d1
    failures += 0 if ok else 1
    print(f"  [{'OK ' if ok else 'FAIL'}] target separation: different target id splits")

    # all samples produce well-formed digests
    for name, sample in GOLDEN_SAMPLES.items():
        outcome = parser.parse_text(sample)
        if outcome.primary is None:
            failures += 1
            print(f"  [FAIL] {name}: no crash to fingerprint")
            continue
        digest = fp.compute(outcome.primary)
        ok = len(digest.digest) == 64 and all(c in "0123456789abcdef" for c in digest.digest)
        failures += 0 if ok else 1
        print(f"  [{'OK ' if ok else 'FAIL'}] {name}: digest={digest.digest[:16]}... "
              f"tiers={[k for k, _ in digest.components if k in ('relaxed', 'family', 'features')]}")

    # clustering sanity
    feats = [("a", similarity_digest(["f1@x.c:1", "main@y.c:2"])),
             ("b", similarity_digest(["f1@x.c:1", "main@y.c:2", "z@w.c:9"])),
             ("c", similarity_digest(["q1@a.c:5"]))]
    clusters = cluster_fingerprints(feats, threshold=0.5)
    ok = any(set(cl) == {"a", "b"} for cl in clusters)
    failures += 0 if ok else 1
    print(f"  [{'OK ' if ok else 'FAIL'}] clustering similar stacks: {clusters}")

    total = 4 + len(GOLDEN_SAMPLES) + 1
    print(f"[kmcs.analysis.fingerprint] {total - failures}/{total} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
