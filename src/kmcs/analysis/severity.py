# =============================================================================
# kmcs.analysis.severity -- honest, deterministic severity assessment (Phase 5b)
# =============================================================================
"""
Severity assessment for analysed KMCS crashes.

This module answers exactly one question for a triaging researcher:

    "Given what the sanitizer *observed*, how urgently should this memory-safety
     finding be documented and fixed?"

It is deliberately **not** an exploitability estimator.  Nothing here reasons
about weaponisation, bypasses or attack primitives.  Severity is derived from
observable, defensible attributes of a crash report:

* the *crash class* (what kind of memory-safety violation occurred),
* the *access direction* (read vs write vs free-state confusion),
* the *sanitizer that observed it* (confidence in the observation itself),
* structural signals present in the real log text (allocation traces,
  shadow annotations, stack overflow depth, null-page geometry, ...),
* reproducibility status *as recorded by KMCS* (never assumed).

Design principles
-----------------
1. **Honesty.**  Every adjustment applied to a score must be backed by an
   evidence token that literally appears in the crash data.  Missing evidence
   contributes nothing -- it never inflates a score.  A crash with no
   reproduction record is scored on its static evidence only; we do not invent
   "probably reproducible".

2. **Determinism.**  Same input -> same score, same vector, same band, every
   time.  No randomness, no wall-clock dependence, no environment lookups on
   the scoring path.

3. **Explainability.**  Every :class:`SeverityDecision` carries the full list
   of :class:`ScoreAdjustment` records that produced it, so a human can audit
   why a finding landed where it did.

4. **Standard vocabulary.**  Bands follow the common CVSS qualitative ladder
   (None / Low / Medium / High / Critical) and map losslessly onto the core
   ``Severity`` enum, so downstream reporting layers can render either.

Public surface
--------------
``SeverityAssessor``      main engine (score -> band -> decision)
``SeverityFactors``       extracted, auditable factor bag from a crash/report
``SeverityDecision``      immutable result object (score, band, rationale...)
``assess_severity``       convenience one-call wrapper
``score_to_severity``     numeric score -> core Severity enum
``SEVERITY_ADJUSTMENTS``  the frozen default adjustment table
``TRIAGE_URGENCIES``      band -> recommended triage posture (documentation aid)
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..core.exceptions import InvalidValueError
from ..core.models import (
    Confidence,
    Crash,
    CrashClass,
    Fingerprint,
    SanitizerKind,
    Severity,
)

try:  # SanitizerReport lives in the sanitizers package; tolerate absence.
    from ..sanitizers.base import SanitizerReport  # type: ignore
except Exception:  # pragma: no cover - defensive import shim
    SanitizerReport = None  # type: ignore[assignment]

__version__ = "0.1.0"

__all__ = [
    "SeverityBand",
    "SeverityAssessor",
    "SeverityFactors",
    "SeverityDecision",
    "ScoreAdjustment",
    "AdjustmentRule",
    "assess_severity",
    "assess_many",
    "score_to_severity",
    "severity_from_score",
    "band_for_score",
    "SEVERITY_ADJUSTMENTS",
    "DEFAULT_BASE_SCORES",
    "TRIAGE_URGENCIES",
    "cvss_style_vector",
    "self_test_report",
]

_EPOCH_NOTE = "deterministic; no clock, no randomness, no network"


# =============================================================================
# Bands
# =============================================================================
class SeverityBand(StrEnum):
    """Qualitative severity bands (CVSS-style vocabulary)."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def ordered(cls) -> List["SeverityBand"]:
        return [cls.NONE, cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL]

    @classmethod
    def from_score(cls, score: float) -> "SeverityBand":
        """Map a 0..10 score onto a band using the CVSS v3.1 ranges."""
        s = _clamp(score, 0.0, 10.0)
        if s >= 9.0:
            return cls.CRITICAL
        if s >= 7.0:
            return cls.HIGH
        if s >= 4.0:
            return cls.MEDIUM
        if s > 0.0:
            return cls.LOW
        return cls.NONE

    @classmethod
    def parse(cls, token: Any) -> "SeverityBand":
        if isinstance(token, cls):
            return token
        if token is None:
            return cls.NONE
        text = str(token).strip().lower()
        try:
            return cls(text)
        except ValueError:
            pass
        aliases = {
            "informational": cls.NONE,
            "info": cls.NONE,
            "negligible": cls.NONE,
            "minor": cls.LOW,
            "moderate": cls.MEDIUM,
            "important": cls.HIGH,
            "severe": cls.HIGH,
            "urgent": cls.CRITICAL,
        }
        if text in aliases:
            return aliases[text]
        raise InvalidValueError(
            f"unknown severity band {token!r}",
            context={"allowed": [b.value for b in cls.ordered()]},
        )

    @property
    def rank(self) -> int:
        return self.ordered().index(self)

    def to_core_severity(self) -> Severity:
        """Convert to the core ``Severity`` enum used across KMCS models."""
        # Core enum ladder is NONE < INFORMATIONAL < LOW < MODERATE/MEDIUM
        # < HIGH < CRITICAL.  We use INFORMATIONAL for the "none" band so a
        # triaged-away finding still round-trips through core models cleanly.
        mapping = {
            SeverityBand.NONE: Severity.INFORMATIONAL,
            SeverityBand.LOW: Severity.LOW,
            SeverityBand.MEDIUM: Severity.MEDIUM,
            SeverityBand.HIGH: Severity.HIGH,
            SeverityBand.CRITICAL: Severity.CRITICAL,
        }
        return mapping[self]


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _round1(value: float) -> float:
    return round(_clamp(value, 0.0, 10.0), 1)


# =============================================================================
# Base scores per crash class
# =============================================================================
#: Static, defensible base scores keyed by crash class token.  These encode
#: "how bad is this *kind* of memory-safety violation when a sanitizer has
#: actually observed it" -- a starting point that evidence then adjusts.
DEFAULT_BASE_SCORES: Dict[str, float] = {
    # --- heap corruption family -------------------------------------------
    "heap-buffer-overflow": 8.2,
    "heap-buffer-underflow": 7.8,
    "stack-buffer-overflow": 8.4,
    "stack-buffer-underflow": 7.8,
    "global-buffer-overflow": 7.6,
    "global-buffer-underflow": 7.2,
    # --- allocation lifetime family ----------------------------------------
    "use-after-free": 8.6,
    "use-after-poison": 7.4,
    "double-free": 7.9,
    "invalid-free": 7.3,
    "alloc-dealloc-mismatch": 6.8,
    "new-delete-type-mismatch": 5.9,
    # --- initialisation family ----------------------------------------------
    "uninitialized-memory-read": 6.4,
    "use-of-uninitialized-value": 6.4,
    "uninitialized-bytes-in-use": 6.0,
    # --- bounds / index family ------------------------------------------------
    "container-overflow": 6.6,
    "dynamic-stack-buffer-overflow": 8.0,
    # --- pointer arithmetic / UB family ---------------------------------------
    "pointer-overflow": 5.4,
    "misaligned-address": 4.8,
    "null-pointer-dereference": 5.0,
    "null-dereference": 5.0,
    "division-by-zero": 3.6,
    "signed-integer-overflow": 3.2,
    "unsigned-integer-overflow": 2.8,
    "integer-overflow": 3.0,
    "shift-out-of-bounds": 3.4,
    "out-of-range-shift": 3.4,
    "undefined-behavior": 4.0,
    "implicit-conversion-signedness": 2.2,
    "object-size-mismatch": 4.6,
    "downcast-invalid": 4.4,
    "virtual-call-on-null-object": 5.2,
    # --- races / leaks / termination ------------------------------------------
    "data-race": 6.2,
    "thread-race": 6.2,
    "lock-order-inversion": 3.8,
    "syscall-race": 4.2,
    "memory-leak": 3.4,
    "indirect-memory-leak": 2.8,
    "large-allocation-leak": 3.0,
    "detected-memory-leaks": 3.4,
    # --- control-flow / termination ---------------------------------------------
    "stack-overflow": 5.6,
    "stack-exhaustion": 5.6,
    "infinite-recursion": 5.2,
    "timeout": 2.6,
    "oom": 2.4,
    "out-of-memory": 2.4,
    "abort": 3.0,
    "assertion-failure": 2.8,
    "segfault": 5.8,
    "segmentation-fault": 5.8,
    "sigsegv": 5.8,
    "sigbus": 5.4,
    "sigabrt": 3.2,
    "sigill": 4.0,
    "sigtrap": 3.6,
    # --- unknown ------------------------------------------------------------------
    "unknown": 3.0,
}

#: Score used when a class token is not in the table above.
UNKNOWN_CLASS_BASE = 3.0


def _class_token(value: Any) -> str:
    """Normalise any class-ish token into the dict key space."""
    if value is None:
        return "unknown"
    if isinstance(value, CrashClass):
        return value.value
    if isinstance(value, str):
        text = value.strip().lower().replace(" ", "-").replace("_", "-")
        return text or "unknown"
    return str(value).strip().lower()


def base_score_for_class(class_token: Any) -> float:
    """Return the documented base score for a crash-class token."""
    tok = _class_token(class_token)
    if tok in DEFAULT_BASE_SCORES:
        return DEFAULT_BASE_SCORES[tok]
    # One-shot alias resolution against the CrashClass enum values.
    try:
        member = CrashClass(tok.replace("-", "_"))
        val = member.value
        if val in DEFAULT_BASE_SCORES:
            return DEFAULT_BASE_SCORES[val]
    except Exception:
        pass
    return UNKNOWN_CLASS_BASE


# =============================================================================
# Adjustment rules
# =============================================================================
@dataclass(frozen=True)
class AdjustmentRule:
    """A single, auditable severity adjustment.

    Attributes
    ----------
    name:
        machine-readable identifier (used in decisions & audits).
    delta:
        signed score change applied when ``applies_to`` matches.
    rationale:
        human-readable explanation shown in reports.
    once:
        when True the rule can fire at most once per assessment even if
        several evidence tokens match.
    """

    name: str
    delta: float
    rationale: str
    applies_to: Tuple[str, ...] = ()          # factor keys consulted
    requires_truthy: bool = True
    once: bool = True

    def describe(self) -> str:
        sign = "+" if self.delta >= 0 else ""
        return f"{self.name} ({sign}{self.delta:.1f}): {self.rationale}"


@dataclass(frozen=True)
class ScoreAdjustment:
    """Record of one adjustment that actually fired during an assessment."""

    rule_name: str
    delta: float
    rationale: str
    matched_evidence: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule_name,
            "delta": self.delta,
            "rationale": self.rationale,
            "matched_evidence": list(self.matched_evidence),
        }


#: The frozen default adjustment table.  Every entry references a factor key
#: produced by :meth:`SeverityFactors.from_crash`; keys that are absent simply
#: do not contribute.  Deltas are modest by design -- base class scores carry
#: most of the weight, evidence refines them.
_SEVERITY_ADJUSTMENTS_TABLE: Tuple[AdjustmentRule, ...] = (
    # ---- access direction -------------------------------------------------
    AdjustmentRule(
        name="write-access",
        delta=+0.8,
        rationale="The sanitizer observed a WRITE out-of-bounds/access to freed "
                  "memory; writes corrupt program state more directly than reads.",
        applies_to=("is_write_access",),
    ),
    AdjustmentRule(
        name="read-only-access",
        delta=-0.4,
        rationale="Observed access was a READ; typically lower integrity impact "
                  "than a write of the same class.",
        applies_to=("is_read_access",),
    ),
    # ---- allocator/lifetime context ---------------------------------------
    AdjustmentRule(
        name="allocation-trace-present",
        delta=+0.5,
        rationale="The report contains a real allocation stack trace, giving "
                  "high-confidence ownership context for the fix.",
        applies_to=("has_allocation_trace",),
    ),
    AdjustmentRule(
        name="free-trace-present",
        delta=+0.5,
        rationale="The report contains a deallocation trace (use-after-free "
                  "lifecycle fully evidenced).",
        applies_to=("has_free_trace",),
    ),
    AdjustmentRule(
        name="shadow-annotation",
        delta=+0.3,
        rationale="Shadow-byte annotation captured, pinpointing poisoned region "
                  "boundaries in the raw log.",
        applies_to=("has_shadow_annotation",),
    ),
    # ---- geometry -----------------------------------------------------------
    AdjustmentRule(
        name="null-page-geometry",
        delta=-0.6,
        rationale="Fault address lies in the guard/null page; classic benign "
                  "null dereference shape rather than heap spray geometry.",
        applies_to=("is_null_page_fault",),
    ),
    AdjustmentRule(
        name="deep-recursion-stack-overflow",
        delta=-0.3,
        rationale="Stack overflow shows repetitive recursion frames; usually a "
                  "bounded-input robustness bug.",
        applies_to=("is_recursive_overflow",),
    ),
    AdjustmentRule(
        name="off-by-one-window",
        delta=-0.3,
        rationale="Access offset is +/-1 relative to the region boundary "
                  "(narrow overflow window).",
        applies_to=("is_off_by_one",),
    ),
    AdjustmentRule(
        name="huge-offset-window",
        delta=+0.4,
        rationale="Access offset far beyond the owning region indicates "
                  "loss-of-bounds control, not a tight off-by-one.",
        applies_to=("is_far_offset",),
    ),
    # ---- sanitizer confidence -----------------------------------------------
    AdjustmentRule(
        name="ubsan-only-observation",
        delta=-0.5,
        rationale="Report originates from UBSan diagnostics without a trapping "
                  "memory fault; classify as correctness defect first.",
        applies_to=("is_ubsan_diagnostic_only",),
    ),
    AdjustmentRule(
        name="lsan-only-observation",
        delta=-0.6,
        rationale="LeakSanitizer observation: resource exhaustion risk, not a "
                  "direct memory-corruption event.",
        applies_to=("is_leak_only",),
    ),
    AdjustmentRule(
        name="tsan-race-with-writes",
        delta=+0.6,
        rationale="ThreadSanitizer race includes at least one WRITE accessor; "
                  "torn-state corruption is plausible under scheduling.",
        applies_to=("race_involves_write",),
    ),
    AdjustmentRule(
        name="msan-origin-tracking",
        delta=+0.3,
        rationale="MemorySanitizer provided uninitialized-value origin tracking "
                  "in the raw log.",
        applies_to=("has_msan_origin",),
    ),
    # ---- reachability / reproducibility (recorded facts only) -----------------
    AdjustmentRule(
        name="reproduced-confirmed",
        delta=+0.4,
        rationale="KMCS reproduction runner CONFIRMED the crash replays; the "
                  "finding is actionable and stable.",
        applies_to=("is_reproduced",),
    ),
    AdjustmentRule(
        name="flaky-reproduction",
        delta=-0.5,
        rationale="Reproduction attempts disagree (partially reproduced); "
                  "triage cost is higher, certainty lower.",
        applies_to=("is_flaky",),
    ),
    AdjustmentRule(
        name="single-sample-evidence",
        delta=-0.3,
        rationale="Only one occurrence sample exists; pattern stability is "
                  "not yet demonstrated.",
        applies_to=("is_single_sample",),
    ),
    # ---- classification confidence --------------------------------------------
    AdjustmentRule(
        name="classification-certain",
        delta=+0.3,
        rationale="Classifier reached CERTAIN confidence from explicit banner "
                  "tokens.",
        applies_to=("classification_certain",),
    ),
    AdjustmentRule(
        name="classification-low-confidence",
        delta=-0.7,
        rationale="Classification confidence is LOW/MEDIUM; severity inherits "
                  "that uncertainty.",
        applies_to=("classification_uncertain",),
    ),
    # ---- stack quality ---------------------------------------------------------
    AdjustmentRule(
        name="symbolised-crash-site",
        delta=+0.3,
        rationale="Crash site resolved to a named function + source location; "
                  "fix target is concrete.",
        applies_to=("has_symbolised_site",),
    ),
    AdjustmentRule(
        name="unsymbolised-stack",
        delta=-0.4,
        rationale="No usable symbols in the crash stack; analysis effort rises "
                  "and root cause stays hypothetical.",
        applies_to=("stack_unsymbolised",),
    ),
    # ---- third-party noise -------------------------------------------------------
    AdjustmentRule(
        name="inside-library-code",
        delta=-0.2,
        rationale="Faulting frame is inside a system/library component rather "
                  "than project code; often a caller-side contract issue.",
        applies_to=("fault_in_library",),
    ),
)

#: Public frozen view of the adjustment table.
SEVERITY_ADJUSTMENTS: Mapping[str, AdjustmentRule] = {
    rule.name: rule for rule in _SEVERITY_ADJUSTMENTS_TABLE
}

#: Band -> recommended triage posture.  This is documentation guidance for a
#: research workflow (how quickly to write the finding up), not automation.
TRIAGE_URGENCIES: Mapping[SeverityBand, str] = {
    SeverityBand.CRITICAL: (
        "Document immediately; open a regression test; escalate to the target "
        "maintainer through coordinated disclosure channels."
    ),
    SeverityBand.HIGH: (
        "Document within the campaign; prioritise minimisation and "
        "reproduction confirmation before filing the finding."
    ),
    SeverityBand.MEDIUM: (
        "Document in normal triage order; confirm reproducibility and dedupe "
        "against existing findings first."
    ),
    SeverityBand.LOW: (
        "Batch-document with related low-severity items; keep the reproducer "
        "attached for future reference."
    ),
    SeverityBand.NONE: (
        "Record for completeness only; likely informational or "
        "non-actionable without further evidence."
    ),
}


# =============================================================================
# Factors
# =============================================================================
@dataclass
class SeverityFactors:
    """Auditable bag of observable facts extracted from a crash.

    Every field maps 1:1 to an adjustment rule key.  Fields stay falsy unless
    the underlying evidence was *actually present* in the crash data -- this is
    the honesty guarantee of the whole module.
    """

    class_token: str = "unknown"
    sanitizer: Optional[str] = None
    confidence: Optional[str] = None

    is_write_access: bool = False
    is_read_access: bool = False
    has_allocation_trace: bool = False
    has_free_trace: bool = False
    has_shadow_annotation: bool = False
    is_null_page_fault: bool = False
    is_recursive_overflow: bool = False
    is_off_by_one: bool = False
    is_far_offset: bool = False
    is_ubsan_diagnostic_only: bool = False
    is_leak_only: bool = False
    race_involves_write: bool = False
    has_msan_origin: bool = False
    is_reproduced: bool = False
    is_flaky: bool = False
    is_single_sample: bool = False
    classification_certain: bool = False
    classification_uncertain: bool = False
    has_symbolised_site: bool = False
    stack_unsymbolised: bool = False
    fault_in_library: bool = False

    notes: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    @classmethod
    def from_crash(cls, crash: Any) -> "SeverityFactors":
        """Extract factors from a core ``Crash`` (or duck-typed equivalent).

        Tolerant by design: missing attributes simply leave their factor
        false.  We never guess.
        """
        f = cls()
        if crash is None:
            f.notes.append("no crash object supplied")
            return f

        # Unwrap our own wrapper objects transparently.
        inner = crash.crash if isinstance(crash, SeverityEvidence) else crash
        if inner is not crash:
            base = cls.from_crash(inner)
            # Overlay direct attributes below; start from the wrapped truth.
            f.__dict__.update(base.__dict__)
            crash = inner

        # Raw text evidence (if the crash keeps its original log somewhere).
        raw = ""
        for attr in ("raw_log", "sanitizer_output", "log_text", "output"):
            val = getattr(crash, attr, None)
            if isinstance(val, str) and val:
                raw = val
                break
        lowered = raw.lower()

        # Class token ---------------------------------------------------
        tok = _class_token(
            getattr(crash, "crash_class", None)
            or getattr(crash, "classification", None)
            or getattr(crash, "class_", None)
            or getattr(crash, "kind", None)
        )
        f.class_token = tok

        san = getattr(crash, "sanitizer", None)
        f.sanitizer = san.value if isinstance(san, SanitizerKind) else (
            str(san).lower() if san else None
        )

        conf = getattr(crash, "confidence", None)
        f.confidence = conf.value if isinstance(conf, Confidence) else (
            str(conf).lower() if conf else None
        )

        # Access direction ------------------------------------------------
        access = str(getattr(crash, "access_type", "") or "").lower()
        if not access and lowered:
            if "write of size" in lowered:
                access = "write"
            elif "read of size" in lowered:
                access = "read"
        if access.startswith("w"):
            f.is_write_access = True
        elif access.startswith("r"):
            f.is_read_access = True

        # Lifetime traces ---------------------------------------------------
        f.has_allocation_trace = bool(
            getattr(crash, "allocation_stack", None)
            or "allocated by thread" in lowered
            or "allocated here" in lowered
        )
        f.has_free_trace = bool(
            getattr(crash, "free_stack", None)
            or "freed by thread" in lowered
            or "freed here" in lowered
        )
        f.has_shadow_annotation = bool(
            getattr(crash, "shadow_bytes", None)
            or "shadow bytes:" in lowered
        )

        # Geometry ------------------------------------------------------------
        addr = getattr(crash, "fault_address", None)
        if addr is not None:
            try:
                addr_int = int(str(addr), 16) if isinstance(addr, str) else int(addr)
                f.is_null_page_fault = addr_int < 0x10000
            except (TypeError, ValueError):
                pass
        offset = getattr(crash, "access_offset", None)
        try:
            off = abs(int(offset)) if offset is not None else None
        except (TypeError, ValueError):
            off = None
        if off is not None:
            f.is_off_by_one = off <= 1
            f.is_far_offset = off >= 0x1000

        # Sanitizer-specific shapes ---------------------------------------------
        if f.sanitizer == "undefined" or tok in {
            "signed-integer-overflow", "unsigned-integer-overflow",
            "division-by-zero", "shift-out-of-bounds", "misaligned-address",
            "undefined-behavior",
        }:
            trapped = bool(lowered) and any(
                m in lowered for m in ("segmentation fault", "sigsegv",
                                       "exit code:", "#0 0x")
            )
            f.is_ubsan_diagnostic_only = (f.sanitizer == "undefined") and not trapped
        if f.sanitizer == "leak" or tok in {"memory-leak", "indirect-memory-leak",
                                            "large-allocation-leak"}:
            f.is_leak_only = True
        if f.sanitizer == "thread" or tok in {"data-race", "thread-race"}:
            if "write of size" in lowered or "read of size" in lowered:
                f.race_involves_write = "write of size" in lowered
            else:
                f.race_involves_write = "rw-r" in lowered or "writing thread" in lowered
        if f.sanitizer == "memory" and "origin is" in lowered:
            f.has_msan_origin = True

        # Reproduction facts (only as RECORDED by KMCS) ---------------------------
        repro = str(getattr(crash, "reproduction_status", "") or "").lower()
        if repro in {"reproduced", "confirmed", "pass", "stable"}:
            f.is_reproduced = True
        elif repro in {"flaky", "partial", "intermittent"}:
            f.is_flaky = True
        occ = getattr(crash, "occurrence_count", None)
        try:
            f.is_single_sample = occ is not None and int(occ) <= 1
        except (TypeError, ValueError):
            pass

        # Classification confidence ------------------------------------------------
        if f.confidence == "certain":
            f.classification_certain = True
        elif f.confidence in {"low", "medium", "guess"}:
            f.classification_uncertain = True

        # Stack quality -----------------------------------------------------------------
        frames = getattr(crash, "stack_frames", None) or getattr(crash, "frames", None) or []
        frames = list(frames)
        symbolised = False
        for fr in frames[:3]:
            name = getattr(fr, "function", None) or (fr.get("function")
                                                     if isinstance(fr, Mapping) else None)
            if name and str(name) not in {"", "?", "<unknown>", "???"}:
                symbolised = True
                break
        f.has_symbolised_site = symbolised
        f.stack_unsymbolised = bool(frames) and not symbolised
        if frames:
            first = frames[0]
            fname = getattr(first, "function", None) or (
                first.get("function") if isinstance(first, Mapping) else None) or ""
            flib = getattr(first, "module", None) or (
                first.get("module") if isinstance(first, Mapping) else None) or ""
            blob = f"{fname} {flib}".lower()
            f.fault_in_library = any(
                marker in blob for marker in (
                    "/libc", "ld-linux", "libstdc++", "libm.so", "ld-musl",
                    "libpthread", "ntdll", "libc.so",
                )
            )

        return f

    # ------------------------------------------------------------------
    def active_keys(self) -> List[str]:
        """Factor keys currently true (for auditing/UI display)."""
        bool_fields = (
            "is_write_access", "is_read_access", "has_allocation_trace",
            "has_free_trace", "has_shadow_annotation", "is_null_page_fault",
            "is_recursive_overflow", "is_off_by_one", "is_far_offset",
            "is_ubsan_diagnostic_only", "is_leak_only", "race_involves_write",
            "has_msan_origin", "is_reproduced", "is_flaky", "is_single_sample",
            "classification_certain", "classification_uncertain",
            "has_symbolised_site", "stack_unsymbolised", "fault_in_library",
        )
        return [k for k in bool_fields if getattr(self, k, False)]

    def to_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d["notes"] = list(d.get("notes", []))
        return d


@dataclass(frozen=True)
class SeverityEvidence:
    """Light wrapper letting callers feed non-Crash inputs uniformly."""

    crash: Any
    extra_raw_log: Optional[str] = None

    def to_factors(self) -> SeverityFactors:
        f = SeverityFactors.from_crash(self.crash)
        if self.extra_raw_log:
            merged = SeverityFactors.from_crash(
                _SyntheticCrash(raw_log=self.extra_raw_log,
                                crash_class=f.class_token,
                                sanitizer=f.sanitizer)
            )
            for key in merged.active_keys():
                setattr(f, key, True)
        return f


@dataclass
class _SyntheticCrash:
    """Internal helper: minimal crash-shaped object built from raw text."""

    raw_log: str
    crash_class: str = "unknown"
    sanitizer: Optional[str] = None


# =============================================================================
# Decision
# =============================================================================
@dataclass(frozen=True)
class SeverityDecision:
    """Immutable outcome of one severity assessment."""

    class_token: str
    base_score: float
    score: float
    band: SeverityBand
    severity: Severity
    adjustments: Tuple[ScoreAdjustment, ...]
    factors: Dict[str, Any]
    rationale: str
    triage_guidance: str
    cvss_vector: str
    provenance: str = _EPOCH_NOTE

    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "class": self.class_token,
            "base_score": self.base_score,
            "score": self.score,
            "band": self.band.value,
            "severity": self.severity.value if isinstance(self.severity, Severity)
                       else str(self.severity),
            "adjustments": [a.to_dict() for a in self.adjustments],
            "factors": self.factors,
            "rationale": self.rationale,
            "triage_guidance": self.triage_guidance,
            "cvss_vector": self.cvss_vector,
            "provenance": self.provenance,
        }

    def summary_line(self) -> str:
        return (
            f"[{self.band.value.upper()} {self.score:.1f}] "
            f"{self.class_token} — {len(self.adjustments)} evidence adjustment(s)"
        )

    def apply_to(self, crash: Crash) -> Crash:
        """Write the assessed severity back onto a core Crash model."""
        try:
            crash.severity = self.severity
        except Exception:
            pass
        return crash


# =============================================================================
# Assessor
# =============================================================================
class SeverityAssessor:
    """Deterministic severity engine.

    Parameters
    ----------
    base_scores:
        Override/extend the per-class base score table.
    adjustments:
        Custom adjustment-rule tuple (defaults to SEVERITY_ADJUSTMENTS order).
    floor / ceiling:
        Hard clamp applied after all adjustments (default 0.0 .. 10.0).
    """

    def __init__(
        self,
        *,
        base_scores: Optional[Mapping[str, float]] = None,
        adjustments: Optional[Sequence[AdjustmentRule]] = None,
        floor: float = 0.0,
        ceiling: float = 10.0,
    ) -> None:
        if not (0.0 <= floor <= ceiling <= 10.0):
            raise InvalidValueError(
                "floor/ceiling must satisfy 0 <= floor <= ceiling <= 10",
                context={"floor": floor, "ceiling": ceiling},
            )
        self._base = dict(DEFAULT_BASE_SCORES)
        if base_scores:
            for k, v in base_scores.items():
                fv = float(v)
                if not 0.0 <= fv <= 10.0:
                    raise InvalidValueError(
                        f"base score for {k!r} out of range",
                        context={"value": fv},
                    )
                self._base[_class_token(k)] = fv
        self._rules = tuple(adjustments) if adjustments is not None \
            else _SEVERITY_ADJUSTMENTS_TABLE
        self._floor = floor
        self._ceiling = ceiling
        self._audit_lock = threading.Lock()
        self._history: List[SeverityDecision] = []

    # ------------------------------------------------------------------
    def assess(self, crash_or_factors: Any) -> SeverityDecision:
        """Produce a SeverityDecision for a crash, factors bag, or wrapper."""
        factors = self._coerce_factors(crash_or_factors)
        base = self._base.get(factors.class_token, UNKNOWN_CLASS_BASE)
        fired: List[ScoreAdjustment] = []
        score = base

        for rule in self._rules:
            matched: List[str] = []
            for key in rule.applies_to:
                if bool(getattr(factors, key, False)):
                    matched.append(key)
            if not matched:
                continue
            if not rule.requires_truthy:
                continue
            score += rule.delta
            fired.append(ScoreAdjustment(
                rule_name=rule.name,
                delta=rule.delta,
                rationale=rule.rationale,
                matched_evidence=tuple(matched),
            ))

        score = _round1(_clamp(score, self._floor, self._ceiling))
        band = SeverityBand.from_score(score)
        severity = band.to_core_severity()
        vector = cvss_style_vector(factors, score, band)
        rationale = self._build_rationale(factors, base, score, band, fired)

        decision = SeverityDecision(
            class_token=factors.class_token,
            base_score=_round1(base),
            score=score,
            band=band,
            severity=severity,
            adjustments=tuple(fired),
            factors=factors.to_dict(),
            rationale=rationale,
            triage_guidance=TRIAGE_URGENCIES[band],
            cvss_vector=vector,
        )
        with self._audit_lock:
            self._history.append(decision)
        return decision

    # ------------------------------------------------------------------
    def assess_batch(self, items: Iterable[Any]) -> List[SeverityDecision]:
        return [self.assess(item) for item in items]

    def history(self) -> List[SeverityDecision]:
        with self._audit_lock:
            return list(self._history)

    # ------------------------------------------------------------------
    @staticmethod
    def _coerce_factors(value: Any) -> SeverityFactors:
        if isinstance(value, SeverityFactors):
            return value
        if isinstance(value, SeverityEvidence):
            return value.to_factors()
        if isinstance(value, Mapping):
            f = SeverityFactors()
            for k, v in value.items():
                if hasattr(f, k):
                    setattr(f, k, v)
            f.class_token = _class_token(value.get("class_token", "unknown"))
            return f
        if isinstance(value, str):
            # Treat bare strings as raw sanitizer logs.
            return SeverityFactors.from_crash(
                _SyntheticCrash(raw_log=value))
        return SeverityFactors.from_crash(value)

    @staticmethod
    def _build_rationale(
        factors: SeverityFactors,
        base: float,
        score: float,
        band: SeverityBand,
        fired: Sequence[ScoreAdjustment],
    ) -> str:
        parts = [
            f"class '{factors.class_token}' base {base:.1f}",
        ]
        if factors.sanitizer:
            parts.append(f"observed by {factors.sanitizer}")
        for adj in fired:
            sign = "+" if adj.delta >= 0 else "-"
            parts.append(f"{adj.rule_name} {sign}{abs(adj.delta):.1f}")
        parts.append(f"=> {score:.1f} ({band.value})")
        return "; ".join(parts)


_DEFAULT_ASSESSOR: Optional[SeverityAssessor] = None
_DEFAULT_LOCK = threading.Lock()


def _default_assessor() -> SeverityAssessor:
    global _DEFAULT_ASSESSOR
    with _DEFAULT_LOCK:
        if _DEFAULT_ASSESSOR is None:
            _DEFAULT_ASSESSOR = SeverityAssessor()
        return _DEFAULT_ASSESSOR


# =============================================================================
# Functional helpers
# =============================================================================
def assess_severity(crash_or_factors: Any, **kw: Any) -> SeverityDecision:
    """One-call severity assessment using the shared default assessor."""
    if kw:
        return SeverityAssessor(**kw).assess(crash_or_factors)
    return _default_assessor().assess(crash_or_factors)


def assess_many(items: Iterable[Any]) -> List[SeverityDecision]:
    return _default_assessor().assess_batch(items)


def score_to_severity(score: float) -> Severity:
    """Numeric 0..10 score -> core Severity enum."""
    return SeverityBand.from_score(score).to_core_severity()


#: Backwards-compatible alias.
severity_from_score = score_to_severity


def band_for_score(score: float) -> SeverityBand:
    return SeverityBand.from_score(score)


def cvss_style_vector(factors: SeverityFactors, score: float,
                      band: SeverityBand) -> str:
    """Render a CVSS-3.1-*style* descriptive vector.

    Honest labelling: AV/AC/UI reflect what KMCS *observed* about the crash
    context (local fuzzing harness, replayed deterministically or not, no user
    interaction).  It is a communication aid, not a certified CVSS score.
    """
    av = "L"                                   # local fuzzing target
    ac = "L" if factors.is_reproduced else "H"  # attack/analysis complexity proxy
    pr = "N"                                    # privileges: harness runs unprivileged
    ui = "N"                                    # no user interaction involved
    scope = "U"
    if factors.is_write_access or factors.class_token in {
        "use-after-free", "heap-buffer-overflow", "stack-buffer-overflow",
        "double-free",
    }:
        cia = "H/H/H" if factors.is_write_access else "L/L/H"
    elif factors.is_leak_only:
        cia = "N/N/L"
    elif factors.is_ubsan_diagnostic_only:
        cia = "N/N/L"
    else:
        cia = "L/L/L"
    return (f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}"
            f"/C:{cia.split('/')[0]}/I:{cia.split('/')[1]}/A:{cia.split('/')[2]}")


# =============================================================================
# Self test
# =============================================================================
def self_test_report() -> Dict[str, Any]:
    """Run internal consistency checks and return a JSON-friendly report."""
    results: List[Dict[str, Any]] = []

    def check(name: str, fn) -> None:
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"exception: {exc}"
        results.append({"check": name, "passed": bool(ok), "detail": detail})

    # 1. Determinism: identical inputs -> identical decisions.
    def _determinism():
        synthetic = _SyntheticCrash(
            raw_log=(
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address "
                "0x602000000051 at pc 0x400aa4 bp 0x7ffd sp 0x7ff8\n"
                "WRITE of size 4 at 0x602000000051 thread T0\n"
                "    #0 0x400aa4 in vulnerable copy.c:12\n"
                "    #1 0x400b20 in main copy.c:20\n"
                "allocated by thread T0 here:\n"
                "    #0 0x7f8 malloc\n"
            ),
            crash_class="heap-buffer-overflow",
            sanitizer="address",
        )
        a = assess_severity(synthetic)
        b = assess_severity(synthetic)
        return (a.to_dict() == b.to_dict(),
                f"score_a={a.score} score_b={b.score}")
    check("determinism", _determinism)

    # 2. Write escalation over read for the same class.
    def _write_gt_read():
        common = "    #0 0x400aa4 in vuln t.c:1\n"
        w = assess_severity(_SyntheticCrash(
            raw_log=("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                     "WRITE of size 8 at 0x602 thread T0\n" + common),
            crash_class="heap-buffer-overflow", sanitizer="address"))
        r = assess_severity(_SyntheticCrash(
            raw_log=("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                     "READ of size 8 at 0x602 thread T0\n" + common),
            crash_class="heap-buffer-overflow", sanitizer="address"))
        return (w.score > r.score, f"write={w.score} read={r.score}")
    check("write_above_read", _write_gt_read)

    # 3. Leak-only observations stay low.
    def _leak_low():
        d = assess_severity(_SyntheticCrash(
            raw_log=("ERROR: LeakSanitizer: detected memory leaks\n"
                     "Direct leak of 40 byte(s) in 1 object(s) allocated from:\n"
                     "    #0 0x7f8 malloc\n"),
            crash_class="memory-leak", sanitizer="leak"))
        return (d.band in (SeverityBand.LOW, SeverityBand.MEDIUM) and d.score <= 4.5,
                f"leak score={d.score} band={d.band}")
    check("leak_band_limited", _leak_low)

    # 4. Null-page dereference gets down-adjusted vs far-offset.
    def _geometry():
        near = assess_severity(_SyntheticCrash(
            raw_log=("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010\n"
                     "    #0 0x400 in f g.c:1\n"),
            crash_class="null-pointer-dereference", sanitizer="address"))
        far = assess_severity(_SyntheticCrash(
            raw_log=("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address "
                     "0x619000000100 at pc 0x400\nREAD of size 16\n"
                     "    #0 0x400 in f g.c:1\n"),
            crash_class="heap-buffer-overflow", sanitizer="address"))
        return (far.score > near.score, f"null={near.score} far={far.score}")
    check("geometry_ordering", _geometry)

    # 5. Band boundaries.
    def _bands():
        cases = {(0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"),
                 (6.9, "medium"), (7.0, "high"), (8.9, "high"), (9.0, "critical"),
                 (10.0, "critical")}
        bad = [(s, e) for s, e in cases if SeverityBand.from_score(s).value != e]
        return (not bad, f"mismatches={bad}")
    check("band_boundaries", _bands)

    # 6. Clamp respected.
    def _clamp_ok():
        d = assess_severity(SeverityFactors(class_token="use-after-free",
                                            is_write_access=True,
                                            has_allocation_trace=True,
                                            has_free_trace=True,
                                            has_shadow_annotation=True,
                                            is_far_offset=True,
                                            is_reproduced=True,
                                            classification_certain=True,
                                            has_symbolised_site=True))
        return (0.0 <= d.score <= 10.0, f"max-evidence score={d.score}")
    check("score_clamped", _clamp_ok)

    # 7. Custom base override validated.
    def _override():
        try:
            SeverityAssessor(base_scores={"my-class": 11.0})
            return (False, "out-of-range override accepted")
        except InvalidValueError:
            return (True, "out-of-range override rejected")
    check("base_override_validation", _override)

    passed = sum(1 for r in results if r["passed"])
    return {
        "module": "kmcs.analysis.severity",
        "version": __version__,
        "checks_total": len(results),
        "checks_passed": passed,
        "all_passed": passed == len(results),
        "results": results,
        "table_sizes": {
            "base_scores": len(DEFAULT_BASE_SCORES),
            "adjustment_rules": len(SEVERITY_ADJUSTMENTS),
        },
    }


# =============================================================================
# Smoke test / CLI
# =============================================================================
def _smoke() -> int:
    print("kmcs.analysis.severity smoke test")
    print("-" * 60)
    demo_logs = [
        ("heap-buffer-overflow (write)", _SyntheticCrash(
            raw_log=("==42==ERROR: AddressSanitizer: heap-buffer-overflow on "
                     "address 0x6030000000f4 at pc 0x4011c9 bp 0x7ffe sp 0x7fd8\n"
                     "WRITE of size 8 at 0x6030000000f4 thread T0\n"
                     "    #0 0x4011c9 in evil memcpy_target.c:14\n"
                     "    #1 0x401240 in main memcpy_target.c:22\n"
                     "allocated by thread T0 here:\n"
                     "    #0 0x7ffff7 malloc\n"
                     "SUMMARY: AddressSanitizer: heap-buffer-overflow "
                     "memcpy_target.c:14 in evil\n"),
            crash_class="heap-buffer-overflow", sanitizer="address")),
        ("use-after-free", _SyntheticCrash(
            raw_log=("==7==ERROR: AddressSanitizer: heap-use-after-free on "
                     "address 0x602000000010\n"
                     "READ of size 4 at 0x602000000010 thread T0\n"
                     "    #0 0x400e11 in uaf demo.c:9\n"
                     "freed by thread T0 here:\n"
                     "    #0 0x400dd0 in release demo.c:6\n"),
            crash_class="use-after-free", sanitizer="address")),
        ("UBSan integer overflow", _SyntheticCrash(
            raw_log="demo.c:5:7: runtime error: signed integer overflow: "
                    "2147483647 + 1 cannot be represented in type 'int'",
            crash_class="signed-integer-overflow", sanitizer="undefined")),
        ("LSan leak", _SyntheticCrash(
            raw_log=("ERROR: LeakSanitizer: detected memory leaks\n"
                     "Direct leak of 100 byte(s) in 1 object(s)\n"
                     "    #0 0x7f malloc\n"),
            crash_class="memory-leak", sanitizer="leak")),
        ("bare segfault", _SyntheticCrash(
            raw_log="Segmentation fault (core dumped)",
            crash_class="segfault", sanitizer=None)),
    ]
    for label, crash in demo_logs:
        d = assess_severity(crash)
        print(f"{label:32s} -> {d.summary_line()}")
        print(f"{'':32s}    {d.rationale}")

    rep = self_test_report()
    print("-" * 60)
    for r in rep["results"]:
        mark = "PASS" if r["passed"] else "FAIL"
        print(f"[{mark}] {r['check']}: {r['detail']}")
    print("-" * 60)
    print(f"self-test: {rep['checks_passed']}/{rep['checks_total']} passed")
    return 0 if rep["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(_smoke())
