# =============================================================================
# kmcs.analysis.classifier -- evidence-driven crash classification
# =============================================================================
"""
Classify crashes into :class:`kmcs.core.models.CrashClass` categories using a
transparent, rule-based engine.

Why rules and not magic
-----------------------
Every classification decision must be *explainable* to a human triager and
*reproducible* across runs.  This module therefore implements a deterministic
ordered rule set: each rule carries an id, a predicate over observable
evidence (sanitizer banner tokens, headline text, memory-access fields,
signal numbers, stack symbols), the resulting :class:`CrashClass`, a base
confidence, and a human-readable rationale template.  The classifier returns
the winning rule plus the full evaluation trace, so "why did KMCS call this a
use-after-free?" always has a concrete answer.

Evidence sources (in priority order)
------------------------------------
1. ``report.crash_class`` when already set by the sanitizer parser — trusted
   but re-validated against the headline (defence in depth against parser
   regressions).
2. Sanitizer banner tokens (ASan/LSan/MSan/TSan/UBSan error names).
3. Structured fields: memory access type/size/offset, allocation metadata,
   shadow-byte annotations ("freed region", "stack region", ...).
4. Signal information (SIGSEGV at address 0 -> null-dereference, SIGABRT +
   assertion text -> assertion-failure, ...).
5. Stack symbol heuristics (frames inside ``operator new``/``malloc`` with a
   double-free headline, etc.).  Symbol rules are intentionally conservative:
   they only *refine* an existing class or resolve UNKNOWN, never override a
   strong banner signal with a weak textual guess.

Confidence model
----------------
Each rule declares a base confidence (LOW/MEDIUM/HIGH).  Corroborating
evidence (e.g. both banner and shadow-byte annotation agree) upgrades one
step; contradicting evidence downgrades one step and appends a warning.
The final :class:`ClassificationResult.confidence_score` is a float derived
from the ladder position plus corroboration count, suitable for ranking.

Extensibility
-------------
``RuleSet`` objects are plain lists of :class:`ClassificationRule` instances;
callers can build custom sets, prepend project-specific rules, or load them
from JSON/YAML mappings via :meth:`RuleSet.from_dicts`.  The default set is
exposed through :func:`default_rule_set` and cached per-thread-safe factory.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.exceptions import CrashClassificationError
from kmcs.core.models import (
    Confidence,
    Crash,
    CrashClass,
    MemoryAccess,
    SanitizerKind,
    SanitizerReport,
    SignalInfo,
    severity_from_crash_class,
)

__all__ = [
    "ClassificationRule",
    "RuleSet",
    "ClassificationResult",
    "CrashClassifier",
    "default_rule_set",
    "classify_text",
    "classify_report",
]

# ============================================================================
# evidence extraction
# ============================================================================


@dataclass(frozen=True)
class _Evidence:
    """Immutable snapshot of everything observable about one crash."""

    sanitizer: str = SanitizerKind.NONE.value
    headline: str = ""
    body: str = ""
    given_class: str = CrashClass.UNKNOWN.value
    access_type: str = ""
    access_size: Optional[int] = None
    offset_from_allocation: Optional[int] = None
    allocation_size: Optional[int] = None
    direction: str = ""
    signal_number: Optional[int] = None
    fault_address: Optional[str] = None
    top_symbols: Tuple[str, ...] = ()
    stats: Mapping[str, int] = field(default_factory=dict)
    warnings: Tuple[str, ...] = ()

    @property
    def text(self) -> str:
        return f"{self.headline}\n{self.body}".lower()

    def has(self, *needles: str) -> bool:
        hay = self.text
        return any(needle.lower() in hay for needle in needles)


def _evidence_from_report(report: SanitizerReport) -> _Evidence:
    access = report.memory_access
    symbols: List[str] = []
    for frame in list(report.stack_trace)[:8]:
        if frame.function:
            symbols.append(frame.function)
    return _Evidence(
        sanitizer=report.sanitizer,
        headline=report.headline or "",
        body=report.raw_output or "",
        given_class=report.crash_class,
        access_type=(access.access_type if access else ""),
        access_size=(access.access_size if access else None),
        offset_from_allocation=(access.offset_from_allocation if access else None),
        allocation_size=(access.allocation_size if access else None),
        direction=(access.direction if access else ""),
        fault_address=(access.access_address if access else None),
        top_symbols=tuple(symbols),
        stats=dict(report.stats),
        warnings=tuple(report.warnings),
    )


def _evidence_from_crash(crash: Crash) -> _Evidence:
    report = crash.sanitizer_report
    ev = _evidence_from_report(report) if report is not None else _Evidence()
    # merge fields that live on the Crash itself
    updates: Dict[str, Any] = {}
    if crash.signal is not None and crash.signal.signal_number is not None:
        updates["signal_number"] = crash.signal.signal_number
        if crash.signal.fault_address:
            updates["fault_address"] = crash.signal.fault_address
    if not ev.sanitizer and crash.sanitizer:
        updates["sanitizer"] = crash.sanitizer
    if ev.given_class == CrashClass.UNKNOWN.value and crash.crash_class:
        updates["given_class"] = crash.crash_class
    if updates:
        ev = _Evidence(**{**ev.__dict__, **updates})
    return ev


# ============================================================================
# rules
# ============================================================================

Predicate = Callable[[_Evidence], bool]


@dataclass(frozen=True)
class ClassificationRule:
    """One deterministic classification step."""

    rule_id: str
    target_class: CrashClass
    predicate: Predicate
    base_confidence: Confidence = Confidence.MEDIUM
    rationale: str = ""
    #: rules with higher priority are evaluated first
    priority: int = 100
    #: when True a match short-circuits the whole rule set
    terminal: bool = True
    #: free-form tags for reporting/telemetry
    tags: Tuple[str, ...] = ()

    def explain(self, evidence: _Evidence) -> str:
        text = self.rationale or f"matched rule {self.rule_id}"
        return text.format(
            class_=self.target_class.value,
            sanitizer=evidence.sanitizer,
            headline=(evidence.headline or "")[:160],
        )


def _contains(*needles: str) -> Predicate:
    def check(ev: _Evidence) -> bool:
        return ev.has(*needles)
    return check


def _banner_class_tokens(tokens: Sequence[str]) -> Predicate:
    """Match sanitizer headline/banner containing any token (normalised)."""
    normalised = tuple(re.sub(r"[\s_]+", "-", t.lower()) for t in tokens)

    def check(ev: _Evidence) -> bool:
        head = re.sub(r"[\s_]+", "-", ev.headline.lower())
        return any(token in head for token in normalised)
    return check


def _is(sanitizer: str, *predicates: Predicate) -> Predicate:
    def check(ev: _Evidence) -> bool:
        if ev.sanitizer != sanitizer:
            return False
        return all(p(ev) for p in predicates) if predicates else True
    return check


_RULES_CACHE: Optional["RuleSet"] = None
_RULES_LOCK = threading.Lock()


class RuleSet:
    """Ordered collection of :class:`ClassificationRule` objects."""

    def __init__(self, rules: Iterable[ClassificationRule] = (), *, name: str = "custom") -> None:
        self.name = name
        self._rules: List[ClassificationRule] = sorted(rules, key=lambda r: -int(r.priority))

    # ------------------------------------------------------------- building

    def add(self, rule: ClassificationRule) -> "RuleSet":
        self._rules.append(rule)
        self._rules.sort(key=lambda r: -int(r.priority))
        return self

    def extend(self, rules: Iterable[ClassificationRule]) -> "RuleSet":
        for rule in rules:
            self.add(rule)
        return self

    @classmethod
    def from_dicts(cls, payloads: Sequence[Mapping[str, Any]], *, name: str = "loaded") -> "RuleSet":
        """Build a rule set from serialisable dicts (JSON friendly).

        Supported predicate specs under key ``when``:
          {"contains": [...]}          -- substring(s) anywhere in the report
          {"headline_contains": [...]} -- substring(s) in the headline
          {"sanitizer": "..."}         -- exact sanitizer token
          {"signal": N}                -- exact signal number
          {"class_is": "..."}          -- pre-set crash class token
        All conditions in one dict must hold (logical AND).
        """
        rules: List[ClassificationRule] = []
        for payload in payloads:
            when = dict(payload.get("when") or {})
            conditions: List[Predicate] = []
            if "contains" in when:
                conditions.append(_contains(*when["contains"]))
            if "headline_contains" in when:
                needles = tuple(str(n).lower() for n in when["headline_contains"])

                def mk(ns: Tuple[str, ...]) -> Predicate:
                    def check(ev: _Evidence) -> bool:
                        hay = ev.headline.lower()
                        return all(n in hay for n in ns)
                    return check
                conditions.append(mk(needles))
            if "sanitizer" in when:
                want = str(when["sanitizer"])

                def sani(ev: _Evidence, want: str = want) -> bool:
                    return ev.sanitizer == want
                conditions.append(sani)
            if "signal" in when:
                signum = int(when["signal"])

                def sig(ev: _Evidence, signum: int = signum) -> bool:
                    return ev.signal_number == signum
                conditions.append(sig)
            if "class_is" in when:
                token = str(when["class_is"])

                def cls_is(ev: _Evidence, token: str = token) -> bool:
                    return ev.given_class == token
                conditions.append(cls_is)

            def combined(evid: _Evidence, preds: Tuple[Predicate, ...] = tuple(conditions)) -> bool:
                return bool(preds) and all(p(evid) for p in preds)

            try:
                target = CrashClass.coerce(payload["class"])
            except Exception as exc:
                raise CrashClassificationError(
                    f"rule '{payload.get('rule_id', '?')}' references unknown class "
                    f"'{payload.get('class')}'", component="analysis.classifier") from exc
            rules.append(ClassificationRule(
                rule_id=str(payload.get("rule_id") or f"json-{len(rules)}"),
                target_class=target,
                predicate=combined,
                base_confidence=Confidence.coerce(payload.get("confidence", "medium")),
                rationale=str(payload.get("rationale", "")),
                priority=int(payload.get("priority", 50)),
                terminal=bool(payload.get("terminal", True)),
                tags=tuple(str(t) for t in payload.get("tags", ())),
            ))
        return cls(rules, name=name)

    def to_dicts(self) -> List[Dict[str, Any]]:
        return [
            {"rule_id": r.rule_id, "class": r.target_class.value,
             "confidence": r.base_confidence.value, "priority": r.priority,
             "terminal": r.terminal, "rationale": r.rationale, "tags": list(r.tags)}
            for r in self._rules
        ]

    # ------------------------------------------------------------ access

    @property
    def rules(self) -> Tuple[ClassificationRule, ...]:
        return tuple(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    def evaluate(self, evidence: _Evidence) -> Optional[Tuple[ClassificationRule, str]]:
        for rule in self._rules:
            try:
                matched = bool(rule.predicate(evidence))
            except Exception:
                # a broken user rule must not take the pipeline down
                continue
            if matched:
                return rule, rule.explain(evidence)
        return None


# ============================================================================
# default rule set
# ============================================================================


def _shadow_annotation(*needles: str) -> Predicate:
    def check(ev: _Evidence) -> bool:
        return ev.has(*needles)
    return check


def default_rule_set() -> RuleSet:
    """The built-in, defence-oriented classification ruleset.

    Priorities: 900+ trust structured sanitizer output, 700+ banner tokens,
    500+ refined heuristics (shadow annotations / access geometry),
    300+ signal-only inference, 100+ symbol hints, 10 fallback.
    """
    global _RULES_CACHE
    with _RULES_LOCK:
        if _RULES_CACHE is not None:
            return _RULES_CACHE

        rules: List[ClassificationRule] = []

        # --- 900: trust the sanitizer's own words ---------------------------
        asan_pairs = [
            ("heap-buffer-overflow", CrashClass.HEAP_BUFFER_OVERFLOW),
            ("heap-buffer-underflow", CrashClass.HEAP_BUFFER_UNDERFLOW),
            ("stack-buffer-overflow", CrashClass.STACK_BUFFER_OVERFLOW),
            ("stack-buffer-underflow", CrashClass.STACK_BUFFER_UNDERFLOW),
            ("global-buffer-overflow", CrashClass.GLOBAL_BUFFER_OVERFLOW),
            ("global-buffer-underflow", CrashClass.GLOBAL_BUFFER_UNDERFLOW),
            ("use-after-free", CrashClass.USE_AFTER_FREE),
            ("use-after-return", CrashClass.USE_AFTER_RETURN),
            ("use-after-scope", CrashClass.USE_AFTER_SCOPE),
            ("double-free", CrashClass.DOUBLE_FREE),
            ("attempting double-free", CrashClass.DOUBLE_FREE),
            ("alloc-dealloc-mismatch", CrashClass.ALLOCATOR_MISUSE),
            ("invalid free", CrashClass.INVALID_FREE),
            ("negative-size-param", CrashClass.ALLOCATOR_MISUSE),
            ("requested allocation is too large", CrashClass.OVERFLOW_ALLOC),
            ("new-delete-type-mismatch", CrashClass.ALLOCATOR_MISUSE),
            ("dynamic-stack-buffer-overflow", CrashClass.STACK_BUFFER_OVERFLOW),
            ("container-overflow", CrashClass.HEAP_BUFFER_OVERFLOW),
            ("initialization-order-fiasco", CrashClass.UNINITIALIZED_USE),
            ("stack-overflow", CrashClass.STACK_OVERFLOW),
            ("allocator-is-out-of-memory", CrashClass.OUT_OF_MEMORY),
            ("segfault", CrashClass.SEGMENTATION_FAULT),
            ("ibus", CrashClass.BUS_ERROR),
        ]
        for token, cls in asan_pairs:
            rules.append(ClassificationRule(
                rule_id=f"asan:{token}",
                target_class=cls,
                predicate=_banner_class_tokens([token]),
                base_confidence=Confidence.HIGH,
                rationale=f"AddressSanitizer banner names '{token}' directly",
                priority=900, tags=("asan", "banner")))

        # LSan / MSan / TSan banners
        rules.append(ClassificationRule(
            rule_id="lsan:leaks",
            target_class=CrashClass.MEMORY_LEAK,
            predicate=_is(SanitizerKind.LSAN.value, _contains("detected memory leaks")),
            base_confidence=Confidence.HIGH,
            rationale="LeakSanitizer reported detected memory leaks",
            priority=895, tags=("lsan", "banner")))
        rules.append(ClassificationRule(
            rule_id="msan:uninit",
            target_class=CrashClass.UNINITIALIZED_USE,
            predicate=_banner_class_tokens(["use-of-uninitialized-value"]),
            base_confidence=Confidence.HIGH,
            rationale="MemorySanitizer observed use of an uninitialized value",
            priority=890, tags=("msan", "banner")))
        rules.append(ClassificationRule(
            rule_id="tsan:race",
            target_class=CrashClass.DATA_RACE,
            predicate=_banner_class_tokens(["data race"]),
            base_confidence=Confidence.HIGH,
            rationale="ThreadSanitizer observed a data race",
            priority=885, tags=("tsan", "banner")))
        rules.append(ClassificationRule(
            rule_id="tsan:lock inversion",
            target_class=CrashClass.LOCK_ORDER_INVERSION,
            predicate=_banner_class_tokens(["lock-order-inversion", "lock order inversion"]),
            base_confidence=Confidence.HIGH,
            rationale="ThreadSanitizer observed a lock-order inversion (potential deadlock)",
            priority=884, tags=("tsan", "banner")))

        # UBSan message patterns
        ubsan_map = [
            ("signed integer overflow", CrashClass.INTEGER_OVERFLOW),
            ("unsigned integer overflow", CrashClass.INTEGER_OVERFLOW),
            ("division by zero", CrashClass.DIVIDE_BY_ZERO),
            ("misaligned", CrashClass.MISALIGNED_ACCESS),
            ("object size mismatch", CrashClass.OBJECT_SIZE_VIOLATION),
            ("outside range of type", CrashClass.ENUM_OUT_OF_RANGE),
            ("unreachable", CrashClass.UNREACHABLE_CODE),
            ("member call on null pointer", CrashClass.NULL_DEREFERENCE),
            ("load of null pointer", CrashClass.NULL_ARGUMENT),
            ("function pointer type mismatch", CrashClass.FUNCTION_TYPE_MISMATCH),
            ("vla bound", CrashClass.VLA_BOUND_CHANGE),
        ]
        for token, cls in ubsan_map:
            rules.append(ClassificationRule(
                rule_id=f"ubsan:{token}",
                target_class=cls,
                predicate=_is(SanitizerKind.UBSAN.value, _contains(token)),
                base_confidence=Confidence.HIGH,
                rationale=f"UBSan runtime error mentions '{token}'",
                priority=880, tags=("ubsan", "banner")))

        # --- 500: geometric refinement from structured fields ---------------
        rules.append(ClassificationRule(
            rule_id="geom:null-page-access",
            target_class=CrashClass.NULL_DEREFERENCE,
            predicate=lambda ev: (
                ev.fault_address is not None
                and ev.fault_address.strip().lower().startswith(("0x0", "0000"))
                and len(ev.fault_address.strip("0xfx ")) <= 16
                and int(ev.fault_address, 16) < 0x10000
            ),
            base_confidence=Confidence.HIGH,
            rationale="faulting address lies inside the null guard page (< 0x10000)",
            priority=750, tags=("geometry",)))
        rules.append(ClassificationRule(
            rule_id="geom:underflow",
            target_class=CrashClass.HEAP_BUFFER_UNDERFLOW,
            predicate=lambda ev: (
                ev.direction == "underflow" and ev.sanitizer == SanitizerKind.ASAN.value),
            base_confidence=Confidence.MEDIUM,
            rationale="observed access offset is negative relative to allocation start",
            priority=560, tags=("geometry",)))
        rules.append(ClassificationRule(
            rule_id="geom:overflow",
            target_class=CrashClass.HEAP_BUFFER_OVERFLOW,
            predicate=lambda ev: (
                ev.direction == "overflow" and ev.sanitizer == SanitizerKind.ASAN.value),
            base_confidence=Confidence.MEDIUM,
            rationale="observed access offset exceeds the allocation end",
            priority=555, tags=("geometry",)))

        # shadow-byte annotations distinguish heap/stack/global/UAF precisely
        rules.append(ClassificationRule(
            rule_id="shadow:freed-region",
            target_class=CrashClass.USE_AFTER_FREE,
            predicate=_shadow_annotation("is located in freed region",
                                         "address is located inside of freed region",
                                         "located in a freed region"),
            base_confidence=Confidence.HIGH,
            rationale="shadow analysis places the fault inside a freed region",
            priority=760, tags=("asan", "shadow")))
        rules.append(ClassificationRule(
            rule_id="shadow:stack-region",
            target_class=CrashClass.STACK_BUFFER_OVERFLOW,
            predicate=_shadow_annotation("is located on stack"),
            base_confidence=Confidence.HIGH,
            rationale="shadow analysis places the fault on a stack region",
            priority=755, tags=("asan", "shadow")))
        rules.append(ClassificationRule(
            rule_id="shadow:global-region",
            target_class=CrashClass.GLOBAL_BUFFER_OVERFLOW,
            predicate=_shadow_annotation("is located in global region",
                                         "is located near global variable"),
            base_confidence=Confidence.HIGH,
            rationale="shadow analysis places the fault in/near a global region",
            priority=754, tags=("asan", "shadow")))

        # --- 300: signal-only inference --------------------------------------
        rules.append(ClassificationRule(
            rule_id="sig:abort-assert",
            target_class=CrashClass.ASSERTION_FAILURE,
            predicate=lambda ev: ev.signal_number == 6 and ev.has("assert"),
            base_confidence=Confidence.HIGH,
            rationale="SIGABRT together with assertion text in output",
            priority=650, tags=("signal",)))
        rules.append(ClassificationRule(
            rule_id="sig:abort",
            target_class=CrashClass.ABORT,
            predicate=lambda ev: ev.signal_number == 6,
            base_confidence=Confidence.MEDIUM,
            rationale="process died on SIGABRT without further context",
            priority=640, tags=("signal",)))
        rules.append(ClassificationRule(
            rule_id="sig:segv-null",
            target_class=CrashClass.NULL_DEREFERENCE,
            predicate=lambda ev: ev.signal_number == 11 and ev.fault_address in {"0x0", "0x0000000000000000"},
            base_confidence=Confidence.HIGH,
            rationale="SIGSEGV exactly at address 0x0",
            priority=645, tags=("signal",)))
        rules.append(ClassificationRule(
            rule_id="sig:segv",
            target_class=CrashClass.SEGMENTATION_FAULT,
            predicate=lambda ev: ev.signal_number == 11,
            base_confidence=Confidence.MEDIUM,
            rationale="process died on SIGSEGV (no sanitizer detail available)",
            priority=630, tags=("signal",)))
        rules.append(ClassificationRule(
            rule_id="sig:fpe",
            target_class=CrashClass.DIVIDE_BY_ZERO,
            predicate=lambda ev: ev.signal_number == 8,
            base_confidence=Confidence.MEDIUM,
            rationale="SIGFPE almost always indicates arithmetic error (division by zero)",
            priority=625, tags=("signal",)))
        rules.append(ClassificationRule(
            rule_id="sig:ill",
            target_class=CrashClass.ILLEGAL_INSTRUCTION,
            predicate=lambda ev: ev.signal_number == 4,
            base_confidence=Confidence.HIGH,
            rationale="process died on SIGILL",
            priority=620, tags=("signal",)))
        rules.append(ClassificationRule(
            rule_id="sig:bus",
            target_class=CrashClass.BUS_ERROR,
            predicate=lambda ev: ev.signal_number == 7,
            base_confidence=Confidence.HIGH,
            rationale="process died on SIGBUS",
            priority=618, tags=("signal",)))
        rules.append(ClassificationRule(
            rule_id="sig:killed-oom",
            target_class=CrashClass.OUT_OF_MEMORY,
            predicate=lambda ev: ev.signal_number == 9 and ev.has("memory", "oom"),
            base_confidence=Confidence.MEDIUM,
            rationale="SIGKILL together with memory pressure text (OOM killer pattern)",
            priority=615, tags=("signal",)))

        # --- 100: symbol hints (only refine UNKNOWN) -------------------------
        rules.append(ClassificationRule(
            rule_id="sym:cxa_throw-abort",
            target_class=CrashClass.ABORT,
            predicate=lambda ev: any(sym in ("std::terminate()", "__cxa_throw")
                                     for sym in ev.top_symbols),
            base_confidence=Confidence.LOW,
            rationale="top frames show std::terminate/__cxa_throw",
            priority=140, terminal=False, tags=("symbols",)))
        rules.append(ClassificationRule(
            rule_id="sym:recursion-depth",
            target_class=CrashClass.STACK_OVERFLOW,
            predicate=lambda ev: (
                len(ev.top_symbols) >= 2
                and ev.top_symbols[0]
                and ev.top_symbols[0] == ev.top_symbols[-1]),
            base_confidence=Confidence.LOW,
            rationale="identical function repeated at stack extremes (deep recursion pattern)",
            priority=130, terminal=False, tags=("symbols",)))

        # --- 10: trust pre-set class / fallback -------------------------------
        def _preset(ev: _Evidence) -> bool:
            try:
                coerced = CrashClass.coerce(ev.given_class)
            except Exception:
                return False
            return coerced is not CrashClass.UNKNOWN

        rules.append(ClassificationRule(
            rule_id="fallback:preset-class",
            target_class=CrashClass.UNKNOWN,  # replaced dynamically below
            predicate=_preset,
            base_confidence=Confidence.MEDIUM,
            rationale="keeping class already established by the sanitizer parser",
            priority=20, tags=("fallback",)))

        # NOTE: the preset rule needs a dynamic target; handled specially in
        # CrashClassifier.classify (see _apply_preset_rule).

        set_obj = RuleSet(rules, name="kmcs-default")
        _RULES_CACHE = set_obj
        return set_obj


# ============================================================================
# results & classifier
# ============================================================================


@dataclass
class ClassificationResult:
    """Outcome of one classification pass, fully explained."""

    crash_class: CrashClass
    confidence: Confidence
    score: float
    rule_id: str
    rationale: str
    severity: Any = None              # kmcs Severity of the resolved class
    corroborated_by: List[str] = field(default_factory=list)
    contradicted_by: List[str] = field(default_factory=list)
    trace: List[str] = field(default_factory=list)
    classified_at: str = ""

    @property
    def is_unknown(self) -> bool:
        return self.crash_class is CrashClass.UNKNOWN

    def apply_to(self, crash: Crash, *, note_prefix: str = "classifier") -> Crash:
        crash.classify(self.crash_class, confidence=self.confidence,
                       note=f"{note_prefix}:{self.rule_id}")
        return crash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_class": self.crash_class.value,
            "confidence": self.confidence.value,
            "score": round(float(self.score), 4),
            "rule_id": self.rule_id,
            "rationale": self.rationale,
            "severity": getattr(self.severity, "value", self.severity),
            "corroborated_by": list(self.corroborated_by),
            "contradicted_by": list(self.contradicted_by),
            "trace": list(self.trace),
            "classified_at": self.classified_at,
        }


class CrashClassifier:
    """Deterministic, explainable crash classifier.

    Parameters
    ----------
    ruleset:
        Custom :class:`RuleSet`; defaults to :func:`default_rule_set`.
    respect_preset:
        When True (default) a crash class already established by the parser
        is kept unless a *higher-priority* rule matches different evidence,
        in which case the disagreement is recorded in ``contradicted_by``
        and confidence is downgraded instead of silently overriding.
    """

    def __init__(self, *, ruleset: Optional[RuleSet] = None,
                 respect_preset: bool = True) -> None:
        self.ruleset = ruleset or default_rule_set()
        self.respect_preset = bool(respect_preset)
        self.decisions = 0
        self.unknowns = 0

    # ------------------------------------------------------------------ api

    def classify_evidence(self, evidence: _Evidence, *,
                          timestamp: str = "") -> ClassificationResult:
        from kmcs.core.models import utc_string
        result = self._classify_core(evidence)
        if not result.classified_at:
            result.classified_at = timestamp or utc_string()
        self.decisions += 1
        if result.is_unknown:
            self.unknowns += 1
        return result

    def classify_report(self, report: SanitizerReport, *,
                        timestamp: str = "") -> ClassificationResult:
        return self.classify_evidence(_evidence_from_report(report), timestamp=timestamp)

    def classify_crash(self, crash: Crash, *, timestamp: str = "",
                       apply: bool = True) -> ClassificationResult:
        result = self.classify_evidence(_evidence_from_crash(crash), timestamp=timestamp)
        if apply and not result.is_unknown:
            result.apply_to(crash)
        return result

    def classify_text(self, text: str, *, sanitizer_hint: str = "",
                      signal_number: Optional[int] = None,
                      timestamp: str = "") -> ClassificationResult:
        """Classify directly from raw log text (convenience path)."""
        evidence = _Evidence(
            sanitizer=sanitizer_hint or SanitizerKind.NONE.value,
            headline=next((ln for ln in text.splitlines()
                           if "ERROR:" in ln or "runtime error" in ln or "WARNING:" in ln), ""),
            body=text,
            signal_number=signal_number,
        )
        return self.classify_evidence(evidence, timestamp=timestamp)

    # ------------------------------------------------------------ internals

    def _classify_core(self, evidence: _Evidence) -> ClassificationResult:
        match = self.ruleset.evaluate(evidence)
        trace: List[str] = []

        if match is None:
            # nothing matched -> honour preset class if valid, else UNKNOWN
            preset = self._preset_class(evidence)
            if preset is not None:
                return ClassificationResult(
                    crash_class=preset, confidence=Confidence.MEDIUM,
                    score=0.5, rule_id="implicit:preset",
                    rationale="no rule matched; retaining parser-established class",
                    severity=severity_from_crash_class(preset),
                    trace=["no-rule-match", "retain-preset"],
                )
            return ClassificationResult(
                crash_class=CrashClass.UNKNOWN, confidence=Confidence.UNKNOWN,
                score=0.0, rule_id="none", rationale="no rule matched and no preset class",
                severity=severity_from_crash_class(CrashClass.UNKNOWN),
                trace=["no-rule-match", "unknown"],
            )

        rule, rationale = match

        # dynamic handling of the preset-retention rule
        if rule.rule_id == "fallback:preset-class":
            preset = self._preset_class(evidence) or CrashClass.UNKNOWN
            rule_target = preset
        else:
            rule_target = rule.target_class

        confidence = rule.base_confidence
        corroborated: List[str] = []
        contradicted: List[str] = []

        # corroboration: does the evidence independently support the same family?
        preset = self._preset_class(evidence)
        if preset is not None and preset is not CrashClass.UNKNOWN:
            if preset.family == rule_target.family and preset is not rule_target:
                corroborated.append(f"parser-class={preset.value}")
            elif preset is not rule_target and rule.priority < 900:
                contradicted.append(
                    f"parser says '{preset.value}', rule '{rule.rule_id}' says "
                    f"'{rule_target.value}'")
                confidence = _downgrade(confidence)
            elif preset is rule_target:
                corroborated.append("parser-class-agrees")

        if evidence.has("freed by thread") and rule_target is CrashClass.USE_AFTER_FREE:
            corroborated.append("free-trace-present")
        if evidence.access_type in ("read", "write") and rule_target.is_memory_safety:
            corroborated.append(f"access-type={evidence.access_type}")
        if len(corroborated) >= 2 and confidence is not Confidence.CONFIRMED:
            confidence = _upgrade(confidence)
            trace.append(f"upgraded-confidence ({len(corroborated)} corroborations)")

        score = _score_for(confidence, len(corroborated), len(contradicted))
        trace.insert(0, f"rule={rule.rule_id} -> {rule_target.value}")

        return ClassificationResult(
            crash_class=rule_target, confidence=confidence, score=score,
            rule_id=rule.rule_id, rationale=rationale,
            severity=severity_from_crash_class(rule_target),
            corroborated_by=corroborated, contradicted_by=contradicted,
            trace=trace,
        )

    @staticmethod
    def _preset_class(evidence: _Evidence) -> Optional[CrashClass]:
        try:
            return CrashClass.coerce(evidence.given_class)
        except Exception:
            return None


def _upgrade(confidence: Confidence) -> Confidence:
    ladder = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED]
    try:
        idx = ladder.index(confidence)
    except ValueError:
        return Confidence.MEDIUM
    return ladder[min(len(ladder) - 1, idx + 1)]


def _downgrade(confidence: Confidence) -> Confidence:
    ladder = [Confidence.CONFIRMED, Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]
    try:
        idx = ladder.index(confidence)
    except ValueError:
        return Confidence.MEDIUM
    return ladder[min(len(ladder) - 1, idx + 1)]


def _score_for(confidence: Confidence, corroborations: int, contradictions: int) -> float:
    base = {
        Confidence.UNKNOWN: 0.0, Confidence.LOW: 0.25, Confidence.MEDIUM: 0.5,
        Confidence.HIGH: 0.75, Confidence.CONFIRMED: 0.9,
    }.get(confidence, 0.4)
    value = base + 0.05 * max(0, corroborations - 1) - 0.15 * max(0, contradictions)
    return max(0.0, min(1.0, value))


# ============================================================================
# convenience functions
# ============================================================================

_DEFAULT_CLASSIFIER: Optional[CrashClassifier] = None
_DEFAULT_LOCK = threading.Lock()


def _default_classifier() -> CrashClassifier:
    global _DEFAULT_CLASSIFIER
    with _DEFAULT_LOCK:
        if _DEFAULT_CLASSIFIER is None:
            _DEFAULT_CLASSIFIER = CrashClassifier()
        return _DEFAULT_CLASSIFIER


def classify_text(text: str, **kw: Any) -> ClassificationResult:
    return _default_classifier().classify_text(text, **kw)


def classify_report(report: SanitizerReport, **kw: Any) -> ClassificationResult:
    return _default_classifier().classify_report(report, **kw)


# ============================================================================
# smoke test
# ============================================================================


def _smoke() -> int:
    from kmcs.analysis.crash_parser import GOLDEN_SAMPLES, CrashParser

    parser = CrashParser()
    classifier = CrashClassifier()
    expectations = {
        "asan_heap_overflow": CrashClass.HEAP_BUFFER_OVERFLOW,
        "asan_uaf": CrashClass.USE_AFTER_FREE,
        "lsan_direct": CrashClass.MEMORY_LEAK,
        "ubsan_overflow": CrashClass.INTEGER_OVERFLOW,
        "tsan_race": CrashClass.DATA_RACE,
        "msan_uninit": CrashClass.UNINITIALIZED_USE,
        "bare_segfault": CrashClass.SEGMENTATION_FAULT,
        "libfuzzer_oom": CrashClass.OUT_OF_MEMORY,
    }
    failures = 0
    for name, sample in GOLDEN_SAMPLES.items():
        outcome = parser.parse_text(sample)
        crash = outcome.primary
        if crash is None:
            print(f"  [FAIL] {name}: parser produced no crash")
            failures += 1
            continue
        result = classifier.classify_crash(crash, apply=False)
        want = expectations[name]
        ok = result.crash_class is want
        if not ok:
            failures += 1
        print(f"  [{'OK ' if ok else 'FAIL'}] {name}: {result.crash_class.value} "
              f"(want {want.value}) via {result.rule_id} conf={result.confidence.value} "
              f"score={result.score:.2f}")
    # custom ruleset loading
    loaded = RuleSet.from_dicts([{
        "rule_id": "demo:assert-text", "class": "assertion-failure",
        "when": {"contains": ["my_custom_assert"]},
        "confidence": "high", "priority": 950,
        "rationale": "project-specific assertion marker",
    }])
    res = CrashClassifier(ruleset=loaded).classify_text(
        "my_custom_assert fired here", sanitizer_hint="none")
    ok2 = res.crash_class is CrashClass.ASSERTION_FAILURE
    print(f"  [{'OK ' if ok2 else 'FAIL'}] custom-ruleset: {res.crash_class.value}")
    failures += 0 if ok2 else 1
    print(f"[kmcs.analysis.classifier] {len(GOLDEN_SAMPLES) + 1 - failures}/"
          f"{len(GOLDEN_SAMPLES) + 1} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
