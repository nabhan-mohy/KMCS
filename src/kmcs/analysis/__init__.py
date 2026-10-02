# =============================================================================
# kmcs.analysis -- crash analysis pipeline (Phase 5b)
# =============================================================================
"""
KMCS crash-analysis package.

This package implements the *analysis* stage of the KMCS pipeline::

    SANITIZER / CRASH DETECTION
        -> crash_parser     (raw log text  -> structured SanitizerReport/Crash)
        -> classifier       (report/log    -> CrashClass + confidence)
        -> fingerprint      (crash         -> stable dedup key)
        -> deduplicator     (fingerprints  -> unique findings, groups)
        -> severity         (crash+context-> Severity ladder position)

Design principles (enforced throughout):

1. **Honesty.**  Every field on an analysed crash is derived from *observed*
   sanitizer output.  Values that were not present in the input stay ``None``
   or ``unknown``; the pipeline never fabricates addresses, function names,
   counts or severities.  Parser coverage claims are computed from real
   samples via :func:`kmcs.analysis.crash_parser.self_test_report`.

2. **Defensive-only.**  Classification describes what the sanitizer observed
   (e.g. ``heap-buffer-overflow``).  Nothing in this package reasons about
   exploitability, weaponisation or bypasses.  Severity reflects *memory
   safety impact and reachability under sanitizers*, for triage purposes.

3. **Determinism.**  Fingerprinting uses only semantic attributes (target id,
   sanitizer, crash class, normalised stack identities, faulting location,
   access type).  Volatile data (PIDs, timestamps, absolute load addresses,
   allocation addresses) is deliberately excluded so re-runs and ASLR do not
   split one bug into many duplicates.

4. **No external services.**  Everything runs offline with the Python
   standard library plus the KMCS core.  No API keys, no network.

Public surface
--------------
``crash_parser``
    ``CrashParser``, ``ParseOutcome``, ``RawCrashRecord``,
    ``parse_crash_log``, ``detect_sanitizer_banner``, ``split_reports``,
    ``Symbolizer``, ``NullSymbolizer``, ``Addr2LineSymbolizer``,
    ``LLVMSymbolizer``, ``symbolizer_for_environment``

``classifier``
    ``CrashClassifier``, ``ClassificationResult``, ``ClassificationRule``,
    ``RuleSet``, ``default_rule_set``, ``classify_text``, ``classify_report``

``fingerprint``
    ``Fingerprinter``, ``FingerprintComponents``, ``fingerprint_report``,
    ``fingerprint_text``, ``similarity_digest``, ``hamming_distance``,
    ``cluster_fingerprints``

``deduplicator``
    ``Deduplicator``, ``DuplicateGroup``, ``DeduplicationResult``,
    ``InMemoryIndex``, ``DatabaseFingerprintIndex``, ``deduplicate_crashes``

``severity``
    ``SeverityAssessor``, ``SeverityFactors``, ``SeverityDecision``,
    ``assess_severity``, ``score_to_severity``, ``SEVERITY_ADJUSTMENTS``
"""

from __future__ import annotations

from .classifier import (
    ClassificationResult,
    ClassificationRule,
    CrashClassifier,
    RuleSet,
    classify_report,
    classify_text,
    default_rule_set,
)
from .crash_parser import (
    Addr2LineSymbolizer,
    CrashParser,
    LLVMSymbolizer,
    NullSymbolizer,
    ParseOutcome,
    RawCrashRecord,
    Symbolizer,
    detect_sanitizer_banner,
    parse_crash_log,
    symbolizer_for_environment,
)
from .deduplicator import (
    DatabaseFingerprintIndex,
    Deduplicator,
    DeduplicationResult,
    DuplicateGroup,
    InMemoryIndex,
    deduplicate_crashes,
)
from .fingerprint import (
    FingerprintComponents,
    Fingerprinter,
    cluster_fingerprints,
    fingerprint_report,
    fingerprint_text,
    hamming_distance,
    similarity_digest,
)
from .severity import (
    SEVERITY_ADJUSTMENTS,
    SeverityAssessor,
    SeverityDecision,
    SeverityFactors,
    assess_severity,
    score_to_severity,
)

__version__ = "0.1.0"
__all__ = [
    # crash_parser
    "CrashParser", "ParseOutcome", "RawCrashRecord", "detect_sanitizer_banner",
    "parse_crash_log", "Symbolizer", "NullSymbolizer", "Addr2LineSymbolizer",
    "LLVMSymbolizer", "symbolizer_for_environment",
    # classifier
    "CrashClassifier", "ClassificationResult", "ClassificationRule", "RuleSet",
    "default_rule_set", "classify_text", "classify_report",
    # fingerprint
    "Fingerprinter", "FingerprintComponents", "fingerprint_report",
    "fingerprint_text", "similarity_digest", "hamming_distance",
    "cluster_fingerprints",
    # deduplicator
    "Deduplicator", "DuplicateGroup", "DeduplicationResult", "InMemoryIndex",
    "DatabaseFingerprintIndex", "deduplicate_crashes",
    # severity
    "SeverityAssessor", "SeverityFactors", "SeverityDecision",
    "assess_severity", "score_to_severity", "SEVERITY_ADJUSTMENTS",
]
