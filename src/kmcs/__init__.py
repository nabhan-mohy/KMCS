"""
Keyless Memory-Corruption Scanner (KMCS)
========================================

**KMCS** is a *defensive* fuzzing and memory-safety research platform.  It
helps security researchers and developers discover crashes and potential
memory-safety problems in **authorised** C and C++ libraries and applications.

A researcher hands KMCS an authorised target plus a collection of valid input
files.  KMCS prepares the target for fuzzing, drives a real fuzzing engine
(AFL++, libFuzzer, Honggfuzz), monitors execution, detects crashes, collects
sanitizer diagnostics (ASan/UBSan/LSan), classifies and de-duplicates the
crashes, attempts reproduction and minimisation, and finally produces a
structured security finding and report.

KMCS orchestrates existing, well-established open-source tooling; it does not
replace AFL++, libFuzzer, Honggfuzz, AddressSanitizer, UndefinedBehaviorSanitizer,
GDB or LLVM utilities — it controls them and organises their output.

------------------------------------------------------------------------------
Security boundary (read carefully)
------------------------------------------------------------------------------

KMCS is a **defensive research tool**.  The application may perform:

* authorised fuzzing
* malformed-input generation *through legitimate fuzzing engines*
* crash detection and memory-safety analysis
* sanitizer-output analysis
* crash classification, fingerprinting and de-duplication
* crash reproduction and test-case minimisation
* regression testing and security reporting

The application must **never** implement:

* exploit generation or weaponisation
* shellcode generation
* automatic exploitation
* persistence mechanisms
* credential theft
* unauthorised scanning
* stealth / evasion mechanisms
* security-control bypasses

These prohibitions are enforced structurally: no such capability exists in the
code base, and requests for them raise
:class:`kmcs.core.exceptions.PolicyViolationError`.  The goal is to discover
and analyse vulnerabilities safely — never to turn them into working attacks.

Only fuzz software you own or have explicit written permission to test.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

__title__ = "Keyless Memory-Corruption Scanner"
__summary__ = (
    "Defensive fuzzing orchestration and memory-safety analysis platform for "
    "authorised C/C++ targets."
)
__author__ = "KMCS Research Team"
__license__ = "Apache-2.0"
__copyright__ = "Copyright (c) KMCS contributors"

#: Semantic version of the package.  Phase 1 delivers ``kmcs.core`` only.
__version__ = "0.1.0"
VERSION_TUPLE: Tuple[int, ...] = tuple(int(part) for part in __version__.split(".")[:3])

#: Identifier used throughout logs, reports and the SQLite database.
APP_ID = "kmcs"
APP_SLUG = "keyless-memory-corruption-scanner"

#: Current delivery phase (1..7).  ``core`` belongs to phase 1.
PHASE = 1
PHASE_NAME = "core-foundation"

#: Development phases as defined by the master specification.
PHASES: Dict[int, str] = {
    1: "core-foundation",
    2: "database-and-targets",
    3: "corpus-and-build-instrumentation",
    4: "fuzzing-engines",
    5: "sanitizers-and-crash-analysis",
    6: "campaigns-reproduction-reporting",
    7: "cli-gui-hardening",
}

#: Capabilities that KMCS implements (defensive analysis only).
PERMITTED_CAPABILITIES: Tuple[str, ...] = (
    "authorized_fuzzing",
    "malformed_input_generation_via_fuzzing_engines",
    "crash_detection",
    "memory_safety_analysis",
    "sanitizer_output_analysis",
    "crash_classification",
    "crash_fingerprinting",
    "crash_deduplication",
    "crash_reproduction",
    "test_case_minimization",
    "regression_testing",
    "security_reporting",
)

#: Capabilities KMCS deliberately refuses to provide.  Kept here so every other
#: layer can quote a single authoritative list when validating requests.
PROHIBITED_CAPABILITIES: Tuple[str, ...] = (
    "exploit_generation",
    "weaponization",
    "shellcode_generation",
    "automatic_exploitation",
    "persistence",
    "credential_theft",
    "unauthorized_scanning",
    "stealth_mechanisms",
    "security_control_bypass",
)

#: KMCS runs entirely offline and requires no credentials of any kind.
REQUIRES_NETWORK = False
REQUIRES_API_KEYS = False
REQUIRES_CREDENTIALS = False


def get_version() -> str:
    """Return the package version string."""
    return __version__


def version_tuple() -> Tuple[int, ...]:
    """Return the version as a tuple of integers for comparisons."""
    return VERSION_TUPLE


def is_compatible(required: str) -> bool:
    """Whether this installation satisfies a ``major.minor`` compatibility ask."""
    try:
        want_major, want_minor = (int(part) for part in required.split(".")[:2])
    except (TypeError, ValueError):
        return False
    have_major = VERSION_TUPLE[0]
    have_minor = VERSION_TUPLE[1] if len(VERSION_TUPLE) > 1 else 0
    if have_major != want_major:
        return have_major > want_major
    return have_minor >= want_minor


def capability_status(requested: str) -> Dict[str, Any]:
    """Classify a requested capability against the defensive-use charter.

    Returns a structured verdict rather than raising, so callers can decide how
    loudly to complain.  Prohibited requests are reported as ``refused`` with
    the reason; unknown requests are reported as ``planned``/``unknown``.
    """
    token = str(requested or "").strip().lower().replace(" ", "_").replace("-", "_")
    if token in PERMITTED_CAPABILITIES:
        return {"requested": token, "verdict": "permitted", "implemented": True, "reason": None}
    if token in PROHIBITED_CAPABILITIES:
        return {
            "requested": token,
            "verdict": "refused",
            "implemented": False,
            "reason": (
                "KMCS is a defensive research tool; offensive capabilities are "
                "intentionally absent from the code base."
            ),
        }
    return {"requested": token, "verdict": "unknown", "implemented": False, "reason": "not part of the KMCS feature set"}


def project_manifest() -> Dict[str, Any]:
    """Machine-readable description of the project (used by CLI/GUI/about boxes)."""
    return {
        "id": APP_ID,
        "slug": APP_SLUG,
        "title": __title__,
        "summary": __summary__,
        "version": __version__,
        "phase": PHASE,
        "phase_name": PHASE_NAME,
        "phases": dict(PHASES),
        "author": __author__,
        "license": __license__,
        "requires_network": REQUIRES_NETWORK,
        "requires_api_keys": REQUIRES_API_KEYS,
        "requires_credentials": REQUIRES_CREDENTIALS,
        "permitted_capabilities": list(PERMITTED_CAPABILITIES),
        "prohibited_capabilities": list(PROHIBITED_CAPABILITIES),
        "submodules_available": _available_submodules(),
    }


def _available_submodules() -> Dict[str, bool]:
    """Report which architectural sub-packages exist *for real*.

    Never claims functionality that has not been built yet — a core principle of
    the KMCS development plan.
    """
    import importlib

    candidates = (
        "core.config",
        "core.events",
        "core.jobs",
        "core.models",
        "core.exceptions",
        "database",
        "targets",
        "fuzzers",
        "sanitizers",
        "analysis",
        "corpus",
        "campaigns",
        "reproduction",
        "reporting",
        "cli",
        "gui",
    )
    result: Dict[str, bool] = {}
    for name in candidates:
        full = f"kmcs.{name}"
        try:
            importlib.import_module(full)
            result[name] = True
        except Exception:
            result[name] = False
    return result


__all__ = [
    "__title__",
    "__summary__",
    "__version__",
    "__author__",
    "__license__",
    "__copyright__",
    "VERSION_TUPLE",
    "APP_ID",
    "APP_SLUG",
    "PHASE",
    "PHASE_NAME",
    "PHASES",
    "PERMITTED_CAPABILITIES",
    "PROHIBITED_CAPABILITIES",
    "REQUIRES_NETWORK",
    "REQUIRES_API_KEYS",
    "REQUIRES_CREDENTIALS",
    "get_version",
    "version_tuple",
    "is_compatible",
    "capability_status",
    "project_manifest",
]
