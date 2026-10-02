"""KMCS fuzzing-engine adapters (Phase 4).

This package wraps *real* external fuzzing engines — AFL++, libFuzzer and
Honggfuzz — behind a single orchestration interface.  KMCS never simulates
fuzzing and never fabricates statistics: every number exposed by an adapter
was parsed from the engine's own output or measured around real process
execution.

Modules
-------
``base``        Shared abstractions: :class:`FuzzSession`, :class:`EngineStats`,
                :class:`EngineCapabilities`, the :class:`FuzzEvent` stream,
                crash/hang discovery, argv construction, resource limits and
                the :class:`FuzzEngineAdapter` lifecycle machinery.
``aflpp``       AFL++ (forkserver mode) adapter with fuzzer_stats parsing.
``libfuzzer``   libFuzzer (in-process, ``-runs``/``-max_total_time``) adapter
                that parses the engine's own textual stats output.
``honggfuzz``   Honggfuzz adapter with persistent-mode and pty support.

Design rules
------------
1. **Real processes only.**  Adapters launch engines via :mod:`subprocess`
   inside their own process group so a runaway campaign can be killed
   deterministically (``os.killpg``).
2. **Honest telemetry.**  If a statistic cannot be read from the engine it is
   reported as ``None``/absent — never guessed, never zero-filled silently.
3. **Defensive scope.**  Adapters refuse configurations that resemble
   exploitation or stealth (see :data:`kmcs.core.models.guard_capability`).
4. **No credentials, no network.**  Everything runs locally against
   user-supplied authorised binaries; no API keys are involved anywhere.
"""

from __future__ import annotations

from kmcs.fuzzers.base import (
    ArtifactKind,
    CrashArtifact,
    EngineCapabilities,
    EngineStats,
    FuzzEngineAdapter,
    FuzzEvent,
    FuzzEventType,
    FuzzLaunchSpec,
    FuzzSession,
    LaunchValidator,
    ResourceLimits,
    StatsSource,
    canonicalise_argv,
    discover_crash_artifacts,
    estimate_execs_per_sec,
    format_duration,
    make_session_directories,
    parse_int_token,
    resolve_engine_binary,
    tail_lines,
    validate_harness_for_engine,
    wait_for_process_exit,
)

__all__ = [
    "ArtifactKind",
    "CrashArtifact",
    "EngineCapabilities",
    "EngineStats",
    "FuzzEngineAdapter",
    "FuzzEvent",
    "FuzzEventType",
    "FuzzLaunchSpec",
    "FuzzSession",
    "LaunchValidator",
    "ResourceLimits",
    "StatsSource",
    "canonicalise_argv",
    "discover_crash_artifacts",
    "estimate_execs_per_sec",
    "format_duration",
    "make_session_directories",
    "parse_int_token",
    "resolve_engine_binary",
    "tail_lines",
    "validate_harness_for_engine",
    "wait_for_process_exit",
]
