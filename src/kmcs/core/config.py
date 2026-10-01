"""
KMCS configuration subsystem (Phase 1 — ``kmcs.core.config``)
=============================================================

Layered, validated, fully-offline configuration for the Keyless
Memory-Corruption Scanner.

Design goals
------------
* **No network, no API keys.**  Every value comes from one of four local
  layers, merged in ascending precedence:

      defaults  →  config file (JSON / TOML / INI)  →  environment (KMCS_*)
      →  explicit CLI/programmatic overrides

* **Validated at the boundary.**  All structures are Pydantic models with
  strict types, bounds and cross-field validators.  Invalid configuration
  never leaks into the runtime; it is reported as structured
  :class:`ValidationIssue` records instead.

* **Secret-safe.**  :class:`KmcsConfig.redacted` produces a copy in which
  every field whose name looks sensitive (token, password, secret, key…) is
  replaced by ``"***"`` before the config is serialised to logs or reports.
  KMCS itself requires *no* credentials; the redaction layer exists so that
  user environments which happen to contain secrets can never leak them.

* **Atomic persistence.**  :class:`ConfigManager.write` uses a temp-file +
  ``os.replace`` strategy so a crash mid-write can never corrupt the file.

Public surface (as re-exported by :mod:`kmcs.core`)
---------------------------------------------------
``ASAN_OPTIONS_DEFAULTS``, ``CampaignConfig``, ``ConfigManager``,
``ConfigResult``, ``ConfigSnapshot``, ``CorpusConfig``, ``CoverageConfig``,
``DEFAULT_CONFIG``, ``EngineKind``, ``EnvironmentProfile``, ``FuzzerConfig``,
``InstrumentationConfig``, ``KmcsConfig``, ``LSanOptions``,
``MinimizationConfig``, ``NotificationConfig``, ``PathsConfig``,
``PerformanceConfig``, ``ReproductionConfig``, ``ReportingConfig``,
``ResourceLimits``, ``RuntimeStatus``, ``SanitizerFlag``, ``SanitizersConfig``,
``TelemetryConfig``, ``UBSanOptions``, ``ValidationIssue``,
``VerificationReport``, ``WorkerConfig``, ``load_config``,
``resolve_environment``.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from kmcs.core.exceptions import ConfigurationError
from kmcs.core.models import EngineKind as _ModelEngineKind

# --------------------------------------------------------------------------- #
# Constants & small helpers
# --------------------------------------------------------------------------- #

__all__ = [
    "ASAN_OPTIONS_DEFAULTS",
    "CampaignConfig",
    "ConfigManager",
    "ConfigResult",
    "ConfigSnapshot",
    "CorpusConfig",
    "CoverageConfig",
    "DEFAULT_CONFIG",
    "EngineKind",
    "EnvironmentProfile",
    "FuzzerConfig",
    "InstrumentationConfig",
    "KmcsConfig",
    "LSanOptions",
    "MinimizationConfig",
    "NotificationConfig",
    "PathsConfig",
    "PerformanceConfig",
    "ReproductionConfig",
    "ReportingConfig",
    "ResourceLimits",
    "RuntimeStatus",
    "SanitizerFlag",
    "SanitizersConfig",
    "TelemetryConfig",
    "UBSanOptions",
    "ValidationIssue",
    "VerificationReport",
    "WorkerConfig",
    "load_config",
    "resolve_environment",
]

#: Environment-variable prefix reserved for KMCS overrides.
ENV_PREFIX = "KMCS_"

#: Substrings that mark a field name as sensitive (used for redaction).
_SENSITIVE_NAME_PARTS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "credential", "private_key", "auth", "session", "cookie",
)

_REDACTION_MASK = "***REDACTED***"

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?)b?\s*$", re.IGNORECASE)
_SIZE_UNITS = {
    "": 1, "b": 1,
    "k": 1024, "ki": 1024, "kb": 1024,
    "m": 1024**2, "mi": 1024**2, "mb": 1024**2,
    "g": 1024**3, "gi": 1024**3, "gb": 1024**3,
    "t": 1024**4, "ti": 1024**4, "tb": 1024**4,
}


def parse_size(value: Union[str, int, float]) -> int:
    """Parse human sizes like ``"512M"``, ``"2 GiB"``, ``1024`` into bytes."""
    if isinstance(value, (int, float)):
        n = int(value)
        if n < 0:
            raise ValueError("size must be non-negative")
        return n
    m = _SIZE_RE.match(str(value))
    if not m:
        raise ValueError(f"unparseable size: {value!r}")
    number, unit = float(m.group(1)), m.group(2).lower()
    return int(number * _SIZE_UNITS.get(unit, 1))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(part in lowered for part in _SENSITIVE_NAME_PARTS)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #

class EngineKind(str, Enum):
    """Fuzzing engine selection at the *configuration* layer.

    Kept intentionally aligned with :class:`kmcs.core.models.EngineKind` but
    declared separately so the config module owns its own vocabulary and can
    evolve validation rules without touching the domain model.
    """

    AFLPP = "aflpp"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"
    CUSTOM = "custom"

    # -- interop with the domain model -------------------------------------
    def to_model(self) -> _ModelEngineKind:
        return _ModelEngineKind(self.value)

    @classmethod
    def from_model(cls, kind: _ModelEngineKind) -> "EngineKind":
        return cls(kind.value)

    @property
    def binary_candidates(self) -> Tuple[str, ...]:
        return {
            EngineKind.AFLPP: ("afl-fuzz", "afl++"),
            EngineKind.LIBFUZZER: (),          # linked into the target
            EngineKind.HONGGFUZZ: ("honggfuzz",),
            EngineKind.CUSTOM: (),
        }[self]


class RuntimeStatus(str, Enum):
    """Lifecycle states surfaced by :class:`ConfigManager.status`."""

    UNINITIALISED = "uninitialised"
    LOADED = "loaded"
    VALID = "valid"
    INVALID = "invalid"
    STALE = "stale"
    WRITE_PENDING = "write_pending"


# --------------------------------------------------------------------------- #
# Validation reporting structures
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ValidationIssue:
    """A single structured configuration problem.

    ``location`` uses dotted-path notation rooted at the config document,
    e.g. ``"fuzzers.aflpp.deterministic"`` — never Python attribute names, so
    the same vocabulary works for files, env vars and CLI overrides.
    """

    location: str
    message: str
    kind: str = "error"                  # "error" | "warning" | "info"
    expected: Optional[str] = None
    actual: Optional[str] = None
    source_layer: str = "unknown"        # default|file|environment|override
    remediation: Optional[str] = None

    def __post_init__(self) -> None:
        if self.kind not in ("error", "warning", "info"):
            raise ValueError(f"bad issue kind {self.kind!r}")

    @property
    def is_error(self) -> bool:
        return self.kind == "error"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location,
            "message": self.message,
            "kind": self.kind,
            "expected": self.expected,
            "actual": self.actual,
            "source_layer": self.source_layer,
            "remediation": self.remediation,
        }

    def format(self) -> str:
        bits = [f"[{self.kind.upper()}] {self.location}: {self.message}"]
        if self.expected is not None:
            bits.append(f"  expected: {self.expected}")
        if self.actual is not None:
            bits.append(f"  actual:   {self.actual}")
        if self.source_layer != "unknown":
            bits.append(f"  layer:    {self.source_layer}")
        if self.remediation:
            bits.append(f"  fix:      {self.remediation}")
        return "\n".join(bits)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.format()


@dataclass(frozen=True)
class VerificationReport:
    """Aggregate result of validating a candidate configuration document."""

    ok: bool
    issues: Tuple[ValidationIssue, ...] = ()
    checked_at: datetime = field(default_factory=_utcnow)
    layers: Tuple[str, ...] = ()

    @property
    def errors(self) -> Tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if i.kind == "error")

    @property
    def warnings(self) -> Tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if i.kind == "warning")

    def summary(self) -> str:
        return (
            f"verification {'PASSED' if self.ok else 'FAILED'}: "
            f"{len(self.errors)} error(s), {len(self.warnings)} warning(s)"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "summary": self.summary(),
            "layers": list(self.layers),
            "checked_at": self.checked_at.isoformat(),
            "issues": [i.to_dict() for i in self.issues],
        }


@dataclass(frozen=True)
class ConfigResult:
    """Outcome of :func:`load_config` — either a good config or issues."""

    config: Optional["KmcsConfig"]
    report: VerificationReport
    raw_merged: Mapping[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.report.ok and self.config is not None

    def raise_if_invalid(self) -> "KmcsConfig":
        if self.config is None or not self.report.ok:
            raise ConfigurationError(
                "configuration is invalid",
                context={
                    "issues": [i.to_dict() for i in self.report.errors],
                    "layers": list(self.report.layers),
                },
            )
        return self.config


@dataclass(frozen=True)
class ConfigSnapshot:
    """Immutable point-in-time view of a managed configuration."""

    revision: int
    digest: str
    created_at: datetime
    payload: Mapping[str, Any]           # already redacted
    source_layers: Tuple[str, ...] = ()
    label: str = ""

    def matches_head(self, head: "ConfigSnapshot") -> bool:
        return head.digest == self.digest and head.revision >= self.revision


# --------------------------------------------------------------------------- #
# Base model
# --------------------------------------------------------------------------- #

class _Section(BaseModel):
    """Common base for every config section.

    ``extra="forbid"`` means typos in a user config file become structured
    validation issues rather than silently ignored keys.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        frozen=False,
        str_strip_whitespace=True,
    )

    def redacted(self) -> Dict[str, Any]:
        """Return a JSON-safe dict with sensitive-looking values masked."""
        return _redact_mapping(self.model_dump(mode="json"))


def _redact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _redact_mapping(value)
    if isinstance(value, (list, tuple, set)):
        return [_redact_value(v) for v in value]
    return value


def _redact_mapping(mapping: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in mapping.items():
        if _is_sensitive_name(str(key)):
            out[str(key)] = _REDACTION_MASK
        else:
            out[str(key)] = _redact_value(value)
    return out


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

class PathsConfig(_Section):
    """Filesystem layout used by KMCS. Everything lives under ``home``."""

    home: Path = Field(
        default_factory=lambda: Path.home() / ".kmcs",
        description="Root directory for all KMCS state.",
    )
    workdir: Path = Field(default_factory=lambda: Path("work"))
    corpus: Path = Field(default_factory=lambda: Path("corpus"))
    crashes: Path = Field(default_factory=lambda: Path("crashes"))
    findings: Path = Field(default_factory=lambda: Path("findings"))
    reports: Path = Field(default_factory=lambda: Path("reports"))
    logs: Path = Field(default_factory=lambda: Path("logs"))
    cache: Path = Field(default_factory=lambda: Path("cache"))
    tmp: Path = Field(default_factory=lambda: Path("tmp"))
    database: Path = Field(default_factory=lambda: Path("kmcs.db"))
    create_missing: bool = Field(
        default=True, description="Create directories lazily when requested."
    )

    @model_validator(mode="after")
    def _validate(self) -> "PathsConfig":
        if str(self.home).strip() == "":
            raise ValueError("paths.home must not be empty")
        return self

    # -- resolution --------------------------------------------------------
    def resolve(self, relative: Union[str, Path]) -> Path:
        """Resolve *relative* against :attr:`home`.

        Absolute paths pass through unchanged (useful for corpora that live
        inside a victim project tree).
        """
        p = Path(relative)
        return p if p.is_absolute() else (self.home / p)

    def ensure(self) -> List[Path]:
        """Create every managed directory (idempotent); return their paths."""
        made: List[Path] = []
        for attr in ("home", "workdir", "corpus", "crashes", "findings",
                     "reports", "logs", "cache", "tmp"):
            path = self.resolve(getattr(self, attr))
            path.mkdir(parents=True, exist_ok=True)
            made.append(path)
        db_path = self.resolve(self.database)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        made.append(db_path.parent)
        return made

    def database_url(self) -> str:
        """SQLite URL for the future :mod:`kmcs.database` package."""
        return f"sqlite:///{self.resolve(self.database).as_posix()}"


# --------------------------------------------------------------------------- #
# Performance / resources
# --------------------------------------------------------------------------- #

class ResourceLimits(_Section):
    """Per-process ceilings handed to fuzzers and reproduction runners.

    These are *defensive* limits: they keep an authorised fuzzing campaign
    from exhausting the research host.  They are enforced via rlimits in the
    jobs engine (Phase 1 ships the plumbing; workers apply them for real).
    """

    cpu_time_seconds: int = Field(default=600, ge=1, le=86_400,
                                 description="RLIMIT_CPU per target execution.")
    address_space_bytes: int = Field(default=8 * 1024**3, ge=64 * 1024**2,
                                     description="RLIMIT_AS ceiling.")
    file_size_bytes: int = Field(default=1024**3, ge=1024,
                                 description="RLIMIT_FSIZE ceiling.")
    max_open_files: int = Field(default=4096, ge=64, le=524_288)
    max_processes: int = Field(default=512, ge=8, le=65_536,
                               description="RLIMIT_NPROC (fork-bomb guard).")
    stack_bytes: int = Field(default=64 * 1024**2, ge=1024**2)
    core_dumps: bool = Field(default=True,
                             description="Allow core dumps for post-mortem GDB.")
    wall_timeout_seconds: float = Field(default=30.0, gt=0, le=86_400,
                                        description="Watchdog kill for one exec.")
    hang_threshold_seconds: float = Field(default=20.0, gt=0, le=86_400)

    @model_validator(mode="after")
    def _coherent(self) -> "ResourceLimits":
        if self.wall_timeout_seconds > self.cpu_time_seconds * 4:
            raise ValueError(
                "wall_timeout_seconds is wildly larger than cpu_time_seconds; "
                "the CPU limit would never engage meaningfully"
            )
        if self.hang_threshold_seconds >= self.wall_timeout_seconds:
            raise ValueError(
                "hang_threshold_seconds must be below wall_timeout_seconds so "
                "hangs are classified before the hard watchdog fires"
            )
        return self

    def as_address_space_str(self) -> str:
        return f"{self.address_space_bytes // (1024 ** 3)}G"


class PerformanceConfig(_Section):
    """Throughput tuning knobs for campaigns and analysis passes."""

    parallel_workers: int = Field(default=4, ge=1, le=256)
    batch_size: int = Field(default=256, ge=1, le=1_000_000)
    queue_max_items: int = Field(default=100_000, ge=16)
    event_queue_max: int = Field(default=50_000, ge=128,
                                description="Bounded event bus replay buffer.")
    dedup_cache_entries: int = Field(default=10_000, ge=0, le=1_000_000)
    fingerprint_cache_ttl_seconds: int = Field(default=3600, ge=0)
    io_chunk_bytes: int = Field(default=1 << 20, ge=1024, le=1 << 26)
    throttle_ms: int = Field(default=0, ge=0, le=60_000)
    snapshot_interval_seconds: float = Field(default=10.0, gt=0, le=3600)

    @model_validator(mode="after")
    def _coherent(self) -> "PerformanceConfig":
        if self.parallel_workers > 64 and self.batch_size < 64:
            raise ValueError(
                "large worker pools need batch_size >= 64 to amortise dispatch"
            )
        return self


# --------------------------------------------------------------------------- #
# Instrumentation / sanitizers
# --------------------------------------------------------------------------- #

class InstrumentationConfig(_Section):
    """Compiler instrumentation selection for building targets."""

    coverage: bool = Field(default=True,
                           description="-fprofile-instr-generate/-fsanitize-coverage")
    sanitisers_enabled: bool = Field(default=True,
                                     description="Compile with ASan et al.")
    afl_llvm_mode: str = Field(
        default="lto", pattern=r"^(classical|lto|never)$",
        description="AFL instrumentation mode passed to afl-clang-lto etc.",
    )
    additional_cflags: List[str] = Field(default_factory=list)
    additional_cxxflags: List[str] = Field(default_factory=list)
    additional_ldflags: List[str] = Field(default_factory=list)
    debug_info: bool = Field(default=True,
                             description="-g keeps symbols for crash analysis.")
    optimisation: str = Field(default="g", pattern=r"^[0-3sg]$")
    link_static_asan: bool = Field(
        default=False, description="Static ASan runtime for portability.")

    @model_validator(mode="after")
    def _no_optimise_when_debug(self) -> "InstrumentationConfig":
        if self.sanitisers_enabled and self.optimisation not in ("g", "0", "1"):
            raise ValueError(
                "sanitiser builds should use -O0/-O1/-Og; -O2+ hides bugs and "
                "produces misleading frames"
            )
        return self


class SanitizerFlag(_Section):
    """A single ``name=value`` option pair for a sanitizer runtime."""

    name: str = Field(min_length=1, max_length=64,
                      pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    value: str = Field(default="1", max_length=256)

    def render(self) -> str:
        return f"{self.name}={self.value}"


#: Canonical ASan runtime options for defensive fuzzing.  Exported because the
#: fuzzers/ packages will merge engine-specific additions on top of this.
ASAN_OPTIONS_DEFAULTS: Dict[str, str] = {
    "abort_on_error": "1",               # SIGABRT → catchable by AFL++
    "detect_leaks": "1",
    "detect_stack_use_after_return": "1",
    "strict_string_checks": "1",
    "check_initialization_order": "1",
    "dump_instruction_bytes": "1",
    "print_stats": "0",
    "allocator_may_return_null": "1",    # OOM is not a finding; don't fake it
    "handle_segv": "1",
    "handle_sigbus": "1",
    "handle_abort": "1",
    "handle_sigill": "1",
    "handle_sigfpe": "1",
    "symbolize": "1",
    "fast_unwind_on_fatal": "0",         # accurate stacks beat speed here
    "malloc_context_size": "30",
    "log_path": "",                      # filled in per-campaign at runtime
    "exitcode": "1",
    "verbosity": "0",
    "color": "0",
}


class UBSanOptions(_Section):
    enabled: bool = True
    halt_on_error: bool = False          # collect many UB kinds per run
    print_stacktrace: bool = True
    log_path: str = ""
    suppressions: str = ""
    check_function_alignment: bool = True
    disable_cfi_check_icall: bool = False
    extra_flags: List[SanitizerFlag] = Field(default_factory=list)

    def to_env(self) -> Dict[str, str]:
        env = {
            "UBSAN_OPTIONS": ":".join(filter(None, [
                f"halt_on_error={int(self.halt_on_error)}",
                f"print_stacktrace={int(self.print_stacktrace)}",
                f"log_path={self.log_path}" if self.log_path else "",
                f"suppressions={self.suppressions}" if self.suppressions else "",
            ]))
        }
        for flag in self.extra_flags:
            env[flag.name] = flag.value
        return env


class LSanOptions(_Section):
    enabled: bool = True
    detect_leaks: bool = True
    use_ld_preload: bool = False
    leak_check: str = Field(default="1", pattern=r"^[012]$")
    max_leaks: int = Field(default=100, ge=0)
    suppressions: str = ""
    report_objects: bool = False
    extra_flags: List[SanitizerFlag] = Field(default_factory=list)

    def to_env(self) -> Dict[str, str]:
        parts = [f"detect_leaks={int(self.detect_leaks)}",
                 f"max_leaks={self.max_leaks}"]
        if self.suppressions:
            parts.append(f"use_ld_preload={int(self.use_ld_preload)}")
        return {"LSAN_OPTIONS": ":".join(parts)}


class SanitizersConfig(_Section):
    """Which memory-safety detectors are compiled in and how they behave."""

    address: bool = Field(default=True, description="AddressSanitizer.")
    undefined: bool = Field(default=True, description="UndefinedBehaviorSanitizer.")
    leak: bool = Field(default=True, description="LeakSanitizer (via ASan).")
    memory: bool = Field(default=False, description="MemorySanitizer (needs MSan build).")
    thread: bool = Field(default=False, description="ThreadSanitizer (incompatible w/ ASan).")
    hardware: bool = Field(default=False, description="HWASan where supported.")

    asan_options: Dict[str, str] = Field(
        default_factory=lambda: dict(ASAN_OPTIONS_DEFAULTS))
    ubsan: UBSanOptions = Field(default_factory=UBSanOptions)
    lsan: LSanOptions = Field(default_factory=LSanOptions)

    @model_validator(mode="after")
    def _mutual_exclusion(self) -> "SanitizersConfig":
        conflicts: List[str] = []
        if self.address and self.memory:
            conflicts.append("address+memory (ASan and MSan cannot share a build)")
        if self.address and self.thread:
            conflicts.append("address+thread (ASan and TSan cannot share a build)")
        if self.memory and self.thread:
            conflicts.append("memory+thread (MSan and TSan cannot share a build)")
        if self.leak and self.memory:
            conflicts.append("leak+memory (LSan is incompatible with MSan)")
        if conflicts:
            raise ValueError(
                "incompatible sanitizer combination(s): " + "; ".join(conflicts)
            )
        if not (self.address or self.undefined or self.memory or self.thread):
            raise ValueError(
                "at least one memory/behaviour sanitizer must stay enabled — "
                "KMCS without sanitizers is just a fuzzer wrapper"
            )
        if self.asan_options.get("detect_leaks") == "0" and self.leak:
            raise ValueError(
                "sanitizers.leak is true but ASAN_OPTIONS detect_leaks=0 "
                "disables it at runtime — pick one"
            )
        return self

    # -- compile/link flag generation --------------------------------------
    def compile_flags(self) -> List[str]:
        flags: List[str] = []
        if self.address:
            flags.append("-fsanitize=address")
        if self.undefined:
            flags.append("-fsanitize=undefined")
        if self.memory:
            flags.append("-fsanitize=memory")
        if self.thread:
            flags.append("-fsanitize=thread")
        if self.hardware:
            flags.append("-fsanitize=hwaddress")
        if self.address:
            flags.append("-fno-omit-frame-pointer")
        return flags

    def asan_env(self, log_prefix: Optional[str] = None) -> Dict[str, str]:
        opts = dict(self.asan_options)
        if log_prefix:
            opts["log_path"] = str(log_prefix)
        if not self.leak:
            opts["detect_leaks"] = "0"
        rendered = ":".join(f"{k}={v}" for k, v in sorted(opts.items()) if v != "")
        env = {"ASAN_OPTIONS": rendered}
        env.update(self.ubsan.to_env())
        env.update(self.lsan.to_env())
        return env

    def active_kinds(self) -> List[str]:
        out = []
        for name, on in (
            ("address", self.address), ("undefined", self.undefined),
            ("leak", self.leak), ("memory", self.memory),
            ("thread", self.thread), ("hardware", self.hardware),
        ):
            if on:
                out.append(name)
        return out


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #

class CoverageConfig(_Section):
    """Coverage collection & merging (source-based / PCGUARD counters)."""

    enabled: bool = True
    metric: str = Field(default="edge", pattern=r"^(edge|pc|bb|func|src)$")
    dump_interval_seconds: int = Field(default=60, ge=5, le=3600)
    keep_raw_dumps: bool = Field(default=False)
    demangle: bool = Field(default=True)
    ignore_regex: List[str] = Field(
        default_factory=lambda: [r"^/usr/", r"libicu", r"\.so(\.|$)"])
    llvm_profdata: str = Field(default="llvm-profdata",
                               description="Binary used to merge .profraw files.")
    llvm_cov: str = Field(default="llvm-cov",
                          description="Binary used to render coverage reports.")
    export_html: bool = Field(default=True)

    @model_validator(mode="after")
    def _binaries(self) -> "CoverageConfig":
        if self.enabled and self.metric == "src" and not self.llvm_profdata:
            raise ValueError("source-based coverage requires llvm_profdata")
        return self


# --------------------------------------------------------------------------- #
# Fuzzer sections
# --------------------------------------------------------------------------- #

class _FuzzerBase(_Section):
    """Fields shared by every engine binding."""

    enabled: bool = True
    timeout_ms: int = Field(default=1000, ge=10, le=1_200_000)
    mem_limit_mb: int = Field(default=2048, ge=16, le=262_144)
    dictionary_file: str = Field(default="",
                                 description="Optional keyword dictionary path.")
    inputs_extension: str = Field(default="", max_length=16)
    extra_args: List[str] = Field(default_factory=list)
    resume: bool = True

    @model_validator(mode="after")
    def _args_safe(self) -> "_FuzzerBase":
        for arg in self.extra_args:
            if "\x00" in arg:
                raise ValueError("NUL byte in extra_args")
        return self


class AFLPPConfig(_FuzzerBase):
    """Binding for the American Fuzzy Loop ++ engine (afl-fuzz)."""

    binary: str = Field(default="afl-fuzz")
    persistent_mode: bool = Field(default=True,
                                  description="LLVM persistent tracing when harness supports it.")
    cmplog: bool = Field(default=True, description="MOpt style cmplog (-c).")
    python_mutator: str = Field(default="", description="optional custom_mutator.so/py")
    schedule: str = Field(default="explore",
                          pattern=r"^(explore|exploit/fast|exploit/slow|lin|quad|ecl|"
                                  r"pex/explore|pex/exploit|rare|rare/explore|"
                                  r"mo/honggfuzz|mo/cowboy|mo/quicksand)$")
    forkserver: bool = Field(default=True)
    shmem_count: int = Field(default=1, ge=1, le=1024)
    bind_cores: str = Field(default="", description="CPU affinity spec, e.g. '0-3'.")
    ui: bool = Field(default=False, description="False → -Q/-V style quiet runs.")
    stat_file: str = Field(default="fuzzer_stats")

    def command_prefix(self) -> List[str]:
        cmd = [self.binary]
        if self.cmplog:
            cmd.append("-c")
        if self.persistent_mode:
            cmd.append("-M")  # master marker; workers omit it
        return cmd


class LibFuzzerConfig(_FuzzerBase):
    """Binding for libFuzzer (driver-style, in-process)."""

    driver_binary: str = Field(default="",
                               description="Instrumented target acting as driver.")
    runs: int = Field(default=0, ge=0, description="0 = unbounded.")
    max_total_time: int = Field(default=0, ge=0)
    max_len: int = Field(default=65_536, ge=1, le=1 << 24)
    min_len: int = Field(default=1, ge=0)
    rss_limit_mb: int = Field(default=2048, ge=16)
    detect_leaks: bool = True
    artifact_prefix: str = Field(default="crash-", max_length=64)
    dict_file: str = ""
    only_ascii: bool = False
    cross_over_prob: int = Field(default=0, ge=0, le=100)
    mutate_depth: int = Field(default=0, ge=0)

    def libfuzzer_args(self) -> List[str]:
        args: List[str] = []
        if self.runs:
            args.append(f"-runs={self.runs}")
        if self.max_total_time:
            args.append(f"-max_total_time={self.max_total_time}")
        args.append(f"-max_len={self.max_len}")
        if self.min_len:
            args.append(f"-min_len={self.min_len}")
        args.append(f"-rss_limit_mb={self.rss_limit_mb}")
        args.append(f"-detect_leaks={int(self.detect_leaks)}")
        if self.artifact_prefix:
            args.append(f"-artifact_prefix={self.artifact_prefix}")
        if self.only_ascii:
            args.append("-only_ascii=1")
        if self.cross_over_prob:
            args.append(f"-cross_over_probability={self.cross_over_prob}")
        if self.mutate_depth:
            args.append(f"-mutate_depth={self.mutate_depth}")
        args.extend(self.extra_args)
        return args


class HonggfuzzConfig(_FuzzerBase):
    """Binding for Honggfuzz (secondary engine)."""

    binary: str = Field(default="honggfuzz")
    threads: int = Field(default=4, ge=1, le=256)
    mutation_rate: int = Field(default=55, ge=0, le=100)
    monitor_signal: bool = Field(default=True)
    sandbox: str = Field(default="linux", pattern=r"^(linux|macos|none)$")
    keep_output: bool = Field(default=False,
                              description="Retain honggfuzz output dir contents.")


class FuzzerConfig(_Section):
    """Container selecting and configuring fuzzing engines."""

    engine: EngineKind = Field(default=EngineKind.AFLPP)
    aflpp: AFLPPConfig = Field(default_factory=AFLPPConfig)
    libfuzzer: LibFuzzerConfig = Field(default_factory=LibFuzzerConfig)
    honggfuzz: HonggfuzzConfig = Field(default_factory=HonggfuzzConfig)
    campaign_wallclock_seconds: int = Field(
        default=86_400, ge=60, le=30 * 86_400,
        description="Hard stop for one campaign regardless of engine state.")
    restart_on_hang: bool = True
    crash_time_budget_s: float = Field(default=5.0, gt=0, le=600)

    @model_validator(mode="after")
    def _engine_present(self) -> "FuzzerConfig":
        section = {
            EngineKind.AFLPP: self.aflpp,
            EngineKind.LIBFUZZER: self.libfuzzer,
            EngineKind.HONGGFUZZ: self.honggfuzz,
        }.get(self.engine)
        if section is not None and not section.enabled:
            raise ValueError(
                f"fuzzers.engine={self.engine.value} selected but its section "
                f"is disabled"
            )
        return self

    def active(self) -> _FuzzerBase:
        return {
            EngineKind.AFLPP: self.aflpp,
            EngineKind.LIBFUZZER: self.libfuzzer,
            EngineKind.HONGGFUZZ: self.honggfuzz,
            EngineKind.CUSTOM: self.aflpp,
        }[self.engine]


# --------------------------------------------------------------------------- #
# Corpus / campaign / worker / minimization / reproduction
# --------------------------------------------------------------------------- #

class CorpusConfig(_Section):
    """Seed corpus handling."""

    initial_seeds: List[Path] = Field(default_factory=list)
    minimize_on_import: bool = True
    dedupe_imports: bool = Field(default=True,
                                 description="Hash-dedupe seeds at import time.")
    max_seed_files: int = Field(default=100_000, ge=1, le=10_000_000)
    max_seed_bytes: int = Field(default=16 * 1024**2, ge=1, le=1 << 30)
    follow_symlinks: bool = Field(default=False,
                                  description="Symlink escape is a footgun; off by default.")
    prune_interval_seconds: int = Field(default=900, ge=0)
    archive_retention_days: int = Field(default=30, ge=0, le=3650)
    magic_allowlist: List[str] = Field(
        default_factory=list,
        description="Optional libmagic types; empty = accept anything.")

    @model_validator(mode="after")
    def _seeds_exist_shape(self) -> "CorpusConfig":
        for seed in self.initial_seeds:
            if str(seed).startswith("~"):
                raise ValueError(f"seed path not expanded: {seed}")
        return self


class WorkerConfig(_Section):
    """One fuzzing worker slot."""

    id: str = Field(default="w0", pattern=r"^[A-Za-z0-9._-]{1,32}$")
    role: str = Field(default="fuzzer", pattern=r"^(fuzzer|explorer|minimizer|replay)$")
    cores: str = Field(default="", description="Affinity, e.g. '2,3'.")
    instance_count: int = Field(default=1, ge=1, le=64)
    memory_soft_limit_mb: int = Field(default=4096, ge=64)
    restart_after_execs: int = Field(default=0, ge=0,
                                     description="0 = never; periodic recycle guard.")
    heartbeat_seconds: float = Field(default=5.0, gt=0, le=300)


class CampaignConfig(_Section):
    """Parameters describing one end-to-end fuzzing campaign."""

    name: str = Field(default="campaign", pattern=r"^[A-Za-z0-9._-]{1,64}$")
    duration_seconds: int = Field(default=3600, ge=10, le=30 * 86_400)
    target_binary: str = Field(default="", description="Absolute path or PATH name.")
    arguments: List[str] = Field(default_factory=list)
    use_file_input: bool = Field(default=True,
                                 description="@@ substitution vs stdin.")
    workers: List[WorkerConfig] = Field(default_factory=lambda: [WorkerConfig()])
    auto_dedup: bool = True
    auto_reproduce: bool = True
    auto_minimize: bool = True
    stop_on_first_crash: bool = False
    triage_severity_floor: str = Field(
        default="low", pattern=r"^(critical|high|medium|low|informational|none)$")
    continue_after_crash: bool = True

    @model_validator(mode="after")
    def _unique_workers(self) -> "CampaignConfig":
        ids = [w.id for w in self.workers]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate worker ids: {ids}")
        if not self.workers:
            raise ValueError("a campaign needs at least one worker")
        return self


class MinimizationConfig(_Section):
    """Test-case reduction (ddmin-style) settings."""

    enabled: bool = True
    algorithm: str = Field(default="ddmin", pattern=r"^(ddmin|hmuа|greedy|binary)$")
    max_iterations: int = Field(default=2000, ge=1, le=1_000_000)
    min_size_bytes: int = Field(default=1, ge=0)
    preserve_validity: bool = Field(
        default=True, description="Only keep reductions that still trigger the bug.")
    timeout_per_try_seconds: float = Field(default=10.0, gt=0, le=600)
    parallel_trials: int = Field(default=4, ge=1, le=64)
    cache_decisions: bool = True


class ReproductionConfig(_Section):
    """Crash reproduction policy."""

    enabled: bool = True
    attempts: int = Field(default=5, ge=1, le=100)
    delay_ms: int = Field(default=100, ge=0, le=60_000)
    require_identical_fingerprint: bool = True
    compare_sanitizer_output: bool = True
    flaky_threshold: float = Field(default=0.2, ge=0.0, le=1.0,
                                   description="Max failure ratio before 'flaky'.")
    gdb_batch: bool = Field(default=True,
                            description="Run GDB in -batch mode (never interactive).")
    symbolize: bool = True
    save_core: bool = True


# --------------------------------------------------------------------------- #
# Reporting / telemetry / notifications
# --------------------------------------------------------------------------- #

class ReportingConfig(_Section):
    formats: List[str] = Field(
        default_factory=lambda: ["json", "markdown", "html"],
        description="Subset of {json, markdown, html, csv, sarif}.")
    output_dir: Path = Field(default_factory=lambda: Path("reports"))
    include_full_stacks: bool = True
    include_sanitizer_log: bool = True
    include_repro_commands: bool = Field(
        default=True,
        description="Include *reproduction* commands (defensive: rerun the "
                    "crashing input under the sanitized binary). Never exploit "
                    "material.")
    anonymise_paths: bool = Field(
        default=False, description="Strip $HOME prefixes from paths in exports.")
    max_stack_frames: int = Field(default=64, ge=1, le=1024)
    template_dir: Optional[Path] = None
    timestamp_files: bool = True

    @model_validator(mode="after")
    def _formats(self) -> "ReportingConfig":
        allowed = {"json", "markdown", "html", "csv", "sarif"}
        bad = [f for f in self.formats if f not in allowed]
        if bad:
            raise ValueError(f"unknown report format(s) {bad}; allowed {sorted(allowed)}")
        if not self.formats:
            raise ValueError("at least one report format required")
        return self


class TelemetryConfig(_Section):
    """Event-bus / metrics plumbing configuration."""

    enabled: bool = True
    sample_interval_seconds: float = Field(default=5.0, gt=0, le=3600)
    buffer_events: int = Field(default=10_000, ge=0, le=1_000_000)
    persist_events: bool = Field(default=False,
                                 description="Append JSON-lines event log.")
    events_path: Path = Field(default_factory=lambda: Path("logs/events.jsonl"))
    topics: List[str] = Field(
        default_factory=lambda: ["kmcs.#"],
        description="Subscription globs for the persisted sink.")
    flush_interval_seconds: float = Field(default=2.0, gt=0, le=600)
    drop_on_backpressure: bool = Field(
        default=True, description="Prefer dropping telemetry over stalling fuzzing.")


class NotificationConfig(_Section):
    """Local-only notifications. NO remote webhooks — KMCS stays offline."""

    enabled: bool = True
    desktop: bool = Field(default=True, description="Best-effort local popup.")
    syslog: bool = Field(default=False)
    file: Path = Field(default_factory=lambda: Path("logs/notifications.log"))
    min_severity: str = Field(
        default="medium", pattern=r"^(critical|high|medium|low|info)$")
    cooldown_seconds: int = Field(default=60, ge=0, le=86_400)

    @model_validator(mode="after")
    def _local_only(self) -> "NotificationConfig":
        # Defensive charter: reject any attempt to configure exfiltration-ish
        # channels even though no such fields exist (belt and braces).
        forbidden = {"webhook", "email", "slack", "telegram", "http", "url"}
        dumped = {k.lower() for k in type(self).model_fields}
        leaked = forbidden & dumped
        if leaked:
            raise ValueError(f"remote notification channels are prohibited: {leaked}")
        return self


# --------------------------------------------------------------------------- #
# Environment profile
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class EnvironmentProfile:
    """Detected host/toolchain facts. Produced by probing — never invented."""

    hostname: str
    platform: str
    python_version: str
    cpu_count: int
    total_memory_bytes: int
    kernel: str
    toolchain: Dict[str, Optional[str]]     # name -> version string or None
    writable_home: bool
    detected_at: datetime
    notes: Tuple[str, ...] = ()

    def missing_tools(self, required: Iterable[str]) -> List[str]:
        have = self.toolchain
        return [t for t in required if not have.get(t)]

    def to_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d["detected_at"] = self.detected_at.isoformat()
        d["toolchain"] = dict(self.toolchain)
        d["notes"] = list(self.notes)
        return d


_TOOLS_PROBED = (
    "gcc", "g++", "clang", "clang++", "afl-fuzz", "afl-clang-lto",
    "afl-clang-fast", "honggfuzz", "gdb", "lldb", "llvm-profdata",
    "llvm-cov", "addr2line", "objdump", "nm", "readelf", "strings",
    "cmake", "make", "ninja", "cargo", "patch", "file",
)


def _tool_version(name: str) -> Optional[str]:
    path = shutil.which(name)
    if path is None:
        return None
    import subprocess
    try:
        proc = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=5,
            stdin=subprocess.DEVNULL,
        )
        first = (proc.stdout or proc.stderr).strip().splitlines()
        return first[0][:200] if first else path
    except Exception:
        return path  # present but --version failed; still usable-ish


def resolve_environment(probe_tools: bool = True) -> EnvironmentProfile:
    """Probe the *real* local environment (offline, read-only).

    No fabricated values: absent tools map to ``None``.
    """
    notes: List[str] = []
    try:
        total_mem = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):  # pragma: no cover
        total_mem = 0
        notes.append("could not determine physical memory")
    home = Path.home()
    try:
        probe = home / ".kmcs-probe"
        probe.touch()
        probe.unlink(missing_ok=True)
        writable = True
    except OSError:
        writable = False
        notes.append("home directory is not writable; set KMCS_HOME")
    toolchain: Dict[str, Optional[str]] = {}
    if probe_tools:
        for tool in _TOOLS_PROBED:
            toolchain[tool] = _tool_version(tool)
    else:
        notes.append("toolchain probing skipped (probe_tools=False)")
    return EnvironmentProfile(
        hostname=socket.gethostname(),
        platform=sys.platform,
        python_version=platform_python(),
        cpu_count=os.cpu_count() or 1,
        total_memory_bytes=int(total_mem),
        kernel=os.uname().release if hasattr(os, "uname") else "unknown",
        toolchain=toolchain,
        writable_home=writable,
        detected_at=_utcnow(),
        notes=tuple(notes),
    )


def platform_python() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


# --------------------------------------------------------------------------- #
# Root config
# --------------------------------------------------------------------------- #

class KmcsConfig(_Section):
    """The root configuration document for a KMCS installation."""

    version: int = Field(default=1, ge=1, description="Schema version.")
    instance_id: str = Field(default="", max_length=128,
                             description="Free-form label for multi-instance hosts.")
    operation_mode: str = Field(
        default="research", pattern=r"^(research|ci)$",
        description="'research': full GUI/CLI; 'ci': headless, fail-fast.")
    paths: PathsConfig = Field(default_factory=PathsConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    resources: ResourceLimits = Field(default_factory=ResourceLimits)
    instrumentation: InstrumentationConfig = Field(default_factory=InstrumentationConfig)
    sanitizers: SanitizersConfig = Field(default_factory=SanitizersConfig)
    coverage: CoverageConfig = Field(default_factory=CoverageConfig)
    fuzzers: FuzzerConfig = Field(default_factory=FuzzerConfig)
    corpus: CorpusConfig = Field(default_factory=CorpusConfig)
    campaigns: CampaignConfig = Field(default_factory=CampaignConfig)
    minimization: MinimizationConfig = Field(default_factory=MinimizationConfig)
    reproduction: ReproductionConfig = Field(default_factory=ReproductionConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)

    # -- derived views ------------------------------------------------------
    def redacted(self) -> Dict[str, Any]:
        return _redact_mapping(self.model_dump(mode="json"))

    def digest(self) -> str:
        import hashlib
        blob = json.dumps(self.redacted(), sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def to_json(self, *, indent: int = 2, redact_secrets: bool = True) -> str:
        payload = self.redacted() if redact_secrets else self.model_dump(mode="json")
        return json.dumps(payload, indent=indent, sort_keys=True, default=str)

    def asan_environment(self, log_prefix: Optional[str] = None) -> Dict[str, str]:
        return self.sanitizers.asan_env(log_prefix=log_prefix)

    def apply_to_environment(self, environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Export the canonical KMCS env vars into *environ* (defaults: os.environ)."""
        env = os.environ if environ is None else environ
        env["KMCS_HOME"] = str(self.paths.home)
        env["KMCS_INSTANCE"] = self.instance_id or "default"
        env["KMCS_OPERATION_MODE"] = self.operation_mode
        for key, value in self.asan_environment().items():
            env[key] = value
        return env


#: The pristine default document (deep-copied on demand; treat as read-only).
DEFAULT_CONFIG: KmcsConfig = KmcsConfig()


# --------------------------------------------------------------------------- #
# Layered loading
# --------------------------------------------------------------------------- #

def _env_overlay(env: Mapping[str, str]) -> Dict[str, Any]:
    """Translate ``KMCS_SECTION__KEY=value`` variables into a nested dict.

    ``__`` separates nesting levels; values are JSON-parsed when possible so
    ``KMCS_PERFORMANCE__PARALLEL_WORKERS=8`` becomes an int, and booleans
    accept ``1/0/true/false/yes/no``.
    """
    overlay: Dict[str, Any] = {}
    for raw_key, raw_val in env.items():
        if not raw_key.startswith(ENV_PREFIX):
            continue
        key = raw_key[len(ENV_PREFIX):]
        if "__" not in key:
            continue  # plain scalars like KMCS_HOME handled elsewhere
        parts = [p.lower() for p in key.split("__")]
        node = overlay
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):  # conflict: scalar beats deeper key
                break
        else:
            node[parts[-1]] = _coerce_scalar(raw_val)
    # KMCS_HOME is special-cased into paths.home
    if "KMCS_HOME" in env:
        overlay.setdefault("paths", {})["home"] = env["KMCS_HOME"]
    return overlay


_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _coerce_scalar(text: str) -> Any:
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        pass
    low = stripped.lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    return stripped


def _deep_merge(base: Dict[str, Any], overlay: Mapping[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)  # type: ignore[arg-type]
        else:
            out[key] = copy.deepcopy(value)
    return out


def _read_document(path: Path) -> Dict[str, Any]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    if suffix == ".json":
        data = json.loads(text)
    elif suffix in (".toml",):
        try:
            import tomllib  # py3.11+
            data = tomllib.loads(text)
        except ModuleNotFoundError:  # pragma: no cover
            raise ConfigurationError("TOML support requires Python ≥ 3.11")
    elif suffix in (".ini", ".cfg"):
        import configparser
        parser = configparser.ConfigParser()
        parser.read_string(text)
        data = {sec: dict(parser.items(sec)) for sec in parser.sections()}
    else:
        raise ConfigurationError(
            f"unsupported config file extension {suffix!r}",
            context={"path": str(path)},
        )
    if not isinstance(data, dict):
        raise ConfigurationError("config document must be a mapping",
                                 context={"path": str(path)})
    return data


def _issues_from_validation(exc: ValidationError, layer: str) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", ())) or "<root>"
        issues.append(ValidationIssue(
            location=loc,
            message=str(err.get("msg", "invalid value")),
            kind="error",
            expected=str(err.get("type", "")),
            actual=repr(err.get("input"))[:120],
            source_layer=layer,
            remediation="fix the value or remove the override",
        ))
    return issues


def load_config(
    path: Optional[Union[str, Path]] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
    overrides: Optional[Mapping[str, Any]] = None,
    strict: bool = True,
) -> ConfigResult:
    """Merge the four layers and validate. Never raises unless ``strict``.

    Returns a :class:`ConfigResult` carrying either a valid
    :class:`KmcsConfig` plus a verification report, or ``config=None`` and a
    report full of :class:`ValidationIssue` records.
    """
    layers: List[str] = ["defaults"]
    merged: Dict[str, Any] = DEFAULT_CONFIG.model_dump()

    if path is not None:
        doc_path = Path(path).expanduser()
        if not doc_path.exists():
            raise ConfigurationError("config file not found",
                                     context={"path": str(doc_path)})
        merged = _deep_merge(merged, _read_document(doc_path))
        layers.append(f"file:{doc_path.name}")

    environment = os.environ if env is None else env
    env_overlay = _env_overlay(environment)
    if env_overlay:
        merged = _deep_merge(merged, env_overlay)
        layers.append("environment")

    if overrides:
        merged = _deep_merge(merged, dict(overrides))
        layers.append("override")

    try:
        cfg = KmcsConfig.model_validate(merged)
    except ValidationError as exc:
        report = VerificationReport(ok=False,
                                    issues=tuple(_issues_from_validation(exc, "+".join(layers))),
                                    layers=tuple(layers))
        if strict:
            raise ConfigurationError(
                "configuration failed validation",
                context={"issues": [i.to_dict() for i in report.errors]},
            ) from exc
        return ConfigResult(config=None, report=report, raw_merged=merged)

    # Non-fatal advisories (things validators can't see statically).
    advisories: List[ValidationIssue] = []
    if cfg.fuzzers.engine is EngineKind.AFLPP and shutil.which(cfg.fuzzers.aflpp.binary) is None:
        advisories.append(ValidationIssue(
            location="fuzzers.engine",
            message=f"AFL++ binary '{cfg.fuzzers.aflpp.binary}' not found on PATH; "
                    "campaigns will report the engine as unavailable rather than fake results",
            kind="warning", source_layer="+".join(layers),
            remediation="install AFL++ or select another engine",
        ))
    if cfg.resources.address_space_bytes > max(1, merged_default_mem()):
        advisories.append(ValidationIssue(
            location="resources.address_space_bytes",
            message="ASan address-space ceiling exceeds visible RAM",
            kind="warning", source_layer="+".join(layers),
        ))
    report = VerificationReport(ok=True, issues=tuple(advisories), layers=tuple(layers))
    return ConfigResult(config=cfg, report=report, raw_merged=merged)


def merged_default_mem() -> int:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except Exception:  # pragma: no cover
        return 1 << 63


# --------------------------------------------------------------------------- #
# Manager
# --------------------------------------------------------------------------- #

class ConfigManager:
    """Mutable owner of the live configuration with snapshots & writes.

    Thread-safe: all mutations happen under one lock; readers get immutable
    snapshots.  Keeps a bounded history so the GUI can diff revisions.
    """

    HISTORY_LIMIT = 32

    def __init__(self, path: Optional[Union[str, Path]] = None,
                 *, env: Optional[Mapping[str, str]] = None,
                 auto_create_dirs: bool = False) -> None:
        self._lock = threading.RLock()
        self._path = Path(path).expanduser() if path else None
        self._env = env
        self._revision = 0
        self._history: List[ConfigSnapshot] = []
        self._status = RuntimeStatus.UNINITIALISED
        self._last_report: Optional[VerificationReport] = None
        self._config: Optional[KmcsConfig] = None
        self._watch_token: Optional[float] = None
        if auto_create_dirs and self._config is not None:
            self._config.paths.ensure()

    # -- lifecycle ----------------------------------------------------------
    def load(self, *, strict: bool = True) -> ConfigResult:
        with self._lock:
            result = load_config(self._path, env=self._env, strict=strict)
            self._last_report = result.report
            if result.config is not None:
                self._config = result.config
                self._revision += 1
                self._status = (RuntimeStatus.VALID if result.report.ok
                                else RuntimeStatus.INVALID)
                self._record_snapshot(label="load")
            else:
                self._status = RuntimeStatus.INVALID
            return result

    def ensure_loaded(self) -> KmcsConfig:
        with self._lock:
            if self._config is None:
                self.load(strict=True)
            assert self._config is not None
            return self._config

    @property
    def config(self) -> KmcsConfig:
        return self.ensure_loaded()

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def status(self) -> RuntimeStatus:
        return self._status

    @property
    def last_report(self) -> Optional[VerificationReport]:
        return self._last_report

    # -- mutation ------------------------------------------------------------
    def update(self, changes: Mapping[str, Any], *, source: str = "programmatic") -> ConfigResult:
        """Apply *changes* (nested dict, dotted keys allowed) and revalidate."""
        with self._lock:
            base = self.ensure_loaded().model_dump()
            flat = _unnest(changes)
            merged = base
            for dotted, value in flat.items():
                _set_dotted(merged, dotted, value)
            try:
                new_cfg = KmcsConfig.model_validate(merged)
            except ValidationError as exc:
                report = VerificationReport(ok=False,
                                            issues=tuple(_issues_from_validation(exc, source)))
                self._last_report = report
                self._status = RuntimeStatus.INVALID
                return ConfigResult(config=None, report=report, raw_merged=merged)
            self._config = new_cfg
            self._revision += 1
            self._status = RuntimeStatus.VALID
            self._record_snapshot(label=source)
            return ConfigResult(config=new_cfg,
                                report=VerificationReport(ok=True, layers=(source,)),
                                raw_merged=merged)

    def reset_to_defaults(self) -> None:
        with self._lock:
            self._config = DEFAULT_CONFIG.model_copy(deep=True)
            self._revision += 1
            self._status = RuntimeStatus.VALID
            self._record_snapshot(label="reset")

    # -- persistence ----------------------------------------------------------
    def write(self, path: Optional[Union[str, Path]] = None,
              *, include_redacted_view: bool = False) -> Path:
        """Atomically persist the current config as JSON.

        ``include_redacted_view`` additionally writes a ``*.redacted.json``
        sibling suitable for attaching to bug reports.
        """
        with self._lock:
            target = Path(path or self._path or (self.config.paths.home / "config.json"))
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = self.ensure_loaded().to_json()
            tmp_fd, tmp_name = tempfile.mkstemp(dir=str(target.parent),
                                                prefix=".kmcs-config-", suffix=".tmp")
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, target)
            finally:
                if os.path.exists(tmp_name):  # pragma: no cover - raced away
                    os.unlink(tmp_name)
            if include_redacted_view:
                red = target.with_suffix(".redacted.json")
                red.write_text(json.dumps(self.config.redacted(), indent=2,
                                          sort_keys=True, default=str),
                               encoding="utf-8")
            self._path = target
            self._status = RuntimeStatus.VALID
            return target

    # -- staleness / watching --------------------------------------------------
    def is_stale(self) -> bool:
        """True if the backing file changed on disk since the last load/write."""
        if self._path is None or not self._path.exists():
            return False
        mtime = self._path.stat().st_mtime
        return self._watch_token is not None and mtime != self._watch_token

    def reload_if_changed(self) -> bool:
        if self.is_stale():
            self.load()
            return True
        return False

    # -- history ----------------------------------------------------------------
    def snapshots(self) -> Tuple[ConfigSnapshot, ...]:
        with self._lock:
            return tuple(self._history)

    def head_snapshot(self) -> ConfigSnapshot:
        snaps = self.snapshots()
        if not snaps:
            raise ConfigurationError("no configuration snapshots recorded yet")
        return snaps[-1]

    def diff(self, older: ConfigSnapshot, newer: ConfigSnapshot) -> Dict[str, Dict[str, Any]]:
        """Field-level diff between two snapshots (values already redacted)."""
        flat_old = _flatten(dict(older.payload))
        flat_new = _flatten(dict(newer.payload))
        changes: Dict[str, Dict[str, Any]] = {}
        for key in sorted(set(flat_old) | set(flat_new)):
            a, b = flat_old.get(key), flat_new.get(key)
            if a != b:
                changes[key] = {"old": a, "new": b}
        return changes

    def _record_snapshot(self, label: str) -> None:
        assert self._config is not None
        payload = self._config.redacted()
        digest = self._config.digest()
        snap = ConfigSnapshot(revision=self._revision, digest=digest,
                              created_at=_utcnow(), payload=payload,
                              source_layers=(label,), label=label)
        self._history.append(snap)
        if len(self._history) > self.HISTORY_LIMIT:
            self._history = self._history[-self.HISTORY_LIMIT:]
        if self._path is not None and self._path.exists():
            self._watch_token = self._path.stat().st_mtime

    # -- verification ------------------------------------------------------------
    def verify(self) -> VerificationReport:
        """Re-validate the current in-memory config (cheap round-trip)."""
        with self._lock:
            cfg = self.ensure_loaded()
            try:
                KmcsConfig.model_validate(cfg.model_dump())
                return VerificationReport(ok=True, layers=("in-memory",))
            except ValidationError as exc:  # pragma: no cover - shouldn't happen
                return VerificationReport(ok=False,
                                          issues=tuple(_issues_from_validation(exc, "in-memory")))

    def status_dict(self) -> Dict[str, Any]:
        cfg = self._config
        return {
            "status": self._status.value,
            "revision": self._revision,
            "path": str(self._path) if self._path else None,
            "digest": cfg.digest() if cfg else None,
            "stale": self.is_stale(),
            "report": self._last_report.to_dict() if self._last_report else None,
        }


# --------------------------------------------------------------------------- #
# Dotted-path utilities
# --------------------------------------------------------------------------- #

def _unnest(data: Mapping[str, Any]) -> Dict[str, Any]:
    """Flatten possibly-nested mappings into dotted-key form."""
    out: Dict[str, Any] = {}

    def walk(prefix: str, node: Mapping[str, Any]) -> None:
        for key, value in node.items():
            dotted = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, Mapping):
                walk(dotted, value)  # type: ignore[arg-type]
            else:
                out[dotted] = value
    walk("", data)
    return out


def _set_dotted(root: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    node = root
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def _flatten(mapping: Mapping[str, Any], prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in mapping.items():
        dotted = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            out.update(_flatten(value, dotted))  # type: ignore[arg-type]
        else:
            out[dotted] = value
    return out


# --------------------------------------------------------------------------- #
# Convenience singleton accessors
# --------------------------------------------------------------------------- #

_MANAGER_LOCK = threading.Lock()
_MANAGER: Optional[ConfigManager] = None


def get_config_manager(path: Optional[Union[str, Path]] = None,
                       *, reload: bool = False) -> ConfigManager:
    """Process-wide :class:`ConfigManager` (lazy, thread-safe)."""
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None or reload:
            mgr = ConfigManager(path)
            mgr.load(strict=False)
            _MANAGER = mgr
        return _MANAGER


def get_config() -> KmcsConfig:
    return get_config_manager().config


if __name__ == "__main__":  # tiny smoke run
    res = load_config(strict=False)
    print(res.raise_if_invalid().digest()[:16], "OK")
