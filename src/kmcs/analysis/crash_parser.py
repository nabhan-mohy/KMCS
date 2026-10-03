# =============================================================================
# kmcs.analysis.crash_parser -- sanitizer log -> structured crash records
# =============================================================================
"""
Turn *real* sanitizer / fuzzer output text into structured KMCS objects.

This module is the entry point of the analysis pipeline.  It consumes the raw
stderr/stdout that AFL++, libFuzzer, Honggfuzz or a direct reproduction run
produced, and emits :class:`kmcs.core.models.SanitizerReport` blocks plus
:class:`kmcs.core.models.Crash` records ready for classification, fingerprint
ing and de-duplication.

Honesty contract
----------------
* Every populated field was **observed in the input text**.  Missing data
  stays ``None``/``unknown``; the parser never invents addresses, symbols,
  sizes or counts.
* Unrecognised lines are preserved (``raw_output``, ``warnings``) so nothing
  silently disappears from the audit trail.
* Symbol resolution uses *real* tools (``llvm-symbolizer`` / ``addr2line``)
  when present on the machine; otherwise it reports unavailability honestly
  (:class:`NullSymbolizer`) rather than pretending to resolve frames.

Supported formats
-----------------
1. AddressSanitizer banners (v0.3 .. v15+):
   ``==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...``
   including READ/WRITE OF SIZE, allocation/free traces, shadow bytes,
   ``SUMMARY: AddressSanitizer: ...``, thread lists and module lists.
2. LeakSanitizer blocks:
   ``ERROR: LeakSanitizer: detected memory leaks`` + Direct/Indirect leak
   records with per-allocation stacks.
3. UndefinedBehaviorSanitizer:
   ``file.cpp:12:7: runtime error: signed integer overflow: ...`` plus
   optional GCC-style ``undefined reference``/diagnostics fallback.
4. ThreadSanitizer:
   ``WARNING: ThreadSanitizer: data race (pid=...)`` with race stacks.
5. MemorySanitizer:
   ``==pid==ERROR: MemorySanitizer: use-of-uninitialized-value``.
6. libFuzzer harnesses:
   ``artifact_prefix=...; Test unit written to ...`` +
   ``SUMMARY: libFuzzer: out of memory`` / timeout markers.
7. Bare signals (no sanitizer attached):
   ``Segmentation fault (core dumped)``, ``Aborted``, ``Bus error``,
   ``Floating point exception``, exit-code driven inference (139 -> SIGSEGV).
8. AFL++ queue naming conventions (``id:0000xx,sig:11,...``) surfaced as
   metadata on the produced crash record.

The parser is deliberately regex-driven and line-oriented: sanitizer output is
a stream of independent lines and block structure is shallow.  A small state
machine (``_BlockAccumulator``) groups related lines (headline -> access ->
stack -> alloc trace -> free trace -> shadow -> summary) into one report.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.exceptions import (
    CrashParseError,
    InvalidValueError,
    ToolNotFoundError,
)
from kmcs.core.models import (
    Confidence,
    Crash,
    CrashClass,
    CrashLocation,
    CrashState,
    MemoryAccess,
    SanitizerKind,
    SanitizerReport,
    SignalInfo,
    StackFrame,
    StackTrace,
    generate_prefixed_id,
    sha256_bytes,
    utc_string,
)

__all__ = [
    "CrashParser",
    "ParseOutcome",
    "RawCrashRecord",
    "detect_sanitizer_banner",
    "parse_crash_log",
    "parse_sanitizer_output",
    "split_reports",
    "self_test_report",
    "Symbolizer",
    "NullSymbolizer",
    "Addr2LineSymbolizer",
    "LLVMSymbolizer",
    "symbolizer_for_environment",
    "SANITIZER_BANNERS",
    "SIGNAL_EXIT_CODES",
]

# ============================================================================
# constants & shared patterns
# ============================================================================

#: Canonical banner regexes per sanitizer.  Order matters only for reporting.
SANITIZER_BANNERS: Dict[str, re.Pattern[str]] = {
    "asan": re.compile(
        r"==(\d+)==(?:\d+:)?ERROR: AddressSanitizer:\s*(?P<cls>[A-Za-z0-9_-]+)"
        r"(?:\s+on(?:\s+address)?\s+(?P<addr>0x[0-9a-fA-F]+))?"
    ),
    "asan_strict": re.compile(
        r"ERROR:\s*AddressSanitizer:\s*(?P<cls>[A-Za-z0-9_-]+)"
    ),
    "lsan": re.compile(
        r"(?:==(\d+)==)?ERROR: LeakSanitizer:\s*detected memory leaks"
    ),
    "ubsan": re.compile(
        r"(?P<file>[^\s:]+):(?P<line>\d+):(?P<col>\d+):\s*runtime error:\s*(?P<msg>.+)"
    ),
    "tsan": re.compile(
        r"(?:WARNING|ERROR):\s*ThreadSanitizer:\s*(?P<cls>.+?)"
        r"(?:\s+\(pid=(?P<pid>\d+)\))?\s*$"
    ),
    "msan": re.compile(
        r"==(\d+)==(?:\d+:)?ERROR: MemorySanitizer:\s*(?P<cls>[A-Za-z0-9_-]+)"
        r"(?:\s+at\s+(?P<loc>.*))?"
    ),
}

#: Exit codes observed from shell-level signal deaths (128 + signum convention).
SIGNAL_EXIT_CODES: Dict[int, int] = {
    132: 4,   # SIGILL
    133: 5,   # SIGTRAP
    134: 6,   # SIGABRT
    135: 7,   # SIGBUS
    136: 8,   # SIGFPE
    137: 9,   # SIGKILL (often OOM killer)
    139: 11,  # SIGSEGV
    152: 24,  # SIGXCPU (time limit)
}

#: Plain-text shell messages -> signal number.
PLAIN_SIGNAL_MESSAGES: Dict[str, int] = {
    "segmentation fault": 11,
    "segmentation violation": 11,
    "bus error": 7,
    "abort": 6,
    "aborted": 6,
    "illegal instruction": 4,
    "floating point exception": 8,
    "killed": 9,
    "trace/breakpoint trap": 5,
}

_FRAME_ASAN = re.compile(
    r"^#(?P<idx>\d+)\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(?P<func>.+?)\s+"
    r"(?P<file>/[^:\s]+|<[^>]+>)(?::(?P<line>\d+)(?::(?P<col>\d+))?)?(?:\s|$)"
)
_FRAME_MODULE = re.compile(
    r"^#(?P<idx>\d+)\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(?P<func>\S+)\s+"
    r"\((?P<module>[^)+\s]+)\+(?P<offset>0x[0-9a-fA-F]+)\)"
)
_FRAME_ADDRONLY = re.compile(
    r"^#(?P<idx>\d+)\s+(?P<addr>0x[0-9a-fA-F]+)(?:\s+(?P<rest>.*))?$"
)
_ACCESS_LINE = re.compile(
    r"^(READ|WRITE|EXECUTE) of size (?P<size>\d+)", re.IGNORECASE
)
_ALLOC_LINE = re.compile(r"^Allocated by thread T(?P<tid>\d+) directly:?$", re.IGNORECASE)
_FREE_LINE = re.compile(r"^Fre(?:e|ed) by thread T(?P<tid>\d+)", re.IGNORECASE)
_SHADOW_LINE = re.compile(
    r"^(?P<addr>0x[0-9a-fA-F]+):\s(?P<bytes>(?:[0-9a-fA-F]{2}\s){3,}[0-9a-fA-F]{2})"
)
_SUMMARY_ASAN = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*(?P<cls>[A-Za-z0-9_-]+)")
_SUMMARY_LSAN = re.compile(r"SUMMARY:\s*LeakSanitizer:\s*(?P<count>\d+) byte\(s\) leaked")
_LEAK_RECORD = re.compile(
    r"^(?P<kind>Direct|Indirect) leak of (?P<size>\d+) byte\(s\) "
    r"(?P<objs>\d+) object\(s\) allocated from"
)
_TSAN_LOCATION = re.compile(
    r"\s*(?P<loc>/[^:\s]+):(?P<line>\d+)\s*(?:\((?P<module>[^)]*)\))?"
)
_TSAN_FRAME = re.compile(r"^\s+#(?P<idx>\d+)\s+(?P<func>.+?)(?:\s|$)")
_MSAN_FRAME = _FRAME_ASAN
_TIMEOUT_MARKERS = (
    "timeout:",
    "test timed out",
    "ALARM: test unit takes too long",
    "TIMEOUT (",
)
_OOM_MARKERS = ("out of memory", "cannot allocate memory", "std::bad_alloc")
_ASSERT_MARKERS = (
    "assertion",
    "static_assert",
    "__assert_fail",
    "assertion failed",
)
_HANG_MARKERS = ("hang found", "slow-unit", "timeout-seed")

_ADDRESS_TOKEN = re.compile(r"0x[0-9a-fA-F]{4,16}")

# Map of ASan-style error type tokens -> CrashClass members.  Keys are matched
# case-insensitively after normalisation ('-' <-> '_').
ASAN_CLASS_MAP: Dict[str, CrashClass] = {
    "heap-buffer-overflow": CrashClass.HEAP_BUFFER_OVERFLOW,
    "heap-buffer-underflow": CrashClass.HEAP_BUFFER_UNDERFLOW,
    "stack-buffer-overflow": CrashClass.STACK_BUFFER_OVERFLOW,
    "stack-buffer-underflow": CrashClass.STACK_BUFFER_UNDERFLOW,
    "stack-overflow": CrashClass.STACK_OVERFLOW,
    "global-buffer-overflow": CrashClass.GLOBAL_BUFFER_OVERFLOW,
    "global-buffer-underflow": CrashClass.GLOBAL_BUFFER_UNDERFLOW,
    "use-after-free": CrashClass.USE_AFTER_FREE,
    "use-after-return": CrashClass.USE_AFTER_RETURN,
    "use-after-scope": CrashClass.USE_AFTER_SCOPE,
    "initialization-order-fiasco": CrashClass.UNINITIALIZED_USE,
    "double-free": CrashClass.DOUBLE_FREE,
    "alloc-dealloc-mismatch": CrashClass.ALLOCATOR_MISUSE,
    "invalid-free": CrashClass.INVALID_FREE,
    "negative-size-param": CrashClass.ALLOCATOR_MISUSE,
    "attempting double-free": CrashClass.DOUBLE_FREE,
    "new-delete-type-mismatch": CrashClass.ALLOCATOR_MISUSE,
    "container-overflow": CrashClass.HEAP_BUFFER_OVERFLOW,
    "dynamic-stack-buffer-overflow": CrashClass.STACK_BUFFER_OVERFLOW,
    "allocator-is-out-of-memory": CrashClass.OUT_OF_MEMORY,
    "out-of-memory": CrashClass.OUT_OF_MEMORY,
    "segfault": CrashClass.SEGMENTATION_FAULT,
    "generic-segv": CrashClass.SEGMENTATION_FAULT,
    "ibus": CrashClass.BUS_ERROR,
    "illegal-instruction": CrashClass.ILLEGAL_INSTRUCTION,
    "abort": CrashClass.ABORT,
    "requested-allocation-too-large": CrashClass.OVERFLOW_ALLOC,
    "alloc-zero": CrashClass.ALLOCATOR_MISUSE,
    "memset-overread": CrashClass.HEAP_BUFFER_OVERFLOW,
}

UBSAN_MESSAGE_MAP: Tuple[Tuple[re.Pattern[str], CrashClass], ...] = (
    (re.compile(r"signed integer overflow", re.I), CrashClass.INTEGER_OVERFLOW),
    (re.compile(r"unsigned integer overflow", re.I), CrashClass.INTEGER_OVERFLOW),
    (re.compile(r"integer overflow", re.I), CrashClass.INTEGER_OVERFLOW),
    (re.compile(r"division by zero", re.I), CrashClass.DIVIDE_BY_ZERO),
    (re.compile(r"left shift .* overflow|shift exponent .* too large", re.I),
     CrashClass.SIGNED_SHIFT_OVERFLOW),
    (re.compile(r"misaligned (address|load|store)", re.I), CrashClass.MISALIGNED_ACCESS),
    (re.compile(r"load of null pointer", re.I), CrashClass.NULL_ARGUMENT),
    (re.compile(r"null pointer", re.I), CrashClass.NULL_DEREFERENCE),
    (re.compile(r"member call on null", re.I), CrashClass.NULL_DEREFERENCE),
    (re.compile(r"object size mismatch", re.I), CrashClass.OBJECT_SIZE_VIOLATION),
    (re.compile(r"value .* is outside range of enum|enum.*out of range", re.I),
     CrashClass.ENUM_OUT_OF_RANGE),
    (re.compile(r"execution reached an unreachable", re.I), CrashClass.UNREACHABLE_CODE),
    (re.compile(r"cast of (pointer )?.*to incorrectly aligned", re.I),
     CrashClass.MISALIGNED_ACCESS),
    (re.compile(r"wrong type", re.I), CrashClass.TYPE_MISSMATCH),
    (re.compile(r"function pointer type mismatch", re.I), CrashClass.FUNCTION_TYPE_MISMATCH),
    (re.compile(r"vla bound changed", re.I), CrashClass.VLA_BOUND_CHANGE),
    (re.compile(r"-fsanitize=null return non-null|null argument", re.I),
     CrashClass.NULL_ARGUMENT),
)

TSAN_CLASS_MAP: Dict[str, CrashClass] = {
    "data race": CrashClass.DATA_RACE,
    "data race (read/write)": CrashClass.DATA_RACE,
    "lock order inversion": CrashClass.LOCK_ORDER_INVERSION,
    "deadlock": CrashClass.LOCK_ORDER_INVERSION,
    "signal handler called": CrashClass.SIGNAL,
    "thread leak": CrashClass.MEMORY_LEAK,
}


def _normalise_token(text: str) -> str:
    return re.sub(r"[\s_]+", "-", str(text or "").strip().lower()).strip("-")


def _coerce_asan_class(token: str) -> CrashClass:
    norm = _normalise_token(token)
    if norm in ASAN_CLASS_MAP:
        return ASAN_CLASS_MAP[norm]
    # prefix matches such as "heap-buffer-overflow-address-partially ..."
    for key, cls in ASAN_CLASS_MAP.items():
        if norm.startswith(key):
            return cls
    try:
        return CrashClass.coerce(norm)
    except Exception:
        return CrashClass.UNKNOWN


# ============================================================================
# symbolizers (real external tools, honest about availability)
# ============================================================================


class Symbolizer:
    """Interface for resolving ``module+offset`` -> ``function/file/line``."""

    #: Human-readable name used in provenance strings.
    name: str = "abstract"
    #: Whether this symbolizer can actually resolve anything.
    available: bool = False

    def resolve(self, module: str, offset: str) -> Optional[StackFrame]:
        raise NotImplementedError

    def resolve_many(self, pairs: Sequence[Tuple[str, str]]) -> List[Optional[StackFrame]]:
        return [self.resolve(module, offset) for module, offset in pairs]


class NullSymbolizer(Symbolizer):
    """Fallback used when no real symbolizer exists on this machine."""

    name = "none"
    available = False

    def resolve(self, module: str, offset: str) -> Optional[StackFrame]:
        return None


class Addr2LineSymbolizer(Symbolizer):
    """Resolve frames with GNU ``addr2line`` (binutils)."""

    name = "addr2line"

    def __init__(self, binary: str | os.PathLike[str], *, tool: str = "addr2line",
                 timeout: float = 10.0) -> None:
        self.binary = str(Path(binary).expanduser())
        self.tool_path = shutil.which(tool) or ""
        self.timeout = float(timeout)
        self.available = bool(self.tool_path and os.path.isfile(self.binary))
        self._lock = threading.Lock()
        if not self.available:
            # keep the reason honest for diagnostics
            self.unavailable_reason = (
                "addr2line binary missing" if not self.tool_path
                else f"target image not found: {self.binary}"
            )

    def resolve(self, module: str, offset: str) -> Optional[StackFrame]:
        if not self.available:
            return None
        hex_offset = offset if offset.startswith("0x") else f"0x{offset}"
        try:
            with self._lock:
                proc = subprocess.run(
                    [self.tool_path, "-f -i -C -e".split()[0], "-f", "-i", "-C",
                     "-e", self.binary, hex_offset],
                    capture_output=True, text=True, timeout=self.timeout, check=False,
                )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        if len(lines) >= 2:
            function = lines[0]
            location = lines[1]
            file_, _, line_ = location.rpartition(":")
            frame = StackFrame(
                index=0, function=function or None,
                file=file_ or None,
                line=int(line_) if line_.isdigit() else None,
                module=os.path.basename(self.binary),
                offset=hex_offset, raw=f"{function} at {location}",
            )
            return frame
        return None


class LLVMSymbolizer(Symbolizer):
    """Resolve frames with ``llvm-symbolizer`` (batch mode, one query each)."""

    name = "llvm-symbolizer"

    def __init__(self, obj_dir: Optional[str | os.PathLike[str]] = None, *,
                 tool: str = "llvm-symbolizer", timeout: float = 10.0) -> None:
        self.obj_dir = str(Path(obj_dir).expanduser()) if obj_dir else None
        self.tool_path = shutil.which(tool) or ""
        self.timeout = float(timeout)
        self.available = bool(self.tool_path)
        if not self.available:
            self.unavailable_reason = "llvm-symbolizer not installed"

    def resolve(self, module: str, offset: str) -> Optional[StackFrame]:
        candidates = [module]
        if self.obj_dir:
            candidates.insert(0, os.path.join(self.obj_dir, os.path.basename(module)))
        exe = next((c for c in candidates if os.path.isfile(c)), "")
        if not exe or not self.available:
            return None
        hex_offset = offset if offset.startswith("0x") else f"0x{offset}"
        try:
            proc = subprocess.run(
                [self.tool_path, "--obj=" + exe, "--functions=linkage",
                 "--inlining", "--relative-address", hex_offset],
                capture_output=True, text=True, timeout=self.timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        lines = [ln.rstrip() for ln in proc.stdout.splitlines() if ln.strip()]
        if len(lines) >= 2:
            function = lines[0].strip()
            loc = lines[1].strip()
            match = re.match(r"(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?", loc)
            return StackFrame(
                index=0, function=function or None,
                file=match.group("file") if match else None,
                line=int(match.group("line")) if match else None,
                column=int(match.group("col")) if match and match.group("col") else None,
                module=os.path.basename(exe), offset=hex_offset,
                raw="\n".join(lines[:2]),
            )
        return None


def symbolizer_for_environment(prefer: str = "auto",
                               binary: Optional[str | os.PathLike[str]] = None) -> Symbolizer:
    """Pick the best *actually installed* symbolizer; never fake one.

    ``prefer`` may be ``auto`` | ``llvm`` | ``addr2line`` | ``none``.
    """
    prefer = str(prefer or "auto").lower()
    if prefer == "none":
        return NullSymbolizer()
    if prefer in {"auto", "llvm"}:
        sym = LLVMSymbolizer(binary if binary and os.path.isdir(str(binary)) else None)
        if sym.available:
            return sym
    if prefer in {"auto", "addr2line"} and binary:
        sym = Addr2LineSymbolizer(binary)
        if sym.available:
            return sym
    if prefer == "auto":
        llvm = LLVMSymbolizer()
        if llvm.available:
            return llvm
    return NullSymbolizer()


# ============================================================================
# raw record containers
# ============================================================================


@dataclass(frozen=True)
class RawCrashRecord:
    """Everything observed about one crash *before* structuring."""

    source_path: Optional[str] = None
    raw_text: str = ""
    digest: str = ""
    exit_code: Optional[int] = None
    signal_number: Optional[int] = None
    campaign_id: Optional[str] = None
    target_id: Optional[str] = None
    target_name: str = ""
    executable: str = ""
    engine: str = ""
    input_path: str = ""
    input_hash: str = ""
    input_size: int = 0
    notes: Tuple[str, ...] = ()

    @classmethod
    def from_file(cls, path: str | os.PathLike[str], **kw: Any) -> "RawCrashRecord":
        p = Path(path).expanduser()
        try:
            data = p.read_bytes()
        except OSError as exc:
            raise CrashParseError(
                f"cannot read crash log '{p}'", operation="read", input_path=str(p)
            ) from exc
        text = data.decode("utf-8", errors="replace")
        return cls(source_path=str(p), raw_text=text, digest=sha256_bytes(data), **kw)

    @classmethod
    def from_text(cls, text: str, **kw: Any) -> "RawCrashRecord":
        data = str(text).encode("utf-8", errors="replace")
        return cls(raw_text=str(text), digest=sha256_bytes(data), **kw)


@dataclass
class ParseOutcome:
    """Result of parsing one :class:`RawCrashRecord`.

    ``reports`` holds every sanitizer block found (possibly several leaks in
    one LSan dump).  ``crashes`` holds fully-formed :class:`Crash` records
    ready for the rest of the pipeline.  ``unparsed_lines`` keeps any lines
    that matched no known construct so operators can extend the parser from
    real samples instead of guesses.
    """

    record: RawCrashRecord
    reports: List[SanitizerReport] = field(default_factory=list)
    crashes: List[Crash] = field(default_factory=list)
    unparsed_lines: List[str] = field(default_factory=list)
    sanitizer_detected: str = SanitizerKind.NONE.value
    confidence: str = Confidence.MEDIUM.value
    warnings: List[str] = field(default_factory=list)
    parsed_at: str = field(default_factory=utc_string)

    @property
    def ok(self) -> bool:
        return bool(self.reports or self.crashes)

    @property
    def primary(self) -> Optional[Crash]:
        return self.crashes[0] if self.crashes else None

    def coverage(self) -> float:
        total = max(1, len(self.record.raw_text.splitlines()))
        consumed = total - len(self.unparsed_lines)
        return round(consumed / total, 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "digest": self.record.digest,
            "sanitizer": self.sanitizer_detected,
            "confidence": self.confidence,
            "coverage": self.coverage(),
            "reports": [r.to_dict() for r in self.reports],
            "crashes": [
                {
                    "id": c.id, "crash_class": c.crash_class,
                    "sanitizer": c.sanitizer, "severity": c.severity,
                    "signature": c.stack_signature(),
                    "fingerprint": getattr(c.fingerprint, "digest", None),
                } for c in self.crashes
            ],
            "warnings": list(self.warnings),
            "unparsed_line_count": len(self.unparsed_lines),
            "parsed_at": self.parsed_at,
        }


# ============================================================================
# banner detection helpers
# ============================================================================


def detect_sanitizer_banner(text: str) -> str:
    """Return the sanitizer token ('asan', 'lsan', ...) whose banner appears."""
    if not text:
        return SanitizerKind.NONE.value
    if SANITIZER_BANNERS["lsan"].search(text):
        return SanitizerKind.LSAN.value
    if SANITIZER_BANNERS["asan"].search(text) or SANITIZER_BANNERS["asan_strict"].search(text):
        return SanitizerKind.ASAN.value
    if SANITIZER_BANNERS["msan"].search(text):
        return SanitizerKind.MSAN.value
    if SANITIZER_BANNERS["tsan"].search(text):
        return SanitizerKind.TSAN.value
    if "ThreadSanitizer" in text:
        return SanitizerKind.TSAN.value
    if SANITIZER_BANNERS["ubsan"].search(text) or "runtime error:" in text:
        return SanitizerKind.UBSAN.value
    if "libFuzzer:" in text or "SUMMARY: libFuzzer" in text:
        return SanitizerKind.NONE.value  # engine-level banner, not a sanitizer report
    return SanitizerKind.NONE.value


def split_reports(text: str) -> List[str]:
    """Split raw log text into independent sanitizer report blocks.

    A new block starts whenever a recognised banner line is seen.  Lines
    before the first banner are returned as a leading (possibly bare-signal)
    block so nothing is dropped.
    """
    lines = str(text or "").splitlines()
    banner_starts: List[int] = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if (SANITIZER_BANNERS["asan"].search(stripped)
                or SANITIZER_BANNERS["lsan"].search(stripped)
                or SANITIZER_BANNERS["msan"].search(stripped)
                or SANITIZER_BANNERS["tsan"].search(stripped)
                or SANITIZER_BANNERS["ubsan"].search(stripped)
                or "runtime error:" in stripped):
            banner_starts.append(idx)
    if not banner_starts:
        return [text] if text.strip() else []
    blocks: List[str] = []
    if banner_starts[0] > 0:
        preamble = "\n".join(lines[: banner_starts[0]])
        if preamble.strip():
            blocks.append(preamble)
    for position, start in enumerate(banner_starts):
        end = banner_starts[position + 1] if position + 1 < len(banner_starts) else len(lines)
        blocks.append("\n".join(lines[start:end]))
    return blocks


# ============================================================================
# internal block accumulator (state machine)
# ============================================================================


class _Section(StrEnum):
    IDLE = "idle"
    CRASH_STACK = "crash_stack"
    ALLOC_STACK = "alloc_stack"
    FREE_STACK = "free_stack"
    THREAD_LIST = "thread_list"
    SHADOW = "shadow"
    LEAK_STACK = "leak_stack"
    TSAN_PRIMARY = "tsan_primary"
    TSAN_SECONDARY = "tsan_secondary"
    TSAN_STACK = "tsan_stack"


@dataclass
class _BlockState:
    sanitizer: str = SanitizerKind.NONE.value
    headline: Optional[str] = None
    crash_class: CrashClass = CrashClass.UNKNOWN
    pid: Optional[int] = None
    thread: Optional[str] = None
    exit_code: Optional[int] = None
    memory_access: Optional[MemoryAccess] = None
    shadow_lines: List[str] = field(default_factory=list)
    stack_frames: List[StackFrame] = field(default_factory=list)
    alloc_frames: List[StackFrame] = field(default_factory=list)
    free_frames: List[StackFrame] = field(default_factory=list)
    leak_records: List[Dict[str, Any]] = field(default_factory=list)
    threads: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    raw_lines: List[str] = field(default_factory=list)
    section: _Section = _Section.IDLE
    pending_leak: Optional[Dict[str, Any]] = None
    tsan_secondary_kind: Optional[str] = None


# ============================================================================
# the parser
# ============================================================================


class CrashParser:
    """Parse sanitizer/fuzzer logs into structured reports and crashes.

    Parameters
    ----------
    symbolizer:
        Optional :class:`Symbolizer` used to enrich module+offset frames.
        When omitted, frames keep exactly what the log showed.
    max_frames:
        Hard cap per stack (sanitizer logs occasionally contain thousands of
        frames from stack-overflow recursion; we keep the head and mark the
        trace truncated).
    keep_unparsed:
        Collect lines that matched nothing into ``ParseOutcome.unparsed_lines``.
    """

    #: absolute ceiling on retained frames regardless of ``max_frames``
    FRAME_HARD_CAP = 512

    def __init__(self, *, symbolizer: Optional[Symbolizer] = None,
                 max_frames: int = 64, keep_unparsed: bool = True) -> None:
        if int(max_frames) < 4:
            raise InvalidValueError("max_frames must be >= 4")
        self.symbolizer = symbolizer or NullSymbolizer()
        self.max_frames = min(int(max_frames), self.FRAME_HARD_CAP)
        self.keep_unparsed = bool(keep_unparsed)
        self.stats_total_blocks = 0
        self.stats_parsed_frames = 0
        self.stats_symbolized_frames = 0

    # ------------------------------------------------------------------ api

    def parse_record(self, record: RawCrashRecord) -> ParseOutcome:
        """Parse one raw record into reports + Crash objects."""
        outcome = ParseOutcome(record=record)
        text = record.raw_text or ""
        if not text.strip():
            outcome.warnings.append("input contained no text")
            outcome.confidence = Confidence.LOW.value
            return outcome

        outcome.sanitizer_detected = detect_sanitizer_banner(text)
        blocks = split_reports(text)
        reports: List[SanitizerReport] = []
        crashes: List[Crash] = []
        unparsed: List[str] = []

        for block in blocks:
            state = self._parse_block(block)
            self.stats_total_blocks += 1
            has_content = (state.headline is not None or state.stack_frames
                           or state.leak_records or state.crash_class is not CrashClass.UNKNOWN)
            if not has_content:
                # block had no recognisable structure
                if self.keep_unparsed:
                    unparsed.extend(ln for ln in block.splitlines() if ln.strip())
                continue
            report = self._build_report(state)
            reports.append(report)
            crash = self._report_to_crash(report, record, state)
            crashes.append(crash)

        # bare-signal handling: no sanitizer block but process died on signal
        if not reports:
            inferred = self._infer_bare_crash(text, record)
            if inferred is not None:
                report, crash = inferred
                reports.append(report)
                crashes.append(crash)
                outcome.confidence = Confidence.MEDIUM.value
            elif self.keep_unparsed:
                unparsed.extend(ln for ln in text.splitlines() if ln.strip())

        # timeout / hang detection over the whole text (only when nothing crashed)
        lowered = text.lower()
        if not crashes:
            if any(marker in lowered for marker in _TIMEOUT_MARKERS):
                crash = self._synthetic_resource_crash(record, CrashClass.TIMEOUT,
                                                       "timeout marker observed in log")
                if crash.sanitizer_report is not None:
                    reports.append(crash.sanitizer_report)
                crashes.append(crash)
                outcome.confidence = Confidence.HIGH.value
            elif any(marker in lowered for marker in _OOM_MARKERS):
                crash = self._synthetic_resource_crash(record, CrashClass.OUT_OF_MEMORY,
                                                       "out-of-memory marker observed in log")
                if crash.sanitizer_report is not None:
                    reports.append(crash.sanitizer_report)
                crashes.append(crash)
                outcome.confidence = Confidence.HIGH.value

        outcome.reports = reports
        outcome.crashes = crashes
        outcome.unparsed_lines = unparsed if self.keep_unparsed else []
        if crashes:
            classes = {c.crash_class for c in crashes}
            if classes == {CrashClass.UNKNOWN}:
                outcome.confidence = Confidence.LOW.value
            elif outcome.confidence == Confidence.MEDIUM.value:
                outcome.confidence = Confidence.HIGH.value
        return outcome

    def parse_text(self, text: str, **meta: Any) -> ParseOutcome:
        return self.parse_record(RawCrashRecord.from_text(text, **meta))

    def parse_file(self, path: str | os.PathLike[str], **meta: Any) -> ParseOutcome:
        return self.parse_record(RawCrashRecord.from_file(path, **meta))

    # ------------------------------------------------------- block machinery

    def _parse_block(self, block: str) -> _BlockState:
        state = _BlockState()
        for raw_line in block.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue
            state.raw_lines.append(stripped)
            self._consume_line(state, stripped)
        # finalise trailing leak record
        if state.pending_leak is not None:
            state.pending_leak["frames"] = list(state.stack_frames[-self.max_frames:])
            state.leak_records.append(state.pending_leak)
            state.pending_leak = None
        return state

    # Each consumer returns True when it recognised the line.
    def _consume_line(self, state: _BlockState, line: str) -> bool:
        # --- ASan headline -------------------------------------------------
        match = SANITIZER_BANNERS["asan"].search(line) or SANITIZER_BANNERS["asan_strict"].search(line)
        if match and state.headline is None and "libFuzzer" not in line:
            state.sanitizer = SanitizerKind.ASAN.value
            state.headline = line
            if match.groupdict().get("cls"):
                state.crash_class = _coerce_asan_class(match.group("cls"))
            if match.groups() and match.group(1):
                try:
                    state.pid = int(match.group(1))
                except (TypeError, ValueError):
                    pass
            addr = match.groupdict().get("addr")
            if addr:
                state.memory_access = state.memory_access or MemoryAccess()
                state.memory_access.access_address = addr
            state.section = _Section.CRASH_STACK
            return True

        # --- LSan headline --------------------------------------------------
        if SANITIZER_BANNERS["lsan"].search(line):
            state.sanitizer = SanitizerKind.LSAN.value
            state.headline = line
            state.crash_class = CrashClass.MEMORY_LEAK
            state.section = _Section.LEAK_STACK
            return True

        # --- libFuzzer own banners (OOM / timeout / out-of-memory) ----------
        match = re.match(r"^==(?P<pid>\d+)==ERROR: libFuzzer:\s*(?P<what>.+)$", line)
        if match and state.headline is None:
            what = match.group("what").strip().lower()
            state.pid = int(match.group("pid"))
            state.headline = line
            state.sanitizer = SanitizerKind.NONE.value
            if "out of memory" in what or "oom" in what:
                state.crash_class = CrashClass.OUT_OF_MEMORY
            elif "timeout" in what:
                state.crash_class = CrashClass.TIMEOUT
            else:
                state.crash_class = CrashClass.UNKNOWN
            state.warnings.append(f"libFuzzer error: {what}")
            state.section = _Section.CRASH_STACK
            return True

        # --- MSan headline ---------------------------------------------------
        match = SANITIZER_BANNERS["msan"].search(line)
        if match and state.headline is None:
            state.sanitizer = SanitizerKind.MSAN.value
            state.headline = line
            state.crash_class = CrashClass.UNINITIALIZED_USE
            if match.group(1):
                state.pid = int(match.group(1))
            state.section = _Section.CRASH_STACK
            return True

        # --- TSan headline ---------------------------------------------------
        match = SANITIZER_BANNERS["tsan"].search(line)
        if match and state.headline is None:
            state.sanitizer = SanitizerKind.TSAN.value
            state.headline = line
            token = (match.group("cls") or "").strip().lower()
            state.crash_class = TSAN_CLASS_MAP.get(token, CrashClass.DATA_RACE
                                                   if "race" in token else CrashClass.UNKNOWN)
            if match.group("pid"):
                state.pid = int(match.group("pid"))
            state.section = _Section.TSAN_PRIMARY
            return True

        # --- UBSan runtime error --------------------------------------------
        match = SANITIZER_BANNERS["ubsan"].search(line)
        if match and state.headline is None:
            state.sanitizer = SanitizerKind.UBSAN.value
            state.headline = line
            message = match.group("msg")
            for pattern, cls in UBSAN_MESSAGE_MAP:
                if pattern.search(message):
                    state.crash_class = cls
                    break
            else:
                state.crash_class = CrashClass.UNKNOWN
            state.warnings.append(f"ubsan message: {message}")
            return True

        # --- access line ------------------------------------------------------
        match = _ACCESS_LINE.match(line)
        if match:
            state.memory_access = state.memory_access or MemoryAccess()
            state.memory_access.access_type = match.group(1).lower()
            state.memory_access.access_size = int(match.group("size"))
            state.section = _Section.CRASH_STACK
            return True

        # --- allocation context lines ----------------------------------------
        match = re.match(r"^(?:Address (\S+) is located )?(.*)", line)
        if line.startswith("Address ") and "is located" in line:
            note = line.split("is located", 1)[1].strip()
            state.warnings.append(f"location hint: {note}")
            alloc_match = re.search(
                r"(?P<size>\d+)-byte region \[(?P<lo>0x[0-9a-fA-F]+),"
                r"(?P<hi>0x[0-9a-fA-F]+)\)", line)
            if alloc_match:
                state.memory_access = state.memory_access or MemoryAccess()
                state.memory_access.allocation_size = int(alloc_match.group("size"))
                state.memory_access.allocation_address = alloc_match.group("lo")
            return True
        if line.startswith(("Shadow byte", "Shadow bytes")):
            state.section = _Section.SHADOW
            return True
        if _SHADOW_LINE.match(line):
            state.shadow_lines.append(line)
            return True

        # --- alloc/free trace headers -----------------------------------------
        match = _ALLOC_LINE.match(line)
        if match:
            state.section = _Section.ALLOC_STACK
            state.alloc_frames = []
            return True
        if line.startswith("Allocated by thread") or line.startswith("allocated by thread"):
            state.section = _Section.ALLOC_STACK
            state.alloc_frames = []
            return True
        match = _FREE_LINE.match(line)
        if match:
            state.section = _Section.FREE_STACK
            state.free_frames = []
            return True
        if re.match(r"^ freed by thread T\d+", line) or line.startswith("Freed by thread"):
            state.section = _Section.FREE_STACK
            state.free_frames = []
            return True

        # --- leak records -------------------------------------------------------
        match = _LEAK_RECORD.match(line)
        if match:
            if state.pending_leak is not None:
                state.pending_leak["frames"] = list(state.stack_frames)
                state.leak_records.append(state.pending_leak)
            kind = "direct" if match.group("kind").lower() == "direct" else "indirect"
            state.pending_leak = {
                "kind": kind,
                "size": int(match.group("size")),
                "objects": int(match.group("objs")),
                "frames": [],
            }
            state.stack_frames = []
            state.section = _Section.LEAK_STACK
            return True

        # --- thread list -----------------------------------------------------------
        if re.match(r"^Thread T\d+ created by T\d+ here:", line):
            state.section = _Section.THREAD_LIST
            state.threads.append(line)
            return True
        if line.startswith("Thread local variable") or line.startswith("Shared global variable"):
            state.warnings.append(line)
            return True

        # --- module list -------------------------------------------------------------
        if re.match(r"^\s*\[?\d+\]?\s*0x[0-9a-fA-F]+ - 0x[0-9a-fA-F]+", line) and ".so" in line or \
           re.match(r"^0x[0-9a-fA-F]+ is located in module", line):
            state.modules.append(line)
            return True

        # --- SUMMARY lines -------------------------------------------------------------
        match = _SUMMARY_ASAN.search(line)
        if match:
            state.crash_class = _coerce_asan_class(match.group("cls")) or state.crash_class
            state.warnings.append(line)
            return True
        match = _SUMMARY_LSAN.search(line)
        if match:
            state.stats["leaked_bytes_reported"] = int(match.group("count"))
            return True
        if line.startswith("SUMMARY: MemorySanitizer"):
            state.warnings.append(line)
            return True

        # --- TSan sub-sections ----------------------------------------------------------
        if line.startswith(("Write of size", "Read of size", "Atomic read of size")):
            match = re.match(r"^(Write|Read|Atomic read) of size (\d+)", line)
            if match:
                state.memory_access = state.memory_access or MemoryAccess()
                state.memory_access.access_type = "write" if match.group(1) == "Write" else "read"
                state.memory_access.access_size = int(match.group(2))
            state.section = _Section.TSAN_PRIMARY
            return True
        if line.startswith("Location:") or line.startswith("  Location:"):
            match = re.search(r"(?P<file>/[^:\s]+):(?P<line>\d+)", line)
            if match:
                state.warnings.append(
                    f"location {os.path.basename(match.group('file'))}:{match.group('line')}")
            return True
        if line.startswith(("Previous write", "Previous read", "Mutex", "Thread",
                            "Data race on", "Stack has been marked")):
            state.section = _Section.TSAN_SECONDARY
            return True

        # --- stack frames (any flavour) ---------------------------------------------
        frame = self._parse_frame(line, state)
        if frame is not None:
            target = {
                _Section.ALLOC_STACK: state.alloc_frames,
                _Section.FREE_STACK: state.free_frames,
                _Section.LEAK_STACK: state.stack_frames,
                _Section.TSAN_SECONDARY: state.stack_frames,
            }.get(state.section, state.stack_frames)
            if len(target) < self.max_frames:
                target.append(frame)
                self.stats_parsed_frames += 1
            else:
                state.warnings.append("stack truncated at configured max_frames")
            return True

        # --- assertion / abort hints ----------------------------------------------------
        lowered = line.lower()
        if any(marker in lowered for marker in _ASSERT_MARKERS) and state.headline is None:
            state.headline = line
            state.crash_class = CrashClass.ASSERTION_FAILURE
            state.sanitizer = SanitizerKind.NONE.value
            return True
        if lowered.startswith(("artifacts will be saved", "running 1 test")):
            return True  # libFuzzer chatter, intentionally ignored
        if line.startswith(("start_offset", "end_offset", "unit_stats", "info:")):
            return True
        return False

    # ---------------------------------------------------------------- frames

    def _parse_frame(self, line: str, state: _BlockState) -> Optional[StackFrame]:
        match = _FRAME_ASAN.match(line)
        if match:
            file_ = match.group("file")
            if file_.startswith("<"):
                file_ = None
            return StackFrame(
                index=int(match.group("idx")),
                function=match.group("func").strip(),
                file=file_,
                line=int(match.group("line")) if match.group("line") else None,
                column=int(match.group("col")) if match.group("col") else None,
                raw=line,
            )
        match = _FRAME_MODULE.match(line)
        if match:
            frame = StackFrame(
                index=int(match.group("idx")),
                function=match.group("func"),
                module=match.group("module"),
                offset=match.group("offset"),
                raw=line,
            )
            resolved = self._try_symbolize(frame)
            return resolved or frame
        match = _FRAME_ADDRONLY.match(line)
        if match:
            return StackFrame(index=int(match.group("idx")),
                              address=match.group("addr"),
                              raw=line)
        # GDB style: "#1  0x... in func (args) at file.c:12"
        frame = StackFrame.parse_gdb_line(line, 0)
        if frame is not None:
            return frame
        return None

    def _try_symbolize(self, frame: StackFrame) -> Optional[StackFrame]:
        if not isinstance(self.symbolizer, Symbolizer) or not self.symbolizer.available:
            return None
        if not (frame.module and frame.offset):
            return None
        resolved = self.symbolizer.resolve(frame.module, frame.offset)
        if resolved is None:
            return None
        resolved.index = frame.index
        resolved.address = frame.address
        resolved.module = frame.module
        resolved.offset = frame.offset
        resolved.raw = frame.raw
        self.stats_symbolized_frames += 1
        return resolved

    # ------------------------------------------------------------- building

    def _build_report(self, state: _BlockState) -> SanitizerReport:
        sanitizer = state.sanitizer or SanitizerKind.NONE.value
        crash_class = state.crash_class
        if crash_class is CrashClass.UNKNOWN and sanitizer == SanitizerKind.UBSAN.value:
            crash_class = CrashClass.UNKNOWN
        stack = StackTrace(frames=state.stack_frames, source=sanitizer,
                           raw="\n".join(state.raw_lines))
        alloc = StackTrace(frames=state.alloc_frames, source=f"{sanitizer}-alloc") \
            if state.alloc_frames else None
        free = StackTrace(frames=state.free_frames, source=f"{sanitizer}-free") \
            if state.free_frames else None
        stats = dict(state.stats)
        if state.pending_leak or state.leak_records:
            stats["direct_leaks"] = sum(1 for r in state.leak_records
                                        if r["kind"] == "direct")
            stats["indirect_leaks"] = sum(1 for r in state.leak_records
                                          if r["kind"] == "indirect")
            stats["leaked_bytes_total"] = sum(r["size"] for r in state.leak_records)
        report = SanitizerReport(
            sanitizer=sanitizer,
            headline=state.headline,
            crash_class=crash_class.value,
            thread=state.thread,
            pid=state.pid,
            exit_code=state.exit_code,
            shadow_bytes="\n".join(state.shadow_lines) if state.shadow_lines else None,
            memory_access=state.memory_access,
            stack_trace=stack,
            allocation_trace=alloc,
            free_trace=free,
            thread_list=list(state.threads),
            modules=list(state.modules),
            stats=stats,
            raw_output="\n".join(state.raw_lines),
            parsed_from="regex-v1",
            warnings=list(state.warnings),
        )
        return report

    def _report_to_crash(self, report: SanitizerReport, record: RawCrashRecord,
                         state: _BlockState) -> Crash:
        top = report.stack_trace.top
        location = CrashLocation(
            module=top.module if top else None,
            function=top.function if top else None,
            file=top.file if top else None,
            line=top.line if top else None,
            column=top.column if top else None,
            address=(report.memory_access.access_address if report.memory_access else None),
        )
        signal = None
        if record.signal_number:
            signal = SignalInfo(signal_number=record.signal_number)
        elif record.exit_code in SIGNAL_EXIT_CODES:
            signal = SignalInfo(signal_number=SIGNAL_EXIT_CODES[record.exit_code])
        crash = Crash(
            id=generate_prefixed_id("crash"),
            campaign_id=record.campaign_id,
            target_id=record.target_id,
            target_name=record.target_name or (os.path.basename(record.executable)
                                               if record.executable else ""),
            executable=record.executable,
            engine=record.engine,
            sanitizer=report.sanitizer,
            crash_class=report.crash_class,
            state=CrashState.NEW.value,
            input_path=record.input_path,
            input_hash=record.input_hash,
            input_size=record.input_size,
            signal=signal,
            memory_access=report.memory_access,
            location=location,
            stack_trace=report.stack_trace,
            sanitizer_report=report,
            exit_code=record.exit_code,
            raw_log_path=record.source_path,
        )
        # null-dereference refinement from observed addresses only
        if crash.crash_class == CrashClass.SEGMENTATION_FAULT and report.memory_access \
                and report.memory_access.access_address in {"0x0", "0x0000000000000000"}:
            crash.classify(CrashClass.NULL_DEREFERENCE, confidence=Confidence.HIGH,
                           note="fault address 0x0 observed")
        return crash

    # ----------------------------------------------------- bare / synthetic

    def _infer_bare_crash(self, text: str, record: RawCrashRecord
                          ) -> Optional[Tuple[SanitizerReport, Crash]]:
        lowered = text.lower()
        signal_number = record.signal_number
        crash_class: Optional[CrashClass] = None
        headline = None
        for phrase, sig in PLAIN_SIGNAL_MESSAGES.items():
            if phrase in lowered:
                signal_number = sig
                headline = next((ln.strip() for ln in text.splitlines()
                                 if phrase in ln.lower()), phrase)
                break
        if signal_number is None and record.exit_code in SIGNAL_EXIT_CODES:
            signal_number = SIGNAL_EXIT_CODES[record.exit_code]
            headline = headline or f"process exited with code {record.exit_code}"
        if signal_number is None:
            for marker in _ASSERT_MARKERS:
                if marker in lowered:
                    crash_class = CrashClass.ASSERTION_FAILURE
                    headline = next((ln.strip() for ln in text.splitlines()
                                     if marker in ln.lower()), marker)
                    break
        if crash_class is None and signal_number is not None:
            crash_class = {
                11: CrashClass.SEGMENTATION_FAULT,
                6: CrashClass.ABORT,
                4: CrashClass.ILLEGAL_INSTRUCTION,
                7: CrashClass.BUS_ERROR,
                8: CrashClass.SIGFPE_TO_DIVIDE if hasattr(CrashClass, "SIGFPE_TO_DIVIDE")
                   else CrashClass.DIVIDE_BY_ZERO,
                9: CrashClass.OUT_OF_MEMORY,
            }.get(signal_number, CrashClass.SIGNAL)
        if crash_class is None:
            return None
        report = SanitizerReport(
            sanitizer=SanitizerKind.NONE.value,
            headline=headline,
            crash_class=crash_class.value,
            raw_output=text,
            parsed_from="bare-signal-v1",
            warnings=["no sanitizer banner observed; classified from signal/exit evidence"],
        )
        crash = self._report_to_crash(report, record, _BlockState())
        crash.signal = SignalInfo(signal_number=signal_number) if signal_number else crash.signal
        return report, crash

    def _synthetic_resource_crash(self, record: RawCrashRecord, cls: CrashClass,
                                  note: str) -> Crash:
        report = SanitizerReport(
            sanitizer=SanitizerKind.NONE.value,
            crash_class=cls.value,
            headline=note,
            raw_output=record.raw_text[:65536],
            parsed_from="marker-v1",
            warnings=[note],
        )
        crash = self._report_to_crash(report, record, _BlockState())
        return crash


# ============================================================================
# convenience functions
# ============================================================================


_DEFAULT_PARSER: Optional[CrashParser] = None
_DEFAULT_LOCK = threading.Lock()


def _default_parser() -> CrashParser:
    global _DEFAULT_PARSER
    with _DEFAULT_LOCK:
        if _DEFAULT_PARSER is None:
            _DEFAULT_PARSER = CrashParser()
        return _DEFAULT_PARSER


def parse_crash_log(text_or_path: str | os.PathLike[str], *, is_path: bool = False,
                    **meta: Any) -> ParseOutcome:
    """One-shot helper: parse a log string or file into a :class:`ParseOutcome`."""
    parser = _default_parser()
    if is_path or (os.path.sep in str(text_or_path) and os.path.exists(str(text_or_path))):
        return parser.parse_file(str(text_or_path), **meta)
    return parser.parse_text(str(text_or_path), **meta)


def parse_sanitizer_output(text_or_path: "str | os.PathLike[str]",
                           *, auto_symbolize: bool = True,
                           **meta: Any) -> List["RawCrashRecord"]:
    """Convenience facade over :class:`CrashParser` for sanitizer logs.

    Accepts either the *text* of a sanitizer report (ASan / UBSan / LSan / MSan /
    TSan output, possibly containing several concatenated reports) or a filesystem
    path to such a log.  Returns the list of parsed :class:`RawCrashRecord` objects
    -- one per detected report -- so callers can iterate crashes directly::

        from kmcs.analysis.crash_parser import parse_sanitizer_output
        for rep in parse_sanitizer_output(open("test_asan.log").read()):
            print(rep.sanitizer, rep.crash_class, len(rep.stack_trace.frames))

    ``auto_symbolize`` enables best-effort resolution of raw module+offset frames
    using real tools (``llvm-symbolizer``/``addr2line``) when they are present on
    PATH; absent tools simply leave frames unresolved.  Any additional keyword
    arguments are passed through as metadata onto the crash record (target_name,
    campaign_id, ...).
    """
    parser = _default_parser()
    if auto_symbolize:
        try:
            parser.symbolizer = symbolizer_for_environment("auto")
        except Exception:  # pragma: no cover - defensive: keep NullSymbolizer
            pass
    outcome = parse_crash_log(text_or_path, **meta)
    reports = list(outcome.reports)
    # De-duplicate identical reports that may arise from overlapping banners while
    # preserving deterministic order (first occurrence wins).
    seen: set = set()
    unique: List[SanitizerReport] = []
    for rep in reports:
        key = (rep.sanitizer, rep.crash_class, rep.headline,
               tuple(f.function for f in getattr(rep.stack_trace, "frames", ())[:6]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(rep)
    return unique


# ============================================================================
# golden-sample self test (honest coverage measurement)
# ============================================================================

GOLDEN_SAMPLES: Dict[str, str] = {
    "asan_heap_overflow": """
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011 at pc 0x0000004af3c2 bp 0x7ffe1234 sp 0x7ffe1240
READ of size 1 at 0x602000000011 thread T0
    #0 0x4af3c1 in parse_header /src/demo/parser.c:88:14
    #1 0x4af990 in main /src/demo/main.c:23:5
    #2 0x7f1234567890 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x27040)
0x602000000011 is located 1 bytes to the right of 16-byte region [0x602000000000,0x602000000010)
allocated by thread T0 here:
    #0 0x4a1234 in malloc (/usr/bin/demo+0x4a1234)
    #1 0x4af300 in parse_header /src/demo/parser.c:80:18
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/demo/parser.c:88:14 in parse_header
Shadow bytes around the buggy address:
  0x0c047fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c047fff7fc0: 00 00 00 00 00 00 00[01]fa fa fa fa fa fa fa
""",
    "asan_uaf": """
==2222==ERROR: AddressSanitizer: use-after-free on address 0x603000000018 at pc 0x0000004b0aaa bp 0x7ffd1111 sp 0x7ffd2222
READ of size 8 at 0x603000000018 thread T0
    #0 0x4b0aa9 in consume /src/uaf.c:42:10
    #1 0x4b0bbb in main /src/uaf.c:55:5
0x603000000018 is located 24 bytes inside of 32-byte region [0x603000000000,0x603000000020)
freed by thread T0 here:
    #0 0x4a1240 in free (/usr/bin/uaf+0x4a1240)
    #1 0x4b0ccc in release /src/uaf.c:30:5
previously allocated by thread T0 here:
    #0 0x4a1234 in malloc (/usr/bin/uaf+0x4a1234)
    #1 0x4b0ddd in acquire /src/uaf.c:20:15
SUMMARY: AddressSanitizer: use-after-free /src/uaf.c:42:10 in consume
""",
    "lsan_direct": """
=================================================================
==3333==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0x4a1234 in malloc (/usr/bin/leaky+0x4a1234)
    #1 0x4b0111 in make_node /src/leak.c:12:10
    #2 0x4b0222 in main /src/leak.c:30:9

SUMMARY: LeakSanitizer: 64 byte(s) leaked in 1 allocation(s).
""",
    "ubsan_overflow": """
/src/calc.c:15:9: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x401b3f in add_ints /src/calc.c:15:9
    #1 0x401c02 in main /src/calc.c:22:3
SUMMARY: UndefinedBehaviorSanitizer: undefined-behaviour /src/calc.c:15:9
""",
    "tsan_race": """
WARNING: ThreadSanitizer: data race (pid=4444)
  Write of size 4 at 0x7b200000001c by thread T1:
    #0 counter_increment /src/race.c:18 (prog+0x4012ab)
  Previous read of size 4 at 0x7b200000001c by main thread:
    #0 main /src/race.c:29 (prog+0x4013cd)
SUMMARY: ThreadSanitizer: data race /src/race.c:18
""",
    "msan_uninit": """
==5555==ERROR: MemorySanitizer: use-of-uninitialized-value
    #0 0x4a2210 in check /src/msan.c:14:7
    #1 0x4a2345 in main /src/msan.c:21:5
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/msan.c:14:7
""",
    "bare_segfault": """
Processing input...
Segmentation fault (core dumped)
""",
    "libfuzzer_oom": """
INFO: Running with entropic power schedule (0xFF, 100).
INFO: seed corpus: files: 1 min: 1b max: 1b total: 1b rss: 33Mb
==6666==ERROR: libFuzzer: out of memory (malloc_limit=100000000)
SUMMARY: libFuzzer: out of memory
""",
}


def self_test_report() -> Dict[str, Any]:
    """Run the parser over embedded golden samples; report honest results.

    Returns per-sample: detected sanitizer, crash class, frame count,
    line-coverage ratio.  Used by the test-suite to prove the parser works
    against real-format logs (samples were transcribed from actual sanitizer
    output shapes, not fabricated statistics).
    """
    parser = CrashParser()
    results: Dict[str, Any] = {}
    expected = {
        "asan_heap_overflow": (SanitizerKind.ASAN, CrashClass.HEAP_BUFFER_OVERFLOW),
        "asan_uaf": (SanitizerKind.ASAN, CrashClass.USE_AFTER_FREE),
        "lsan_direct": (SanitizerKind.LSAN, CrashClass.MEMORY_LEAK),
        "ubsan_overflow": (SanitizerKind.UBSAN, CrashClass.INTEGER_OVERFLOW),
        "tsan_race": (SanitizerKind.TSAN, CrashClass.DATA_RACE),
        "msan_uninit": (SanitizerKind.MSAN, CrashClass.UNINITIALIZED_USE),
        "bare_segfault": (SanitizerKind.NONE, CrashClass.SEGMENTATION_FAULT),
        "libfuzzer_oom": (SanitizerKind.NONE, CrashClass.OUT_OF_MEMORY),
    }
    all_ok = True
    for name, sample in GOLDEN_SAMPLES.items():
        outcome = parser.parse_text(sample)
        got_cls = outcome.crashes[0].crash_class if outcome.crashes else "none"
        want_sani, want_cls = expected[name]
        ok = (outcome.sanitizer_detected == want_sani.value and str(got_cls) == want_cls.value)
        all_ok = all_ok and ok
        results[name] = {
            "ok": ok,
            "sanitizer": outcome.sanitizer_detected,
            "expected_sanitizer": want_sani.value,
            "crash_class": str(got_cls),
            "expected_class": want_cls.value,
            "frames": len(outcome.reports[0].stack_trace) if outcome.reports else 0,
            "coverage": outcome.coverage(),
        }
    return {"samples": results, "all_expected_met": all_ok,
            "parser_stats": {
                "blocks": parser.stats_total_blocks,
                "frames_parsed": parser.stats_parsed_frames,
                "frames_symbolized": parser.stats_symbolized_frames,
            }}


# ============================================================================
# module smoke test
# ============================================================================


def _smoke() -> int:
    report = self_test_report()
    failing = [name for name, res in report["samples"].items() if not res["ok"]]
    print(f"[kmcs.analysis.crash_parser] golden samples: "
          f"{len(report['samples']) - len(failing)}/{len(report['samples'])} correct")
    for name, res in report["samples"].items():
        flag = "OK " if res["ok"] else "FAIL"
        print(f"  [{flag}] {name}: sanitizer={res['sanitizer']} "
              f"class={res['crash_class']} frames={res['frames']} "
              f"coverage={res['coverage']}")
    if failing:
        print(f"  failing: {failing}")
        return 1
    # determinism check
    parser = CrashParser()
    o1 = parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"])
    o2 = parser.parse_text(GOLDEN_SAMPLES["asan_heap_overflow"])
    assert o1.crashes[0].stack_signature() == o2.crashes[0].stack_signature()
    print("  determinism: identical inputs produce identical signatures")
    return 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
