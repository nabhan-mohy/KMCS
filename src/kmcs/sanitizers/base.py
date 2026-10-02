"""KMCS sanitizer foundation — shared contract for every sanitizer adapter.

This module is the backbone of the KMCS sanitizers package (Phase 5a).  It
defines how KMCS talks to compiler memory-safety sanitizers
(AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer,
MemorySanitizer, ThreadSanitizer, HWASan) in a *defensive, analysis-only* way:

1. **Environment policy** — build ``ASAN_OPTIONS``-style environment strings
   for child processes with fuzzing-appropriate defaults, campaign options,
   operator overrides and hard-won invariant options that must never be
   disabled mid-campaign.
2. **Report parsing** — turn raw sanitizer console output into structured
   :class:`SanitizedCrash` records: error kind, crash class, access size,
   fault address, allocation/free stacks, thread labels, shadow bytes and
   statistics lines.  Parsing is pure-function based so it can be unit tested
   without spawning any process.
3. **Symbolisation** — optionally pipe raw reports through
   ``llvm-symbolizer`` (a real subprocess; honestly reported as unavailable
   when the tool is missing — KMCS never fabricates symbols).
4. **Classification hooks** — map sanitizer error names onto KMCS
   :class:`~kmcs.core.models.CrashClass` values used by the later analysis
   pipeline (fingerprinting / dedup / severity live in ``kmcs.analysis``).

Security posture
----------------
KMCS only *reads and structures* sanitizer diagnostics produced during
authorized fuzzing campaigns.  Nothing here crafts exploit payloads,
shellcode or weaponised inputs.  Malformed inputs are produced exclusively
by legitimate fuzzing engines configured by the researcher.

Zero external services: standard library plus KMCS core models/exceptions
only — no API keys, no network.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from abc import ABC
from dataclasses import dataclass, field
from enum import Enum, unique
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.exceptions import ConfigurationError, KMCSValueError
from kmcs.core.models import CrashClass, SanitizerKind

__all__ = [
    "UNKNOWN_INT",
    "SanitizerStatus",
    "StackRole",
    "SanitizerFrame",
    "SanitizerStack",
    "SanitizedCrash",
    "SanitizerEnvPolicy",
    "SanitizerAdapter",
    "parse_options_string",
    "format_options_dict",
    "merge_options",
    "split_report_blocks",
    "SUMMARY_RE",
    "LOOSE_SUMMARY_RE",
    "SUMMARY_LINE_RE",
    "STATS_RE",
    "THREADED_HEADER_RE",
    "ALLOC_STAT_RE",
    "ACCESS_RE",
    "FRAME_AT_RE",
    "TSAN_FRAME_RE",
    "ASAN_ERROR_CLASSES",
    "UBSAN_ERROR_CLASSES",
    "TSAN_ERROR_CLASSES",
    "MSAN_ERROR_CLASSES",
    "LSAN_ERROR_CLASSES",
    "SANITIZER_TAG_ALIASES",
    "extract_error_kind_from_summary",
    "normalise_frames_in_text",
    "symbolize_report",
    "register_adapter",
    "get_adapter",
    "all_adapters",
    "adapter_for_kind",
    "ADAPTER_REGISTRY",
]

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

#: Sentinel used when an integer attribute is unknown rather than zero.
UNKNOWN_INT = -1


def _dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_options_string(text: str) -> Dict[str, str]:
    """Parse a sanitizer ``*_OPTIONS`` value into an ordered dict.

    Handles the common grammar ``key=value:key2=value2:...`` including:

    * empty segments (tolerated),
    * values containing ``=`` (split on first ``=`` only),
    * bare flags without ``=`` which are recorded as ``"1"``,
    * whitespace around separators (stripped).

    >>> parse_options_string("halt_on_error=1:detect_leaks=0")
    {'halt_on_error': '1', 'detect_leaks': '0'}
    """
    result: Dict[str, str] = {}
    if not text:
        return result
    for segment in text.split(":"):
        segment = segment.strip()
        if not segment:
            continue
        if "=" in segment:
            key, _, value = segment.partition("=")
            key = key.strip()
            if not key:
                continue
            result[key] = value.strip()
        else:
            # Bare token such as "verbosity" is interpreted as enabled.
            result[segment] = "1"
    return result


def format_options_dict(options: Mapping[str, object]) -> str:
    """Serialise an options mapping back into a sanitizer env string."""
    parts: List[str] = []
    for key, value in options.items():
        if value is None:
            continue
        parts.append(f"{key}={value}")
    return ":".join(parts)


def merge_options(
    base: Mapping[str, object],
    override: Mapping[str, object],
    *,
    locked: Sequence[str] = (),
) -> Dict[str, str]:
    """Merge two option mappings, honouring *locked* keys.

    ``locked`` keys always keep the *base* value: these encode invariants the
    adapter refuses to let operators break (for instance disabling the ASan
    allocator shim while fuzzing would silently mask use-after-free bugs).
    Conflicts between option *values* are surfaced by
    :meth:`SanitizerEnvPolicy.validate`; here locked keys are simply
    preserved so an override can never weaken a hard-won invariant.
    """
    merged = {str(k): str(v) for k, v in base.items() if v is not None}
    locked_set = set(locked)
    for key, value in override.items():
        if value is None:
            continue
        if str(key) in locked_set:
            continue
        merged[str(key)] = str(value)
    return merged


# ---------------------------------------------------------------------------
# Statuses & enums
# ---------------------------------------------------------------------------


@unique
class SanitizerStatus(str, Enum):
    """Lifecycle status of a sanitizer adapter relative to the current host."""

    SUPPORTED = "supported"          # KMCS knows how to drive it here
    UNAVAILABLE = "unavailable"      # known, but toolchain lacks it on this host
    INCOMPATIBLE = "incompatible"    # cannot coexist with another requested sanitizer
    EXPERIMENTAL = "experimental"    # wired up but not battle-tested
    DISABLED = "disabled"            # turned off by configuration


@unique
class StackRole(str, Enum):
    """Which logical stack a parsed sanitizer trace represents."""

    CRASH = "crash"                       # where the bad access happened
    ALLOCATION = "allocation"             # alloc site printed by the tool
    SECOND_ALLOCATION = "second_allocation"
    PRECEDING_FREE = "preceding_free"     # ASan "freed by thread T0 here"
    DEALLOCATED_BY = "deallocated_by"
    SHARED_OWNER = "shared_owner"         # HWASan shared ownership traces
    ORIGIN = "origin"                     # MSAN uninitialised-value origin
    THREAD_CREATED = "thread_created"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Structured report model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SanitizerFrame:
    """A single parsed stack frame from a sanitizer trace."""

    index: int = UNKNOWN_INT
    address: Optional[str] = None          # hex string, prefix optional
    module: Optional[str] = None           # binary/object name
    function: Optional[str] = None         # possibly demangled C++ name
    file: Optional[str] = None
    line: int = UNKNOWN_INT
    column: int = UNKNOWN_INT
    raw: str = ""                          # original text line (lossless)
    symbolized: bool = False               # touched by llvm-symbolizer step

    def short(self) -> str:
        if self.function:
            loc = (
                f"{self.file}:{self.line}"
                if self.file and self.line >= 0
                else (self.file or "")
            )
            return f"{self.function} ({loc})" if loc else self.function
        if self.module and self.address:
            return f"{self.module}+{self.address}"
        if self.address:
            return f"0x{self.address}"
        return self.raw.strip() or "<frame?>"


@dataclass(slots=True)
class SanitizerStack:
    """One named stack trace inside a sanitizer report."""

    role: StackRole = StackRole.CRASH
    thread: Optional[str] = None           # e.g. "T0"
    frames: List[SanitizerFrame] = field(default_factory=list)

    def top_frames(self, count: int = 4) -> List[SanitizerFrame]:
        return self.frames[:count]

    def signature_lines(self, count: int = 4) -> List[str]:
        return [f.short() for f in self.top_frames(count)]


@dataclass(slots=True)
class SanitizedCrash:
    """Structured view of one sanitizer report block.

    This is the currency between the ``sanitizers`` package (who parses) and
    the ``analysis`` package (who classifies/fingerprints).  It keeps the
    *raw* text so nothing is lost, while exposing the fields KMCS needs for
    deduplication and reporting.
    """

    sanitizer: SanitizerKind = SanitizerKind.NONE
    error_kind: str = ""                    # e.g. "heap-use-after-free"
    crash_class: Optional[CrashClass] = None
    summary: str = ""                       # the "ERROR: ..." headline
    exit_code: Optional[int] = None
    pid: Optional[int] = None
    thread: Optional[str] = None            # crashing thread label ("T0")
    fault_address: Optional[str] = None     # hex, normalised lowercase w/o 0x
    access_size: Optional[int] = None
    access_type: Optional[str] = None       # read / write / free / alloc
    allocation_size: Optional[int] = None
    shadow_bytes: List[str] = field(default_factory=list)
    shadow_line: Optional[str] = None
    stacks: List[SanitizerStack] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    extra: Dict[str, str] = field(default_factory=dict)
    raw_text: str = ""
    source_path: Optional[str] = None       # log file it was parsed from
    truncated: bool = False                 # hit parser size limits

    # -- convenience -----------------------------------------------------
    @property
    def crash_stack(self) -> Optional[SanitizerStack]:
        for stack in self.stacks:
            if stack.role is StackRole.CRASH:
                return stack
        return self.stacks[0] if self.stacks else None

    @property
    def allocation_stack(self) -> Optional[SanitizerStack]:
        for stack in self.stacks:
            if stack.role in (StackRole.ALLOCATION, StackRole.PRECEDING_FREE):
                return stack
        return None

    def frame_signatures(self, depth: int = 4) -> List[str]:
        stack = self.crash_stack
        return stack.signature_lines(depth) if stack else []

    def to_dict(self) -> Dict[str, object]:
        return {
            "sanitizer": str(self.sanitizer.value),
            "error_kind": self.error_kind,
            "crash_class": str(self.crash_class.value) if self.crash_class else None,
            "summary": self.summary,
            "exit_code": self.exit_code,
            "pid": self.pid,
            "thread": self.thread,
            "fault_address": self.fault_address,
            "access_size": self.access_size,
            "access_type": self.access_type,
            "allocation_size": self.allocation_size,
            "shadow_bytes": list(self.shadow_bytes),
            "stats": dict(self.stats),
            "extra": dict(self.extra),
            "truncated": self.truncated,
            "source_path": self.source_path,
            "stacks": [
                {
                    "role": str(stack.role.value),
                    "thread": stack.thread,
                    "frames": [f.short() for f in stack.frames],
                }
                for stack in self.stacks
            ],
        }


# ---------------------------------------------------------------------------
# Shared regexes (LLVM-family grammar)
# ---------------------------------------------------------------------------

#: Headline of a threaded sanitizer report: "==1234==ERROR: AddressSanitizer: ..."
SUMMARY_RE = re.compile(
    r"^(?:==(?P<pid>\d+)==|\[(?P<pid2>\d+)\])?\s*"
    r"(?:(?P<tool>Address|Memory|Thread|Leak|Undefined|HWAddress)Sanitizer(?:\[[^\]]*\])?:\s*)?"
    r"ERROR:\s*"
    r"(?P<san>address|leak|memory|thread|undefined|hwaddress|libfuzzer)"
    r"(?:[^:\s]*)?(?:\([^)]*\))?:\s*"
    r"(?P<error>[A-Za-z][A-Za-z0-9_\-]*)(?P<rest>.*)$",
    re.MULTILINE,
)

#: Simpler fallback matching any "ERROR: <x>-sanitizer: <kind>" anywhere.
LOOSE_SUMMARY_RE = re.compile(
    r"ERROR:\s*(address|leak|memory|thread|undefined|hwaddress|HWAddress|libfuzzer|LibFuzzer)"
    r"(?:[^:\s]*)?(?:\([^)]*\))?:?\s*"
    r"((?:detected memory leaks)|[A-Za-z][A-Za-z0-9_\-]*)",
)

#: "SUMMARY: AddressSanitizer: heap-buffer-overflow file.cpp:12 in foo()"
SUMMARY_LINE_RE = re.compile(
    r"^SUMMARY:\s*([A-Za-z ]*Sanitizer):\s*([\w\-]+)\s+(.*)$", re.MULTILINE
)

#: LSAN/ASan leak totals: "88 byte(s) leaked in 2 allocation(s)."
LEAK_LEAK_RE = re.compile(r"(\d+)\s+byte\(s\) leaked (?:by|in)\s+(\d+)\s+allocation\(s\)")
#: Region size hint: "inside of 8-byte region"
REGION_SIZE_RE = re.compile(r"(?:inside|outside)\s+of\s+(\d+)-byte region")
ALLOC_STAT_RE = re.compile(r"^\s*stat(\w+):\s*(\d+)", re.MULTILINE)
SHADOW_BYTES_RE = re.compile(r"[0-9a-fA-F]{2}(?:[\s\[\]]+[0-9a-fA-F]{2})*")
ADDRESS_IN_TEXT_RE = re.compile(r"0x([0-9a-fA-F]{6,16})")

#: Threaded header: "==1234==ERROR: AddressSanitizer: ..."
THREADED_HEADER_RE = re.compile(r"==(\d+)==ERROR:")

#: "#0 foo at /path/file.c:12" (ASan/LSan/MSan frame form)
FRAME_AT_RE = re.compile(
    r"#(\d+)\s+(0x[0-9a-fA-F]+\s+)?(.+?)\s+at\s+(\S+):(\d+)(?::(\d+))?"
)
#: "/path/bin(func+0x10)" older glibc-style frames
FRAME_PAREN_RE = re.compile(r"^(.+?)\(([^()+]+)\+0x([0-9a-fA-F]+)\)")
#: TSan frame: "    foo bar.c:12:7 (bin+0x1234)"
TSAN_FRAME_RE = re.compile(
    r"^\s{2,8}(\S+)\s+(\S+?):(\d+):(\d+)\s+\((\S+)\+0x([0-9a-fA-F]+)\)\s*$"
)

#: Access info line: "READ of size 4 at 0x7f... thread T0"
ACCESS_RE = re.compile(
    r"(READ|WRITE|FREE|ALLOC|DEALLOC) of size (\d+) at (0x[0-9a-fA-F]+)"
    r"(?:\s+on)?(?:\s+thread\s+(T\d+))?(?:\s+by\s+thread\s+(T\d+))?"
)
#: HWASan variant "Access of size 4 at 0x..."
HWASAN_ACCESS_RE = re.compile(r"Access of size (\d+) at (0x[0-9a-fA-F]+)")

#: "allocated by thread T0 here:" / "freed by thread T0 here:" ...
_STACK_HEADER_RES: List[Tuple[re.Pattern, StackRole]] = [
    (re.compile(r"previously allocated by thread (T\d+) here:"), StackRole.SECOND_ALLOCATION),
    (re.compile(r"allocated by thread (T\d+) here:"), StackRole.ALLOCATION),
    (re.compile(r"freed by thread (T\d+) here:"), StackRole.PRECEDING_FREE),
    (re.compile(r"deallocated by thread (T\d+) here:"), StackRole.DEALLOCATED_BY),
    (re.compile(r"Memory is also owned by .* \(T(\d+)\)"), StackRole.SHARED_OWNER),
    (re.compile(r"Thread T\d+ \('([^']*)'\) created by T\d+ here:"), StackRole.THREAD_CREATED),
]

#: MSan origin headers
MSAN_ORIGIN_RES: List[Tuple[re.Pattern, StackRole]] = [
    (re.compile(r"Uninitialized value was stored to memory at"), StackRole.OTHER),
    (re.compile(r"Uninitialized value was created by a heap allocation"), StackRole.ALLOCATION),
    (re.compile(r"Uninitialized value was created by"), StackRole.ORIGIN),
]

STATS_RE = re.compile(r"^\s*(?:process profile:|process runtime:)", re.MULTILINE)

#: Known ASan error kinds → CrashClass
ASAN_ERROR_CLASSES: Dict[str, CrashClass] = {
    "heap-buffer-overflow": CrashClass.HEAP_BUFFER_OVERFLOW,
    "heap-buffer-underflow": CrashClass.HEAP_BUFFER_UNDERFLOW,
    "stack-buffer-overflow": CrashClass.STACK_BUFFER_OVERFLOW,
    "stack-buffer-underflow": CrashClass.STACK_BUFFER_UNDERFLOW,
    "global-buffer-overflow": CrashClass.GLOBAL_BUFFER_OVERFLOW,
    "global-buffer-underflow": CrashClass.GLOBAL_BUFFER_UNDERFLOW,
    "use-after-free": CrashClass.USE_AFTER_FREE,
    "heap-use-after-free": CrashClass.USE_AFTER_FREE,
    "stack-use-after-return": CrashClass.USE_AFTER_RETURN,
    "stack-use-after-scope": CrashClass.USE_AFTER_SCOPE,
    "use-after-scope": CrashClass.USE_AFTER_SCOPE,
    "use-after-poison": CrashClass.UNKNOWN,
    "double-free": CrashClass.DOUBLE_FREE,
    "attempting double-free": CrashClass.DOUBLE_FREE,
    "invalid-free": CrashClass.INVALID_FREE,
    "alloc-dealloc-mismatch": CrashClass.ALLOCATOR_MISUSE,
    "new-delete-type-mismatch": CrashClass.ALLOCATOR_MISUSE,
    "bad-alloc": CrashClass.OVERFLOW_ALLOC,
    "allocator-is-out-of-memory": CrashClass.OUT_OF_MEMORY,
    "container-overflow": CrashClass.UNKNOWN,
    "dynamic-stack-buffer-overflow": CrashClass.STACK_BUFFER_OVERFLOW,
    "memcpy-param-overlap": CrashClass.ALLOCATOR_MISUSE,
    "negative-size-param": CrashClass.ALLOCATOR_MISUSE,
    "zero-sized-alloc": CrashClass.ALLOCATOR_MISUSE,
    "SEGV": CrashClass.SEGMENTATION_FAULT,
    "generic-segv": CrashClass.SEGMENTATION_FAULT,
    "BUS": CrashClass.BUS_ERROR,
    "ILL": CrashClass.ILLEGAL_INSTRUCTION,
    "ABRT": CrashClass.ABORT,
    "FPE": CrashClass.DIVIDE_BY_ZERO,
    "timeout": CrashClass.TIMEOUT,
    "out-of-memory": CrashClass.OUT_OF_MEMORY,
}

UBSAN_ERROR_CLASSES: Dict[str, CrashClass] = {
    "signed-integer-overflow": CrashClass.INTEGER_OVERFLOW,
    "unsigned-integer-overflow": CrashClass.INTEGER_OVERFLOW,
    "integer-overflow": CrashClass.INTEGER_OVERFLOW,
    "shift-out-of-bounds": CrashClass.SIGNED_SHIFT_OVERFLOW,
    "left-shift-overflow": CrashClass.SIGNED_SHIFT_OVERFLOW,
    "division-by-zero": CrashClass.DIVIDE_BY_ZERO,
    "misaligned-address": CrashClass.MISALIGNED_ACCESS,
    "object-size": CrashClass.OBJECT_SIZE_VIOLATION,
    "enum-encoding-not-valid": CrashClass.ENUM_OUT_OF_RANGE,
    "unreachable": CrashClass.UNREACHABLE_CODE,
    "type-mismatch": CrashClass.TYPE_MISSMATCH,
    "function-mismatch": CrashClass.FUNCTION_TYPE_MISMATCH,
    "undefined-behavior": CrashClass.UNKNOWN,
    "null-pointer-use": CrashClass.NULL_DEREFERENCE,
    "nonnull-argument": CrashClass.NULL_ARGUMENT,
    "vla-bound-not-constant": CrashClass.VLA_BOUND_CHANGE,
    "implicit-conversion": CrashClass.INTEGER_OVERFLOW,
    "pointer-overflow": CrashClass.INTEGER_OVERFLOW,
}

TSAN_ERROR_CLASSES: Dict[str, CrashClass] = {
    "data-race": CrashClass.DATA_RACE,
    "lock-order-inversion": CrashClass.LOCK_ORDER_INVERSION,
    "signal-handler-race": CrashClass.DATA_RACE,
    "mutex-set-check-fail": CrashClass.LOCK_ORDER_INVERSION,
}

MSAN_ERROR_CLASSES: Dict[str, CrashClass] = {
    "use-of-uninitialized-value": CrashClass.UNINITIALIZED_USE,
    "param-type-mismatch": CrashClass.TYPE_MISSMATCH,
    "atomic-alignment": CrashClass.MISALIGNED_ACCESS,
}

LSAN_ERROR_CLASSES: Dict[str, CrashClass] = {
    "direct-leak": CrashClass.MEMORY_LEAK,
    "indirect-leak": CrashClass.INDIRECT_LEAK,
    "detected memory leaks": CrashClass.MEMORY_LEAK,
}

#: Canonical sanitizer-tag spelling used by adapters.
SANITIZER_TAG_ALIASES: Dict[str, SanitizerKind] = {
    "address": SanitizerKind.ASAN,
    "asan": SanitizerKind.ASAN,
    "hwaddress": SanitizerKind.HWASAN,
    "hwasan": SanitizerKind.HWASAN,
    "leak": SanitizerKind.LSAN,
    "lsan": SanitizerKind.LSAN,
    "memory": SanitizerKind.MSAN,
    "msan": SanitizerKind.MSAN,
    "thread": SanitizerKind.TSAN,
    "tsan": SanitizerKind.TSAN,
    "undefined": SanitizerKind.UBSAN,
    "ubsan": SanitizerKind.UBSAN,
}


def extract_error_kind_from_summary(text: str) -> Tuple[Optional[SanitizerKind], str]:
    """Best-effort ``(sanitizer, error_kind)`` extraction from arbitrary text.

    Returns ``(None, "")`` when nothing recognisable is present — callers must
    treat that as *unknown*, never guess a severity.
    """
    match = LOOSE_SUMMARY_RE.search(text)
    if match:
        tag = (match.group(1) or "").lower()
        kind = SANITIZER_TAG_ALIASES.get(tag, SanitizerKind.NONE)
        return kind, match.group(2)
    # Some builds print "AddressSanitizer: heap-use-after-free" without ERROR:.
    alt = re.search(
        r"(Address|Leak|Memory|Thread|Undefined|HWAddress)Sanitizer:\s*([\w\-]+)", text
    )
    if alt:
        head = alt.group(1).lower()
        table = {
            "address": SanitizerKind.ASAN,
            "leak": SanitizerKind.LSAN,
            "memory": SanitizerKind.MSAN,
            "thread": SanitizerKind.TSAN,
            "undefined": SanitizerKind.UBSAN,
            "hwaddress": SanitizerKind.HWASAN,
        }
        return table[head], alt.group(2)
    return None, ""


# ---------------------------------------------------------------------------
# Report splitting
# ---------------------------------------------------------------------------

_BLOCK_BREAK_RE = re.compile(
    r"(?=^==\d+==ERROR:)|(?=^ERROR:\s*\w+(?:[ -]?[Ss]anitizer)?)"
    r"|(?=^WARNING:\s*\w+(?:[ -]?[Ss]anitizer)?)"
    r"|(?=^\[\d+\]\s*===+\s*$)",
    re.MULTILINE,
)


def split_report_blocks(text: str) -> List[str]:
    """Split a console transcript into individual sanitizer report blocks.

    A *block* starts at a sanitizer banner (``==pid==ERROR: ...``,
    ``ERROR: <x>-sanitizer: ...``) and runs until the next banner or EOF.
    Text before the first banner is dropped (it belongs to program stdout,
    not to any report).
    """
    if not text:
        return []
    parts = _BLOCK_BREAK_RE.split(text)
    blocks = [p for p in parts if p and ("ERROR:" in p or "WARNING:" in p or "SUMMARY:" in p)]
    # Merge continuation fragments that lost their banner (rare interleaving).
    merged: List[str] = []
    for block in blocks:
        if merged and not block.lstrip().startswith(("==", "ERROR:", "[", "WARNING:")):
            merged[-1] += "\n" + block
        else:
            merged.append(block)
    return merged


# ---------------------------------------------------------------------------
# Frame parsing
# ---------------------------------------------------------------------------


def _parse_loc(loc: str) -> Tuple[Optional[str], int, int]:
    """Split ``file`` / ``file:line`` / ``file:line:col`` (robust to paths)."""
    m = re.match(r"^(.*?):(\d+):(\d+)$", loc)
    if m:
        return m.group(1), int(m.group(2)), int(m.group(3))
    m = re.match(r"^(.*?):(\d+)$", loc)
    if m:
        return m.group(1), int(m.group(2)), UNKNOWN_INT
    return loc or None, UNKNOWN_INT, UNKNOWN_INT


def _parse_in_desc(desc: str) -> SanitizerFrame:
    """Parse the ``in <func> <loc> [<more>]`` portion of a modern ASan frame."""
    desc = desc.strip()
    func: Optional[str] = None
    rest = ""
    m = re.match(r"^in\s+(.+?)\s+((?:/[\w.\-]+|[\w.\-]+\.(?:c|cc|cpp|cxx|h|hpp)(?::\d+(?::\d+)?)?|\?\?(?::\d+)?)|(?:0x[0-9a-fA-F]+))$", desc)
    if m:
        func, rest = m.group(1), m.group(2)
    else:
        m = re.match(r"^in\s+(\S+)\s*(.*)$", desc)
        if m:
            func, rest = m.group(1), m.group(2).strip()
        else:
            rest = desc
    file_, line_, col_ = (None, UNKNOWN_INT, UNKNOWN_INT)
    module: Optional[str] = None
    address: Optional[str] = None
    pm = re.match(r"^\((\S*)\+0x([0-9a-fA-F]+)\)$", rest)
    if pm:
        module, address = pm.group(1) or None, pm.group(2)
    elif rest:
        lm = re.match(r"^(.*?):(\d+)(?::(\d+))?$", rest)
        if lm:
            file_, line_, col_ = lm.group(1), int(lm.group(2)), int(lm.group(3) or UNKNOWN_INT)
        elif rest.startswith("0x"):
            address = rest[2:]
        else:
            module = rest
    return SanitizerFrame(function=func, file=file_, line=line_, column=col_,
                          module=module, address=address)


def _parse_frame_line(line: str, index: int) -> Optional[SanitizerFrame]:
    line = line.rstrip("\n")
    stripped = line.strip()
    if not stripped:
        return None
    # TSan style first: "    func dir/file.c:12:7 (bin+0x1234)"
    m = TSAN_FRAME_RE.match(line)
    if m:
        return SanitizerFrame(
            index=index, function=m.group(1), file=m.group(2),
            line=int(m.group(3)), column=int(m.group(4)),
            module=m.group(5), address=m.group(6), raw=line,
        )
    # Modern form: "#N 0xADDR in func loc [extra]" or "#N in func loc"
    m = re.match(r"#(\d+)\s+(.*)$", stripped)
    if m:
        idx, rest = int(m.group(1)), m.group(2).strip()
        address = None
        am = re.match(r"^0x([0-9a-fA-F]+)\s+(.*)$", rest)
        if am:
            address, rest = am.group(1), am.group(2).strip()
        if rest.startswith("in "):
            frame = _parse_in_desc(rest)
            frame.index = idx
            if frame.address is None:
                frame.address = address
            frame.raw = line
            return frame
        # Old glibc-ish forms below.
        mm = re.match(r"^\((\S+)\+0x([0-9a-fA-F]+)\)$", rest)
        if mm:
            return SanitizerFrame(index=idx, address=mm.group(2), module=mm.group(1), raw=line)
        om = FRAME_PAREN_RE.match(rest)
        if om:
            return SanitizerFrame(index=idx, module=om.group(1), function=om.group(2),
                                  address=om.group(3), raw=line)
        # "#N at func file:line" (FRAME_AT_RE without addr) — legacy LSan form
        fam = FRAME_AT_RE.match(stripped)
        if fam:
            file_, line_, col_ = _parse_loc(fam.group(4) + ":" + fam.group(5)
                                            + ((":" + fam.group(6)) if fam.group(6) else ""))
            return SanitizerFrame(index=idx, function=fam.group(3).strip(), file=file_,
                                  line=line_, column=col_, raw=line)
        return SanitizerFrame(index=idx, address=address,
                              function=rest or None, raw=line)
    # Legacy standalone: "#N func at /path/file.c:12" (no leading 0x)
    fam = FRAME_AT_RE.match(stripped)
    if fam:
        file_, line_, col_ = _parse_loc(fam.group(4) + ":" + fam.group(5)
                                        + ((":" + fam.group(6)) if fam.group(6) else ""))
        return SanitizerFrame(index=int(fam.group(1)), function=fam.group(3).strip(),
                              file=file_, line=line_, column=col_, raw=line)
    om = FRAME_PAREN_RE.match(stripped)
    if om:
        return SanitizerFrame(index=index, module=om.group(1), function=om.group(2),
                              address=om.group(3), raw=line)
    return SanitizerFrame(index=UNKNOWN_INT, raw=line)


def _looks_like_frame(line: str) -> bool:
    s = line.strip()
    if re.match(r"#\d+", s):
        return True
    if TSAN_FRAME_RE.match(line):
        return True
    return False


def _collect_stack(
    lines: Sequence[str], start: int, role: StackRole, thread: Optional[str]
) -> Tuple[SanitizerStack, int]:
    frames: List[SanitizerFrame] = []
    i = start
    idx = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if _looks_like_frame(line):
            frame = _parse_frame_line(line, idx)
            if frame is not None:
                frames.append(frame)
                idx += 1
            i += 1
            continue
        break
    return SanitizerStack(role=role, thread=thread, frames=frames), i


# ---------------------------------------------------------------------------
# Symbolisation (real tools, honest failure reporting)
# ---------------------------------------------------------------------------


def _find_symbolizer() -> Optional[str]:
    for name in (
        "llvm-symbolizer",
        "llvm-symbolizer-18",
        "llvm-symbolizer-17",
        "llvm-symbolizer-16",
        "llvm-symbolizer-15",
        "llvm-symbolizer-14",
    ):
        path = shutil.which(name)
        if path:
            return path
    return None


def symbolize_report(
    raw_text: str, binary: Optional[Path] = None, timeout: float = 30.0
) -> Tuple[str, bool]:
    """Pipe *raw_text* through ``llvm-symbolizer`` if available.

    Returns ``(text, did_symbolize)``.  When the tool is missing the input is
    returned unchanged with ``False`` — KMCS never fabricates symbols.
    """
    sym = _find_symbolizer()
    if not sym:
        return raw_text, False
    cmd = [sym, "--functions=linkage", "--inlining", "--demangle"]
    if binary:
        cmd += ["--obj=" + str(binary)]
    payload = _addresses_only(raw_text)
    if not payload.strip():
        return raw_text, False
    try:
        proc = subprocess.run(  # fixed argv, no shell
            cmd,
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return raw_text, False
    if proc.returncode != 0 or not proc.stdout.strip():
        return raw_text, False
    return _merge_symbolized(raw_text, proc.stdout), True


def _addresses_only(text: str) -> str:
    """Feed the symbolizer just the addresses it can resolve."""
    out: List[str] = []
    for line in text.splitlines():
        m = re.search(r"#\d+\s+0x([0-9a-fA-F]+)", line)
        if m:
            out.append(m.group(1))
    return "\n".join(out) + ("\n" if out else "")


def _merge_symbolized(original: str, symbol_output: str) -> str:
    """Annotate frame lines with resolved ``func file:line`` when supplied."""
    entries = [e.strip() for e in symbol_output.split("\n\n") if e.strip()]
    lines = original.splitlines()
    ei = 0
    for i, line in enumerate(lines):
        if ei >= len(entries):
            break
        m = re.match(r"^#\d+\s+0x[0-9a-fA-F]+", line.strip())
        if m and " at " not in line:
            parts = entries[ei].splitlines()
            func = parts[0].strip()
            loc = parts[1].strip() if len(parts) > 1 else "??:?"
            if (func and func != "??") or (loc and loc != "??:?"):
                lines[i] = f"{line.strip()} — {func} @ {loc}"
            ei += 1
    return "\n".join(lines)


def normalise_frames_in_text(text: str) -> str:
    """Normalise obvious cosmetic differences between sanitizer dialects.

    * unify ``0X`` → ``0x`` prefixes (lowercase digits),
    * collapse ``\\r\\n`` → ``\\n``,
    * strip ANSI colour codes (some CI systems keep them),
    * canonicalise ``AddressSanitizer`` spacing variants.
    """
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"0X([0-9a-fA-F]+)", lambda m: "0x" + m.group(1).lower(), text)
    text = re.sub(r"Address\s*Sanitizer", "AddressSanitizer", text)
    return text


# ---------------------------------------------------------------------------
# Environment policy
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SanitizerEnvPolicy:
    """Validated, layered sanitizer environment configuration.

    Layer precedence (highest wins unless the key is *locked*):

    1. operator-provided explicit env (``overrides``)
    2. campaign-level options (``campaign``)
    3. adapter defaults tuned for fuzzing (``defaults``)
    """

    defaults: Dict[str, str] = field(default_factory=dict)
    campaign: Dict[str, str] = field(default_factory=dict)
    overrides: Dict[str, str] = field(default_factory=dict)
    locked: Tuple[str, ...] = ()
    #: Option pairs that must NOT both be active (conflict groups).
    conflicts: Tuple[Tuple[str, str], ...] = ()

    def add_defaults(self, mapping: Mapping[str, object]) -> "SanitizerEnvPolicy":
        self.defaults.update({k: str(v) for k, v in mapping.items() if v is not None})
        return self

    def add_campaign(self, mapping: Mapping[str, object]) -> "SanitizerEnvPolicy":
        self.campaign.update({k: str(v) for k, v in mapping.items() if v is not None})
        return self

    def add_overrides(self, mapping: Mapping[str, object]) -> "SanitizerEnvPolicy":
        self.overrides.update({k: str(v) for k, v in mapping.items() if v is not None})
        return self

    def lock(self, *keys: str) -> "SanitizerEnvPolicy":
        self.locked = tuple(_dedupe_keep_order(list(self.locked) + list(keys)))
        return self

    def effective(self) -> Dict[str, str]:
        merged = merge_options(self.defaults, self.campaign, locked=self.locked)
        merged = merge_options(merged, self.overrides, locked=self.locked)
        return merged

    def validate(self) -> List[str]:
        """Return human-readable problems; raise on fatal ones."""
        problems: List[str] = []
        eff = self.effective()
        for a, b in self.conflicts:
            va = str(eff.get(a, "0")).lower()
            vb = str(eff.get(b, "0")).lower()
            if a in eff and b in eff and va not in ("0", "false", "") and vb not in ("0", "false", ""):
                problems.append(f"options '{a}' and '{b}' conflict; disable one of them")
        for layer in (self.defaults, self.campaign, self.overrides):
            for key, value in layer.items():
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(key)):
                    raise ConfigurationError(
                        f"invalid sanitizer option name {key!r}", context={"key": key}
                    )
                if value is not None and any(ch in str(value) for ch in "\n\r\x00"):
                    raise ConfigurationError(
                        f"sanitizer option {key!r} contains control characters",
                        context={"key": key},
                    )
        return problems

    def to_env(
        self,
        env_var: str,
        base_env: Optional[Mapping[str, str]] = None,
        extra_flags: Sequence[str] = (),
    ) -> Dict[str, str]:
        """Produce a child-process environment dict with the options exported.

        ``extra_flags`` such as ``detect_odr_violation=0`` are appended after
        validation.  Existing values of *env_var* in *base_env* are treated as
        campaign layer (operator overrides win over them; adapter defaults
        lose to them).
        """
        problems = self.validate()
        if problems:
            raise ConfigurationError("; ".join(problems), context={"env_var": env_var})
        base = dict(base_env or {})
        inherited = parse_options_string(base.get(env_var, ""))
        layers = SanitizerEnvPolicy(
            defaults=dict(self.defaults),
            campaign={**inherited, **self.campaign},
            overrides=dict(self.overrides),
            locked=self.locked,
            conflicts=self.conflicts,
        )
        for flag in extra_flags:
            if "=" in flag:
                k, _, v = flag.partition("=")
                layers.overrides[k.strip()] = v.strip()
        eff = layers.effective()
        base[env_var] = format_options_dict(eff)
        return base


# ---------------------------------------------------------------------------
# The adapter contract
# ---------------------------------------------------------------------------


class SanitizerAdapter(ABC):
    """Abstract driver for one sanitizer family.

    Concrete adapters (``asan.py``, ``ubsan.py`` …) supply:

    * :attr:`kind` / :attr:`env_var` — identity,
    * :meth:`default_options` — fuzzing-tuned baseline options,
    * :meth:`class_map` — error-kind → :class:`CrashClass` mapping,
    * optional :meth:`enhance` — post-parse enrichment hook.

    Parsing itself lives here because all LLVM sanitizers share ~90% of the
    report grammar; per-tool quirks are handled by small hooks.
    """

    #: Which sanitizer this adapter drives.
    kind: SanitizerKind = SanitizerKind.NONE
    #: Environment variable carrying its options.
    env_var: str = ""
    #: Compiler flag that enables it (informational; build system uses models).
    compile_flag: str = ""
    #: Human-readable display name.
    display_name: str = "sanitizer"
    #: Whether the engine requires recompilation with instrumentation.
    requires_instrumentation: bool = True
    #: Adapters whose output is a *finding* even without a crash signal.
    reports_without_crash: bool = False

    # ---------------- construction helpers ----------------

    def make_policy(self) -> SanitizerEnvPolicy:
        policy = SanitizerEnvPolicy(conflicts=self.option_conflicts())
        policy.add_defaults(self.default_options())
        policy.lock(*self.locked_options())
        return policy

    def default_options(self) -> Dict[str, object]:
        """Baseline options suitable for fuzzing campaigns."""
        return {}

    def locked_options(self) -> Tuple[str, ...]:
        """Option names operators may not change mid-campaign."""
        return ()

    def option_conflicts(self) -> Tuple[Tuple[str, str], ...]:
        return ()

    def prepare_environment(
        self,
        env: Optional[Mapping[str, str]] = None,
        *,
        campaign_options: Optional[Mapping[str, object]] = None,
        overrides: Optional[Mapping[str, object]] = None,
        extra_flags: Sequence[str] = (),
    ) -> Dict[str, str]:
        """Build the full child environment for running an instrumented target."""
        policy = self.make_policy()
        if campaign_options:
            policy.add_campaign(campaign_options)
        if overrides:
            policy.add_overrides(overrides)
        base = dict(env if env is not None else os.environ)
        if not self.env_var:
            return base
        return policy.to_env(self.env_var, base, extra_flags)

    # ---------------- classification ----------------

    def classify(self, error_kind: str) -> Optional[CrashClass]:
        mapping = self.class_map()
        kind_norm = (error_kind or "").strip().lower()
        if kind_norm in mapping:
            return mapping[kind_norm]
        # Exact-case fallback for spellings like "SEGV"/"ABRT".
        if error_kind in mapping:
            return mapping[error_kind]
        # Prefix fallback: "heap-buffer-overflow-read" etc. Longest key wins.
        for key, cls in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
            if kind_norm.startswith(key.lower()):
                return cls
        return None

    def class_map(self) -> Dict[str, CrashClass]:
        return {}

    # ---------------- parsing ----------------

    def parse_report(
        self,
        text: str,
        *,
        source_path: Optional[str] = None,
        exit_code: Optional[int] = None,
        symbolize: bool = False,
        binary: Optional[Path] = None,
    ) -> List[SanitizedCrash]:
        """Parse *text* into zero or more :class:`SanitizedCrash` records."""
        crashes: List[SanitizedCrash] = []
        for block in split_report_blocks(normalise_frames_in_text(text)):
            crash = self._parse_block(block, source_path=source_path, exit_code=exit_code)
            if crash is None:
                continue
            if symbolize:
                new_raw, did = symbolize_report(crash.raw_text, binary)
                if did:
                    crash.raw_text = new_raw
                    for stack in crash.stacks:
                        for frame in stack.frames:
                            if "—" in frame.raw:
                                frame.symbolized = True
            self.enhance(crash)
            crashes.append(crash)
        return crashes

    def parse_log_file(self, path: Path, **kwargs) -> List[SanitizedCrash]:
        try:
            text = Path(path).read_text(errors="replace")
        except OSError as exc:
            raise KMCSValueError(
                f"cannot read sanitizer log {path}: {exc}", context={"path": str(path)}
            ) from exc
        return self.parse_report(text, source_path=str(path), **kwargs)

    # Hooks ---------------------------------------------------------------

    def enhance(self, crash: SanitizedCrash) -> None:
        """Adapter-specific post-processing (override freely)."""

    # Block parser --------------------------------------------------------

    def _parse_block(
        self, block: str, *, source_path: Optional[str], exit_code: Optional[int]
    ) -> Optional[SanitizedCrash]:
        crash = SanitizedCrash(
            sanitizer=self.kind, raw_text=block, source_path=source_path, exit_code=exit_code
        )
        lines = block.splitlines()

        # ---- headline
        headline_seen = False
        desc: Optional[str] = None
        for line in lines:
            m = SUMMARY_RE.match(line.strip())
            loose = False
            if not m:
                m = LOOSE_SUMMARY_RE.search(line)
                loose = m is not None
            if m:
                if loose:
                    tag = (m.group(1) or "").lower()
                    crash.sanitizer = SANITIZER_TAG_ALIASES.get(tag, crash.sanitizer)
                    crash.error_kind = m.group(2)
                    desc = None
                else:
                    groups = m.groupdict()
                    san_tag = (groups.get("san") or "").lower()
                    if not san_tag and groups.get("tool"):
                        san_tag = groups["tool"].lower()
                    crash.sanitizer = SANITIZER_TAG_ALIASES.get(san_tag, crash.sanitizer)
                    crash.error_kind = groups.get("error") or ""
                    rest = (groups.get("rest") or "").strip()
                    if crash.error_kind == "detected" and rest.startswith("memory leaks"):
                        crash.error_kind = "detected memory leaks"
                        rest = rest[len("memory leaks"):].strip()
                    if rest.startswith(":"):
                        desc = rest[1:].strip() or None
                    elif rest:
                        desc = rest  # e.g. "on unknown address 0x..."
                    if groups.get("pid"):
                        crash.pid = int(groups["pid"])
                    elif groups.get("pid2"):
                        crash.pid = int(groups["pid2"])
                tm = THREADED_HEADER_RE.search(line)
                if tm:
                    crash.pid = int(tm.group(1))
                crash.summary = line.strip()
                if desc:
                    crash.extra.setdefault("description", desc.strip())
                headline_seen = True
                break
        if not headline_seen:
            kind, err = extract_error_kind_from_summary(block)
            if kind is None:
                return None
            crash.sanitizer = kind
            crash.error_kind = err
            for line in lines:
                if "ERROR:" in line:
                    crash.summary = line.strip()
                    break

        # ---- SUMMARY: line carries the authoritative crash location
        sm = SUMMARY_LINE_RE.search(block)
        if sm:
            crash.extra["summary_line"] = sm.group(0).strip()
            if not crash.error_kind:
                crash.error_kind = sm.group(2)

        # ---- crash class
        crash.crash_class = self.classify(crash.error_kind)

        # ---- signal-style headline: "SEGV on unknown address 0x..."
        sig_m = re.match(
            r"^(SEGV|BUS|ILL|ABRT|FPE)(?:\s+on(?:\s+unknown)?\s+address\s+0x([0-9a-fA-F]+))?",
            crash.error_kind or "",
        )
        if sig_m:
            crash.error_kind = sig_m.group(1)
            if sig_m.group(2):
                crash.fault_address = sig_m.group(2).lower()
            sm2 = re.search(r"signal is caused by a (READ|WRITE)", block, re.IGNORECASE)
            if sm2:
                crash.access_type = sm2.group(1).lower()
            tm2 = re.search(r"\bT(\d+)\)", crash.summary)
            if tm2:
                crash.thread = f"T{tm2.group(1)}"

        # ---- access info
        am = ACCESS_RE.search(block)
        if am and not sig_m:
            crash.access_type = am.group(1).lower()
            crash.access_size = int(am.group(2))
            crash.fault_address = am.group(3).lower().removeprefix("0x")
            crash.thread = am.group(4) or am.group(5)
        else:
            hm = HWASAN_ACCESS_RE.search(block)
            if hm:
                crash.access_size = int(hm.group(1))
                crash.fault_address = hm.group(2).lower().removeprefix("0x")
            else:
                fm = ADDRESS_IN_TEXT_RE.search(block)
                if fm:
                    crash.extra.setdefault("address_candidate", fm.group(1))

        # ---- region/allocation size
        rm = REGION_SIZE_RE.search(block)
        if rm:
            crash.allocation_size = int(rm.group(1))

        # ---- leak totals (LSAN/ASan-with-leak-detection)
        lm = LEAK_LEAK_RE.search(block)
        if lm:
            crash.extra["leaked_bytes"] = lm.group(1)
            crash.extra["leaked_allocations"] = lm.group(2)
            crash.allocation_size = crash.allocation_size or int(lm.group(1))

        # ---- shadow dump
        for line in lines:
            if "Shadow bytes" in line:
                crash.shadow_line = line.strip()
            elif re.match(r"^\s*(=>)?0x[0-9a-fA-F]{4,16}:\s*[0-9a-fA-F \[\]]+", line):
                for chunk in SHADOW_BYTES_RE.findall(line):
                    crash.shadow_bytes.append(re.sub(r"[\[\]\s]+", "", chunk))

        # ---- stacks
        crash.stacks = self._parse_stacks(lines, error_kind=crash.error_kind)
        if crash.thread is None and crash.stacks:
            crash.thread = crash.stacks[0].thread

        # ---- stats
        for stat in ALLOC_STAT_RE.finditer(block):
            crash.stats[f"stat_{stat.group(1)}"] = int(stat.group(2))

        return crash

    def _parse_stacks(self, lines: Sequence[str], *,
                      error_kind: str = "") -> List[SanitizerStack]:
        stacks: List[SanitizerStack] = []
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            matched_role: Optional[StackRole] = None
            matched_thread: Optional[str] = None
            for pattern, role in _STACK_HEADER_RES:
                m = pattern.search(line)
                if m:
                    matched_role = role
                    for g in m.groups():
                        if g:
                            candidate = g if g.startswith("T") else f"T{g}"
                            if re.fullmatch(r"T\d+", candidate):
                                matched_thread = candidate
                                break
                    break
            if matched_role is None:
                for pattern, role in MSAN_ORIGIN_RES:
                    if pattern.search(line):
                        matched_role = role
                        break
            if matched_role is not None:
                stack, i = _collect_stack(lines, i + 1, matched_role, matched_thread)
                if stack.frames:
                    stacks.append(stack)
                continue
            if _looks_like_frame(line):
                stack, i = _collect_stack(lines, i, StackRole.CRASH, None)
                if stack.frames:
                    stacks.append(stack)
                continue
            i += 1
        # Backfill thread labels for the crash stack from the access line.
        joined = "\n".join(lines)
        am = None if re.match(r"^(SEGV|BUS|ILL|ABRT|FPE)", error_kind or "") else ACCESS_RE.search(joined)
        if am is None and error_kind:
            tm3 = re.match(r"^\w+ on (?:unknown )?address", error_kind)
            _ = tm3  # signal reports handled via summary thread extraction above
        if am:
            label = am.group(4) or am.group(5)
            if label:
                for stack in stacks:
                    if stack.role is StackRole.CRASH and stack.thread is None:
                        stack.thread = label
        return stacks


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ADAPTER_REGISTRY: Dict[str, SanitizerAdapter] = {}
_REGISTRY_LOCK = threading.RLock()


def register_adapter(adapter: SanitizerAdapter) -> SanitizerAdapter:
    """Idempotently register an adapter instance under its kind value."""
    with _REGISTRY_LOCK:
        ADAPTER_REGISTRY[str(adapter.kind.value)] = adapter
    return adapter


def get_adapter(name: str) -> Optional[SanitizerAdapter]:
    """Look up by kind value (``"address"``), alias (``"asan"``) or class name."""
    if not name:
        return None
    key = name.strip().lower()
    with _REGISTRY_LOCK:
        if key in ADAPTER_REGISTRY:
            return ADAPTER_REGISTRY[key]
        alias = SANITIZER_TAG_ALIASES.get(key)
        if alias is not None and str(alias.value) in ADAPTER_REGISTRY:
            return ADAPTER_REGISTRY[str(alias.value)]
        for adapter in ADAPTER_REGISTRY.values():
            if type(adapter).__name__.lower() == key:
                return adapter
    return None


def all_adapters() -> List[SanitizerAdapter]:
    with _REGISTRY_LOCK:
        return list(ADAPTER_REGISTRY.values())


def adapter_for_kind(kind: Optional[SanitizerKind]) -> Optional[SanitizerAdapter]:
    """Return the registered adapter for a :class:`SanitizerKind` or ``None``.

    ``None`` means the concrete module has not been imported/registered yet —
    callers should import :mod:`kmcs.sanitizers` which registers everything.
    """
    if kind is None:
        return None
    return get_adapter(str(kind.value))


# ---------------------------------------------------------------------------
# Self-smoke test
# ---------------------------------------------------------------------------

_SAMPLE_ASAN = """
==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x0000004ab71c bp 0x7ffd4c000010 sp 0x7ffd4c000008
READ of size 4 at 0x602000000010 thread T0
    #0 0x4ab71b in parse_chunk /src/target/parser.c:88:12
    #1 0x4ac002 in main /src/target/main.c:21:5
    #2 0x7f3c1a02a082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082)
0x602000000010 is located 0 bytes inside of 8-byte region [0x602000000010,0x602000000018)
freed by thread T0 here:
    #0 0x49f10d in free (target_asan+0x49f10d)
    #1 0x4ab6ff in close_chunk /src/target/parser.c:80:3
previously allocated by thread T0 here:
    #0 0x49ee3f in malloc (target_asan+0x49ee3f)
    #1 0x4ab5bd in open_chunk /src/target/parser.c:60:11
Shadow bytes near the faulting address:
  0x0c041fff8000: fa fa fd fd
=>0x0c041fff8010: [fd]fa fa fa
  0x0c041fff8020: fa fa fa fa
SUMMARY: AddressSanitizer: heap-use-after-free /src/target/parser.c:88:12 in parse_chunk
"""


def _smoke() -> None:
    from kmcs.sanitizers.asan import ASANAdapter  # local import avoids cycle

    adapter = ASANAdapter()
    register_adapter(adapter)
    crashes = adapter.parse_report(_SAMPLE_ASAN)
    assert len(crashes) == 1, f"expected 1 crash got {len(crashes)}"
    c = crashes[0]
    assert c.sanitizer is SanitizerKind.ASAN
    assert c.error_kind == "heap-use-after-free", c.error_kind
    assert c.crash_class is CrashClass.USE_AFTER_FREE, c.crash_class
    assert c.access_type == "read" and c.access_size == 4
    assert c.fault_address == "602000000010", c.fault_address
    assert c.thread == "T0"
    assert c.allocation_size == 8, c.allocation_size
    roles = {s.role for s in c.stacks}
    assert StackRole.CRASH in roles and StackRole.PRECEDING_FREE in roles, roles
    assert c.frame_signatures()[0].startswith("parse_chunk"), c.frame_signatures()
    assert "parser.c:88" in c.raw_text
    env = adapter.prepare_environment(
        {"PATH": os.environ.get("PATH", "")}, overrides={"log_path": "/tmp/asan.log"}
    )
    assert "ASAN_OPTIONS" in env and "log_path=/tmp/asan.log" in env["ASAN_OPTIONS"]
    pol = adapter.make_policy()
    pol.add_overrides({"allocator_may_return_null": "1"})
    assert pol.validate() == []
    d = c.to_dict()
    assert d["crash_class"] == "use-after-free"
    print(
        "sanitizers.base smoke: OK,",
        len(c.stacks),
        "stacks,",
        len(c.shadow_bytes),
        "shadow tokens",
    )


if __name__ == "__main__":
    _smoke()
