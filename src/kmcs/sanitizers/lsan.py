"""LeakSanitizer (LSan) adapter for KMCS.

LeakSanitizer detects *memory leaks*: heap allocations that are never freed
and remain unreachable when the process exits (or on demand via
``__lsan_do_leak_check()``).  LSan normally rides on AddressSanitizer
(``detect_leaks=1`` in ``ASAN_OPTIONS``) but has its own runtime, options
variable (``LSAN_OPTIONS``), suppression grammar and report layout, all of
which this module models honestly.

KMCS treats leak reports as **findings without crash signals**: a leaking
program usually exits cleanly.  The base contract's ``reports_without_crash``
flag is set so campaign pipelines record them even when no fatal signal fired.

Capabilities:

* fuzzing-tuned ``LSAN_OPTIONS`` policy with locked invariants,
* full leak-report parser: direct/indirect leak blocks, per-leak byte counts,
  allocation stacks, top-level SUMMARY totals, LeakSanitizer note lines,
* LSan suppression-file generation and parsing (``leak:`` / ``obj:`` /
  ``fun:`` rules) used to silence known-acceptable third-party leaks,
* leak classification onto :class:`~kmcs.core.models.CrashClass`
  (MEMORY_LEAK / INDIRECT_LEAK) via the shared table in
  :mod:`kmcs.sanitizers.base`,
* honest availability probing: a real compile+link+run attempt with
  ``-fsanitize=address`` plus a deliberate leak.  If the host disables LSan
  (missing ptrace capability, some containers/QEMU setups) we say so plainly
  instead of fabricating support.

Security posture: analysis-only.  This module reads sanitizer diagnostics
from authorized campaigns; it never crafts payloads or exploits anything.
Zero external services: standard library plus KMCS core only — no API keys,
no network.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.models import CrashClass, SanitizerKind
from kmcs.sanitizers.base import (
    LSAN_ERROR_CLASSES,
    SanitizedCrash,
    SanitizerAdapter,
    SanitizerFrame,
    SanitizerStack,
    StackRole,
    register_adapter,
)

__all__ = [
    "LSANAdapter",
    "LSANReport",
    "LeakRecord",
    "parse_lsan_report",
    "parse_suppression_file",
    "format_suppression_entry",
    "build_suppression_file",
    "LEAK_BLOCK_RE",
    "LEAK_HEADER_RE",
    "SUMMARY_LEAKS_RE",
    "STATS_LINE_RE",
    "SUPPRESSION_RULE_RE",
    "LSanSupport",
    "lsan_support",
    "get_lsan_adapter",
]

# ---------------------------------------------------------------------------
# Report grammar
# ---------------------------------------------------------------------------

#: Current LSan block opener:
#:   "Direct leak of 27 byte(s) in 1 object(s) allocated from:"
LEAK_BLOCK_RE = re.compile(
    r"^(?P<kind>Direct|Indirect)\s+leak\s+of\s+(?P<bytes>\d+)\s+byte\(s\)"
    r"\s+in\s+(?P<objects>\d+)\s+object\(s\)\s+allocated\s+from:"
)

#: Older/alternate spelling: "NN bytes in M leaks are leaked"
LEAK_HEADER_RE = re.compile(
    r"^(?:.*?\[\d+\]\s*)?(?P<bytes>\d+)\s+bytes?\s+in\s+(?P<count>\d+)\s+"
    r"(?P<kind>direct|indirect)?\s*leaks?\s+are\s+leaked"
)

#: Top-level totals line:
#:   "SUMMARY: AddressSanitizer: 27 byte(s) leaked in 1 allocation(s)."
SUMMARY_LEAKS_RE = re.compile(
    r"SUMMARY:\s*(?:AddressSanitizer|LeakSanitizer):\s*"
    r"(?P<bytes>\d+)\s+byte\(s\)\s+leaked\s+in\s+(?P<allocs>\d+)\s+allocation\(s\)",
    re.IGNORECASE,
)

#: Note/diagnostic lines emitted by the LeakSanitizer runtime itself.
STATS_LINE_RE = re.compile(r"LeakSanitizer:(?P<message>[^\n]*)", re.IGNORECASE)

#: Frame line inside an allocation stack: "#0 0x... in func file.cpp:12[:3]"
FRAME_LINE_RE = re.compile(
    r"^#(?P<idx>\d+)\s+(?P<addr>0x[0-9a-fA-F]+)\s+in\s+(?P<func>.+?)"
    r"(?:\s+(?P<file>[^\s]+\.(?:c|cc|cpp|cxx|C|h|hpp)):(?P<line>\d+))?"
    r"(?::(?P<col>\d+))?\s*$"
)

#: Suppression rule grammar understood by LSan:
#:   leak:FunctionName        obj:*libfoo.so*       fun:helper
SUPPRESSION_RULE_RE = re.compile(
    r"^(?P<kind>leak|obj|fun)\s*:\s*(?P<pattern>[^\s#].*?)\s*$"
)

#: Comment/blank noise inside suppression files.
_SUPPRESSOR_COMMENT_RE = re.compile(r"^\s*(#.*)?$")


def _parse_frames(lines: Sequence[str], start: int) -> Tuple[List[SanitizerFrame], int]:
    """Collect consecutive frame lines beginning at *start*.

    Returns ``(frames, next_index)``.  Stops at the first non-frame, non-blank
    line so each leak block keeps exactly its own allocation trace.
    """
    frames: List[SanitizerFrame] = []
    i = start
    n = len(lines)
    while i < n:
        stripped = lines[i].strip()
        if not stripped:
            # Blank line tolerated only if the following line is still a frame.
            k = i + 1
            if k < n and FRAME_LINE_RE.match(lines[k].strip()):
                i += 1
                continue
            break
        m = FRAME_LINE_RE.match(stripped)
        if m is None:
            break
        frame = SanitizerFrame(
            index=int(m.group("idx")),
            address=m.group("addr").lower().removeprefix("0x"),
            function=m.group("func").strip(),
            raw=stripped,
        )
        if m.group("file"):
            frame.file = m.group("file")
            try:
                frame.line = int(m.group("line"))
            except (TypeError, ValueError):
                pass
            col = m.group("col")
            if col:
                try:
                    frame.column = int(col)
                except (TypeError, ValueError):
                    pass
        frames.append(frame)
        i += 1
    return frames, i


# ---------------------------------------------------------------------------
# Structured models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LeakRecord:
    """One parsed leak block (a single distinct leak site)."""

    kind: str = "direct"                 # "direct" | "indirect"
    leaked_bytes: int = 0
    objects: int = 1
    allocation_stack: Optional[SanitizerStack] = None
    raw_text: str = ""

    def as_dict(self) -> Dict[str, object]:
        stack_frames = (self.allocation_stack.frames
                        if self.allocation_stack is not None else [])
        return {
            "kind": self.kind,
            "leaked_bytes": self.leaked_bytes,
            "objects": self.objects,
            "stack": [f.short() for f in stack_frames],
        }


@dataclass(slots=True)
class LSANReport:
    """Aggregated view of one LeakSanitizer output stream."""

    leaks: List[LeakRecord] = field(default_factory=list)
    total_bytes: int = 0
    total_allocations: int = 0
    notes: List[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def direct_count(self) -> int:
        return sum(1 for leak in self.leaks if leak.kind == "direct")

    @property
    def indirect_count(self) -> int:
        return sum(1 for leak in self.leaks if leak.kind == "indirect")

    def as_dict(self) -> Dict[str, object]:
        return {
            "leaks": [leak.as_dict() for leak in self.leaks],
            "total_bytes": self.total_bytes,
            "total_allocations": self.total_allocations,
            "direct": self.direct_count,
            "indirect": self.indirect_count,
            "notes": list(self.notes),
            "truncated": self.truncated,
        }


def parse_lsan_report(text: str, *, max_blocks: int = 512) -> LSANReport:
    """Parse raw LSan/ASan-leak console output into an :class:`LSANReport`.

    Pure function; never raises on malformed input — unrecognised chunks are
    skipped.  *max_blocks* bounds work on pathological logs; when exceeded
    the report is marked ``truncated`` (honest signalling, silent partial
    results are worse than flagged ones).
    """
    report = LSANReport()
    if not text:
        return report
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        stripped = lines[i].strip()
        m = LEAK_BLOCK_RE.match(stripped)
        if m:
            if len(report.leaks) >= max_blocks:
                report.truncated = True
                report.notes.append(f"stopped after {max_blocks} leak blocks")
                break
            kind = m.group("kind").lower()
            frames, j = _parse_frames(lines, i + 1)
            block_lines = [stripped, *lines[i + 1:j]]
            stack = (SanitizerStack(role=StackRole.ALLOCATION, thread=None,
                                    frames=frames) if frames else None)
            report.leaks.append(LeakRecord(
                kind=kind,
                leaked_bytes=int(m.group("bytes")),
                objects=int(m.group("objects")),
                allocation_stack=stack,
                raw_text="\n".join(block_lines),
            ))
            i = j
            continue
        h = LEAK_HEADER_RE.match(stripped)
        if h:
            if len(report.leaks) >= max_blocks:
                report.truncated = True
                break
            kind = (h.group("kind") or "direct").lower()
            frames, j = _parse_frames(lines, i + 1)
            report.leaks.append(LeakRecord(
                kind=kind,
                leaked_bytes=int(h.group("bytes")),
                objects=int(h.group("count")),
                allocation_stack=(SanitizerStack(role=StackRole.ALLOCATION,
                                                 thread=None, frames=frames)
                                  if frames else None),
                raw_text="\n".join([stripped, *lines[i + 1:j]]),
            ))
            i = j
            continue
        sm = SUMMARY_LEAKS_RE.search(stripped)
        if sm:
            report.total_bytes = int(sm.group("bytes"))
            report.total_allocations = int(sm.group("allocs"))
        for note_m in STATS_LINE_RE.finditer(stripped):
            message = note_m.group("message").strip()
            if message and message not in report.notes:
                report.notes.append(message)
        i += 1
    if not report.total_bytes and report.leaks:
        # No SUMMARY line present: derive totals strictly from parsed blocks.
        report.total_bytes = sum(leak.leaked_bytes for leak in report.leaks)
        report.total_allocations = len(report.leaks)
    return report


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------


def format_suppression_entry(kind: str, pattern: str) -> str:
    """Render one suppression rule; validates kind and rejects blanks."""
    kind_norm = (kind or "").strip().lower()
    if kind_norm not in ("leak", "obj", "fun"):
        raise ValueError(f"unknown suppression kind: {kind!r}")
    pattern_clean = (pattern or "").strip()
    if not pattern_clean:
        raise ValueError("suppression pattern must be non-empty")
    if any(ch in pattern_clean for ch in "\n\r"):
        raise ValueError("suppression pattern must be single-line")
    return f"{kind_norm}:{pattern_clean}"


def parse_suppression_file(path: Path) -> List[Tuple[str, str]]:
    """Read an LSan suppression file into ``(kind, pattern)`` tuples.

    Comments (``#``) and blank lines are ignored; malformed rules are skipped
    because suppressions are triage aids, not security-critical input.
    """
    rules: List[Tuple[str, str]] = []
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return rules
    for line in text.splitlines():
        if _SUPPRESSOR_COMMENT_RE.match(line):
            continue
        m = SUPPRESSION_RULE_RE.match(line.strip())
        if m:
            rules.append((m.group("kind").lower(), m.group("pattern").strip()))
    return rules


def build_suppression_file(entries: Sequence[Mapping[str, str]], path: Path,
                           *,
                           header: str = "KMCS generated LSan suppressions") -> Path:
    """Atomically write a suppression file from structured entries.

    Each entry needs ``kind`` and ``pattern`` keys; duplicates collapse and
    invalid entries are dropped.  Written via temp file + rename so
    concurrent readers never observe partial content.
    """
    seen: Dict[str, None] = {}
    lines: List[str] = [f"# {header}",
                        "# generated: local KMCS run (no external services)"]
    for entry in entries:
        kind = str(entry.get("kind", "")).lower()
        pattern = str(entry.get("pattern", ""))
        try:
            rule = format_suppression_entry(kind, pattern)
        except ValueError:
            continue
        if rule in seen:
            continue
        seen[rule] = None
        lines.append(rule)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(target)
    return target


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class LSANAdapter(SanitizerAdapter):
    """KMCS driver for LeakSanitizer reports."""

    kind = SanitizerKind.LSAN
    env_var = "LSAN_OPTIONS"
    compile_flag = "-fsanitize=address"   # LSan rides on ASan instrumentation
    display_name = "LeakSanitizer"
    requires_instrumentation = True
    #: Leaks do not abort the process; they are findings regardless.
    reports_without_crash = True

    def default_options(self) -> Dict[str, object]:
        return {
            "detect_leaks": 1,
            "report_objects": 1,          # per-leak object counts feed dedup
            "fast_unwind_on_fatal": 0,    # accurate alloc stacks beat speed here
            "malloc_context_size": 30,
            "exitcode": 23,               # distinctive code: "leak detected"
                                          # separable from genuine crashes
        }

    def locked_options(self) -> Tuple[str, ...]:
        # Flipping detect_leaks/exitcode mid-campaign would make crash sets
        # incomparable across workers and hide leaks from the harness.
        return ("detect_leaks", "exitcode")

    def class_map(self) -> Dict[str, CrashClass]:
        return dict(LSAN_ERROR_CLASSES)

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
        """Turn LSan output into one SanitizedCrash per distinct leak block.

        Whole-run SUMMARY totals attach to every crash's stats so downstream
        severity scoring sees both the individual leak and the aggregate.
        """
        report = parse_lsan_report(text)
        crashes: List[SanitizedCrash] = []
        for record in report.leaks:
            error_kind = f"{record.kind}-leak"
            crash = SanitizedCrash(
                sanitizer=SanitizerKind.LSAN,
                error_kind=error_kind,
                crash_class=self.classify(error_kind),
                summary=(f"{record.kind.capitalize()} leak of "
                         f"{record.leaked_bytes} byte(s) in "
                         f"{record.objects} object(s)"),
                exit_code=exit_code,
                source_path=source_path,
                raw_text=record.raw_text,
                allocation_size=record.leaked_bytes,
            )
            crash.extra["leak_kind"] = record.kind
            crash.extra["leaked_bytes"] = str(record.leaked_bytes)
            crash.extra["leaked_objects"] = str(record.objects)
            if record.allocation_stack is not None:
                crash.stacks = [record.allocation_stack]
                if record.allocation_stack.frames:
                    crash.extra["alloc_site"] = record.allocation_stack.frames[0].short()
            crashes.append(crash)
        if not crashes:
            # No discrete blocks: fall back to the shared parser so wrapped
            # "ERROR: LeakSanitizer" banners still produce something honest.
            return super().parse_report(
                text, source_path=source_path, exit_code=exit_code,
                symbolize=False, binary=None,
            )
        for crash in crashes:
            crash.stats["lsan_total_bytes"] = report.total_bytes
            crash.stats["lsan_total_allocations"] = report.total_allocations
            if report.truncated:
                crash.truncated = True
            self.enhance(crash)
        return crashes

    def enhance(self, crash: SanitizedCrash) -> None:
        """Ensure leak crashes always carry a CrashClass."""
        if crash.crash_class is None:
            kind = (crash.extra.get("leak_kind") or "").lower()
            if kind == "indirect":
                crash.crash_class = CrashClass.INDIRECT_LEAK
            else:
                crash.crash_class = (self.classify(crash.error_kind)
                                     or CrashClass.MEMORY_LEAK)


# ---------------------------------------------------------------------------
# Availability probing (real compile+leak+run attempt — never assumed)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LSanSupport:
    """Honest result of probing this host for working LeakSanitizer."""

    compiler: str
    supported: bool
    version: str = ""
    details: str = ""
    leak_detected_in_probe: Optional[bool] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "compiler": self.compiler,
            "supported": self.supported,
            "version": self.version,
            "details": self.details,
            "leak_detected_in_probe": self.leak_detected_in_probe,
        }


_PROBE_SOURCE = (
    "#include <stdlib.h>\n"
    "int main(void) { volatile char *p = (char*)malloc(64); p[0] = 1; return 0; }\n"
)


def lsan_support(compiler: Optional[str] = None, *,
                 timeout: float = 30.0) -> LSanSupport:
    """Probe *compiler* for a genuinely functional LeakSanitizer runtime.

    Compiles a deliberately leaking program with ``-fsanitize=address``,
    runs it once and checks whether LSan actually reported the leak.  On
    hosts where LSan is disabled (missing PTRACE permission, hardened
    containers, QEMU) the probe says so plainly — KMCS prefers an honest
    "unavailable" over fabricated capabilities.
    """
    candidates = [compiler] if compiler else ["clang", "clang++", "gcc", "g++"]
    chosen = None
    for cand in candidates:
        if not cand:
            continue
        found = shutil.which(cand)
        if found:
            chosen = found
            break
    if chosen is None:
        return LSanSupport(compiler=",".join(c for c in candidates if c),
                           supported=False,
                           details="no supported compiler found on PATH")
    version = ""
    try:
        proc = subprocess.run([chosen, "--version"], capture_output=True,
                              text=True, timeout=10, check=False)
        first = (proc.stdout or proc.stderr).splitlines()
        version = first[0].strip() if first else ""
    except (OSError, subprocess.SubprocessError):
        version = "<unknown>"
    with tempfile.TemporaryDirectory(prefix="kmcs-lsan-probe-") as tmp:
        src = Path(tmp) / "probe.c"
        out = Path(tmp) / "probe.bin"
        try:
            src.write_text(_PROBE_SOURCE, encoding="utf-8")
        except OSError as exc:
            return LSanSupport(compiler=chosen, supported=False,
                               version=version,
                               details=f"temp write failed: {exc}")
        try:
            proc = subprocess.run(
                [chosen, "-fsanitize=address", "-g", str(src), "-o", str(out)],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return LSanSupport(compiler=chosen, supported=False,
                               version=version, details="compile probe timed out")
        except OSError as exc:
            return LSanSupport(compiler=chosen, supported=False,
                               version=version, details=f"spawn failed: {exc}")
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
            return LSanSupport(compiler=chosen, supported=False, version=version,
                               details=" | ".join(tail))
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = "detect_leaks=1:exitcode=23"
        try:
            run = subprocess.run([str(out)], capture_output=True, text=True,
                                 timeout=15, check=False, env=env)
        except (OSError, subprocess.SubprocessError) as exc:
            return LSanSupport(compiler=chosen, supported=False, version=version,
                               details=f"compiled but could not execute probe: {exc}")
        combined = (run.stdout or "") + (run.stderr or "")
        leak_seen = ("leaked" in combined.lower() or "LeakSanitizer" in combined)
        disabled_note = ("LeakSanitizer has encountered a fatal error" in combined)
        if leak_seen and not disabled_note:
            return LSanSupport(compiler=chosen, supported=True, version=version,
                               details="probe leak detected by LSan runtime",
                               leak_detected_in_probe=True)
        if disabled_note:
            return LSanSupport(compiler=chosen, supported=False, version=version,
                               details=("LSan runtime present but disabled on this "
                                        "host (ptrace/container restriction)"),
                               leak_detected_in_probe=False)
        return LSanSupport(compiler=chosen, supported=False, version=version,
                           details=("probe compiled and ran but no leak was "
                                    "reported — LSan likely unsupported"),
                           leak_detected_in_probe=False)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_LSAN_ADAPTER = LSANAdapter()
register_adapter(_LSAN_ADAPTER)


def get_lsan_adapter() -> LSANAdapter:
    """Return the process-wide LSan adapter instance."""
    return _LSAN_ADAPTER


# ---------------------------------------------------------------------------
# Self-smoke test (python -m kmcs.sanitizers.lsan)
# ---------------------------------------------------------------------------


def _smoke() -> int:
    adapter = get_lsan_adapter()
    sample = """
=================================================================
==1234==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 27 byte(s) in 1 object(s) allocated from:
    #0 0x4f2a1b in malloc /build/clang/lib/asan/asan_malloc_linux.cc:146:3
    #1 0x401149 in make_thing /src/widget.c:12:10
    #2 0x4011f2 in main /src/widget.c:20:15

Indirect leak of 144 byte(s) in 2 object(s) allocated from:
    #0 0x4f2a1b in malloc /build/clang/lib/asan/asan_malloc_linux.cc:146:3
    #1 0x401170 in chain_node /src/widget.c:15:9

SUMMARY: AddressSanitizer: 171 byte(s) leaked in 3 allocation(s).
"""
    crashes = adapter.parse_report(sample, source_path="smoke.log", exit_code=23)
    assert len(crashes) == 2, f"expected 2 leak records, got {len(crashes)}"
    kinds = sorted(c.error_kind for c in crashes)
    assert kinds == ["direct-leak", "indirect-leak"], kinds
    direct = [c for c in crashes if c.error_kind == "direct-leak"][0]
    assert direct.crash_class is CrashClass.MEMORY_LEAK, direct.crash_class
    assert direct.allocation_size == 27, direct.allocation_size
    assert direct.stats["lsan_total_bytes"] == 171, direct.stats
    assert direct.stacks and direct.stacks[0].frames[0].function == "malloc", \
        direct.stacks
    indirect = [c for c in crashes if c.error_kind == "indirect-leak"][0]
    assert indirect.crash_class is CrashClass.INDIRECT_LEAK, indirect.crash_class
    env = adapter.prepare_environment({"PATH": "/usr/bin"},
                                      overrides={"detect_leaks": 1})
    assert "LSAN_OPTIONS" in env and "detect_leaks=1" in env["LSAN_OPTIONS"], env
    # Locked option must resist operator override attempts.
    env2 = adapter.prepare_environment({}, overrides={"detect_leaks": 0})
    assert "detect_leaks=1" in env2["LSAN_OPTIONS"], env2["LSAN_OPTIONS"]
    # Suppressions round-trip (dedup + invalid-kind rejection).
    with tempfile.TemporaryDirectory() as td:
        supp = build_suppression_file(
            [{"kind": "leak", "pattern": "make_thing"},
             {"kind": "leak", "pattern": "make_thing"},
             {"kind": "bogus", "pattern": "x"}],
            Path(td) / "leaks.supp")
        rules = parse_suppression_file(supp)
        assert rules == [("leak", "make_thing")], rules
    # Empty/garbage input parses to zero leaks without raising.
    assert parse_lsan_report("not a leak report at all").leaks == []
    support = lsan_support()
    print(f"lsan smoke: {len(crashes)} leaks parsed; "
          f"support={support.supported} ({support.details}); env OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
