"""MemorySanitizer (MSan) adapter for KMCS.

MemorySanitizer detects reads of **uninitialised heap/memory values** in
C/C++ programs.  Unlike ASan/UBSan, MSan works by shadow-tracking every bit
of application memory (shadow memory + origin tracking), which means it
requires *whole-program* instrumentation: any uninstrumented library produces
false positives unless it is intercept-instrumented or explicitly handled.
KMCS models that reality honestly: the adapter's ``notes`` describe the
instrumentation requirement instead of pretending partial builds are safe.

Report anatomy (clang):

    ==1234==ERROR: MemorySanitizer: use-of-uninitialized-value
        #0 0x... in consume /src/main.cpp:12:7
        ...
    Uninitialized value was created by a heap allocation
        #0 0x... in malloc ...
    SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/main.cpp:12:7

Origin mode (``track_origins=1``, the default) adds richer origin notes such
as "Uninitialized value was stored to memory at", "…was created by a heap
allocation" or "…was created by a call to read()".  This parser extracts the
error kind, crash stack, and origin stacks with their roles.

Capabilities:

* fuzzing-tuned ``MSAN_OPTIONS`` policy with locked invariants
  (stack traces on, exit code distinct from ASan's so triage can tell them
  apart, origin tracking kept at its strongest cheap setting),
* full report parser: header line, crash frames, origin blocks with role
  classification via :data:`kmcs.sanitizers.base.MSAN_ORIGIN_RES`,
* heuristic *origin kind* extraction (heap vs. alloca vs. I/O vs. copy) used
  by the dedup engine to separate genuinely different root causes that share
  one crash location,
* honest availability probing with a real compile+run attempt (MSan exists
  only in clang; gcc lacks it entirely — the probe reflects that truth).

Security posture: analysis-only diagnostics reader for authorized fuzzing
campaigns; no exploit generation.  Zero external services: standard library
plus KMCS core only — no API keys, no network.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from kmcs.core.models import CrashClass, SanitizerKind
from kmcs.sanitizers.base import (
    MSAN_ERROR_CLASSES,
    MSAN_ORIGIN_RES,
    SanitizedCrash,
    SanitizerAdapter,
    SanitizerFrame,
    SanitizerStack,
    StackRole,
    register_adapter,
)

__all__ = [
    "MSANAdapter",
    "MSAN_HEADER_RE",
    "MSAN_SUMMARY_RE",
    "ORIGIN_HEADER_RE",
    "FRAME_LINE_RE",
    "parse_msan_report",
    "classify_origin_kind",
    "MSanSupport",
    "msan_support",
    "get_msan_adapter",
]

# ---------------------------------------------------------------------------
# Report grammar
# ---------------------------------------------------------------------------

#: Error banner: "==1234==ERROR: MemorySanitizer: use-of-uninitialized-value"
MSAN_HEADER_RE = re.compile(
    r"^(?:==(?P<pid>\d+)==|.*?\[\d+\]\s*)?ERROR:\s*MemorySanitizer:\s*"
    r"(?P<kind>[a-z][a-z0-9_-]*)",
    re.IGNORECASE,
)

#: Summary line: "SUMMARY: MemorySanitizer: use-of-uninitialized-value file:line:col"
MSAN_SUMMARY_RE = re.compile(
    r"^SUMMARY:\s*MemorySanitizer:\s*(?P<kind>[a-z][a-z0-9_-]*)\s*"
    r"(?:(?P<location>\S+))?",
    re.IGNORECASE | re.MULTILINE,
)

#: Origin block headers (prose lines that open an origin trace).
ORIGIN_HEADER_RE = re.compile(
    r"^(?P<header>Uninitialized value was .+|"
    r"Memory was found to be uninitialized in .*|"
    r"Location is unknown.*)$"
)

#: Frame line: "#0 0x4f2a1b in func /src/file.cpp:12:7" (file optional).
FRAME_LINE_RE = re.compile(
    r"^#(?P<idx>\d+)\s+(?P<addr>0x[0-9a-fA-F]+)\s+in\s+(?P<func>.+?)"
    r"(?:\s+(?P<file>[^\s]+\.(?:c|cc|cpp|cxx|C|h|hpp|S)):(?P<line>\d+))?"
    r"(?::(?P<col>\d+))?\s*$"
)

#: Alternate frame form without symbol: "#1 0x4f2a1b (/lib/libc.so.6+0x123)"
BARE_FRAME_RE = re.compile(
    r"^#(?P<idx>\d+)\s+(?P<addr>0x[0-9a-fA-F]+)\s+(?P<module>\(.+\))\s*$"
)

#: Note lines that carry no structural meaning but are worth keeping raw.
_IGNORED_PREFIXES = ("NOTE:", "HINT:", "Stats:")


def _match_origin_header(line: str) -> Optional[Tuple[StackRole, str]]:
    """Return ``(role, matched_text)`` when *line* opens an origin block."""
    stripped = line.strip()
    for pattern, role in MSAN_ORIGIN_RES:
        m = pattern.match(stripped)
        if m:
            return role, stripped
    om = ORIGIN_HEADER_RE.match(stripped)
    if om:
        return StackRole.ORIGIN, stripped
    return None


def _parse_frame_block(lines: Sequence[str], start: int,
                       ) -> Tuple[List[SanitizerFrame], int]:
    """Parse consecutive frame lines from *start*; returns frames + next index."""
    frames: List[SanitizerFrame] = []
    i = start
    n = len(lines)
    while i < n:
        stripped = lines[i].strip()
        if not stripped:
            k = i + 1
            if k < n and (FRAME_LINE_RE.match(lines[k].strip())
                          or BARE_FRAME_RE.match(lines[k].strip())):
                i += 1
                continue
            break
        m = FRAME_LINE_RE.match(stripped)
        if m:
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
            continue
        b = BARE_FRAME_RE.match(stripped)
        if b:
            module = b.group("module").strip("()")
            frame = SanitizerFrame(
                index=int(b.group("idx")),
                address=b.group("addr").lower().removeprefix("0x"),
                function=None,
                module=module.split("+")[0].strip(),
                raw=stripped,
            )
            frames.append(frame)
            i += 1
            continue
        break
    return frames, i


#: Origin prose → machine-readable origin kind (feeds dedup separation).
_ORIGIN_KINDS: Tuple[Tuple[str, str], ...] = (
    ("created by a heap allocation", "heap"),
    ("created by a call to mmap", "mmap"),
    ("created by a call to read()", "io-read"),
    ("created by a call to recv", "io-recv"),
    ("stored to memory at", "store"),
    ("propagated through store", "store"),
    ("made uninitialized here", "origin"),
    ("created by allocating stack memory", "stack-alloca"),
    ("was created by", "other"),
)


def classify_origin_kind(header_text: str) -> str:
    """Map an origin-block header onto a short origin-kind token.

    Unknown headers yield ``"unknown"`` — never guessed beyond evidence.
    """
    lowered = (header_text or "").lower()
    for needle, token in _ORIGIN_KINDS:
        if needle in lowered:
            return token
    return "unknown"


@dataclass(slots=True)
class MSanParsedReport:
    """Structured intermediate form returned by :func:`parse_msan_report`."""

    error_kind: str = ""
    summary_location: str = ""
    crash_frames: List[SanitizerFrame] = None  # type: ignore[assignment]
    origins: List[Tuple[StackRole, str, List[SanitizerFrame]]] = None  # type: ignore[assignment]
    pid: Optional[int] = None

    def __post_init__(self) -> None:
        if self.crash_frames is None:
            self.crash_frames = []
        if self.origins is None:
            self.origins = []


def parse_msan_report(text: str) -> MSanParsedReport:
    """Parse MSan console output into structured pieces (pure function).

    Tolerant of missing frames/origins; never raises.  Multiple reports in
    one stream collapse onto the *first* banner because MSan halts by
    default under KMCS policy (halt_on_error=1); additional banners set
    ``truncated`` style notes on the produced crashes elsewhere.
    """
    parsed = MSanParsedReport()
    if not text:
        return parsed
    lines = text.splitlines()
    n = len(lines)
    i = 0
    # Locate the first ERROR banner.
    while i < n:
        hm = MSAN_HEADER_RE.match(lines[i].strip())
        if hm:
            parsed.error_kind = hm.group("kind").lower()
            pid_raw = hm.groupdict().get("pid")
            if pid_raw:
                try:
                    parsed.pid = int(pid_raw)
                except (TypeError, ValueError):
                    parsed.pid = None
            i += 1
            break
        i += 1
    else:
        # No banner at all — maybe only a SUMMARY line survived log rotation.
        sm = MSAN_SUMMARY_RE.search(text)
        if sm:
            parsed.error_kind = sm.group("kind").lower()
            parsed.summary_location = (sm.group("location") or "").strip()
        return parsed

    # Crash frames follow the banner until the first origin header.
    frames, j = _parse_frame_block(lines, i)
    parsed.crash_frames = frames
    i = j
    # Origin blocks: header line then its own frame list.
    while i < n:
        header = _match_origin_header(lines[i])
        if header is None:
            stripped = lines[i].strip()
            if stripped.startswith("SUMMARY:"):
                sm = MSAN_SUMMARY_RE.match(stripped)
                if sm:
                    parsed.summary_location = (sm.group("location") or "").strip()
                    if not parsed.error_kind:
                        parsed.error_kind = sm.group("kind").lower()
            i += 1
            continue
        role, header_text = header
        frames, j = _parse_frame_block(lines, i + 1)
        parsed.origins.append((role, header_text, frames))
        i = j
    if not parsed.summary_location and parsed.crash_frames:
        top = parsed.crash_frames[0]
        if top.file:
            loc = f"{top.file}:{top.line}" if top.line and top.line > 0 else top.file
            parsed.summary_location = loc
    return parsed


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class MSANAdapter(SanitizerAdapter):
    """KMCS driver for MemorySanitizer reports."""

    kind = SanitizerKind.MSAN
    env_var = "MSAN_OPTIONS"
    compile_flag = "-fsanitize=memory"
    display_name = "MemorySanitizer"
    requires_instrumentation = True
    #: MSan aborts on error under our policy, but diagnostics may arrive with
    #: clean exits when halt_on_error is relaxed for targeted experiments.
    reports_without_crash = True

    def default_options(self) -> Dict[str, object]:
        return {
            "print_stacktrace": 1,
            "halt_on_error": 1,           # first-use reporting keeps traces exact
            "use_sigaltstack": 1,
            "track_origins": 1,           # strongest provenance we can fingerprint
            "exit_code": 86,              # distinctive, separable from ASan/UBSan
            "verbosity": 1,
        }

    def locked_options(self) -> Tuple[str, ...]:
        # Changing origin tracking or halt behaviour mid-campaign would make
        # fingerprints incomparable between workers.
        return ("print_stacktrace", "halt_on_error", "track_origins", "exit_code")

    def class_map(self) -> Dict[str, CrashClass]:
        return dict(MSAN_ERROR_CLASSES)

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
        """Parse MSan output into structured crashes.

        One crash per ERROR banner found.  Origin blocks become additional
        stacks with their proper :class:`StackRole`, and the leading origin
        header is distilled into ``extra["origin_kind"]`` for the dedup
        engine.
        """
        if not text:
            return []
        crashes: List[SanitizedCrash] = []
        # Split on banners so multi-report logs still yield one crash each.
        segments = re.split(r"(?=^.*ERROR:\s*MemorySanitizer)", text,
                            flags=re.MULTILINE)
        for segment in segments:
            if not MSAN_HEADER_RE.search(segment.splitlines()[0]
                                        if segment else ""):
                continue
            parsed = parse_msan_report(segment)
            if not parsed.error_kind:
                continue
            crash = SanitizedCrash(
                sanitizer=SanitizerKind.MSAN,
                error_kind=parsed.error_kind,
                crash_class=self.classify(parsed.error_kind),
                summary=(f"MemorySanitizer: {parsed.error_kind} at "
                         f"{parsed.summary_location}"
                         if parsed.summary_location else
                         f"MemorySanitizer: {parsed.error_kind}"),
                exit_code=exit_code,
                source_path=source_path,
                raw_text=segment.strip(),
            )
            stacks: List[SanitizerStack] = []
            if parsed.crash_frames:
                stacks.append(SanitizerStack(role=StackRole.CRASH, thread=None,
                                             frames=parsed.crash_frames))
            for role, header_text, frames in parsed.origins:
                if frames:
                    stacks.append(SanitizerStack(role=role, thread=None,
                                                 frames=frames))
                elif role is not StackRole.UNKNOWN:
                    stacks.append(SanitizerStack(role=role, thread=None,
                                                 frames=[]))
            crash.stacks = stacks
            if parsed.origins:
                crash.extra["origin_kind"] = classify_origin_kind(
                    parsed.origins[0][1])
                crash.extra["origin_header"] = parsed.origins[0][1]
            if parsed.pid is not None:
                crash.pid = parsed.pid
            self.enhance(crash)
            crashes.append(crash)
        if not crashes:
            # Honest fallback: shared loose-summary path (returns nothing for
            # unrecognisable input rather than inventing findings).
            return super().parse_report(
                text, source_path=source_path, exit_code=exit_code,
                symbolize=False, binary=None,
            )
        return crashes

    #: Caveat surfaced on every MSan finding (see :meth:`enhance`).
    INSTRUMENTATION_NOTE = (
        "MSan requires whole-program instrumentation; uninstrumented code "
        "leads to false positives \u2014 verify build coverage."
    )

    def enhance(self, crash: SanitizedCrash) -> None:
        """Fill classification gaps and annotate instrumentation caveats."""
        if crash.crash_class is None:
            crash.crash_class = self.classify(crash.error_kind)
        crash.extra.setdefault("build_caveat", self.INSTRUMENTATION_NOTE)


# ---------------------------------------------------------------------------
# Availability probing (real compile+run attempt — never assumed)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MSanSupport:
    """Honest result of probing this host for working MemorySanitizer."""

    compiler: str
    supported: bool
    version: str = ""
    details: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "compiler": self.compiler,
            "supported": self.supported,
            "version": self.version,
            "details": self.details,
        }


_PROBE_SOURCE = (
    "#include <stdlib.h>\n"
    "int main(void) { volatile int *p = (int*)malloc(4); *p = 1; return 0; }\n"
)


def msan_support(compiler: Optional[str] = None, *,
                 timeout: float = 30.0) -> MSanSupport:
    """Probe *compiler* for a functional MemorySanitizer runtime.

    MSan is a Clang-only feature (GCC has no equivalent); the probe compiles
    a tiny program with ``-fsanitize=memory`` and runs it.  Failures are
    reported verbatim — KMCS prefers an honest "unavailable" over fabricated
    support.
    """
    candidates = [compiler] if compiler else ["clang", "clang++"]
    chosen = None
    for cand in candidates:
        if not cand:
            continue
        found = shutil.which(cand)
        if found:
            chosen = found
            break
    if chosen is None:
        return MSanSupport(compiler=",".join(c for c in candidates if c),
                           supported=False,
                           details=("no clang found on PATH; MSan is a "
                                    "Clang-only sanitizer (gcc cannot provide it)"))
    version = ""
    try:
        proc = subprocess.run([chosen, "--version"], capture_output=True,
                              text=True, timeout=10, check=False)
        first = (proc.stdout or proc.stderr).splitlines()
        version = first[0].strip() if first else ""
    except (OSError, subprocess.SubprocessError):
        version = "<unknown>"
    with tempfile.TemporaryDirectory(prefix="kmcs-msan-probe-") as tmp:
        src = Path(tmp) / "probe.c"
        out = Path(tmp) / "probe.bin"
        try:
            src.write_text(_PROBE_SOURCE, encoding="utf-8")
        except OSError as exc:
            return MSanSupport(compiler=chosen, supported=False,
                               version=version,
                               details=f"temp write failed: {exc}")
        try:
            proc = subprocess.run(
                [chosen, "-fsanitize=memory", "-fno-omit-frame-pointer",
                 "-g", str(src), "-o", str(out)],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return MSanSupport(compiler=chosen, supported=False,
                               version=version, details="compile probe timed out")
        except OSError as exc:
            return MSanSupport(compiler=chosen, supported=False,
                               version=version, details=f"spawn failed: {exc}")
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
            return MSanSupport(compiler=chosen, supported=False, version=version,
                               details=" | ".join(tail))
        try:
            run = subprocess.run([str(out)], capture_output=True, text=True,
                                 timeout=15, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return MSanSupport(compiler=chosen, supported=False, version=version,
                               details=f"compiled but could not execute probe: {exc}")
        combined = (run.stdout or "") + (run.stderr or "")
        if run.returncode == 0:
            return MSanSupport(compiler=chosen, supported=True, version=version,
                               details="compile+link+run OK")
        if "MemorySanitizer" in combined:
            # Runtime fired on the probe itself: MSan works, just flagged us.
            return MSanSupport(compiler=chosen, supported=True, version=version,
                               details="runtime active (probe flagged by MSan)")
        return MSanSupport(compiler=chosen, supported=False, version=version,
                           details=f"probe exited {run.returncode} without MSan output")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_MSAN_ADAPTER = MSANAdapter()
register_adapter(_MSAN_ADAPTER)


def get_msan_adapter() -> MSANAdapter:
    """Return the process-wide MSan adapter instance."""
    return _MSAN_ADAPTER


# ---------------------------------------------------------------------------
# Self-smoke test (python -m kmcs.sanitizers.msan)
# ---------------------------------------------------------------------------


def _smoke() -> int:
    adapter = get_msan_adapter()
    sample = """\
==1234==ERROR: MemorySanitizer: use-of-uninitialized-value
    #0 0x52a4e1 in consume /src/main.cpp:12:7
    #1 0x52a5c0 in main /src/main.cpp:20:3
    #2 0x7f0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2751f)
Uninitialized value was created by a heap allocation
    #0 0x4f2a1b in malloc /build/clang/lib/msan/msan.cc:123:1
    #1 0x52a4b0 in main /src/main.cpp:18:15
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/main.cpp:12:7
"""
    crashes = adapter.parse_report(sample, source_path="smoke.log", exit_code=86)
    assert len(crashes) == 1, f"expected 1 crash, got {len(crashes)}"
    crash = crashes[0]
    assert crash.error_kind == "use-of-uninitialized-value", crash.error_kind
    assert crash.crash_class is CrashClass.UNINITIALIZED_USE, crash.crash_class
    assert crash.stacks and crash.stacks[0].role is StackRole.CRASH, crash.stacks
    assert any(s.role is StackRole.ALLOCATION for s in crash.stacks), crash.stacks
    assert crash.extra.get("origin_kind") == "heap", crash.extra
    assert "/src/main.cpp:12" in crash.summary, crash.summary
    env = adapter.prepare_environment({"PATH": "/usr/bin"})
    assert "MSAN_OPTIONS" in env, list(env.keys())
    assert "track_origins=1" in env["MSAN_OPTIONS"], env["MSAN_OPTIONS"]
    env2 = adapter.prepare_environment({}, overrides={"track_origins": 0})
    assert "track_origins=1" in env2["MSAN_OPTIONS"], env2["MSAN_OPTIONS"]
    assert classify_origin_kind("Uninitialized value was stored to memory at") == "store"
    assert classify_origin_kind("something novel") == "unknown"
    assert adapter.parse_report("") == []
    support = msan_support()
    print(f"msan smoke: {len(crashes)} crash parsed; "
          f"support={support.supported} ({support.details}); env OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
