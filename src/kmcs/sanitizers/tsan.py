"""ThreadSanitizer (TSan) adapter for KMCS.

ThreadSanitizer detects *data races* and related concurrency defects in C/C++
and Go programs: unsynchronised accesses to shared memory, lock-order
inversions (deadlock risk), unsafe use of signal handlers, detached-thread
teardown races and more.  TSan differs structurally from the ASan family:

* reports open with ``WARNING: ThreadSanitizer: <kind>`` (not ``ERROR:``),
* every race is described by **two or three thread stacks** (the two racing
  accesses, plus the history of one of them), each labelled ``Thread T<n>``,
* findings are *potential* bugs: a race is a scheduling hazard, not an
  immediate crash; severity triage must reflect that nuance.

This module gives KMCS a first-class, analysis-only driver:

* fuzzing-tuned ``TSAN_OPTIONS`` policy with locked invariants (second stack
  traces always on so both racers are fingerprinted, halt-on-error under
  campaigns so AFL++ observes a crash signal),
* a dedicated report parser for the TSan grammar: banner kinds, per-thread
  access lines ("Write of size 8 at 0x... by thread T1"), location frames in
  TSan's ``func file.cpp:12:7 (bin+0x...)`` style, thread creation traces,
  mutex/atomic context lines, and SUMMARY extraction,
* classification onto :class:`~kmcs.core.models.CrashClass` (DATA_RACE /
  LOCK_ORDER_INVERSION) via the shared table in :mod:`kmcs.sanitizers.base`,
* rich structured extras: both racer threads, both addresses, function/file
  of each access, mutex identity for lock-order reports — everything the
  dedup engine needs to keep distinct races apart,
* honest availability probing via a real compile-and-run attempt (a genuine
  two-thread race program); if the toolchain lacks the runtime we report the
  truth rather than fabricating support.

Security posture: this module only *reads and structures* sanitizer
diagnostics produced during authorized fuzzing campaigns.  No exploit
generation, no payload crafting.  Zero external services: standard library
plus KMCS core only — no API keys, no network.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from kmcs.core.models import CrashClass, SanitizerKind
from kmcs.sanitizers.base import (
    TSAN_ERROR_CLASSES,
    SanitizedCrash,
    SanitizerAdapter,
    SanitizerFrame,
    SanitizerStack,
    StackRole,
    register_adapter,
)

__all__ = [
    "TSANAdapter",
    "TSanParsedWarning",
    "RaceAccess",
    "parse_tsan_warnings",
    "TSAN_WARNING_RE",
    "TSAN_SUMMARY_RE",
    "TSAN_ACCESS_LINE_RE",
    "TSAN_THREAD_HEADER_RE",
    "TSAN_FRAME_LOC_RE",
    "TSAN_MUTEX_RE",
    "TSanSupport",
    "tsan_support",
    "get_tsan_adapter",
]

# ---------------------------------------------------------------------------
# Report grammar
# ---------------------------------------------------------------------------

#: Banner: "WARNING: ThreadSanitizer: data race (pid: 4242)"
TSAN_WARNING_RE = re.compile(
    r"^WARNING:\s*ThreadSanitizer:\s*(?P<kind>[a-z][a-z0-9_-]*"
    r"(?:[ ][a-z0-9_-]+)?)"                       # prose kinds use spaces: "data race"
    r"(?:\s*\((?:potential deadlock(?: (?:on the new mutex|while destroying a mutex))?|"
    r"try lock|real time memory map mode|signal-unsafe call inside a signal|"
    r"instrumentation memory limit|error|[a-z- ]+?)\))?"
    r"(?:\s*\(pid:\s*(?P<pid>\d+)\))?",
    re.IGNORECASE,
)

#: Summary: "SUMMARY: ThreadSanitizer: data race /src/foo.cpp:12:7 in bar()"
#: Kind may be two prose words ("data race"); the location token always
#: carries a "/" or ":" and the optional function follows the word "in".
TSAN_SUMMARY_RE = re.compile(
    r"^SUMMARY:\s*ThreadSanitizer:\s*"
    r"(?P<kind>[a-z][a-z0-9_-]*(?:[ ][a-z0-9_-]+)??)"
    r"\s+(?P<location>\S*[/:]\S*)"
    r"(?:\s+in\s+(?P<func>.+?))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

#: Access description line.  Real TSan spellings include a leading
#: qualifier ("Previous read of size 8 at 0x... by main thread:"), an
#: optional mutex/atomic annotation and the "(tid)" suffix on thread labels:
#:   "Write of size 8 at 0x7b50 by thread T1:"
#:   "Previous read of size 8 at 0x7b50 by main thread:"
#:   "Mutex M1 lock previously acquired by the same thread here:" (handled
#:   separately as context, not as an access).
TSAN_ACCESS_LINE_RE = re.compile(
    r"^(?:(?:Previous|Location)\s+)?"                       # qualifier prefix
    r"(?P<op>Read|Write|V-Read|Atomic\s+Read|Atomic\s+Write|Free|"
    r"Allocation|Deallocation|Lock|Unlock|Try\w*Lock)"
    r"\s+of\s+size\s+(?P<size>\d+)\s+"
    r"at\s+(?P<addr>0x[0-9a-fA-F]+)"
    r"(?:\s+on\s+mutex\s+M\d+)?"
    r"\s+by\s+(?:thread\s+(?P<thread1>T\d+)|(?P<thread2>main\s+thread))"
    r"(?:\s*\(tid=\d+[^)]*\))?"
    r":?\s*$",
    re.IGNORECASE,
)

#: Alternate spelling without "of size N": "Location is stack address ..."
LOCATION_KIND_RE = re.compile(
    r"^Location is (?P<kind>heap|stack|global|unknown) address",
    re.IGNORECASE,
)

#: Thread creation headers.  Two real spellings exist:
#:   "Thread T1 'worker' (t2) created at:"
#:   "Thread T1 (tid=4244, running) created by main thread at:"
TSAN_THREAD_HEADER_RE = re.compile(
    r"^Thread\s+(?P<tid>T\d+)\s*"
    r"(?:\((?:tid=\d+[^)]*|t\d+)\)|'(?P<name>[^']*)')?\s*"
    r"(?:\((?:t\d+|tid=\d+[^)]*)\)|'[^']*')?\s*"
    r"created\s+"
    r"(?:by\s+(?:main\s+thread|thread\s+T\d+|the\s+same\s+thread)"
    r"(?:\s+\([^)]*\))?\s+)?"
    r"at:\s*$",
    re.IGNORECASE,
)

#: Location frame in TSan style: "  func_name file.cpp:12:7 (bin+0x1234)"
#: Function name may contain spaces for C++ signatures; we anchor on the
#: trailing file:line:col (module+offset) pattern instead.
TSAN_FRAME_LOC_RE = re.compile(
    r"^\s+(?P<func>.+?)\s+(?P<file>\S+\.(?:c|cc|cpp|cxx|C|h|hpp|go|rs))"
    r":(?P<line>\d+)(?::(?P<col>\d+))?\s*(?:\((?P<module>[^)+]+)\+0x"
    r"(?P<offset>[0-9a-fA-F]+)\))?\s*$"
)

#: Bare-module frame: "    __tsan_atomic64_compare_exchange_weak (<binary>+0x1)"
TSAN_BARE_FRAME_RE = re.compile(
    r"^\s+(?P<func>\S.*?)\s+\((?P<module>[^)+]+)\+0x(?P<offset>[0-9a-fA-F]+)\)\s*$"
)

#: Mutex identity lines used by lock-order-inversion reports:
#:   "Mutex m3 (loop-lock-A &):"  /  "  #0 pthread_mutex_lock foo.c:5:3"
TSAN_MUTEX_RE = re.compile(
    r"^Mutex\s+(?P<id>m\d+)\s*(?:\((?P<name>[^)]*)\))?[^:]*:\s*$"
)

#: Hint/footer noise worth recording but not parsing structurally.
_TSAN_NOISE_PREFIXES = ("Hint:", "NOTE:", "Stats:")


def _normalise_thread(token: str) -> str:
    """Normalise an access-line thread token to a canonical ``T<n>`` label."""
    token = (token or "").strip().lower()
    if token.startswith("main"):
        return "T0"
    m = re.match(r"t(\d+)", token)
    return f"T{m.group(1)}" if m else token or "T?"


@dataclass(slots=True)
class RaceAccess:
    """One described access inside a TSan warning (read/write/free side)."""

    operation: str = ""            # normalised lowercase, e.g. "write"
    size: int = 0
    address: str = ""              # hex without 0x prefix
    thread: str = ""               # canonical T-label
    location_kind: str = ""        # heap | stack | global | unknown
    frames: List[SanitizerFrame] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "operation": self.operation,
            "size": self.size,
            "address": self.address,
            "thread": self.thread,
            "location_kind": self.location_kind,
            "top_frame": (self.frames[0].short() if self.frames else None),
        }


@dataclass(slots=True)
class TSanParsedWarning:
    """Structured intermediate form of exactly one TSan WARNING block."""

    kind: str = ""                                  # "data-race", ...
    pid: Optional[int] = None
    accesses: List[RaceAccess] = field(default_factory=list)
    thread_creation: Dict[str, SanitizerStack] = field(default_factory=dict)
    mutexes: List[Tuple[str, str]] = field(default_factory=list)  # (id, name)
    summary_location: str = ""
    summary_function: str = ""
    hints: List[str] = field(default_factory=list)
    raw_text: str = ""

    @property
    def racing_threads(self) -> List[str]:
        seen: Dict[str, None] = {}
        for access in self.accesses:
            if access.thread:
                seen.setdefault(access.thread, None)
        return list(seen)

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "pid": self.pid,
            "accesses": [a.as_dict() for a in self.accesses],
            "threads": self.racing_threads,
            "mutexes": [{"id": mid, "name": name} for mid, name in self.mutexes],
            "summary_location": self.summary_location,
            "summary_function": self.summary_function,
            "hints": list(self.hints),
        }


def _collect_frames(lines: Sequence[str], start: int,
                    ) -> Tuple[List[SanitizerFrame], int]:
    """Gather consecutive TSan location frames beginning at *start*."""
    frames: List[SanitizerFrame] = []
    i = start
    n = len(lines)
    while i < n:
        stripped = lines[i]
        if not stripped.strip():
            k = i + 1
            if k < n and (TSAN_FRAME_LOC_RE.match(lines[k])
                          or TSAN_BARE_FRAME_RE.match(lines[k])):
                i += 1
                continue
            break
        m = TSAN_FRAME_LOC_RE.match(stripped)
        if m:
            frame = SanitizerFrame(
                index=len(frames),
                function=m.group("func").strip(),
                file=m.group("file"),
                raw=stripped.strip(),
            )
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
            if m.group("module"):
                frame.module = m.group("module").strip()
            frames.append(frame)
            i += 1
            continue
        b = TSAN_BARE_FRAME_RE.match(stripped)
        if b:
            frame = SanitizerFrame(
                index=len(frames),
                function=b.group("func").strip(),
                module=b.group("module").strip(),
                raw=stripped.strip(),
            )
            frames.append(frame)
            i += 1
            continue
        break
    return frames, i


def parse_tsan_warnings(text: str, *, max_warnings: int = 128) -> List[TSanParsedWarning]:
    """Split a TSan console stream into structured warnings (pure function).

    Never raises on malformed input.  Blocks start at ``WARNING:
    ThreadSanitizer:`` banners and run until the next banner or EOF; the
    SUMMARY line (when present) is attached to the warning it follows.
    *max_warnings* bounds pathological logs; excess blocks are dropped and
    the last kept warning records the drop in ``hints`` (honest signalling).
    """
    if not text:
        return []
    lines = text.splitlines()
    n = len(lines)
    starts = [i for i, ln in enumerate(lines) if TSAN_WARNING_RE.match(ln.strip())]
    warnings: List[TSanParsedWarning] = []
    for idx, start in enumerate(starts):
        if len(warnings) >= max_warnings:
            if warnings:
                warnings[-1].hints.append(
                    f"dropped {len(starts) - idx} further warnings after "
                    f"{max_warnings}-warning limit"
                )
            break
        end = starts[idx + 1] if idx + 1 < len(starts) else n
        warnings.append(_parse_one_block(lines[start:end]))
    return warnings


def _parse_one_block(block_lines: Sequence[str]) -> TSanParsedWarning:
    """Parse one WARNING..EOF slice of TSan output."""
    parsed = TSanParsedWarning(raw_text="\n".join(block_lines))
    head = TSAN_WARNING_RE.match(block_lines[0].strip())
    if head:
        parsed.kind = head.group("kind").strip().lower().replace(" ", "-")
        pid_raw = head.groupdict().get("pid")
        if pid_raw:
            try:
                parsed.pid = int(pid_raw)
            except (TypeError, ValueError):
                parsed.pid = None
    current: Optional[RaceAccess] = None
    i = 1
    n = len(block_lines)
    while i < n:
        line = block_lines[i]
        stripped = line.strip()
        am = TSAN_ACCESS_LINE_RE.match(stripped)
        if am:
            current = RaceAccess(
                operation=re.sub(r"\s+", "-", am.group("op")).lower(),
                size=int(am.group("size")),
                address=am.group("addr").lower().removeprefix("0x"),
                thread=_normalise_thread(am.group("thread1")
                                         or am.group("thread2") or ""),
            )
            frames, j = _collect_frames(block_lines, i + 1)
            current.frames = frames
            parsed.accesses.append(current)
            i = j
            continue
        thm = TSAN_THREAD_HEADER_RE.match(stripped)
        if thm:
            tid = _normalise_thread(thm.group("tid"))
            frames, j = _collect_frames(block_lines, i + 1)
            parsed.thread_creation[tid] = SanitizerStack(
                role=StackRole.THREAD_CREATED, thread=tid, frames=frames)
            i = j
            continue
        mm = TSAN_MUTEX_RE.match(stripped)
        if mm:
            parsed.mutexes.append((mm.group("id"),
                                   (mm.group("name") or "").strip()))
            i += 1
            continue
        lm = LOCATION_KIND_RE.match(stripped)
        if lm and current is not None:
            current.location_kind = lm.group("kind").lower()
            i += 1
            continue
        sm = TSAN_SUMMARY_RE.match(stripped)
        if sm:
            parsed.summary_location = (sm.group("location") or "").strip()
            parsed.summary_function = (sm.group("func") or "").strip()
            if not parsed.kind:
                parsed.kind = (sm.group("kind") or "").lower().replace(" ", "-")
            i += 1
            continue
        if stripped.startswith(_TSAN_NOISE_PREFIXES) and stripped not in parsed.hints:
            parsed.hints.append(stripped)
        i += 1
    # Infer location kinds from top-frame heuristics when TSan printed none.
    for access in parsed.accesses:
        if not access.location_kind and access.frames:
            top = access.frames[0]
            if top.file and top.function and "malloc" in top.function:
                access.location_kind = "heap"
            elif top.file:
                access.location_kind = "global-or-stack"
    return parsed


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class TSANAdapter(SanitizerAdapter):
    """KMCS driver for ThreadSanitizer reports."""

    kind = SanitizerKind.TSAN
    env_var = "TSAN_OPTIONS"
    compile_flag = "-fsanitize=thread"
    display_name = "ThreadSanitizer"
    requires_instrumentation = True
    #: Under halt_on_error TSan aborts on the first warning, but operators
    #: running diagnostic passes may keep going; treat reports as findings.
    reports_without_crash = True

    def default_options(self) -> Dict[str, object]:
        return {
            "halt_on_error": 1,           # campaign runs surface a crash signal
            "report_bugs": 1,
            "second_deadlock_stack": 1,   # both sides of lock inversions traced
            "history_size": 4,            # deeper access history → better dedup
            "detect_deadlocks": 1,
            "detect_leaks": 0,            # LSan ownership stays with ASan runs
            "die_after_failing_test": 1,
            "verbosity": 1,
        }

    def locked_options(self) -> Tuple[str, ...]:
        # These shape *which* warnings appear and how deep their stacks are;
        # changing them mid-campaign would split fingerprints across workers.
        return ("halt_on_error", "second_deadlock_stack", "history_size",
                "detect_deadlocks")

    def class_map(self) -> Dict[str, CrashClass]:
        return dict(TSAN_ERROR_CLASSES)

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
        """Parse TSan output into one SanitizedCrash per WARNING block.

        Both racer stacks become structured :class:`SanitizerStack` entries
        (role CRASH for the first described access, OTHER for subsequent
        ones, THREAD_CREATED for creation traces) so the fingerprinting layer
        can key on the full race signature instead of one side only.
        """
        warnings = parse_tsan_warnings(text)
        if not warnings:
            # Not TSan-shaped (or empty): defer to the shared parser which
            # understands loose summaries, rather than inventing findings.
            return super().parse_report(
                text, source_path=source_path, exit_code=exit_code,
                symbolize=symbolize, binary=binary,
            )
        crashes: List[SanitizedCrash] = []
        for parsed in warnings:
            crash = self._crash_from_warning(parsed, source_path=source_path,
                                             exit_code=exit_code)
            self.enhance(crash)
            crashes.append(crash)
        return crashes

    def _crash_from_warning(
        self,
        parsed: TSanParsedWarning,
        *,
        source_path: Optional[str],
        exit_code: Optional[int],
    ) -> SanitizedCrash:
        kind = parsed.kind or "unknown"
        threads = parsed.racing_threads
        summary_loc = parsed.summary_location or ""
        if parsed.summary_function:
            summary = (f"ThreadSanitizer: {kind} in {parsed.summary_function}"
                       + (f" at {summary_loc}" if summary_loc else ""))
        elif summary_loc:
            summary = f"ThreadSanitizer: {kind} at {summary_loc}"
        else:
            summary = f"ThreadSanitizer: {kind}"
        crash = SanitizedCrash(
            sanitizer=SanitizerKind.TSAN,
            error_kind=kind,
            crash_class=self.classify(kind),
            summary=summary,
            exit_code=exit_code,
            pid=parsed.pid,
            thread=(threads[0] if threads else None),
            source_path=source_path,
            raw_text=parsed.raw_text,
        )
        # Stacks: first described access is the crash-side trace; the other
        # described accesses keep their own traces under OTHER so nothing is
        # silently discarded.
        stacks: List[SanitizerStack] = []
        for pos, access in enumerate(parsed.accesses):
            if not access.frames:
                continue
            role = StackRole.CRASH if pos == 0 else StackRole.OTHER
            stacks.append(SanitizerStack(role=role, thread=access.thread,
                                         frames=list(access.frames)))
        for tid, stack in parsed.thread_creation.items():
            if stack.frames:
                stacks.append(stack)
            del tid  # label already embedded in the stack
        crash.stacks = stacks
        # Structured extras for dedup/severity.
        if len(threads) >= 2:
            crash.extra["racing_threads"] = ",".join(threads[:4])
        elif threads:
            crash.extra["racing_threads"] = threads[0]
        addrs = [a.address for a in parsed.accesses if a.address]
        if addrs:
            crash.fault_address = addrs[0]
            if len(set(addrs)) > 1:
                crash.extra["race_addresses"] = ",".join(dict.fromkeys(addrs[:8]))
        sizes = [a.size for a in parsed.accesses if a.size]
        if sizes:
            crash.access_size = sizes[0]
            if len(set(sizes)) > 1:
                crash.extra["access_sizes"] = ",".join(str(s) for s in sizes[:8])
        ops = [a.operation for a in parsed.accesses if a.operation]
        if ops:
            crash.access_type = ops[0]
            crash.extra["race_operations"] = "+".join(dict.fromkeys(ops[:4]))
        kinds = [a.location_kind for a in parsed.accesses if a.location_kind]
        if kinds:
            crash.extra["location_kinds"] = "+".join(dict.fromkeys(kinds[:4]))
        if parsed.mutexes:
            crash.extra["mutexes"] = ";".join(
                f"{mid}:{name}" if name else mid
                for mid, name in parsed.mutexes[:8])
        if parsed.hints:
            crash.extra["hints"] = " | ".join(parsed.hints[:4])
        if any("limit" in hint for hint in parsed.hints):
            crash.truncated = True
        return crash

    def enhance(self, crash: SanitizedCrash) -> None:
        """Complete classification and annotate race-specific semantics."""
        if crash.crash_class is None:
            crash.crash_class = self.classify(crash.error_kind)
        if crash.error_kind == "data-race":
            crash.extra.setdefault(
                "semantics",
                "Potential concurrency bug: correctness depends on thread "
                "scheduling; fix by synchronising the racing accesses.",
            )
        elif crash.error_kind == "lock-order-inversion":
            crash.extra.setdefault(
                "semantics",
                "Lock-order inversion: potential deadlock under adversarial "
                "scheduling even if it never fired in this run.",
            )


# ---------------------------------------------------------------------------
# Availability probing (real compile+run attempt — never assumed)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TSanSupport:
    """Honest result of probing this host for working ThreadSanitizer."""

    compiler: str
    supported: bool
    version: str = ""
    details: str = ""
    race_detected_in_probe: Optional[bool] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "compiler": self.compiler,
            "supported": self.supported,
            "version": self.version,
            "details": self.details,
            "race_detected_in_probe": self.race_detected_in_probe,
        }


_PROBE_SOURCE = """\
#include <pthread.h>
#include <stdlib.h>

static long g_shared = 0;

static void *worker(void *arg) {
    for (long i = 0; i < 100000; ++i) g_shared += (long)(size_t)arg;
    return NULL;
}

int main(void) {
    pthread_t a, b;
    pthread_create(&a, NULL, worker, (void *)(size_t)1);
    pthread_create(&b, NULL, worker, (void *)(size_t)2);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    return 0;
}
"""


def tsan_support(compiler: Optional[str] = None, *,
                 timeout: float = 60.0) -> TSanSupport:
    """Probe *compiler* for a genuinely functional ThreadSanitizer runtime.

    Compiles a deliberately racy two-thread program with
    ``-fsanitize=thread``, runs it once and checks whether TSan actually
    reported a data race.  Failures (missing clang, missing runtime,
    unsupported platform) are reported verbatim — KMCS prefers an honest
    "unavailable" over fabricated capability.
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
        return TSanSupport(compiler=",".join(c for c in candidates if c),
                           supported=False,
                           details=("no clang found on PATH; TSan ships with "
                                    "the LLVM toolchain (gcc has no equivalent)"))
    version = ""
    try:
        proc = subprocess.run([chosen, "--version"], capture_output=True,
                              text=True, timeout=10, check=False)
        first = (proc.stdout or proc.stderr).splitlines()
        version = first[0].strip() if first else ""
    except (OSError, subprocess.SubprocessError):
        version = "<unknown>"
    with tempfile.TemporaryDirectory(prefix="kmcs-tsan-probe-") as tmp:
        src = Path(tmp) / "probe.c"
        out = Path(tmp) / "probe.bin"
        try:
            src.write_text(_PROBE_SOURCE, encoding="utf-8")
        except OSError as exc:
            return TSanSupport(compiler=chosen, supported=False,
                               version=version,
                               details=f"temp write failed: {exc}")
        try:
            proc = subprocess.run(
                [chosen, "-fsanitize=thread", "-g", "-O1",
                 "-pthread", str(src), "-o", str(out)],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return TSanSupport(compiler=chosen, supported=False,
                               version=version, details="compile probe timed out")
        except OSError as exc:
            return TSanSupport(compiler=chosen, supported=False,
                               version=version, details=f"spawn failed: {exc}")
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
            return TSanSupport(compiler=chosen, supported=False, version=version,
                               details=" | ".join(tail))
        env_extra = {"TSAN_OPTIONS": "halt_on_error=0:report_bugs=1"}
        import os as _os
        run_env = dict(_os.environ)
        run_env.update(env_extra)
        try:
            run = subprocess.run([str(out)], capture_output=True, text=True,
                                 timeout=40, check=False, env=run_env)
        except (OSError, subprocess.SubprocessError) as exc:
            return TSanSupport(compiler=chosen, supported=False, version=version,
                               details=f"compiled but could not execute probe: {exc}")
        combined = (run.stdout or "") + (run.stderr or "")
        race_seen = "WARNING: ThreadSanitizer" in combined
        if race_seen:
            return TSanSupport(compiler=chosen, supported=True, version=version,
                               details="probe race detected by TSan runtime",
                               race_detected_in_probe=True)
        if "FATAL: ThreadSanitizer" in combined:
            return TSanSupport(compiler=chosen, supported=False, version=version,
                               details=("TSan runtime fatal on this host: "
                                        + combined.strip().splitlines()[-1]),
                               race_detected_in_probe=False)
        return TSanSupport(compiler=chosen, supported=False, version=version,
                           details=("probe compiled and ran but no race was "
                                    "reported — TSan likely unsupported here"),
                           race_detected_in_probe=False)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_TSAN_ADAPTER = TSANAdapter()
register_adapter(_TSAN_ADAPTER)


def get_tsan_adapter() -> TSANAdapter:
    """Return the process-wide TSan adapter instance."""
    return _TSAN_ADAPTER


# ---------------------------------------------------------------------------
# Self-smoke test (python -m kmcs.sanitizers.tsan)
# ---------------------------------------------------------------------------


def _smoke() -> int:
    adapter = get_tsan_adapter()
    sample = """\
WARNING: ThreadSanitizer: data race (pid: 4242)
  Write of size 8 at 0x7b50 by thread T1:
    #0 worker /src/race.c:8:22 (probe+0x401234)
    #1 pthread_start (/lib/libpthread.so.0+0x7ea7)

  Previous read of size 8 at 0x7b50 by main thread:
    #0 main /src/race.c:16:12 (probe+0x4012ab)

  Thread T1 (tid=4244, running) created by main thread at:
    #0 pthread_create (/lib/libpthread.so.0+0x973b)
    #1 main /src/race.c:14:3 (probe+0x401290)

SUMMARY: ThreadSanitizer: data race /src/race.c:8:22 in worker
"""
    crashes = adapter.parse_report(sample, source_path="smoke.log", exit_code=66)
    assert len(crashes) == 1, f"expected 1 crash, got {len(crashes)}"
    crash = crashes[0]
    assert crash.error_kind == "data-race", crash.error_kind
    assert crash.crash_class is CrashClass.DATA_RACE, crash.crash_class
    assert crash.pid == 4242, crash.pid
    assert crash.fault_address == "7b50", crash.fault_address
    assert crash.access_size == 8, crash.access_size
    assert crash.access_type == "write", crash.access_type
    assert crash.extra.get("racing_threads") == "T1,T0", crash.extra
    assert crash.extra.get("race_operations") == "write+read", crash.extra
    assert "/src/race.c:8:22" in crash.summary, crash.summary
    assert "worker" in crash.summary, crash.summary
    roles = [(s.role, s.thread) for s in crash.stacks]
    assert (StackRole.CRASH, "T1") in roles, roles
    assert (StackRole.OTHER, "T0") in roles, roles
    assert any(s.role is StackRole.THREAD_CREATED for s in crash.stacks), roles
    env = adapter.prepare_environment({"PATH": "/usr/bin"})
    assert "TSAN_OPTIONS" in env, list(env.keys())
    assert "halt_on_error=1" in env["TSAN_OPTIONS"], env["TSAN_OPTIONS"]
    env2 = adapter.prepare_environment({}, overrides={"halt_on_error": 0})
    assert "halt_on_error=1" in env2["TSAN_OPTIONS"], env2["TSAN_OPTIONS"]
    # Lock-order variant parses too.
    loi = """\
WARNING: ThreadSanitizer: lock-order-inversion (potential deadlock) (pid: 99)
  Cycle in lock order graph: M0 (0x7b10) => M1 (0x7b20) => M0

  Mutex M1 acquired here while holding mutex M0 in main thread:
    #0 pthread_mutex_lock /src/deadlock.c:12:3 (probe+0x401111)
    #1 main /src/deadlock.c:30:3 (probe+0x4011ff)

  Mutex M0 previously acquired by the same thread here:
    #0 pthread_mutex_lock /src/deadlock.c:11:3 (probe+0x401100)

SUMMARY: ThreadSanitizer: lock-order-inversion /src/deadlock.c:12:3 in pthread_mutex_lock
"""
    loi_crashes = adapter.parse_report(loi, source_path="loi.log", exit_code=66)
    assert len(loi_crashes) == 1, len(loi_crashes)
    assert loi_crashes[0].crash_class is CrashClass.LOCK_ORDER_INVERSION, \
        loi_crashes[0].crash_class
    # Garbage input yields zero invented findings.
    assert adapter.parse_report("") == []
    support = tsan_support()
    print(f"tsan smoke: {len(crashes)} race + {len(loi_crashes)} inversion parsed; "
          f"support={support.supported} ({support.details}); env OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
