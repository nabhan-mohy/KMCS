"""UndefinedBehaviorSanitizer (UBSan) adapter for KMCS.

UBSan is the LLVM/GCC runtime checker for *undefined behavior* in C and C++:
integer overflow, division by zero, misaligned accesses, type-punning
violations, out-of-range enum values, null-pointer misuse, unreachable-code
fall-through and more.  Unlike ASan, UBSan reports are **diagnostics**: by
default the program keeps running after a report (unless ``halt_on_error=1``),
so KMCS treats UBSan output as findings even when the process exits cleanly.

This module gives KMCS a first-class, analysis-only driver:

* fuzzing-tuned ``UBSAN_OPTIONS`` policy with locked invariants
  (stack traces always on, halt-on-error under campaigns so the fuzzing
  engine observes a crash signal),
* two report grammars parsed honestly:
    - standalone runtime errors   ``file.cpp:12:7: runtime error: ...``,
    - wrapped diagnostics         ``ERROR/SUMMARY: UndefinedBehaviorSanitizer``,
* per-check-name classification onto :class:`~kmcs.core.models.CrashClass`
  using the shared table in :mod:`kmcs.sanitizers.base`,
* check-group knowledge (``-fsanitize=`` identifiers) used by the build layer
  to request exactly the checks a campaign wants,
* honest availability probing via real compiler subprocess compile attempts
  (never assumed, never faked).

Security posture: this module only *reads and structures* sanitizer
diagnostics produced during authorized fuzzing campaigns.  It contains no
exploit generation, payload crafting or weaponisation of any kind.
Zero external services: standard library plus KMCS core only — no API keys,
no network.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.models import CrashClass, SanitizerKind
from kmcs.sanitizers.base import (
    UBSAN_ERROR_CLASSES,
    SanitizedCrash,
    SanitizerAdapter,
    SanitizerFrame,
    SanitizerStack,
    StackRole,
    register_adapter,
)

__all__ = [
    "UBSANAdapter",
    "UBSAN_CHECKS",
    "UBSAN_IMPLICIT_CHECKS",
    "UBSAN_CHECK_GROUPS",
    "check_names_for_flag",
    "normalise_check_name",
    "UBSAN_RUNTIME_LINE_RE",
    "UBSAN_SUMMARY_RE",
    "UBSAN_STATS_RE",
    "UBSAN_LOCATION_RE",
    "UBSAN_VALUE_RE",
    "parse_ubsan_runtime_line",
    "parse_ubsan_values",
    "UBSanSupport",
    "ubsan_support",
    "get_ubsan_adapter",
]

# ---------------------------------------------------------------------------
# Check knowledge
# ---------------------------------------------------------------------------

#: Individual UBSan checks understood by KMCS (name -> human description).
#: These map directly onto ``-fsanitize=<name>`` identifiers accepted by
#: clang/gcc; KMCS passes them through unchanged but documents them here so
#: reports can be explained to researchers without consulting man pages.
UBSAN_CHECKS: Dict[str, str] = {
    "alignment": "Misaligned memory address used in load/store or cast.",
    "bool": "Load of a bool that is neither 0 nor 1.",
    "builtin": "Invalid arguments to __builtin_* intrinsics.",
    "bounds": "Array index outside the declared bounds (C99 VLA aware).",
    "char16-stride-mismatch": "UTF-16 string stride mismatch.",
    "compare": "Comparisons with invalid or unordered operands.",
    "division-by-zero": "Integer division (or remainder) by zero.",
    "enum-constexpr-conversion": "Constant expression converts to invalid enum value.",
    "enum-count": "Loads an enum value outside its enumerator set.",
    "float-cast-overflow": "Floating-point value cannot be represented in target integer type.",
    "float-divide-by-zero": "Floating-point division by zero.",
    "function": "Calling through a null or mis-typed function pointer.",
    "implicit-unsigned-integer-truncation": "Truncating unsigned conversion (implicit group).",
    "implicit-signed-integer-truncation": "Truncating signed conversion (implicit group).",
    "implicit-integer-sign-change": "Sign-changing implicit conversion (implicit group).",
    "integer-divide-by-zero": "Integer division or modulo by zero.",
    "nonnull": "Null passed to a parameter declared nonnull.",
    "nonnull-attribute": "Null argument to function with __attribute__((nonnull)).",
    "null": "Null pointer dereference (load/store through null).",
    "nullability": "Combined null + nonnull checks.",
    "object-size": "Access beyond the object size known from __builtin_object_size.",
    "pointer-compare": "Comparison of pointers to unrelated objects.",
    "pointer-overflow": "Pointer arithmetic wrapping around the address space.",
    "readable": "Read through an invalid (null/misaligned) pointer.",
    "return-nonnull": "Function declared returning nonnull returns null.",
    "shift": "Shift amount too large or negative shift operand.",
    "shift-base": "Left-shift of a negative base value.",
    "shift-exponent": "Shift exponent out of range.",
    "signed-integer-overflow": "Signed addition/subtraction/multiplication overflow.",
    "unsigned-integer-overflow": "Unsigned overflow (only with trap behaviour).",
    "sub-object-format": "printf-style format/specifier mismatch on subobjects.",
    "unaligned": "Unaligned load/store access.",
    "unreachable": "Control flow reached __builtin_unreachable()/noreturn end.",
    "vla-bound": "VLA bound changed between definition and use.",
    "writable": "Write through an invalid pointer.",
    "vptr": "Virtual call on an object with a bad vtable pointer.",
    "virtual-call": "Virtual function called on null object.",
}

#: Checks enabled by the ``undefined`` umbrella group (documentation aid).
UBSAN_IMPLICIT_CHECKS: Tuple[str, ...] = (
    "alignment",
    "bool",
    "builtin",
    "float-cast-overflow",
    "float-divide-by-zero",
    "integer-divide-by-zero",
    "nonnull",
    "object-size",
    "return-nonnull",
    "signed-integer-overflow",
    "unreachable",
    "unsigned-integer-overflow",
    "vla-bound",
)

#: Convenience groups accepted by ``-fsanitize=``.
UBSAN_CHECK_GROUPS: Dict[str, Tuple[str, ...]] = {
    "undefined": UBSAN_IMPLICIT_CHECKS,
    "integer": ("signed-integer-overflow", "unsigned-integer-overflow", "shift",
                "division-by-zero", "float-cast-overflow"),
    "null": ("null", "nonnull", "return-nonnull"),
    "implicit": ("implicit-unsigned-integer-truncation",
                 "implicit-signed-integer-truncation",
                 "implicit-integer-sign-change"),
    "implicit-conversion": ("implicit-unsigned-integer-truncation",
                            "implicit-signed-integer-truncation",
                            "implicit-integer-sign-change"),
}


def check_names_for_flag(flag_value: str) -> Tuple[str, ...]:
    """Expand a ``-fsanitize=`` payload (comma separated) into concrete names.

    Group names are expanded; unknown names pass through untouched so newer
    compiler releases keep working.  Pure function -- unit-testable offline.
    """
    names: List[str] = []
    for token in (flag_value or "").split(","):
        token = token.strip()
        if not token:
            continue
        if token in UBSAN_CHECK_GROUPS:
            names.extend(UBSAN_CHECK_GROUPS[token])
        else:
            names.append(token)
    seen: Dict[str, None] = {}
    for name in names:
        seen.setdefault(name, None)
    return tuple(seen)


# ---------------------------------------------------------------------------
# Report grammar
# ---------------------------------------------------------------------------

#: Standalone UBSan runtime line: ``src/file.cpp:12:7: runtime error: msg``
#: (also accepts absolute paths; angle-bracket pseudo-files are excluded at
#: the start to avoid matching ``<stdin>`` headers as file names).
UBSAN_RUNTIME_LINE_RE = re.compile(
    r"^(?P<file>[^\s<>][^:\n]*):(?P<line>\d+):(?P<col>\d+):\s*"
    r"runtime error:\s*(?P<message>.*)$"
)

#: Wrapped summary line emitted next to many UBSan reports.
UBSAN_SUMMARY_RE = re.compile(
    r"^SUMMARY:\s*UndefinedBehaviorSanitizer(?:\s*\[\d+\])?:\s*"
    r"(?P<location>\S+)\s*:\s*(?P<message>.*)$"
)

#: Trailing statistics block printed with ``print_stats=1``.
UBSAN_STATS_RE = re.compile(
    r"^\s*(?P<count>\d+)\s+(?P<kind>unique|non-unique)\s+checks\s+"
    r"(?P<failures>\d+)\s+times\s+failed,\s+covering\s+(?P<kinds>\d+)\s+kinds",
    re.MULTILINE,
)

#: Values embedded in messages: ``... 2147483647 + 1 cannot be represented ...``
UBSAN_VALUE_RE = re.compile(r"-?\d{1,20}")

#: Location inside a note/frame header: ``foo.cpp:20:5``
UBSAN_LOCATION_RE = re.compile(
    r"(?P<file>[^\s:][^:\n]*):(?P<line>\d+)(?::(?P<col>\d+))?"
)

#: Prose-message prefixes mapped onto canonical check tokens.  The compiler
#: writes prose ("signed integer overflow") while our classification table is
#: keyed by dash spellings; this bridges the two deterministically.
_PROSE_TO_CHECK: Tuple[Tuple[str, str], ...] = (
    ("signed integer overflow", "signed-integer-overflow"),
    ("unsigned integer overflow", "unsigned-integer-overflow"),
    ("integer overflow", "integer-overflow"),
    ("division by zero", "division-by-zero"),
    ("divide by zero", "division-by-zero"),
    ("misaligned address", "misaligned-address"),
    ("object-size-mismatch", "object-size"),
    ("execution reached a statement marked unreachable", "unreachable"),
    ("call to function", "function-mismatch"),
    ("member call on null pointer", "null-pointer-use"),
    ("load of null pointer", "null-pointer-use"),
    ("store to null pointer", "null-pointer-use"),
    ("nan cannot be represented", "float-cast-overflow"),
    ("infinity cannot be represented", "float-cast-overflow"),
    ("value out of range for type", "float-cast-overflow"),
    ("left shift of", "left-shift-overflow"),
    ("shift exponent", "shift-out-of-bounds"),
    ("is not in range of type", "enum-encoding-not-valid"),
    ("dereference of null pointer", "null-pointer-use"),
    ("passing null pointer to parameter declared non-null", "nonnull-argument"),
    ("null returned from function that must return nonnull", "return-nonnull"),
    ("changing vla bound", "vla-bound-not-constant"),
)


def normalise_check_name(message: str) -> str:
    """Turn a free-form UBSan message into a canonical check-ish token.

    ``signed integer overflow: 2147483647 + 1 ...`` -> ``signed-integer-overflow``
    Unknown messages fall back to the dashed leading phrase; callers must
    treat unrecognised tokens as *unknown*, never guess a severity.
    """
    message = (message or "").strip()
    if not message:
        return ""
    head = message.split(":", 1)[0].strip().lower()
    # Direct dash-spelling hit against the classification table wins.
    dashed = re.sub(r"[^a-z0-9]+", "-", head).strip("-")
    if dashed in UBSAN_ERROR_CLASSES:
        return dashed
    # Prose prefix lookup, longest needle first for determinism.
    for needle, canonical in sorted(_PROSE_TO_CHECK, key=lambda p: -len(p[0])):
        if head.startswith(needle):
            return canonical
    # Whole-message scan fallback (some variants embed the prose later).
    for needle, canonical in sorted(_PROSE_TO_CHECK, key=lambda p: -len(p[0])):
        if needle in message.lower():
            return canonical
    return dashed


def parse_ubsan_runtime_line(line: str) -> Optional[Dict[str, str]]:
    """Parse one standalone runtime-error line into structured fields."""
    match = UBSAN_RUNTIME_LINE_RE.match((line or "").strip())
    if not match:
        return None
    message = match.group("message").strip()
    return {
        "file": match.group("file").strip(),
        "line": match.group("line"),
        "column": match.group("col"),
        "message": message,
        "check": normalise_check_name(message),
    }


def parse_ubsan_values(message: str) -> List[int]:
    """Extract numeric operands mentioned in a UBSan message (for triage)."""
    values: List[int] = []
    for raw in UBSAN_VALUE_RE.findall(message or ""):
        try:
            values.append(int(raw))
        except ValueError:
            continue
    return values


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class UBSANAdapter(SanitizerAdapter):
    """KMCS driver for UndefinedBehaviorSanitizer reports."""

    kind = SanitizerKind.UBSAN
    env_var = "UBSAN_OPTIONS"
    compile_flag = "-fsanitize=undefined"
    display_name = "UndefinedBehaviorSanitizer"
    requires_instrumentation = True
    #: UBSan prints diagnostics without necessarily aborting; those are still
    #: findings worth recording.
    reports_without_crash = True

    # ---------------- environment policy ----------------

    def default_options(self) -> Dict[str, object]:
        return {
            "print_stacktrace": 1,      # every diagnostic gets frames -> fingerprints
            "halt_on_error": 1,         # campaign runs must surface a crash signal
            "abort_on_error": 0,        # halt path already yields a fatal signal
            "silence_unsigned_overflow_check": 0,
            "diagnose_suppressed_errors": 0,
        }

    def locked_options(self) -> Tuple[str, ...]:
        # print_stacktrace/halt_on_error are campaign-wide invariants: changing
        # them mid-run would split fingerprints and hide crashes from AFL++.
        return ("print_stacktrace", "halt_on_error")

    def class_map(self) -> Dict[str, CrashClass]:
        return dict(UBSAN_ERROR_CLASSES)

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
        """Parse UBSan output into structured crashes.

        Handles both wrapped ``ERROR: UndefinedBehaviorSanitizer`` blocks
        (delegated to the shared base parser which understands the common
        sanitizer grammar) and pure standalone ``file:line:col: runtime
        error:`` streams with no ERROR banner at all.
        """
        text = text or ""
        wrapped_markers = ("ERROR: UndefinedBehaviorSanitizer",
                           "SUMMARY: UndefinedBehaviorSanitizer")
        results: List[SanitizedCrash] = []

        if any(marker in text for marker in wrapped_markers):
            results.extend(
                super().parse_report(
                    text, source_path=source_path, exit_code=exit_code,
                    symbolize=symbolize, binary=binary,
                )
            )

        standalone_lines = [
            ln for ln in text.splitlines()
            if UBSAN_RUNTIME_LINE_RE.match(ln.strip())
        ]
        if standalone_lines:
            results.extend(
                self._parse_standalone_stream(text, source_path=source_path,
                                              exit_code=exit_code)
            )
        if not results:
            # Fall back to the base parser: it may still recognise loose
            # summaries we do not explicitly handle.
            results.extend(
                super().parse_report(
                    text, source_path=source_path, exit_code=exit_code,
                    symbolize=False, binary=None,
                )
            )
        return results

    def _parse_standalone_stream(
        self,
        full_text: str,
        *,
        source_path: Optional[str],
        exit_code: Optional[int],
    ) -> List[SanitizedCrash]:
        """Group runtime-error lines + their notes/frames into reports.

        One UBSan *report* is a runtime-error line optionally followed by
        indented frame lines (``#N ...``) and ``note:`` lines (e.g. the
        allocation site).  Distinct error sites are distinct findings;
        byte-identical repeats collapse into one report with an occurrence
        counter (honest counting, no invention).
        """
        lines = full_text.splitlines()
        crashes: List[SanitizedCrash] = []
        i = 0
        n = len(lines)
        while i < n:
            stripped = lines[i].strip()
            parsed = parse_ubsan_runtime_line(stripped)
            if parsed is None:
                i += 1
                continue
            block_lines = [stripped]
            j = i + 1
            while j < n:
                nxt = lines[j].strip()
                is_new_error = parse_ubsan_runtime_line(nxt) is not None
                if is_new_error:
                    break
                if nxt.startswith("note:") or nxt.startswith("#"):
                    block_lines.append(nxt)
                    j += 1
                    continue
                if not nxt:
                    # Blank line: only part of the block if continuation
                    # follows that is clearly still this report's context.
                    k = j + 1
                    while k < n and not lines[k].strip():
                        k += 1
                    if k < n and (lines[k].strip().startswith("#")
                                  or lines[k].strip().startswith("note:")):
                        block_lines.append(nxt)
                        j += 1
                        continue
                    break
                break
            crash = self._build_from_parsed(parsed, "\n".join(block_lines),
                                            source_path=source_path,
                                            exit_code=exit_code)
            duplicate = False
            for existing in reversed(crashes[-3:]):
                if (existing.extra.get("check") == crash.extra.get("check")
                        and existing.summary == crash.summary):
                    occ = int(existing.extra.get("occurrences", "1")) + 1
                    existing.extra["occurrences"] = str(occ)
                    duplicate = True
                    break
            if not duplicate:
                crashes.append(crash)
            i = j
        return crashes

    def _build_from_parsed(
        self,
        parsed: Mapping[str, str],
        raw_block: str,
        *,
        source_path: Optional[str],
        exit_code: Optional[int],
    ) -> SanitizedCrash:
        check = parsed.get("check") or ""
        message = parsed.get("message") or ""
        crash = SanitizedCrash(
            sanitizer=SanitizerKind.UBSAN,
            error_kind=check,
            crash_class=self.classify(check) or self._classify_message(message),
            summary=(f"{parsed['file']}:{parsed['line']}:{parsed['column']}: "
                     f"runtime error: {message}"),
            exit_code=exit_code,
            source_path=source_path,
            raw_text=raw_block,
        )
        crash.extra["check"] = check
        crash.extra["description"] = message
        crash.extra["location_file"] = parsed["file"]
        crash.extra["location_line"] = parsed["line"]
        crash.extra["location_column"] = parsed["column"]
        values = parse_ubsan_values(message)
        if values:
            crash.extra["operand_values"] = ",".join(str(v) for v in values[:8])
        addr_m = re.search(r"\b0x([0-9a-fA-F]{1,16})\b", message)
        if addr_m:
            crash.fault_address = addr_m.group(1).lower()
        crash.stacks = self._stacks_from_block(raw_block, parsed)
        stats_m = UBSAN_STATS_RE.search(raw_block)
        if stats_m:
            crash.stats["ubsan_unique_checks"] = int(stats_m.group("count"))
            crash.stats["ubsan_failures"] = int(stats_m.group("failures"))
        return crash

    def _classify_message(self, message: str) -> Optional[CrashClass]:
        """Secondary classification path when the check token is unknown."""
        lowered = (message or "").lower()
        probes: Tuple[Tuple[str, CrashClass], ...] = (
            ("signed integer overflow", CrashClass.INTEGER_OVERFLOW),
            ("unsigned integer overflow", CrashClass.INTEGER_OVERFLOW),
            ("division by zero", CrashClass.DIVIDE_BY_ZERO),
            ("integer overflow", CrashClass.INTEGER_OVERFLOW),
            ("misaligned address", CrashClass.MISALIGNED_ACCESS),
            ("type-punned pointer", CrashClass.TYPE_MISSMATCH),
            ("load of null pointer", CrashClass.NULL_DEREFERENCE),
            ("store to null pointer", CrashClass.NULL_DEREFERENCE),
            ("member call on null", CrashClass.NULL_DEREFERENCE),
            ("cannot be represented in type", CrashClass.INTEGER_OVERFLOW),
            ("executed unreachable statement", CrashClass.UNREACHABLE_CODE),
            ("statement marked unreachable", CrashClass.UNREACHABLE_CODE),
            ("not in range of type", CrashClass.ENUM_OUT_OF_RANGE),
            ("shift exponent", CrashClass.SIGNED_SHIFT_OVERFLOW),
            ("left shift of", CrashClass.SIGNED_SHIFT_OVERFLOW),
            ("declared non-null", CrashClass.NULL_ARGUMENT),
            ("changing vla bound", CrashClass.VLA_BOUND_CHANGE),
        )
        for needle, cls in probes:
            if needle in lowered:
                return cls
        return None

    def _stacks_from_block(
        self, block: str, parsed: Mapping[str, str]
    ) -> List[SanitizerStack]:
        """Build stacks for a standalone UBSan report.

        The primary frame comes from the ``file:line:col`` headline (function
        names recovered from ``#N ... in func`` frame lines when present);
        ``note:`` lines contribute an ALLOCATION-role stack describing where
        the offending object was created.
        """
        top = SanitizerFrame(
            index=0,
            file=parsed.get("file"),
            line=int(parsed.get("line", -1) or -1),
            column=int(parsed.get("column", -1) or -1),
            raw=f"{parsed.get('file')}:{parsed.get('line')}:{parsed.get('column')}",
        )
        for line in block.splitlines()[1:]:
            stripped = line.strip()
            if not stripped.startswith("#"):
                continue
            # Preferred grammar: "#N 0xADDR in function file:line"
            im = re.match(
                r"#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+([^\s(]+)", stripped
            )
            candidate: Optional[str] = im.group(1) if im else None
            if candidate is None:
                im2 = re.match(r"#\d+\s+(?:0x[0-9a-fA-F]+\s+)?([^\s(]+)", stripped)
                candidate = im2.group(1) if im2 else None
            if candidate and "(" not in candidate and candidate != "in":
                top.function = candidate
                break
        stacks = [SanitizerStack(role=StackRole.CRASH, thread=None, frames=[top])]

        note_frames: List[SanitizerFrame] = []
        for line in block.splitlines()[1:]:
            stripped = line.strip()
            if not stripped.startswith("note:"):
                continue
            lm = UBSAN_LOCATION_RE.search(stripped)
            note = SanitizerFrame(index=len(note_frames), raw=stripped)
            if lm:
                note.file = lm.group("file")
                try:
                    note.line = int(lm.group("line"))
                except (TypeError, ValueError):
                    pass
                try:
                    col = lm.group("col")
                except (IndexError, re.error):
                    col = None
                if col:
                    try:
                        note.column = int(col)
                    except (TypeError, ValueError):
                        pass
            note_frames.append(note)
        if note_frames:
            stacks.append(SanitizerStack(role=StackRole.ALLOCATION, thread=None,
                                         frames=note_frames))
        return stacks

    # ---------------- enrichment ----------------

    def enhance(self, crash: SanitizedCrash) -> None:
        """Attach check documentation and complete missing classifications."""
        check = crash.extra.get("check") or crash.error_kind or ""
        doc = UBSAN_CHECKS.get(check)
        if doc:
            crash.extra.setdefault("check_description", doc)
        if crash.crash_class is None:
            crash.crash_class = self.classify(check) or self._classify_message(
                crash.extra.get("description", "") or crash.error_kind
            )


# ---------------------------------------------------------------------------
# Availability probing (real subprocess compile attempt -- never assumed)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class UBSanSupport:
    """Result of probing one compiler for UBSan support."""

    compiler: str
    supported: bool
    version: str = ""
    details: str = ""
    checked: bool = True

    def as_dict(self) -> Dict[str, object]:
        return {
            "compiler": self.compiler,
            "supported": self.supported,
            "version": self.version,
            "details": self.details,
            "checked": self.checked,
        }


_PROBE_PROGRAM = (
    "#include <stdlib.h>\n"
    "int main(void) { volatile int x = 1; volatile int y = 1; return x / y; }\n"
)


def ubsan_support(compiler: Optional[str] = None, *,
                  timeout: float = 25.0) -> UBSanSupport:
    """Probe *compiler* (default: first of clang/clang++/gcc/g++ on PATH).

    Performs a genuine compile-and-link with ``-fsanitize=undefined`` in a
    temporary directory, then executes the probe once to prove the runtime
    library is present.  Returns an honest :class:`UBSanSupport`; never
    raises for missing tools -- KMCS reports unavailability instead of
    pretending.
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
        return UBSanSupport(compiler=",".join(c for c in candidates if c),
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
    with tempfile.TemporaryDirectory(prefix="kmcs-ubsan-probe-") as tmp:
        src = Path(tmp) / "probe.c"
        out = Path(tmp) / "probe.bin"
        try:
            src.write_text(_PROBE_PROGRAM, encoding="utf-8")
        except OSError as exc:
            return UBSanSupport(compiler=chosen, supported=False,
                                version=version,
                                details=f"temp write failed: {exc}")
        try:
            proc = subprocess.run(
                [chosen, "-fsanitize=undefined", "-fno-omit-frame-pointer",
                 "-g", str(src), "-o", str(out)],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return UBSanSupport(compiler=chosen, supported=False,
                                version=version, details="compile probe timed out")
        except OSError as exc:
            return UBSanSupport(compiler=chosen, supported=False,
                                version=version, details=f"spawn failed: {exc}")
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
            return UBSanSupport(compiler=chosen, supported=False, version=version,
                                details=" | ".join(tail))
        try:
            run = subprocess.run([str(out)], capture_output=True, timeout=10,
                                 check=False)
            ok = run.returncode == 0
            detail = ("compile+link+run OK" if ok
                      else f"runtime exited {run.returncode}")
        except (OSError, subprocess.SubprocessError) as exc:
            ok = False
            detail = f"compiled but could not execute probe: {exc}"
        return UBSanSupport(compiler=chosen, supported=ok, version=version,
                            details=detail)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_UBSAN_ADAPTER = UBSANAdapter()
register_adapter(_UBSAN_ADAPTER)


def get_ubsan_adapter() -> UBSANAdapter:
    """Return the process-wide UBSan adapter instance."""
    return _UBSAN_ADAPTER


# ---------------------------------------------------------------------------
# Self-smoke test (python -m kmcs.sanitizers.ubsan)
# ---------------------------------------------------------------------------


def _smoke() -> int:
    adapter = get_ubsan_adapter()
    sample = (
        "test_ubsan.cpp:10:13: runtime error: signed integer overflow: "
        "2147483647 + 1 cannot be represented in type 'int'\n"
        "    #0 0x401234 in main test_ubsan.cpp:10\n"
        "    #1 0x7f8 in __libc_start_main (/lib/libc.so.6+0x1)\n"
        "test_ubsan.cpp:14:9: runtime error: division by zero\n"
        "note: buffer created here alloc.cpp:20:5\n"
    )
    crashes = adapter.parse_report(sample, source_path="smoke.log", exit_code=1)
    assert crashes, "standalone stream should parse"
    kinds = [c.error_kind for c in crashes]
    assert kinds[0] == "signed-integer-overflow", kinds
    assert crashes[0].crash_class is CrashClass.INTEGER_OVERFLOW, crashes[0].crash_class
    assert any(c.crash_class is CrashClass.DIVIDE_BY_ZERO for c in crashes), \
        [c.crash_class for c in crashes]
    div = [c for c in crashes if c.crash_class is CrashClass.DIVIDE_BY_ZERO][0]
    assert div.stacks and div.stacks[-1].role is StackRole.ALLOCATION, div.stacks
    env = adapter.prepare_environment({"PATH": "/usr/bin"},
                                      campaign_options={"halt_on_error": 1})
    assert "UBSAN_OPTIONS" in env, list(env.keys())
    assert "print_stacktrace=1" in env["UBSAN_OPTIONS"], env["UBSAN_OPTIONS"]
    names = check_names_for_flag("undefined,integer,bounds")
    assert "bounds" in names and "signed-integer-overflow" in names, names
    assert parse_ubsan_values("signed integer overflow: 2147483647 + 1 ...") == \
        [2147483647, 1]
    support = ubsan_support()
    print(f"ubsan smoke: {len(crashes)} crashes parsed; "
          f"support={support.supported} ({support.compiler}); env OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
