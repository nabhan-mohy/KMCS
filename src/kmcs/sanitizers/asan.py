"""AddressSanitizer (ASan) and HWAddressSanitizer (HWASan) adapter.

AddressSanitizer is the workhorse memory-error detector of the LLVM/GCC
toolchain: it catches heap/stack/global buffer overflows, use-after-free,
double frees, allocator misuse and (via LeakSanitizer) leaks.  This module
gives KMCS a first-class, *analysis-only* driver for it:

* fuzzing-tuned ``ASAN_OPTIONS`` policy with locked invariants
  (fast unsymbolized reports under fuzzing; symbolization happens offline so
  thousands of parallel workers don't each pay for it),
* full report parsing inherited from :mod:`kmcs.sanitizers.base` plus ASan
  specifics: shadow-byte annotations, poison patterns, allocation hints,
* HWASan tag-based diagnostics ("Tags don't match", memory tags),
* suppression-file helpers (LSAN-style leak suppressions are shared),
* honest capability probing (compiler support detection via real subprocess
  compile attempts — never assumed).

Nothing in this module executes exploit code or crafts weaponised inputs; it
only *reads* sanitizer diagnostics produced by authorized fuzzing campaigns.
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
    ADAPTER_REGISTRY,
    ASAN_ERROR_CLASSES,
    SUMMARY_LINE_RE,
    SanitizedCrash,
    SanitizerAdapter,
    SanitizerEnvPolicy,
    register_adapter,
)

__all__ = [
    "ASANAdapter",
    "HWASANAdapter",
    "asan_support",
    "hwasan_support",
    "detect_shadow_annotation",
    "parse_allocation_hint",
    "build_suppression_file",
    "ASAN_SHADOW_PATTERNS",
]

# ---------------------------------------------------------------------------
# Shadow byte knowledge (documentation + light analysis aid)
# ---------------------------------------------------------------------------

#: Human-readable meanings of common ASan shadow-byte tags.  Used only to
#: *explain* reports in structured output — never to decide severity.
ASAN_SHADOW_PATTERNS: Dict[str, str] = {
    "00": "addressable",
    "01": "partial redzone (1/8 bytes poisoned)",
    "02": "2-byte left redzone",
    "03": "3-byte left redzone",
    "04": "4-byte left redzone",
    "05": "5-byte left redzone",
    "06": "6-byte left redzone",
    "07": "heap left redzone / freed heap region prefix",
    "08": "8-byte left redzone",
    "09": "9-byte left redzone",
    "0a": "10-byte left redzone",
    "0b": "11-byte left redzone",
    "0c": "12-byte left redzone",
    "0d": "13-byte left redzone",
    "0e": "14-byte left redzone",
    "0f": "15-byte left redzone",
    "f1": "left global redzone (array start padding)",
    "f2": "mid global redzone",
    "f3": "right global redzone (array end padding)",
    "f5": "stack left redzone",
    "f6": "stack mid redzone",
    "f7": "stack right redzone",
    "f8": "stack after return (use-after-return poison)",
    "f9": "stack use after scope (poisoned local)",
    "fa": "global redzone",
    "fb": "global array begin/end marker",
    "fc": "container overflow (poisoned interior)",
    "fd": "left redzone (generic, freed heap region)",
    "fe": "intra-object redzone",
    "ff": "poisoned / non-asan addressable gap",
}

_FREED_REGION_RE = re.compile(r"is located (?:(-?\d+) bytes )?(inside|outside) of (\d+)-byte region")
_UAF_HINT_RE = re.compile(r"(?:freed|deallocated) by thread T(\d+) here")
_POISON_TAG_RE = re.compile(r"Shadow byte annotation \('([^']*)'\)")


def detect_shadow_annotation(crash: SanitizedCrash) -> Optional[str]:
    """Return the meaning of the shadow byte marked ``[...]`` in the dump."""
    line = crash.shadow_line or ""
    m = _POISON_TAG_RE.search(line)
    if m:
        return m.group(1)
    # Find bracketed token in raw text, e.g. "[fd]" or "f[8]".
    bm = re.search(r"[0-9a-f]*\[([0-9a-f]{2})\][0-9a-f]*", crash.raw_text)
    if bm:
        return ASAN_SHADOW_PATTERNS.get(bm.group(1))
    return None


def parse_allocation_hint(crash: SanitizedCrash) -> Dict[str, object]:
    """Extract 'located N bytes inside of M-byte region' geometry facts."""
    out: Dict[str, object] = {}
    m = _FREED_REGION_RE.search(crash.raw_text)
    if m:
        offset = int(m.group(1)) if m.group(1) else 0
        out["region_size"] = int(m.group(3))
        out["region_relation"] = m.group(2)
        out["offset_within_region"] = offset if m.group(2) == "inside" else -offset
        if crash.allocation_size is None:
            crash.allocation_size = int(m.group(3))
    return out


# ---------------------------------------------------------------------------
# Suppressions (leak & known-benign noise)
# ---------------------------------------------------------------------------


def build_suppression_file(entries: Sequence[Tuple[str, str]], path: Path) -> Path:
    """Write an LSAN/ASan-style suppression file atomically.

    ``entries`` are ``(kind, pattern)`` pairs where kind is one of
    ``leak``, ``called_from_lib``, ``direct_leak`` … and *pattern* is a
    function-name regex.  Malformed entries are rejected loudly — silent
    drops would hide findings.
    """
    lines: List[str] = []
    for kind, pattern in entries:
        if not re.fullmatch(r"(leak|called_from_lib|direct_leak|indirect_leak)", kind):
            raise ValueError(f"invalid suppression kind: {kind!r}")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid suppression regex {pattern!r}: {exc}") from exc
        lines.append(f"{kind}:{pattern}")
    text = "\n".join(lines) + ("\n" if lines else "")
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)
    return path


# ---------------------------------------------------------------------------
# Compiler support probes (real subprocess checks, honestly reported)
# ---------------------------------------------------------------------------

_PROBE_SRC = "int main(void){int*x=(int*)malloc(4);(void)x;return 0;}"
_PROBE_PREFIX = "#include <stdlib.h>\n"


@dataclass(slots=True)
class SupportProbe:
    """Result of probing whether a compiler can build with a sanitizer."""

    available: bool
    compiler: str
    notes: List[str] = field(default_factory=list)
    version: str = ""


def _run_probe(compiler: str, flag: str, timeout: float = 25.0) -> Tuple[bool, str, List[str]]:
    path = shutil.which(compiler)
    if not path:
        return False, "", [f"{compiler} not on PATH"]
    notes: List[str] = []
    version = ""
    try:
        proc = subprocess.run(  # fixed argv, no shell
            [path, "--version"], capture_output=True, text=True, timeout=timeout, check=False
        )
        if proc.returncode == 0:
            version = proc.stdout.splitlines()[0].strip() if proc.stdout else ""
    except (OSError, subprocess.SubprocessError):
        pass
    with tempfile.TemporaryDirectory(prefix="kmcs-san-probe-") as td:
        src = Path(td) / "probe.c"
        out = Path(td) / "probe.bin"
        src.write_text(_PROBE_PREFIX + _PROBE_SRC)
        try:
            proc = subprocess.run(  # fixed argv, no shell
                [path, flag, "-g", "-O0", str(src), "-o", str(out)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, version, notes + [f"{compiler} probe timed out"]
        except OSError as exc:
            return False, version, notes + [f"{compiler} probe failed: {exc}"]
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip().splitlines()
            hint = stderr[0] if stderr else f"exit {proc.returncode}"
            return False, version, notes + [f"{compiler} does not accept '{flag}': {hint}"]
        return True, version, notes


def asan_support(compiler: Optional[str] = None) -> SupportProbe:
    """Probe whether *compiler* (default cc/gcc/clang sweep) supports ASan."""
    compilers = [compiler] if compiler else ["clang", "gcc", "cc"]
    for cand in compilers:
        ok, version, notes = _run_probe(cand, "-fsanitize=address")
        if ok:
            return SupportProbe(True, cand, notes, version)
    merged_notes: List[str] = []
    for cand in compilers:
        ok, version, notes = _run_probe(cand, "-fsanitize=address")
        merged_notes.extend(notes)
    return SupportProbe(False, compilers[0], merged_notes)


def hwasan_support(compiler: Optional[str] = None) -> SupportProbe:
    """Probe HWASan support (needs clang + hardware/arch support)."""
    compilers = [compiler] if compiler else ["clang"]
    for cand in compilers:
        ok, version, notes = _run_probe(cand, "-fsanitize=hwaddress")
        if ok:
            return SupportProbe(True, cand, notes, version)
    return SupportProbe(False, compilers[0], ["hwaddress requires clang on supported arch"])


# ---------------------------------------------------------------------------
# The ASan adapter
# ---------------------------------------------------------------------------


class ASANAdapter(SanitizerAdapter):
    """Drive AddressSanitizer diagnostics for fuzzing campaigns."""

    kind = SanitizerKind.ASAN
    env_var = "ASAN_OPTIONS"
    compile_flag = "-fsanitize=address"
    display_name = "AddressSanitizer"
    requires_instrumentation = True
    reports_without_crash = False

    # ---- options -------------------------------------------------------

    def default_options(self) -> Dict[str, object]:
        return {
            # Fuzzers want fast, unsymbolized inline reports; symbolization
            # is done offline (KMCS Phase 5b) to keep worker CPU free.
            "symbolize": 0,
            "external_symbolizer_path": "",
            "fast_unwind_on_fatal": 1,
            "abort_on_error": 0,
            "print_stacktrace": 1,
            "handle_segv": 1,
            "handle_abort": 1,
            "handle_sigill": 1,
            "allocator_release_to_os_interval_ms": 500,
            "detect_odr_violation": 0,
            "use_after_scope": 1,
            "detect_stack_use_after_return": 1,
            "check_initialization_order": 1,
            "dedup_token_length": 3,
            "print_full_thread_history": 0,
            "max_unused_forbidden_memory_mb": 4096,
            "verbosity": 0,
        }

    def locked_options(self) -> Tuple[str, ...]:
        # Turning these off would silently mask classes of bugs — the whole
        # point of running ASan under fuzzing.
        return ("use_after_scope", "detect_stack_use_after_return", "check_initialization_order")

    def option_conflicts(self) -> Tuple[Tuple[str, str], ...]:
        # strict_init_order without check_initialization_order is meaningless.
        return (("strict_init_order", "check_initialization_order"),)

    # ---- classification ------------------------------------------------

    def class_map(self) -> Dict[str, CrashClass]:
        return dict(ASAN_ERROR_CLASSES)

    # ---- enrichment ----------------------------------------------------

    def enhance(self, crash: SanitizedCrash) -> None:
        """Annotate ASan-specific context onto parsed crashes."""
        geo = parse_allocation_hint(crash)
        for key, value in geo.items():
            crash.extra.setdefault(key, str(value))
        ann = detect_shadow_annotation(crash)
        if ann:
            crash.extra["shadow_annotation"] = ann
        um = _UAF_HINT_RE.search(crash.raw_text)
        if um:
            crash.extra["freed_by_thread"] = f"T{um.group(1)}"
        # Refine null-dereference vs generic SEGV using fault address.
        if crash.crash_class in (CrashClass.SEGMENTATION_FAULT, None) and crash.fault_address:
            try:
                addr = int(crash.fault_address, 16)
            except ValueError:
                addr = -1
            if 0 <= addr <= 0x1000:
                crash.crash_class = CrashClass.NULL_DEREFERENCE
                crash.extra["nullish_address"] = "1"
        # Poison-pattern based refinement for stack-use-after-scope etc.
        if crash.error_kind == "use-after-poison":
            if ann and "scope" in ann:
                crash.crash_class = CrashClass.USE_AFTER_SCOPE
            elif ann and "after return" in ann:
                crash.crash_class = CrashClass.USE_AFTER_RETURN
            elif ann and "container" in ann:
                crash.crash_class = CrashClass.UNKNOWN
                crash.extra["container_overflow"] = "1"
        # Summary-line fallback location when frames were stripped.
        sm = SUMMARY_LINE_RE.search(crash.raw_text)
        if sm and not (crash.crash_stack and crash.crash_stack.frames):
            crash.extra.setdefault("summary_location", sm.group(3).strip())

    # ---- reproduction helpers -----------------------------------------

    def repro_command(
        self,
        binary: Path,
        input_file: Path,
        *,
        args: Sequence[str] = (),
        options_override: Optional[Mapping[str, object]] = None,
    ) -> List[str]:
        """Build a fully-symbolized single-run command for triage.

        Reproductions *do* symbolize (unlike campaign runs) because there is
        exactly one process and humans read its output.
        """
        opts: Dict[str, object] = {
            "symbolize": 1,
            "print_stats": 0,
            "abort_on_error": 0,
            "detect_leaks": 0,
        }
        if options_override:
            opts.update(dict(options_override))
        # argv for execvp-style runners; the matching environment comes from
        # :meth:`repro_environment` (kept separate on purpose — no shell
        # string interpolation of paths anywhere).
        return [str(binary), *args, str(input_file)]

    def repro_environment(
        self, options_override: Optional[Mapping[str, object]] = None
    ) -> Dict[str, str]:
        opts: Dict[str, object] = {"symbolize": 1, "detect_leaks": 0}
        if options_override:
            opts.update(dict(options_override))
        policy = SanitizerEnvPolicy(defaults=self.default_options(), overrides=opts)
        return policy.to_env(self.env_var, dict(os.environ))


# ---------------------------------------------------------------------------
# HWASan adapter (tag-based, ARM64/clang)
# ---------------------------------------------------------------------------

_HWASAN_TAG_RE = re.compile(r"Memory tag \((\d+)\) != allocate tag \((\d+)\)")


class HWASANAdapter(ASANAdapter):
    """Hardware Tagged AddressSanitizer (AArch64 MTE-style software tags)."""

    kind = SanitizerKind.HWASAN
    env_var = "HWASAN_OPTIONS"
    compile_flag = "-fsanitize=hwaddress"
    display_name = "HWAddressSanitizer"

    def default_options(self) -> Dict[str, object]:
        base = super().default_options()
        base.pop("external_symbolizer_path", None)
        base.update({"memory_tagging": 1, "memtag": 1})
        return base

    def enhance(self, crash: SanitizedCrash) -> None:
        super().enhance(crash)
        tm = _HWASAN_TAG_RE.search(crash.raw_text)
        if tm:
            crash.extra["memory_tag"] = tm.group(1)
            crash.extra["allocate_tag"] = tm.group(2)
            # Tag mismatch without a classic error name still means UAF-ish.
            if crash.crash_class is None:
                crash.crash_class = CrashClass.USE_AFTER_FREE


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register_adapter(ASANAdapter())
register_adapter(HWASANAdapter())


# ---------------------------------------------------------------------------
# Self-smoke test
# ---------------------------------------------------------------------------

_SAMPLE_STACK_OVERFLOW = """
==31337==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd1234abcd at pc 0x5555555556c1 bp 0x7ffd1234aa10 sp 0x7ffd1234aa08
WRITE of size 12 at 0x7ffd1234abcd thread T0
    #0 0x5555555556c0 in copy_name /src/app/name.c:44:5
    #1 0x5555555557ab in handle_request /src/app/server.c:120:9
    #2 0x555555555b12 in main /src/app/main.c:31:3
Address 0x7ffd1234abcd is located in stack of thread T0 at offset 45 in frame
    #0 0x55555555564f in handle_request /src/app/server.c:110
Shadow bytes near the faulting address:
  f1 f1 f1 f1 00[f2]f2 f2 f2
SUMMARY: AddressSanitizer: stack-buffer-overflow /src/app/name.c:44:5 in copy_name
"""

_SAMPLE_SEGV_NULL = """
==99==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000030 (pc 0x5555abcdef bp 0x7ffc0000 sp 0x7ffc0010 T0)
The signal is caused by a READ memory access.
    #0 0x5555abce in deref /src/lib/util.c:12:10
    #1 0x5555abd0 in main /src/lib/main.c:5:3
SUMMARY: AddressSanitizer: SEGV /src/lib/util.c:12:10 in deref
"""


def _smoke() -> None:
    adapter = ADAPTER_REGISTRY["address"]
    assert isinstance(adapter, ASANAdapter)

    crashes = adapter.parse_report(_SAMPLE_STACK_OVERFLOW)
    assert len(crashes) == 1
    c = crashes[0]
    assert c.crash_class is CrashClass.STACK_BUFFER_OVERFLOW, c.crash_class
    assert c.access_type == "write" and c.access_size == 12
    assert c.thread == "T0"
    assert c.frame_signatures()[0].startswith("copy_name"), c.frame_signatures()
    assert c.extra.get("shadow_annotation") == "mid global redzone", c.extra.get("shadow_annotation")

    null_crashes = adapter.parse_report(_SAMPLE_SEGV_NULL)
    assert len(null_crashes) == 1
    nc = null_crashes[0]
    assert nc.crash_class is CrashClass.NULL_DEREFERENCE, nc.crash_class
    assert nc.extra.get("nullish_address") == "1"

    env = adapter.prepare_environment({}, campaign_options={"detect_leaks": 0},
                                      overrides={"verbosity": 1})
    opts = env["ASAN_OPTIONS"]
    assert "symbolize=0" in opts and "detect_leaks=0" in opts and "verbosity=1" in opts
    assert "use_after_scope" in opts  # locked default present

    sup = build_suppression_file([("leak", "^SDL_.*$")], Path(tempfile.mkstemp()[1]))
    assert sup.read_text().strip() == "leak:^SDL_.*$"
    sup.unlink()

    probe = asan_support()
    print(
        "asan smoke OK — two samples parsed; ASan toolchain support:",
        "available" if probe.available else f"unavailable ({'; '.join(probe.notes[:2])})",
    )


if __name__ == "__main__":
    _smoke()
