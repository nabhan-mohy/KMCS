"""KMCS target detection — real, offline environment & artefact probing.

This module answers three questions with **measured facts only**:

1. *What toolchain does this machine actually have?*  (:class:`ToolProbe`,
   :class:`ToolchainDetector`) — compilers, AFL++ components, sanitiser
   runtimes, debuggers, binary-analysis helpers.  Nothing is faked: every
   version string was produced by executing the tool and parsing its own
   banner; every capability flag was produced by **compiling and running a
   tiny probe program** with that compiler.

2. *What kind of artefact did the researcher point KMCS at?*
   (:class:`TargetProfiler`) — ELF / Mach-O / PE classification from raw
   magic bytes (no external ``file`` dependency), static vs dynamic linkage,
   sonames, source-tree language mix, project system detection
   (CMake / autotools / make / meson / bare).

3. *Is the binary already instrumented for fuzzing, and with which
   instrumentation?*  (:class:`InstrumentationProbe`) — searches the symbol
   and section tables for the tell-tale symbols/sections emitted by
   AFL-clang-fast/LTO, afl-gcc-plugin, SanitizerCoverage PCGUARD and ASan,
   using ``nm``/``objdump``/``readelf`` when present and falling back to a
   pure-Python byte-level scan so detection still works on stripped binaries.

Security posture
----------------
Detection is strictly **local and passive**: it reads files inside paths the
caller controls and executes only trivial, self-contained probe programs it
wrote itself into a temporary directory.  There is no network activity, no
credentials, no telemetry, and none of the prohibited capability classes
(exploitation, persistence, stealth, credential access) exist anywhere in
this module — see :func:`kmcs.core.models.guard_capability`.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from kmcs.core.exceptions import (
    PolicyViolationError,
    TargetInvalidError,
    ToolNotFoundError,
)
from kmcs.core.models import (
    Architecture,
    Authorisation,
    BuildRecipe,
    HarnessSpec,
    InstrumentationKind,
    Language,
    OperatingSystem,
    OptimizationLevel,
    SanitizerKind,
    Target,
    TargetKind,
    generate_prefixed_id,
    normalize_path,
    sha256_file,
    utc_string,
)

__all__ = [
    "ELF_MAGIC",
    "MACHO_MAGICS",
    "PE_MAGIC",
    "ARTIFACT_SIGNATURES",
    "INSTRUMENTATION_SYMBOLS",
    "INSTRUMENTATION_SECTIONS",
    "SANITIZER_RUNTIME_MARKERS",
    "OFF_LIMIT_PATTERNS",
    "LinkageKind",
    "ToolProbe",
    "ToolchainInfo",
    "ToolchainDetector",
    "ArtifactProfile",
    "SourceTreeProfile",
    "InstrumentationReport",
    "TargetProfiler",
    "InstrumentationProbe",
    "detect_authorization",
    "is_off_limits_artifact",
    "probe_tool",
    "draft_target_from_path",
    "default_detector",
]

# ---------------------------------------------------------------------------
# Constants: formats, signatures, policy
# ---------------------------------------------------------------------------

#: Portable executable / object magic numbers (first bytes of a file).
ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS: Dict[bytes, str] = {
    b"\xfe\xed\xfa\xce": "macho-32-be",
    b"\xfe\xed\xfa\xcf": "macho-64-be",
    b"\xce\xfa\xed\xfe": "macho-32-le",
    b"\xcf\xfa\xed\xfe": "macho-64-le",
    b"\xca\xfe\xba\xbe": "macho-fat-universal",
}
PE_MAGIC = b"MZ"

#: Well-known compiled artefact suffixes that are *never* fuzz targets by
#: themselves; classifying them keeps campaigns honest about what they run.
ARTIFACT_SIGNATURES: Dict[str, str] = {
    ".o": "object-file",
    ".a": "static-library",
    ".lib": "static-library",
    ".so": "shared-library",
    ".dylib": "shared-library",
    ".dll": "shared-library",
    ".pyc": "python-bytecode",
    ".class": "java-bytecode",
    ".py": "python-source",
    ".pyx": "cython-source",
    ".h": "c-header",
    ".hpp": "cxx-header",
}

#: Symbol fragments that prove a specific fuzzing instrumentation is baked
#: into a binary.  Keys are InstrumentationKind values; values are lists of
#: substrings searched against collected symbol tokens.
INSTRUMENTATION_SYMBOLS: Dict[str, Tuple[str, ...]] = {
    InstrumentationKind.AFL_CLANG_FAST.value: (
        "__afl_area_ptr", "__afl_init_pid", "__afl_maybe_log",
        "__afl_manual_init", "__afl_persistent_hook",
    ),
    InstrumentationKind.AFL_CLANG_LTO.value: (
        "__afl_area_initial", "__afl_auto_first",
    ),
    InstrumentationKind.AFL_GCC_PLUGIN.value: (
        "__afl_more_responsive", "__afl_gcov_handler",
    ),
    InstrumentationKind.PCGUARD.value: (
        "__sanitizer_cov_trace_pc_guard", "__sanitizer_cov_trace_pc_guard_init",
    ),
    InstrumentationKind.TRACE_PC.value: (
        "__sancov_lowest_stack", "__sanitizer_cov_trace_pc",
        "__sanitizer_cov_trace_const_pc",
    ),
    InstrumentationKind.LLVM_PROFILE.value: ("__llvm_prf_", "__llvm_profile_write_file"),
}

#: Section names that betray instrumentation even in stripped binaries.
INSTRUMENTATION_SECTIONS: Dict[str, Tuple[str, ...]] = {
    InstrumentationKind.AFL_CLANG_FAST.value: (".llvmbc", ".llvmcmd"),
    InstrumentationKind.AFL_CLANG_LTO.value: (".llvmbc", ".llvmcmd", "__afl_fuzz"),
    InstrumentationKind.QEMU_MODE.value: (),
}

#: Runtime library markers proving a sanitizer was linked in.
SANITIZER_RUNTIME_MARKERS: Dict[str, Tuple[str, ...]] = {
    SanitizerKind.ASAN.value: ("__asan_report_error", "__asan_init", "libasan.so"),
    SanitizerKind.UBSAN.value: ("__ubsan_handle_type_mismatch", "libubsan.so"),
    SanitizerKind.LSAN.value: ("__lsan_do_leak_check", "detect_leaks"),
    SanitizerKind.MSAN.value: ("__msan_warning", "libmsan.so"),
    SanitizerKind.TSAN.value: ("__tsan_read", "__tsan_init", "libtsan.so"),
    SanitizerKind.HWASAN.value: ("__hwasan_tag_memory", "libhwasan.so"),
}

#: Files that must never be registered as fuzz targets regardless of who
#: asks.  This is a blunt safety rail (system kernels/bootloaders/crypto key
#: material), not a sandbox substitute.
OFF_LIMIT_PATTERNS: Tuple[str, ...] = (
    "/boot/", "/sys/", "/proc/", "/dev/", "/etc/shadow", "/etc/sudoers",
    "id_rsa", "id_ed25519", ".pem", ".key", "authorized_keys",
    "/lib/modules/", "/usr/lib/systemd/",
)

_CENSUS_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", "build", "build-kmcs", "cmake-build-debug",
    "cmake-build-release", ".venv", "venv", "dist", ".tox",
})


def _safe(fn: Any, default: Any = None) -> Any:
    """Run ``fn()`` swallowing any exception; return ``default``."""
    try:
        return fn()
    except Exception:
        return default


def is_off_limits_artifact(path: Any) -> bool:
    """Return True if *path* matches an always-forbidden target pattern."""
    token = normalize_path(path).lower()
    name = os.path.basename(token)
    for pattern in OFF_LIMIT_PATTERNS:
        if pattern in token or pattern == name:
            return True
        if pattern.startswith("*") and token.endswith(pattern[1:]):
            return True
    return False


def detect_authorization(path: Any) -> Optional[Authorisation]:
    """Discover a written authorisation record sitting next to a target.

    KMCS looks for ``KMCS_AUTHORIZATION.md`` / ``.json`` / ``.txt`` /
    ``.kmcs-authorization`` in the artefact's directory and its parents up
    to the filesystem root.  A found document becomes a structured
    :class:`Authorisation` whose statement quotes the document verbatim
    (truncated) and whose scope covers the containing tree.  Returns
    ``None`` when nothing suitable exists — callers must then refuse the
    operation, because absence of consent is never interpreted as consent.
    """
    start = normalize_path(path)
    directory = start if os.path.isdir(start) else os.path.dirname(start) or "."
    candidates: List[str] = []
    current = os.path.realpath(directory)
    seen = set()
    while current and current not in seen and current != os.sep:
        seen.add(current)
        for filename in ("KMCS_AUTHORIZATION.md", "KMCS_AUTHORIZATION.json",
                         "KMCS_AUTHORIZATION.txt", ".kmcs-authorization"):
            candidates.append(os.path.join(current, filename))
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        text = _safe(lambda: open(candidate, "r", encoding="utf-8", errors="replace").read(), "")
        if not text or len(text.strip()) < 10:
            continue
        lowered = text.lower()
        # Require explicit permission language; a README mentioning fuzzing
        # is not consent.
        grants = any(marker in lowered for marker in
                     ("i authorize", "we authorize", "authorized for",
                      "permission granted", "granted permission", "consent"))
        if not grants:
            continue
        relationship = "owner"
        for token in ("maintainer", "contracted_tester", "bug_bounty_program",
                      "internal_team", "research_permit"):
            if token.replace("_", " ") in lowered or token in lowered:
                relationship = token
                break
        granted_by_match = re.search(
            r"(?im)^\s*(?:granted\s+by|authoriz(?:ed|er))\s*[:\-]\s*(.+)$", text)
        granted_by = granted_by_match.group(1).strip()[:200] if granted_by_match else "unspecified"
        expires = None
        expiry_match = re.search(
            r"(?im)^\s*expires\s*[:\-]\s*(\d{4}-\d{2}-\d{2}[T ]?\S*)", text)
        if expiry_match:
            expires = expiry_match.group(1).strip() or None
        return Authorisation(
            granted_by=granted_by,
            relationship=relationship,
            statement=text.strip()[:4000],
            evidence_ref=candidate,
            scope=_make_scope(paths=(os.path.realpath(directory),)),
            expires_at=expires,
        )
    return None


def _make_scope(paths: Tuple[str, ...]) -> Any:
    from kmcs.core.models import Scope
    return Scope(paths=paths)


# ---------------------------------------------------------------------------
# File-format classification (pure python, no `file` dependency)
# ---------------------------------------------------------------------------

class LinkageKind:
    """String constants describing how an artefact links its dependencies."""

    STATIC = "static"
    SHARED = "shared"
    DYNAMIC = "dynamic"
    UNKNOWN = "unknown"


_ELF_CLASS_NAMES = {1: "elf32", 2: "elf64"}
_ELF_MACHINE_ARCH = {
    0x3E: Architecture.X86_64, 0x03: Architecture.X86, 0xB7: Architecture.AARCH64,
    0x28: Architecture.ARM, 0xF3: Architecture.RISCV64, 0x15: Architecture.PPC64,
    0x16: Architecture.S390X,
}
_MACHO_ARCH = {
    0x01000007: Architecture.X86, 0x0100000C: Architecture.AARCH64,
    0x01000007 | 0x01000000: Architecture.X86_64,
}


@dataclass
class ArtifactProfile:
    """Measured properties of one file on disk."""

    path: str
    exists: bool = False
    readable: bool = False
    writable: bool = False
    executable_bit: bool = False
    size_bytes: int = 0
    sha256: str = ""
    category: str = "unknown"   # binary | shared-library | static-library | source | text | empty | unknown
    format: str = "unknown"     # elf64 | elf32 | macho-* | pe | archive | script | text | data
    architecture: str = Architecture.UNKNOWN.value
    operating_system: str = OperatingSystem.UNKNOWN.value
    linkage: str = LinkageKind.UNKNOWN
    build_id: str = ""
    needed_libraries: List[str] = field(default_factory=list)
    soname: str = ""
    strings_sampled: int = 0
    is_position_independent: bool = False
    detected_sanitizers: List[str] = field(default_factory=list)
    detected_instrumentation: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    profiled_at: str = field(default_factory=utc_string)

    @property
    def looks_like_executable(self) -> bool:
        return self.category in {"binary", "shared-library"} and self.executable_bit

    @property
    def likely_language(self) -> str:
        joined = " ".join(self.needed_libraries).lower() + " " + self.soname.lower()
        if "libstdc++" in joined or "libc++" in joined:
            return Language.CPP.value
        if self.format.startswith(("elf", "macho", "pe")):
            return Language.C.value
        return Language.UNKNOWN.value

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


@dataclass
class SourceTreeProfile:
    """Aggregated facts about a source directory (used to build recipes)."""

    root: str
    language: str = Language.UNKNOWN.value
    project_system: str = "bare"
    files: int = 0
    bytes: int = 0
    dirs: int = 0
    extensions: Dict[str, int] = field(default_factory=dict)
    truncated: bool = False
    has_license: bool = False
    profiled_at: str = field(default_factory=utc_string)

    def summary(self) -> str:
        return (f"{self.root}: {self.files} files ({self.language}, "
                f"{self.project_system}), {self.bytes} bytes")

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


class TargetProfiler:
    """Classify artefacts and source trees with measured evidence only."""

    MAX_SCAN_BYTES = 64 << 20  # read at most 64 MiB of any single file

    def __init__(self, *, follow_symlinks: bool = False,
                 max_tree_files: int = 20000) -> None:
        self.follow_symlinks = bool(follow_symlinks)
        self.max_tree_files = int(max_tree_files)

    # -- public --------------------------------------------------------------
    def profile_path(self, path: Any) -> Any:
        """Dispatch: file → :meth:`profile_file`; directory → tree profile."""
        token = normalize_path(path)
        if os.path.isdir(token):
            return self.profile_source_tree(token)
        return self.profile_file(token)

    def profile_file(self, path: Any) -> ArtifactProfile:
        token = normalize_path(path)
        profile = ArtifactProfile(path=token)
        if not os.path.exists(token):
            profile.notes.append("path does not exist")
            return profile
        if os.path.isdir(token):
            profile.notes.append("directory passed to profile_file")
            profile.category = "unknown"
            return profile
        profile.exists = True
        st = _safe(lambda: os.stat(token))
        if st is None:
            profile.notes.append("stat failed")
            return profile
        profile.size_bytes = int(st.st_size)
        profile.readable = _safe(lambda: os.access(token, os.R_OK), False)
        profile.writable = _safe(lambda: os.access(token, os.W_OK), False)
        profile.executable_bit = bool(st.st_mode & stat.S_IXUSR)
        if profile.size_bytes == 0:
            profile.category = "empty"
            return profile
        if not profile.readable:
            profile.notes.append("not readable")
            return profile
        head = _safe(lambda: self._read_head(token, 64), b"") or b""
        profile.sha256 = _safe(lambda: sha256_file(token), "") or ""
        self._classify(profile, head)
        if profile.format.startswith("elf"):
            self._parse_elf(profile, head)
        elif profile.format == "pe":
            self._classify_pe(profile, head)
        elif profile.format.startswith("macho"):
            self._classify_macho(profile, head)
        elif profile.format == "archive":
            profile.linkage = LinkageKind.STATIC
        ext_kind = ARTIFACT_SIGNATURES.get(os.path.splitext(token)[1].lower())
        if profile.category == "unknown" and ext_kind:
            profile.category = ext_kind
        if profile.category in {"binary", "shared-library"}:
            self._scan_markers(profile)
        return profile

    def profile_many(self, paths: Iterable[Any]) -> List[ArtifactProfile]:
        return [self.profile_file(p) for p in paths]

    def find_candidate_binaries(self, root: Any, *,
                                limit: int = 200) -> List[ArtifactProfile]:
        """Walk *root*, returning profiles of executable ELF/Mach-O/PE files."""
        root_token = normalize_path(root)
        out: List[ArtifactProfile] = []
        if os.path.isfile(root_token):
            profile = self.profile_file(root_token)
            return [profile] if profile.category == "binary" else []
        for dirpath, dirnames, filenames in os.walk(root_token, followlinks=self.follow_symlinks):
            dirnames[:] = [d for d in dirnames if d not in _CENSUS_SKIP_DIRS and not d.startswith(".")]
            for filename in filenames:
                if len(out) >= limit:
                    return out
                full = os.path.join(dirpath, filename)
                if is_off_limits_artifact(full):
                    continue
                if os.path.splitext(filename)[1].lower() in ARTIFACT_SIGNATURES:
                    continue
                profile = _safe(lambda: self.profile_file(full))
                if profile is None:
                    continue
                if profile.category == "binary" and profile.executable_bit:
                    out.append(profile)
        return out

    def census(self, root: Any, *, extensions: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """Count files by extension inside *root* (bounded walk)."""
        root_token = normalize_path(root)
        counts: Dict[str, int] = {}
        total_files = 0
        total_bytes = 0
        visited_dirs = 0
        wanted = {e.lower() for e in extensions} if extensions else None
        for dirpath, dirnames, filenames in os.walk(root_token, followlinks=self.follow_symlinks):
            visited_dirs += 1
            dirnames[:] = [d for d in dirnames if d not in _CENSUS_SKIP_DIRS]
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if wanted is not None and ext not in wanted:
                    continue
                total_files += 1
                full = os.path.join(dirpath, filename)
                size = _safe(lambda: os.path.getsize(full), 0)
                total_bytes += int(size or 0)
                key = ext or "(none)"
                counts[key] = counts.get(key, 0) + 1
                if total_files >= self.max_tree_files:
                    return {"files": total_files, "bytes": total_bytes, "dirs": visited_dirs,
                            "extensions": counts, "truncated": True}
        return {"files": total_files, "bytes": total_bytes, "dirs": visited_dirs,
                "extensions": counts, "truncated": False}

    def detect_project_system(self, root: Any) -> str:
        """Return 'cmake' | 'meson' | 'autotools' | 'make' | 'bare' from markers."""
        root_token = normalize_path(root)
        if os.path.isfile(os.path.join(root_token, "CMakeLists.txt")):
            return "cmake"
        if os.path.isfile(os.path.join(root_token, "meson.build")):
            return "meson"
        if os.path.isfile(os.path.join(root_token, "configure.ac")) or \
           os.path.isfile(os.path.join(root_token, "configure.in")) or \
           os.path.isfile(os.path.join(root_token, "Makefile.am")):
            return "autotools"
        if os.path.isfile(os.path.join(root_token, "Makefile")) or \
           os.path.isfile(os.path.join(root_token, "makefile")):
            return "make"
        return "bare"

    def profile_source_tree(self, root: Any) -> SourceTreeProfile:
        root_token = normalize_path(root)
        if not os.path.isdir(root_token):
            raise TargetInvalidError(f"source root '{root_token}' is not a directory",
                                     component="targets.detector")
        census = self.census(root_token, extensions=(
            ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".rs", ".go", ".py", ".java",
        ))
        counts = census["extensions"]
        c_files = counts.get(".c", 0) + counts.get(".h", 0)
        cpp_files = sum(counts.get(e, 0) for e in (".cc", ".cpp", ".cxx", ".hpp", ".hh"))
        if c_files and cpp_files:
            language: Language = Language.MIXED
        elif cpp_files:
            language = Language.CPP
        elif c_files:
            language = Language.C
        elif counts.get(".rs", 0):
            language = Language.RUST
        elif counts.get(".go", 0):
            language = Language.GO
        elif counts.get(".py", 0):
            language = Language.PYTHON
        else:
            language = Language.UNKNOWN
        return SourceTreeProfile(
            root=root_token, language=str(language.value),
            project_system=self.detect_project_system(root_token),
            files=census["files"], bytes=census["bytes"], dirs=census["dirs"],
            extensions=dict(census["extensions"]), truncated=census["truncated"],
            has_license=bool(_safe(lambda: any(
                f.upper().startswith(("LICENSE", "COPYING"))
                for f in os.listdir(root_token)), False)),
        )

    # -- internals ----------------------------------------------------------
    def _read_head(self, path: str, size: int) -> bytes:
        with open(path, "rb") as handle:
            return handle.read(size)

    def _classify(self, profile: ArtifactProfile, head: bytes) -> None:
        if head.startswith(ELF_MAGIC):
            ei_class = head[4] if len(head) > 4 else 0
            profile.format = _ELF_CLASS_NAMES.get(ei_class, "elf")
            profile.category = "binary"
            profile.operating_system = OperatingSystem.LINUX.value
            return
        for magic, name in MACHO_MAGICS.items():
            if head.startswith(magic):
                profile.format = name
                profile.category = "binary"
                profile.operating_system = OperatingSystem.MACOS.value
                return
        if head.startswith(PE_MAGIC):
            lfanew = struct.unpack("<I", head[0x3C:0x40])[0] if len(head) >= 0x40 else 0
            if lfanew + 4 <= len(head) and head[lfanew:lfanew + 4] == b"PE\x00\x00":
                profile.format = "pe"
                profile.category = "binary"
                profile.operating_system = OperatingSystem.WINDOWS.value
                return
        if head.startswith(b"!<arch>\n"):
            profile.format = "archive"
            profile.category = "static-library"
            return
        if head.startswith(b"#!"):
            profile.format = "script"
            profile.category = "text"
            return
        printable_ratio = sum(1 for b in head if 9 <= b <= 13 or 32 <= b < 127) / max(1, len(head))
        profile.strings_sampled = int(printable_ratio * len(head))
        if printable_ratio > 0.85:
            profile.format = "text"
            first_line = head.split(b"\n", 1)[0][:120].decode("utf-8", "ignore").lower()
            profile.category = "source" if (first_line.startswith("#include")
                                            or "int main" in first_line) else "text"
        else:
            profile.format = "data"
            profile.category = "unknown"

    def _parse_elf(self, profile: ArtifactProfile, head: bytes) -> None:
        """Parse enough ELF header to get type/machine (pure python)."""
        try:
            little_endian = head[5] == 1
            is64 = head[4] == 2
            base = 16
            if is64:
                fmt = (("=" if little_endian else ">") + "HHIQQQIHHHHHH")
            else:
                fmt = (("=" if little_endian else ">") + "HHIIIIIHHHHHH")
            need = struct.calcsize(fmt)
            if len(head) < base + need:
                profile.notes.append("elf header truncated in sample")
                return
            fields = struct.unpack(fmt, head[base:base + need])
            e_type, e_machine = fields[0], fields[1]
            arch = _ELF_MACHINE_ARCH.get(e_machine)
            if arch is not None:
                profile.architecture = str(arch.value)
            if e_type == 3:
                profile.category = "shared-library"
                profile.linkage = LinkageKind.SHARED
            elif e_type == 2:
                profile.linkage = LinkageKind.DYNAMIC
            profile.is_position_independent = e_type in (2, 3)
        except Exception as exc:  # malformed/truncated ELF — degrade gracefully
            profile.notes.append(f"elf header parse failed: {exc}")

    def _classify_pe(self, profile: ArtifactProfile, head: bytes) -> None:
        try:
            lfanew = struct.unpack("<I", head[0x3C:0x40])[0]
            machine = struct.unpack("<H", head[lfanew + 4:lfanew + 6])[0]
            characteristics = struct.unpack("<H", head[lfanew + 22:lfanew + 24])[0]
            mapping = {0x8664: Architecture.X86_64, 0x14C: Architecture.X86,
                       0xAA64: Architecture.AARCH64}
            arch = mapping.get(machine)
            if arch:
                profile.architecture = str(arch.value)
            profile.linkage = (LinkageKind.DYNAMIC if characteristics & 0x2000
                               else LinkageKind.STATIC)
        except Exception as exc:
            profile.notes.append(f"pe header parse failed: {exc}")

    def _classify_macho(self, profile: ArtifactProfile, head: bytes) -> None:
        for magic, name in MACHO_MAGICS.items():
            if not head.startswith(magic):
                continue
            big_endian = magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
            prefix = ">" if big_endian else "<"
            try:
                cputype = struct.unpack(prefix + "i", head[4:8])[0] & 0x01FFFFFF
                arch = _MACHO_ARCH.get(cputype)
                if arch:
                    profile.architecture = str(arch.value)
            except Exception:
                pass
            try:
                filetype = struct.unpack(prefix + "I", head[12:16])[0] & 0xF
                if filetype == 0xC:  # MH_DYLIB
                    profile.category = "shared-library"
                    profile.linkage = LinkageKind.SHARED
            except Exception:
                pass
            return

    def _scan_markers(self, profile: ArtifactProfile) -> None:
        """Byte-scan the file for sanitizer/instrumentation symbol names."""
        blob = _safe(lambda: self._read_head(profile.path, min(self.MAX_SCAN_BYTES,
                                                               profile.size_bytes)), b"")
        if not blob:
            return
        for sanitizer, markers in SANITIZER_RUNTIME_MARKERS.items():
            if any(m.encode("ascii", "ignore") in blob for m in markers):
                profile.detected_sanitizers.append(sanitizer)
        for kind, needles in INSTRUMENTATION_SYMBOLS.items():
            if any(n.encode("ascii", "ignore") in blob for n in needles):
                profile.detected_instrumentation.append(kind)


# ---------------------------------------------------------------------------
# Toolchain probing
# ---------------------------------------------------------------------------

@dataclass
class ToolProbe:
    """One probed executable: existence, version, sanity."""

    name: str
    path: Optional[str] = None
    present: bool = False
    version: str = ""
    version_parsed: Tuple[int, ...] = ()
    family: str = ""
    runnable: bool = False
    error: str = ""
    probed_at: float = field(default_factory=time.time)
    latency_ms: float = 0.0

    @property
    def available(self) -> bool:
        return bool(self.present and self.runnable)

    def require(self, purpose: str = "operation") -> "ToolProbe":
        if not self.available:
            raise ToolNotFoundError(
                f"required tool '{self.name}' is unavailable "
                f"({self.error or 'not installed'}) — needed for {purpose}",
                details={"tool": self.name, "purpose": purpose},
            )
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "path": self.path, "present": self.present,
                "version": self.version, "family": self.family,
                "runnable": self.runnable, "error": self.error,
                "latency_ms": self.latency_ms}


_VERSION_PATTERNS = (
    re.compile(r"version (\d+(?:\.\d+)*)"),
    re.compile(r"(\d+\.\d+(?:\.\d+)?)"),
)


def _parse_version(text: str) -> Tuple[str, Tuple[int, ...]]:
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(text or "")
        if match:
            parts = tuple(int(p) for p in re.findall(r"\d+", match.group(1))[:4])
            return match.group(1), parts
    return "", ()


def probe_tool(name: str, *, version_args: Optional[Sequence[str]] = None,
               timeout: float = 10.0) -> ToolProbe:
    """Locate *name* on PATH and capture its self-reported version.

    Executes ``<name> <--version>`` once, parses stdout/stderr, and records
    honest failure modes (missing, not-executable, timeout).
    """
    probe = ToolProbe(name=name)
    resolved = shutil.which(name)
    if not resolved:
        probe.error = "not found on PATH"
        return probe
    probe.path = resolved
    probe.present = True
    args = list(version_args if version_args is not None else ["--version"])
    started = time.monotonic()
    try:
        result = subprocess.run([resolved, *args], capture_output=True,
                                timeout=timeout, check=False, text=True, errors="replace")
        probe.latency_ms = round((time.monotonic() - started) * 1000, 1)
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        probe.version, probe.version_parsed = _parse_version(combined)
        probe.runnable = True
        lowered = combined.lower()
        if "apple clang" in lowered or "clang" in lowered:
            probe.family = "clang"
        elif "gcc" in lowered:
            probe.family = "gcc"
        elif "afl" in lowered:
            probe.family = "afl++"
        else:
            probe.family = "other"
    except FileNotFoundError as exc:
        probe.error = f"exec failed: {exc}"
    except subprocess.TimeoutExpired:
        probe.error = f"'{name}' timed out after {timeout}s answering --version"
    except PermissionError:
        probe.error = "not executable (permission denied)"
    except OSError as exc:
        probe.error = f"oserror: {exc}"
    return probe


_CORE_TOOLS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("gcc", ("--version",)), ("g++", ("--version",)),
    ("clang", ("--version",)), ("clang++", ("--version",)),
    ("afl-clang-fast", ("--version",)), ("afl-clang-fast++", ("--version",)),
    ("afl-clang-lto", ("--version",)), ("afl-clang-lto++", ("--version",)),
    ("afl-gcc", ("--version",)), ("afl-g++", ("--version",)),
    ("afl-fuzz", ("--version",)), ("afl-showmap", ("--version",)),
    ("afl-cmin", ("--version",)), ("afl-tmin", ("--version",)),
    ("afl-analyze", ("--version",)), ("afl-qemu-trace", ()),
    ("llvm-profdata", ("--version",)), ("llvm-cov", ("--version",)),
    ("llvm-nm", ("--version",)), ("llvm-objdump", ("--version",)),
    ("llvm-symbolizer", ("--version",)),
    ("nm", ("--version",)), ("objdump", ("--version",)),
    ("readelf", ("--version",)), ("strings", ("--version",)),
    ("addr2line", ("--version",)), ("file", ("--version",)),
    ("gdb", ("--version",)), ("lldb", ("--version",)),
    ("honggfuzz", ("--version",)),
    ("cmake", ("--version",)), ("make", ("--version",)), ("ninja", ("--version",)),
    ("patchelf", ("--version",)), ("pkg-config", ("--version",)),
)


@dataclass
class ToolchainInfo:
    """Snapshot of everything KMCS could measure about the local toolchain."""

    host_os: str = field(default_factory=lambda: str(OperatingSystem.host().value))
    host_arch: str = field(default_factory=lambda: str(Architecture.host().value))
    hostname: str = field(default_factory=lambda: _safe(lambda: os.uname().nodename, "localhost"))
    python: str = field(default_factory=lambda: sys.version.split()[0])
    tools: Dict[str, ToolProbe] = field(default_factory=dict)
    capabilities: Dict[str, bool] = field(default_factory=dict)
    sanitizer_support: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    probed_at: str = field(default_factory=utc_string)
    duration_seconds: float = 0.0

    # -- lookups -------------------------------------------------------------
    def get(self, name: str) -> Optional[ToolProbe]:
        return self.tools.get(name)

    def require(self, *names: str, purpose: str = "operation") -> List[ToolProbe]:
        missing = [n for n in names if not (n in self.tools and self.tools[n].available)]
        if missing:
            raise ToolNotFoundError(
                f"toolchain is missing required tools for {purpose}: {', '.join(missing)}",
                details={"missing": missing, "probed": sorted(self.tools)},
            )
        return [self.tools[n] for n in names]

    def best_compiler(self) -> Optional[ToolProbe]:
        """Prefer clang (best sanitizer support), fall back to gcc/cc."""
        for name in ("clang", "gcc", "cc"):
            probe = self.tools.get(name)
            if probe and probe.available:
                return probe
        return None

    def afl_available(self) -> bool:
        return any(self.tools.get(n) and self.tools[n].available
                   for n in ("afl-fuzz", "afl-clang-fast", "afl-showmap"))

    def libfuzzer_capable(self) -> bool:
        return bool(self.capabilities.get("libfuzzer_driver"))

    @property
    def ready_for_basic_campaign(self) -> bool:
        return bool(self.best_compiler())

    def summary_lines(self) -> List[str]:
        lines = [f"host: {self.host_os}/{self.host_arch} python={self.python} "
                 f"probed in {self.duration_seconds:.1f}s"]
        for name in sorted(self.tools):
            probe = self.tools[name]
            status = "OK  " if probe.available else ("PATH" if probe.present else "MISS")
            lines.append(f"  [{status}] {name:<18} {probe.version or probe.error}")
        for cap, value in sorted(self.capabilities.items()):
            lines.append(f"  {'+' if value else '-'} capability: {cap}")
        return lines

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_os": self.host_os, "host_arch": self.host_arch,
            "hostname": self.hostname, "python": self.python,
            "tools": {k: v.to_dict() for k, v in self.tools.items()},
            "capabilities": dict(self.capabilities),
            "sanitizer_support": dict(self.sanitizer_support),
            "warnings": list(self.warnings), "probed_at": self.probed_at,
            "duration_seconds": self.duration_seconds,
        }


class ToolchainDetector:
    """Probes compilers, AFL++ parts, sanitizers and analysis helpers.

    Capability checks compile-and-run micro programs with the real toolchain;
    results are cached per detector instance and optionally persisted to JSON
    so repeated CLI invocations do not recompile the world.
    """

    #: minimal C programs keyed by capability tag
    _PROBE_PROGRAMS: Dict[str, str] = {
        "compiler_works": "int main(void){return 0;}",
        "asan": (
            "#include <stdlib.h>\n#include <string.h>\n"
            "int main(void){char*p=(char*)malloc(8);memset(p,'A',8);"
            "int ok=(p[0]=='A');free(p);return ok?0:1;}\n"
        ),
        "ubsan": (
            "int main(void){volatile int x=256;unsigned char y=(unsigned char)x;"
            "int z=1/(1+(x&0));return (y==0 && z==1)?0:0;}\n"
        ),
        "lsan": "#include <stdlib.h>\nint main(void){void*p=malloc(16);(void)p;return 0;}\n",
        "lto": "int main(void){return 0;}\n",
        "pthread": (
            "#include <pthread.h>\nvoid*worker(void*a){(void)a;return 0;}\n"
            "int main(void){pthread_t t;pthread_create(&t,0,worker,0);"
            "pthread_join(t,0);return 0;}\n"
        ),
        "static_libs": "int main(void){return 0;}\n",
    }

    _PROBE_FLAGS: Dict[str, Tuple[str, ...]] = {
        "asan": ("-fsanitize=address",),
        "ubsan": ("-fsanitize=undefined",),
        "lsan": ("-fsanitize=address", "-fsanitize-recover=address"),
        "lto": ("-flto",),
        "pthread": ("-pthread",),
        "static_libs": ("-static",),
    }

    def __init__(self, *, cache_dir: Optional[str] = None,
                 include_optional: bool = True, timeout: float = 10.0) -> None:
        self.cache_dir = normalize_path(cache_dir) if cache_dir else None
        self.include_optional = include_optional
        self.timeout = float(timeout)
        self._lock = threading.Lock()
        self._cached: Optional[ToolchainInfo] = None

    # -- public API -----------------------------------------------------------
    def detect(self, *, force: bool = False) -> ToolchainInfo:
        """Full environment snapshot.  Cached unless ``force``."""
        with self._lock:
            if self._cached is not None and not force:
                return self._cached
            started = time.monotonic()
            info = ToolchainInfo()
            arg_map = dict(_CORE_TOOLS)
            names = [name for name, _ in _CORE_TOOLS]
            if not self.include_optional:
                keep = {"gcc", "g++", "clang", "clang++", "make", "cmake",
                        "afl-fuzz", "afl-clang-fast", "nm", "objdump", "gdb"}
                names = [n for n in names if n in keep]
            for name in names:
                info.tools[name] = probe_tool(name, version_args=arg_map.get(name),
                                              timeout=self.timeout)
            self._fill_sanitizer_support(info)
            self._derive_capabilities(info)
            self._add_warnings(info)
            info.duration_seconds = round(time.monotonic() - started, 2)
            self._cached = info
            return info

    def refresh(self) -> ToolchainInfo:
        return self.detect(force=True)

    # -- capability compilation probes ---------------------------------------
    def _fill_sanitizer_support(self, info: ToolchainInfo) -> None:
        """For each compiler present, try linking each sanitizer for real."""
        workdir = _safe(lambda: tempfile.mkdtemp(prefix="kmcs-probe-"), "")
        if not workdir:
            info.warnings.append("could not create temp dir for compile probes")
            return
        try:
            for comp_name in ("clang", "gcc"):
                probe = info.tools.get(comp_name)
                if not (probe and probe.available and probe.path):
                    continue
                for tag, flags in self._PROBE_FLAGS.items():
                    ok, note = self._try_compile(workdir, probe.path, flags, tag)
                    info.sanitizer_support[f"{comp_name}:{tag}"] = (
                        "yes" if ok else f"no ({note})")
        finally:
            _safe(lambda: shutil.rmtree(workdir, ignore_errors=True))

    def _try_compile(self, workdir: str, compiler: str, flags: Sequence[str],
                     tag: str) -> Tuple[bool, str]:
        src = os.path.join(workdir, f"probe_{tag}.c")
        exe = os.path.join(workdir, f"probe_{tag}")
        try:
            with open(src, "w", encoding="utf-8") as handle:
                handle.write(self._PROBE_PROGRAMS.get(tag,
                                                      self._PROBE_PROGRAMS["compiler_works"]))
            command = [compiler, *flags, src, "-o", exe]
            result = subprocess.run(command, capture_output=True, timeout=self.timeout,
                                    check=False, text=True, errors="replace")
            if result.returncode != 0:
                tail = (result.stderr or result.stdout or "").strip().splitlines()
                return False, (tail[-1] if tail else f"exit {result.returncode}")[:160]
            run = subprocess.run([exe], capture_output=True, timeout=self.timeout,
                                 check=False)
            return True, "" if run.returncode == 0 else f"runtime exit {run.returncode}"
        except subprocess.TimeoutExpired:
            return False, "compile/run timed out"
        except OSError as exc:
            return False, str(exc)[:160]

    def _derive_capabilities(self, info: ToolchainInfo) -> None:
        caps: Dict[str, bool] = {}
        caps["has_c_compiler"] = bool(info.best_compiler())
        caps["has_cpp_compiler"] = any(
            info.tools.get(n) and info.tools[n].available for n in ("g++", "clang++"))
        caps["aflpp_present"] = info.afl_available()
        caps["aflqemu_present"] = bool(info.tools.get("afl-qemu-trace")
                                       and info.tools["afl-qemu-trace"].present)
        caps["honggfuzz_present"] = bool(info.tools.get("honggfuzz")
                                         and info.tools["honggfuzz"].available)
        caps["gdb_present"] = bool(info.tools.get("gdb") and info.tools["gdb"].available)
        caps["binutils_present"] = all(
            info.tools.get(n) and info.tools[n].available
            for n in ("nm", "objdump", "readelf"))
        caps["symbolizer_present"] = caps["binutils_present"] or bool(
            info.tools.get("llvm-symbolizer") and info.tools["llvm-symbolizer"].available)
        for key, value in info.sanitizer_support.items():
            compiler, _, tag = key.partition(":")
            if value == "yes":
                caps[f"{compiler}_{tag}"] = True
        caps["asan"] = caps.get("clang_asan", False) or caps.get("gcc_asan", False)
        caps["ubsan"] = caps.get("clang_ubsan", False) or caps.get("gcc_ubsan", False)
        caps["lto"] = caps.get("clang_lto", False) or caps.get("gcc_lto", False)
        caps["static_linking"] = caps.get("clang_static_libs", False) or \
            caps.get("gcc_static_libs", False)
        caps["libfuzzer_driver"] = (caps["asan"] and bool(info.best_compiler())
                                    and info.best_compiler().family == "clang")
        info.capabilities = caps

    def _add_warnings(self, info: ToolchainInfo) -> None:
        if not info.capabilities.get("has_c_compiler"):
            info.warnings.append("no working C compiler found — builds will fail honestly")
        if not info.capabilities.get("aflpp_present"):
            info.warnings.append("AFL++ not installed — engine selection will report unavailability")
        if not info.capabilities.get("asan"):
            info.warnings.append("AddressSanitizer could not be linked by any probed compiler")
        if not info.capabilities.get("gdb_present"):
            info.warnings.append("GDB missing — crash stack analysis will use sanitizer reports only")

    # -- caching ---------------------------------------------------------------
    def save_cache(self, info: ToolchainInfo, path: Optional[str] = None) -> str:
        import json
        target = normalize_path(path or (os.path.join(self.cache_dir, "toolchain.json")
                                         if self.cache_dir else "toolchain.json"))
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        tmp = target + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(info.to_dict(), handle, indent=2, sort_keys=True, default=str)
        os.replace(tmp, target)
        return target

    def load_cache(self, path: Optional[str] = None) -> Optional[ToolchainInfo]:
        import json
        target = normalize_path(path or (os.path.join(self.cache_dir, "toolchain.json")
                                         if self.cache_dir else "toolchain.json"))
        if not os.path.isfile(target):
            return None
        try:
            with open(target, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            info = ToolchainInfo(
                host_os=payload.get("host_os", ""), host_arch=payload.get("host_arch", ""),
                hostname=payload.get("hostname", ""), python=payload.get("python", ""),
                capabilities=payload.get("capabilities", {}),
                sanitizer_support=payload.get("sanitizer_support", {}),
                warnings=payload.get("warnings", []),
                probed_at=payload.get("probed_at", ""),
                duration_seconds=float(payload.get("duration_seconds", 0.0)),
            )
            for name, tp in payload.get("tools", {}).items():
                allowed = {k: v for k, v in tp.items() if k in ToolProbe.__dataclass_fields__}
                info.tools[name] = ToolProbe(**allowed)
            self._cached = info
            return info
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Instrumentation probe (nm/objdump/readelf with pure-python fallback)
# ---------------------------------------------------------------------------

@dataclass
class InstrumentationReport:
    """Evidence about how (and whether) a binary was instrumented."""

    binary_path: str
    instrumented: bool = False
    kinds: List[str] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    afl_symbols_found: List[str] = field(default_factory=list)
    sancov_symbols_found: List[str] = field(default_factory=list)
    sections_seen: List[str] = field(default_factory=list)
    method: str = ""            # nm | objdump | readelf | bytescan | none
    symbol_count: int = 0
    stripped: Optional[bool] = None
    confidence: float = 0.0
    notes: List[str] = field(default_factory=list)
    probed_at: str = field(default_factory=utc_string)

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


class InstrumentationProbe:
    """Detect fuzzing instrumentation in a compiled artefact."""

    def __init__(self, *, prefer_llvm: bool = True, timeout: float = 30.0) -> None:
        self.prefer_llvm = bool(prefer_llvm)
        self.timeout = float(timeout)

    # -- public --------------------------------------------------------------
    def probe(self, binary_path: Any) -> InstrumentationReport:
        token = normalize_path(binary_path)
        report = InstrumentationReport(binary_path=token)
        if not os.path.isfile(token):
            raise TargetInvalidError(f"cannot probe missing binary '{token}'",
                                     component="targets.detector")
        symbols = self._collect_symbols(token, report)
        sections = self._collect_sections(token, report)
        report.sections_seen = sections
        haystack = "\n".join(symbols)
        for kind, needles in INSTRUMENTATION_SYMBOLS.items():
            hits = [needle for needle in needles if needle in haystack]
            if not hits:
                continue
            if kind not in report.kinds:
                report.kinds.append(kind)
            if kind in {InstrumentationKind.AFL_CLANG_FAST.value,
                        InstrumentationKind.AFL_CLANG_LTO.value,
                        InstrumentationKind.AFL_GCC_PLUGIN.value}:
                report.afl_symbols_found.extend(h for h in hits
                                                if h not in report.afl_symbols_found)
            else:
                report.sancov_symbols_found.extend(h for h in hits
                                                   if h not in report.sancov_symbols_found)
        for section_needle, kind in (
                (".llvmbc", InstrumentationKind.AFL_CLANG_FAST.value),
                ("__afl_fuzz", InstrumentationKind.AFL_CLANG_LTO.value)):
            if any(section_needle in s for s in sections) and kind not in report.kinds:
                report.kinds.append(kind)
        joined_sections = " ".join(sections)
        for sanitizer, markers in SANITIZER_RUNTIME_MARKERS.items():
            if any(marker in haystack or marker in joined_sections for marker in markers):
                if sanitizer not in report.sanitizers:
                    report.sanitizers.append(sanitizer)
        if not symbols:
            self._bytescan(token, report)
        report.instrumented = bool(report.kinds)
        report.symbol_count = len(symbols)
        if symbols:
            report.stripped = len(symbols) < 5
        weights = {"nm": 0.9, "llvm-nm": 0.9, "objdump": 0.85, "readelf": 0.85,
                   "bytescan": 0.5, "none": 0.2}
        base = weights.get(report.method or "none", 0.2)
        report.confidence = round(min(0.99, base * (1.0 if report.kinds else 0.4)), 3)
        return report

    # -- symbol/section collection ---------------------------------------------
    def _run(self, argv: Sequence[str]) -> Optional[str]:
        executable = shutil.which(argv[0])
        if not executable:
            return None
        try:
            result = subprocess.run(list(argv), capture_output=True, timeout=self.timeout,
                                    check=False, text=True, errors="replace")
            if result.returncode != 0 and not result.stdout:
                return None
            return result.stdout
        except (subprocess.TimeoutExpired, OSError):
            return None

    def _collect_symbols(self, path: str, report: InstrumentationReport) -> List[str]:
        commands: List[List[str]] = []
        if self.prefer_llvm and shutil.which("llvm-nm"):
            commands.append(["llvm-nm", "-a", path])
        if shutil.which("nm"):
            commands.append(["nm", "-a", path])
        if shutil.which("objdump"):
            commands.append(["objdump", "-T", path])
        for command in commands:
            output = self._run(command)
            if output:
                report.method = os.path.basename(command[0])
                tokens: List[str] = []
                for line in output.splitlines():
                    tokens.extend(line.split())
                return tokens
        return []

    def _collect_sections(self, path: str, report: InstrumentationReport) -> List[str]:
        output = None
        if shutil.which("readelf"):
            output = self._run(["readelf", "-S", path])
        if output is None and shutil.which("objdump"):
            output = self._run(["objdump", "-h", path])
        if not output:
            return self._sections_bytescan(path)
        sections: List[str] = []
        for line in output.splitlines():
            match = re.search(r"\[\s*\d+\]\s+(\S+)", line)
            if match:
                sections.append(match.group(1))
        return sorted(set(sections))

    def _sections_bytescan(self, path: str) -> List[str]:
        try:
            with open(path, "rb") as handle:
                blob = handle.read(64 << 20)
        except OSError:
            return []
        return [s.decode("ascii", "ignore")
                for s in re.findall(rb"[ -~]{4,}", blob)][:20000]

    def _bytescan(self, path: str, report: InstrumentationReport) -> None:
        try:
            with open(path, "rb") as handle:
                blob = handle.read(64 << 20)
        except OSError as exc:
            report.notes.append(f"bytescan failed: {exc}")
            return
        if report.method in ("", "none"):
            report.method = "bytescan"
        for kind, needles in INSTRUMENTATION_SYMBOLS.items():
            for needle in needles:
                if needle.encode("ascii", "ignore") in blob and kind not in report.kinds:
                    report.kinds.append(kind)
                    report.notes.append(f"matched '{needle}' via byte scan")
        for sanitizer, markers in SANITIZER_RUNTIME_MARKERS.items():
            if any(m.encode("ascii", "ignore") in blob for m in markers) \
                    and sanitizer not in report.sanitizers:
                report.sanitizers.append(sanitizer)


# ---------------------------------------------------------------------------
# High-level convenience: turn a path into a draft Target model
# ---------------------------------------------------------------------------

_DEFAULT_SANITIZERS = (SanitizerKind.ASAN.value, SanitizerKind.UBSAN.value)


def draft_target_from_path(path: Any, *, name: Optional[str] = None,
                           authorisation: Optional[Authorisation] = None,
                           profiler: Optional[TargetProfiler] = None,
                           instrument_probe: Optional[InstrumentationProbe] = None,
                           harness_mode: str = "stdin") -> Target:
    """Build a fully-populated :class:`Target` draft from a filesystem path.

    Every field comes from measurement: file hashes from the artefact,
    architecture from the ELF header, sanitizers from symbol scans, source
    language from a bounded tree census.  Unknowns stay ``unknown`` — they
    are never guessed into something optimistic.
    """
    if is_off_limits_artifact(path):
        raise PolicyViolationError(
            "refusing to register an off-limits system artefact as a fuzz target",
            details={"path": normalize_path(path)}, component="targets.detector")
    guard = profiler or TargetProfiler()
    token = normalize_path(path)
    if os.path.isdir(token):
        tree = guard.profile_source_tree(token)
        binaries = guard.find_candidate_binaries(token, limit=25)
        chosen = binaries[0] if binaries else None
        target = Target(
            id=generate_prefixed_id("tgt"),
            name=name or os.path.basename(token.rstrip("/")),
            binary_path=chosen.path if chosen else "",
            source_root=token,
            kind=TargetKind.SOURCE_TREE.value if not chosen else TargetKind.BINARY.value,
            language=tree.language,
            authorisation=authorisation,
        )
        if chosen:
            target.architecture = chosen.architecture
            target.operating_system = chosen.operating_system
            target.sanitizers_enabled = list(chosen.detected_sanitizers)
        target.build_recipe = BuildRecipe(
            source_root=token, system=tree.project_system,
            sanitizers=list(_DEFAULT_SANITIZERS),
            instrumentation=InstrumentationKind.NONE.value,
            optimization=OptimizationLevel.O1.value,
        )
    else:
        profile = guard.profile_file(token)
        target = Target(
            id=generate_prefixed_id("tgt"),
            name=name or os.path.basename(token),
            binary_path=token,
            source_root="",
            kind=(TargetKind.BINARY.value if profile.category == "binary"
                  else TargetKind.LIBRARY.value if profile.category == "shared-library"
                  else TargetKind.UNKNOWN.value),
            language=profile.likely_language,
            architecture=profile.architecture,
            operating_system=profile.operating_system,
            sanitizers_enabled=list(profile.detected_sanitizers),
            authorisation=authorisation,
        )
        target.metadata["artifact_sha256"] = profile.sha256
        target.metadata["artifact_format"] = profile.format
        target.metadata["artifact_size"] = profile.size_bytes
        target.build_recipe = BuildRecipe(sanitizers=list(_DEFAULT_SANITIZERS))
    binary_or_root = target.binary_path or token
    if harness_mode == "file":
        target.harness = HarnessSpec(mode="file", argv_template=[binary_or_root, "@@"])
    else:
        target.harness = HarnessSpec(mode=harness_mode, argv_template=[binary_or_root])
    probe = instrument_probe or InstrumentationProbe()
    if target.binary_path and os.path.isfile(target.binary_path):
        report = probe.probe(target.binary_path)
        target.instrumented = report.instrumented
        if report.kinds:
            target.instrumentation = report.kinds[0]
        merged = list(dict.fromkeys(target.sanitizers_enabled + report.sanitizers))
        target.sanitizers_enabled = merged
        target.metadata["instrumentation_method"] = report.method
        target.metadata["instrumentation_confidence"] = report.confidence
    return target


def default_detector(*, cache_dir: Optional[str] = None) -> ToolchainDetector:
    """Module-level factory keeping call sites terse."""
    return ToolchainDetector(cache_dir=cache_dir)


if __name__ == "__main__":  # pragma: no cover - manual smoke
    det = ToolchainDetector().detect()
    print("\n".join(det.summary_lines()))
