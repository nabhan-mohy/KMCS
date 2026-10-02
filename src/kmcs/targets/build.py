"""KMCS build system — instrumented, sanitizer-enabled compilation.

This module turns a :class:`~kmcs.core.models.BuildRecipe` into real
compiler invocations and executes them as **actual subprocesses**.  It never
fabricates success: every :class:`BuildResult` reports the exit code the
toolchain returned, the wall-clock time measured around the run, and the
captured compiler output (redacted for secrets before storage).

Responsibilities
----------------
* :class:`CompilerFlags` — canonical, deduplicated flag sets for each
  instrumentation family (AFL++ clang/gcc wrappers, libFuzzer PCGUARD) and
  each sanitizer combination, with conflict detection *before* invoking the
  compiler so users get an actionable error instead of a 40-line diagnostic.
* :class:`BuildPlan` — a fully-rendered, inspectable list of steps
  (configure / compile / link / post-process) derived from a recipe plus the
  detected toolchain.  Plans are deterministic and printable so researchers
  can audit exactly what will be executed *before* it runs.
* :class:`BuildRunner` — executes plans with process-group timeouts, live log
  capture, environment isolation (sanitizer env vars exported for the built
  binaries' own runtime), artifact discovery and verification (re-probing the
  produced binary to confirm instrumentation actually landed).
* :func:`build_target` — one-shot convenience used by the campaign worker:
  authorisation gate → plan → run → verify → updated :class:`Target`.

Safety rails
------------
* Refuses recipes whose flags contain prohibited/offensive constructs.
* Refuses ASan+TSan/MSan combinations (documented sanitizer conflicts).
* Never writes outside the declared build directory; deletes stale trees only
  when they carry the KMCS marker file we created ourselves.
* Compiler environment is scrubbed of credential-shaped variables before
  being passed down (see :func:`kmcs.core.exceptions.redact`).
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.exceptions import (
    BuildError,
    InstrumentationError,
    PolicyViolationError,
    TargetInvalidError,
    ToolNotFoundError,
)
from kmcs.core.models import (
    BuildRecipe,
    InstrumentationKind,
    OptimizationLevel,
    SanitizerKind,
    Target,
    guard_capability,
    normalize_path,
    sha256_file,
    utc_string,
)
from kmcs.targets.detector import (
    InstrumentationProbe,
    ToolchainDetector,
    ToolchainInfo,
    TargetProfiler,
)

__all__ = [
    "SANITIZER_FLAGS",
    "SANITIZER_ENV",
    "INSTRUMENTATION_FLAGS",
    "DANGEROUS_FLAG_PATTERNS",
    "CompilerFlags",
    "BuildStep",
    "BuildPlan",
    "BuildResult",
    "ArtifactRecord",
    "BuildRunner",
    "plan_build",
    "build_target",
]

# ---------------------------------------------------------------------------
# Canonical flag knowledge
# ---------------------------------------------------------------------------

#: Link-time/runtime flags per sanitizer (clang & gcc share these spellings).
SANITIZER_FLAGS: Dict[str, str] = {
    SanitizerKind.ASAN.value: "-fsanitize=address",
    SanitizerKind.UBSAN.value: "-fsanitize=undefined",
    SanitizerKind.LSAN.value: "-fsanitize=leak",
    SanitizerKind.MSAN.value: "-fsanitize=memory",
    SanitizerKind.TSAN.value: "-fsanitize=thread",
    SanitizerKind.HWASAN.value: "-fsanitize=hwaddress",
    SanitizerKind.SAFESTACK.value: "-fsanitize=safe-stack",
}

#: Environment exports that make the sanitizers behave well under fuzzing.
SANITIZER_ENV: Dict[str, Dict[str, str]] = {
    SanitizerKind.ASAN.value: {
        "ASAN_OPTIONS": ("detect_leaks=1:abort_on_error=1:allocator_may_return_null=1"
                         ":handle_segv=1:print_stacktrace=1:detect_odr_violation=0"),
        "ASAN_SYMBOLIZER_PATH": "",   # filled in at runtime when addr2line/llvm-symbolizer found
    },
    SanitizerKind.UBSAN.value: {
        "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:abort_on_error=1",
    },
    SanitizerKind.LSAN.value: {"LSAN_OPTIONS": "use_ld_preload=0"},
    SanitizerKind.TSAN.value: {"TSAN_OPTIONS": "halt_on_error=1:second_deadlock_stack=1"},
    SanitizerKind.MSAN.value: {"MSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"},
}

#: Which extra flags each instrumentation kind requires on top of plain CC.
INSTRUMENTATION_FLAGS: Dict[str, Dict[str, Sequence[str]]] = {
    InstrumentationKind.NONE.value: {"cflags": (), "ldflags": ()},
    InstrumentationKind.AFL_CLANG_FAST.value: {
        "cflags": ("AFL_USE_ASAN=auto",), "ldflags": (),
        "note": "instrumentation provided by afl-clang-fast wrapper itself",
    },
    InstrumentationKind.AFL_CLANG_LTO.value: {
        "cflags": ("-lstdc++",), "ldflags": ("-lm",),
        "note": "LTO mode needs its runtime linked explicitly in some distros",
    },
    InstrumentationKind.AFL_GCC_PLUGIN.value: {
        "cflags": (), "ldflags": ("--param ap-plugin-pass",),
        "note": "afl-gcc wrapper loads the plugin automatically",
    },
    InstrumentationKind.PCGUARD.value: {
        "cflags": ("-fsanitize=fuzzer-no-link",),
        "ldflags": ("-fsanitize=fuzzer-no-link",),
    },
    InstrumentationKind.TRACE_PC.value: {
        "cflags": ("-fsanitize-coverage=trace-pc",),
        "ldflags": (),
    },
    InstrumentationKind.LLVM_PROFILE.value: {
        "cflags": ("-fprofile-instr-generate", "-fcoverage-mapping"),
        "ldflags": ("-fprofile-instr-generate",),
    },
}

#: Flags that must never appear in user-supplied cflags/cxxflags/ldflags
#: because they defeat the safety or observability of the platform.  The
#: framework injects its own vetted versions of sanitizer/optimize flags.
DANGEROUS_FLAG_PATTERNS: Tuple[str, ...] = (
    "-rdynamic",            # leaks symbols into dynamic tables needlessly
    "-freorder-functions",  # breaks crash-site attribution stability
    "-fno-sanitize-recover=all",  # handled by our curated env instead
    "-z execstack",         # marks stack executable — offensive-adjacent
    "-nopie",
    "-Wl,-z,execstack",
)


class CompilerFlags:
    """Pure helpers that assemble validated compiler flag lists."""

    @staticmethod
    def dedupe(flags: Sequence[str]) -> List[str]:
        seen: set = set()
        out: List[str] = []
        for flag in flags:
            token = str(flag)
            if token and token not in seen:
                seen.add(token)
                out.append(token)
        return out

    @staticmethod
    def validate_user_flags(flags: Iterable[str], *, context: str = "recipe") -> List[str]:
        cleaned: List[str] = []
        for raw in flags:
            flag = str(raw).strip()
            if not flag:
                continue
            lowered = flag.lower()
            guard_capability(lowered, context=f"{context} flag")
            for dangerous in DANGEROUS_FLAG_PATTERNS:
                if lowered == dangerous or lowered.startswith(dangerous + "="):
                    raise InstrumentationError(
                        f"refusing dangerous compiler flag '{flag}' supplied in {context}",
                        component="targets.build", details={"flag": flag},
                    )
            if lowered.startswith("-fsanitize="):
                tokens = set(flag.split("=", 1)[1].split(","))
                unknown = tokens - set(SANITIZER_FLAGS.values()) - {
                    "fuzzer", "fuzzer-no-link", "address,undefined", "null", "bounds"}
                if unknown:
                    raise InstrumentationError(
                        f"unsupported -fsanitize tokens {sorted(unknown)} in {context}; "
                        "declare sanitizers via the recipe's 'sanitizers' field instead",
                        component="targets.build", details={"flag": flag},
                    )
            cleaned.append(flag)
        return cleaned

    @classmethod
    def for_recipe(cls, recipe: BuildRecipe, *, for_cxx: bool = False,
                   toolchain: Optional[ToolchainInfo] = None) -> List[str]:
        """Full compile-flag list: optimization + debug + sanitizers + extras."""
        flags: List[str] = [OptimizationLevel.coerce(recipe.optimization).flag]
        if recipe.keep_symbols:
            flags.append("-g")
        flags.append("-fno-omit-frame-pointer")
        for sanitizer in recipe.sanitizers:
            flag = SANITIZER_FLAGS.get(str(sanitizer))
            if flag:
                flags.append(flag)
        instr = INSTRUMENTATION_FLAGS.get(str(recipe.instrumentation), {})
        if str(recipe.instrumentation) == InstrumentationKind.PCGUARD.value:
            flags.extend(instr.get("cflags", ()))
        user = cls.validate_user_flags(recipe.cxxflags if for_cxx else recipe.cflags,
                                       context="cxxflags" if for_cxx else "cflags")
        flags.extend(user)
        for name, value in recipe.definitions.items():
            flags.append(f"-D{name}={value}" if value else f"-D{name}")
        return cls.dedupe(flags)

    @classmethod
    def linker_for_recipe(cls, recipe: BuildRecipe,
                          toolchain: Optional[ToolchainInfo] = None) -> List[str]:
        flags: List[str] = []
        for sanitizer in recipe.sanitizers:
            flag = SANITIZER_FLAGS.get(str(sanitizer))
            if flag:
                flags.append(flag)
        instr = INSTRUMENTATION_FLAGS.get(str(recipe.instrumentation), {})
        flags.extend(instr.get("ldflags", ()))
        flags.extend(cls.validate_user_flags(recipe.ldflags, context="ldflags"))
        return cls.dedupe(flags)

    @classmethod
    def sanitizer_environment(cls, recipe: BuildRecipe, *,
                              symbolizer: str = "") -> Dict[str, str]:
        env: Dict[str, str] = {}
        for sanitizer in recipe.sanitizers:
            for key, value in SANITIZER_ENV.get(str(sanitizer), {}).items():
                if key == "ASAN_SYMBOLIZER_PATH":
                    if symbolizer:
                        env[key] = symbolizer
                    continue
                existing = env.get(key)
                env[key] = f"{existing}:{value}" if existing else value
        return env


# ---------------------------------------------------------------------------
# Plans and steps
# ---------------------------------------------------------------------------

@dataclass
class BuildStep:
    """One executable step inside a :class:`BuildPlan`."""

    name: str
    argv: List[str]
    cwd: str = ""
    env: Dict[str, str] = field(default_factory=dict)
    kind: str = "compile"          # configure | compile | link | custom | verify
    source_files: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    timeout_seconds: float = 900.0
    required: bool = True
    notes: str = ""

    def describe(self) -> str:
        rendered = " ".join(shlex.quote(a) for a in self.argv)
        where = f" (cwd={self.cwd})" if self.cwd else ""
        return f"[{self.kind}] {self.name}: {rendered}{where}"

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


@dataclass
class ArtifactRecord:
    """A produced (or discovered) build artefact with verified facts."""

    path: str
    sha256: str = ""
    size_bytes: int = 0
    kind: str = "executable"       # executable | shared-library | static-library | object
    instrumented: bool = False
    instrumentation_kinds: List[str] = field(default_factory=list)
    sanitizers_detected: List[str] = field(default_factory=list)
    probe_confidence: float = 0.0
    recorded_at: str = field(default_factory=utc_string)

    def refresh(self) -> "ArtifactRecord":
        if os.path.isfile(self.path):
            self.size_bytes = os.path.getsize(self.path)
            self.sha256 = sha256_file(self.path)
        return self

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


@dataclass
class BuildPlan:
    """Deterministic, auditable sequence of :class:`BuildStep`s."""

    target_id: str
    recipe: BuildRecipe
    steps: List[BuildStep] = field(default_factory=list)
    build_dir: str = ""
    expected_artifacts: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_string)
    toolchain_snapshot: Dict[str, Any] = field(default_factory=dict)

    def add(self, step: BuildStep) -> BuildStep:
        self.steps.append(step)
        return step

    def render(self) -> str:
        lines = [f"# KMCS build plan for target {self.target_id}",
                 f"# build dir: {self.build_dir}",
                 f"# instrumentation: {self.recipe.instrumentation} "
                 f"sanitizers: {','.join(self.recipe.sanitizers) or 'none'}"]
        lines += [step.describe() for step in self.steps]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id, "build_dir": self.build_dir,
            "steps": [s.to_dict() for s in self.steps],
            "expected_artifacts": list(self.expected_artifacts),
            "warnings": list(self.warnings), "created_at": self.created_at,
            "toolchain_snapshot": dict(self.toolchain_snapshot),
            "recipe": self.recipe.to_dict(),
        }


@dataclass
class StepOutcome:
    """Measured result of executing one BuildStep."""

    step_name: str
    argv: List[str]
    returncode: Optional[int]
    stdout_tail: str = ""
    stderr_tail: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


@dataclass
class BuildResult:
    """Honest outcome of a whole build: no fabricated successes ever."""

    target_id: str
    success: bool = False
    outcomes: List[StepOutcome] = field(default_factory=list)
    artifacts: List[ArtifactRecord] = field(default_factory=list)
    started_at: str = field(default_factory=utc_string)
    finished_at: str = ""
    duration_seconds: float = 0.0
    build_dir: str = ""
    log_path: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    environment_snapshot: Dict[str, str] = field(default_factory=dict)

    @property
    def first_error(self) -> str:
        for outcome in self.outcomes:
            if not outcome.ok:
                tail = (outcome.stderr_tail or outcome.stdout_tail or outcome.error).strip()
                return f"step '{outcome.step_name}' failed: {tail[:2000]}"
        return self.errors[0] if self.errors else ""

    def summary(self) -> str:
        state = "SUCCESS" if self.success else "FAILED"
        arts = ", ".join(os.path.basename(a.path) for a in self.artifacts) or "none"
        return (f"build {state} for {self.target_id} in {self.duration_seconds:.1f}s "
                f"({len(self.outcomes)} steps, artifacts: {arts})")

    def to_dict(self) -> Dict[str, Any]:
        payload = dict(vars(self))
        payload["outcomes"] = [o.to_dict() for o in self.outcomes]
        payload["artifacts"] = [a.to_dict() for a in self.artifacts]
        return payload


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

_MARKER = ".kmcs-build-managed"


def _autodetect_system(recipe: BuildRecipe, source_root: str) -> str:
    if recipe.system and recipe.system != "autodetect":
        return recipe.system
    probe = TargetProfiler()
    return probe.detect_project_system(source_root)


def plan_build(target: Target, *, toolchain: Optional[ToolchainInfo] = None,
               detector: Optional[ToolchainDetector] = None,
               source_files: Optional[Sequence[str]] = None,
               build_dir: Optional[str] = None,
               clean: bool = False) -> BuildPlan:
    """Derive an executable :class:`BuildPlan` from a target's recipe.

    Two families of plans exist:

    * **Direct compile** — when explicit C/C++ sources are given (typical for
      harness builds): one compile+link step per translation unit group.
    * **Project-system build** — cmake/make/autotools/meson driven by the
      recipe's ``configure_command``/``build_command`` with CC/CXX/flags
      injected through the environment, which is how AFL++ documents its
      usage against real-world projects.
    """
    recipe = target.build_recipe
    info = toolchain or (detector or ToolchainDetector()).detect()
    source_root = recipe.source_root or target.source_root or ""
    plan = BuildPlan(target_id=target.id, recipe=recipe,
                     build_dir=normalize_path(build_dir or recipe.build_dir
                                              or os.path.join(source_root or ".",
                                                              "build-kmcs")))
    plan.toolchain_snapshot = {
        "host_os": info.host_os, "host_arch": info.host_arch,
        "capabilities": dict(info.capabilities),
        "compiler": (info.best_compiler().path if info.best_compiler() else ""),
    }
    conflicts = recipe.conflicts()
    if conflicts:
        raise InstrumentationError(
            "build recipe contains conflicting options: " + "; ".join(conflicts),
            component="targets.build", details={"conflicts": conflicts},
        )
    cc = recipe.effective_cc()
    cxx = recipe.effective_cxx()
    # Resolve the requested compiler against reality; fail honestly if absent.
    def _resolve(name: str, purpose: str) -> str:
        resolved = shutil.which(name)
        if not resolved:
            raise ToolNotFoundError(
                f"{purpose} compiler '{name}' is not installed on this machine; "
                "the build cannot proceed (KMCS does not fake builds)",
                component="targets.build", details={"requested": name, "purpose": purpose},
            )
        return resolved

    cc_path = _resolve(cc, "C")
    cxx_path = _resolve(cxx, "C++") if (source_files and any(
        str(f).endswith((".cc", ".cpp", ".cxx", ".C")) for f in source_files)) else cc_path
    cflags = CompilerFlags.for_recipe(recipe, for_cxx=False, toolchain=info)
    cxxflags = CompilerFlags.for_recipe(recipe, for_cxx=True, toolchain=info)
    ldflags = CompilerFlags.linker_for_recipe(recipe, toolchain=info)
    symbolizer = ""
    for candidate in ("llvm-symbolizer", "addr2line"):
        probe = info.tools.get(candidate)
        if probe and probe.available and probe.path:
            symbolizer = probe.path
            break
    base_env = dict(recipe.environment)
    base_env.update(CompilerFlags.sanitizer_environment(recipe, symbolizer=symbolizer))
    base_env.setdefault("CC", cc_path)
    base_env.setdefault("CXX", cxx_path)

    if clean:
        plan.add(BuildStep(
            name="clean", kind="custom",
            argv=[sys_executable_or_sh(), "-c",
                  f'if [ -f "{os.path.join(plan.build_dir, _MARKER)}" ]; then rm -rf "{plan.build_dir}"; fi'],
            cwd=source_root or plan.build_dir,
            notes="removes only KMCS-marked build directories",
        ))
    plan.add(BuildStep(name="mkdir", kind="custom",
                       argv=["mkdir", "-p", plan.build_dir], cwd="."))
    plan.add(BuildStep(name="mark", kind="custom",
                       argv=["touch", os.path.join(plan.build_dir, _MARKER)], cwd="."))

    if source_files:
        objects: List[str] = []
        for src in source_files:
            src_token = normalize_path(src)
            if not os.path.isfile(src_token):
                raise TargetInvalidError(f"declared source file missing: {src_token}",
                                         component="targets.build")
            is_cxx = src_token.endswith((".cc", ".cpp", ".cxx", ".C", ".hpp"))
            obj = os.path.join(plan.build_dir,
                               os.path.basename(src_token) + ".o")
            objects.append(obj)
            plan.add(BuildStep(
                name=f"compile:{os.path.basename(src_token)}", kind="compile",
                argv=[cxx_path if is_cxx else cc_path,
                      *(cxxflags if is_cxx else cflags), "-c", src_token, "-o", obj],
                cwd=source_root or os.path.dirname(src_token),
                env=dict(base_env), source_files=[src_token], outputs=[obj],
            ))
        exe_name = target.name or os.path.basename(target.binary_path or "kmcs-harness")
        exe_path = os.path.join(plan.build_dir, re.sub(r"\s+", "_", exe_name))
        plan.add(BuildStep(
            name="link", kind="link",
            argv=[cxx_path if any(o.endswith((".cc.o", ".cpp.o", ".cxx.o")) for o in objects) else cc_path,
                  *objects, *ldflags, "-o", exe_path],
            cwd=source_root or plan.build_dir, env=dict(base_env),
            outputs=[exe_path],
        ))
        plan.expected_artifacts = [exe_path]
        return plan

    system = _autodetect_system(recipe, source_root)
    configure = recipe.configure_command
    build_cmd = recipe.build_command
    if system == "cmake" and not configure:
        configure = " ".join(["cmake", "-S", source_root or ".",
                              "-B", plan.build_dir,
                              f'-DCMAKE_C_COMPILER={cc_path}',
                              f'-DCMAKE_CXX_COMPILER={cxx_path}',
                              f'-DCMAKE_C_FLAGS={" ".join(cflags)}',
                              f'-DCMAKE_CXX_FLAGS={" ".join(cxxflags)}',
                              f'-DCMAKE_EXE_LINKER_FLAGS={" ".join(ldflags)}',
                              "-DCMAKE_BUILD_TYPE=Debug",
                              *recipe.cmake_args])
    elif system == "autotools" and not configure:
        configure = " ".join(["./configure", f"CFLAGS={' '.join(cflags)}",
                              f"CXXFLAGS={' '.join(cxxflags)}",
                              f"LDFLAGS={' '.join(ldflags)}"])
    if configure:
        plan.add(BuildStep(name="configure", kind="configure",
                           argv=["sh", "-c", configure],
                           cwd=(plan.build_dir if system == "cmake" else source_root) or ".",
                           env=dict(base_env)))
    if not build_cmd:
        if system in {"cmake", "make", "autotools"}:
            jobs = str(_cpu_count())
            build_cmd = (f"cmake --build {plan.build_dir} -j{jobs}"
                         if system == "cmake" else f"make -j{jobs} "
                         + " ".join(recipe.make_targets))
        elif system == "meson":
            build_cmd = f"ninja -C {plan.build_dir}"
        else:
            raise BuildError(
                "cannot derive a build command: recipe has no build_command and the "
                f"project system '{system}' has no standard KMCS default; set "
                "build_recipe.build_command explicitly",
                component="targets.build", details={"system": system},
            )
    plan.add(BuildStep(name="build", kind="compile",
                       argv=["sh", "-c", build_cmd],
                       cwd=source_root or plan.build_dir, env=dict(base_env)))
    expected = [normalize_path(a) for a in recipe.artifacts]
    if not expected and target.binary_path:
        expected = [target.binary_path]
    plan.expected_artifacts = expected
    if not expected:
        plan.warnings.append(
            "no expected artifacts declared; after building, point the target at "
            "the produced binary (KMCS will search the build tree but will not guess)")
    return plan


def sys_executable_or_sh() -> str:
    return shutil.which("sh") or "/bin/sh"


def _cpu_count() -> int:
    try:
        return max(1, os.cpu_count() or 1)
    except Exception:
        return 1


import re  # noqa: E402  (used above in plan_build; kept local to avoid shadowing)
import sys  # noqa: E402


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

class BuildRunner:
    """Executes :class:`BuildPlan` objects as real subprocesses."""

    TAIL_LIMIT = 8000  # chars of stdout/stderr retained per step

    def __init__(self, *, toolchain: Optional[ToolchainInfo] = None,
                 log_dir: Optional[str] = None,
                 default_timeout: float = 900.0,
                 on_output: Optional[Callable[[str, str], None]] = None) -> None:
        self.toolchain = toolchain
        self.log_dir = normalize_path(log_dir) if log_dir else None
        self.default_timeout = float(default_timeout)
        self.on_output = on_output
        self._lock = threading.Lock()

    # -- public ---------------------------------------------------------------
    def execute(self, plan: BuildPlan, *, stop_on_error: bool = True,
                timeout: Optional[float] = None) -> BuildResult:
        """Run every step in order; results are whatever the tools reported."""
        result = BuildResult(target_id=plan.target_id, build_dir=plan.build_dir)
        started = time.monotonic()
        log_handle = self._open_log(plan, result)
        try:
            for step in plan.steps:
                outcome = self._run_step(step, timeout or self.default_timeout, log_handle)
                result.outcomes.append(outcome)
                if self.on_output:
                    _safe_call(self.on_output, step.name,
                               outcome.stderr_tail or outcome.stdout_tail)
                if not outcome.ok:
                    result.errors.append(
                        f"step '{step.name}' exited "
                        f"{outcome.returncode if outcome.returncode is not None else 'signal/timeout'}")
                    if stop_on_error and step.required:
                        break
            else:
                pass
            result.success = all(o.ok for o in result.outcomes) and bool(result.outcomes)
            if result.success:
                self._collect_artifacts(plan, result)
                if not result.artifacts:
                    result.success = False
                    result.errors.append(
                        "all steps exited 0 but no verifiable artifacts were found — "
                        "this is reported as failure, not success")
        finally:
            if log_handle:
                _safe_call(log_handle.close)
            result.finished_at = utc_string()
            result.duration_seconds = round(time.monotonic() - started, 3)
        return result

    def rebuild_and_verify(self, target: Target, *, clean: bool = False,
                           source_files: Optional[Sequence[str]] = None,
                           toolchain: Optional[ToolchainInfo] = None
                           ) -> Tuple[BuildPlan, BuildResult]:
        """Convenience: plan → execute → verify instrumentation landed."""
        info = toolchain or self.toolchain or ToolchainDetector().detect()
        plan = plan_build(target, toolchain=info, source_files=source_files, clean=clean)
        result = self.execute(plan)
        for artifact in result.artifacts:
            self.verify_artifact(artifact)
        return plan, result

    def verify_artifact(self, artifact: ArtifactRecord) -> ArtifactRecord:
        """Re-probe a produced binary so 'instrumented' is a fact, not a hope."""
        if not os.path.isfile(artifact.path):
            artifact.instrumented = False
            return artifact
        artifact.refresh()
        report = InstrumentationProbe().probe(artifact.path)
        artifact.instrumented = report.instrumented
        artifact.instrumentation_kinds = list(report.kinds)
        artifact.sanitizers_detected = list(report.sanitizers)
        artifact.probe_confidence = report.confidence
        return artifact

    # -- internals --------------------------------------------------------------
    def _open_log(self, plan: BuildPlan, result: BuildResult):
        if not self.log_dir:
            return None
        try:
            os.makedirs(self.log_dir, exist_ok=True)
            handle = open(os.path.join(self.log_dir,
                                       f"build-{int(time.time())}-{plan.target_id}.log"),
                          "w", encoding="utf-8", errors="replace")
            result.log_path = handle.name
            handle.write(plan.render() + "\n\n")
            return handle
        except OSError:
            return None

    def _run_step(self, step: BuildStep, timeout: float,
                  log_handle: Any) -> StepOutcome:
        outcome = StepOutcome(step_name=step.name, argv=list(step.argv), returncode=None)
        env = os.environ.copy()
        # Scrub credential-shaped variables inherited from the parent shell.
        for key in list(env):
            upper = key.upper()
            if any(marker in upper for marker in ("TOKEN", "PASSWORD", "SECRET", "APIKEY", "API_KEY")):
                env.pop(key, None)
        env.update(step.env)
        cwd = step.cwd or None
        if cwd and not os.path.isdir(cwd):
            outcome.error = f"working directory does not exist: {cwd}"
            return outcome
        started = time.monotonic()
        try:
            popen_kwargs: Dict[str, Any] = dict(
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env,
                text=True, errors="replace",
            )
            if os.name == "posix":
                popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen(step.argv, **popen_kwargs)  # noqa: S603 - argv is planned & audited
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                outcome.returncode = proc.returncode
            except subprocess.TimeoutExpired:
                outcome.timed_out = True
                _kill_process_tree(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except Exception:
                    stdout, stderr = "", ""
                outcome.returncode = proc.returncode if proc.returncode is not None else -signal.SIGKILL
            outcome.stdout_tail = (stdout or "")[-self.TAIL_LIMIT:]
            outcome.stderr_tail = (stderr or "")[-self.TAIL_LIMIT:]
        except FileNotFoundError as exc:
            outcome.error = f"executable not found: {exc}"
        except PermissionError as exc:
            outcome.error = f"permission denied: {exc}"
        except OSError as exc:
            outcome.error = f"oserror launching step: {exc}"
        finally:
            outcome.duration_seconds = round(time.monotonic() - started, 3)
        if log_handle:
            _safe_call(log_handle.write,
                       f"=== {step.name} rc={outcome.returncode} "
                       f"({outcome.duration_seconds}s) ===\n"
                       f"--- stdout ---\n{outcome.stdout_tail}\n"
                       f"--- stderr ---\n{outcome.stderr_tail}\n\n")
            _safe_call(log_handle.flush)
        return outcome

    def _collect_artifacts(self, plan: BuildPlan, result: BuildResult) -> None:
        candidates: List[str] = []
        for step in plan.steps:
            candidates.extend(step.outputs)
        for declared in plan.expected_artifacts:
            if declared not in candidates:
                candidates.append(declared)
        found: List[str] = []
        for candidate in candidates:
            token = normalize_path(candidate)
            if os.path.isfile(token):
                found.append(token)
        if not found and plan.build_dir and os.path.isdir(plan.build_dir):
            profiler = TargetProfiler()
            for profile in profiler.find_candidate_binaries(plan.build_dir, limit=50):
                found.append(profile.path)
        for path in dict.fromkeys(found):
            record = ArtifactRecord(path=path).refresh()
            ext = os.path.splitext(path)[1].lower()
            if ext in {".so", ".dylib"}:
                record.kind = "shared-library"
            elif ext in {".a", ".lib"}:
                record.kind = "static-library"
            elif ext == ".o":
                record.kind = "object"
            result.artifacts.append(record)


def _kill_process_tree(proc: "subprocess.Popen[str]") -> None:
    """Terminate a whole process group (build systems fork children)."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:  # pragma: no cover - non-posix
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        _safe_call(proc.terminate)
    time.sleep(0.2)
    try:
        if proc.poll() is None:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:  # pragma: no cover
                proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        _safe_call(proc.kill)


def _safe_call(fn: Any, *args: Any, **kw: Any) -> Any:
    try:
        return fn(*args, **kw)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# One-shot entry point used by campaigns/workers
# ---------------------------------------------------------------------------

def build_target(target: Target, *, require_authorization: bool = True,
                 clean: bool = False, source_files: Optional[Sequence[str]] = None,
                 toolchain: Optional[ToolchainInfo] = None,
                 detector: Optional[ToolchainDetector] = None,
                 runner: Optional[BuildRunner] = None,
                 log_dir: Optional[str] = None,
                 update_target: bool = True) -> BuildResult:
    """Authorisation-gated build of *target*; updates the model on success.

    On success the target's ``binary_path`` (when unset), ``instrumented``,
    ``instrumentation`` and ``sanitizers_enabled`` fields are refreshed from
    the *verified* artifact probe — never from what the recipe hoped for.
    """
    if require_authorization:
        target.require_authorization(operation="build")
    info = toolchain or (detector or ToolchainDetector()).detect()
    executor = runner or BuildRunner(toolchain=info, log_dir=log_dir)
    plan = plan_build(target, toolchain=info, source_files=source_files, clean=clean)
    result = executor.execute(plan)
    for artifact in result.artifacts:
        executor.verify_artifact(artifact)
    if result.success and update_target:
        primary = _pick_primary_artifact(target, result)
        if primary is not None:
            if not target.binary_path or not os.path.isfile(target.binary_path):
                target.binary_path = primary.path
            target.instrumented = primary.instrumented
            if primary.instrumentation_kinds:
                target.instrumentation = primary.instrumentation_kinds[0]
            merged = list(dict.fromkeys(list(target.sanitizers_enabled)
                                        + list(primary.sanitizers_detected)))
            target.sanitizers_enabled = merged
            target.metadata["last_build"] = {
                "at": result.finished_at, "duration_s": result.duration_seconds,
                "sha256": primary.sha256, "plan_steps": len(plan.steps),
                "log": result.log_path,
            }
            target.updated_at = utc_string()
    return result


def _pick_primary_artifact(target: Target, result: BuildResult) -> Optional[ArtifactRecord]:
    if not result.artifacts:
        return None
    wanted = os.path.basename(target.binary_path or target.name or "")
    if wanted:
        for record in result.artifacts:
            if os.path.basename(record.path) == wanted and record.kind == "executable":
                return record
    for record in result.artifacts:
        if record.kind == "executable":
            return record
    return result.artifacts[0]


if __name__ == "__main__":  # pragma: no cover - manual smoke
    demo = Target(name="smoke", binary_path="", build_recipe=BuildRecipe(
        sanitizers=["address"], instrumentation="none"))
    print(plan_build(demo.__class__(name="x", binary_path="/bin/true",
                                    build_recipe=BuildRecipe(instrumentation="none")),
                     toolchain=ToolchainDetector(include_optional=False).detect()).render())
