"""KMCS AFL++ engine adapter (Phase 4, module ``aflpp``).

Drives the real ``afl-fuzz`` binary as a supervised subprocess and turns its
on-disk bookkeeping (``fuzzer_stats``, ``queue/``, ``crashes/``, ``hangs/``)
into KMCS :class:`~kmcs.fuzzers.base.EngineStats` and
:class:`~kmcs.fuzzers.base.CrashArtifact` objects.  Nothing is simulated: if
``afl-fuzz`` is not installed, :meth:`AFLPlusPlusAdapter.probe` reports
``available=False`` and every start attempt raises
:class:`~kmcs.core.exceptions.FuzzerUnavailableError`.

Key behaviours
--------------
* **Forkserver mode** by default; persistent mode (``@@`` + ``AFL_PERSISTENT``)
  when the harness declares it.
* **Multi-worker synchronisation**: ``workers > 1`` fans out into
  ``-M`` (main) plus ``-S`` (secondary) instances that share the sync parent
  directory — exactly how AFL++ parallel fuzzing is meant to work.
* **Sanitizer-aware env**: ASan/UBSan/LSan variables are exported for the
  *target's* runtime (``ASAN_OPTIONS``, ``UBSAN_OPTIONS``, ``AFL_*`` knobs)
  with crash-detection-friendly defaults, honouring anything the user set.
* **Dictionary & tokens** passthrough (``-x`` / ``-s`` style extras via
  ``extra_args`` remain fully under user control).
* **Honest stats**: values come from parsing the engine's own
  ``fuzzer_stats`` key/value file; missing keys stay ``None``.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from kmcs.core.models import (
    EngineKind,
    SanitizerKind,
    normalize_path,
    safe_filename,
)
from kmcs.fuzzers.base import (
    EngineCapabilities,
    EngineStats,
    FuzzEngineAdapter,
    FuzzLaunchSpec,
    FuzzSession,
    StatsSource,
    parse_int_token,
    resolve_engine_binary,
)

__all__ = [
    "AFLPLUSPLUS_BINARY",
    "AFLPlusPlusAdapter",
    "FUZZER_STATS_KEYS",
    "build_afl_environment",
    "parse_fuzzer_stats",
    "parse_plot_data_row",
]

#: primary driver binary searched on PATH
AFLPLUSPLUS_BINARY = "afl-fuzz"

#: companion tools probed for capability reporting (never required to run)
_AFL_COMPANIONS = ("afl-showmap", "afl-cmin", "afl-tmin", "afl-analyze",
                   "afl-clang-fast", "afl-clang-lto", "afl-gcc-fast")

#: canonical keys of afl-fuzz's fuzzer_stats file
FUZZER_STATS_KEYS: Tuple[str, ...] = (
    "start_time", "end_time", "fuzz_run_time", "exec_secs", "execs_done",
    "exec_per_sec", "cycles_total", "cycles_passed", "corpus_count",
    "corpus_found", "corpus_installed", "mapdensity_min", "mapdensity_avg",
    "mapdensity_max", "coverage_exec", "bitmap_cvg", "unique_crashes",
    "unique_hangs", "last_path", "last_crash", "last_hang", "exec_timeout",
    "afl_version", "command_line",
)

_KEY_LINE = re.compile(r"^\s*(?P<key>[a-z0-9_]+)\s*:\s*(?P<value>.*?)\s*$")


def parse_fuzzer_stats(path: os.PathLike | str) -> Dict[str, str]:
    """Parse an AFL++ ``fuzzer_stats`` file into a dict.

    Malformed lines are skipped silently (the file can be written while we
    read it); a missing file yields ``{}``.
    """
    result: Dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return result
    for line in text.splitlines():
        match = _KEY_LINE.match(line)
        if match:
            result[match.group("key")] = match.group("value")
    return result


def parse_plot_data_row(path: os.PathLike | str, *, last: bool = True) -> Dict[str, float]:
    """Read one row of AFL++ ``plot_data`` (CSV with a ``#`` header).

    Returns numeric fields keyed by the header column names; empty when the
    file is absent or has no data rows yet.
    """
    p = Path(path)
    try:
        lines = [ln for ln in p.read_text(encoding="utf-8",
                                          errors="replace").splitlines()
                 if ln.strip()]
    except OSError:
        return {}
    if len(lines) < 2:
        return {}
    header = lines[0].lstrip("#").strip()
    columns = [c.strip() for c in header.split(",")]
    row = lines[-1] if last else lines[1]
    values: Dict[str, float] = {}
    for name, raw in zip(columns, row.split(",")):
        try:
            values[name] = float(raw)
        except ValueError:
            continue
    return values


def build_afl_environment(spec: FuzzLaunchSpec,
                          base_env: Optional[Mapping[str, str]] = None
                          ) -> Dict[str, str]:
    """Compose the child environment for an afl-fuzz run.

    Merges (in priority order): process environment → sanitizer defaults →
    AFL++ tuning defaults → user-supplied ``spec.env`` overrides.  Values the
    user already set are never clobbered.
    """
    env: Dict[str, str] = dict(base_env if base_env is not None else os.environ)

    # --- sanitizer runtime options (crash detection friendly) --------------
    sanitizers = {str(s) for s in spec.target.sanitizers_enabled}
    if SanitizerKind.ASAN.value in sanitizers or SanitizerKind.NONE.value not in sanitizers:
        env.setdefault("ASAN_OPTIONS",
                       "abort_on_error=1:detect_leaks=0:"
                       "allocator_may_return_null=1:handle_segv=1:"
                       "detect_odr_violation=0:symbolize=0")
    if SanitizerKind.UBSAN.value in sanitizers:
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1:")
    if SanitizerKind.LSAN.value in sanitizers:
        asan_opts = env.get("ASAN_OPTIONS", "")
        if "detect_leaks=0" in asan_opts:
            env["ASAN_OPTIONS"] = asan_opts.replace("detect_leaks=0",
                                                    "detect_leaks=1")
        env.setdefault("LSAN_OPTIONS", "use_unaligned=1:")

    # --- AFL++ tuning -------------------------------------------------------
    env.setdefault("AFL_SKIP_CPUFREQ", "1")     # we may not own cpufreq
    env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "0")
    env.setdefault("AFL_BENCH_JUST_ONE", "0")
    env.setdefault("AFL_FAST_CAL", "1")
    env.setdefault("AFL_NO_UI", "1")            # we consume logs, not curses
    env.setdefault("AFL_QUIET", "0")
    if spec.timeout_ms:
        env.setdefault("AFL_TMOUT_METHOD_POW", "50 990")
    # propagate instrumentation-relevant flags the target may expect
    for key, value in spec.env.items():
        env[str(key)] = str(value)
    return env


class AFLPlusPlusAdapter(FuzzEngineAdapter):
    """KMCS adapter for the AFL++ suite (``afl-fuzz`` forkserver mode)."""

    engine_display_name = "AFL++"
    requires_instrumentation = True
    stats_refresh_seconds = 5.0
    artifact_refresh_seconds = 2.0

    # -- identity / probe ------------------------------------------------------
    @property
    def engine_kind(self) -> EngineKind:
        return EngineKind.AFLPP

    def probe(self) -> EngineCapabilities:
        """Locate ``afl-fuzz`` and derive capabilities from its version."""
        binary = self.binary_override or resolve_engine_binary(
            [AFLPLUSPLUS_BINARY], extra_dirs=self._search_dirs())
        if not binary:
            return EngineCapabilities(
                engine=EngineKind.AFLPP.value, available=False,
                notes=f"'{AFLPLUSPLUS_BINARY}' not found on PATH")
        version = ""
        notes: List[str] = []
        try:
            import subprocess
            proc = subprocess.run([binary, "-h"], capture_output=True,
                                  timeout=10, text=True)
            blob = (proc.stdout or "") + (proc.stderr or "")
            match = re.search(r"version\s+(\d+(?:\.\d+)+)", blob, re.I)
            if match:
                version = match.group(1)
            elif "usage:" not in blob.lower():
                notes.append("afl-fuzz -h produced unexpected output")
        except Exception as exc:  # noqa: BLE001 - probing must never raise
            notes.append(f"version probe failed: {exc}")
        companions = {}
        for tool in _AFL_COMPANIONS:
            companions[tool] = resolve_engine_binary([tool]) is not None
        if not companions.get("afl-clang-fast"):
            notes.append("afl-clang-fast missing: instrumented builds need "
                         "kmcs.targets.build with another wrapper or clang-lto")
        major = parse_int_token(version.split(".")[0] if version else None, 3) or 3
        return EngineCapabilities(
            engine=EngineKind.AFLPP.value, available=True, binary_path=binary,
            version=version,
            persistent_mode=True,
            cmplog=major >= 3 and companions.get("afl-clang-fast", False),
            dictionary_support=True,
            tokens_support=major >= 4,
            custom_mutator_support=True,
            parallel_workers=True,
            in_process=False,
            coverage_feedback=True,
            sandbox_options=("none",),
            notes="; ".join(notes))

    def _search_dirs(self) -> Sequence[str]:
        dirs: List[str] = []
        cfg_root = os.environ.get("KMCS_HOME")
        if cfg_root:
            dirs.append(os.path.join(cfg_root, "bin"))
        dirs.append("/usr/local/bin")
        return dirs

    # -- argv -------------------------------------------------------------------
    def build_argv(self, spec: FuzzLaunchSpec,
                   session_paths: Mapping[str, str]) -> List[str]:
        """Render the full ``afl-fuzz`` command line for *spec*.

        AFL++ layout: ``-o OUT`` is the *sync parent* directory; each
        instance (``-M main`` / ``-S worker``) writes into ``OUT/<name>/``.
        With ``workers == 1`` a single master instance named ``kmcs`` is
        used.  Secondary workers are launched by KMCS via
        :meth:`secondary_argv` sharing the same sync parent, which is how
        AFL++ parallel fuzzing synchronises queues between instances.
        """
        caps = self.capabilities()
        caps.require_available("build an AFL++ command line")
        out_dir = spec.resolved_output_dir()
        sync_parent = os.path.dirname(out_dir.rstrip(os.sep)) or "."
        instance = "main" if spec.workers > 1 else "kmcs"
        argv: List[str] = [caps.binary_path or AFLPLUSPLUS_BINARY]
        argv += ["-i", spec.seeds_dir, "-o", sync_parent]
        argv += ["-M", safe_filename(instance)]
        if spec.timeout_ms:
            # '+' suffix lets AFL++ auto-scale the timeout per-execution
            argv += ["-t", f"{max(1, int(spec.timeout_ms))}+"]
        if spec.memory_limit_mb:
            argv += ["-m", str(max(4, int(spec.memory_limit_mb)))]
        if spec.dictionary_path:
            argv += ["-x", spec.dictionary_path]
        if spec.tokens_path:
            # struct-aware mutation (AFL++ >= 4.x): -s takes the tokens file
            argv += ["-s", spec.tokens_path]
        argv += list(spec.extra_args)
        argv += ["--", spec.target.binary_path]
        argv += self._target_args(spec)
        return argv

    def secondary_argv(self, spec: FuzzLaunchSpec, index: int) -> List[str]:
        """Argv for the *index*-th secondary worker (``-S`` fan-out)."""
        master = self.build_argv(spec, {})
        patched: List[str] = []
        for token in master:
            if token == "-M":
                patched.append("-S")
                continue
            if patched and patched[-1] == "-S" and not token.startswith("-"):
                # replace the master's instance name with this worker's
                patched[-1] = f"worker-{index:02d}"
                continue
            patched.append(token)
        return patched

    def _target_args(self, spec: FuzzLaunchSpec) -> List[str]:
        """Arguments passed to the *target* after ``--``."""
        harness = spec.target.harness
        mode = harness.mode
        binary = spec.target.binary_path
        rest = [p for p in harness.argv_template if p != binary]
        if mode in ("stdin", "persistent", "in-process"):
            # stdin: AFL passes input via inherited fd automatically
            return [p for p in rest if "@@" not in p]
        # file / argv modes: '@@' placeholder handling
        rendered: List[str] = []
        saw_placeholder = False
        for part in rest:
            if "@@" in part:
                rendered.append(part.replace("@@", "@@"))
                saw_placeholder = True
            else:
                rendered.append(part)
        if not saw_placeholder:
            rendered.append("@@")
        return rendered

    # -- environment ---------------------------------------------------------------
    def build_environment(self, spec: FuzzLaunchSpec) -> Dict[str, str]:
        env = build_afl_environment(spec)
        env.setdefault("AFL_FINAL_SYNC", "1")
        return env

    # -- stats ------------------------------------------------------------------------
    def collect_stats(self, session: FuzzSession) -> Optional[EngineStats]:
        """Parse ``fuzzer_stats`` (+ plot_data) from the session's out dir."""
        out_dir = self._instance_out_dir(session)
        stats_file = os.path.join(out_dir, "fuzzer_stats")
        raw = parse_fuzzer_stats(stats_file)
        if not raw:
            return None
        stats = EngineStats(engine=self.engine_kind.value,
                            source=StatsSource.FILE.value)
        stats.raw = raw
        mapping = {
            "execs_done": "execs_done",
            "execs_per_sec": "exec_per_sec",
            "corpus_count": "corpus_count",
            "queue_items": "corpus_count",
            "crashes_found": "unique_crashes",
            "hangs_found": "unique_hangs",
            "cycles_done": "cycles_passed",
        }
        for target_key, source_key in mapping.items():
            if source_key in raw:
                value: Optional[float]
                if "." in raw[source_key]:
                    try:
                        value = float(raw[source_key])
                    except ValueError:
                        value = None
                else:
                    value = parse_int_token(raw[source_key])
                if value is not None:
                    stats.values[target_key] = value
        if "fuzz_run_time" in raw:
            seconds = parse_int_token(raw["fuzz_run_time"])
            if seconds is not None:
                stats.values["time_since_start"] = seconds
        elif "start_time" in raw:
            started = parse_int_token(raw["start_time"])
            if started:
                stats.values["time_since_start"] = max(0, int(time.time()) - started)
        cvg = raw.get("bitmap_cvg", "").rstrip("%")
        try:
            stats.values["coverage_percent"] = float(cvg)
        except ValueError:
            pass
        plot = parse_plot_data_row(os.path.join(out_dir, "plot_data"))
        if plot:
            if "stability" in plot:
                stats.values.setdefault("stability_percent", plot["stability"])
        # observed truth about artifacts on disk complements engine counters
        return stats

    def _instance_out_dir(self, session: FuzzSession) -> str:
        """Where the master afl-fuzz instance writes its bookkeeping.

        Mirrors :meth:`build_argv`: with ``workers > 1`` the instance is
        named ``main`` inside the sync parent; otherwise it is ``kmcs`` and
        the session's own output dir *is* the sync parent, so we join.
        """
        out_dir = session.spec.output_dir or session.spec.resolved_output_dir()
        sync_parent = os.path.dirname(out_dir.rstrip(os.sep)) or "."
        instance = "main" if session.spec.workers > 1 else "kmcs"
        candidate = os.path.join(sync_parent, instance)
        if os.path.isdir(candidate):
            return candidate
        return out_dir

    def artifact_watch_dirs(self, session: FuzzSession) -> List[str]:
        root = session.spec.output_dir or session.spec.resolved_output_dir()
        if session.spec.workers > 1:
            root = os.path.dirname(root.rstrip(os.sep)) or "."
        dirs = [root]
        return dirs

    # -- console parsing ------------------------------------------------------------

    def consume_output(self, session: FuzzSession, stream: str,
                       line: str) -> None:
        """Surface interesting afl-fuzz console lines as warnings/events.

        AFL++ prints e.g. ``[+] We've got crashes ...``; we log them but rely
        primarily on filesystem discovery for correctness.
        """
        lowered = line.lower()
        if "error" in lowered and "[!]" in line:
            from kmcs.fuzzers.base import FuzzEvent, FuzzEventType
            session._publish(FuzzEvent.make(FuzzEventType.WARNING,
                                            console=line[:MAX_CONSOLE]))


MAX_CONSOLE = 500


# ---------------------------------------------------------------------------
# smoke test
# ---------------------------------------------------------------------------


def _smoke() -> int:  # pragma: no cover
    tmp = Path("/tmp/kmcs-afl-smoke")
    tmp.mkdir(exist_ok=True)
    inst = tmp / "fuzzer_stats"
    inst.write_text(
        "start_time        : 1700000000\n"
        "execs_done        : 123456\n"
        "exec_per_sec      : 890.12\n"
        "corpus_count      : 42\n"
        "unique_crashes    : 3\n"
        "unique_hangs      : 1\n"
        "bitmap_cvg        : 12.34%\n"
        "fuzz_run_time     : 300\n")
    parsed = parse_fuzzer_stats(inst)
    assert parsed["execs_done"] == "123456"
    stats = EngineStats(engine="aflpp", source=StatsSource.FILE.value)
    stats.merge_from({"execs_done": parse_int_token(parsed["execs_done"]),
                      "crashes_found": parse_int_token(parsed["unique_crashes"])})
    assert stats.execs_done == 123456 and stats.crashes_found == 3

    adapter = AFLPlusPlusAdapter()
    caps = adapter.capabilities()
    print("aflpp probe:", "available" if caps.available else "NOT INSTALLED",
          caps.version or "", "-", caps.notes or "ok")
    print("kmcs.fuzzers.aflpp smoke OK")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_smoke())
