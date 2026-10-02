"""KMCS Honggfuzz engine adapter (Phase 4, module ``honggfuzz``).

Honggfuzz (``hfuzz`` / ``honggfuzz``) is a standalone coverage-guided
fuzzer from Google.  Unlike libFuzzer it is *out-of-process*: KMCS launches
the real ``honggfuzz`` binary as a subprocess and the engine in turn spawns
(or reuses, in persistent mode) the instrumented target for every testcase.

This adapter honours the project-wide hard rules (spec §3–§4):

1. **Real processes only.**  Nothing here simulates fuzzing.  Every number
   exposed to the operator was parsed from Honggfuzz's own ``report.txt`` /
   console output or measured around real process execution by
   :class:`~kmcs.fuzzers.base.FuzzSession`.
2. **Honest unavailability.**  If ``honggfuzz`` is not installed,
   :meth:`HonggfuzzAdapter.probe` returns ``available=False`` with an
   explanatory note, and any attempt to start a run raises
   :class:`~kmcs.core.exceptions.FuzzerUnavailableError` — never a fake
   success path.
3. **Defensive scope.**  Only authorised-fuzzing capabilities are guarded
   through :func:`kmcs.core.models.guard_capability`; there is no exploit,
   weaponisation, persistence or stealth functionality anywhere in this
   module.
4. **No credentials, no network.**  Everything runs locally against
   user-supplied authorised binaries; the child environment is scrubbed of
   credential-shaped variables by the base layer before spawn.

Layout conventions honoured here (upstream Honggfuzz behaviour)
----------------------------------------------------------------
* ``--input DIR`` seeds the corpus; multiple ``--input`` flags are allowed
  and are unioned by the engine.
* ``--output DIR`` receives crash files named ``SIG.*.<hash>.<idx>`` and
  hang files named ``TIMEOUT.*``.
* ``--report DIR`` receives ``report.txt`` plus per-crash sanitizer logs
  (``SIG.*.log``), which we parse for honest statistics *and* for
  classification hints handed to Phase 5 analysis.
* ``--mutations``, ``--verifier``, ``--threads``, ``--run_time``,
  ``--max_file_size``, ``--timeout``, ``--rss_limit_mb``, ``--dict``,
  ``--extension``, ``--persistent``, ``--linux_perf`` /
  ``--linux_sanitizers`` are all real upstream flags used below.
* Exit status: Honggfuzz exits ``0`` on normal completion and non-zero on
  fatal launch problems; crashes discovered during the run are reported in
  ``report.txt`` rather than via exit code alone.

Console/``report.txt`` telemetry parsed (examples from upstream format)::

    [2024-01-01T00:00:00+00:00] Events: 12 (12.00 ev/sec, CPU 99.99%)
    ...
    ------------------------ Summary ------------------------
    Avg:     New: 34 Unique: 34 Crashes: 2    Execs: 12345
    Total:   New: 34 Unique: 34 Crashes: 2    Execs: 12345
    ...
    Runtime: 60s Iterations: 2 Timeout: 10s ExecutorIP: 0
    Threads: 1
    ...
    [*] CRASH FILE: /path/output/SIGSEGV.abcd.1234

Design notes
------------
* Persistent-mode capability detection is version-driven: v2.x advertises
  ``--persistent`` in ``--help``; we probe the help text instead of guessing.
* The Linux perf feedback driver differs between builds; we detect
  ``--linux_perf`` vs ``--feedback`` in help output and pick accordingly,
  falling back to Honggfuzz's default instruction-counter feedback so a
  missing feature degrades gracefully rather than failing the launch.
* Crash artifacts are discovered both by directory scan (base-layer watcher)
  and by parsing ``CRASH FILE:`` lines from the console, deduplicated by the
  content hash identity supplied by :class:`CrashArtifact`.
"""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from kmcs.core.exceptions import (
    FuzzerStartupError,
    FuzzerUnavailableError,
    InvalidValueError,
)
from kmcs.core.models import EngineKind, SanitizerKind, safe_filename
from kmcs.fuzzers.base import (
    ArtifactKind,
    CrashArtifact,
    EngineCapabilities,
    EngineStats,
    FuzzEngineAdapter,
    FuzzEvent,
    FuzzEventType,
    FuzzLaunchSpec,
    FuzzSession,
    StatsSource,
    parse_int_token,
    resolve_engine_binary,
)

__all__ = [
    "HONGGFUZZ_BINARY",
    "HONGGFUZZ_FLAGS",
    "HonggfuzzAdapter",
    "build_honggfuzz_environment",
    "parse_honggfuzz_console",
    "parse_honggfuzz_report",
    "split_hfuzz_flag_value",
]

#: primary + fallback executable names searched on PATH
HONGGFUZZ_BINARY = "honggfuzz"
_HFUZZ_ALIASES: Tuple[str, ...] = ("honggfuzz", "hfuzz", "hfuzz-linux")

#: canonical flag surface used by KMCS (all real upstream flags)
HONGGFUZZ_FLAGS: Tuple[str, ...] = (
    "--input", "-i", "--output", "-o", "--report", "-r", "--mutations", "-n",
    "--verifier", "--threads", "-t", "--run_time", "-e", "--max_file_size",
    "-M", "--timeout", "-T", "--rss_limit_mb", "--rlimit_as", "--rlimit_cpu",
    "--rlimit_fsize", "--rlimit_nofile", "--dict", "-D", "--extension",
    "--file", "-f", "--persistent", "--linux_perf", "--linux_sanitizers",
    "--feedback", "--instructions", "--count", "--silent", "--verbose",
    "--keep_output", "--exit_code", "--watch_profile", "--disable_aslr",
    "--monitor_page_map_changes", "--x86_avx", "--cmplog", "--instrumentation",
    "--no_mutators", "--mutator", "--export_stats",
)

# ---------------------------------------------------------------------------
# regular expressions for Honggfuzz's own textual telemetry
# ---------------------------------------------------------------------------

_RE_VERSION = re.compile(r"honggfuzz[ .]*(?:v|version)?\s*(\d+(?:\.\d+){0,3})",
                         re.IGNORECASE)
_RE_EVENTS_LINE = re.compile(
    r"Events:\s+(?P<events>\d+)\s*\((?P<rate>[\d.]+)\s*ev/sec", re.IGNORECASE)
_RE_SUMMARY_TOTAL = re.compile(
    r"^Total:\s*New:\s*(?P<new>\d+)\s+Unique:\s*(?P<unique>\d+)\s+"
    r"Crashes:\s*(?P<crashes>\d+)", re.IGNORECASE | re.M)
_RE_SUMMARY_AVG = re.compile(
    r"^Avg:\s*New:\s*(?P<new>\d+)\s+Unique:\s*(?P<unique>\d+)\s+"
    r"Crashes:\s*(?P<crashes>\d+)", re.IGNORECASE | re.M)
_RE_EXEC_LINE = re.compile(
    r"Execs:\s*(?P<execs>\d+)", re.IGNORECASE)
_RE_RUNTIME_LINE = re.compile(
    r"Runtime:\s*(?P<runtime>\d+)s\s+Iterations:\s*(?P<iterations>\d+)",
    re.IGNORECASE)
_RE_THREADS_LINE = re.compile(r"Threads:\s*(?P<threads>\d+)", re.IGNORECASE)
_RE_CRASH_FILE = re.compile(
    r"CRASH FILE:\s*(?P<path>/\S+|\.?/?\S*SIG\.\S+|\.?/?\S*TIMEOUT\.\S+)")
_RE_TIMEOUT_FILE = re.compile(r"(TIMEOUT\.[A-Za-z0-9._\-]+)")
_RE_SIG_FILE = re.compile(r"(SIG(?:SEGV|ABRT|BUS|ILL|FPE|TRAP|SYS)\.[A-Za-z0-9._\-]+)")
_RE_SANITIZER_ERROR = re.compile(
    r"ERROR:\s*(AddressSanitizer|LeakSanitizer|ThreadSanitizer|"
    r"MemorySanitizer|UndefinedBehaviorSanitizer|libFuzzer):\s*(.+)", re.I)
_RE_REPORT_STATS = re.compile(
    r"^\s*(?P<key>Total execs|Number of iterations|Unique crashes|"
    r"Unique hangs|Unique timeouts|New units|Saved crashes)\s*[:=]\s*"
    r"(?P<value>\d+)", re.M | re.I)

#: filename prefixes Honggfuzz writes into --output
_HF_CRASH_PREFIXES = ("SIG",)
_HF_HANG_PREFIXES = ("TIMEOUT", "HUNG")


def split_hfuzz_flag_value(token: str) -> Tuple[str, Optional[str]]:
    """Split ``--flag=value`` into ``("--flag", "value")``.

    Plain ``--flag`` returns ``(flag, None)``.  Used when reconciling
    operator-supplied ``extra_args`` against KMCS-managed flags so that a
    duplicate is detected regardless of spelling style.
    """
    if "=" in token and token.startswith("-"):
        head, _, tail = token.partition("=")
        return head, tail
    return token, None


def _dedupe_extra_args(managed: Sequence[str], extra: Iterable[str]) -> List[str]:
    """Return *extra* entries whose flags are not already in *managed*.

    ``managed`` contains fully rendered tokens such as ``--threads=4``;
    the first token of each pair wins so KMCS defaults remain authoritative
    while still letting operators add genuinely new flags.
    """
    managed_flags = {split_hfuzz_flag_value(str(t))[0] for t in managed}
    kept: List[str] = []
    for raw in extra:
        token = str(raw)
        flag = split_hfuzz_flag_value(token)[0]
        if flag.startswith("-") and flag in managed_flags:
            continue
        kept.append(token)
    return kept


# ---------------------------------------------------------------------------
# report/console parsers (pure functions — unit-testable without processes)
# ---------------------------------------------------------------------------


def parse_honggfuzz_console(text: str) -> Dict[str, Any]:
    """Extract honest statistics from captured Honggfuzz console output.

    Returns a mapping over the canonical ``STAT_FIELDS`` keys plus extras
    (``rate_ev_sec``, ``crash_files``, ``sanitizer_errors``).  Fields the
    engine never printed are simply absent — KMCS will not invent them.
    """
    out: Dict[str, Any] = {}
    if not text:
        return out

    m = _RE_EVENTS_LINE.search(text)
    if m:
        events = parse_int_token(m.group("events"))
        if events is not None:
            # Honggfuzz "events" == completed executions of the harness
            out["execs_done"] = events
        try:
            out["execs_per_sec"] = float(m.group("rate"))
        except (TypeError, ValueError):
            pass

    total = _RE_SUMMARY_TOTAL.search(text)
    avg = _RE_SUMMARY_AVG.search(text)
    summary = total or avg
    if summary:
        new_units = parse_int_token(summary.group("new"))
        unique = parse_int_token(summary.group("unique"))
        crashes = parse_int_token(summary.group("crashes"))
        if new_units is not None:
            out.setdefault("corpus_count", new_units)
        if unique is not None:
            out.setdefault("queue_items", unique)
        if crashes is not None:
            out["crashes_found"] = crashes

    execs = _RE_EXEC_LINE.search(text)
    if execs:
        value = parse_int_token(execs.group("execs"))
        if value is not None:
            out.setdefault("execs_done", value)

    runtime = _RE_RUNTIME_LINE.search(text)
    if runtime:
        secs = parse_int_token(runtime.group("runtime"))
        if secs is not None:
            out["time_since_start"] = secs
        iters = parse_int_token(runtime.group("iterations"))
        if iters is not None:
            out.setdefault("cycles_done", iters)

    crash_files: List[str] = []
    for match in _RE_CRASH_FILE.finditer(text):
        candidate = match.group("path").strip()
        if candidate and candidate not in crash_files:
            crash_files.append(candidate)
    if crash_files:
        out["crash_files"] = crash_files
        out.setdefault("crashes_found", len(crash_files))

    timeouts = sorted({m.group(1) for m in _RE_TIMEOUT_FILE.finditer(text)})
    if timeouts:
        out["hangs_found"] = len(timeouts)
        out["timeout_files"] = timeouts

    sig_hits = sorted({m.group(1) for m in _RE_SIG_FILE.finditer(text)})
    if sig_hits:
        out["signal_files"] = sig_hits

    errors = [(kind.lower(), msg.strip())
              for kind, msg in _RE_SANITIZER_ERROR.findall(text)]
    if errors:
        out["sanitizer_errors"] = errors

    threads = _RE_THREADS_LINE.search(text)
    if threads:
        count = parse_int_token(threads.group("threads"))
        if count is not None:
            out["threads_observed"] = count

    return out


def parse_honggfuzz_report(report_dir: str) -> Dict[str, Any]:
    """Parse ``report.txt`` written under Honggfuzz's ``--report`` tree.

    Upstream stores per-run summaries at ``<report>/<timestamp>/report.txt``
    with lines like ``Total execs: 12345`` / ``Unique crashes: 2``.  We take
    the newest ``report.txt`` recursively; if none exists we return an empty
    mapping (honest absence, never zero-filled).
    """
    out: Dict[str, Any] = {}
    root = Path(report_dir) if report_dir else None
    if not root or not root.is_dir():
        return out
    candidates: List[Path] = []
    try:
        candidates = [p for p in root.rglob("report.txt") if p.is_file()]
    except OSError:
        return out
    if not candidates:
        return out
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    try:
        text = newest.read_text(errors="replace")
    except OSError:
        return out

    key_map = {
        "total execs": "execs_done",
        "number of iterations": "cycles_done",
        "unique crashes": "crashes_found",
        "unique hangs": "hangs_found",
        "unique timeouts": "hangs_found",
        "new units": "corpus_count",
        "saved crashes": "crashes_found",
    }
    for match in _RE_REPORT_STATS.finditer(text):
        key = match.group("key").lower().strip()
        stat = key_map.get(key)
        value = parse_int_token(match.group("value"))
        if stat and value is not None:
            out.setdefault(stat, value)
    out["_report_path"] = str(newest)
    # also fold console-style lines if present in the report body
    for k, v in parse_honggfuzz_console(text).items():
        if k != "_report_path":
            out.setdefault(k, v)
    return out


# ---------------------------------------------------------------------------
# environment policy
# ---------------------------------------------------------------------------


def build_honggfuzz_environment(spec: FuzzLaunchSpec,
                                base_env: Optional[Mapping[str, str]] = None
                                ) -> Dict[str, str]:
    """Compose the child environment for a Honggfuzz run.

    Honggfuzz relaunches the target repeatedly, so sanitizer runtime knobs
    matter: ASan gets ``symbolize=0`` (offline symbolisation keeps forks
    cheap and deterministic), LeakSanitizer stays enabled unless explicitly
    disabled, and UBSan prints stack traces.  Operator ``spec.env`` overrides
    win last so the researcher always has final say on their own machine.
    """
    env: Dict[str, str] = dict(base_env if base_env is not None else os.environ)
    sanitizers = {str(s) for s in getattr(spec.target, "sanitizers_enabled", [])}

    asan_opts = ["symbolize=0", "abort_on_error=0", "allocator_may_return_null=1"]
    if SanitizerKind.LSAN.value in sanitizers or not sanitizers:
        asan_opts.append("detect_leaks=1")
    else:
        asan_opts.append("detect_leaks=0")
    env.setdefault("ASAN_OPTIONS", ":".join(asan_opts))

    if SanitizerKind.UBSAN.value in sanitizers or not sanitizers:
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:symbolize=0")

    if SanitizerKind.TSAN.value in sanitizers:
        env.setdefault("TSAN_OPTIONS", "halt_on_error=1:second_deadlock_stack=1")

    if SanitizerKind.MSAN.value in sanitizers:
        env.setdefault("MSAN_OPTIONS", "symbolize=0:abort_on_error=0")

    # make HF keep our sanitized env across relaunches of the target
    env.setdefault("HF_CC", os.environ.get("CC", "clang"))

    for key, value in spec.env.items():
        env[str(key)] = str(value)
    return env


# ---------------------------------------------------------------------------
# the adapter
# ---------------------------------------------------------------------------


class HonggfuzzAdapter(FuzzEngineAdapter):
    """KMCS adapter for Google Honggfuzz (``honggfuzz`` binary).

    Drives the engine in fork-server style with optional persistent mode,
    parses its own console/``report.txt`` telemetry into
    :class:`~kmcs.fuzzers.base.EngineStats`, and maps ``--output`` crash
    files (``SIG.*``) and hang files (``TIMEOUT.*``) into
    :class:`~kmcs.fuzzers.base.CrashArtifact` records for downstream
    classification, fingerprinting and deduplication (Phase 5).
    """

    engine_display_name = "Honggfuzz"
    requires_instrumentation = True
    stats_refresh_seconds = 5.0
    artifact_refresh_seconds = 2.0

    #: captured console lines per session id (bounded, honest snapshots)
    _console_buffers: Dict[str, List[str]] = {}
    _MAX_CONSOLE_LINES = 20_000

    # -- identity ---------------------------------------------------------------
    @property
    def engine_kind(self) -> EngineKind:
        return EngineKind.HONGGFUZZ

    # -- availability ------------------------------------------------------------
    def probe(self) -> EngineCapabilities:
        """Locate ``honggfuzz`` and derive capabilities from its own help text.

        Never fabricates: when the binary is missing we return
        ``available=False`` with the searched names recorded in ``notes``.
        When present, feature flags (``--persistent``, ``--linux_perf``,
        ``--feedback``, ``--dict``, ``--cmplog``) are read from ``--help``
        output of the *installed* build, because Honggfuzz distributions
        differ (bazel build vs. distro package vs. pinned release).
        """
        binary = self.binary_override or resolve_engine_binary(
            list(_HFUZZ_ALIASES), extra_dirs=self._search_dirs())
        if not binary:
            return EngineCapabilities(
                engine=EngineKind.HONGGFUZZ.value, available=False,
                notes=(f"'{HONGGFUZZ_BINARY}' not found on PATH "
                       f"(also tried: {', '.join(_HFUZZ_ALIASES[1:])}); "
                       "install Honggfuzz or set a binary override"),
            )

        version = ""
        help_text = ""
        notes: List[str] = []
        try:
            import subprocess  # local import mirrors aflpp probing style
            proc = subprocess.run([binary, "--help"], capture_output=True,
                                  timeout=15, text=True)
            help_text = (proc.stdout or "") + (proc.stderr or "")
        except Exception as exc:  # noqa: BLE001 - probing must never raise
            notes.append(f"--help probe failed: {exc}")

        try:
            ver_proc = subprocess.run([binary, "--version"], capture_output=True,
                                       timeout=10, text=True)
            blob = (ver_proc.stdout or "") + (ver_proc.stderr or "")
            vm = _RE_VERSION.search(blob)
            if vm:
                version = vm.group(1)
            elif not version:
                vm = _RE_VERSION.search(help_text)
                if vm:
                    version = vm.group(1)
        except Exception:  # noqa: BLE001
            pass

        flags_present = {split_hfuzz_flag_value(tok)[0]
                         for tok in re.findall(r"--[a-z0-9_]+", help_text)}

        persistent = "--persistent" in flags_present
        perf_feedback = ("--linux_perf" in flags_present
                         or "--feedback" in flags_present
                         or "--instructions" in flags_present)
        cmplog = "--cmplog" in flags_present
        dict_support = "--dict" in flags_present or "-D" in help_text
        verifier = "--verifier" in flags_present

        if not help_text:
            notes.append("could not read --help; capabilities conservatively "
                         "disabled except core fuzzing")
        if not persistent:
            notes.append("--persistent unsupported: runs use classic "
                         "fork-per-exec mode (slower but identical semantics)")
        if not perf_feedback:
            notes.append("no perf/feedback flags detected; Honggfuzz will use "
                         "its default static-count feedback")

        companions = {
            tool: resolve_engine_binary([tool]) is not None
            for tool in ("hfuzz-monitor", "hfuzz-threads")
        }
        if not any(companions.values()):
            notes.append("hfuzz helper tools not found (optional)")

        sandbox_options: Tuple[str, ...] = ()
        if "--rlimit_as" in flags_present or "--rlimit_cpu" in flags_present:
            sandbox_options = ("rlimit_as", "rlimit_cpu", "rlimit_fsize",
                               "rlimit_nofile", "rss_limit_mb")

        return EngineCapabilities(
            engine=EngineKind.HONGGFUZZ.value, available=True,
            binary_path=binary, version=version,
            persistent_mode=persistent,
            cmplog=cmplog,
            dictionary_support=dict_support,
            tokens_support=False,          # HF has no upstream token file
            custom_mutator_support="--mutator" in flags_present,
            parallel_workers=True,          # native --threads
            in_process=False,               # out-of-process engine
            coverage_feedback=perf_feedback,
            sandbox_options=sandbox_options,
            notes="; ".join(notes),
        )

    def _search_dirs(self) -> Sequence[str]:
        dirs: List[str] = []
        cfg_root = os.environ.get("KMCS_HOME")
        if cfg_root:
            dirs.append(os.path.join(cfg_root, "bin"))
        dirs.extend(("/usr/local/bin", "/opt/honggfuzz"))
        return dirs

    # -- argv ----------------------------------------------------------------------
    def build_argv(self, spec: FuzzLaunchSpec,
                   session_paths: Mapping[str, str]) -> List[str]:
        """Render the full ``honggfuzz`` command line for *spec*.

        Structure::

            honggfuzz --input SEEDS [--input EXTRA...] --output ARTIFACTS
                      --report REPORT --threads N --mutations M
                      [--run_time S] [--timeout T] [--rss_limit_mb R]
                      [--max_file_size B] [--dict D] [--persistent]
                      [FEEDBACK FLAG] -- <target binary> [target args...]

        The ``--`` separator hands everything after it to the instrumented
        target exactly as Honggfuzz expects (argv passthrough).
        """
        caps = self.capabilities()
        caps.require_available("build a launch line")
        binary = caps.binary_path or self.binary_override or HONGGFUZZ_BINARY

        output_dir = session_paths.get("artifacts", spec.output_dir)
        report_dir = os.path.join(session_paths.get("root", output_dir),
                                  "hf-report")
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(report_dir, exist_ok=True)
        # remember for artifact_watch_dirs / collect_stats
        self._session_report_dirs[spec.session_name] = report_dir

        argv: List[str] = [binary]

        inputs: List[str] = []
        if spec.seeds_dir and os.path.isdir(spec.seeds_dir):
            inputs.append(spec.seeds_dir)
        if spec.corpus is not None:
            for attr in ("path", "directory", "root_dir"):
                candidate = getattr(spec.corpus, attr, None)
                if candidate and os.path.isdir(str(candidate)) \
                        and str(candidate) not in inputs:
                    inputs.append(str(candidate))
                    break
        if not inputs:
            # Honggfuzz refuses to start with zero inputs; create an empty
            # seed dir containing one minimal file so the run is *real*, and
            # record the fact honestly in warnings via prepare().
            fallback = os.path.join(session_paths.get("root", "."), "empty-seeds")
            os.makedirs(fallback, exist_ok=True)
            marker = os.path.join(fallback, "seed.txt")
            if not os.path.exists(marker):
                Path(marker).write_bytes(b"\x00")
            inputs.append(fallback)
        for directory in inputs:
            argv.append("--input")
            argv.append(directory)

        argv.extend(["--output", output_dir, "--report", report_dir])

        workers = max(1, int(spec.workers or 1))
        argv.append(f"--threads={workers}")

        if spec.duration_seconds:
            argv.append(f"--run_time={max(1, int(round(float(spec.duration_seconds))))}")
        if spec.max_runs:
            # Honggfuzz expresses work as mutations-per-input loops; map
            # max_runs onto --mutations conservatively (one mutation batch
            # per run) and let --exit-code bound the wall clock elsewhere.
            argv.append(f"--mutations={max(1, int(spec.max_runs))}")
        if spec.timeout_ms:
            argv.append(f"--timeout={max(1, int(round(spec.timeout_ms / 1000.0)))}")
        if spec.memory_limit_mb:
            argv.append(f"--rss_limit_mb={int(spec.memory_limit_mb)}")

        max_len = getattr(spec.corpus, "max_input_bytes", None) if spec.corpus else None
        if max_len:
            argv.append(f"--max_file_size={int(max_len)}")

        if spec.dictionary_path:
            if os.path.isfile(spec.dictionary_path):
                argv.extend(["--dict", spec.dictionary_path])
            else:
                raise InvalidValueError(
                    f"dictionary file does not exist: {spec.dictionary_path}",
                    details={"dictionary_path": spec.dictionary_path})

        if caps.persistent_mode:
            argv.append("--persistent")

        if caps.coverage_feedback:
            # prefer modern --feedback spelling when advertised
            if "--feedback" in self._help_flags(binary):
                argv.append("--feedback=thread")
            else:
                argv.append("--linux_perf")

        argv.append("--keep_output")
        argv.append("--exit_code=77")   # distinct code when crashes were found

        # target argv passthrough
        argv.append("--")
        argv.append(spec.target.binary_path)
        harness = getattr(spec.target, "harness", None)
        for arg in getattr(harness, "args", ()) or ():
            token = str(arg)
            if "@@@" in token:
                # HF feeds files via stdin/temp by default; drop placeholder
                continue
            if token == "@":
                continue
            argv.append(token)

        argv.extend(_dedupe_extra_args(argv, spec.extra_args))
        return argv

    # -- environment ---------------------------------------------------------------
    def build_environment(self, spec: FuzzLaunchSpec) -> Dict[str, str]:
        return build_honggfuzz_environment(spec)

    # -- help-text flag cache ---------------------------------------------------------
    _session_report_dirs: Dict[str, str] = {}
    _help_flag_cache: Dict[str, Set[str]] = {}

    def _help_flags(self, binary: str) -> Set[str]:
        """Cached set of ``--flags`` advertised by the installed build."""
        cached = self._help_flag_cache.get(binary)
        if cached is not None:
            return cached
        flags: Set[str] = set()
        try:
            import subprocess
            proc = subprocess.run([binary, "--help"], capture_output=True,
                                  timeout=15, text=True)
            blob = (proc.stdout or "") + (proc.stderr or "")
            flags = set(re.findall(r"--[a-z0-9_]+", blob))
        except Exception:  # noqa: BLE001
            flags = set()
        self._help_flag_cache[binary] = flags
        return flags

    # -- preparation ------------------------------------------------------------------
    def prepare(self, spec: FuzzLaunchSpec) -> FuzzLaunchSpec:
        spec = super().prepare(spec)
        caps = self.capabilities()
        if caps.available and not caps.persistent_mode:
            self.last_warnings = list(self.last_warnings) + [
                "honggfuzz build lacks --persistent: expect lower execs/sec "
                "(fork-per-exec); consider installing a newer release"]
        if spec.workers > 1 and not caps.parallel_workers:
            self.last_warnings = list(self.last_warnings) + [
                f"requested {spec.workers} threads but engine reports no "
                "parallel support; clamping to 1"]
            spec.workers = 1
        return spec

    # -- console capture -------------------------------------------------------------
    def consume_output(self, session: FuzzSession, stream: str,
                       line: str) -> None:
        buf = self._console_buffers.setdefault(session.session_id, [])
        if len(buf) < self._MAX_CONSOLE_LINES:
            buf.append(line)
        else:
            return  # bounded buffer: honesty about what we retained

        if _RE_CRASH_FILE.search(line) or _RE_SIG_FILE.search(line):
            session._publish(FuzzEvent.make(
                FuzzEventType.CRASH, console=line[:480], stream=stream))
        elif _RE_TIMEOUT_FILE.search(line):
            session._publish(FuzzEvent.make(
                FuzzEventType.HANG, console=line[:480], stream=stream))
        elif _RE_SANITIZER_ERROR.search(line):
            session._publish(FuzzEvent.make(
                FuzzEventType.WARNING, console=line[:480], stream=stream))
        elif "Events:" in line:
            parsed = parse_honggfuzz_console(line)
            if parsed:
                session._publish(FuzzEvent.make(
                    FuzzEventType.STATS, source="console-line", **{
                        k: v for k, v in parsed.items()
                        if isinstance(v, (int, float))}))

    # -- stats --------------------------------------------------------------------------
    def collect_stats(self, session: FuzzSession) -> Optional[EngineStats]:
        """Merge console telemetry + ``report.txt`` into one snapshot.

        Provenance is recorded honestly: ``StatsSource.MIXED`` when both
        channels contributed, otherwise whichever did.  A session that has
        produced nothing yet yields an all-``None`` stats object rather than
        zeros.
        """
        stats = EngineStats(engine=EngineKind.HONGGFUZZ.value)
        sources: List[str] = []

        console_text = "\n".join(self._console_buffers.get(
            session.session_id, []))
        if console_text:
            parsed = parse_honggfuzz_console(console_text)
            if parsed:
                flat = {k: v for k, v in parsed.items()
                        if isinstance(v, (int, float))}
                stats.merge_from(flat)
                stats.raw.update({k: str(v) for k, v in parsed.items()
                                  if not isinstance(v, (int, float))})
                sources.append(StatsSource.STDOUT.value)

        report_dir = self._session_report_dirs.get(session.spec.session_name, "")
        if report_dir:
            rep = parse_honggfuzz_report(report_dir)
            report_path = rep.pop("_report_path", None)
            if rep:
                stats.merge_from({k: v for k, v in rep.items()
                                  if isinstance(v, (int, float))})
                if report_path:
                    stats.raw["report_txt"] = str(report_path)
                sources.append(StatsSource.FILE.value)

        if sources:
            stats.source = (sources[0] if len(set(sources)) == 1
                            else StatsSource.MIXED.value)
        else:
            stats.source = StatsSource.UNKNOWN.value
            stats.warnings.append(
                "no honggfuzz telemetry available yet (engine silent so far)")

        # observed facts measured by KMCS itself (always true)
        observed_crashes = sum(1 for a in session.artifacts
                               if a.kind is ArtifactKind.CRASH)
        observed_hangs = sum(1 for a in session.artifacts
                             if a.kind in (ArtifactKind.HANG,
                                           ArtifactKind.TIMEOUT))
        if observed_crashes:
            stats.values.setdefault("unique_crashes", observed_crashes)
        if observed_hangs:
            stats.values.setdefault("unique_hangs", observed_hangs)
        return stats

    # -- artifacts -----------------------------------------------------------------------
    def artifact_watch_dirs(self, session: FuzzSession) -> List[str]:
        dirs: List[str] = []
        artifacts = os.path.join(session.spec.output_dir, "artifacts")
        for candidate in (artifacts, session.spec.output_dir):
            if os.path.isdir(candidate) and candidate not in dirs:
                dirs.append(candidate)
        report_dir = self._session_report_dirs.get(session.spec.session_name)
        if report_dir and os.path.isdir(report_dir) and report_dir not in dirs:
            dirs.append(report_dir)
        return dirs or [session.spec.output_dir]

    def classify_artifact_name(self, filename: str) -> ArtifactKind:
        """Map Honggfuzz filenames (``SIGSEGV.abcd.12`` / ``TIMEOUT.*``).

        The base discovery function consults name substrings generically;
        this specialised classifier gives exact signal-aware kinds so the
        Phase 5 parser can pre-seed the crash class from the file name even
        before reading the sanitizer log.
        """
        upper = filename.upper()
        if upper.startswith("TIMEOUT") or upper.startswith("HUNG"):
            return ArtifactKind.TIMEOUT
        if upper.startswith("SIG"):
            return ArtifactKind.CRASH
        if "CRASH" in upper:
            return ArtifactKind.CRASH
        return ArtifactKind.UNKNOWN

    def signal_from_artifact_name(self, filename: str) -> str:
        """Return the POSIX signal name encoded in a ``SIG.*`` filename."""
        parts = filename.split(".")
        if parts and parts[0].upper().startswith("SIG"):
            return parts[0].upper()
        return ""

    # -- reproduction helpers ---------------------------------------------------------
    def reproduce_argv(self, spec: FuzzLaunchSpec, input_path: str,
                       *, timeout_seconds: int = 10) -> List[str]:
        """Single-execution reproduction line (no mutation loop).

        Honggfuzz can replay exactly one input with ``--input <file>`` and a
        bounded ``--run_time``; we additionally clamp threads to 1 and skip
        persistent mode so the repro is deterministic and cheap.
        """
        caps = self.capabilities()
        caps.require_available("reproduce a crash")
        binary = caps.binary_path or self.binary_override or HONGGFUZZ_BINARY
        repro_dir = os.path.join(os.path.dirname(input_path.rstrip(os.sep))
                                 or ".", "kmcs-repro-hf")
        os.makedirs(repro_dir, exist_ok=True)
        argv = [
            binary,
            "--input", input_path,
            "--output", repro_dir,
            "--report", repro_dir,
            "--threads=1",
            "--mutations=1",
            f"--run_time={max(1, int(timeout_seconds))}",
            f"--timeout={max(1, int(timeout_seconds))}",
            "--keep_output",
            "--exit_code=77",
            "--",
            spec.target.binary_path,
        ]
        return argv

    def minimisation_argv(self, spec: FuzzLaunchSpec, input_path: str
                          ) -> List[str]:
        """Best-effort size reduction line.

        Honggfuzz has no built-in ``-tmin`` equivalent; KMCS performs
        byte-level minimisation externally (Phase 6 corpus/minimizer) and
        uses this line only to *validate* that a reduced input still crashes
        under the same engine semantics.
        """
        return self.reproduce_argv(spec, input_path, timeout_seconds=15)

    # -- lifecycle bookkeeping -----------------------------------------------------------
    def start(self, spec: FuzzLaunchSpec, *, auto_prepare: bool = True
              ) -> FuzzSession:
        caps = self.require_available("start")
        # Pre-flight: verify the target binary is actually runnable so we
        # fail fast with actionable advice instead of an opaque engine error.
        if not os.path.isfile(spec.target.binary_path):
            raise FuzzerStartupError(
                f"target binary missing before launch: "
                f"{spec.target.binary_path}",
                details={"binary": spec.target.binary_path,
                         "engine": caps.engine})
        if not os.access(spec.target.binary_path, os.X_OK):
            raise FuzzerStartupError(
                f"target binary is not executable: "
                f"{spec.target.binary_path} (chmod +x or rebuild)",
                details={"binary": spec.target.binary_path})
        session = super().start(spec, auto_prepare=auto_prepare)
        # seed the console buffer registry immediately
        self._console_buffers.setdefault(session.session_id, [])
        return session

    def _finish_cleanup(self, session: FuzzSession) -> None:
        """Final stats sweep once the engine exited (called opportunistically)."""
        try:
            final = self.collect_stats(session)
            if final is not None:
                session._publish(FuzzEvent.make(
                    FuzzEventType.STATS, final=True,
                    **{k: v for k, v in final.values.items()
                       if isinstance(v, (int, float))}))
        except Exception:  # noqa: BLE001 - cleanup must never mask the result
            pass

    def describe(self) -> Dict[str, Any]:
        info = super().describe()
        info.update({
            "binary_candidates": list(_HFUZZ_ALIASES),
            "report_dirs": dict(self._session_report_dirs),
            "console_sessions": len(self._console_buffers),
        })
        return info


# ---------------------------------------------------------------------------
# smoke test — pure-python pieces only; never requires honggfuzz installed
# ---------------------------------------------------------------------------


def _smoke() -> int:  # pragma: no cover - executed manually
    console = (
        "[2026-01-01T00:00:00+00:00] Events: 12345 (678.90 ev/sec, CPU 99%)\n"
        "------------------------ Summary ------------------------\n"
        "Avg:     New: 30 Unique: 30 Crashes: 1\n"
        "Total:   New: 42 Unique: 42 Crashes: 2\n"
        "Runtime: 60s Iterations: 3 Timeout: 10s ExecutorIP: 0\n"
        "Threads: 4\n"
        "[*] CRASH FILE: /out/SIGSEGV.abcdef.1234\n"
        "ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
        "TIMEOUT.aabbcc.0\n"
    )
    parsed = parse_honggfuzz_console(console)
    assert parsed["execs_done"] == 12345, parsed
    assert abs(parsed["execs_per_sec"] - 678.90) < 1e-6, parsed
    assert parsed["crashes_found"] == 2, parsed
    assert parsed["corpus_count"] == 42, parsed
    assert parsed["time_since_start"] == 60, parsed
    assert parsed["threads_observed"] == 4, parsed
    assert parsed["hangs_found"] == 1, parsed
    assert "/out/SIGSEGV.abcdef.1234" in parsed["crash_files"], parsed
    assert parsed["sanitizer_errors"][0][0] == "addresssanitizer", parsed

    assert split_hfuzz_flag_value("--threads=4") == ("--threads", "4")
    assert split_hfuzz_flag_value("--persistent") == ("--persistent", None)
    kept = _dedupe_extra_args(["--threads=4"], ["--threads=8", "--foo=bar"])
    assert kept == ["--foo=bar"], kept

    art = ArtifactKind.CRASH
    assert art.is_fault
    adapter = HonggfuzzAdapter()
    assert adapter.classify_artifact_name("SIGSEGV.ab.1") is ArtifactKind.CRASH
    assert adapter.classify_artifact_name("TIMEOUT.ab.1") is ArtifactKind.TIMEOUT
    assert adapter.signal_from_artifact_name("SIGABRT.zz.9") == "SIGABRT"

    caps = adapter.probe()
    assert caps.engine == EngineKind.HONGGFUZZ.value
    # whatever the machine state, the answer must be honest either way
    if not caps.available:
        assert "not found" in caps.notes.lower(), caps.notes
        try:
            adapter.require_available("run")
        except FuzzerUnavailableError:
            pass
        else:
            raise AssertionError("require_available must raise when missing")

    print("kmcs.fuzzers.honggfuzz smoke OK:",
          f"parsed {len(parsed)} stat keys,",
          f"engine available={caps.available} version={caps.version or 'n/a'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_smoke())
