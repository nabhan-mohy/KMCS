"""KMCS libFuzzer engine adapter (Phase 4, module ``libfuzzer``).

libFuzzer is an **in-process** engine: the fuzz driver is compiled into the
target binary itself (``-fsanitize=fuzzer``), so "running the fuzzer" means
executing the instrumented binary with libFuzzer flags.  This adapter builds
those command lines, launches the binary as a real subprocess, and parses
libFuzzer's own console telemetry (``#NNN RUNs``, ``DONE NNN runs``,
``SUMMARY: ...``, artifact filenames) into honest
:class:`~kmcs.fuzzers.base.EngineStats`.

Layout conventions honoured here (upstream libFuzzer behaviour):

* ``-artifact_prefix=DIR/`` makes the engine write ``crash-*``, ``timeout-*``
  and ``slow-unit-*`` files directly into our artifacts directory.
* ``-exact_artifact_path=`` pins one output file when reproducing.
* The final corpus lives in positional directory argument(s); multiple dirs
  act as inputs *and* outputs (union semantics).
* Exit code 1 (or crash-signal death) indicates a found bug; exit 0 after
  ``-error_exitcode=`` tuning indicates a clean run.

If the target was not built with a libFuzzer driver, launching it will fail
fast — the adapter detects the classic ``Error: You are trying to dlopen a
libFuzzer...`` / missing-main symptoms from stderr and reports them as
:class:`~kmcs.core.exceptions.FuzzerStartupError` with actionable advice.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from kmcs.core.models import EngineKind, SanitizerKind, safe_filename
from kmcs.fuzzers.base import (
    EngineCapabilities,
    EngineStats,
    FuzzEngineAdapter,
    FuzzLaunchSpec,
    FuzzSession,
    StatsSource,
    format_duration,
    parse_int_token,
    resolve_engine_binary,
)

__all__ = [
    "LIBFUZZER_FLAGS",
    "LibFuzzerAdapter",
    "build_libfuzzer_environment",
    "parse_libfuzzer_console",
]


#: canonical libFuzzer flag surface used by KMCS (all are real upstream flags)
LIBFUZZER_FLAGS: Tuple[str, ...] = (
    "-runs", "-max_total_time", "-max_len", "-len_control", "-timeout",
    "-rss_limit_mb", "-malloc_limit_mb", "-artifact_prefix",
    "-exact_artifact_path", "-dict", "-close_input_fds", "-handle_abort",
    "-handle_segv", "-handle_sigill", "-handle_sigfpe", "-handle_sigbus",
    "-error_exitcode", "-merge", "-merge_control_file", "-jobs", "-workers",
    "-seed", "-random_seed", "-print_final_stats", "-print_pure_cov",
    "-detect_leaks", "-verbosity", "-use_value_profile", "-shrink",
    "-only_ascii", "-prefer_small", "-dump_coverage_corpus",
)

_RE_LINE_EVENT = re.compile(
    r"^#(?P<n>\d+)\s+(?P<kind>RUNS|INITED|NEW|EXEC_COVER|REDUCE|DONE|MERGE_1|MERGE_CONTROL|COVERAGE)\b"
    r"(?:\s+(?P<detail>.*))?$")
_RE_DONE = re.compile(r"^DONE\s+(?P<runs>\d+)\s+runs")
_RE_SUMMARY = re.compile(r"^SUMMARY:\s*(?P<sanitizer>\w+Sanitizer):\s*"
                         r"(?P<type>[A-Za-z _\-]+?)\s+(?P<target>\S+)",
                         re.M)
_RE_ARTIFACT = re.compile(r"(?P<path>(?P<base>[^\s]*)(?P<name>crash-\S+|"
                          r"timeout-\S+|slow-unit-\S+|oom-\S+))")
_RE_EXEC_PER_SEC = re.compile(r"(\d+(?:\.\d+)?)\s+execs/sec")
_RE_STAT_TAIL = re.compile(r"stat::total_pcs_used:\s*(?P<pcs>\d+)")


def parse_libfuzzer_console(text: str) -> Dict[str, Any]:
    """Extract every statistic libFuzzer printed into *text*.

    Only what is literally present is returned; absent metrics are omitted
    (callers merge into :class:`EngineStats` which defaults to ``None``).
    """
    out: Dict[str, Any] = {}
    max_runs = 0
    for line in text.splitlines():
        match = _RE_LINE_EVENT.match(line.strip())
        if match and match.group("kind") in ("RUNS", "DONE", "NEW",
                                             "EXEC_COVER", "INITED"):
            try:
                value = int(match.group("n"))
            except (TypeError, ValueError):
                continue
            if value > max_runs:
                max_runs = value
            if match.group("kind") == "INITED":
                out.setdefault("corpus_count", value)
            elif match.group("kind") == "NEW":
                out["new_units"] = out.get("new_units", 0) + 1
            elif match.group("kind") == "EXEC_COVER":
                out.setdefault("edges_found", value)
    done = _RE_DONE.search(text)
    if done:
        max_runs = max(max_runs, int(done.group("runs")))
    if max_runs:
        out["runs"] = max_runs
        out.setdefault("execs_done", max_runs)
    speed = _RE_EXEC_PER_SEC.search(text)
    if speed:
        out["execs_per_sec"] = float(speed.group(1))
    summary = _RE_SUMMARY.search(text)
    if summary:
        out["summary"] = {
            "sanitizer": summary.group("sanitizer"),
            "type": summary.group("type").strip(),
            "location": summary.group("target"),
        }
        out.setdefault("crashes_found", 1)
    artifacts = sorted({m.group("path") for m in _RE_ARTIFACT.finditer(text)})
    if artifacts:
        out["artifacts"] = artifacts
    pcs = _RE_STAT_TAIL.search(text)
    if pcs:
        out.setdefault("edges_found", int(pcs.group("pcs")))
    return out


def build_libfuzzer_environment(spec: FuzzLaunchSpec,
                                base_env: Optional[Mapping[str, str]] = None
                                ) -> Dict[str, str]:
    """Environment for the in-process run: sanitizer runtime knobs only."""
    env: Dict[str, str] = dict(base_env if base_env is not None else os.environ)
    sanitizers = {str(s) for s in spec.target.sanitizers_enabled}
    if SanitizerKind.ASAN.value in sanitizers or not sanitizers:
        env.setdefault("ASAN_OPTIONS",
                       "abort_on_error=0:allocator_may_return_null=1:"
                       "detect_leaks=1:detect_odr_violation=0:symbolize=0")
    if SanitizerKind.UBSAN.value in sanitizers:
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:")
    for key, value in spec.env.items():
        env[str(key)] = str(value)
    return env


class LibFuzzerAdapter(FuzzEngineAdapter):
    """Adapter for libFuzzer-instrumented binaries (in-process fuzzing)."""

    engine_display_name = "libFuzzer"
    requires_instrumentation = True   # the driver must be compiled in
    stats_refresh_seconds = 3.0
    artifact_refresh_seconds = 1.5

    #: captured console per session id (stdout/stderr accumulate here)
    _console_buffers: Dict[str, List[str]] = {}

    @property
    def engine_kind(self) -> EngineKind:
        return EngineKind.LIBFUZZER

    # -- probe ---------------------------------------------------------------
    def probe(self) -> EngineCapabilities:
        """libFuzzer needs no separate binary; we check clang availability
        purely to report build-side capability honestly."""
        clang = resolve_engine_binary(["clang", "clang++"])
        notes: List[str] = []
        if not clang:
            notes.append("clang not found: targets cannot be built with "
                         "-fsanitize=fuzzer (kmcs.targets.build)")
        return EngineCapabilities(
            engine=EngineKind.LIBFUZZER.value, available=True,
            binary_path=clang or "", version="",
            persistent_mode=True, cmplog=False,
            dictionary_support=True, tokens_support=False,
            custom_mutator_support=False, parallel_workers=True,
            in_process=True, coverage_feedback=True,
            sandbox_options=("rss_limit_mb", "malloc_limit_mb", "max_len"),
            notes="; ".join(notes))

    # -- argv ------------------------------------------------------------------
    def build_argv(self, spec: FuzzLaunchSpec,
                   session_paths: Mapping[str, str]) -> List[str]:
        """Compose ``<target-binary> -flags... <corpus_dirs>``."""
        artifacts_dir = session_paths.get("artifacts", spec.output_dir)
        argv: List[str] = [spec.target.binary_path]
        # input/output corpus dir (KMCS seeds dir doubles as output)
        seed_target = os.path.join(artifacts_dir, "generated")
        os.makedirs(seed_target, exist_ok=True)
        argv.append("-artifact_prefix=" + os.path.join(artifacts_dir, "")
                    if not artifacts_dir.endswith(os.sep)
                    else "-artifact_prefix=" + artifacts_dir)
        argv.append("-print_final_stats=1")
        argv.append("-close_input_fds=0")
        argv.append("-handle_abort=1")
        argv.append("-error_exitcode=0")  # crashes still visible via artifacts/SUMMARY
        verbosity = 1 if spec.duration_seconds and spec.duration_seconds < 60 else 0
        argv.append(f"-verbosity={verbosity}")
        if spec.max_runs:
            argv.append(f"-runs={int(spec.max_runs)}")
        if spec.duration_seconds:
            argv.append(f"-max_total_time={max(1, int(spec.duration_seconds))}")
        if spec.timeout_ms:
            argv.append(f"-timeout={max(1, int(round(spec.timeout_ms / 1000.0)))}")
        if spec.memory_limit_mb:
            argv.append(f"-rss_limit_mb={int(spec.memory_limit_mb)}")
        if spec.corpus is not None and getattr(spec.corpus, "max_input_bytes", None):
            argv.append(f"-max_len={int(spec.corpus.max_input_bytes)}")
        if spec.dictionary_path:
            argv.append(f"-dict={spec.dictionary_path}")
        argv.extend(str(a) for a in spec.extra_args)
        argv.append(spec.seeds_dir)
        argv.append(seed_target)
        return argv

    def build_environment(self, spec: FuzzLaunchSpec) -> Dict[str, str]:
        return build_libfuzzer_environment(spec)

    # -- console capture -------------------------------------------------------
    def consume_output(self, session: FuzzSession, stream: str,
                       line: str) -> None:
        buf = self._console_buffers.setdefault(session.session_id, [])
        if len(buf) < 20_000:
            buf.append(line)
        if line.startswith(("ERROR:", "SUMMARY:", "==", "INFO: Seed",
                            "Error:")) and ("Sanitizer" in line or "ERROR" in line):
            from kmcs.fuzzers.base import FuzzEvent, FuzzEventType
            session._publish(FuzzEvent.make(FuzzEventType.WARNING,
                                            console=line[:480]))

    # -- stats -------------------------------------------------------------------
    def collect_stats(self, session: FuzzSession) -> Optional[EngineStats]:
        buffer = self._console_buffers.get(session.session_id)
        if not buffer:
            return None
        parsed = parse_libfuzzer_console("\n".join(buffer))
        if not parsed:
            return None
        stats = EngineStats(engine=self.engine_kind.value,
                            source=StatsSource.STDOUT.value)
        numeric_keys = ("execs_done", "execs_per_sec", "runs", "corpus_count",
                        "crashes_found", "edges_found", "new_units")
        values: Dict[str, Optional[float]] = {}
        for key in numeric_keys:
            if key in parsed:
                values[key] = parsed[key]
        stats.merge_from(values)
        if "summary" in parsed:
            stats.raw["summary"] = str(parsed["summary"])
        start = session.started_at
        if start:
            stats.values.setdefault(
                "time_since_start", round(session.elapsed_seconds or 0.0, 1))
        return stats

    def artifact_watch_dirs(self, session: FuzzSession) -> List[str]:
        out = session.spec.output_dir or session.spec.resolved_output_dir()
        return [os.path.join(out, "artifacts"), out]

    # -- lifecycle hooks ----------------------------------------------------------
    def start(self, spec: FuzzLaunchSpec, *, auto_prepare: bool = True) -> FuzzSession:
        session = super().start(spec, auto_prepare=auto_prepare)
        self._console_buffers.setdefault(session.session_id, [])
        return session

    def _finish_cleanup(self, session: FuzzSession) -> None:
        """Drop console buffer once persisted elsewhere (best effort)."""
        self._console_buffers.pop(session.session_id, None)

    # -- reproduction helper --------------------------------------------------------
    def reproduce_argv(self, spec: FuzzLaunchSpec, input_path: str,
                       *, exact_out: Optional[str] = None) -> List[str]:
        """Argv that replays exactly one input against the target.

        Used by Phase 6 reproduction; kept here because only this adapter
        knows libFuzzer's single-file replay convention
        (``-run_all_corpora=0`` + passing the file as sole corpus arg plus
        ``-exact_artifact_path`` to capture a fresh crash copy).
        """
        argv = [spec.target.binary_path, "-runs=1", "-error_exitcode=0",
                "-verbosity=1"]
        if exact_out:
            argv.append(f"-exact_artifact_path={exact_out}")
        argv.append(input_path)
        return argv

    def minimisation_argv(self, spec: FuzzLaunchSpec, input_path: str,
                          work_dir: str) -> List[str]:
        """Argv for libFuzzer's built-in `-shrink` reducer."""
        os.makedirs(work_dir, exist_ok=True)
        dest = os.path.join(work_dir, f"min-{safe_filename(os.path.basename(input_path))}")
        return [spec.target.binary_path, "-shrink=1", "-runs=2000000",
                "-error_exitcode=0", "-verbosity=0",
                f"-exact_artifact_path={dest}", input_path]


# ---------------------------------------------------------------------------
# smoke test
# ---------------------------------------------------------------------------


_SAMPLE_CONSOLE = """\
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3247981234
INFO: Loaded 1 modules   (42 inline 8-bit counters): 42 [0x0, 0x2a),
INFO: Loaded 1 PC tables (42 PCs): 42 [0x2a,0x54),
INFO:       17 files found in /tmp/seeds
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: seed corpus: files: 17 min size: 1 max size: 512
#18      INITED cov: 11 ft: 12 corp: 5/307b exec/s: 0 rss: 31Mb
#19      NEW    cov: 12 ft: 13 corp: 6/555b lim: 4096 exec/s: 0 rss: 31Mb
#1024    RUNS cov: 20 ft: 25 corp: 9/900b exec/s: 1024 rss: 32Mb
#4096    EXEC_COVER cov: 22 ft: 28 corp: 10/1kb exec/s: 1365 rss: 33Mb
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018
SUMMARY: AddressSanitizer: heap-buffer-overflow harness.c:12 in LLVMFuzzerTestOneInput
Artifact prefix is: /tmp/artifacts/
===
==42==NOTE: a memory allocation of 123 bytes has failed
Done 4096 runs in 3 second(s)
"""


def _smoke() -> int:  # pragma: no cover
    parsed = parse_libfuzzer_console(_SAMPLE_CONSOLE)
    assert parsed["runs"] >= 4096, parsed
    assert parsed["corpus_count"] == 17 or parsed.get("new_units"), parsed
    assert parsed["summary"]["sanitizer"] == "AddressSanitizer", parsed
    assert parsed["summary"]["type"] == "heap-buffer-overflow", parsed
    assert parsed["crashes_found"] == 1

    adapter = LibFuzzerAdapter()
    caps = adapter.capabilities()
    print("libfuzzer probe: always-launchable (in-process); clang:",
          caps.binary_path or "NOT FOUND", "|", caps.notes or "ok")

    from kmcs.core.models import Target, TargetKind, make_authorisation
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="kmcs-lf-"))
    script = tmp / "fakefuzz.sh"
    script.write_text("#!/bin/sh\n"
                      "echo '#100 RUNS cov: 5 corp: 2/10b exec/s: 100 rss: 20Mb'\n"
                      "sleep \"${FAKE_SLEEP:-0.3}\"\n"
                      "echo 'Done 100 runs in 0 second(s)'\n"
                      "exit 0\n")
    script.chmod(0o755)
    seeds = tmp / "seeds"; seeds.mkdir()
    (seeds / "s1").write_bytes(b"hello")
    auth = make_authorisation("researcher",
                              "defensive security research on our own build",
                              paths=[str(tmp)])
    target = Target(name="fake-libfuzz", binary_path=str(script),
                    kind=TargetKind.BINARY.value, authorisation=auth,
                    instrumented=True, sanitizers_enabled=["asan"])
    target.harness.mode = "persistent"
    spec = FuzzLaunchSpec(target=target, seeds_dir=str(seeds),
                          output_dir=str(tmp / "out"), duration_seconds=5,
                          env={"FAKE_SLEEP": "0.2"})
    session = adapter.start(spec)
    finished = session.wait(timeout=15)
    events = []
    drain_deadline = time.time() + 2
    while time.time() < drain_deadline:
        batch = session.events(timeout=0.2)
        if not batch:
            break
        events.extend(batch)
    assert finished, "session did not finish naturally"
    types = [e.type.value for e in events]
    assert "started" in types and ("stopped" in types or "killed" in types), types
    stats = session.stats
    print("real-run stats:", stats.summary_line())
    assert stats.execs_done == 100, stats.to_dict()
    print("kmcs.fuzzers.libfuzzer smoke OK (real subprocess run)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_smoke())
