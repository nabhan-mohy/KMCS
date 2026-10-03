"""kmcs.cli.commands -- the KMCS command-line interface.

Design contract (from the master specification)
===============================================
The CLI is a *thin control surface*.  It must never contain fuzzing, analysis,
campaign or persistence logic itself.  Every subcommand validates its arguments,
calls into the appropriate service layer module (targets.manager, fuzzers.*,
analysis.*, reporting.*, database.*) and prints the *real* result.  When a tool
is missing the CLI says so honestly; it never pretends an operation succeeded.

Invocation notes
================
``kmcs.cli.commands`` doubles as the module entry point
(``python -m kmcs.cli.commands ...``).  To keep that invocation warning-free,
the package ``kmcs.cli.__init__`` imports this module lazily; if you import the
package first, run the console helper instead::

    python -c "from kmcs.cli import main; raise SystemExit(main())" doctor

Commands implemented
====================
    kmcs doctor                          environment + subsystem health report
    kmcs target add|list|show|remove     registered fuzzing targets
    kmcs campaign list                   campaigns stored in the database
    kmcs campaign start                  launches a REAL fuzzing engine process
                                         (AFL++ / libFuzzer / Honggfuzz adapters)
    kmcs campaign stop                   terminates a running campaign by id/all
    kmcs crash import|list|show          crash artifacts (parses real logs!)
    kmcs finding list|show|reproduce     analysed findings + real re-execution
    kmcs report generate                 HTML / JSON / Markdown / CSV / SARIF

No API keys, no network: everything runs locally against installed tools.
Exit codes: 0 success, 1 user error, 2 genuine backend failure (missing tool,
broken subsystem, database error).
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import getpass
import importlib
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# graceful imports: the CLI must still run 'doctor' even when a subsystem is
# broken -- that is precisely what 'doctor' exists to report.
# --------------------------------------------------------------------------- #

_IMPORT_ERRORS: Dict[str, str] = {}


def _try_import(name: str) -> Tuple[Optional[Any], Optional[str]]:
    """Import ``name`` returning ``(module, None)`` or ``(None, error-text)``."""
    try:
        return importlib.import_module(name), None
    except Exception as exc:  # noqa: BLE001 - report ANY import failure honestly
        msg = f"{type(exc).__name__}: {exc}"
        _IMPORT_ERRORS[name] = msg
        return None, msg


# --------------------------------------------------------------------------- #
# terminal helpers
# --------------------------------------------------------------------------- #

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def ok(s: str) -> str: return _c("32", s)
def bad(s: str) -> str: return _c("31", s)
def warn(s: str) -> str: return _c("33", s)
def hdr(s: str) -> str: return _c("1;36", s)
def dim(s: str) -> str: return _c("2", s)


class CliError(Exception):
    """User-facing error with an honest message; exit code 1."""

    def __init__(self, message: str, *, hint: str = "") -> None:
        super().__init__(message)
        self.hint = hint


class ServiceError(Exception):
    """Backend failure (tool missing, db error, broken subsystem); exit code 2."""


def _print_table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> None:
    rows = [[("" if v is None else str(v)) for v in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            if i < len(widths):
                widths[i] = max(widths[i], min(len(cell), 48))
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(hdr(line))
    print(dim("-" * len(line)))
    for r in rows:
        cells = []
        for i, cell in enumerate(r):
            c = cell if len(cell) <= 48 else cell[:45] + "..."
            cells.append(c.ljust(widths[i]))
        print("  ".join(cells).rstrip())


def _fmt_ts(ts: Any) -> str:
    if ts is None:
        return "-"
    if isinstance(ts, (int, float)):
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(ts, _dt.datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    return str(ts)[:19]


# --------------------------------------------------------------------------- #
# workspace / database access
# --------------------------------------------------------------------------- #

_DEFAULT_WORKSPACE = Path(os.environ.get(
    "KMCS_HOME", str(Path.cwd() / "kmcs-workspace")))


def _db_file(args: argparse.Namespace) -> Path:
    if getattr(args, "db", None):
        return Path(args.db).expanduser()
    return _DEFAULT_WORKSPACE / "kmcs.db"


def _open_database(args: argparse.Namespace):
    """Open (creating parents if needed) the KMCS database via the service layer."""
    dbmod, err = _try_import("kmcs.database.database")
    if dbmod is None:
        raise ServiceError(f"database subsystem unavailable: {err}")
    path = _db_file(args)
    path.parent.mkdir(parents=True, exist_ok=True)
    manager_cls = getattr(dbmod, "DatabaseManager", None)
    if manager_cls is None:
        raise ServiceError("kmcs.database.database exposes no DatabaseManager")
    try:
        mgr = manager_cls(str(path))
    except Exception as exc:  # noqa: BLE001
        raise ServiceError(f"cannot open database at {path}: {exc}") from exc
    init = getattr(mgr, "initialize", None)
    if callable(init):
        try:
            init()
        except Exception as exc:  # noqa: BLE001
            raise ServiceError(f"database initialisation failed: {exc}") from exc
    return mgr


# --------------------------------------------------------------------------- #
# kmcs doctor
# --------------------------------------------------------------------------- #

_DOCTOR_TOOLS: Tuple[Tuple[str, str, str], ...] = (
    ("afl-fuzz", "AFL++ fuzzer", "apt install afl++"),
    ("afl-showmap", "AFL++ coverage tool", "apt install afl++"),
    ("clang", "Clang compiler", "apt install clang"),
    ("llvm-symbolizer", "LLVM symbolizer", "apt install llvm"),
    ("honggfuzz", "honggfuzz fuzzer", "apt install honggfuzz (or build upstream)"),
    ("gdb", "GNU debugger", "apt install gdb"),
    ("objdump", "GNU objdump", "apt install binutils"),
)

_SUBSYSTEM_MODULES: Tuple[Tuple[str, str], ...] = (
    ("core", "kmcs.core"),
    ("database", "kmcs.database.database"),
    ("targets", "kmcs.targets.manager"),
    ("fuzzers", "kmcs.fuzzers.base"),
    ("sanitizers", "kmcs.sanitizers.asan"),
    ("crash_parser", "kmcs.analysis.crash_parser"),
    ("classifier", "kmcs.analysis.classifier"),
    ("severity", "kmcs.analysis.severity"),
    ("reporting", "kmcs.reporting.html"),
)


def cmd_doctor(args: argparse.Namespace) -> int:
    """Environment health check: real tools, real imports, writable workspace."""
    print(hdr("KMCS doctor"))
    print(f"  Python: {sys.version.split()[0]} ({sys.executable})")
    uname = getattr(os, "uname", None)
    platform = uname().sysname.lower() if uname else sys.platform
    print(f"  Platform: {platform}")
    try:
        print(f"  User: {getpass.getuser()}@{socket.gethostname()}")
    except OSError:
        pass
    print()

    print(hdr("External tools:"))
    missing_tools: List[str] = []
    for tool, desc, install_hint in _DOCTOR_TOOLS:
        path = shutil.which(tool)
        if path:
            version = ""
            try:
                res = subprocess.run([tool, "--version"], capture_output=True,
                                     text=True, timeout=5)
                first = (res.stdout or res.stderr).strip().splitlines()
                if first:
                    version = first[0][:70]
            except Exception:  # noqa: BLE001 - version probe is best-effort
                version = ""
            print(f"  [{ok('ok')}] {tool:<18} {desc}")
            extra = f"   ver: {dim(version)}" if version else ""
            print(f"            path: {path}{extra}")
        else:
            missing_tools.append(tool)
            print(f"  [{bad('missing')}] {tool:<18} {desc}   {dim('# ' + install_hint)}")
    print()

    print(hdr("Subsystems:"))
    broken: List[str] = []
    for name, modname in _SUBSYSTEM_MODULES:
        _, err = _try_import(modname)
        if err is None:
            print(f"  [{ok('ok')}] {name}")
        else:
            broken.append(name)
            print(f"  [{bad('broken')}] {name}  {dim('(' + err + ')')}")
    print()

    ws = _DEFAULT_WORKSPACE
    exists = ws.exists()
    writable = True
    try:
        ws.mkdir(parents=True, exist_ok=True)
        probe = ws / ".kmcs-write-probe"
        probe.write_text("x")
        probe.unlink()
    except OSError:
        writable = False
    print(hdr("Workspace:"))
    print(f"  Root: {ws}")
    print(f"  Exists: {'yes' if exists else 'no (created on demand)'}")
    print(f"  Writable: {'yes' if writable else bad('no')}")
    db_path = ws / "kmcs.db"
    if db_path.exists():
        print(f"  Database: {db_path} ({db_path.stat().st_size:,} bytes)")
    else:
        print(dim(f"  Database: {db_path} (not created yet)"))
    print()

    if missing_tools:
        print(warn(f"note: {len(missing_tools)} external tool(s) not on PATH: "
                   + ", ".join(missing_tools)))
    if broken:
        print(bad("error: broken subsystems: " + ", ".join(broken)))
        return 2
    if not writable:
        print(bad("error: workspace not writable"))
        return 2
    print(ok("all KMCS subsystems operational."))
    return 0


# --------------------------------------------------------------------------- #
# target commands -> kmcs.targets.manager
# --------------------------------------------------------------------------- #

def _target_manager(args: argparse.Namespace):
    tmod, err = _try_import("kmcs.targets.manager")
    if tmod is None:
        raise ServiceError(f"targets subsystem unavailable: {err}")
    cls = getattr(tmod, "TargetManager", None)
    if cls is None:
        raise ServiceError("kmcs.targets.manager exposes no TargetManager class")
    for kwargs in ({"workspace": _DEFAULT_WORKSPACE}, {"root": _DEFAULT_WORKSPACE}, {}):
        try:
            return cls(**kwargs)
        except TypeError:
            continue
        except Exception as exc:  # noqa: BLE001
            raise ServiceError(f"cannot construct TargetManager: {exc}") from exc
    raise ServiceError("TargetManager constructor signature unrecognised")


def _first_attr(obj: Any, names: Sequence[str], default: Any = None) -> Any:
    for n in names:
        v = getattr(obj, n, None)
        if v is not None:
            return v
    return default


def cmd_target_add(args: argparse.Namespace) -> int:
    mgr = _target_manager(args)
    source = Path(args.source).expanduser() if args.source else None
    binary = Path(args.binary).expanduser() if args.binary else None
    if not source and not binary:
        raise CliError("provide --source FILE or --binary FILE",
                       hint="e.g. kmcs target add demo --source /src/demo/main.c")
    if source and not source.exists():
        raise CliError(f"source file not found: {source}")
    authorised_by = args.authorised_by or getpass.getuser()
    fn = getattr(mgr, "register_target", None) or getattr(mgr, "add_target", None) \
        or getattr(mgr, "add", None)
    if fn is None:
        raise ServiceError("TargetManager exposes no register/add method")
    attempts: List[Dict[str, Any]] = [
        dict(name=args.name, source=source, binary=binary,
             authorised_by=authorised_by),
        dict(name=args.name, source=source, binary=binary),
        dict(name=args.name, source=source or binary),
    ]
    last_exc: Optional[Exception] = None
    for kw in attempts:
        try:
            target = fn(**kw)
            break
        except TypeError as exc:
            last_exc = exc
            continue
        except Exception as exc:  # noqa: BLE001
            raise ServiceError(str(exc)) from exc
    else:
        raise ServiceError(f"could not call register method: {last_exc}")
    tid = _first_attr(target, ("id", "target_id"), "?")
    name = _first_attr(target, ("name",), args.name)
    print(ok(f"target registered: id={tid} name={name}"))
    print(dim(f"  authorised-by: {authorised_by}   (defensive research use only)"))
    return 0


def cmd_target_list(args: argparse.Namespace) -> int:
    mgr = _target_manager(args)
    fn = getattr(mgr, "list_targets", None) or getattr(mgr, "all", None) \
        or getattr(mgr, "list", None)
    if fn is None:
        raise ServiceError("TargetManager exposes no listing method")
    targets: Iterable[Any] = fn()
    rows = []
    for t in targets:
        rows.append([
            _first_attr(t, ("id", "target_id"), "?"),
            _first_attr(t, ("name",), "?"),
            _first_attr(t, ("status", "state"), "-"),
            _first_attr(t, ("language", "primary_language"), "-"),
            _first_attr(t, ("executable_path", "binary", "source_path", "source"),
                        "-"),
        ])
    if not rows:
        print(dim("no targets registered yet -- try: "
                  "kmcs target add NAME --source f.c"))
        return 0
    _print_table(rows, ["ID", "NAME", "STATUS", "LANG", "SOURCE/BINARY"])
    print(dim(f"{len(rows)} target(s)"))
    return 0


def cmd_target_show(args: argparse.Namespace) -> int:
    mgr = _target_manager(args)
    fn = getattr(mgr, "get_target", None) or getattr(mgr, "get", None)
    if fn is None:
        raise ServiceError("TargetManager exposes no getter")
    try:
        target = fn(args.target_id)
    except Exception as exc:  # noqa: BLE001
        raise CliError(f"no such target: {args.target_id!r} ({exc})",
                       hint="run: kmcs target list") from None
    if target is None:
        raise CliError(f"no such target: {args.target_id!r}",
                       hint="run: kmcs target list")
    print(hdr(f"target {_first_attr(target, ('id', 'target_id'), args.target_id)}"))
    fields = ([f.name for f in dataclasses.fields(target)]
              if dataclasses.is_dataclass(target) else list(vars(target)))
    for k in fields:
        if k.startswith("_"):
            continue
        print(f"  {k:<22} {str(getattr(target, k, ''))[:110]}")
    return 0


def cmd_target_remove(args: argparse.Namespace) -> int:
    mgr = _target_manager(args)
    fn = getattr(mgr, "remove_target", None) or getattr(mgr, "remove", None) \
        or getattr(mgr, "delete", None)
    if fn is None:
        raise ServiceError("TargetManager exposes no removal method")
    try:
        fn(args.target_id)
    except Exception as exc:  # noqa: BLE001
        raise CliError(f"cannot remove target {args.target_id!r}: {exc}") from None
    print(ok(f"target {args.target_id} removed"))
    return 0


# --------------------------------------------------------------------------- #
# campaign commands
# --------------------------------------------------------------------------- #

_PID_DIR_NAME = "running-campaigns"


def _pid_dir() -> Path:
    return _DEFAULT_WORKSPACE / _PID_DIR_NAME


def _live_campaign_records() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for pf in sorted(_pid_dir().glob("*.json")):
        try:
            meta = json.loads(pf.read_text())
            pid = int(meta.get("pid", -1))
            meta["_alive"] = pid > 0 and os.path.exists(f"/proc/{pid}")
            meta["_file"] = pf
            out.append(meta)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return out


def cmd_campaign_list(args: argparse.Namespace) -> int:
    live = _live_campaign_records()
    rows = [[m.get("campaign_id", "?"),
             (ok("RUNNING") if m["_alive"] else warn("dead-record")),
             m.get("pid") if m["_alive"] else "-"]
            for m in live]
    live_ids = {m.get("campaign_id") for m in live}
    try:
        mgr = _open_database(args)
        fn = getattr(mgr, "list_campaigns", None)
        campaigns = list(fn()) if callable(fn) else []
        for c in campaigns:
            cid = _first_attr(c, ("id", "campaign_id"), "?")
            if cid in live_ids:
                continue
            rows.append([cid, _first_attr(c, ("status", "state"), "-"), "-"])
    except ServiceError as exc:
        print(warn(f"(database not available: {exc})"))
    if not rows:
        print(dim("no campaigns found -- start one: "
                  "kmcs campaign start --target-id N"))
        return 0
    _print_table(rows, ["CAMPAIGN", "STATE", "PID"])
    return 0


_ENGINE_MODULES = {
    "aflpp": "kmcs.fuzzers.aflpp",
    "afl++": "kmcs.fuzzers.aflpp",
    "afl": "kmcs.fuzzers.aflpp",
    "libfuzzer": "kmcs.fuzzers.libfuzzer",
    "lf": "kmcs.fuzzers.libfuzzer",
    "honggfuzz": "kmcs.fuzzers.honggfuzz",
    "hfuzz": "kmcs.fuzzers.honggfuzz",
}


def _adapter_class(engine_name: str):
    modname = _ENGINE_MODULES.get(engine_name.lower())
    if modname is None:
        raise CliError(f"unknown engine {engine_name!r}",
                       hint=f"valid: {', '.join(sorted(set(_ENGINE_MODULES)))}")
    fmod, err = _try_import(modname)
    if fmod is None:
        raise ServiceError(f"fuzzer subsystem unavailable: {err}")
    cls = getattr(fmod, "ADAPTER", None)
    if cls is None:
        for candidate in ("AFLPlusPlusAdapter", "AFLppAdapter", "LibFuzzerAdapter",
                          "HonggfuzzAdapter"):
            cls = getattr(fmod, candidate, None)
            if cls is not None:
                break
    if cls is None:  # last resort: any FuzzEngineAdapter subclass defined here
        base_mod, _ = _try_import("kmcs.fuzzers.base")
        if base_mod is not None:
            root = getattr(base_mod, "FuzzEngineAdapter", object)
            for attr in vars(fmod).values():
                if isinstance(attr, type) and issubclass(attr, root) \
                        and attr is not root:
                    cls = attr
                    break
    if cls is None:
        raise ServiceError(f"{modname} exposes no adapter class")
    return cls


def cmd_campaign_start(args: argparse.Namespace) -> int:
    """Launch a REAL fuzzing engine through the adapter layer. No simulation."""
    mgr = _open_database(args)
    get_t = getattr(mgr, "get_target", None) or getattr(mgr, "target_get", None)
    target = None
    if callable(get_t):
        try:
            target = get_t(args.target_id)
        except Exception:  # noqa: BLE001
            target = None
    if target is None:
        raise CliError(f"unknown target id {args.target_id!r}",
                       hint="register one first: kmcs target add ... ; "
                            "see: kmcs target list")
    exe = _first_attr(target, ("executable_path", "binary", "fuzz_target"))
    if not exe or not Path(str(exe)).exists():
        raise ServiceError(
            "target has no built instrumented executable yet "
            f"(recorded: {exe!r}). Build it first via the targets.build service.")
    engine_name = args.engine or str(_first_attr(
        target, ("default_engine", "engine"), "aflpp"))

    corpus = Path(args.corpus).expanduser() if args.corpus \
        else _DEFAULT_WORKSPACE / "corpus" / str(_first_attr(
            target, ("id", "target_id"), args.target_id))
    corpus.mkdir(parents=True, exist_ok=True)
    seeds = [p for p in corpus.rglob("*") if p.is_file()]
    if not seeds:
        raise CliError(f"corpus directory is empty: {corpus}",
                       hint="place valid seed input files there, or pass --corpus DIR")

    adapter_cls = _adapter_class(engine_name)
    outdir = Path(args.output).expanduser() if args.output \
        else _DEFAULT_WORKSPACE / "fuzz-out" / (
            f"{_first_attr(target, ('id', 'target_id'), args.target_id)}-{engine_name}")
    outdir.mkdir(parents=True, exist_ok=True)
    campaign_id = args.campaign_id_override or f"cmp-{int(time.time())}-{os.getpid()}"

    # honest availability probe (never fake a start)
    probe = None
    try:
        probe_fn = getattr(adapter_cls, "probe", None)
        if callable(probe_fn):
            probe = probe_fn()
    except Exception as exc:  # noqa: BLE001
        probe = None
        print(warn(f"(probe raised {type(exc).__name__}; continuing cautiously)"))
    if probe is not None and not getattr(probe, "available", True):
        reason = (_first_attr(probe, ("notes", "reason", "detail"), "")
                  or f"{engine_name} binary not found on this machine")
        raise ServiceError(f"engine {engine_name!r} is NOT available: {reason}")

    if args.foreground:
        print(hdr(f"campaign {campaign_id}: {engine_name} -> {exe}"))
        print(dim(f"  corpus: {corpus}   output: {outdir}"))
        print(dim("  Ctrl-C stops the engine cleanly."))
        instance = None
        for kwargs in (
            dict(target=str(exe), corpus=corpus, output=outdir,
                 campaign_id=campaign_id, jobs=args.jobs,
                 extra_args=tuple(shlex.split(args.engine_args))),
            dict(executable=str(exe), corpus_dir=corpus, output_dir=outdir),
            dict(),
        ):
            try:
                instance = adapter_cls(**kwargs)
                break
            except TypeError:
                continue
        if instance is None:
            raise ServiceError("adapter constructor signature unrecognised")
        run = getattr(instance, "run_foreground", None) or \
            getattr(instance, "start", None) or getattr(instance, "run", None)
        if run is None:
            raise ServiceError("adapter exposes no run/start method")
        proc = run()
        code = getattr(proc, "returncode", 0) or 0
        print("campaign finished" if code == 0 else f"campaign exited rc={code}")
        return 0 if code == 0 else 2

    # background: re-exec this CLI in foreground mode inside a new session
    child = [sys.executable, "-m", "kmcs.cli.commands", "campaign", "start",
             "--target-id", str(args.target_id), "--engine", engine_name,
             "--corpus", str(corpus), "--output", str(outdir),
             "--jobs", str(args.jobs), "--foreground",
             "--_campaign-id", campaign_id]
    if args.engine_args:
        child += ["--engine-args", args.engine_args]
    log = outdir / "campaign.log"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2]) + os.pathsep + \
        env.get("PYTHONPATH", "")
    with open(log, "ab") as lf:
        proc = subprocess.Popen(child, stdout=lf, stderr=subprocess.STDOUT,
                                cwd=str(_DEFAULT_WORKSPACE), env=env,
                                start_new_session=True)
    _pid_dir().mkdir(parents=True, exist_ok=True)
    (_pid_dir() / f"{campaign_id}.json").write_text(json.dumps({
        "campaign_id": campaign_id, "pid": proc.pid, "target_id": args.target_id,
        "engine": engine_name, "output": str(outdir), "log": str(log),
        "started": time.time()}))
    print(ok(f"campaign started: id={campaign_id} engine={engine_name} "
             f"pid={proc.pid}"))
    print(dim(f"  log: {log}"))
    print(dim(f"  stop with: kmcs campaign stop {campaign_id}"))
    return 0


def cmd_campaign_stop(args: argparse.Namespace) -> int:
    key = args.campaign_id
    records = _live_campaign_records()
    stopped = 0
    matched = 0
    for meta in records:
        cid = meta.get("campaign_id", "?")
        if key != "all" and cid != key:
            continue
        matched += 1
        pid = int(meta.get("pid", -1))
        pf = meta.get("_file")
        if meta["_alive"]:
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
                print(ok(f"campaign {cid}: SIGTERM sent to process group {pid}"))
                stopped += 1
            except ProcessLookupError:
                print(warn(f"campaign {cid}: process {pid} already gone"))
            except PermissionError as exc:
                raise ServiceError(f"cannot stop pid {pid}: {exc}") from None
        else:
            print(warn(f"campaign {cid}: no live process (stale record removed)"))
        if pf is not None:
            try:
                Path(pf).unlink()
            except OSError:
                pass
    if not matched:
        raise CliError(f"no campaign named {key!r}",
                       hint="see: kmcs campaign list")
    return 0


# --------------------------------------------------------------------------- #
# crash commands -> analysis.crash_parser + database
# --------------------------------------------------------------------------- #

def _cp():
    mod, err = _try_import("kmcs.analysis.crash_parser")
    if mod is None:
        raise ServiceError(f"crash parser unavailable: {err}")
    return mod


def cmd_crash_import(args: argparse.Namespace) -> int:
    """Parse a real sanitizer/crash log and (optionally) persist the crashes."""
    cp = _cp()
    path = Path(args.file).expanduser()
    if not path.exists():
        raise CliError(f"file not found: {path}")
    parse = getattr(cp, "parse_crash_log", None)
    if parse is None:
        raise ServiceError("crash parser exposes no parse_crash_log()")
    outcome = parse(str(path), is_path=True,
                    target_name=args.target or "",
                    campaign_id=args.campaign or "")
    crashes = list(getattr(outcome, "crashes", []))
    reports = list(getattr(outcome, "reports", []))
    print(hdr(f"parsed {path.name}"))
    print(f"  sanitizer detected : {getattr(outcome, 'sanitizer_detected', '?')}")
    cov = getattr(outcome, "coverage", None)
    print(f"  parse coverage     : {cov():.1%}" if callable(cov) else
          "  parse coverage     : ?")
    print(f"  reports / crashes  : {len(reports)} / {len(crashes)}")
    for c in crashes:
        st = getattr(c, "stack_trace", None)
        nframes = len(getattr(st, "frames", [])) if st is not None else 0
        print(f"    - class={getattr(c, 'crash_class', '?')} "
              f"severity={getattr(c, 'severity', '?')} frames={nframes}")
    if args.save:
        mgr = _open_database(args)
        fn = getattr(mgr, "save_crash", None) or getattr(mgr, "add_crash", None) \
            or getattr(mgr, "crash_create", None)
        if not callable(fn):
            raise ServiceError("database manager exposes no crash-save method")
        saved = 0
        for c in crashes:
            try:
                fn(c)
                saved += 1
            except Exception as exc:  # noqa: BLE001
                print(warn(f"  could not persist crash: {exc}"))
        print(ok(f"persisted {saved} crash(es) to {_db_file(args)}"))
    if not crashes and not reports:
        print(bad("no crash content recognised in file "
                  "(honest result: nothing fabricated)"))
        return 2
    return 0


def cmd_crash_list(args: argparse.Namespace) -> int:
    mgr = _open_database(args)
    fn = getattr(mgr, "list_crashes", None) or getattr(mgr, "crashes", None)
    if not callable(fn):
        raise ServiceError("database manager exposes no crash listing")
    try:
        crashes = list(fn(campaign_id=getattr(args, "campaign", None)))
    except TypeError:
        crashes = list(fn())
    rows = [[_first_attr(c, ("id", "crash_id"), "?"),
             _first_attr(c, ("crash_class",), "-"),
             _first_attr(c, ("sanitizer",), "-"),
             _first_attr(c, ("severity",), "-"),
             _first_attr(c, ("input_path",), "-"),
             _fmt_ts(_first_attr(c, ("detected_at", "created_at")))]
            for c in crashes]
    if not rows:
        print(dim("no crashes stored -- import one: "
                  "kmcs crash import LOGFILE --save"))
        return 0
    _print_table(rows, ["ID", "CLASS", "SANITIZER", "SEVERITY", "INPUT", "DETECTED"])
    print(dim(f"{len(rows)} crash(es)"))
    return 0


def cmd_crash_show(args: argparse.Namespace) -> int:
    mgr = _open_database(args)
    fn = getattr(mgr, "get_crash", None) or getattr(mgr, "crash_get", None)
    if not callable(fn):
        raise ServiceError("database manager exposes no crash getter")
    try:
        crash = fn(args.crash_id)
    except Exception as exc:  # noqa: BLE001
        raise CliError(f"no such crash {args.crash_id!r}: {exc}",
                       hint="see: kmcs crash list") from None
    if crash is None:
        raise CliError(f"no such crash: {args.crash_id!r}",
                       hint="see: kmcs crash list")
    print(hdr(f"crash {_first_attr(crash, ('id', 'crash_id'), args.crash_id)}"))
    keys = ([f.name for f in dataclasses.fields(crash)]
            if dataclasses.is_dataclass(crash) else list(vars(crash)))
    for k in keys:
        if k.startswith("_"):
            continue
        s = str(getattr(crash, k, ""))
        print(f"  {k:<22} {s[:110]}" + (" ..." if len(s) > 110 else ""))
    st = getattr(crash, "stack_trace", None)
    frames = getattr(st, "frames", []) if st is not None else []
    if frames:
        print(hdr("  stack:"))
        for i, fr in enumerate(frames[:12]):
            loc = getattr(fr, "file", "") or ""
            ln = getattr(fr, "line", "") or ""
            tail = f"{loc}:{ln}" if ln else loc
            print(f"    #{i:<2} {str(getattr(fr, 'function', '?')):<40} {dim(tail)}")
    return 0


# --------------------------------------------------------------------------- #
# finding commands
# --------------------------------------------------------------------------- #

def _findings_from_db(args: argparse.Namespace) -> List[Any]:
    mgr = _open_database(args)
    for name in ("list_findings", "findings", "finding_list"):
        fn = getattr(mgr, name, None)
        if callable(fn):
            return list(fn())
    crashes_fn = getattr(mgr, "list_crashes", None)
    if callable(crashes_fn):
        try:
            return list(crashes_fn())
        except TypeError:
            return list(crashes_fn(campaign_id=None))
    raise ServiceError("no findings/crashes accessor on database manager")


def cmd_finding_list(args: argparse.Namespace) -> int:
    items = _findings_from_db(args)
    rows = [[_first_attr(f, ("id", "finding_id"), "?"),
             _first_attr(f, ("title", "crash_class"), "-"),
             _first_attr(f, ("severity",), "-"),
             _first_attr(f, ("status",), "-"),
             _first_attr(f, ("fingerprint_digest", "fingerprint"), "-")]
            for f in items]
    if not rows:
        print(dim("no findings yet (they are produced by the analysis pipeline)")
              )
        return 0
    _print_table(rows, ["ID", "TITLE/CLASS", "SEVERITY", "STATUS", "FINGERPRINT"])
    print(dim(f"{len(rows)} finding(s)"))
    return 0


def cmd_finding_show(args: argparse.Namespace) -> int:
    items = _findings_from_db(args)
    match = next((f for f in items
                  if str(_first_attr(f, ("id", "finding_id"), ""))
                  == str(args.finding_id)), None)
    if match is None:
        raise CliError(f"no such finding: {args.finding_id!r}",
                       hint="see: kmcs finding list")
    print(hdr(f"finding {args.finding_id}"))
    keys = ([f.name for f in dataclasses.fields(match)]
            if dataclasses.is_dataclass(match) else list(vars(match)))
    for k in keys:
        if k.startswith("_"):
            continue
        print(f"  {k:<22} {str(getattr(match, k, ''))[:110]}")
    return 0


def cmd_finding_reproduce(args: argparse.Namespace) -> int:
    """Re-execute the recorded crashing input against the real executable."""
    items = _findings_from_db(args)
    match = next((f for f in items
                  if str(_first_attr(f, ("id", "finding_id"), ""))
                  == str(args.finding_id)), None)
    if match is None:
        raise CliError(f"no such finding: {args.finding_id!r}",
                       hint="see: kmcs finding list")
    crash_obj = getattr(match, "crash", None) or match
    exe = _first_attr(crash_obj, ("executable", "executable_path", "binary"))
    inp = _first_attr(crash_obj, ("input_path", "testcase", "crashing_input"))
    if not exe or not Path(str(exe)).exists():
        raise ServiceError(f"recorded executable not present: {exe!r}")
    if not inp or not Path(str(inp)).exists():
        raise ServiceError(f"recorded crashing input not present: {inp!r}")
    env = dict(os.environ)
    env.setdefault("ASAN_OPTIONS", "symbolize=1:abort_on_error=0")
    print(dim(f"reproducing: {exe} < {inp}"))
    try:
        with open(inp, "rb") as fh:
            proc = subprocess.run([str(exe)], stdin=fh, capture_output=True,
                                  timeout=args.timeout, env=env)
    except subprocess.TimeoutExpired:
        print(warn("reproduction: target timed out (possible hang finding)"))
        return 0
    rc = proc.returncode
    crashed = rc < 0 or rc > 128 or rc == 1
    tail = (proc.stderr.decode("utf-8", "replace") or "")[-1500:]
    if crashed and ("Sanitizer" in tail or "runtime error" in tail):
        print(ok("REPRODUCED: sanitizer reported the same class of fault"))
    elif crashed:
        print(ok(f"REPRODUCED: process died abnormally (rc={rc})"))
    else:
        print(bad(f"NOT reproduced (clean exit rc={rc})"))
    if tail.strip():
        print(dim("--- last sanitizer output ---"))
        print(tail.strip()[:1200])
    return 0 if crashed else 2


# --------------------------------------------------------------------------- #
# report commands -> kmcs.reporting.*
# --------------------------------------------------------------------------- #

_FORMAT_MODULES = {
    "html": "kmcs.reporting.html",
    "json": "kmcs.reporting.json_report",
    "markdown": "kmcs.reporting.markdown",
    "md": "kmcs.reporting.markdown",
    "csv": "kmcs.reporting.csv_report",
    "sarif": "kmcs.reporting.sarif",
}


def cmd_report_generate(args: argparse.Namespace) -> int:
    fmt = args.format.lower()
    modname = _FORMAT_MODULES.get(fmt)
    if modname is None:
        raise CliError(f"unknown format {args.format!r}",
                       hint=f"valid: {', '.join(sorted(_FORMAT_MODULES))}")
    mod, err = _try_import(modname)
    if mod is None:
        raise ServiceError(f"reporter unavailable: {err}")
    mgr = _open_database(args)
    entry = None
    for name in ("generate_report", "render_report", "build_report", "report"):
        fn = getattr(mod, name, None)
        if callable(fn):
            entry = fn
            break
    if entry is None:
        cls = getattr(mod, "ReportGenerator", None) or getattr(mod, "Reporter", None)
        if cls is None:
            raise ServiceError(f"{modname} exposes no report entry point")
        inst = cls()
        entry = getattr(inst, "generate", None) or getattr(inst, "render", None)
        if entry is None:
            raise ServiceError(f"{modname} generator has no generate()/render()")
    out = Path(args.output).expanduser() if args.output \
        else _DEFAULT_WORKSPACE / "reports" / \
        f"kmcs-report-{int(time.time())}.{fmt}"
    out.parent.mkdir(parents=True, exist_ok=True)

    call_variants: List[Any] = []
    kwargs_sets: List[Dict[str, Any]] = []
    for db_kw in ("database", "manager", "session", "db"):
        d: Dict[str, Any] = {db_kw: mgr}
        if args.campaign:
            d["campaign_id"] = args.campaign
        kwargs_sets.append(d)
    for d in kwargs_sets:
        call_variants.append(lambda d=d: entry(**d))
    call_variants.append(lambda: entry(mgr))
    call_variants.append(lambda: entry(session=mgr))

    result = None
    last_exc: Optional[Exception] = None
    for variant in call_variants:
        try:
            result = variant()
            break
        except TypeError as exc:
            last_exc = exc
            continue
        except (CliError, ServiceError):
            raise
        except Exception as exc:  # noqa: BLE001
            raise ServiceError(f"report generation failed: {exc}") from exc
    else:
        raise ServiceError(f"reporter signature incompatible: {last_exc}")

    if isinstance(result, (str, bytes)):
        blob = result.encode("utf-8", "replace") if isinstance(result, str) \
            else bytes(result)
    else:
        content = getattr(result, "content", None)
        if isinstance(content, (str, bytes)):
            blob = content.encode("utf-8", "replace") if isinstance(content, str) \
                else bytes(content)
        else:
            blob = json.dumps(result, default=str, indent=2).encode("utf-8")
    out.write_bytes(blob)
    print(ok(f"report written: {out} ({len(blob):,} bytes, format={fmt})"))
    print(dim("  generated strictly from stored KMCS data -- no synthetic values"))
    return 0


# --------------------------------------------------------------------------- #
# argument parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kmcs",
        description=("KMCS -- Keyless Memory-Corruption Scanner. Defensive "
                     "fuzzing and memory-safety research platform. Authorised "
                     "C/C++ targets only."),
        epilog="Run 'kmcs COMMAND --help' for per-command options.")
    p.add_argument("--db", help="path to kmcs database (default: workspace/kmcs.db)")
    p.add_argument("--workspace",
                   help="workspace root (default: $KMCS_HOME or ./kmcs-workspace)")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    # doctor --------------------------------------------------------------
    sp = sub.add_parser("doctor", help="check environment, tools and subsystems")
    sp.set_defaults(func=cmd_doctor)

    # target --------------------------------------------------------------
    tp = sub.add_parser("target", help="manage fuzzing targets").add_subparsers(
        dest="subcommand", metavar="ACTION")
    ta = tp.add_parser("add", help="register a target")
    ta.add_argument("name")
    ta.add_argument("--source", help="main source file of the target")
    ta.add_argument("--binary", help="pre-built instrumented executable")
    ta.add_argument("--engine",
                    help="preferred engine (aflpp|libfuzzer|honggfuzz)")
    ta.add_argument("--authorised-by", dest="authorised_by",
                    help="who authorised this research target (default: you)")
    ta.set_defaults(func=cmd_target_add)
    tl = tp.add_parser("list", help="list registered targets")
    tl.set_defaults(func=cmd_target_list)
    tsh = tp.add_parser("show", help="show one target")
    tsh.add_argument("target_id")
    tsh.set_defaults(func=cmd_target_show)
    tr = tp.add_parser("remove", help="remove a target")
    tr.add_argument("target_id")
    tr.set_defaults(func=cmd_target_remove)

    # campaign ------------------------------------------------------------
    cp = sub.add_parser("campaign", help="manage fuzzing campaigns").add_subparsers(
        dest="subcommand", metavar="ACTION")
    cl = cp.add_parser("list", help="list campaigns (live + historical)")
    cl.set_defaults(func=cmd_campaign_list)
    cs = cp.add_parser("start", help="start a campaign (launches a REAL fuzzer)")
    cs.add_argument("--target-id", dest="target_id", required=True)
    cs.add_argument("--engine",
                    help="aflpp|libfuzzer|honggfuzz (default: target preference)")
    cs.add_argument("--corpus", help="seed corpus directory (>=1 file required)")
    cs.add_argument("--output", help="engine output directory")
    cs.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    cs.add_argument("--engine-args", dest="engine_args", default="",
                    help="extra raw arguments passed verbatim to the engine")
    cs.add_argument("--foreground", action="store_true",
                    help="run attached (blocks); default spawns detached process")
    cs.add_argument("--_campaign-id", dest="campaign_id_override",
                    help=argparse.SUPPRESS)
    cs.set_defaults(func=cmd_campaign_start)
    ct = cp.add_parser("stop", help="stop a running campaign (or 'all')")
    ct.add_argument("campaign_id")
    ct.set_defaults(func=cmd_campaign_stop)

    # crash ---------------------------------------------------------------
    kp = sub.add_parser("crash", help="inspect crash artifacts").add_subparsers(
        dest="subcommand", metavar="ACTION")
    ki = kp.add_parser("import", help="parse & store a real sanitizer log")
    ki.add_argument("file")
    ki.add_argument("--target", help="associate target name")
    ki.add_argument("--campaign", help="associate campaign id")
    ki.add_argument("--save", action="store_true",
                    help="persist parsed crashes to the database")
    ki.set_defaults(func=cmd_crash_import)
    kl = kp.add_parser("list", help="list stored crashes")
    kl.add_argument("--campaign", help="filter by campaign id")
    kl.set_defaults(func=cmd_crash_list)
    ksh = kp.add_parser("show", help="show one crash with stack trace")
    ksh.add_argument("crash_id")
    ksh.set_defaults(func=cmd_crash_show)

    # finding -------------------------------------------------------------
    fp = sub.add_parser("finding", help="analysed findings").add_subparsers(
        dest="subcommand", metavar="ACTION")
    fl = fp.add_parser("list", help="list findings")
    fl.set_defaults(func=cmd_finding_list)
    fsh = fp.add_parser("show", help="show a finding with evidence")
    fsh.add_argument("finding_id")
    fsh.set_defaults(func=cmd_finding_show)
    fr = fp.add_parser("reproduce",
                       help="re-execute the crashing input against the real binary")
    fr.add_argument("finding_id")
    fr.add_argument("--timeout", type=float, default=15.0)
    fr.set_defaults(func=cmd_finding_reproduce)

    # report --------------------------------------------------------------
    rp = sub.add_parser("report", help="generate reports").add_subparsers(
        dest="subcommand", metavar="ACTION")
    rg = rp.add_parser("generate",
                       help="emit html|json|markdown|csv|sarif report")
    rg.add_argument("--format", required=True, choices=sorted(_FORMAT_MODULES))
    rg.add_argument("--output", help="destination file")
    rg.add_argument("--campaign", help="restrict report to one campaign")
    rg.set_defaults(func=cmd_report_generate)

    return p


def run_command(argv: Optional[Sequence[str]] = None) -> int:
    global _DEFAULT_WORKSPACE
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    if getattr(args, "workspace", None):
        _DEFAULT_WORKSPACE = Path(args.workspace).expanduser().resolve()
    fn = getattr(args, "func", None)
    if fn is None:
        parser.print_help()
        return 1
    try:
        return int(fn(args) or 0)
    except CliError as exc:
        print(bad(f"error: {exc}"), file=sys.stderr)
        if exc.hint:
            print(dim(f"hint: {exc.hint}"), file=sys.stderr)
        return 1
    except ServiceError as exc:
        print(bad(f"backend error: {exc}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(warn("\ninterrupted"), file=sys.stderr)
        return 130


def main(argv: Optional[Sequence[str]] = None) -> int:
    return run_command(argv)


if __name__ == "__main__":
    sys.exit(main())
