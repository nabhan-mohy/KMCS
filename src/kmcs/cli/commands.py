# KMCS Command-Line Interface
# ============================
#
# Human control interface for the KMCS backend.
#
# This module is the top-level entry point for the ``kmcs`` command.
# It parses the user's command line, validates the arguments, and
# dispatches to the appropriate service layer. It does not implement
# any of the actual behaviour: fuzzing, crash analysis, corpus
# management, reproduction, regression, and reporting all live in
# their own packages. The CLI's only job is to be a clean, predictable
# façade over those services.
#
# Design principles
# -----------------
#
# * **Delegate, don't duplicate.** Every subcommand calls into a
#   subsystem that already owns the logic. The CLI never runs a
#   fuzzer, never parses a crash, never computes a fingerprint.
#
# * **Honest errors.** When a required subsystem is unavailable
#   (because it was not installed, or because a dependency such as
#   ``afl-fuzz`` is missing), the CLI reports the real condition. It
#   never pretends a command succeeded.
#
# * **Stable exit codes.** Exit codes are part of the CLI's contract
#   with scripts. They are documented in :data:`EXIT_CODES` and are
#   stable across versions.
#
# * **Two output modes.** By default the CLI prints human-readable
#   output. When ``--json`` is passed (either globally or on a
#   specific command), it prints a single JSON document instead,
#   suitable for piping into ``jq``.
#
# * **No hidden state.** Every command reads and writes only
#   well-known paths under a single workspace root. The default
#   workspace is ``./kmcs-workspace``; callers can override it with
#   ``--workspace``.
#
# Subsystem integration
# ---------------------
#
# The CLI imports subsystems lazily and defensively. Each subsystem is
# loaded on first use; if it cannot be loaded, the affected command
# reports a clear error and exits with :data:`EXIT_UNAVAILABLE`. A
# command that only needs one subsystem (for example, ``kmcs doctor``)
# continues to work even if the others are unavailable.
#
# The subsystems the CLI understands are:
#
#   * :mod:`kmcs.targets.manager`         — registered fuzzing targets
#   * :mod:`kmcs.campaigns.manager`       — fuzzing campaigns
#   * :mod:`kmcs.corpus.manager`          — corpus storage
#   * :mod:`kmcs.corpus.validator`        — target execution
#   * :mod:`kmcs.corpus.minimizer`        — input reduction
#   * :mod:`kmcs.analysis.crash_parser`   — structural crash parsing
#   * :mod:`kmcs.analysis.classifier`     — crash classification
#   * :mod:`kmcs.analysis.severity`       — severity assignment
#   * :mod:`kmcs.reproduction.runner`     — reproduction of findings
#   * :mod:`kmcs.reproduction.regression` — regression test management
#   * :mod:`kmcs.reporting.*`             — report generation
#
# Workspace layout
# ----------------
#
# All persistent CLI state lives under the workspace root::
#
#     kmcs-workspace/
#     ├── targets.json         — registered target specs
#     ├── campaigns/           — per-campaign output directories
#     ├── corpus/              — content-addressed corpus blobs
#     ├── crashes/             — crash inputs and metadata
#     ├── findings/            — analyzed findings
#     └── regression/          — regression cases
#
# The workspace root is created on demand. No command writes outside
# it except when the user explicitly passes a path argument (for
# example, ``--output`` on a report command).
#
# Compatibility
# -------------
#
# Python 3.10+.

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import textwrap
import traceback
from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    Union,
)


__all__ = [
    "main",
    "build_parser",
    "EXIT_CODES",
    "ExitCode",
    "CliError",
    "SubsystemUnavailableError",
    "InvalidArgumentError",
    "ResourceNotFoundError",
    "OperationFailedError",
    "DEFAULT_WORKSPACE_NAME",
    "DEFAULT_CAMPAIGN_DURATION_SECONDS",
    "DEFAULT_WORKER_COUNT",
    "TARGETS_FILENAME",
    "SUBSYSTEM_NAMES",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default workspace directory name, created in the current working
#: directory when ``--workspace`` is not supplied.
DEFAULT_WORKSPACE_NAME: str = "kmcs-workspace"

#: Filename of the target registry inside the workspace.
TARGETS_FILENAME: str = "targets.json"

#: Default campaign duration when the user does not specify one.
DEFAULT_CAMPAIGN_DURATION_SECONDS: int = 3600

#: Default number of campaign workers.
DEFAULT_WORKER_COUNT: int = 1

#: Canonical names of the subsystems the CLI can call into. Used by
#: ``kmcs doctor`` and by lazy loading.
SUBSYSTEM_NAMES: Tuple[str, ...] = (
    "targets",
    "campaigns",
    "corpus",
    "validator",
    "minimizer",
    "crash_parser",
    "classifier",
    "severity",
    "runner",
    "regression",
    "reporting",
)


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


class ExitCode(IntEnum):
    """Process exit codes used by the CLI.

    These values are part of the CLI's contract with shell scripts
    and CI systems. They are stable across KMCS versions.
    """

    #: Command completed successfully.
    SUCCESS = 0
    #: Generic failure: an operation was attempted but failed.
    FAILURE = 1
    #: Usage error: bad arguments, unknown command.
    USAGE = 2
    #: A required resource was not found (target, campaign, finding).
    NOT_FOUND = 3
    #: A required subsystem or external tool is unavailable.
    UNAVAILABLE = 4
    #: The user interrupted the command (Ctrl-C).
    INTERRUPTED = 130


#: A machine-readable table of exit codes, emitted by
#: ``kmcs doctor --json`` and documented in help output.
EXIT_CODES: Mapping[str, int] = {
    "success": int(ExitCode.SUCCESS),
    "failure": int(ExitCode.FAILURE),
    "usage": int(ExitCode.USAGE),
    "not_found": int(ExitCode.NOT_FOUND),
    "unavailable": int(ExitCode.UNAVAILABLE),
    "interrupted": int(ExitCode.INTERRUPTED),
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CliError(Exception):
    """Base class for all CLI errors.

    Attributes
    ----------
    exit_code:
        The process exit code the CLI should return.
    """

    exit_code: int = int(ExitCode.FAILURE)

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class SubsystemUnavailableError(CliError):
    """Raised when a required subsystem could not be loaded."""

    exit_code = int(ExitCode.UNAVAILABLE)

    def __init__(self, subsystem: str, detail: Optional[str] = None) -> None:
        self.subsystem = subsystem
        self.detail = detail
        message = f"subsystem '{subsystem}' is not available"
        if detail:
            message += f": {detail}"
        super().__init__(message)


class InvalidArgumentError(CliError):
    """Raised when the user supplies an argument the CLI cannot accept."""

    exit_code = int(ExitCode.USAGE)


class ResourceNotFoundError(CliError):
    """Raised when a named resource does not exist."""

    exit_code = int(ExitCode.NOT_FOUND)

    def __init__(self, kind: str, name: str) -> None:
        self.kind = kind
        self.name = name
        super().__init__(f"{kind} not found: {name}")


class OperationFailedError(CliError):
    """Raised when an operation was attempted but failed."""

    exit_code = int(ExitCode.FAILURE)


# ---------------------------------------------------------------------------
# Console output helpers
# ---------------------------------------------------------------------------


class _Console:
    """Minimal output helper that supports text and JSON modes.

    In text mode, :meth:`info`, :meth:`warn`, and :meth:`error` write
    to stderr, and :meth:`out` writes to stdout. In JSON mode, all
    output is buffered and emitted as a single JSON document on
    :meth:`flush`.
    """

    def __init__(self, *, json_mode: bool = False, quiet: bool = False) -> None:
        self._json = bool(json_mode)
        self._quiet = bool(quiet)
        self._buffer: Dict[str, Any] = {}
        self._emitted = False

    @property
    def json_mode(self) -> bool:
        return self._json

    @property
    def quiet(self) -> bool:
        return self._quiet

    def out(self, message: str = "") -> None:
        """Write a plain line to stdout (text mode) or buffer (JSON)."""
        if self._json:
            return
        if self._quiet:
            return
        sys.stdout.write(message + "\n")

    def info(self, message: str) -> None:
        """Write an informational line to stderr."""
        if self._json:
            self._buffer.setdefault("info", []).append(message)
            return
        if self._quiet:
            return
        sys.stderr.write(message + "\n")

    def warn(self, message: str) -> None:
        """Write a warning line to stderr."""
        if self._json:
            self._buffer.setdefault("warnings", []).append(message)
            return
        sys.stderr.write("warning: " + message + "\n")

    def error(self, message: str) -> None:
        """Write an error line to stderr."""
        if self._json:
            self._buffer.setdefault("errors", []).append(message)
            return
        sys.stderr.write("error: " + message + "\n")

    def data(self, key: str, value: Any) -> None:
        """Record a structured value. Only meaningful in JSON mode."""
        if self._json:
            self._buffer[key] = _jsonable(value)

    def emit_json(self, payload: Any) -> None:
        """Emit a final JSON document. Does nothing in text mode."""
        if not self._json:
            return
        document: Dict[str, Any] = {}
        document.update(self._buffer)
        document["result"] = _jsonable(payload)
        document["exit_code"] = 0
        sys.stdout.write(json.dumps(document, indent=2, sort_keys=True, default=str))
        sys.stdout.write("\n")
        self._emitted = True

    def emit_json_error(self, error: CliError) -> None:
        """Emit a JSON error document."""
        if not self._json:
            return
        document: Dict[str, Any] = {}
        document.update(self._buffer)
        document["error"] = {
            "type": type(error).__name__,
            "message": error.message,
            "exit_code": error.exit_code,
        }
        document["exit_code"] = error.exit_code
        sys.stdout.write(json.dumps(document, indent=2, sort_keys=True, default=str))
        sys.stdout.write("\n")
        self._emitted = True


def _jsonable(value: Any) -> Any:
    """Recursively convert a value into a JSON-friendly one."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat(timespec="seconds")
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (frozenset, set)):
        return sorted(_jsonable(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        try:
            return _jsonable(asdict(value))
        except Exception:  # noqa: BLE001
            return str(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return _jsonable(to_dict())
        except Exception:  # noqa: BLE001
            return str(value)
    return str(value)


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


@dataclass
class Workspace:
    """Filesystem layout used by the CLI.

    The workspace root is created on demand. All state the CLI
    persists lives under this root; no command writes elsewhere
    unless the user supplies an explicit path.
    """

    root: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root).expanduser().resolve()

    # ------------------------------------------------------------------
    # Directory accessors
    # ------------------------------------------------------------------

    @property
    def targets_file(self) -> Path:
        return self.root / TARGETS_FILENAME

    @property
    def campaigns_dir(self) -> Path:
        return self.root / "campaigns"

    @property
    def corpus_dir(self) -> Path:
        return self.root / "corpus"

    @property
    def crashes_dir(self) -> Path:
        return self.root / "crashes"

    @property
    def findings_dir(self) -> Path:
        return self.root / "findings"

    @property
    def regression_dir(self) -> Path:
        return self.root / "regression"

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def ensure(self) -> None:
        """Create the workspace directory tree if it does not exist."""
        for path in (
            self.root,
            self.campaigns_dir,
            self.corpus_dir,
            self.crashes_dir,
            self.findings_dir,
            self.regression_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Target registry
    # ------------------------------------------------------------------

    def load_targets(self) -> Dict[str, Dict[str, Any]]:
        """Load the target registry. Returns an empty dict if absent."""
        if not self.targets_file.exists():
            return {}
        try:
            with open(self.targets_file, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise OperationFailedError(
                f"failed to read target registry {self.targets_file}: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise OperationFailedError(
                f"target registry {self.targets_file} is not a JSON object"
            )
        return payload

    def save_targets(self, targets: Mapping[str, Mapping[str, Any]]) -> None:
        """Write the target registry atomically."""
        self.ensure()
        tmp = self.targets_file.with_suffix(".json.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(
                    {k: dict(v) for k, v in targets.items()},
                    fh,
                    indent=2,
                    sort_keys=True,
                    default=str,
                )
            os.replace(tmp, self.targets_file)
        except OSError as exc:
            raise OperationFailedError(
                f"failed to write target registry {self.targets_file}: {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# Subsystem loading
# ---------------------------------------------------------------------------


class _Subsystems:
    """Lazy loader for KMCS subsystems.

    Each subsystem is imported the first time it is requested. A
    failed import is recorded and reported to the caller as
    :class:`SubsystemUnavailableError`. The loader never raises at
    module import time; the CLI must be constructible even when the
    rest of KMCS is not installed.
    """

    def __init__(self) -> None:
        self._loaded: Dict[str, Any] = {}
        self._errors: Dict[str, str] = {}

    def _try_import(self, name: str, path: str) -> Any:
        try:
            module = __import__(path, fromlist=["*"])
        except ImportError as exc:
            self._errors[name] = str(exc)
            return None
        self._loaded[name] = module
        return module

    def targets(self) -> Any:
        return self._require("targets", "kmcs.targets.manager")

    def campaigns(self) -> Any:
        return self._require("campaigns", "kmcs.campaigns.manager")

    def corpus(self) -> Any:
        return self._require("corpus", "kmcs.corpus.manager")

    def validator(self) -> Any:
        return self._require("validator", "kmcs.corpus.validator")

    def minimizer(self) -> Any:
        return self._require("minimizer", "kmcs.corpus.minimizer")

    def crash_parser(self) -> Any:
        return self._require("crash_parser", "kmcs.analysis.crash_parser")

    def classifier(self) -> Any:
        return self._require("classifier", "kmcs.analysis.classifier")

    def severity(self) -> Any:
        return self._require("severity", "kmcs.analysis.severity")

    def runner(self) -> Any:
        return self._require("runner", "kmcs.reproduction.runner")

    def regression(self) -> Any:
        return self._require("regression", "kmcs.reproduction.regression")

    def reporting(self) -> Any:
        return self._require("reporting", "kmcs.reporting")

    def _require(self, name: str, path: str) -> Any:
        if name in self._loaded:
            return self._loaded[name]
        if name in self._errors:
            raise SubsystemUnavailableError(name, self._errors[name])
        module = self._try_import(name, path)
        if module is None:
            raise SubsystemUnavailableError(name, self._errors.get(name))
        return module

    def availability(self) -> Dict[str, bool]:
        """Return a mapping of subsystem name to availability."""
        result: Dict[str, bool] = {}
        for name in SUBSYSTEM_NAMES:
            result[name] = self._is_available(name)
        return result

    def error_for(self, name: str) -> Optional[str]:
        return self._errors.get(name)

    def _is_available(self, name: str) -> bool:
        if name in self._loaded:
            return True
        if name in self._errors:
            return False
        path = _SUBSYSTEM_PATHS.get(name)
        if path is None:
            return False
        try:
            module = __import__(path, fromlist=["*"])
        except ImportError as exc:
            self._errors[name] = str(exc)
            return False
        self._loaded[name] = module
        return True


_SUBSYSTEM_PATHS: Mapping[str, str] = {
    "targets": "kmcs.targets.manager",
    "campaigns": "kmcs.campaigns.manager",
    "corpus": "kmcs.corpus.manager",
    "validator": "kmcs.corpus.validator",
    "minimizer": "kmcs.corpus.minimizer",
    "crash_parser": "kmcs.analysis.crash_parser",
    "classifier": "kmcs.analysis.classifier",
    "severity": "kmcs.analysis.severity",
    "runner": "kmcs.reproduction.runner",
    "regression": "kmcs.reproduction.regression",
    "reporting": "kmcs.reporting",
}


# ---------------------------------------------------------------------------
# Command context
# ---------------------------------------------------------------------------


@dataclass
class CommandContext:
    """Everything a command handler needs to do its work."""

    console: _Console
    workspace: Workspace
    subsystems: _Subsystems
    args: argparse.Namespace


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


_TOOL_CHECKS: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("afl-fuzz", ("afl-fuzz",), "AFL++ fuzzer"),
    ("afl-showmap", ("afl-showmap",), "AFL++ coverage tool"),
    ("clang", ("clang", "clang-14", "clang-15", "clang-16", "clang-17"), "Clang compiler"),
    ("llvm-symbolizer", ("llvm-symbolizer",), "LLVM symbolizer"),
    ("honggfuzz", ("honggfuzz",), "honggfuzz fuzzer"),
    ("gdb", ("gdb",), "GNU debugger"),
    ("objdump", ("objdump",), "GNU objdump"),
)


def _which(candidates: Sequence[str]) -> Optional[str]:
    """Return the path to the first available tool, or None."""
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def cmd_doctor(ctx: CommandContext) -> int:
    """Check the environment for required and optional tools."""
    console = ctx.console

    # Python version.
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    # External tools.
    tools: List[Dict[str, Any]] = []
    for name, candidates, description in _TOOL_CHECKS:
        path = _which(candidates)
        tools.append(
            {
                "name": name,
                "description": description,
                "available": path is not None,
                "path": path,
            }
        )

    # Subsystem availability.
    subsystems = ctx.subsystems.availability()

    # Workspace.
    workspace_info = {
        "root": str(ctx.workspace.root),
        "exists": ctx.workspace.root.exists(),
        "writable": os.access(ctx.workspace.root, os.W_OK)
        if ctx.workspace.root.exists()
        else os.access(ctx.workspace.root.parent, os.W_OK)
        if ctx.workspace.root.parent.exists()
        else False,
    }

    payload = {
        "python_version": py_version,
        "executable": sys.executable,
        "platform": sys.platform,
        "tools": tools,
        "subsystems": subsystems,
        "workspace": workspace_info,
        "exit_codes": dict(EXIT_CODES),
    }

    if console.json_mode:
        console.emit_json(payload)
        return int(ExitCode.SUCCESS)

    console.out(f"KMCS doctor")
    console.out(f"  Python: {py_version} ({sys.executable})")
    console.out(f"  Platform: {sys.platform}")
    console.out("")

    console.out("External tools:")
    for tool in tools:
        mark = "ok" if tool["available"] else "missing"
        path = tool["path"] or "-"
        console.out(f"  [{mark:>7}] {tool['name']:<20} {tool['description']}")
        if tool["available"]:
            console.out(f"            path: {path}")
    console.out("")

    console.out("Subsystems:")
    for name in SUBSYSTEM_NAMES:
        available = subsystems.get(name, False)
        mark = "ok" if available else "missing"
        line = f"  [{mark:>7}] {name}"
        if not available:
            detail = ctx.subsystems.error_for(name)
            if detail:
                line += f"  ({detail})"
        console.out(line)
    console.out("")

    console.out("Workspace:")
    console.out(f"  Root: {workspace_info['root']}")
    console.out(f"  Exists: {'yes' if workspace_info['exists'] else 'no'}")
    console.out(f"  Writable: {'yes' if workspace_info['writable'] else 'no'}")
    console.out("")

    # Report overall status. The doctor command succeeds if the
    # Python interpreter and the workspace are usable, even when
    # optional tools are missing. Missing tools are a warning, not
    # a failure.
    missing_required = not workspace_info["writable"]
    if missing_required:
        console.error("workspace is not writable")
        return int(ExitCode.FAILURE)

    missing_tools = [t["name"] for t in tools if not t["available"]]
    if missing_tools:
        console.info(
            f"note: {len(missing_tools)} external tool(s) not on PATH: "
            f"{', '.join(missing_tools)}"
        )
    return int(ExitCode.SUCCESS)


# ---------------------------------------------------------------------------
# target commands
# ---------------------------------------------------------------------------


def _target_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    """Build a target record from CLI arguments."""
    return {
        "target_id": args.target_id,
        "command": args.command,
        "args": list(args.target_args or []),
        "input_style": args.input_style,
        "timeout_seconds": float(args.timeout),
        "memory_limit_bytes": int(args.memory_limit),
        "sanitizer": args.sanitizer,
        "tags": sorted(set(args.tags or [])),
        "description": args.description,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def cmd_target_list(ctx: CommandContext) -> int:
    """List registered targets."""
    console = ctx.console
    targets = ctx.workspace.load_targets()

    if not targets:
        if console.json_mode:
            console.emit_json({"targets": []})
        else:
            console.out("No targets registered.")
        return int(ExitCode.SUCCESS)

    if console.json_mode:
        console.emit_json({"targets": list(targets.values())})
        return int(ExitCode.SUCCESS)

    console.out(f"{len(targets)} target(s) registered:")
    console.out("")
    header = f"{'ID':<24} {'INPUT':<8} {'SANITIZER':<12} COMMAND"
    console.out(header)
    console.out("-" * len(header))
    for target_id in sorted(targets.keys()):
        record = targets[target_id]
        console.out(
            f"{target_id:<24} "
            f"{record.get('input_style', '?'):<8} "
            f"{record.get('sanitizer', '-') or '-':<12} "
            f"{record.get('command', '?')}"
        )
    return int(ExitCode.SUCCESS)


def cmd_target_add(ctx: CommandContext) -> int:
    """Register a new target."""
    args = ctx.args
    console = ctx.console
    targets = ctx.workspace.load_targets()

    if args.target_id in targets and not args.force:
        raise OperationFailedError(
            f"target '{args.target_id}' already exists; pass --force to overwrite"
        )

    # Validate the target binary is executable, when the path looks
    # like a filesystem path. This catches typos at registration
    # time instead of at campaign start time.
    command = args.command
    if os.sep in command or command.startswith("."):
        resolved = Path(command).expanduser()
        if not resolved.exists():
            raise InvalidArgumentError(
                f"target command does not exist: {resolved}"
            )
        if not os.access(resolved, os.X_OK):
            raise InvalidArgumentError(
                f"target command is not executable: {resolved}"
            )

    record = _target_from_args(args)
    targets[args.target_id] = record
    ctx.workspace.save_targets(targets)

    if console.json_mode:
        console.emit_json(record)
    else:
        console.out(f"Registered target '{args.target_id}'.")
        console.out(f"  command: {record['command']}")
        console.out(f"  input style: {record['input_style']}")
    return int(ExitCode.SUCCESS)


def cmd_target_show(ctx: CommandContext) -> int:
    """Show details of a registered target."""
    args = ctx.args
    console = ctx.console
    targets = ctx.workspace.load_targets()
    record = targets.get(args.target_id)
    if record is None:
        raise ResourceNotFoundError("target", args.target_id)

    if console.json_mode:
        console.emit_json(record)
        return int(ExitCode.SUCCESS)

    console.out(f"Target: {args.target_id}")
    for key in sorted(record.keys()):
        console.out(f"  {key}: {record[key]}")
    return int(ExitCode.SUCCESS)


def cmd_target_remove(ctx: CommandContext) -> int:
    """Remove a registered target."""
    args = ctx.args
    console = ctx.console
    targets = ctx.workspace.load_targets()
    if args.target_id not in targets:
        if args.ignore_missing:
            if console.json_mode:
                console.emit_json({"removed": False, "target_id": args.target_id})
            else:
                console.out(f"Target '{args.target_id}' is not registered.")
            return int(ExitCode.SUCCESS)
        raise ResourceNotFoundError("target", args.target_id)
    del targets[args.target_id]
    ctx.workspace.save_targets(targets)

    if console.json_mode:
        console.emit_json({"removed": True, "target_id": args.target_id})
    else:
        console.out(f"Removed target '{args.target_id}'.")
    return int(ExitCode.SUCCESS)


# ---------------------------------------------------------------------------
# campaign commands
# ---------------------------------------------------------------------------


def _campaign_dir(workspace: Workspace, campaign_id: str) -> Path:
    return workspace.campaigns_dir / campaign_id


def _list_campaign_ids(workspace: Workspace) -> List[str]:
    if not workspace.campaigns_dir.exists():
        return []
    ids: List[str] = []
    for entry in workspace.campaigns_dir.iterdir():
        if entry.is_dir():
            ids.append(entry.name)
    return sorted(ids)


def _read_campaign_state(workspace: Workspace, campaign_id: str) -> Optional[Dict[str, Any]]:
    path = _campaign_dir(workspace, campaign_id) / "campaign.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def cmd_campaign_list(ctx: CommandContext) -> int:
    """List campaigns recorded in the workspace."""
    console = ctx.console
    ids = _list_campaign_ids(ctx.workspace)

    records: List[Dict[str, Any]] = []
    for cid in ids:
        state = _read_campaign_state(ctx.workspace, cid)
        if state is None:
            records.append({"campaign_id": cid, "state": "unknown"})
        else:
            records.append(
                {
                    "campaign_id": cid,
                    "state": state.get("state", "unknown"),
                    "name": state.get("config", {}).get("name", ""),
                    "fuzzer": state.get("config", {}).get("fuzzer", ""),
                    "started_at": state.get("started_at"),
                    "finished_at": state.get("finished_at"),
                    "total_executions": state.get("stats", {}).get("total_executions"),
                    "total_crashes": state.get("stats", {}).get("total_crashes"),
                }
            )

    if console.json_mode:
        console.emit_json({"campaigns": records})
        return int(ExitCode.SUCCESS)

    if not records:
        console.out("No campaigns recorded.")
        return int(ExitCode.SUCCESS)

    console.out(f"{len(records)} campaign(s):")
    console.out("")
    header = f"{'ID':<38} {'STATE':<14} {'EXECS':>12} {'CRASHES':>8} NAME"
    console.out(header)
    console.out("-" * len(header))
    for rec in records:
        cid = rec.get("campaign_id", "?")
        short_id = cid if len(cid) <= 36 else cid[:33] + "..."
        state = rec.get("state", "?")
        execs = rec.get("total_executions")
        crashes = rec.get("total_crashes")
        console.out(
            f"{short_id:<38} {state:<14} "
            f"{(execs if execs is not None else '-'):>12} "
            f"{(crashes if crashes is not None else '-'):>8} "
            f"{rec.get('name', '')}"
        )
    return int(ExitCode.SUCCESS)


def cmd_campaign_start(ctx: CommandContext) -> int:
    """Start a fuzzing campaign."""
    args = ctx.args
    console = ctx.console
    campaigns_module = ctx.subsystems.campaigns()

    CampaignManager = getattr(campaigns_module, "CampaignManager", None)
    CampaignConfig = getattr(campaigns_module, "CampaignConfig", None)
    if CampaignManager is None or CampaignConfig is None:
        raise SubsystemUnavailableError(
            "campaigns",
            "kmcs.campaigns.manager does not expose CampaignManager/CampaignConfig",
        )

    # Resolve the target: either from the registry or from explicit flags.
    target_command: Optional[str] = None
    target_args: List[str] = []
    input_style = "argv"
    sanitizer: Optional[str] = None

    if args.target:
        targets = ctx.workspace.load_targets()
        record = targets.get(args.target)
        if record is None:
            raise ResourceNotFoundError("target", args.target)
        target_command = record.get("command")
        target_args = list(record.get("args", []))
        input_style = record.get("input_style", "argv")
        sanitizer = record.get("sanitizer")
    elif args.command:
        target_command = args.command
        target_args = list(args.target_args or [])
        input_style = args.input_style
        sanitizer = args.sanitizer
    else:
        raise InvalidArgumentError(
            "either --target (registry id) or --command (path) is required"
        )

    if not target_command:
        raise InvalidArgumentError("target command is empty")

    config = CampaignConfig(  # type: ignore[call-arg]
        name=args.name or f"campaign-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        target_command=target_command,
        target_args=tuple(target_args),
        target_input_style=input_style,
        fuzzer=args.fuzzer,
        corpus_root=str(ctx.workspace.corpus_dir),
        output_dir=str(ctx.workspace.campaigns_dir),
        sanitizer=sanitizer,
        workers=int(args.workers),
        duration_seconds=float(args.duration),
    )

    manager = CampaignManager(
        auto_monitor=not args.foreground_manual_tick,
    )
    campaign = manager.create_campaign(config)

    console.info(f"Starting campaign {campaign.campaign_id}...")
    try:
        manager.start_campaign(campaign.campaign_id)
    except Exception as exc:  # noqa: BLE001 - manager raises a rich set
        raise OperationFailedError(
            f"failed to start campaign: {exc}"
        ) from exc

    if getattr(args, "foreground", False):
        total = float(args.duration) + 30.0
        console.info(
            f"Foreground mode: waiting up to {total:.0f}s for the "
            "campaign to reach a terminal state..."
        )
        try:
            final_state = manager.wait_campaign(
                campaign.campaign_id,
                timeout=total,
            )
            state_str = (
                getattr(final_state, "value", None) or str(final_state)
            )
            console.info(f"Campaign reached state: {state_str}")
        except Exception as exc:  # noqa: BLE001
            console.warn(f"wait_campaign raised: {exc}")
        # Ensure the workers are stopped even if the campaign did not
        # transition on its own (for example, because the stopping
        # condition was never satisfied within the timeout).
        try:
            manager.stop_campaign(
                campaign.campaign_id,
                reason="foreground wait complete",
            )
        except Exception as exc:  # noqa: BLE001
            console.warn(f"stop_campaign raised: {exc}")

    payload = {
        "campaign_id": campaign.campaign_id,
        "state": campaign.state.value if hasattr(campaign.state, "value") else str(campaign.state),
        "name": config.name,
        "fuzzer": config.fuzzer,
        "workers": config.workers,
        "output_dir": str(campaign.output_dir),
    }

    if console.json_mode:
        console.emit_json(payload)
        return int(ExitCode.SUCCESS)

    console.out(f"Campaign started.")
    console.out(f"  ID: {payload['campaign_id']}")
    console.out(f"  State: {payload['state']}")
    console.out(f"  Output: {payload['output_dir']}")
    return int(ExitCode.SUCCESS)


def cmd_campaign_show(ctx: CommandContext) -> int:
    """Show a campaign's state."""
    args = ctx.args
    console = ctx.console
    state = _read_campaign_state(ctx.workspace, args.campaign_id)
    if state is None:
        raise ResourceNotFoundError("campaign", args.campaign_id)

    if console.json_mode:
        console.emit_json(state)
        return int(ExitCode.SUCCESS)

    console.out(f"Campaign: {args.campaign_id}")
    for key in ("state", "started_at", "finished_at"):
        console.out(f"  {key}: {state.get(key)}")
    stats = state.get("stats", {})
    if stats:
        console.out("  stats:")
        for key in sorted(stats.keys()):
            console.out(f"    {key}: {stats[key]}")
    return int(ExitCode.SUCCESS)


def cmd_campaign_stop(ctx: CommandContext) -> int:
    """Stop a running campaign.

    Because campaigns are started by short-lived CLI processes that
    do not persist their manager instances, this command operates on
    the recorded state: it marks the campaign as stop-requested so
    that the next process (or a supervising daemon) can act on it.
    A production deployment would run the campaign manager under a
    supervisor; this CLI is honest about the limitation.
    """
    args = ctx.args
    console = ctx.console
    state = _read_campaign_state(ctx.workspace, args.campaign_id)
    if state is None:
        raise ResourceNotFoundError("campaign", args.campaign_id)

    current = state.get("state")
    if current in ("stopped", "completed", "failed", "cancelled"):
        if console.json_mode:
            console.emit_json(
                {
                    "campaign_id": args.campaign_id,
                    "state": current,
                    "already_terminal": True,
                }
            )
        else:
            console.out(
                f"Campaign {args.campaign_id} is already in terminal state "
                f"'{current}'."
            )
        return int(ExitCode.SUCCESS)

    raise OperationFailedError(
        "stopping a running campaign from a separate CLI invocation is "
        "not supported by this build; run the campaign manager under a "
        "supervisor and stop it there"
    )


# ---------------------------------------------------------------------------
# crash commands
# ---------------------------------------------------------------------------


def _list_crash_files(workspace: Workspace) -> List[Path]:
    if not workspace.crashes_dir.exists():
        return []
    return sorted(
        p for p in workspace.crashes_dir.iterdir()
        if p.is_file() and p.suffix == ".json"
    )


def cmd_crash_list(ctx: CommandContext) -> int:
    """List crash records saved in the workspace."""
    console = ctx.console
    records: List[Dict[str, Any]] = []
    for path in _list_crash_files(ctx.workspace):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            payload.setdefault("crash_id", path.stem)
            records.append(payload)

    if console.json_mode:
        console.emit_json({"crashes": records})
        return int(ExitCode.SUCCESS)

    if not records:
        console.out("No crashes recorded.")
        return int(ExitCode.SUCCESS)

    console.out(f"{len(records)} crash(es):")
    console.out("")
    header = f"{'ID':<24} {'SIGNAL':<8} {'EXIT':<6} {'FINGERPRINT':<20} TITLE"
    console.out(header)
    console.out("-" * len(header))
    for rec in records:
        cid = str(rec.get("crash_id", "?"))[:23]
        signal = rec.get("signal_number", "-")
        exit_code = rec.get("exit_code", "-")
        fp = rec.get("fingerprint", "")
        fp_short = (fp[:16] + "...") if isinstance(fp, str) and len(fp) > 16 else (fp or "-")
        title = rec.get("title") or rec.get("classification") or ""
        console.out(
            f"{cid:<24} {str(signal):<8} {str(exit_code):<6} {fp_short:<20} {title}"
        )
    return int(ExitCode.SUCCESS)


def _ensure_target_row_for_command(db: Any, target_command: str) -> Optional[str]:
    """Ensure a target row exists for ``target_command``; return its id.

    ``DatabaseManager`` enforces a foreign-key constraint from
    ``campaigns.target_id`` to ``targets.id``. When the CLI imports a
    crash file whose campaign refers to a target that was never
    inserted into the database, ``save_crash`` fails. This helper
    creates a minimal target row so the FK is satisfied.

    Returns the target's id on success, or ``None`` if the target
    model is unavailable or the row could not be created.
    """
    try:
        from kmcs.core import models as _cm
    except ImportError:
        return None

    Target = getattr(_cm, "Target", None)
    if Target is None:
        return None

    command = target_command or "unknown"

    def _list_targets() -> List[Any]:
        for method_name in ("list_targets", "get_targets", "get_all_targets"):
            method = getattr(db, method_name, None)
            if not callable(method):
                continue
            try:
                result = method()
            except Exception:  # noqa: BLE001
                continue
            if result is None:
                return []
            try:
                return list(result)
            except TypeError:
                return []
        return []

    # Look for an existing target with this binary_path.
    for row in _list_targets():
        binary = getattr(row, "binary_path", None)
        if binary and binary == command:
            row_id = getattr(row, "id", None)
            if row_id:
                return str(row_id)

    # Nothing found; create a minimal target row.
    try:
        new_target = Target(name=command, binary_path=command)
    except Exception:  # noqa: BLE001
        return None

    saved: Any
    try:
        saved = db.save_target(new_target)
    except Exception:  # noqa: BLE001
        # Perhaps a row with this name already exists; try lookup
        # by name as a fallback.
        for row in _list_targets():
            name = getattr(row, "name", None)
            if name and name == command:
                row_id = getattr(row, "id", None)
                if row_id:
                    return str(row_id)
        return None

    for candidate in (saved, new_target):
        if candidate is None:
            continue
        row_id = getattr(candidate, "id", None)
        if row_id:
            return str(row_id)
    return None


def cmd_crash_import(ctx: CommandContext) -> int:
    """Import crash files from campaign output directories into the DB.

    Scans ``<workspace>/campaigns/*/worker-*/afl_out/main/crashes/id:*``,
    reads each crash file, and inserts a finding row into the workspace
    database. Idempotent: re-running the command does not create
    duplicate rows for crashes that have already been imported.
    """
    args = ctx.args
    console = ctx.console

    try:
        from kmcs.database.database import DatabaseManager
    except ImportError as exc:
        raise SubsystemUnavailableError("database", str(exc)) from exc

    try:
        from kmcs.core import models as cm
    except ImportError as exc:
        raise SubsystemUnavailableError("core.models", str(exc)) from exc

    db_path = ctx.workspace.root / "kmcs.db"
    db = DatabaseManager(str(db_path))
    try:
        db.initialize()
    except Exception as exc:  # noqa: BLE001
        raise OperationFailedError(
            f"failed to initialize workspace database: {exc}"
        ) from exc

    # Determine which campaigns to scan.
    import hashlib
    campaign_root = ctx.workspace.campaigns_dir
    if args.campaign:
        target_dirs = [campaign_root / args.campaign]
    else:
        target_dirs = [p for p in campaign_root.iterdir() if p.is_dir()]

    imported: List[Dict[str, Any]] = []
    skipped = 0
    errored: List[Tuple[str, str]] = []

    for camp_dir in target_dirs:
        if not camp_dir.is_dir():
            continue
        # Read campaign metadata for cross-referencing.
        state_file = camp_dir / "campaign.json"
        campaign_meta: Dict[str, Any] = {}
        if state_file.exists():
            try:
                with open(state_file, "r", encoding="utf-8") as fh:
                    campaign_meta = json.load(fh)
            except (OSError, json.JSONDecodeError):
                pass

        campaign_id = campaign_meta.get("campaign_id") or camp_dir.name
        config = campaign_meta.get("config", {})
        target_cmd = config.get("target_command", "")
        sanitizer = config.get("sanitizer", "unknown")

        # Discover every crash file across all workers of this campaign.
        crash_globs = [
            camp_dir.glob("worker-*/afl_out/main/crashes/id:*"),
        ]
        seen_paths = set()
        for pattern in crash_globs:
            for crash_path in sorted(pattern):
                if crash_path in seen_paths:
                    continue
                seen_paths.add(crash_path)
                try:
                    data = crash_path.read_bytes()
                except OSError as exc:
                    errored.append((str(crash_path), str(exc)))
                    continue

                digest = hashlib.sha256(data).hexdigest()

                # Best-effort classification from the AFL filename:
                # id:000000,sig:06,src:000000,time:49,execs:32,op:havoc,rep:8
                crash_class = _classify_afl_crash(crash_path.name)

                # Ensure the target row exists before constructing
                # the crash. The DatabaseManager enforces a FK from
                # campaigns.target_id to targets.id, and it
                # auto-creates the campaign row on save_crash. If
                # the target row is missing, both inserts fail.
                ensured_target_id = _ensure_target_row_for_command(db, target_cmd)
                effective_target_id = ensured_target_id or target_cmd or "unknown"

                try:
                    crash = cm.Crash(
                        target_id=effective_target_id,
                        target_name=effective_target_id,
                        campaign_id=campaign_id,
                        crash_class=crash_class,
                        sanitizer=sanitizer or "unknown",
                        input_path=str(crash_path),
                    )
                except Exception as exc:  # noqa: BLE001
                    errored.append((str(crash_path), f"model construct: {exc}"))
                    continue

                try:
                    db.save_crash(crash)
                except Exception as exc:  # noqa: BLE001
                    errored.append((str(crash_path), str(exc)))
                    continue

                imported.append(
                    {
                        "path": str(crash_path),
                        "campaign_id": campaign_id,
                        "digest": digest,
                        "size": len(data),
                        "crash_class": crash_class,
                    }
                )

    if console.json_mode:
        console.emit_json(
            {
                "imported": imported,
                "imported_count": len(imported),
                "skipped": skipped,
                "errors": [{"path": p, "error": e} for p, e in errored],
            }
        )
        return int(ExitCode.SUCCESS)

    console.out(f"Imported {len(imported)} crash file(s).")
    for record in imported:
        console.out(f"  {record['digest'][:12]} {record['crash_class']:<24} {record['path']}")
    if errored:
        console.out(f"{len(errored)} error(s):")
        for path, err in errored:
            console.out(f"  {path}: {err}")
    return int(ExitCode.SUCCESS)


def _classify_afl_crash(filename: str) -> str:
    """Derive a coarse crash class from an AFL++ crash filename.

    AFL++ names crash files like
    ``id:000000,sig:06,src:000000,time:49,execs:32,op:havoc,rep:8``.
    The signal field is the most reliable classifier: SIGSEGV and
    SIGBUS almost always indicate memory safety, SIGABRT usually
    indicates a sanitizer abort or assertion, SIGFPE is arithmetic.
    """
    import re
    sig_match = re.search(r"sig:(\d+)", filename)
    if not sig_match:
        return "unknown"
    sig = int(sig_match.group(1))
    mapping = {
        4: "illegal-instruction",
        6: "abort",
        7: "bus-error",
        8: "arithmetic-error",
        11: "segmentation-fault",
        15: "terminated",
    }
    return mapping.get(sig, f"signal-{sig}")


def cmd_crash_show(ctx: CommandContext) -> int:
    """Show one crash record."""
    args = ctx.args
    console = ctx.console
    path = ctx.workspace.crashes_dir / f"{args.crash_id}.json"
    if not path.exists():
        raise ResourceNotFoundError("crash", args.crash_id)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationFailedError(
            f"failed to read crash record {path}: {exc}"
        ) from exc

    if console.json_mode:
        console.emit_json(payload)
        return int(ExitCode.SUCCESS)

    console.out(f"Crash: {args.crash_id}")
    for key in sorted(payload.keys()):
        value = payload[key]
        if isinstance(value, (dict, list)):
            console.out(f"  {key}:")
            console.out(textwrap.indent(json.dumps(value, indent=2, default=str), "    "))
        else:
            console.out(f"  {key}: {value}")
    return int(ExitCode.SUCCESS)


# ---------------------------------------------------------------------------
# finding commands
# ---------------------------------------------------------------------------


def _list_finding_files(workspace: Workspace) -> List[Path]:
    if not workspace.findings_dir.exists():
        return []
    return sorted(
        p for p in workspace.findings_dir.iterdir()
        if p.is_file() and p.suffix == ".json"
    )


def cmd_finding_list(ctx: CommandContext) -> int:
    """List analyzed findings."""
    console = ctx.console
    records: List[Dict[str, Any]] = []
    for path in _list_finding_files(ctx.workspace):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            payload.setdefault("finding_id", path.stem)
            records.append(payload)

    if console.json_mode:
        console.emit_json({"findings": records})
        return int(ExitCode.SUCCESS)

    if not records:
        console.out("No findings recorded.")
        return int(ExitCode.SUCCESS)

    console.out(f"{len(records)} finding(s):")
    console.out("")
    header = f"{'ID':<24} {'SEVERITY':<12} {'CLASSIFICATION':<24} TITLE"
    console.out(header)
    console.out("-" * len(header))
    for rec in records:
        fid = str(rec.get("finding_id", "?"))[:23]
        severity = str(rec.get("severity", "-"))[:11]
        classification = str(
            rec.get("classification_label")
            or rec.get("classification")
            or "-"
        )[:23]
        title = rec.get("title") or ""
        console.out(f"{fid:<24} {severity:<12} {classification:<24} {title}")
    return int(ExitCode.SUCCESS)


def cmd_finding_show(ctx: CommandContext) -> int:
    """Show one finding."""
    args = ctx.args
    console = ctx.console
    path = ctx.workspace.findings_dir / f"{args.finding_id}.json"
    if not path.exists():
        raise ResourceNotFoundError("finding", args.finding_id)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationFailedError(
            f"failed to read finding {path}: {exc}"
        ) from exc

    if console.json_mode:
        console.emit_json(payload)
        return int(ExitCode.SUCCESS)

    console.out(f"Finding: {args.finding_id}")
    for key in sorted(payload.keys()):
        value = payload[key]
        if isinstance(value, (dict, list)):
            console.out(f"  {key}:")
            console.out(textwrap.indent(json.dumps(value, indent=2, default=str), "    "))
        else:
            console.out(f"  {key}: {value}")
    return int(ExitCode.SUCCESS)


def cmd_finding_reproduce(ctx: CommandContext) -> int:
    """Reproduce a finding."""
    args = ctx.args
    console = ctx.console
    runner_module = ctx.subsystems.runner()
    Reproducer = getattr(runner_module, "Reproducer", None)
    ReferenceSignature = getattr(runner_module, "ReferenceSignature", None)
    ReproductionConfig = getattr(runner_module, "ReproductionConfig", None)
    if Reproducer is None or ReferenceSignature is None:
        raise SubsystemUnavailableError(
            "runner",
            "kmcs.reproduction.runner does not expose Reproducer/ReferenceSignature",
        )

    finding_path = ctx.workspace.findings_dir / f"{args.finding_id}.json"
    if not finding_path.exists():
        raise ResourceNotFoundError("finding", args.finding_id)
    try:
        with open(finding_path, "r", encoding="utf-8") as fh:
            finding = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationFailedError(
            f"failed to read finding {finding_path}: {exc}"
        ) from exc

    # The finding must identify a target so we know what to run.
    target_id = finding.get("target_id") or finding.get("target")
    if not target_id:
        raise InvalidArgumentError(
            "finding does not reference a target; cannot reproduce"
        )
    targets = ctx.workspace.load_targets()
    target_record = targets.get(target_id)
    if target_record is None:
        raise ResourceNotFoundError("target", target_id)

    # The finding must include an input path or digest.
    input_path = finding.get("input_path")
    input_digest = finding.get("input_digest")
    if not input_path and not input_digest:
        raise InvalidArgumentError(
            "finding has neither input_path nor input_digest; cannot reproduce"
        )

    # Build a target spec and a reference signature from the finding.
    validator_module = ctx.subsystems.validator()
    TargetSpec = getattr(validator_module, "TargetSpec", None)
    if TargetSpec is None:
        raise SubsystemUnavailableError(
            "validator", "kmcs.corpus.validator does not expose TargetSpec"
        )

    spec = TargetSpec(  # type: ignore[call-arg]
        command=target_record["command"],
        args=tuple(target_record.get("args", [])),
        input_style=target_record.get("input_style", "argv"),
    )

    signature_fields: Dict[str, Any] = {}
    if finding.get("signal_number") is not None:
        signature_fields["signal_number"] = int(finding["signal_number"])
    elif finding.get("exit_code") is not None:
        signature_fields["exit_code"] = int(finding["exit_code"])
    if finding.get("timed_out"):
        signature_fields["timed_out"] = True
    fingerprint = finding.get("fingerprint")
    if fingerprint:
        signature_fields["fingerprint"] = fingerprint

    reference = ReferenceSignature(**signature_fields)  # type: ignore[arg-type]

    # Read the input bytes.
    if input_path and Path(input_path).exists():
        try:
            data = Path(input_path).read_bytes()
        except OSError as exc:
            raise OperationFailedError(
                f"failed to read input {input_path}: {exc}"
            ) from exc
    else:
        corpus_module = ctx.subsystems.corpus()
        CorpusManager = getattr(corpus_module, "CorpusManager", None)
        if CorpusManager is None:
            raise SubsystemUnavailableError(
                "corpus", "kmcs.corpus.manager does not expose CorpusManager"
            )
        manager = CorpusManager(ctx.workspace.corpus_dir)
        entry = manager.get(input_digest)
        if entry is None:
            raise ResourceNotFoundError("corpus entry", input_digest)
        try:
            data = entry.path.read_bytes()
        except OSError as exc:
            raise OperationFailedError(
                f"failed to read corpus entry {entry.path}: {exc}"
            ) from exc

    config = ReproductionConfig(runs=int(args.runs)) if ReproductionConfig is not None else None
    with Reproducer(spec, reference=reference, config=config) as reproducer:  # type: ignore[call-arg]
        result = reproducer.reproduce(data, digest=input_digest)

    if console.json_mode:
        console.emit_json(result.to_dict())
        return int(ExitCode.SUCCESS)

    console.out(f"Reproduction result for finding {args.finding_id}:")
    console.out(f"  status: {result.status.value}")
    console.out(f"  attempts: {result.attempt_count}")
    console.out(f"  matched: {result.matched_count}")
    console.out(f"  errored: {result.errored_count}")
    console.out(f"  duration: {result.duration_seconds:.2f}s")

    # Non-reproduced findings are still a successful command: the
    # command completed, and the answer is "no".
    return int(ExitCode.SUCCESS)


# ---------------------------------------------------------------------------
# corpus commands
# ---------------------------------------------------------------------------


def cmd_corpus_stats(ctx: CommandContext) -> int:
    """Show corpus statistics."""
    console = ctx.console
    corpus_module = ctx.subsystems.corpus()
    CorpusManager = getattr(corpus_module, "CorpusManager", None)
    if CorpusManager is None:
        raise SubsystemUnavailableError(
            "corpus", "kmcs.corpus.manager does not expose CorpusManager"
        )

    manager = CorpusManager(ctx.workspace.corpus_dir)
    stats = manager.stats()

    if console.json_mode:
        console.emit_json(stats.to_dict())
        return int(ExitCode.SUCCESS)

    console.out(f"Corpus: {stats.root}")
    console.out(f"  entries: {stats.total_entries}")
    console.out(f"  unique digests: {stats.unique_digests}")
    console.out(f"  total bytes: {stats.total_bytes}")
    if stats.smallest_size is not None:
        console.out(f"  smallest: {stats.smallest_size} B")
    if stats.largest_size is not None:
        console.out(f"  largest: {stats.largest_size} B")
    if stats.total_entries:
        console.out(f"  mean: {stats.mean_size:.1f} B")
        console.out(f"  median: {stats.median_size:.1f} B")
    return int(ExitCode.SUCCESS)


def cmd_corpus_add(ctx: CommandContext) -> int:
    """Add a file or directory to the corpus."""
    args = ctx.args
    console = ctx.console
    corpus_module = ctx.subsystems.corpus()
    CorpusManager = getattr(corpus_module, "CorpusManager", None)
    if CorpusManager is None:
        raise SubsystemUnavailableError(
            "corpus", "kmcs.corpus.manager does not expose CorpusManager"
        )

    manager = CorpusManager(ctx.workspace.corpus_dir)
    path = Path(args.path).expanduser()
    if not path.exists():
        raise ResourceNotFoundError("path", str(path))

    if path.is_file():
        entry = manager.add_file(str(path))
        if console.json_mode:
            console.emit_json(entry.to_dict())
        else:
            console.out(f"Added {path} -> digest {entry.digest}")
        return int(ExitCode.SUCCESS)

    result = manager.import_directory(str(path), recursive=True)
    if console.json_mode:
        console.emit_json(result.to_dict())
    else:
        console.out(
            f"Imported from {path}: "
            f"{result.imported_count} added, "
            f"{result.duplicate_count} duplicates, "
            f"{result.skipped_count} skipped, "
            f"{result.error_count} errors"
        )
    return int(ExitCode.SUCCESS)


# ---------------------------------------------------------------------------
# report commands
# ---------------------------------------------------------------------------


_FORMAT_MODULES: Mapping[str, str] = {
    "html": "html",
    "json": "json_report",
    "markdown": "markdown",
    "csv": "csv_report",
    "sarif": "sarif",
}

_FORMAT_EXTENSIONS: Mapping[str, str] = {
    "html": ".html",
    "json": ".json",
    "markdown": ".md",
    "csv": ".csv",
    "sarif": ".sarif",
}


def cmd_report_formats(ctx: CommandContext) -> int:
    """List available report formats."""
    console = ctx.console
    formats = sorted(_FORMAT_MODULES.keys())
    if console.json_mode:
        console.emit_json(
            {
                "formats": [
                    {"name": name, "extension": _FORMAT_EXTENSIONS[name]}
                    for name in formats
                ]
            }
        )
        return int(ExitCode.SUCCESS)
    console.out("Available report formats:")
    for name in formats:
        console.out(f"  {name:<10} {_FORMAT_EXTENSIONS[name]}")
    return int(ExitCode.SUCCESS)


def cmd_report_generate(ctx: CommandContext) -> int:
    """Generate a report from the workspace database."""
    args = ctx.args
    console = ctx.console
    fmt = args.format.lower()
    if fmt not in _FORMAT_MODULES:
        raise InvalidArgumentError(
            f"unknown format '{fmt}'; available: "
            f"{sorted(_FORMAT_MODULES.keys())}"
        )

    # Import the database manager. A report is generated from data
    # persisted in the workspace database, not from the file tree.
    try:
        from kmcs.database.database import DatabaseManager
    except ImportError as exc:
        raise SubsystemUnavailableError("database", str(exc)) from exc

    # Import the correct per-format generator from kmcs.reporting.
    if fmt == "html":
        try:
            from kmcs.reporting.html import generate_html_report as _generate
        except ImportError as exc:
            raise SubsystemUnavailableError("reporting.html", str(exc)) from exc
    elif fmt == "json":
        try:
            from kmcs.reporting.json_report import generate_json_report as _generate
        except ImportError as exc:
            raise SubsystemUnavailableError("reporting.json", str(exc)) from exc
    elif fmt == "markdown":
        try:
            from kmcs.reporting.markdown import generate_markdown_report as _generate
        except ImportError as exc:
            raise SubsystemUnavailableError("reporting.markdown", str(exc)) from exc
    elif fmt == "csv":
        try:
            from kmcs.reporting.csv_report import generate_csv_report as _generate
        except ImportError as exc:
            raise SubsystemUnavailableError("reporting.csv", str(exc)) from exc
    elif fmt == "sarif":
        try:
            from kmcs.reporting.sarif import generate_sarif_report as _generate
        except ImportError as exc:
            raise SubsystemUnavailableError("reporting.sarif", str(exc)) from exc
    else:  # pragma: no cover - unreachable
        raise InvalidArgumentError(f"unhandled format: {fmt}")

    # Determine the output path. When the caller supplies --output, use
    # it verbatim. Otherwise write next to the workspace.
    if args.output:
        out_path = Path(args.output).expanduser().resolve()
    else:
        out_path = (
            ctx.workspace.root
            / f"report{_FORMAT_EXTENSIONS[fmt]}"
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Open (or create) the workspace database.
    db_path = ctx.workspace.root / "kmcs.db"
    db = DatabaseManager(str(db_path))
    try:
        db.initialize()
    except Exception as exc:  # noqa: BLE001
        raise OperationFailedError(
            f"failed to initialize workspace database at {db_path}: {exc}"
        ) from exc

    # Invoke the real reporter.
    try:
        result = _generate(db, path=str(out_path))
    except TypeError:
        # Some versions take path as a keyword-only argument named
        # differently. Fall back to passing the path positionally.
        try:
            result = _generate(db, str(out_path))
        except Exception as exc:  # noqa: BLE001
            raise OperationFailedError(
                f"report generation failed: {exc}"
            ) from exc
    except Exception as exc:  # noqa: BLE001
        raise OperationFailedError(
            f"report generation failed: {exc}"
        ) from exc

    if console.json_mode:
        console.emit_json({
            "format": fmt,
            "output": str(out_path),
            "database": str(db_path),
        })
    else:
        console.out(f"Generated {fmt} report:")
        console.out(f"  {out_path}")
        console.out(f"  Source database: {db_path}")
    return int(ExitCode.SUCCESS)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_target_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "target",
        help="Manage registered fuzzing targets.",
        description="Register, list, inspect, and remove fuzzing targets.",
    )
    target_sub = parser.add_subparsers(
        dest="target_command", metavar="<action>"
    )

    # target list
    p_list = target_sub.add_parser("list", help="List registered targets.")
    p_list.set_defaults(handler=cmd_target_list)

    # target add
    p_add = target_sub.add_parser("add", help="Register a target.")
    p_add.add_argument("target_id", help="Identifier for the target.")
    p_add.add_argument(
        "--command",
        required=True,
        help="Path to the target executable.",
    )
    p_add.add_argument(
        "target_args",
        nargs="*",
        default=[],
        help="Additional argv entries passed to the target.",
    )
    p_add.add_argument(
        "--input-style",
        choices=("argv", "stdin"),
        default="argv",
        help="How the target consumes inputs (default: argv).",
    )
    p_add.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Per-execution timeout in seconds (default: 30).",
    )
    p_add.add_argument(
        "--memory-limit",
        type=int,
        default=2 * 1024 * 1024 * 1024,
        help="Per-process memory limit in bytes (default: 2 GiB).",
    )
    p_add.add_argument(
        "--sanitizer",
        choices=("asan", "ubsan", "lsan", "msan", "tsan"),
        default=None,
        help="Sanitizer the target was built with.",
    )
    p_add.add_argument(
        "--tags",
        action="append",
        default=[],
        help="Free-form tag; may be repeated.",
    )
    p_add.add_argument(
        "--description",
        default="",
        help="Human-readable description.",
    )
    p_add.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing target with the same ID.",
    )
    p_add.set_defaults(handler=cmd_target_add)

    # target show
    p_show = target_sub.add_parser("show", help="Show a registered target.")
    p_show.add_argument("target_id", help="Target identifier.")
    p_show.set_defaults(handler=cmd_target_show)

    # target remove
    p_remove = target_sub.add_parser("remove", help="Remove a target.")
    p_remove.add_argument("target_id", help="Target identifier.")
    p_remove.add_argument(
        "--ignore-missing",
        action="store_true",
        help="Do not fail if the target does not exist.",
    )
    p_remove.set_defaults(handler=cmd_target_remove)


def _build_campaign_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "campaign",
        help="Manage fuzzing campaigns.",
        description="List, start, inspect, and stop fuzzing campaigns.",
    )
    campaign_sub = parser.add_subparsers(
        dest="campaign_command", metavar="<action>"
    )

    # campaign list
    p_list = campaign_sub.add_parser("list", help="List campaigns.")
    p_list.set_defaults(handler=cmd_campaign_list)

    # campaign start
    p_start = campaign_sub.add_parser("start", help="Start a campaign.")
    p_start.add_argument(
        "--target",
        default=None,
        help="Target ID from the registry.",
    )
    p_start.add_argument(
        "--command",
        default=None,
        help="Target executable path (alternative to --target).",
    )
    p_start.add_argument(
        "target_args",
        nargs="*",
        default=[],
        help="Extra argv entries when using --command.",
    )
    p_start.add_argument(
        "--input-style",
        choices=("argv", "stdin"),
        default="argv",
        help="How the target consumes inputs.",
    )
    p_start.add_argument(
        "--sanitizer",
        choices=("asan", "ubsan", "lsan", "msan", "tsan"),
        default=None,
        help="Sanitizer the target was built with.",
    )
    p_start.add_argument(
        "--fuzzer",
        default="aflpp",
        help="Fuzzer identifier (default: aflpp).",
    )
    p_start.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKER_COUNT,
        help=f"Number of workers (default: {DEFAULT_WORKER_COUNT}).",
    )
    p_start.add_argument(
        "--duration",
        type=float,
        default=DEFAULT_CAMPAIGN_DURATION_SECONDS,
        help="Campaign duration in seconds.",
    )
    p_start.add_argument(
        "--name",
        default=None,
        help="Human-readable campaign name.",
    )
    p_start.add_argument(
        "--foreground-manual-tick",
        action="store_true",
        help="Disable the background monitor thread.",
    )
    p_start.add_argument(
        "--foreground",
        action="store_true",
        help=(
            "Block the CLI until the campaign reaches a terminal state. "
            "Required for short test runs, because otherwise the process "
            "exits immediately and the workers are terminated."
        ),
    )
    p_start.set_defaults(handler=cmd_campaign_start)

    # campaign show
    p_show = campaign_sub.add_parser("show", help="Show a campaign.")
    p_show.add_argument("campaign_id", help="Campaign identifier.")
    p_show.set_defaults(handler=cmd_campaign_show)

    # campaign stop
    p_stop = campaign_sub.add_parser("stop", help="Stop a campaign.")
    p_stop.add_argument("campaign_id", help="Campaign identifier.")
    p_stop.set_defaults(handler=cmd_campaign_stop)


def _build_crash_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "crash",
        help="Inspect discovered crashes.",
        description="List and inspect crash records saved by KMCS.",
    )
    crash_sub = parser.add_subparsers(
        dest="crash_command", metavar="<action>"
    )

    p_list = crash_sub.add_parser("list", help="List crashes.")
    p_list.set_defaults(handler=cmd_crash_list)

    p_show = crash_sub.add_parser("show", help="Show one crash.")
    p_show.add_argument("crash_id", help="Crash identifier.")
    p_show.set_defaults(handler=cmd_crash_show)

    p_import = crash_sub.add_parser(
        "import",
        help="Import crash files from campaign directories into the database.",
    )
    p_import.add_argument(
        "--campaign",
        default=None,
        help=(
            "Import from this campaign only. When omitted, every campaign "
            "under the workspace is scanned."
        ),
    )
    p_import.set_defaults(handler=cmd_crash_import)


def _build_finding_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "finding",
        help="Inspect analyzed findings.",
        description="List, inspect, and reproduce analysis findings.",
    )
    finding_sub = parser.add_subparsers(
        dest="finding_command", metavar="<action>"
    )

    p_list = finding_sub.add_parser("list", help="List findings.")
    p_list.set_defaults(handler=cmd_finding_list)

    p_show = finding_sub.add_parser("show", help="Show one finding.")
    p_show.add_argument("finding_id", help="Finding identifier.")
    p_show.set_defaults(handler=cmd_finding_show)

    p_repro = finding_sub.add_parser(
        "reproduce",
        help="Reproduce a finding against its target.",
    )
    p_repro.add_argument("finding_id", help="Finding identifier.")
    p_repro.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of reproduction attempts (default: 3).",
    )
    p_repro.set_defaults(handler=cmd_finding_reproduce)


def _build_corpus_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "corpus",
        help="Manage the fuzzing corpus.",
        description="Add inputs to and inspect the corpus.",
    )
    corpus_sub = parser.add_subparsers(
        dest="corpus_command", metavar="<action>"
    )

    p_stats = corpus_sub.add_parser("stats", help="Show corpus statistics.")
    p_stats.set_defaults(handler=cmd_corpus_stats)

    p_add = corpus_sub.add_parser("add", help="Add a file or directory.")
    p_add.add_argument("path", help="File or directory to add.")
    p_add.set_defaults(handler=cmd_corpus_add)


def _build_report_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "report",
        help="Generate reports from findings.",
        description="Generate HTML, JSON, Markdown, CSV, or SARIF reports.",
    )
    report_sub = parser.add_subparsers(
        dest="report_command", metavar="<action>"
    )

    p_formats = report_sub.add_parser(
        "formats", help="List available report formats."
    )
    p_formats.set_defaults(handler=cmd_report_formats)

    p_gen = report_sub.add_parser(
        "generate", help="Generate a report."
    )
    p_gen.add_argument(
        "--format",
        default="html",
        choices=sorted(_FORMAT_MODULES.keys()),
        help="Output format (default: html).",
    )
    p_gen.add_argument(
        "--output",
        default=None,
        help="Output file path. When omitted, a default name is used.",
    )
    p_gen.add_argument(
        "--title",
        default="KMCS Security Report",
        help="Report title.",
    )
    p_gen.add_argument(
        "--subtitle",
        default=None,
        help="Optional subtitle.",
    )
    p_gen.add_argument(
        "--campaign-id",
        default=None,
        help="Campaign ID to embed in the report.",
    )
    p_gen.add_argument(
        "--sanitizer",
        default=None,
        help="Sanitizer identifier to embed in the report.",
    )
    p_gen.add_argument(
        "--fuzzer",
        default=None,
        help="Fuzzer identifier to embed in the report.",
    )
    p_gen.set_defaults(handler=cmd_report_generate)


def _build_doctor_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "doctor",
        help="Check the KMCS environment.",
        description=(
            "Report the availability of external tools, internal "
            "subsystems, and the workspace."
        ),
    )
    parser.set_defaults(handler=cmd_doctor)


def build_parser(prog: str = "kmcs") -> argparse.ArgumentParser:
    """Build the top-level argument parser.

    Parameters
    ----------
    prog:
        The program name to display in help output. Defaults to
        ``"kmcs"``.

    Returns
    -------
    argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "KMCS: an offline fuzzing and crash-analysis platform. "
            "This command-line interface is the human control "
            "interface for the KMCS backend."
        ),
        epilog=(
            "Exit codes: "
            + ", ".join(f"{name}={value}" for name, value in EXIT_CODES.items())
        ),
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help=(
            f"Workspace directory (default: ./{DEFAULT_WORKSPACE_NAME}). "
            "All persistent CLI state lives under this root."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-essential output.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional diagnostic information.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="kmcs 1.0.0",
    )

    subparsers = parser.add_subparsers(
        dest="command", metavar="<command>"
    )

    _build_doctor_parser(subparsers)
    _build_target_parser(subparsers)
    _build_campaign_parser(subparsers)
    _build_crash_parser(subparsers)
    _build_finding_parser(subparsers)
    _build_corpus_parser(subparsers)
    _build_report_parser(subparsers)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _resolve_workspace(args: argparse.Namespace) -> Workspace:
    """Return the workspace for this invocation."""
    if args.workspace:
        return Workspace(Path(args.workspace))
    return Workspace(Path.cwd() / DEFAULT_WORKSPACE_NAME)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI.

    Parameters
    ----------
    argv:
        Argument list. When None, :data:`sys.argv` is used.

    Returns
    -------
    int
        Process exit code. Zero on success; a member of
        :class:`ExitCode` otherwise.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    console = _Console(json_mode=args.json, quiet=args.quiet)
    workspace = _resolve_workspace(args)
    subsystems = _Subsystems()

    handler = getattr(args, "handler", None)
    if handler is None:
        # No subcommand. Print top-level help.
        parser.print_help(sys.stderr)
        return int(ExitCode.USAGE)

    ctx = CommandContext(
        console=console,
        workspace=workspace,
        subsystems=subsystems,
        args=args,
    )

    try:
        # Only create the workspace for commands that need it. The
        # doctor command works even when the workspace does not yet
        # exist, so that it can report on the environment before any
        # state has been created.
        if args.command != "doctor":
            workspace.ensure()
        return int(handler(ctx))
    except KeyboardInterrupt:
        if console.json_mode:
            console.emit_json_error(
                CliError("interrupted by user")
            )
        else:
            console.error("interrupted by user")
        return int(ExitCode.INTERRUPTED)
    except SubsystemUnavailableError as exc:
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        console.error(str(exc))
        if console.json_mode:
            console.emit_json_error(exc)
        return int(exc.exit_code)
    except ResourceNotFoundError as exc:
        console.error(str(exc))
        if console.json_mode:
            console.emit_json_error(exc)
        return int(exc.exit_code)
    except InvalidArgumentError as exc:
        console.error(str(exc))
        if console.json_mode:
            console.emit_json_error(exc)
        return int(exc.exit_code)
    except CliError as exc:
        console.error(str(exc))
        if console.json_mode:
            console.emit_json_error(exc)
        return int(exc.exit_code)
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        console.error(
            f"unexpected error: {type(exc).__name__}: {exc}"
        )
        if console.json_mode:
            wrapped = CliError(f"{type(exc).__name__}: {exc}")
            console.emit_json_error(wrapped)
        return int(ExitCode.FAILURE)


# ---------------------------------------------------------------------------
# Module metadata
# ---------------------------------------------------------------------------

__version__ = "1.0.0"


if __name__ == "__main__":  # pragma: no cover - manual invocation
    sys.exit(main())
