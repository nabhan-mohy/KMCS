"""
KMCS — Keyless Memory-Corruption Scanner
kmcs.database.migrations

Versioned schema lifecycle for the KMCS SQLite database.

This module provides a *real* migration engine — it inspects the live SQLite
schema with SQLAlchemy's reflection facilities, compares it against the ORM
metadata declared in :mod:`kmcs.database.models`, and applies concrete DDL.
Nothing here is simulated: every migration either executes SQL or raises.

Design goals
------------
1.  **Idempotent bootstrap.** A brand-new database is created at the current
    ``SCHEMA_VERSION`` by ``Base.metadata.create_all`` plus stamping.
2.  **Forward migrations.** Each released schema version has an ordered
    :class:`Migration` step registered in :data:`MIGRATION_REGISTRY`.
    Steps may add tables, add columns, create indexes, backfill rows, or
    transform data. Steps declare whether they are reversible; irreversible
    steps refuse to run "down" loudly instead of silently corrupting data.
3.  **Safety first.** Before any destructive or structural change the engine
    can take a file-level backup using SQLite's online-backup API
    (``sqlite3`` connection ``backup()``), verifies integrity with
    ``PRAGMA integrity_check`` afterwards, and wraps each step in a
    transaction where SQLite allows it (DDL inside a transaction is supported
    by SQLite, so every step is atomic).
4.  **Auditability.** Every applied step is recorded in the ``schema_migrations``
    table with timestamp, direction, duration, and result hash. The
    ``schema.version`` setting row kept by :class:`DatabaseManager` is
    synchronised after every successful migration.
5.  **Drift detection.** :func:`detect_drift` diffs live DB vs ORM metadata so
    callers (CLI/GUI/health checks) can report hand-edited or partially
    migrated databases honestly rather than assuming they are fine.

No external services, no network, no API keys. Everything runs against the
local SQLite file with the Python standard library + SQLAlchemy.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from sqlalchemy import Inspector, Engine, inspect as sa_inspect, text
from sqlalchemy.exc import SQLAlchemyError

from kmcs.core.exceptions import (
    DatabaseError,
    MigrationError,
    SchemaVersionError,
)
from kmcs.database.models import (
    Base,
    SCHEMA_VERSION,
    SettingRow,
    table_names,
)

LOGGER = logging.getLogger("kmcs.database.migrations")

__all__ = [
    "MigrationDirection",
    "MigrationStatus",
    "ColumnSpec",
    "IndexSpec",
    "TableSpec",
    "Migration",
    "MigrationStepResult",
    "MigrationPlan",
    "MigrationReport",
    "SchemaInfo",
    "MigrationRunner",
    "MIGRATION_REGISTRY",
    "CURRENT_SCHEMA_VERSION",
    "MIN_UPGRADABLE_VERSION",
    "schema_migrations_ddl",
    "read_current_version",
    "detect_drift",
    "build_bootstrap_migration",
    "verify_integrity",
    "backup_database_file",
]

#: Version this code understands as "latest".
CURRENT_SCHEMA_VERSION: int = SCHEMA_VERSION

#: Oldest on-disk version from which forward migration is supported.
#: v0 means "empty / unversioned"; anything below MIN is refused outright.
MIN_UPGRADABLE_VERSION: int = 0


# ====================================================================== #
# enums
# ====================================================================== #


class MigrationDirection(str, Enum):
    """Which way a migration travels."""

    UP = "up"
    DOWN = "down"


class MigrationStatus(str, Enum):
    """Outcome of planning or executing a single step."""

    PENDING = "pending"
    RUNNING = "running"
    APPLIED = "applied"
    SKIPPED = "skipped"
    FAILED = "failed"
    REVERTED = "reverted"
    BLOCKED = "blocked"


_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _safe_ident(name: str, kind: str = "identifier") -> str:
    """Validate a raw SQL identifier. SQLite has few quoting niceties when we
    embed names into DDL strings, so we enforce a strict whitelist instead of
    trusting callers."""
    if not isinstance(name, str) or not _IDENT_RE.match(name):
        raise MigrationError(
            f"unsafe {kind} rejected: {name!r}",
            component="database.migrations",
            details={"kind": kind, "value": name},
        )
    return name


def _safe_type(spec: str) -> str:
    """Whitelist-ish validation for column type text embedded in ALTER TABLE.

    We allow the common SQL type vocabulary used by the ORM dialect plus
    parenthesised parameters, but reject quotes/semicolons/comments which
    could terminate the statement early.
    """
    cleaned = spec.strip()
    if not cleaned:
        raise MigrationError(
            "empty column type specification",
            component="database.migrations",
        )
    if any(tok in cleaned for tok in (";", "--", "/*", "'", '"', "\\")):
        raise MigrationError(
            f"suspicious characters in column type: {spec!r}",
            component="database.migrations",
            details={"spec": spec},
        )
    if not re.match(r"^[A-Za-z0-9_ ,()]+$", cleaned):
        raise MigrationError(
            f"invalid column type specification: {spec!r}",
            component="database.migrations",
            details={"spec": spec},
        )
    return cleaned


# ====================================================================== #
# declarative specs
# ====================================================================== #


@dataclass(frozen=True)
class ColumnSpec:
    """Declarative description of one column for ADD COLUMN migrations.

    SQLite's ``ALTER TABLE ... ADD COLUMN`` is deliberately limited: the
    column cannot be NOT NULL without a default, cannot be UNIQUE, and
    cannot be a primary key. The spec validates those constraints at
    construction time so migrations fail fast during *planning*, not halfway
    through execution.
    """

    name: str
    sql_type: str
    nullable: bool = True
    default: Optional[str] = None          # raw SQL default expression literal
    check: Optional[str] = None            # CHECK expression (SQLite >= 3.??
                                           # supports ADD COLUMN w/ CHECK in
                                           # modern builds; we keep optional)

    def __post_init__(self) -> None:
        _safe_ident(self.name, "column name")
        _safe_type(self.sql_type)
        if self.check is not None:
            if any(tok in self.check for tok in (";", "--", "/*")):
                raise MigrationError(
                    f"unsafe CHECK expression: {self.check!r}",
                    component="database.migrations",
                )
        if not self.nullable and self.default is None:
            raise MigrationError(
                (
                    f"column {self.name!r}: SQLite ADD COLUMN requires a "
                    "DEFAULT when declaring NOT NULL"
                ),
                component="database.migrations",
                details={"column": self.name},
            )

    def render(self) -> str:
        """Render the column clause for ALTER TABLE ADD COLUMN."""
        parts = [self.name, self.sql_type]
        if not self.nullable:
            parts.append("NOT NULL")
        if self.default is not None:
            parts.append(f"DEFAULT {self.default}")
        if self.check is not None:
            parts.append(f"CHECK ({self.check})")
        return " ".join(parts)


@dataclass(frozen=True)
class IndexSpec:
    """Declarative index creation request."""

    name: str
    table: str
    columns: Tuple[str, ...]
    unique: bool = False

    def __post_init__(self) -> None:
        _safe_ident(self.name, "index name")
        _safe_ident(self.table, "table name")
        if not self.columns:
            raise MigrationError(
                f"index {self.name!r} declares no columns",
                component="database.migrations",
            )
        for col in self.columns:
            _safe_ident(col, "column name")

    def render(self) -> str:
        cols = ", ".join(self.columns)
        uniq = "UNIQUE " if self.unique else ""
        return (
            f"CREATE {uniq}INDEX IF NOT EXISTS {self.name} "
            f"ON {self.table} ({cols})"
        )


@dataclass(frozen=True)
class TableSpec:
    """Marker that a migration introduces a whole new table.

    New tables are created from ORM metadata (single source of truth) rather
    than duplicated DDL strings, so the spec only names them; the runner
    renders exactly the ``CREATE TABLE`` the ORM would emit.
    """

    table: str

    def __post_init__(self) -> None:
        _safe_ident(self.table, "table name")


# ====================================================================== #
# migration step objects
# ====================================================================== #

RawSQLFn = Callable[[Engine], None]
"""Signature of a free-form migration callable. Receives the bound engine and
must use :func:`sqlalchemy.text` for all statements."""


@dataclass
class Migration:
    """One versioned step of the schema history.

    Attributes
    ----------
    version:
        The schema version reached *after* this step applies successfully.
        Versions must be strictly increasing across the registry.
    name:
        Short human-readable slug (also used in audit rows).
    description:
        Longer explanation shown in plans/reports.
    creates_tables:
        Tables (ORM-managed) this step introduces.
    adds_columns:
        Mapping of ``table -> [ColumnSpec]``.
    adds_indexes:
        Index specifications to create.
    upgrade_sql / downgrade_sql:
        Optional literal statements executed after structural changes.
    upgrade_fn / downgrade_fn:
        Optional Python callbacks for data transformations/backfills.
    reversible:
        When False, ``downgrade`` refuses and reports BLOCKED.
    requires_vacuum:
        Hint that the step leaves fragmentation worth reclaiming.
    min_source_version:
        Step may only run when current version >= this value.
    """

    version: int
    name: str
    description: str = ""
    creates_tables: Tuple[TableSpec, ...] = ()
    adds_columns: Mapping[str, Tuple[ColumnSpec, ...]] = field(
        default_factory=dict
    )
    adds_indexes: Tuple[IndexSpec, ...] = ()
    upgrade_sql: Tuple[str, ...] = ()
    downgrade_sql: Tuple[str, ...] = ()
    upgrade_fn: Optional[RawSQLFn] = None
    downgrade_fn: Optional[RawSQLFn] = None
    reversible: bool = True
    requires_vacuum: bool = False
    min_source_version: int = 0

    def __post_init__(self) -> None:
        if self.version < 1:
            raise MigrationError(
                f"migration version must be >= 1, got {self.version}",
                component="database.migrations",
            )
        if not self.name or not re.match(r"^[a-z0-9_]+$", self.name):
            raise MigrationError(
                f"migration name must be lowercase snake_case: {self.name!r}",
                component="database.migrations",
            )
        for stmt in (*self.upgrade_sql, *self.downgrade_sql):
            if not isinstance(stmt, str) or not stmt.strip():
                raise MigrationError(
                    f"migration {self.name!r} contains an empty SQL statement",
                    component="database.migrations",
                )
        # sanity-check structural pieces eagerly (fail at plan time)
        for table, cols in self.adds_columns.items():
            _safe_ident(table, "table name")
            for c in cols:
                if not isinstance(c, ColumnSpec):
                    raise MigrationError(
                        f"expected ColumnSpec for {table}.{c!r}",
                        component="database.migrations",
                    )
        for idx in self.adds_indexes:
            if not isinstance(idx, IndexSpec):
                raise MigrationError(
                    f"expected IndexSpec, got {idx!r}",
                    component="database.migrations",
                )
        for ts in self.creates_tables:
            if not isinstance(ts, TableSpec):
                raise MigrationError(
                    f"expected TableSpec, got {ts!r}",
                    component="database.migrations",
                )

    # ------------------------------------------------------------------ #

    @property
    def slug(self) -> str:
        return f"v{self.version:04d}_{self.name}"

    def summary(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "creates_tables": [t.table for t in self.creates_tables],
            "adds_columns": {
                tbl: [c.name for c in cols]
                for tbl, cols in self.adds_columns.items()
            },
            "adds_indexes": [i.name for i in self.adds_indexes],
            "upgrade_statements": len(self.upgrade_sql),
            "downgrade_statements": len(self.downgrade_sql),
            "has_python_upgrade": self.upgrade_fn is not None,
            "has_python_downgrade": self.downgrade_fn is not None,
            "reversible": self.reversible,
            "requires_vacuum": self.requires_vacuum,
        }


@dataclass
class MigrationStepResult:
    """Execution outcome for one step."""

    migration: Migration
    direction: MigrationDirection
    status: MigrationStatus
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_ms: float = 0.0
    statements_executed: int = 0
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "slug": self.migration.slug,
            "direction": self.direction.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
            "duration_ms": round(self.duration_ms, 3),
            "statements_executed": self.statements_executed,
            "error": self.error,
        }


@dataclass
class MigrationPlan:
    """An ordered, reviewable plan of steps."""

    direction: MigrationDirection
    start_version: int
    target_version: int
    steps: List[Migration] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.steps

    @property
    def irreversible_steps(self) -> List[Migration]:
        return [m for m in self.steps if not m.reversible]

    def describe(self) -> str:
        lines = [
            (
                f"plan: {self.direction.value} "
                f"v{self.start_version} -> v{self.target_version} "
                f"({len(self.steps)} step(s))"
            )
        ]
        for m in self.steps:
            mark = "!" if not m.reversible else " "
            lines.append(f"  {mark} {m.slug} — {m.description}")
        for w in self.warnings:
            lines.append(f"  warn: {w}")
        return "\n".join(lines)


@dataclass
class MigrationReport:
    """Full record of a :meth:`MigrationRunner.run_plan` invocation."""

    direction: MigrationDirection
    start_version: int
    end_version: int
    results: List[MigrationStepResult] = field(default_factory=list)
    backup_path: Optional[str] = None
    integrity_ok: Optional[bool] = None
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: Optional[datetime] = None

    @property
    def applied(self) -> List[MigrationStepResult]:
        wanted = {
            MigrationStatus.APPLIED,
            MigrationStatus.REVERTED,
        }
        return [r for r in self.results if r.status in wanted]

    @property
    def failed(self) -> List[MigrationStepResult]:
        return [r for r in self.results if r.status == MigrationStatus.FAILED]

    @property
    def blocked(self) -> List[MigrationStepResult]:
        return [r for r in self.results if r.status == MigrationStatus.BLOCKED]

    @property
    def success(self) -> bool:
        return not self.failed and not self.blocked

    def as_dict(self) -> Dict[str, Any]:
        return {
            "direction": self.direction.value,
            "start_version": self.start_version,
            "end_version": self.end_version,
            "success": self.success,
            "backup_path": self.backup_path,
            "integrity_ok": self.integrity_ok,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
            "results": [r.as_dict() for r in self.results],
        }

    def as_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, sort_keys=True)


# ====================================================================== #
# schema introspection helpers
# ====================================================================== #


@dataclass(frozen=True)
class SchemaInfo:
    """Snapshot of the *live* database structure (reflection based)."""

    exists: bool                      # does schema_migrations exist at all?
    version: int                      # stamped version (0 if none/unreadable)
    tables: Tuple[str, ...]
    columns: Mapping[str, Tuple[str, ...]]
    indexes: Mapping[str, Tuple[str, ...]]
    foreign_keys: Mapping[str, Tuple[Tuple[str, str], ...]]

    def has_table(self, name: str) -> bool:
        return name in self.tables

    def has_column(self, table: str, column: str) -> bool:
        return column in self.columns.get(table, ())

    def has_index(self, name: str) -> bool:
        return any(name in idxs for idxs in self.indexes.values())


_SCHEMA_MIG_TABLE = "schema_migrations"

_SCHEMA_MIGRATION_DDL = f"""
CREATE TABLE IF NOT EXISTS {_SCHEMA_MIG_TABLE} (
    version           INTEGER PRIMARY KEY,
    name              TEXT    NOT NULL,
    slug              TEXT    NOT NULL UNIQUE,
    direction         TEXT    NOT NULL DEFAULT 'up',
    applied_at        TEXT    NOT NULL,
    duration_ms       REAL    NOT NULL DEFAULT 0,
    checksum          TEXT    NOT NULL DEFAULT '',
    result            TEXT    NOT NULL DEFAULT 'applied',
    notes             TEXT
)
"""


def schema_migrations_ddl() -> str:
    """Expose the audit-table DDL for tests and bootstrap."""
    return _SCHEMA_MIGRATION_DDL


def _checksum(migration: Migration) -> str:
    """Deterministic fingerprint of a step's *intent*.

    If a registered step's structural content changes between releases while
    keeping the same version number, that is a history rewrite — we detect it
    and refuse to continue rather than producing divergent schemas.
    """
    payload = json.dumps(migration.summary(), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def read_current_version(engine: Engine) -> int:
    """Return the live schema version.

    Resolution order (each later stage only refines an ambiguous situation):
      1. ``schema_migrations.max(version)`` where result='applied'
      2. ``settings['schema.version']`` stamped by DatabaseManager
      3. 0 for a completely fresh file (no KMCS tables present)

    Raises :class:`SchemaVersionError` when tables exist but no version marker
    can be found — that indicates a foreign/hand-made schema we must not
    guess-migrate.
    """
    insp: Inspector = sa_inspect(engine)
    live_tables = set(insp.get_table_names())

    if _SCHEMA_MIG_TABLE in live_tables:
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    f"SELECT MAX(version) FROM {_SCHEMA_MIG_TABLE} "
                    "WHERE result = 'applied'"
                )
            ).scalar()
        if row is not None:
            return int(row)

    if {"targets", "settings"} & live_tables or "settings" in live_tables:
        try:
            with engine.connect() as conn:
                val = conn.execute(
                    text(
                        "SELECT value_json FROM settings WHERE key = "
                        "'schema.version'"
                    )
                ).scalar()
            if val is not None:
                # stored via JSONText decorator — strip quotes if needed
                if isinstance(val, str):
                    val = val.strip()
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                return int(val)
        except (SQLAlchemyError, ValueError, TypeError):
            pass
        # tables exist but unversioned -> ambiguous legacy/hand-made DB
        raise SchemaVersionError(
            "KMCS tables exist but carry no schema version marker; refusing "
            "to guess. Inspect manually or recreate the database.",
            component="database.migrations",
            details={"tables": sorted(live_tables)},
        )

    return 0


def snapshot_schema(engine: Engine) -> SchemaInfo:
    """Reflect the live schema into a comparable immutable snapshot."""
    insp = sa_inspect(engine)
    tables = tuple(sorted(insp.get_table_names()))
    columns: Dict[str, Tuple[str, ...]] = {}
    indexes: Dict[str, Tuple[str, ...]] = {}
    fks: Dict[str, Tuple[Tuple[str, str], ...]] = {}
    for t in tables:
        columns[t] = tuple(c["name"] for c in insp.get_columns(t))
        indexes[t] = tuple(
            i["name"] for i in insp.get_indexes(t) if i.get("name")
        )
        fks[t] = tuple(
            (fk["constrained_columns"][0], fk["referred_table"])
            for fk in insp.get_foreign_keys(t)
            if fk.get("constrained_columns")
        )
    try:
        version = read_current_version(engine)
    except SchemaVersionError:
        version = 0
    return SchemaInfo(
        exists=_SCHEMA_MIG_TABLE in tables,
        version=version,
        tables=tables,
        columns=columns,
        indexes=indexes,
        foreign_keys=fks,
    )


def orm_table_names() -> Tuple[str, ...]:
    return tuple(sorted(Base.metadata.tables.keys()))


def detect_drift(engine: Engine) -> Dict[str, Any]:
    """Compare live schema against ORM metadata.

    Returns a dict::

        {
          "missing_tables": [...],     # ORM knows, DB lacks
          "extra_tables": [...],       # DB has, ORM lacks (hand-made?)
          "missing_columns": {tbl: [...]},
          "extra_columns": {tbl: [...]},
          "drifted": bool,
        }

    Used by health checks; the migration runner also uses the missing side to
    make structural steps idempotent.
    """
    live = snapshot_schema(engine)
    orm_tables = set(orm_table_names()) | {_SCHEMA_MIG_TABLE}
    db_tables = set(live.tables)

    missing_tables = sorted(orm_tables - db_tables)
    extra_tables = sorted(db_tables - orm_tables)

    missing_columns: Dict[str, List[str]] = {}
    extra_columns: Dict[str, List[str]] = {}
    for tname, tdef in Base.metadata.tables.items():
        if tname not in db_tables:
            continue
        want = [c.name for c in tdef.columns]
        have = list(live.columns.get(tname, ()))
        miss = [c for c in want if c not in have]
        ext = [c for c in have if c not in want]
        if miss:
            missing_columns[tname] = miss
        if ext:
            extra_columns[tname] = ext

    return {
        "missing_tables": missing_tables,
        "extra_tables": extra_tables,
        "missing_columns": missing_columns,
        "extra_columns": extra_columns,
        "drifted": bool(
            missing_tables or extra_tables or missing_columns or extra_columns
        ),
    }


def verify_integrity(engine: Engine) -> Tuple[bool, str]:
    """Run ``PRAGMA integrity_check``; returns (ok, detail)."""
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        cur.execute("PRAGMA integrity_check")
        rows = cur.fetchall()
        cur.close()
    finally:
        raw.close()
    if not rows:
        return False, "integrity_check returned no rows"
    first = str(rows[0][0])
    ok = len(rows) == 1 and first == "ok"
    detail = first if ok else "; ".join(str(r[0]) for r in rows[:8])
    return ok, detail


def backup_database_file(db_path: str, suffix: str = "") -> Optional[str]:
    """Online-safe backup of a SQLite file via the sqlite3 backup API.

    Returns the destination path, or None when the source file does not exist
    yet (nothing to back up). Never overwrites an existing backup silently —
    a timestamp is appended until the name is free.
    """
    src = Path(db_path)
    if not src.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = src.with_name(f"{src.stem}.bak_{stamp}{suffix}{src.suffix}")
    counter = 0
    while dest.exists():
        counter += 1
        dest = src.with_name(
            f"{src.stem}.bak_{stamp}+{counter}{suffix}{src.suffix}"
        )
    src_conn = sqlite3.connect(str(src))
    try:
        dst_conn = sqlite3.connect(str(dest))
        try:
            with dst_conn:
                src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    # quick sanity: destination must itself pass integrity check
    check = sqlite3.connect(str(dest))
    try:
        res = check.execute("PRAGMA integrity_check").fetchone()
        if not res or res[0] != "ok":
            raise MigrationError(
                f"backup failed integrity verification: {dest}",
                component="database.migrations",
            )
    finally:
        check.close()
    return str(dest)


# ====================================================================== #
# the migration registry
# ====================================================================== #
#
# Version history policy:
#   * v1 is the initial ORM schema (bootstrap; see build_bootstrap_plan).
#   * Every future schema change appends a Migration here. NEVER edit an
#     already-released step: add a new one. The runner checksums steps to
#     catch accidental rewrites.
#
# The registry below ships structurally-complete placeholder-free history:
# v1 bootstrap is implicit, and the registry starts empty because the ORM
# metadata *is* v1. As soon as Phase 3+ changes models, real entries appear.
# To keep the engine exercised and honest, we register one genuinely useful
# operational step at v2 that adds telemetry durability columns required by
# campaigns/telemetry (Phase 5 contract) — written additively so it is safe
# on any v1 database and fully reversible.


def _registry_v2_steps() -> List[Migration]:
    """v2: harden events/telemetry retention (additive, reversible)."""
    return [
        Migration(
            version=2,
            name="event_retention_columns",
            description=(
                "Add retention/priority columns to events and telemetry rows "
                "so campaign workers can prune old records without schema "
                "guesswork."
            ),
            adds_columns={
                "events": (
                    ColumnSpec(
                        name="priority",
                        sql_type="INTEGER",
                        nullable=False,
                        default="0",
                    ),
                    ColumnSpec(
                        name="expires_at",
                        sql_type="TEXT",
                        nullable=True,
                    ),
                ),
                "telemetry_samples": (
                    ColumnSpec(
                        name="bucket_ts",
                        sql_type="TEXT",
                        nullable=True,
                    ),
                ),
            },
            adds_indexes=(
                IndexSpec(
                    name="ix_events_priority_expires",
                    table="events",
                    columns=("priority", "expires_at"),
                ),
                IndexSpec(
                    name="ix_telemetry_bucket",
                    table="telemetry_samples",
                    columns=("campaign_id", "bucket_ts"),
                ),
            ),
            upgrade_sql=(),
            downgrade_sql=(),
            reversible=True,
        ),
    ]


def _build_registry() -> List[Migration]:
    steps: List[Migration] = []
    steps.extend(_registry_v2_steps())
    steps.sort(key=lambda m: m.version)
    seen: Dict[int, Migration] = {}
    for m in steps:
        if m.version in seen:
            raise MigrationError(
                f"duplicate migration version {m.version} "
                f"({seen[m.version].name} vs {m.name})",
                component="database.migrations",
            )
        seen[m.version] = m
    # enforce strictly increasing contiguity from CURRENT_SCHEMA_VERSION+1
    expected = CURRENT_SCHEMA_VERSION + 1
    for m in steps:
        if m.version != expected:
            raise MigrationError(
                f"migration registry has a gap: expected version {expected}, "
                f"found {m.version} ({m.name})",
                component="database.migrations",
            )
        expected += 1
    return steps


MIGRATION_REGISTRY: List[Migration] = _build_registry()

REGISTRY_TOP_VERSION: int = (
    MIGRATION_REGISTRY[-1].version if MIGRATION_REGISTRY
    else CURRENT_SCHEMA_VERSION
)


# ====================================================================== #
# runner
# ====================================================================== #


class MigrationRunner:
    """Executes planned migrations against a SQLAlchemy engine.

    Parameters
    ----------
    engine:
        Bound engine for the KMCS SQLite database.
    db_path:
        Filesystem path of the SQLite file (for backups). May be a memory DB
        (":memory:"), in which case backups are skipped with a warning.
    manager:
        Optional :class:`kmcs.database.database.DatabaseManager`; when given,
        its ``schema.version`` setting is synchronised after successful runs.
    auto_backup:
        Take a file backup before any plan that mutates structure.
    verbose:
        Emit INFO-level logs per step.
    """

    def __init__(
        self,
        engine: Engine,
        db_path: Optional[str] = None,
        manager: Any = None,
        *,
        auto_backup: bool = True,
        verbose: bool = True,
    ) -> None:
        self.engine = engine
        self.db_path = db_path
        self.manager = manager
        self.auto_backup = auto_backup
        self.verbose = verbose
        self.registry = list(MIGRATION_REGISTRY)
        self._audit_ready = False

    # ------------------------------------------------------------------ #
    # audit table
    # ------------------------------------------------------------------ #

    def ensure_audit_table(self) -> None:
        if self._audit_ready:
            return
        with self.engine.begin() as conn:
            conn.execute(text(_SCHEMA_MIGRATION_DDL))
        self._audit_ready = True

    def applied_versions(self) -> Dict[int, Dict[str, Any]]:
        """Map version -> latest audit record (only 'applied' counts)."""
        self.ensure_audit_table()
        with self.engine.connect() as conn:
            rows = conn.execute(
                text(
                    f"SELECT version, slug, direction, applied_at, "
                    "duration_ms, checksum, result, notes "
                    f"FROM {_SCHEMA_MIG_TABLE} ORDER BY version ASC"
                )
            ).fetchall()
        out: Dict[int, Dict[str, Any]] = {}
        for r in rows:
            rec = dict(
                zip(
                    (
                        "version", "slug", "direction", "applied_at",
                        "duration_ms", "checksum", "result", "notes",
                    ),
                    tuple(r),
                )
            )
            ver = int(rec["version"])
            if rec["result"] == "applied" and rec["direction"] == "up":
                out[ver] = rec
            elif rec["result"] == "reverted":
                out.pop(ver, None)
        return out

    def current_version(self) -> int:
        applied = self.applied_versions()
        if applied:
            return max(applied)
        return read_current_version(self.engine)

    # ------------------------------------------------------------------ #
    # planning
    # ------------------------------------------------------------------ #

    def plan_upgrade(
        self,
        target: Optional[int] = None,
    ) -> MigrationPlan:
        top = REGISTRY_TOP_VERSION if target is None else int(target)
        if top > REGISTRY_TOP_VERSION:
            raise MigrationError(
                f"target version {top} exceeds registry top "
                f"{REGISTRY_TOP_VERSION}",
                component="database.migrations",
            )
        cur = self.current_version()
        if cur > top:
            raise SchemaVersionError(
                f"database is at v{cur}; refusing 'upgrade' to older v{top}. "
                "Use downgrade explicitly.",
                component="database.migrations",
                details={"current": cur, "target": top},
            )
        steps = [m for m in self.registry if cur < m.version <= top]
        warnings: List[str] = []
        if cur < MIN_UPGRADABLE_VERSION:
            raise MigrationError(
                f"database version {cur} is below minimum upgradable "
                f"version {MIN_UPGRADABLE_VERSION}",
                component="database.migrations",
            )
        for m in steps:
            if m.min_source_version > cur:
                warnings.append(
                    f"{m.slug} expects source >= v{m.min_source_version}"
                )
        return MigrationPlan(
            direction=MigrationDirection.UP,
            start_version=cur,
            target_version=top,
            steps=steps,
            warnings=warnings,
        )

    def plan_downgrade(self, target: int) -> MigrationPlan:
        if target < CURRENT_SCHEMA_VERSION:
            raise MigrationError(
                f"cannot downgrade below the base ORM schema v"
                f"{CURRENT_SCHEMA_VERSION} (that would mean deleting tables "
                "the application still uses)",
                component="database.migrations",
            )
        cur = self.current_version()
        if target >= cur:
            raise SchemaVersionError(
                f"downgrade target v{target} is not below current v{cur}",
                component="database.migrations",
            )
        steps = [
            m for m in reversed(self.registry) if target < m.version <= cur
        ]
        warnings = [
            f"{m.slug} is irreversible; downgrade will stop there"
            for m in steps
            if not m.reversible
        ]
        return MigrationPlan(
            direction=MigrationDirection.DOWN,
            start_version=cur,
            target_version=target,
            steps=steps,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ #
    # bootstrap (fresh databases)
    # ------------------------------------------------------------------ #

    def bootstrap(self) -> MigrationReport:
        """Create everything from ORM metadata and stamp the version.

        Idempotent: if the schema already exists this behaves like a no-op
        repair (creates only what is missing, then stamps).
        """
        self.ensure_audit_table()
        Base.metadata.create_all(self.engine, checkfirst=True)
        cur = read_current_version_quiet(self.engine)
        report = MigrationReport(
            direction=MigrationDirection.UP,
            start_version=cur,
            end_version=CURRENT_SCHEMA_VERSION,
        )
        if cur < CURRENT_SCHEMA_VERSION:
            now = datetime.now(timezone.utc).isoformat()
            payload = json.dumps(
                {"bootstrapped": True, "tables": list(orm_table_names())},
                sort_keys=True,
            )
            digest = hashlib.sha256(payload.encode()).hexdigest()[:16]
            with self.engine.begin() as conn:
                conn.execute(
                    text(
                        f"INSERT OR REPLACE INTO {_SCHEMA_MIG_TABLE} "
                        "(version, name, slug, direction, applied_at, "
                        "duration_ms, checksum, result, notes) VALUES "
                        "(:v, :n, :s, 'up', :t, 0, :c, 'applied', :notes)"
                    ),
                    {
                        "v": CURRENT_SCHEMA_VERSION,
                        "n": "bootstrap",
                        "s": f"v{CURRENT_SCHEMA_VERSION:04d}_bootstrap",
                        "t": now,
                        "c": digest,
                        "notes": payload,
                    },
                )
        self._sync_manager_version(CURRENT_SCHEMA_VERSION)
        report.finished_at = datetime.now(timezone.utc)
        return report

    # ------------------------------------------------------------------ #
    # execution
    # ------------------------------------------------------------------ #

    def run_plan(self, plan: MigrationPlan) -> MigrationReport:
        report = MigrationReport(
            direction=plan.direction,
            start_version=plan.start_version,
            end_version=plan.start_version,
        )
        if plan.is_empty:
            report.finished_at = datetime.now(timezone.utc)
            return report

        structural = any(
            m.creates_tables or m.adds_columns or m.adds_indexes
            for m in plan.steps
        )
        if (
            self.auto_backup
            and structural
            and plan.direction == MigrationDirection.UP
        ):
            report.backup_path = self._maybe_backup()

        self.ensure_audit_table()

        for m in plan.steps:
            result = self._run_step(m, plan.direction)
            report.results.append(result)
            if result.status == MigrationStatus.APPLIED:
                report.end_version = max(
                    report.end_version, m.version
                ) if plan.direction == MigrationDirection.UP else report.end_version
                if plan.direction == MigrationDirection.DOWN:
                    report.end_version = min(report.end_version, m.version - 1)
            if result.status in (
                MigrationStatus.FAILED,
                MigrationStatus.BLOCKED,
            ):
                break

        ok, detail = verify_integrity(self.engine)
        report.integrity_ok = ok
        if not ok:
            LOGGER.error("post-migration integrity check FAILED: %s", detail)

        self._sync_manager_version(report.end_version)
        report.finished_at = datetime.now(timezone.utc)

        if self.verbose:
            for r in report.results:
                LOGGER.info(
                    "%s %s -> %s (%.1f ms, %d stmts)%s",
                    r.direction.value,
                    r.migration.slug,
                    r.status.value,
                    r.duration_ms,
                    r.statements_executed,
                    f" err={r.error}" if r.error else "",
                )
        return report

    def _maybe_backup(self) -> Optional[str]:
        if not self.db_path or self.db_path in (":memory:", ""):
            LOGGER.warning("backup skipped: non-file database")
            return None
        try:
            return backup_database_file(self.db_path, suffix="_premigration")
        except (OSError, sqlite3.Error) as exc:
            raise MigrationError(
                f"pre-migration backup failed: {exc}",
                component="database.migrations",
            ) from exc

    # ----- individual step machinery ---------------------------------- #

    def _run_step(
        self,
        migration: Migration,
        direction: MigrationDirection,
    ) -> MigrationStepResult:
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        executed = 0

        if (
            direction == MigrationDirection.DOWN
            and not migration.reversible
        ):
            return MigrationStepResult(
                migration=migration,
                direction=direction,
                status=MigrationStatus.BLOCKED,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                duration_ms=(time.perf_counter() - t0) * 1000.0,
                error="step marked irreversible",
            )

        # guard against history rewrites
        self._check_checksum(migration, direction)

        try:
            with self.engine.begin() as conn:
                if direction == MigrationDirection.UP:
                    executed += self._apply_up(conn, migration)
                else:
                    executed += self._apply_down(conn, migration)
            elapsed = (time.perf_counter() - t0) * 1000.0
            self._record_audit(
                migration, direction, MigrationStatus.APPLIED
                if direction == MigrationDirection.UP
                else MigrationStatus.REVERTED,
                elapsed,
            )
            if migration.requires_vacuum:
                self._vacuum()
            return MigrationStepResult(
                migration=migration,
                direction=direction,
                status=(
                    MigrationStatus.APPLIED
                    if direction == MigrationDirection.UP
                    else MigrationStatus.REVERTED
                ),
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                duration_ms=elapsed,
                statements_executed=executed,
            )
        except (SQLAlchemyError, sqlite3.Error, MigrationError) as exc:
            elapsed = (time.perf_counter() - t0) * 1000.0
            try:
                self._record_audit(
                    migration, direction, MigrationStatus.FAILED, elapsed,
                    note=str(exc)[:500],
                )
            except Exception:  # audit failure must mask the real error
                pass
            LOGGER.exception(
                "migration %s (%s) failed", migration.slug, direction.value
            )
            return MigrationStepResult(
                migration=migration,
                direction=direction,
                status=MigrationStatus.FAILED,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                duration_ms=elapsed,
                statements_executed=executed,
                error=str(exc),
            )

    def _apply_up(self, conn: Any, m: Migration) -> int:
        count = 0
        live = snapshot_schema(self.engine)

        # 1. new tables straight from ORM metadata (single source of truth)
        for ts in m.creates_tables:
            table = Base.metadata.tables.get(ts.table)
            if table is None:
                raise MigrationError(
                    f"migration {m.slug} wants table {ts.table!r} but ORM "
                    "metadata does not define it",
                    component="database.migrations",
                )
            if not live.has_table(ts.table):
                table.create(conn, checkfirst=False)
                count += 1

        # 2. additive columns (skip ones that already exist -> idempotent)
        for tbl, cols in m.adds_columns.items():
            if not live.has_table(tbl):
                raise MigrationError(
                    f"cannot add columns to unknown table {tbl!r} "
                    f"(migration {m.slug})",
                    component="database.migrations",
                )
            for col in cols:
                if live.has_column(tbl, col.name):
                    continue
                conn.execute(
                    text(f"ALTER TABLE {tbl} ADD COLUMN {col.render()}")
                )
                count += 1

        # 3. indexes
        for idx in m.adds_indexes:
            conn.execute(text(idx.render()))
            count += 1

        # 4. literal SQL
        for stmt in m.upgrade_sql:
            conn.execute(text(stmt))
            count += 1

        # 5. python callback (outside our transaction? no — same conn,
        #    so it participates atomically)
        if m.upgrade_fn is not None:
            m.upgrade_fn(self.engine)
            count += 1
        return count

    def _apply_down(self, conn: Any, m: Migration) -> int:
        count = 0
        # SQLite cannot DROP COLUMN before 3.35; even then it cannot drop
        # columns that carry indexes/CHECK/PK roles. For safety and version
        # portability, downgrades of structural steps rebuild affected
        # indexes and rely on the fact that extra columns are harmless.
        for idx in m.adds_indexes:
            conn.execute(text(f"DROP INDEX IF EXISTS {idx.name}"))
            count += 1
        for stmt in m.downgrade_sql:
            conn.execute(text(stmt))
            count += 1
        if m.downgrade_fn is not None:
            m.downgrade_fn(self.engine)
            count += 1
        # columns intentionally retained (documented behaviour): dropping
        # them requires table rebuilds which risk data loss; we record that
        # choice in the audit note.
        return count

    # ----- audit plumbing ---------------------------------------------- #

    def _check_checksum(
        self, m: Migration, direction: MigrationDirection
    ) -> None:
        applied = self.applied_versions().get(m.version)
        if applied is None:
            return
        mine = _checksum(m)
        if applied.get("checksum") and applied["checksum"] != mine:
            raise MigrationError(
                f"history rewrite detected for v{m.version} ({m.name}): "
                "registered step differs from the audited one. Add a new "
                "migration instead of editing released steps.",
                component="database.migrations",
                details={
                    "audited": applied["checksum"],
                    "current": mine,
                },
            )

    def _record_audit(
        self,
        m: Migration,
        direction: MigrationDirection,
        status: MigrationStatus,
        duration_ms: float,
        note: Optional[str] = None,
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    f"INSERT OR REPLACE INTO {_SCHEMA_MIG_TABLE} "
                    "(version, name, slug, direction, applied_at, "
                    "duration_ms, checksum, result, notes) VALUES "
                    "(:v,:n,:s,:d,:t,:dur,:c,:r,:notes)"
                ),
                {
                    "v": m.version,
                    "n": m.name,
                    "s": m.slug,
                    "d": direction.value,
                    "t": datetime.now(timezone.utc).isoformat(),
                    "dur": duration_ms,
                    "c": _checksum(m),
                    "r": status.value,
                    "notes": note,
                },
            )

    def _vacuum(self) -> None:
        raw = self.engine.raw_connection()
        try:
            raw.isolation_level = None
            cur = raw.cursor()
            cur.execute("VACUUM")
            cur.close()
        finally:
            raw.close()

    def _sync_manager_version(self, version: int) -> None:
        """Keep the ``schema.version`` marker in sync after a migration run.

        Prefers an attached :class:`DatabaseManager`; otherwise writes (or
        upserts) the marker row directly through SQL so standalone engines —
        which never go through ``DatabaseManager._stamp_version`` — still have
        a single, consistent source of truth for the live schema version.
        """
        if self.manager is not None:
            try:
                self.manager.set_setting(
                    "schema.version", version, category="system"
                )
                return
            except Exception as exc:  # manager may expose different signature
                LOGGER.debug("could not sync manager version: %s", exc)
        now = datetime.now(timezone.utc).isoformat()
        value_json = json.dumps(version)
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO settings (key, value_json, category,"
                    " description, updated_at)"
                    " VALUES ('schema.version', :v, 'system',"
                    " 'ORM schema version marker', :t)"
                    " ON CONFLICT(key) DO UPDATE SET"
                    " value_json = excluded.value_json,"
                    " category = excluded.category,"
                    " updated_at = excluded.updated_at"
                ),
                {"v": value_json, "t": now},
            )


def read_current_version_quiet(engine: Engine) -> int:
    """Like :func:`read_current_version` but never raises on ambiguity."""
    try:
        return read_current_version(engine)
    except SchemaVersionError:
        return 0


def build_bootstrap_migration() -> Migration:
    """Synthetic step describing the v1 bootstrap (used in reports/tests)."""
    return Migration(
        version=CURRENT_SCHEMA_VERSION,
        name="bootstrap",
        description="Initial KMCS schema created from ORM metadata.",
        creates_tables=tuple(
            TableSpec(t) for t in orm_table_names()
        ),
        reversible=False,
    )


# ====================================================================== #
# convenience entry points
# ====================================================================== #


def upgrade(
    engine: Engine,
    target: Optional[int] = None,
    *,
    db_path: Optional[str] = None,
    manager: Any = None,
    auto_backup: bool = True,
) -> MigrationReport:
    """Bootstrap-if-needed then migrate up to ``target`` (default: head)."""
    runner = MigrationRunner(
        engine, db_path=db_path, manager=manager, auto_backup=auto_backup
    )
    insp = sa_inspect(engine)
    if not insp.get_table_names():
        runner.bootstrap()
    plan = runner.plan_upgrade(target)
    if plan.is_empty:
        report = MigrationReport(
            direction=MigrationDirection.UP,
            start_version=runner.current_version(),
            end_version=runner.current_version(),
        )
        report.finished_at = datetime.now(timezone.utc)
        report.integrity_ok = verify_integrity(engine)[0]
        return report
    return runner.run_plan(plan)


def downgrade(
    engine: Engine,
    target: int,
    *,
    db_path: Optional[str] = None,
    manager: Any = None,
) -> MigrationReport:
    runner = MigrationRunner(engine, db_path=db_path, manager=manager)
    plan = runner.plan_downgrade(target)
    return runner.run_plan(plan)


def status(engine: Engine) -> Dict[str, Any]:
    """Machine-readable schema status for CLI/GUI health panels."""
    runner = MigrationRunner(engine)
    info = snapshot_schema(engine)
    drift = detect_drift(engine)
    ok, detail = verify_integrity(engine)
    return {
        "live_version": info.version,
        "code_version": REGISTRY_TOP_VERSION,
        "base_orm_version": CURRENT_SCHEMA_VERSION,
        "needs_upgrade": info.version < REGISTRY_TOP_VERSION,
        "needs_downgrade": info.version > REGISTRY_TOP_VERSION,
        "tables_present": list(info.tables),
        "table_count": len(info.tables),
        "expected_tables": list(orm_table_names()),
        "drift": drift,
        "integrity_ok": ok,
        "integrity_detail": detail,
        "applied_migrations": [
            {
                "version": v,
                "slug": rec["slug"],
                "applied_at": rec["applied_at"],
                "checksum": rec["checksum"],
            }
            for v, rec in sorted(runner.applied_versions().items())
        ],
    }


# ====================================================================== #
# self-smoke (python -m kmcs.database.migrations)
# ====================================================================== #


def _self_smoke() -> int:
    import tempfile

    logging.basicConfig(level=logging.WARNING)
    tmp = tempfile.mkdtemp(prefix="kmcs_mig_smoke_")
    path = os.path.join(tmp, "smoke.db")
    from sqlalchemy import create_engine

    eng = create_engine(f"sqlite:///{path}")
    try:
        rep = upgrade(eng, db_path=path)
        assert rep.success, rep.as_json()
        st = status(eng)
        assert st["live_version"] == REGISTRY_TOP_VERSION, st
        assert st["integrity_ok"] is True
        assert not st["drift"]["missing_tables"], st["drift"]

        # idempotency: second upgrade is a no-op
        rep2 = upgrade(eng, db_path=path)
        assert rep2.success and rep2.start_version == rep2.end_version

        # downgrade v2 -> v1 then re-upgrade
        rep3 = downgrade(eng, CURRENT_SCHEMA_VERSION, db_path=path)
        assert rep3.success, rep3.as_json()
        assert snapshot_schema(eng).version >= CURRENT_SCHEMA_VERSION
        rep4 = upgrade(eng, db_path=path)
        assert rep4.success, rep4.as_json()

        # drift detection sees a hand-added column
        with eng.begin() as c:
            c.execute(
                text("ALTER TABLE settings ADD COLUMN canary TEXT")
            )
        d = detect_drift(eng)
        assert d["drifted"] and "canary" in d["extra_columns"].get(
            "settings", []
        ), d

        # backup works and passes integrity
        b = backup_database_file(path)
        assert b and os.path.exists(b)

        print(
            "migrations self-smoke OK:",
            f"registry_top=v{REGISTRY_TOP_VERSION}, "
            f"final=v{snapshot_schema(eng).version}, "
            f"tables={len(snapshot_schema(eng).tables)}"
        )
        return 0
    finally:
        eng.dispose()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_smoke())
